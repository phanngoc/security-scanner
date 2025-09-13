package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/lsp"
	"github.com/le-company/security-scanner/internal/parser"
	"github.com/le-company/security-scanner/internal/rules"
)

// Scanner represents the main security scanner
type Scanner struct {
	config         *config.Config
	logger         *zap.Logger
	ruleEngine     *rules.RuleEngine
	parserRegistry *parser.ParserRegistry
}

// New creates a new scanner instance
func New(cfg *config.Config, logger *zap.Logger) *Scanner {
	return &Scanner{
		config:         cfg,
		logger:         logger,
		ruleEngine:     rules.NewRuleEngine(cfg),
		parserRegistry: parser.NewParserRegistry(".", cfg, logger),
	}
}

// ScanResult represents the result of a security scan
type ScanResult struct {
	Findings     []*Finding      `json:"findings"`
	Statistics   *ScanStatistics `json:"statistics"`
	StartTime    time.Time       `json:"start_time"`
	EndTime      time.Time       `json:"end_time"`
	Duration     time.Duration   `json:"duration"`
	ScannedFiles []string        `json:"scanned_files"`
	SkippedFiles []string        `json:"skipped_files"`
}

// Finding represents a security vulnerability finding
type Finding struct {
	ID          string                  `json:"id"`
	RuleID      string                  `json:"rule_id"`
	Type        rules.VulnerabilityType `json:"type"`
	Severity    config.SeverityLevel    `json:"severity"`
	Title       string                  `json:"title"`
	Description string                  `json:"description"`
	File        string                  `json:"file"`
	Line        int                     `json:"line"`
	Column      int                     `json:"column"`
	Code        string                  `json:"code"`
	Context     []string                `json:"context"`
	Remediation string                  `json:"remediation"`
	CWE         string                  `json:"cwe"`
	OWASP       rules.OWASPReference    `json:"owasp"`
	Confidence  int                     `json:"confidence"`
}

// ScanStatistics contains scan statistics
type ScanStatistics struct {
	FilesScanned   int                             `json:"files_scanned"`
	FilesSkipped   int                             `json:"files_skipped"`
	LinesScanned   int                             `json:"lines_scanned"`
	FindingsCount  int                             `json:"findings_count"`
	BySeverity     map[config.SeverityLevel]int    `json:"by_severity"`
	ByType         map[rules.VulnerabilityType]int `json:"by_type"`
	ProcessingTime time.Duration                   `json:"processing_time"`
	Workers        int                             `json:"workers"`
}

// FileJob represents a file to be scanned
type FileJob struct {
	Path     string
	Content  []byte
	Language string
}

// Scan performs the security scan
func (s *Scanner) Scan() (*ScanResult, error) {
	startTime := time.Now()

	s.logger.Info("Starting security scan",
		zap.String("path", s.config.ScanPath),
		zap.Int("workers", s.config.Parallel))

	// Initialize result
	result := &ScanResult{
		Findings:     make([]*Finding, 0),
		StartTime:    startTime,
		ScannedFiles: make([]string, 0),
		SkippedFiles: make([]string, 0),
		Statistics: &ScanStatistics{
			BySeverity: make(map[config.SeverityLevel]int),
			ByType:     make(map[rules.VulnerabilityType]int),
			Workers:    s.config.Parallel,
		},
	}

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up parallel processing pipeline
	fileJobs := make(chan *FileJob, s.config.Parallel*2)
	findings := make(chan *Finding, s.config.Parallel*10)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.config.Parallel; i++ {
		wg.Add(1)
		go s.worker(ctx, &wg, fileJobs, findings)
	}

	// Start finding collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go s.findingCollector(ctx, &collectorWg, findings, result)

	// Walk directory and send files for processing
	walkErr := s.walkDirectory(ctx, fileJobs, result)

	// Close file jobs channel and wait for workers
	close(fileJobs)
	wg.Wait()

	// Close findings channel and wait for collector
	close(findings)
	collectorWg.Wait()

	// Calculate final statistics
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Statistics.ProcessingTime = result.Duration
	result.Statistics.FindingsCount = len(result.Findings)

	s.logger.Info("Scan completed",
		zap.Int("findings", len(result.Findings)),
		zap.Int("files_scanned", result.Statistics.FilesScanned),
		zap.Duration("duration", result.Duration))

	if walkErr != nil {
		s.logger.Warn("Directory walk completed with warnings", zap.Error(walkErr))
	}

	return result, nil
}

// worker processes file jobs in parallel
func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan *FileJob, findings chan<- *Finding) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}
			s.processFile(job, findings)
		}
	}
}

// processFile processes a single file for security vulnerabilities
func (s *Scanner) processFile(job *FileJob, findings chan<- *Finding) {
	s.logger.Debug("Processing file", zap.String("file", job.Path))

	// Use ParserRegistry with caching for enhanced symbol table
	enhancedSymbolTable, parseErr := s.parserRegistry.GetSymbolTable(job.Path)

	// Convert enhanced symbol table to basic for compatibility with existing rules
	var symbolTable *parser.SymbolTable
	if enhancedSymbolTable != nil {
		symbolTable = s.convertEnhancedToBasic(enhancedSymbolTable)
	}

	if parseErr != nil {
		s.logger.Warn("Failed to parse file",
			zap.String("file", job.Path),
			zap.Error(parseErr))
	}

	// Run security rules on the file
	enabledRules := s.ruleEngine.GetEnabledRules()
	for _, rule := range enabledRules {
		if s.ruleAppliesToLanguage(rule, job.Language) {
			fileFindings := s.checkRule(rule, job, symbolTable)
			for _, finding := range fileFindings {
				findings <- finding
			}
		}
	}
}

// checkRule checks a specific security rule against a file
func (s *Scanner) checkRule(rule *rules.Rule, job *FileJob, symbolTable *parser.SymbolTable) []*Finding {
	var findings []*Finding

	lines := strings.Split(string(job.Content), "\n")

	for _, pattern := range rule.Patterns {
		switch pattern.Type {
		case rules.PatternRegex:
			if pattern.Regex != nil {
				findings = append(findings, s.checkRegexPattern(rule, pattern, job, lines)...)
			}
		case rules.PatternLiteral:
			findings = append(findings, s.checkLiteralPattern(rule, pattern, job, lines)...)
		case rules.PatternFunction:
			if symbolTable != nil {
				findings = append(findings, s.checkFunctionPattern(rule, pattern, job, symbolTable)...)
			}
		case rules.PatternAST:
			if symbolTable != nil {
				findings = append(findings, s.checkASTPattern(rule, pattern, job, symbolTable)...)
			}
		}
	}

	return findings
}

// checkRegexPattern checks regex patterns against file content
func (s *Scanner) checkRegexPattern(rule *rules.Rule, pattern rules.Pattern, job *FileJob, lines []string) []*Finding {
	var findings []*Finding

	for lineNum, line := range lines {
		matches := pattern.Regex.FindAllStringIndex(line, -1)
		for _, match := range matches {
			finding := &Finding{
				ID:          fmt.Sprintf("%s-%s-%d-%d", rule.ID, job.Path, lineNum+1, match[0]),
				RuleID:      rule.ID,
				Type:        rule.Type,
				Severity:    rule.Severity,
				Title:       rule.Name,
				Description: rule.Description,
				File:        job.Path,
				Line:        lineNum + 1,
				Column:      match[0] + 1,
				Code:        strings.TrimSpace(line),
				Context:     s.getLineContext(lines, lineNum, 2),
				Remediation: rule.Remediation,
				CWE:         rule.CWE,
				OWASP:       rule.OWASP,
				Confidence:  85, // Default confidence for regex matches
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkLiteralPattern checks literal string patterns
func (s *Scanner) checkLiteralPattern(rule *rules.Rule, pattern rules.Pattern, job *FileJob, lines []string) []*Finding {
	var findings []*Finding

	for lineNum, line := range lines {
		if strings.Contains(line, pattern.Pattern) {
			index := strings.Index(line, pattern.Pattern)
			finding := &Finding{
				ID:          fmt.Sprintf("%s-%s-%d-%d", rule.ID, job.Path, lineNum+1, index),
				RuleID:      rule.ID,
				Type:        rule.Type,
				Severity:    rule.Severity,
				Title:       rule.Name,
				Description: rule.Description,
				File:        job.Path,
				Line:        lineNum + 1,
				Column:      index + 1,
				Code:        strings.TrimSpace(line),
				Context:     s.getLineContext(lines, lineNum, 2),
				Remediation: rule.Remediation,
				CWE:         rule.CWE,
				OWASP:       rule.OWASP,
				Confidence:  75, // Lower confidence for literal matches
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// checkFunctionPattern checks patterns in function calls
func (s *Scanner) checkFunctionPattern(rule *rules.Rule, pattern rules.Pattern, job *FileJob, symbolTable *parser.SymbolTable) []*Finding {
	var findings []*Finding

	// Check function calls in symbol table
	for funcName, funcInfo := range symbolTable.Functions {
		for _, call := range funcInfo.Calls {
			if strings.Contains(call, pattern.Pattern) {
				pos := symbolTable.FileSet.Position(funcInfo.StartPos)
				finding := &Finding{
					ID:          fmt.Sprintf("%s-%s-%s", rule.ID, job.Path, funcName),
					RuleID:      rule.ID,
					Type:        rule.Type,
					Severity:    rule.Severity,
					Title:       rule.Name,
					Description: fmt.Sprintf("%s in function %s", rule.Description, funcName),
					File:        job.Path,
					Line:        pos.Line,
					Column:      pos.Column,
					Code:        fmt.Sprintf("Function: %s calls %s", funcName, call),
					Remediation: rule.Remediation,
					CWE:         rule.CWE,
					OWASP:       rule.OWASP,
					Confidence:  90, // Higher confidence for function-level analysis
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// checkASTPattern checks patterns using AST analysis
func (s *Scanner) checkASTPattern(rule *rules.Rule, pattern rules.Pattern, job *FileJob, symbolTable *parser.SymbolTable) []*Finding {
	var findings []*Finding

	// TODO: Implement AST-based pattern matching
	// This would involve more sophisticated analysis of the AST structure

	return findings
}

// getLineContext gets surrounding lines for context
func (s *Scanner) getLineContext(lines []string, lineNum, contextSize int) []string {
	start := lineNum - contextSize
	end := lineNum + contextSize + 1

	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}

	context := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		prefix := "   "
		if i == lineNum {
			prefix = ">> "
		}
		context = append(context, fmt.Sprintf("%s%4d: %s", prefix, i+1, lines[i]))
	}

	return context
}

// ruleAppliesToLanguage checks if a rule applies to the given language
func (s *Scanner) ruleAppliesToLanguage(rule *rules.Rule, language string) bool {
	for _, lang := range rule.Languages {
		if lang == "*" || lang == language {
			return true
		}
	}
	return false
}

// walkDirectory walks the directory and sends files for processing
func (s *Scanner) walkDirectory(ctx context.Context, jobs chan<- *FileJob, result *ScanResult) error {
	var processedFiles int

	return filepath.WalkDir(s.config.ScanPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			s.logger.Warn("Error accessing path", zap.String("path", path), zap.Error(err))
			return nil // Continue walking
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if d.IsDir() {
			// Check if directory should be ignored
			if s.shouldIgnorePath(path) {
				return filepath.SkipDir
			}
			return nil
		}

		// Check file limit (0 = unlimited)
		if s.config.MaxFiles > 0 && processedFiles >= s.config.MaxFiles {
			s.logger.Info("Reached maximum file limit, stopping scan",
				zap.Int("max_files", s.config.MaxFiles),
				zap.Int("processed", processedFiles))
			return filepath.SkipAll
		}

		// Check if file should be processed
		if !s.shouldProcessFile(path) {
			result.SkippedFiles = append(result.SkippedFiles, path)
			result.Statistics.FilesSkipped++
			return nil
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			s.logger.Warn("Failed to read file", zap.String("file", path), zap.Error(err))
			result.SkippedFiles = append(result.SkippedFiles, path)
			result.Statistics.FilesSkipped++
			return nil
		}

		// Count lines
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		lineCount := 0
		for scanner.Scan() {
			lineCount++
		}
		result.Statistics.LinesScanned += lineCount

		// Determine language
		language := s.detectLanguage(path)

		// Create job
		job := &FileJob{
			Path:     path,
			Content:  content,
			Language: language,
		}

		// Send job for processing
		select {
		case jobs <- job:
			result.ScannedFiles = append(result.ScannedFiles, path)
			result.Statistics.FilesScanned++
			processedFiles++
		case <-ctx.Done():
			return ctx.Err()
		}

		return nil
	})
}

// shouldIgnorePath checks if a path should be ignored
func (s *Scanner) shouldIgnorePath(path string) bool {
	// Normalize path for comparison
	normalizedPath := filepath.Clean(path)

	// Check allowed directories first (if specified)
	if len(s.config.AllowedDirs) > 0 || len(s.config.Rules.AllowedDirs) > 0 {
		allowed := false

		// Check config-level allowed dirs
		for _, allowedDir := range s.config.AllowedDirs {
			if s.pathMatchesPattern(normalizedPath, allowedDir) {
				allowed = true
				break
			}
		}

		// Check rules-level allowed dirs
		if !allowed {
			for _, allowedDir := range s.config.Rules.AllowedDirs {
				if s.pathMatchesPattern(normalizedPath, allowedDir) {
					allowed = true
					break
				}
			}
		}

		// If we have allowed dirs but this path doesn't match any, ignore it
		if !allowed {
			return true
		}
	}

	// Check excluded directories
	for _, excludedDir := range s.config.ExcludedDirs {
		if s.pathMatchesPattern(normalizedPath, excludedDir) {
			return true
		}
	}

	for _, excludedDir := range s.config.Rules.ExcludedDirs {
		if s.pathMatchesPattern(normalizedPath, excludedDir) {
			return true
		}
	}

	// Check legacy ignore patterns
	for _, pattern := range s.config.Rules.IgnorePatterns {
		if strings.Contains(normalizedPath, pattern) {
			return true
		}
	}

	return false
}

// shouldProcessFile checks if a file should be processed
func (s *Scanner) shouldProcessFile(path string) bool {
	ext := filepath.Ext(path)
	for _, allowedExt := range s.config.Rules.FileExtensions {
		if ext == allowedExt {
			return true
		}
	}
	return false
}

// pathMatchesPattern checks if a path matches a directory pattern
func (s *Scanner) pathMatchesPattern(path, pattern string) bool {
	// Normalize both paths
	normalizedPath := filepath.Clean(path)
	normalizedPattern := filepath.Clean(pattern)

	// Handle absolute paths
	if filepath.IsAbs(normalizedPattern) {
		// For absolute patterns, check if path starts with pattern
		return strings.HasPrefix(normalizedPath, normalizedPattern)
	}

	// For relative patterns, check multiple scenarios

	// 1. Direct prefix match
	if strings.HasPrefix(normalizedPath, normalizedPattern) {
		return true
	}

	// 2. Check if any component in the path matches the pattern
	pathParts := strings.Split(normalizedPath, string(filepath.Separator))
	patternParts := strings.Split(normalizedPattern, string(filepath.Separator))

	// Check for exact directory name match
	for i, part := range pathParts {
		if part == patternParts[0] {
			// If pattern is single directory, match found
			if len(patternParts) == 1 {
				return true
			}

			// Check if remaining path matches remaining pattern
			if i+len(patternParts) <= len(pathParts) {
				match := true
				for j, patternPart := range patternParts {
					if i+j >= len(pathParts) || pathParts[i+j] != patternPart {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}

	// 3. Wildcard matching (simple glob support)
	if strings.Contains(normalizedPattern, "*") {
		matched, _ := filepath.Match(normalizedPattern, normalizedPath)
		if matched {
			return true
		}

		// Try matching directory components
		for _, part := range pathParts {
			if matched, _ := filepath.Match(normalizedPattern, part); matched {
				return true
			}
		}
	}

	return false
}

// detectLanguage detects the programming language of a file
func (s *Scanner) detectLanguage(path string) string {
	ext := filepath.Ext(path)
	switch ext {
	case ".go":
		return "go"
	case ".php":
		return "php"
	case ".js", ".mjs":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".java":
		return "java"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".cs":
		return "csharp"
	case ".cpp", ".cc", ".cxx":
		return "cpp"
	case ".c":
		return "c"
	case ".html", ".htm":
		return "html"
	default:
		return "unknown"
	}
}

// findingCollector collects findings from workers
func (s *Scanner) findingCollector(ctx context.Context, wg *sync.WaitGroup, findings <-chan *Finding, result *ScanResult) {
	defer wg.Done()

	var mu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			return
		case finding, ok := <-findings:
			if !ok {
				return
			}

			mu.Lock()
			result.Findings = append(result.Findings, finding)
			result.Statistics.BySeverity[finding.Severity]++
			result.Statistics.ByType[finding.Type]++
			mu.Unlock()
		}
	}
}

// convertEnhancedToBasic converts enhanced LSP symbol table to basic symbol table
func (s *Scanner) convertEnhancedToBasic(enhanced *lsp.SymbolTable) *parser.SymbolTable {
	if enhanced == nil {
		return nil
	}

	basic := &parser.SymbolTable{
		Functions: make(map[string]*parser.FunctionInfo),
		Variables: make(map[string]*parser.VariableInfo),
		Imports:   make(map[string]string),
		Language:  enhanced.Language,
		FilePath:  enhanced.FileURI,
	}

	// Traverse the scope tree to extract symbols
	if enhanced.ScopeTree != nil {
		s.traverseAndConvert(enhanced.ScopeTree, basic)
	}

	// Copy dependency imports
	if enhanced.DependencyGraph != nil && enhanced.DependencyGraph.Nodes != nil {
		if node, exists := enhanced.DependencyGraph.Nodes[enhanced.FileURI]; exists {
			for importName, importPath := range node.Imports {
				basic.Imports[importName] = importPath
			}
		}
	}

	return basic
}

// traverseAndConvert recursively traverses the scope tree and converts symbols
func (s *Scanner) traverseAndConvert(node *lsp.ScopeNode, basic *parser.SymbolTable) {
	if node == nil {
		return
	}

	// Convert current node based on its kind
	switch node.Kind {
	case 12: // SymbolKindFunction
		basic.Functions[node.Name] = &parser.FunctionInfo{
			Name:     node.Name,
			StartPos: 0, // LSP uses different position system
			EndPos:   0, // LSP uses different position system
			Body:     []string{node.Detail},
			Calls:    node.CallGraph,
		}
	case 6: // SymbolKindMethod
		basic.Functions[node.Name] = &parser.FunctionInfo{
			Name:     node.Name,
			StartPos: 0,
			EndPos:   0,
			Body:     []string{node.Detail},
			Calls:    node.CallGraph,
		}
	case 13: // SymbolKindVariable
		basic.Variables[node.Name] = &parser.VariableInfo{
			Name:     node.Name,
			Type:     node.Detail,
			StartPos: 0,
			EndPos:   0,
			Scope:    node.NamePath,
		}
	case 14: // SymbolKindConstant
		basic.Variables[node.Name] = &parser.VariableInfo{
			Name:     node.Name,
			Type:     node.Detail,
			StartPos: 0,
			EndPos:   0,
			Scope:    node.NamePath,
		}
	}

	// Recursively process children
	for _, child := range node.Children {
		s.traverseAndConvert(child, basic)
	}
}
