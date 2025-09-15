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

	"github.com/le-company/security-scanner/internal/analyzer"
	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/hir"
	"github.com/le-company/security-scanner/internal/lsp"
	"github.com/le-company/security-scanner/internal/parser"
	"github.com/le-company/security-scanner/internal/rules"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// Scanner represents the main security scanner
type Scanner struct {
	config         *config.Config
	logger         *zap.Logger
	ruleEngine     *rules.RuleEngine
	parserRegistry *parser.ParserRegistry
	hirProgram     *hir.HIRProgram
	hirTransformer *hir.BasicTransformer
	analyzerEngine *analyzer.AnalysisEngine
	indexService   *hir.IndexService
}

// New creates a new scanner instance
func New(cfg *config.Config, logger *zap.Logger) *Scanner {
	// Initialize HIR program
	hirProgram := &hir.HIRProgram{
		Files:           make(map[string]*hir.HIRFile),
		Symbols:         hir.NewGlobalSymbolTable(),
		CallGraph:       hir.NewCallGraph(),
		CFGs:            make(map[hir.SymbolID]*hir.CFG),
		DependencyGraph: hir.NewDependencyGraph(),
		IncludeGraph:    hir.NewIncludeGraph(),
		CreatedAt:       time.Now(),
	}

	// Initialize index service
	indexService, err := hir.NewIndexService(".", logger)
	if err != nil {
		logger.Warn("Failed to initialize index service", zap.Error(err))
		indexService = nil
	}

	// Initialize analyzer registry and engine
	registry := analyzer.NewAnalyzerRegistry()

	// Load and register rules dynamically
	ruleLoader := rules.NewLoader(logger)
	if err := ruleLoader.LoadAllRules(registry); err != nil {
		logger.Warn("Failed to load some rules", zap.Error(err))
	}

	// Create analysis context
	var analysisContext *analyzer.AnalysisContext
	if indexService != nil {
		analysisContext = &analyzer.AnalysisContext{
			WorkspaceIndex: indexService.GetIndex(),
			Config:         cfg,
			Logger:         logger,
			Timeout:        30 * time.Second,
		}
	}

	// Initialize analysis engine
	analyzerEngine := analyzer.NewAnalysisEngine(registry, analysisContext)

	return &Scanner{
		config:         cfg,
		logger:         logger,
		ruleEngine:     rules.NewRuleEngine(cfg),
		parserRegistry: parser.NewParserRegistry(".", cfg, logger),
		hirProgram:     hirProgram,
		hirTransformer: hir.NewBasicTransformer(hirProgram),
		analyzerEngine: analyzerEngine,
		indexService:   indexService,
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

	// Primary approach: HIR/CFG Analysis
	hirFindings, hirErr := s.analyzeWithHIR(job)
	if hirErr == nil && len(hirFindings) > 0 {
		s.logger.Debug("HIR/CFG analysis successful",
			zap.String("file", job.Path),
			zap.Int("findings", len(hirFindings)))
		for _, finding := range hirFindings {
			findings <- finding
		}
		return // HIR analysis succeeded, skip traditional analysis
	}

	// if hirErr != nil {
	// 	s.logger.Debug("HIR analysis failed, falling back to traditional analysis",
	// 		zap.String("file", job.Path),
	// 		zap.Error(hirErr))
	// }

	// // Fallback approach: Traditional pattern matching
	// enhancedSymbolTable, parseErr := s.parserRegistry.GetSymbolTable(job.Path)

	// // Symbol table conversion disabled for now
	// _ = enhancedSymbolTable

	// if parseErr != nil {
	// 	s.logger.Warn("Failed to parse file",
	// 		zap.String("file", job.Path),
	// 		zap.Error(parseErr))
	// }

	// // Run traditional security rules on the file
	// // Traditional rule checking temporarily disabled due to type conflicts
	// // TODO: Unify types.Rule and rules.Rule type systems
	// s.logger.Debug("Traditional rule checking temporarily disabled", zap.String("file", job.Path))

	// The OWASP rule patterns we updated will still work through the rule providers
	ruleProviders := s.ruleEngine.GetEnabledRuleProviders()
	for _, provider := range ruleProviders {
		if provider.GetRule() != nil && s.languageMatches(provider.GetRule().Languages, job.Language) {
			fileFindings := s.checkProviderRule(provider, job)
			for _, finding := range fileFindings {
				findings <- finding
			}
		}
	}

	// OTP plaintext vulnerabilities are now handled by OTPAnalyzer through the analyzer registry
}

// analyzeWithHIR performs HIR/CFG-based security analysis
func (s *Scanner) analyzeWithHIR(job *FileJob) ([]*Finding, error) {
	// Transform file content to HIR
	hirFile, err := s.hirTransformer.TransformBasicFile(job.Path, job.Content)
	if err != nil {
		return nil, fmt.Errorf("HIR transformation failed: %w", err)
	}

	// Add file to HIR program (thread-safe)
	s.hirProgram.AddFile(hirFile)

	// Add symbols to global symbol table (thread-safe)
	s.hirProgram.AddSymbols(hirFile.Symbols)

	// Perform symbol linking (thread-safe)
	if err := s.hirProgram.SafeSymbolLinking(); err != nil {
		return nil, fmt.Errorf("symbol linking failed: %w", err)
	}

	// Ensure file is indexed with HIR data
	if s.indexService != nil {
		if err := s.indexService.EnsureFileIndexed(context.Background(), job.Path, job.Content, job.Language); err != nil {
			s.logger.Warn("Failed to index file", zap.String("file", job.Path), zap.Error(err))
		}
	}

	// Use new analyzer engine for comprehensive analysis
	var findings []*Finding
	if s.analyzerEngine != nil {
		// Create analysis job
		analysisJob := &analyzer.AnalysisJob{
			Path:        job.Path,
			Language:    job.Language,
			Content:     job.Content,
			HIRFile:     hirFile,
			SymbolTable: nil, // Will be loaded by analyzer engine
			CFG:         nil, // Will be loaded by analyzer engine
			Metadata:    make(map[string]interface{}),
		}

		// Run analysis
		analysisFindings, err := s.analyzerEngine.AnalyzeFile(context.Background(), analysisJob)
		if err != nil {
			s.logger.Warn("Analysis engine failed", zap.String("file", job.Path), zap.Error(err))
		} else {
			// Convert analysis findings to scanner findings
			for _, analysisFinding := range analysisFindings {
				scannerFinding := s.convertAnalysisFindingToScannerFinding(analysisFinding, job)
				findings = append(findings, scannerFinding)
			}
		}
	}

	s.logger.Debug("HIR/CFG analysis completed",
		zap.String("file", job.Path),
		zap.Int("hir_findings", len(findings)),
		zap.Int("converted_findings", len(findings)))

	return findings, nil
}

// analyzeOTPFlowWithCFG performs CFG-based OTP flow analysis
func (s *Scanner) analyzeOTPFlowWithCFG(job *FileJob) []*Finding {
	var findings []*Finding

	// Only analyze PHP files for OTP patterns
	if job.Language != "php" {
		return findings
	}

	// TODO: Implement OTP analysis with proper registry access
	// For now, skip OTP analysis until registry access is fixed
	s.logger.Info("OTP analysis temporarily disabled - registry access needs to be implemented")

	return findings
}

// convertOTPFlowFindingToScannerFinding converts OTP flow finding to scanner finding
func (s *Scanner) convertOTPFlowFindingToScannerFinding(otpFinding *types.SecurityFinding, job *FileJob) *Finding {
	// Extract line number from position (simplified)
	lines := strings.Split(string(job.Content), "\n")
	lineNum := otpFinding.Line
	if lineNum == 0 {
		lineNum = 1
	}

	// Get code context
	var code string
	if lineNum <= len(lines) {
		code = strings.TrimSpace(lines[lineNum-1])
	}

	// Map severity
	severity := otpFinding.Severity

	// Map vulnerability type
	var vulnType rules.VulnerabilityType
	switch otpFinding.VulnType {
	case types.HardcodedSecrets:
		vulnType = rules.HardcodedSecrets
	default:
		vulnType = rules.HardcodedSecrets
	}

	return &Finding{
		ID:          otpFinding.RuleID + "-" + job.Path + "-" + fmt.Sprintf("%d", lineNum),
		RuleID:      otpFinding.RuleID,
		Type:        vulnType,
		Severity:    severity,
		Title:       "OTP Code Stored in Plaintext",
		Description: otpFinding.Message,
		File:        job.Path,
		Line:        lineNum,
		Column:      1,
		Code:        code,
		Context:     s.getLineContext(lines, lineNum-1, 2),
		Remediation: otpFinding.Remediation,
		CWE:         otpFinding.CWE,
		OWASP:       rules.OWASPReference{Top10_2021: otpFinding.OWASP.Top10_2021},
		Confidence:  85, // Default confidence
	}
}

// convertHIRFindingToScannerFinding converts HIR security finding to scanner finding
func (s *Scanner) convertHIRFindingToScannerFinding(hirFinding *hir.SecurityFinding, job *FileJob) *Finding {
	// Extract line number from position
	lines := strings.Split(string(job.Content), "\n")
	lineNum := 1
	if hirFinding.Position > 0 && int(hirFinding.Position) < len(string(job.Content)) {
		lineNum = strings.Count(string(job.Content)[:int(hirFinding.Position)], "\n") + 1
	}

	// Get code context
	var code string
	if lineNum <= len(lines) {
		code = strings.TrimSpace(lines[lineNum-1])
	}

	// Map HIR severity to config severity
	var severity config.SeverityLevel
	switch hirFinding.Severity {
	case hir.SeverityLow:
		severity = config.SeverityLow
	case hir.SeverityMedium:
		severity = config.SeverityMedium
	case hir.SeverityHigh:
		severity = config.SeverityHigh
	case hir.SeverityCritical:
		severity = config.SeverityCritical
	default:
		severity = config.SeverityMedium
	}

	// Map HIR vulnerability type to rules vulnerability type
	var vulnType rules.VulnerabilityType
	switch hirFinding.Type {
	case hir.VulnSQLInjection:
		vulnType = rules.SQLInjection
	case hir.VulnXSS:
		vulnType = rules.XSS
	case hir.VulnCommandInjection:
		vulnType = rules.CommandInjection
	case hir.VulnPathTraversal:
		vulnType = rules.PathTraversal
	case hir.VulnHardcodedSecret:
		vulnType = rules.HardcodedSecrets
	default:
		vulnType = rules.SQLInjection // Default
	}

	return &Finding{
		ID:          hirFinding.ID,
		RuleID:      hirFinding.ID,
		Type:        vulnType,
		Severity:    severity,
		Title:       hirFinding.Message,
		Description: hirFinding.Description,
		File:        job.Path,
		Line:        lineNum,
		Column:      1, // HIR doesn't provide column info
		Code:        code,
		Context:     s.getLineContext(lines, lineNum-1, 2),
		Remediation: s.getRemediationForType(vulnType),
		CWE:         s.getCWEForType(vulnType),
		OWASP:       s.getOWASPForType(vulnType),
		Confidence:  int(hirFinding.Confidence * 100), // Convert to percentage
	}
}

// getRemediationForType returns remediation advice for vulnerability type
func (s *Scanner) getRemediationForType(vulnType rules.VulnerabilityType) string {
	switch vulnType {
	case rules.SQLInjection:
		return "Use parameterized queries or prepared statements. Validate and sanitize all user inputs."
	case rules.XSS:
		return "Always encode output data. Use HTML entity encoding for HTML context, JavaScript encoding for JS context."
	case rules.CommandInjection:
		return "Avoid executing system commands with user input. Use allow-lists and input validation."
	case rules.PathTraversal:
		return "Validate file paths against a whitelist. Use absolute paths and avoid user input in file operations."
	case rules.HardcodedSecrets:
		return "Store secrets in environment variables or secure configuration files. Never hardcode credentials."
	default:
		return "Review and validate the identified security issue."
	}
}

// getCWEForType returns CWE identifier for vulnerability type
func (s *Scanner) getCWEForType(vulnType rules.VulnerabilityType) string {
	switch vulnType {
	case rules.SQLInjection:
		return "CWE-89"
	case rules.XSS:
		return "CWE-79"
	case rules.CommandInjection:
		return "CWE-78"
	case rules.PathTraversal:
		return "CWE-22"
	case rules.HardcodedSecrets:
		return "CWE-798"
	default:
		return "CWE-1"
	}
}

// getOWASPForType returns OWASP reference for vulnerability type
func (s *Scanner) getOWASPForType(vulnType rules.VulnerabilityType) rules.OWASPReference {
	switch vulnType {
	case rules.SQLInjection, rules.XSS, rules.CommandInjection:
		return rules.OWASPReference{Top10_2021: "A03:2021"}
	case rules.PathTraversal:
		return rules.OWASPReference{Top10_2021: "A01:2021"}
	case rules.HardcodedSecrets:
		return rules.OWASPReference{Top10_2021: "A02:2021"}
	default:
		return rules.OWASPReference{Top10_2021: "A03:2021"}
	}
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
func (s *Scanner) ruleAppliesToLanguage(rule *types.Rule, language string) bool {
	for _, lang := range rule.Languages {
		if lang == "*" || lang == language {
			return true
		}
	}
	return false
}

// languageMatches checks if any language in the list matches the target
func (s *Scanner) languageMatches(languages []string, target string) bool {
	for _, lang := range languages {
		if lang == "*" || lang == target {
			return true
		}
	}
	return false
}

// checkProviderRule checks a rule through its provider interface
func (s *Scanner) checkProviderRule(provider rules.RuleProvider, job *FileJob) []*Finding {
	var findings []*Finding

	// Check if provider has IsVulnerable method by trying to type assert to known types
	isVulnerable := false
	switch rule := provider.(type) {
	case interface{ IsVulnerable(string, string) bool }:
		isVulnerable = rule.IsVulnerable(string(job.Content), job.Path)
	default:
		// Fallback: check patterns manually for providers without IsVulnerable method
		ruleData := provider.GetRule()
		if ruleData != nil && len(ruleData.Patterns) > 0 {
			for _, pattern := range ruleData.Patterns {
				if pattern.Regex != nil && pattern.Regex.MatchString(string(job.Content)) {
					isVulnerable = true
					break
				}
			}
		}
	}

	if isVulnerable {
		rule := provider.GetRule()
		finding := &Finding{
			RuleID:      rule.ID,
			Type:        rules.VulnerabilityType(string(provider.GetType())),
			Severity:    rule.Severity,
			Title:       rule.Name,
			Description: rule.Description,
			File:        job.Path,
			Line:        1, // TODO: Get actual line from provider
			Column:      1,
			Code:        "", // Could extract code snippet
			Remediation: rule.Remediation,
			OWASP:       rules.OWASPReference{Top10_2021: rule.OWASP.Top10_2021},
			CWE:         rule.CWE,
		}
		findings = append(findings, finding)
	}

	return findings
}

// Removed obsolete checkOTPPlaintextVulnerabilities - now handled by OTPAnalyzer directly

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

// convertAnalysisFindingToScannerFinding converts analysis finding to scanner finding
func (s *Scanner) convertAnalysisFindingToScannerFinding(analysisFinding *types.SecurityFinding, job *FileJob) *Finding {
	// Extract line number from position (simplified)
	lines := strings.Split(string(job.Content), "\n")
	lineNum := 1
	if analysisFinding.Line > 0 && analysisFinding.Line <= len(lines) {
		lineNum = analysisFinding.Line
	}

	// Extract code context
	code := ""
	if lineNum > 0 && lineNum <= len(lines) {
		code = strings.TrimSpace(lines[lineNum-1])
	}

	return &Finding{
		ID:          fmt.Sprintf("%s-%s-%d", analysisFinding.RuleID, job.Path, len(job.Content)),
		RuleID:      analysisFinding.RuleID,
		Type:        rules.VulnerabilityType(analysisFinding.VulnType),
		Severity:    analysisFinding.Severity,
		Title:       analysisFinding.RuleName,
		Description: analysisFinding.Message,
		File:        analysisFinding.File,
		Line:        lineNum,
		Column:      analysisFinding.Column,
		Code:        code,
		Context:     []string{},
		Remediation: analysisFinding.Remediation,
		CWE:         analysisFinding.CWE,
		OWASP:       rules.OWASPReference{Top10_2021: analysisFinding.OWASP.Top10_2021},
		Confidence:  85,
	}
}

// Close closes the scanner and cleans up resources
func (s *Scanner) Close() error {
	if s.indexService != nil {
		return s.indexService.Close()
	}
	return nil
}

// GetIndexService returns the index service for external use
func (s *Scanner) GetIndexService() *hir.IndexService {
	return s.indexService
}
