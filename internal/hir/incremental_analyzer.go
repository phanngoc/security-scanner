package hir

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"go.uber.org/zap"
)

// IncrementalAnalyzer provides incremental analysis capabilities
type IncrementalAnalyzer struct {
	workspace *WorkspaceIndex
	linker    *SymbolLinker
	program   *HIRProgram
	logger    *zap.Logger

	// Configuration
	maxDependencyDepth  int
	enableTaintAnalysis bool
	enableCallGraph     bool
}

// NewIncrementalAnalyzer creates a new incremental analyzer
func NewIncrementalAnalyzer(workspacePath string, logger *zap.Logger) (*IncrementalAnalyzer, error) {
	workspace, err := NewWorkspaceIndex(workspacePath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace index: %w", err)
	}

	program := NewHIRProgram()
	linker := NewSymbolLinker(program)

	return &IncrementalAnalyzer{
		workspace:           workspace,
		linker:              linker,
		program:             program,
		logger:              logger,
		maxDependencyDepth:  3, // Default max dependency depth
		enableTaintAnalysis: true,
		enableCallGraph:     true,
	}, nil
}

// AnalysisRequest represents a request for incremental analysis
type AnalysisRequest struct {
	Files        []string // Files to analyze
	ChangedFiles []string // Files that have changed
	ForceRebuild bool     // Force full rebuild
	MaxDepth     int      // Max dependency depth (0 = use default)
}

// AnalysisResponse represents the result of incremental analysis
type AnalysisResponse struct {
	ProcessedFiles []string           // Files that were processed
	AffectedFiles  []string           // Files affected by changes
	SkippedFiles   []string           // Files skipped (up to date)
	Findings       []*SecurityFinding // Security findings
	Metrics        *AnalysisMetrics   // Analysis metrics
	Duration       time.Duration      // Total analysis time
	Errors         []error            // Analysis errors
}

// AnalysisMetrics contains metrics about the analysis
type AnalysisMetrics struct {
	FilesScanned     int
	FilesUpToDate    int
	FilesRebuilt     int
	SymbolsExtracted int
	CallGraphEdges   int
	DependencyEdges  int
	SecurityFindings int
	CacheHits        int
	CacheMisses      int
}

// AnalyzeIncremental performs incremental analysis
func (ia *IncrementalAnalyzer) AnalyzeIncremental(request *AnalysisRequest) (*AnalysisResponse, error) {
	startTime := time.Now()

	response := &AnalysisResponse{
		ProcessedFiles: make([]string, 0),
		AffectedFiles:  make([]string, 0),
		SkippedFiles:   make([]string, 0),
		Findings:       make([]*SecurityFinding, 0),
		Metrics:        &AnalysisMetrics{},
		Errors:         make([]error, 0),
	}

	ia.logger.Info("Starting incremental analysis",
		zap.Int("files", len(request.Files)),
		zap.Int("changed", len(request.ChangedFiles)),
		zap.Bool("force_rebuild", request.ForceRebuild))

	maxDepth := request.MaxDepth
	if maxDepth == 0 {
		maxDepth = ia.maxDependencyDepth
	}

	// Step 1: Determine which files need to be processed
	filesToProcess, err := ia.determineFilesToProcess(request, maxDepth)
	if err != nil {
		return response, fmt.Errorf("failed to determine files to process: %w", err)
	}

	response.ProcessedFiles = filesToProcess.NeedProcessing
	response.AffectedFiles = filesToProcess.Affected
	response.SkippedFiles = filesToProcess.UpToDate

	ia.logger.Info("File processing plan",
		zap.Int("to_process", len(filesToProcess.NeedProcessing)),
		zap.Int("affected", len(filesToProcess.Affected)),
		zap.Int("up_to_date", len(filesToProcess.UpToDate)))

	// Step 2: Process files that need updating
	for _, filePath := range filesToProcess.NeedProcessing {
		err := ia.processFile(filePath, response)
		if err != nil {
			ia.logger.Error("Failed to process file",
				zap.String("file", filePath),
				zap.Error(err))
			response.Errors = append(response.Errors, err)
			continue
		}
		response.Metrics.FilesScanned++
	}

	// Step 3: Re-link symbols if needed
	if len(filesToProcess.NeedProcessing) > 0 {
		err = ia.linkSymbols(filesToProcess.NeedProcessing)
		if err != nil {
			ia.logger.Error("Failed to link symbols", zap.Error(err))
			response.Errors = append(response.Errors, err)
		}
	}

	// Step 4: Run security analysis on affected files
	allAffectedFiles := append(filesToProcess.NeedProcessing, filesToProcess.Affected...)
	securityFindings, err := ia.runSecurityAnalysis(allAffectedFiles)
	if err != nil {
		ia.logger.Error("Failed to run security analysis", zap.Error(err))
		response.Errors = append(response.Errors, err)
	} else {
		response.Findings = securityFindings
		response.Metrics.SecurityFindings = len(securityFindings)
	}

	response.Duration = time.Since(startTime)
	response.Metrics.FilesUpToDate = len(filesToProcess.UpToDate)
	response.Metrics.FilesRebuilt = len(filesToProcess.NeedProcessing)

	ia.logger.Info("Incremental analysis completed",
		zap.Duration("duration", response.Duration),
		zap.Int("findings", len(response.Findings)),
		zap.Int("errors", len(response.Errors)))

	return response, nil
}

// ProcessingPlan contains files categorized by processing needs
type ProcessingPlan struct {
	NeedProcessing []string // Files that need to be processed
	Affected       []string // Files affected by changes but up to date
	UpToDate       []string // Files that are up to date
}

// determineFilesToProcess determines which files need processing
func (ia *IncrementalAnalyzer) determineFilesToProcess(request *AnalysisRequest, maxDepth int) (*ProcessingPlan, error) {
	plan := &ProcessingPlan{
		NeedProcessing: make([]string, 0),
		Affected:       make([]string, 0),
		UpToDate:       make([]string, 0),
	}

	affectedFiles := make(map[string]bool)

	// If force rebuild, mark all files for processing
	if request.ForceRebuild {
		plan.NeedProcessing = append(plan.NeedProcessing, request.Files...)
		return plan, nil
	}

	// Check each file's status
	for _, filePath := range request.Files {
		needsProcessing, err := ia.fileNeedsProcessing(filePath)
		if err != nil {
			ia.logger.Warn("Error checking file status",
				zap.String("file", filePath),
				zap.Error(err))
			// Assume needs processing if we can't determine
			needsProcessing = true
		}

		if needsProcessing {
			plan.NeedProcessing = append(plan.NeedProcessing, filePath)

			// Find dependent files
			dependents, err := ia.findDependentFiles(filePath, maxDepth)
			if err != nil {
				ia.logger.Warn("Error finding dependents",
					zap.String("file", filePath),
					zap.Error(err))
				continue
			}

			for _, dep := range dependents {
				affectedFiles[dep] = true
			}
		} else {
			plan.UpToDate = append(plan.UpToDate, filePath)
		}
	}

	// Add explicitly changed files
	for _, changedFile := range request.ChangedFiles {
		if !contains(plan.NeedProcessing, changedFile) {
			plan.NeedProcessing = append(plan.NeedProcessing, changedFile)
		}

		// Find dependent files for changed files
		dependents, err := ia.findDependentFiles(changedFile, maxDepth)
		if err != nil {
			ia.logger.Warn("Error finding dependents for changed file",
				zap.String("file", changedFile),
				zap.Error(err))
			continue
		}

		for _, dep := range dependents {
			affectedFiles[dep] = true
		}
	}

	// Convert affected files map to slice, excluding files already being processed
	for file := range affectedFiles {
		if !contains(plan.NeedProcessing, file) {
			plan.Affected = append(plan.Affected, file)
		}
	}

	return plan, nil
}

// fileNeedsProcessing checks if a file needs to be processed
func (ia *IncrementalAnalyzer) fileNeedsProcessing(filePath string) (bool, error) {
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to stat file: %w", err)
	}

	// Calculate file hash
	hash, err := ia.calculateFileHash(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Check if file is up to date in index
	upToDate, err := ia.workspace.IsFileUpToDate(filePath, hash, fileInfo.ModTime())
	if err != nil {
		return false, fmt.Errorf("failed to check if file is up to date: %w", err)
	}

	return !upToDate, nil
}

// findDependentFiles finds files that depend on the given file
func (ia *IncrementalAnalyzer) findDependentFiles(filePath string, maxDepth int) ([]string, error) {
	// Get file ID from index
	fileRecord, err := ia.workspace.GetFileByPath(filePath)
	if err != nil {
		// File not in index yet
		return []string{}, nil
	}

	// Get dependents from workspace index
	dependentIDs, err := ia.workspace.GetDependents(fileRecord.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get dependents: %w", err)
	}

	dependents := make([]string, 0, len(dependentIDs))

	// Convert IDs to file paths (this would need proper implementation)
	// For now, return empty slice
	// TODO: Implement proper ID to path conversion

	return dependents, nil
}

// processFile processes a single file
func (ia *IncrementalAnalyzer) processFile(filePath string, response *AnalysisResponse) error {
	ia.logger.Debug("Processing file", zap.String("file", filePath))

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Get file info for metadata
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	hash, err := ia.calculateFileHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	// Transform to HIR using basic transformer
	transformer := NewBasicTransformer(ia.program)
	hirFile, err := transformer.TransformBasicFile(filePath, content)
	if err != nil {
		return fmt.Errorf("failed to transform file to HIR: %w", err)
	}

	// Store file in workspace index
	fileRecord, err := ia.workspace.StoreFile(hirFile, hash, fileInfo.ModTime(), fileInfo.Size())
	if err != nil {
		return fmt.Errorf("failed to store file: %w", err)
	}

	// Store symbols
	err = ia.workspace.StoreSymbols(fileRecord.ID, hirFile.Symbols)
	if err != nil {
		return fmt.Errorf("failed to store symbols: %w", err)
	}

	// Store HIR units
	for _, unit := range hirFile.Units {
		// Build CFG for unit
		if ia.enableCallGraph {
			cfgBuilder := NewCFGBuilder()
			cfg, err := cfgBuilder.BuildCFG(unit)
			if err != nil {
				ia.logger.Warn("Failed to build CFG for unit",
					zap.String("file", filePath),
					zap.String("unit", string(unit.Symbol.ID)),
					zap.Error(err))
			} else {
				unit.CFG = cfg
			}
		}

		err = ia.workspace.StoreHIRUnit(fileRecord.ID, unit)
		if err != nil {
			return fmt.Errorf("failed to store HIR unit: %w", err)
		}
	}

	// Add to program
	ia.program.Files[filePath] = hirFile

	response.Metrics.SymbolsExtracted += len(hirFile.Symbols)

	return nil
}

// linkSymbols performs symbol linking for processed files
func (ia *IncrementalAnalyzer) linkSymbols(processedFiles []string) error {
	ia.logger.Debug("Linking symbols", zap.Int("files", len(processedFiles)))

	// This would involve re-running the symbol linker on affected files
	// For now, run it on the entire program
	return ia.linker.LinkSymbols()
}

// runSecurityAnalysis runs security analysis on affected files
func (ia *IncrementalAnalyzer) runSecurityAnalysis(affectedFiles []string) ([]*SecurityFinding, error) {
	ia.logger.Debug("Running security analysis", zap.Int("files", len(affectedFiles)))

	allFindings := make([]*SecurityFinding, 0)

	for _, filePath := range affectedFiles {
		findings, err := ia.analyzeFileForSecurity(filePath)
		if err != nil {
			ia.logger.Warn("Failed to analyze file for security",
				zap.String("file", filePath),
				zap.Error(err))
			continue
		}

		allFindings = append(allFindings, findings...)

		// Store findings in workspace
		fileRecord, err := ia.workspace.GetFileByPath(filePath)
		if err != nil {
			ia.logger.Warn("Failed to get file record for storing findings",
				zap.String("file", filePath),
				zap.Error(err))
			continue
		}

		err = ia.workspace.StoreSecurityFindings(fileRecord.ID, findings)
		if err != nil {
			ia.logger.Warn("Failed to store security findings",
				zap.String("file", filePath),
				zap.Error(err))
		}
	}

	return allFindings, nil
}

// analyzeFileForSecurity analyzes a single file for security issues
func (ia *IncrementalAnalyzer) analyzeFileForSecurity(filePath string) ([]*SecurityFinding, error) {
	// Get HIR file from program
	hirFile, exists := ia.program.Files[filePath]
	if !exists {
		return nil, fmt.Errorf("file not found in HIR program: %s", filePath)
	}

	analyzer := NewHIRSecurityAnalyzer(ia.program)
	findings, err := analyzer.AnalyzeFile(hirFile)
	if err != nil {
		return nil, fmt.Errorf("security analysis failed: %w", err)
	}

	return findings, nil
}

// calculateFileHash calculates SHA256 hash of file content
func (ia *IncrementalAnalyzer) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	_, err = io.Copy(hasher, file)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// HIRSecurityAnalyzer performs security analysis on HIR
type HIRSecurityAnalyzer struct {
	program *HIRProgram
	rules   []HIRSecurityRule
}

// NewHIRSecurityAnalyzer creates a new HIR security analyzer
func NewHIRSecurityAnalyzer(program *HIRProgram) *HIRSecurityAnalyzer {
	analyzer := &HIRSecurityAnalyzer{
		program: program,
		rules:   make([]HIRSecurityRule, 0),
	}

	// Register security rules
	analyzer.registerDefaultRules()

	return analyzer
}

// HIRSecurityRule represents a security rule that operates on HIR
type HIRSecurityRule interface {
	ID() string
	Name() string
	Description() string
	Severity() Severity
	Check(file *HIRFile, program *HIRProgram) ([]*SecurityFinding, error)
}

// registerDefaultRules registers default security rules
func (hsa *HIRSecurityAnalyzer) registerDefaultRules() {
	// These would be actual rule implementations
	rules := []HIRSecurityRule{
		NewSQLInjectionHIRRule(),
		NewXSSHIRRule(),
		NewCommandInjectionHIRRule(),
		NewPathTraversalHIRRule(),
		NewHardcodedSecretHIRRule(),
	}

	hsa.rules = append(hsa.rules, rules...)
}

// AnalyzeFile analyzes a single HIR file for security issues
func (hsa *HIRSecurityAnalyzer) AnalyzeFile(file *HIRFile) ([]*SecurityFinding, error) {
	allFindings := make([]*SecurityFinding, 0)

	for _, rule := range hsa.rules {
		findings, err := rule.Check(file, hsa.program)
		if err != nil {
			return nil, fmt.Errorf("rule %s failed: %w", rule.ID(), err)
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// Placeholder rule implementations (these would be full implementations)

type SQLInjectionHIRRule struct{}

func NewSQLInjectionHIRRule() *SQLInjectionHIRRule { return &SQLInjectionHIRRule{} }
func (r *SQLInjectionHIRRule) ID() string          { return "SQL-HIR-001" }
func (r *SQLInjectionHIRRule) Name() string        { return "SQL Injection (HIR)" }
func (r *SQLInjectionHIRRule) Description() string { return "Detects SQL injection via HIR analysis" }
func (r *SQLInjectionHIRRule) Severity() Severity  { return SeverityHigh }
func (r *SQLInjectionHIRRule) Check(file *HIRFile, program *HIRProgram) ([]*SecurityFinding, error) {
	var findings []*SecurityFinding

	// Analyze HIR units for SQL injection patterns
	for _, unit := range file.Units {
		if unit.Body != nil {
			for _, stmt := range unit.Body.Stmts {
				if stmt.Type == HIRCall {
					// Check if this is a SQL function call with security risk
					if risk, ok := stmt.Meta["security_risk"].(string); ok && risk == "SQL Injection" {
						finding := &SecurityFinding{
							ID:          "HIR-SQL-001",
							Type:        VulnSQLInjection,
							Severity:    SeverityHigh,
							Confidence:  0.95,
							Message:     "SQL injection vulnerability detected via HIR analysis",
							Description: "Tainted user input flows directly into SQL query without sanitization",
							File:        file.Path,
							Position:    stmt.Position,
						}
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings, nil
}

type XSSHIRRule struct{}

func NewXSSHIRRule() *XSSHIRRule          { return &XSSHIRRule{} }
func (r *XSSHIRRule) ID() string          { return "XSS-HIR-001" }
func (r *XSSHIRRule) Name() string        { return "XSS (HIR)" }
func (r *XSSHIRRule) Description() string { return "Detects XSS via HIR analysis" }
func (r *XSSHIRRule) Severity() Severity  { return SeverityHigh }
func (r *XSSHIRRule) Check(file *HIRFile, program *HIRProgram) ([]*SecurityFinding, error) {
	return []*SecurityFinding{}, nil
}

type CommandInjectionHIRRule struct{}

func NewCommandInjectionHIRRule() *CommandInjectionHIRRule { return &CommandInjectionHIRRule{} }
func (r *CommandInjectionHIRRule) ID() string              { return "CMD-HIR-001" }
func (r *CommandInjectionHIRRule) Name() string            { return "Command Injection (HIR)" }
func (r *CommandInjectionHIRRule) Description() string {
	return "Detects command injection via HIR analysis"
}
func (r *CommandInjectionHIRRule) Severity() Severity { return SeverityCritical }
func (r *CommandInjectionHIRRule) Check(file *HIRFile, program *HIRProgram) ([]*SecurityFinding, error) {
	return []*SecurityFinding{}, nil
}

type PathTraversalHIRRule struct{}

func NewPathTraversalHIRRule() *PathTraversalHIRRule { return &PathTraversalHIRRule{} }
func (r *PathTraversalHIRRule) ID() string           { return "PATH-HIR-001" }
func (r *PathTraversalHIRRule) Name() string         { return "Path Traversal (HIR)" }
func (r *PathTraversalHIRRule) Description() string  { return "Detects path traversal via HIR analysis" }
func (r *PathTraversalHIRRule) Severity() Severity   { return SeverityHigh }
func (r *PathTraversalHIRRule) Check(file *HIRFile, program *HIRProgram) ([]*SecurityFinding, error) {
	return []*SecurityFinding{}, nil
}

type HardcodedSecretHIRRule struct{}

func NewHardcodedSecretHIRRule() *HardcodedSecretHIRRule { return &HardcodedSecretHIRRule{} }
func (r *HardcodedSecretHIRRule) ID() string             { return "SECRET-HIR-001" }
func (r *HardcodedSecretHIRRule) Name() string           { return "Hardcoded Secret (HIR)" }
func (r *HardcodedSecretHIRRule) Description() string {
	return "Detects hardcoded secrets via HIR analysis"
}
func (r *HardcodedSecretHIRRule) Severity() Severity { return SeverityHigh }
func (r *HardcodedSecretHIRRule) Check(file *HIRFile, program *HIRProgram) ([]*SecurityFinding, error) {
	return []*SecurityFinding{}, nil
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Close closes the incremental analyzer
func (ia *IncrementalAnalyzer) Close() error {
	return ia.workspace.Close()
}

// Configuration methods

func (ia *IncrementalAnalyzer) SetMaxDependencyDepth(depth int) {
	ia.maxDependencyDepth = depth
}

func (ia *IncrementalAnalyzer) SetEnableTaintAnalysis(enable bool) {
	ia.enableTaintAnalysis = enable
}

func (ia *IncrementalAnalyzer) SetEnableCallGraph(enable bool) {
	ia.enableCallGraph = enable
}

// GetMetrics returns current analysis metrics
func (ia *IncrementalAnalyzer) GetMetrics() (*AnalysisMetrics, error) {
	// This would return accumulated metrics from the workspace
	return &AnalysisMetrics{}, nil
}
