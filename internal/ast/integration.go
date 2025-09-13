package ast

import (
	"fmt"
	"path/filepath"

	"go.uber.org/zap"
)

// ParserIntegration integrates the new AST parser system with the existing scanner
type ParserIntegration struct {
	registry   *ParserRegistry
	ruleEngine *SecurityRuleEngine
	logger     *zap.Logger
}

// NewParserIntegration creates a new parser integration
func NewParserIntegration(logger *zap.Logger) *ParserIntegration {
	registry := NewParserRegistry()
	ruleEngine := NewSecurityRuleEngine()

	// Register all language parsers
	registry.RegisterParser(NewSimplePHPASTParser())
	// TODO: Add more language parsers (Go, JavaScript, Python, etc.)

	return &ParserIntegration{
		registry:   registry,
		ruleEngine: ruleEngine,
		logger:     logger,
	}
}

// ParseAndAnalyze parses a file and performs security analysis
func (pi *ParserIntegration) ParseAndAnalyze(filePath string, content []byte) (*AnalysisResult, error) {
	// Detect language from file extension
	ext := filepath.Ext(filePath)
	parser := pi.registry.GetParserByExtension(ext)

	if parser == nil {
		return nil, fmt.Errorf("no parser available for file extension: %s", ext)
	}

	pi.logger.Debug("Parsing file with AST parser",
		zap.String("file", filePath),
		zap.String("language", parser.GetLanguage()))

	// Parse the file
	ast, stats, err := parser.Parse(content, filePath)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	// Build symbol table
	symbolTable, err := parser.BuildSymbolTable(ast)
	if err != nil {
		return nil, fmt.Errorf("symbol table building failed: %w", err)
	}

	// Perform security analysis
	findings, err := pi.ruleEngine.AnalyzeAST(ast, symbolTable)
	if err != nil {
		return nil, fmt.Errorf("security analysis failed: %w", err)
	}

	result := &AnalysisResult{
		FilePath:    filePath,
		Language:    parser.GetLanguage(),
		AST:         ast,
		SymbolTable: symbolTable,
		Findings:    findings,
		ParseStats:  stats,
		Metrics:     CalculateMetrics(ast),
	}

	pi.logger.Info("Analysis completed",
		zap.String("file", filePath),
		zap.String("language", parser.GetLanguage()),
		zap.Int("findings", len(findings)),
		zap.Int("nodes", stats.NodesCreated),
		zap.Duration("parse_time", stats.Duration))

	return result, nil
}

// AnalysisResult contains the complete analysis result for a file
type AnalysisResult struct {
	FilePath    string
	Language    string
	AST         *ProgramNode
	SymbolTable *SymbolTable
	Findings    []SecurityFinding
	ParseStats  *ParseStats
	Metrics     *ASTMetrics
}

// GetFindingsBySeverity returns findings grouped by severity
func (ar *AnalysisResult) GetFindingsBySeverity() map[Severity][]SecurityFinding {
	result := make(map[Severity][]SecurityFinding)

	for _, finding := range ar.Findings {
		result[finding.Severity] = append(result[finding.Severity], finding)
	}

	return result
}

// GetFindingsByRule returns findings grouped by rule ID
func (ar *AnalysisResult) GetFindingsByRule() map[string][]SecurityFinding {
	result := make(map[string][]SecurityFinding)

	for _, finding := range ar.Findings {
		result[finding.RuleID] = append(result[finding.RuleID], finding)
	}

	return result
}

// HasCriticalFindings returns true if there are critical severity findings
func (ar *AnalysisResult) HasCriticalFindings() bool {
	for _, finding := range ar.Findings {
		if finding.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasHighSeverityFindings returns true if there are high severity findings
func (ar *AnalysisResult) HasHighSeverityFindings() bool {
	for _, finding := range ar.Findings {
		if finding.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// GetSupportedLanguages returns all supported languages
func (pi *ParserIntegration) GetSupportedLanguages() []string {
	return pi.registry.GetSupportedLanguages()
}

// GetSupportedExtensions returns all supported file extensions
func (pi *ParserIntegration) GetSupportedExtensions() []string {
	return pi.registry.GetSupportedExtensions()
}

// IsFileSupported checks if a file is supported for parsing
func (pi *ParserIntegration) IsFileSupported(filePath string) bool {
	ext := filepath.Ext(filePath)
	return pi.registry.GetParserByExtension(ext) != nil
}

// BatchAnalyze analyzes multiple files concurrently
func (pi *ParserIntegration) BatchAnalyze(files []FileInput) ([]*AnalysisResult, error) {
	results := make([]*AnalysisResult, len(files))
	errors := make([]error, len(files))

	// TODO: Implement concurrent processing
	for i, file := range files {
		result, err := pi.ParseAndAnalyze(file.Path, file.Content)
		results[i] = result
		errors[i] = err
	}

	// Check for errors
	for _, err := range errors {
		if err != nil {
			return results, err
		}
	}

	return results, nil
}

// FileInput represents input for batch analysis
type FileInput struct {
	Path    string
	Content []byte
}

// AnalysisSummary provides a summary of analysis results
type AnalysisSummary struct {
	TotalFiles         int
	SupportedFiles     int
	ParsedFiles        int
	FailedFiles        int
	TotalFindings      int
	FindingsBySeverity map[Severity]int
	FindingsByRule     map[string]int
	Languages          map[string]int
	TotalNodes         int
	TotalParseTime     int64 // milliseconds
}

// GenerateSummary generates a summary from multiple analysis results
func GenerateSummary(results []*AnalysisResult) *AnalysisSummary {
	summary := &AnalysisSummary{
		FindingsBySeverity: make(map[Severity]int),
		FindingsByRule:     make(map[string]int),
		Languages:          make(map[string]int),
	}

	for _, result := range results {
		if result == nil {
			summary.FailedFiles++
			continue
		}

		summary.ParsedFiles++
		summary.TotalFindings += len(result.Findings)
		summary.Languages[result.Language]++
		summary.TotalNodes += result.Metrics.NodeCount
		summary.TotalParseTime += result.ParseStats.Duration.Milliseconds()

		// Count findings by severity
		for _, finding := range result.Findings {
			summary.FindingsBySeverity[finding.Severity]++
			summary.FindingsByRule[finding.RuleID]++
		}
	}

	summary.TotalFiles = len(results)
	summary.SupportedFiles = summary.ParsedFiles + summary.FailedFiles

	return summary
}

// TaintAnalyzer performs taint analysis on AST
type TaintAnalyzer struct {
	symbolTable *SymbolTable
	sources     []string
	sinks       []string
}

// NewTaintAnalyzer creates a new taint analyzer
func NewTaintAnalyzer(symbolTable *SymbolTable) *TaintAnalyzer {
	return &TaintAnalyzer{
		symbolTable: symbolTable,
		sources:     []string{"_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES"},
		sinks:       []string{"echo", "print", "query", "exec", "system"},
	}
}

// PerformTaintAnalysis performs taint analysis on the AST
func (ta *TaintAnalyzer) PerformTaintAnalysis(ast *ProgramNode) []TaintPath {
	var paths []TaintPath

	// Mark taint sources
	ta.markTaintSources(ast)

	// Propagate taint through data flow
	ta.propagateTaint(ast)

	// Find taint paths to sinks
	paths = ta.findTaintPaths(ast)

	return paths
}

// TaintPath represents a path from taint source to sink
type TaintPath struct {
	Source   Position
	Sink     Position
	Path     []Position
	Severity Severity
}

func (ta *TaintAnalyzer) markTaintSources(ast *ProgramNode) {
	walker := NewASTWalker()
	visitor := &TaintSourceVisitor{analyzer: ta}
	walker.AddVisitor(visitor)
	walker.Walk(ast)
}

func (ta *TaintAnalyzer) propagateTaint(ast *ProgramNode) {
	// Implement taint propagation through assignments and function calls
	walker := NewASTWalker()
	visitor := &TaintPropagationVisitor{analyzer: ta}
	walker.AddVisitor(visitor)
	walker.Walk(ast)
}

func (ta *TaintAnalyzer) findTaintPaths(ast *ProgramNode) []TaintPath {
	var paths []TaintPath

	walker := NewASTWalker()
	visitor := &TaintSinkVisitor{analyzer: ta, paths: &paths}
	walker.AddVisitor(visitor)
	walker.Walk(ast)

	return paths
}

// TaintSourceVisitor marks taint sources
type TaintSourceVisitor struct {
	BaseVisitor
	analyzer *TaintAnalyzer
}

func (v *TaintSourceVisitor) VisitVariable(node *VariableNode) error {
	for _, source := range v.analyzer.sources {
		if node.Name == source {
			if varSymbol, exists := v.analyzer.symbolTable.Variables[node.Name]; exists {
				varSymbol.IsTainted = true
				varSymbol.TaintSources = append(varSymbol.TaintSources, "user_input")
			}
		}
	}
	return nil
}

// TaintPropagationVisitor propagates taint through assignments
type TaintPropagationVisitor struct {
	BaseVisitor
	analyzer *TaintAnalyzer
}

func (v *TaintPropagationVisitor) VisitAssignment(node *AssignmentNode) error {
	// If right side is tainted, mark left side as tainted
	if rightVar, ok := node.Right.(*VariableNode); ok {
		if rightSymbol, exists := v.analyzer.symbolTable.Variables[rightVar.Name]; exists {
			if rightSymbol.IsTainted {
				if leftVar, ok := node.Left.(*VariableNode); ok {
					if leftSymbol, exists := v.analyzer.symbolTable.Variables[leftVar.Name]; exists {
						leftSymbol.IsTainted = true
						leftSymbol.TaintSources = append(leftSymbol.TaintSources, rightSymbol.TaintSources...)
					}
				}
			}
		}
	}
	return nil
}

// TaintSinkVisitor finds taint sinks
type TaintSinkVisitor struct {
	BaseVisitor
	analyzer *TaintAnalyzer
	paths    *[]TaintPath
}

func (v *TaintSinkVisitor) VisitFunctionCall(node *FunctionCallNode) error {
	for _, sink := range v.analyzer.sinks {
		if node.Function == sink {
			// Check if any argument is tainted
			for _, arg := range node.Arguments {
				if varNode, ok := arg.(*VariableNode); ok {
					if varSymbol, exists := v.analyzer.symbolTable.Variables[varNode.Name]; exists {
						if varSymbol.IsTainted {
							path := TaintPath{
								Source:   varSymbol.Symbol.Position,
								Sink:     node.Position,
								Severity: SeverityHigh,
							}
							*v.paths = append(*v.paths, path)
						}
					}
				}
			}
		}
	}
	return nil
}
