package ast

import (
	"fmt"
	"io"
	"time"
)

// ASTParser interface defines the contract for language-specific parsers
type ASTParser interface {
	// Parse parses source code and returns an AST
	Parse(content []byte, filename string) (*ProgramNode, *ParseStats, error)
	
	// GetLanguage returns the language this parser handles
	GetLanguage() string
	
	// GetSupportedExtensions returns file extensions this parser supports
	GetSupportedExtensions() []string
	
	// BuildSymbolTable builds a symbol table from the AST
	BuildSymbolTable(ast *ProgramNode) (*SymbolTable, error)
	
	// ValidateAST validates the AST for correctness
	ValidateAST(ast *ProgramNode) []error
	
	// GetParseOptions returns available parsing options
	GetParseOptions() *ParseOptions
	
	// SetParseOptions sets parsing options
	SetParseOptions(options *ParseOptions)
}

// ParseOptions represents options for parsing
type ParseOptions struct {
	// Include comments in AST
	IncludeComments bool
	
	// Include whitespace nodes
	IncludeWhitespace bool
	
	// Perform semantic analysis
	SemanticAnalysis bool
	
	// Build symbol table
	BuildSymbolTable bool
	
	// Perform taint analysis
	TaintAnalysis bool
	
	// Maximum parse time
	MaxParseTime time.Duration
	
	// Error recovery mode
	ErrorRecovery bool
	
	// Debug mode
	Debug bool
	
	// Language-specific options
	LanguageOptions map[string]interface{}
}

// DefaultParseOptions returns default parsing options
func DefaultParseOptions() *ParseOptions {
	return &ParseOptions{
		IncludeComments:   false,
		IncludeWhitespace: false,
		SemanticAnalysis:  true,
		BuildSymbolTable:  true,
		TaintAnalysis:     true,
		MaxParseTime:      30 * time.Second,
		ErrorRecovery:     true,
		Debug:             false,
		LanguageOptions:   make(map[string]interface{}),
	}
}

// ParserRegistry manages language-specific parsers
type ParserRegistry struct {
	parsers      map[string]ASTParser
	extensions   map[string]ASTParser
	defaultOpts  *ParseOptions
}

// NewParserRegistry creates a new parser registry
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers:     make(map[string]ASTParser),
		extensions:  make(map[string]ASTParser),
		defaultOpts: DefaultParseOptions(),
	}
}

// RegisterParser registers a parser for a language
func (pr *ParserRegistry) RegisterParser(parser ASTParser) {
	language := parser.GetLanguage()
	pr.parsers[language] = parser
	
	for _, ext := range parser.GetSupportedExtensions() {
		pr.extensions[ext] = parser
	}
}

// GetParser returns a parser for the given language
func (pr *ParserRegistry) GetParser(language string) ASTParser {
	return pr.parsers[language]
}

// GetParserByExtension returns a parser for the given file extension
func (pr *ParserRegistry) GetParserByExtension(extension string) ASTParser {
	return pr.extensions[extension]
}

// GetSupportedLanguages returns all supported languages
func (pr *ParserRegistry) GetSupportedLanguages() []string {
	languages := make([]string, 0, len(pr.parsers))
	for lang := range pr.parsers {
		languages = append(languages, lang)
	}
	return languages
}

// GetSupportedExtensions returns all supported file extensions
func (pr *ParserRegistry) GetSupportedExtensions() []string {
	extensions := make([]string, 0, len(pr.extensions))
	for ext := range pr.extensions {
		extensions = append(extensions, ext)
	}
	return extensions
}

// Parse parses content using the appropriate parser
func (pr *ParserRegistry) Parse(content []byte, filename string, language string) (*ProgramNode, *ParseStats, error) {
	var parser ASTParser
	
	if language != "" {
		parser = pr.GetParser(language)
	} else {
		// Try to detect language from filename
		for ext, p := range pr.extensions {
			if len(filename) >= len(ext) && filename[len(filename)-len(ext):] == ext {
				parser = p
				break
			}
		}
	}
	
	if parser == nil {
		return nil, nil, fmt.Errorf("no parser found for language '%s' or filename '%s'", language, filename)
	}
	
	// Set default options if not already set
	if parser.GetParseOptions() == nil {
		parser.SetParseOptions(pr.defaultOpts)
	}
	
	return parser.Parse(content, filename)
}

// BaseASTParser provides common functionality for AST parsers
type BaseASTParser struct {
	language         string
	extensions       []string
	options          *ParseOptions
}

// NewBaseASTParser creates a new base parser
func NewBaseASTParser(language string, extensions []string) *BaseASTParser {
	return &BaseASTParser{
		language:   language,
		extensions: extensions,
		options:    DefaultParseOptions(),
	}
}

// GetLanguage returns the parser language
func (p *BaseASTParser) GetLanguage() string {
	return p.language
}

// GetSupportedExtensions returns supported file extensions
func (p *BaseASTParser) GetSupportedExtensions() []string {
	return p.extensions
}

// GetParseOptions returns parsing options
func (p *BaseASTParser) GetParseOptions() *ParseOptions {
	return p.options
}

// SetParseOptions sets parsing options
func (p *BaseASTParser) SetParseOptions(options *ParseOptions) {
	p.options = options
}

// ValidateAST performs basic AST validation
func (p *BaseASTParser) ValidateAST(ast *ProgramNode) []error {
	var errors []error
	
	// Basic validation - can be overridden by specific parsers
	if ast == nil {
		errors = append(errors, fmt.Errorf("AST is nil"))
		return errors
	}
	
	if ast.Language != p.language {
		errors = append(errors, fmt.Errorf("AST language mismatch: expected %s, got %s", p.language, ast.Language))
	}
	
	return errors
}

// ParseResult represents the result of parsing
type ParseResult struct {
	AST         *ProgramNode
	SymbolTable *SymbolTable
	Stats       *ParseStats
	Errors      []error
	Warnings    []error
}

// ParserError represents a parsing error
type ParserError struct {
	Position Position
	Message  string
	Code     string
	Severity ErrorSeverity
}

type ErrorSeverity int

const (
	ErrorSeverityError ErrorSeverity = iota
	ErrorSeverityWarning
	ErrorSeverityInfo
)

func (e *ParserError) Error() string {
	return fmt.Sprintf("%s:%d:%d: %s", e.Position.Filename, e.Position.Line, e.Position.Column, e.Message)
}

// SyntaxError represents a syntax error
type SyntaxError struct {
	*ParserError
	Expected string
	Actual   string
}

// SemanticError represents a semantic error
type SemanticError struct {
	*ParserError
	Symbol string
	Type   string
}

// ParseResultBuilder helps build parse results
type ParseResultBuilder struct {
	result *ParseResult
}

// NewParseResultBuilder creates a new parse result builder
func NewParseResultBuilder() *ParseResultBuilder {
	return &ParseResultBuilder{
		result: &ParseResult{
			Stats:    &ParseStats{StartTime: time.Now()},
			Errors:   make([]error, 0),
			Warnings: make([]error, 0),
		},
	}
}

// SetAST sets the AST
func (b *ParseResultBuilder) SetAST(ast *ProgramNode) *ParseResultBuilder {
	b.result.AST = ast
	return b
}

// SetSymbolTable sets the symbol table
func (b *ParseResultBuilder) SetSymbolTable(st *SymbolTable) *ParseResultBuilder {
	b.result.SymbolTable = st
	return b
}

// AddError adds an error
func (b *ParseResultBuilder) AddError(err error) *ParseResultBuilder {
	b.result.Errors = append(b.result.Errors, err)
	b.result.Stats.AddError(err)
	return b
}

// AddWarning adds a warning
func (b *ParseResultBuilder) AddWarning(err error) *ParseResultBuilder {
	b.result.Warnings = append(b.result.Warnings, err)
	b.result.Stats.AddWarning(err)
	return b
}

// Build builds the final result
func (b *ParseResultBuilder) Build() *ParseResult {
	b.result.Stats.EndTime = time.Now()
	b.result.Stats.Duration = b.result.Stats.EndTime.Sub(b.result.Stats.StartTime)
	return b.result
}

// TokenPosition represents a token position for error reporting
type TokenPosition struct {
	Line   int
	Column int
	Offset int
	Length int
}

// ASTWalker provides utilities for walking AST
type ASTWalker struct {
	visitors []NodeVisitor
}

// NewASTWalker creates a new AST walker
func NewASTWalker() *ASTWalker {
	return &ASTWalker{
		visitors: make([]NodeVisitor, 0),
	}
}

// AddVisitor adds a visitor to the walker
func (w *ASTWalker) AddVisitor(visitor NodeVisitor) {
	w.visitors = append(w.visitors, visitor)
}

// Walk walks the AST and applies all visitors
func (w *ASTWalker) Walk(node ASTNode) error {
	for _, visitor := range w.visitors {
		if err := node.Accept(visitor); err != nil {
			return err
		}
	}
	
	// Walk children
	for _, child := range node.GetChildren() {
		if err := w.Walk(child); err != nil {
			return err
		}
	}
	
	return nil
}

// ASTTransformer provides utilities for transforming AST
type ASTTransformer interface {
	Transform(node ASTNode) (ASTNode, error)
}

// SecurityAnalyzer performs security analysis on AST
type SecurityAnalyzer struct {
	symbolTable *SymbolTable
	rules       []SecurityRule
}

// SecurityRule represents a security analysis rule
type SecurityRule interface {
	Check(node ASTNode, st *SymbolTable) []SecurityFinding
	GetID() string
	GetName() string
	GetSeverity() Severity
}

// SecurityFinding represents a security finding
type SecurityFinding struct {
	RuleID      string
	Message     string
	Position    Position
	Severity    Severity
	CWE         string
	OWASP       string
	Confidence  int
	Context     string
}

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// NewSecurityAnalyzer creates a new security analyzer
func NewSecurityAnalyzer(st *SymbolTable) *SecurityAnalyzer {
	return &SecurityAnalyzer{
		symbolTable: st,
		rules:       make([]SecurityRule, 0),
	}
}

// AddRule adds a security rule
func (sa *SecurityAnalyzer) AddRule(rule SecurityRule) {
	sa.rules = append(sa.rules, rule)
}

// Analyze performs security analysis on AST
func (sa *SecurityAnalyzer) Analyze(ast *ProgramNode) ([]SecurityFinding, error) {
	var findings []SecurityFinding
	
	walker := NewASTWalker()
	
	// Add security analysis visitor
	visitor := &SecurityVisitor{
		analyzer: sa,
		findings: &findings,
	}
	walker.AddVisitor(visitor)
	
	err := walker.Walk(ast)
	return findings, err
}

// SecurityVisitor implements NodeVisitor for security analysis
type SecurityVisitor struct {
	BaseVisitor
	analyzer *SecurityAnalyzer
	findings *[]SecurityFinding
}

// Visit checks security rules for each node
func (v *SecurityVisitor) Visit(node ASTNode) error {
	for _, rule := range v.analyzer.rules {
		ruleFindings := rule.Check(node, v.analyzer.symbolTable)
		*v.findings = append(*v.findings, ruleFindings...)
	}
	return nil
}

// DebugPrinter provides AST debugging utilities
type DebugPrinter struct {
	writer io.Writer
	indent int
}

// NewDebugPrinter creates a new debug printer
func NewDebugPrinter(writer io.Writer) *DebugPrinter {
	return &DebugPrinter{
		writer: writer,
		indent: 0,
	}
}

// PrintAST prints the AST structure
func (dp *DebugPrinter) PrintAST(node ASTNode) {
	dp.printNode(node)
	for _, child := range node.GetChildren() {
		dp.indent++
		dp.PrintAST(child)
		dp.indent--
	}
}

func (dp *DebugPrinter) printNode(node ASTNode) {
	for i := 0; i < dp.indent; i++ {
		fmt.Fprint(dp.writer, "  ")
	}
	fmt.Fprintf(dp.writer, "%s\n", node.String())
}

// ASTMetrics provides AST metrics
type ASTMetrics struct {
	NodeCount      int
	FunctionCount  int
	ClassCount     int
	VariableCount  int
	MaxDepth       int
	CyclomaticComplexity int
}

// CalculateMetrics calculates AST metrics
func CalculateMetrics(ast *ProgramNode) *ASTMetrics {
	metrics := &ASTMetrics{}
	
	walker := NewASTWalker()
	visitor := &MetricsVisitor{metrics: metrics}
	walker.AddVisitor(visitor)
	walker.Walk(ast)
	
	return metrics
}

// MetricsVisitor implements NodeVisitor for metrics calculation
type MetricsVisitor struct {
	BaseVisitor
	metrics *ASTMetrics
	depth   int
}

// Visit calculates metrics for each node
func (v *MetricsVisitor) Visit(node ASTNode) error {
	v.metrics.NodeCount++
	
	if v.depth > v.metrics.MaxDepth {
		v.metrics.MaxDepth = v.depth
	}
	
	return nil
}

// VisitFunction counts functions
func (v *MetricsVisitor) VisitFunction(node *FunctionNode) error {
	v.metrics.FunctionCount++
	v.depth++
	defer func() { v.depth-- }()
	return nil
}

// VisitClass counts classes
func (v *MetricsVisitor) VisitClass(node *ClassNode) error {
	v.metrics.ClassCount++
	return nil
}

// VisitVariable counts variables
func (v *MetricsVisitor) VisitVariable(node *VariableNode) error {
	v.metrics.VariableCount++
	return nil
}