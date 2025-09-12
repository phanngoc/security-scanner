package rules

import (
	"fmt"
	"strings"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/lsp"
)

// SymbolBasedRule represents a security rule that uses symbol table analysis
type SymbolBasedRule struct {
	*Rule
	SymbolMatchers []SymbolMatcher `json:"symbol_matchers"`
	FlowAnalyzers  []FlowAnalyzer  `json:"flow_analyzers"`
	TaintRules     []TaintRule     `json:"taint_rules"`
}

// SymbolMatcher defines how to match symbols for security analysis
type SymbolMatcher struct {
	SymbolKinds    []lsp.SymbolKind    `json:"symbol_kinds"`
	NamePatterns   []string            `json:"name_patterns"`
	SecurityFlags  SecurityFlagMatcher `json:"security_flags"`
	CallGraphRules []CallGraphRule     `json:"call_graph_rules"`
}

// SecurityFlagMatcher matches security flags in symbols
type SecurityFlagMatcher struct {
	RequireUserInput   bool `json:"require_user_input"`
	RequireSQLQuery    bool `json:"require_sql_query"`
	RequireCommand     bool `json:"require_command"`
	RequireFilesystem  bool `json:"require_filesystem"`
	RequireAuth        bool `json:"require_auth"`
	RequireCrypto      bool `json:"require_crypto"`
	RequireTaintedData bool `json:"require_tainted_data"`
}

// CallGraphRule analyzes function call patterns
type CallGraphRule struct {
	CallerPattern  string   `json:"caller_pattern"`
	CalleePatterns []string `json:"callee_patterns"`
	CallDepth      int      `json:"call_depth"`
	RiskLevel      string   `json:"risk_level"`
}

// FlowAnalyzer analyzes data flow for security vulnerabilities
type FlowAnalyzer struct {
	SourcePatterns []string `json:"source_patterns"`
	SinkPatterns   []string `json:"sink_patterns"`
	SanitizeRules  []string `json:"sanitize_rules"`
	FlowType       string   `json:"flow_type"` // "taint", "control", "data"
}

// TaintRule defines taint analysis rules
type TaintRule struct {
	TaintSources     []TaintSource     `json:"taint_sources"`
	TaintSinks       []TaintSink       `json:"taint_sinks"`
	Sanitizers       []Sanitizer       `json:"sanitizers"`
	PropagationRules []PropagationRule `json:"propagation_rules"`
}

// TaintSource represents a source of tainted data
type TaintSource struct {
	SymbolPattern string   `json:"symbol_pattern"`
	TaintTypes    []string `json:"taint_types"`
	Confidence    float64  `json:"confidence"`
}

// TaintSink represents a dangerous operation that shouldn't receive tainted data
type TaintSink struct {
	SymbolPattern string               `json:"symbol_pattern"`
	DangerousArgs []int                `json:"dangerous_args"`
	TaintTypes    []string             `json:"taint_types"`
	Severity      config.SeverityLevel `json:"severity"`
}

// Sanitizer represents a function that cleans tainted data
type Sanitizer struct {
	SymbolPattern string   `json:"symbol_pattern"`
	CleanedTypes  []string `json:"cleaned_types"`
	Effectiveness float64  `json:"effectiveness"`
}

// PropagationRule defines how taint propagates through operations
type PropagationRule struct {
	Operation     string `json:"operation"`
	InputArgs     []int  `json:"input_args"`
	OutputTainted bool   `json:"output_tainted"`
}

// SymbolBasedAnalyzer performs security analysis using symbol tables
type SymbolBasedAnalyzer struct {
	rules  map[VulnerabilityType]*SymbolBasedRule
	logger interface{} // zap.Logger interface
}

// NewSymbolBasedAnalyzer creates a new symbol-based analyzer
func NewSymbolBasedAnalyzer() *SymbolBasedAnalyzer {
	analyzer := &SymbolBasedAnalyzer{
		rules: make(map[VulnerabilityType]*SymbolBasedRule),
	}

	analyzer.initializeSymbolBasedRules()
	return analyzer
}

// initializeSymbolBasedRules initializes enhanced security rules
func (sba *SymbolBasedAnalyzer) initializeSymbolBasedRules() {
	// SQL Injection - Symbol-based analysis
	sba.addSymbolRule(&SymbolBasedRule{
		Rule: &Rule{
			ID:          "SYMBOL-SQL-001",
			Type:        SQLInjection,
			Name:        "SQL Injection via Symbol Analysis",
			Description: "Detects SQL injection vulnerabilities through data flow analysis",
			Severity:    config.SeverityCritical,
			Languages:   []string{"go", "php", "java", "python", "javascript"},
			OWASP:       OWASPReference{Top10_2021: "A03:2021", Category: "Injection"},
			CWE:         "CWE-89",
			Remediation: "Use parameterized queries and validate all user inputs",
		},
		FlowAnalyzers: []FlowAnalyzer{
			{
				SourcePatterns: []string{
					"$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
					"request.query", "request.body", "request.params",
					"http.Request", "r.URL.Query", "r.Form",
				},
				SinkPatterns: []string{
					"mysql_query", "mysqli_query", "pg_query",
					"db.Query", "db.Exec", "database/sql.Query",
					"SELECT", "INSERT", "UPDATE", "DELETE",
				},
				SanitizeRules: []string{
					"mysqli_real_escape_string", "pg_escape_string",
					"Prepare", "prepare", "bindParam", "bindValue",
				},
				FlowType: "taint",
			},
		},
		TaintRules: []TaintRule{
			{
				TaintSources: []TaintSource{
					{SymbolPattern: "user_input", TaintTypes: []string{"sql_injection"}, Confidence: 0.9},
					{SymbolPattern: "external_data", TaintTypes: []string{"sql_injection"}, Confidence: 0.8},
				},
				TaintSinks: []TaintSink{
					{
						SymbolPattern: "sql_query",
						DangerousArgs: []int{0, 1}, // First and second arguments
						TaintTypes:    []string{"sql_injection"},
						Severity:      config.SeverityCritical,
					},
				},
				Sanitizers: []Sanitizer{
					{SymbolPattern: "escape_sql", CleanedTypes: []string{"sql_injection"}, Effectiveness: 0.95},
					{SymbolPattern: "prepare_statement", CleanedTypes: []string{"sql_injection"}, Effectiveness: 0.99},
				},
			},
		},
		SymbolMatchers: []SymbolMatcher{
			{
				SymbolKinds:  []lsp.SymbolKind{lsp.SymbolKindFunction, lsp.SymbolKindMethod},
				NamePatterns: []string{"query", "execute", "prepare"},
				SecurityFlags: SecurityFlagMatcher{
					RequireUserInput: true,
					RequireSQLQuery:  true,
				},
			},
		},
	})

	// XSS - Symbol-based analysis
	sba.addSymbolRule(&SymbolBasedRule{
		Rule: &Rule{
			ID:          "SYMBOL-XSS-001",
			Type:        XSS,
			Name:        "Cross-Site Scripting via Symbol Analysis",
			Description: "Detects XSS vulnerabilities through output context analysis",
			Severity:    config.SeverityHigh,
			Languages:   []string{"php", "javascript", "java", "python"},
			OWASP:       OWASPReference{Top10_2021: "A03:2021", Category: "Injection"},
			CWE:         "CWE-79",
			Remediation: "Always encode output data according to context",
		},
		FlowAnalyzers: []FlowAnalyzer{
			{
				SourcePatterns: []string{
					"$_GET", "$_POST", "$_REQUEST",
					"request.query", "request.body",
					"user_input", "external_data",
				},
				SinkPatterns: []string{
					"echo", "print", "printf", "innerHTML", "outerHTML",
					"document.write", "response.write", "HttpResponse.Write",
				},
				SanitizeRules: []string{
					"htmlspecialchars", "htmlentities", "strip_tags",
					"encodeURIComponent", "escapeHtml", "sanitizeHtml",
				},
				FlowType: "taint",
			},
		},
		SymbolMatchers: []SymbolMatcher{
			{
				SymbolKinds:  []lsp.SymbolKind{lsp.SymbolKindFunction, lsp.SymbolKindMethod},
				NamePatterns: []string{"echo", "print", "write", "render"},
				SecurityFlags: SecurityFlagMatcher{
					RequireUserInput: true,
				},
			},
		},
	})

	// Command Injection - Symbol-based analysis
	sba.addSymbolRule(&SymbolBasedRule{
		Rule: &Rule{
			ID:          "SYMBOL-CMD-001",
			Type:        CommandInjection,
			Name:        "Command Injection via Symbol Analysis",
			Description: "Detects command injection through system call analysis",
			Severity:    config.SeverityCritical,
			Languages:   []string{"php", "python", "java", "go"},
			OWASP:       OWASPReference{Top10_2021: "A03:2021", Category: "Injection"},
			CWE:         "CWE-78",
			Remediation: "Never pass user input to system commands. Use parameterized APIs.",
		},
		FlowAnalyzers: []FlowAnalyzer{
			{
				SourcePatterns: []string{
					"$_GET", "$_POST", "$_REQUEST",
					"request.query", "request.body",
					"os.Args", "command_line_args",
				},
				SinkPatterns: []string{
					"system", "exec", "shell_exec", "passthru",
					"os.system", "subprocess.call", "Runtime.exec",
					"exec.Command", "cmd.Exec",
				},
				SanitizeRules: []string{
					"escapeshellarg", "escapeshellcmd", "shlex.quote",
					"whitelist_validation", "command_sanitizer",
				},
				FlowType: "taint",
			},
		},
		SymbolMatchers: []SymbolMatcher{
			{
				SymbolKinds:  []lsp.SymbolKind{lsp.SymbolKindFunction},
				NamePatterns: []string{"system", "exec", "command", "shell"},
				SecurityFlags: SecurityFlagMatcher{
					RequireUserInput: true,
					RequireCommand:   true,
				},
			},
		},
	})

	// Hardcoded Secrets - Enhanced symbol analysis
	sba.addSymbolRule(&SymbolBasedRule{
		Rule: &Rule{
			ID:          "SYMBOL-SECRET-001",
			Type:        HardcodedSecrets,
			Name:        "Hardcoded Secrets via Symbol Analysis",
			Description: "Detects hardcoded secrets through variable analysis",
			Severity:    config.SeverityHigh,
			Languages:   []string{"*"},
			OWASP:       OWASPReference{Top10_2021: "A02:2021", Category: "Cryptographic Failures"},
			CWE:         "CWE-798",
			Remediation: "Use environment variables or secure configuration management",
		},
		SymbolMatchers: []SymbolMatcher{
			{
				SymbolKinds: []lsp.SymbolKind{
					lsp.SymbolKindVariable,
					lsp.SymbolKindConstant,
					lsp.SymbolKindField,
				},
				NamePatterns: []string{
					"password", "passwd", "pwd", "secret", "key",
					"token", "api_key", "apikey", "private_key",
					"credential", "auth", "certificate",
				},
			},
		},
	})
}

// AnalyzeSymbolTable performs security analysis on a symbol table
func (sba *SymbolBasedAnalyzer) AnalyzeSymbolTable(symbolTable *lsp.SymbolTable) []*SecurityFinding {
	var findings []*SecurityFinding

	// Get symbols with security concerns
	vulnerableSymbols := symbolTable.GetSecurityVulnerabilities()

	for _, symbol := range vulnerableSymbols {
		// Run symbol-based rules
		for _, rule := range sba.rules {
			if ruleFindings := sba.analyzeSymbolWithRule(symbol, rule, symbolTable); len(ruleFindings) > 0 {
				findings = append(findings, ruleFindings...)
			}
		}
	}

	// Perform flow analysis
	flowFindings := sba.performFlowAnalysis(symbolTable)
	findings = append(findings, flowFindings...)

	// Perform taint analysis
	taintFindings := sba.performTaintAnalysis(symbolTable)
	findings = append(findings, taintFindings...)

	return findings
}

// analyzeSymbolWithRule analyzes a symbol against a specific rule
func (sba *SymbolBasedAnalyzer) analyzeSymbolWithRule(symbol *lsp.ScopeNode, rule *SymbolBasedRule, symbolTable *lsp.SymbolTable) []*SecurityFinding {
	var findings []*SecurityFinding

	// Check if rule applies to this symbol
	if !sba.ruleAppliesToSymbol(symbol, rule) {
		return findings
	}

	// Check symbol matchers
	for _, matcher := range rule.SymbolMatchers {
		if sba.symbolMatchesPattern(symbol, matcher) {
			finding := &SecurityFinding{
				RuleID:      rule.ID,
				Type:        rule.Type,
				Severity:    rule.Severity,
				Title:       rule.Name,
				Description: sba.generateContextualDescription(rule, symbol),
				Location:    sba.symbolToLocation(symbol, symbolTable),
				Symbol:      symbol,
				Confidence:  sba.calculateConfidence(symbol, matcher),
				Context:     sba.extractSymbolContext(symbol, symbolTable),
				Remediation: rule.Remediation,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// performFlowAnalysis performs data flow analysis
func (sba *SymbolBasedAnalyzer) performFlowAnalysis(symbolTable *lsp.SymbolTable) []*SecurityFinding {
	var findings []*SecurityFinding

	for _, rule := range sba.rules {
		for _, flowAnalyzer := range rule.FlowAnalyzers {
			if flowFindings := sba.analyzeDataFlow(symbolTable, rule, flowAnalyzer); len(flowFindings) > 0 {
				findings = append(findings, flowFindings...)
			}
		}
	}

	return findings
}

// performTaintAnalysis performs taint analysis
func (sba *SymbolBasedAnalyzer) performTaintAnalysis(symbolTable *lsp.SymbolTable) []*SecurityFinding {
	var findings []*SecurityFinding

	for _, rule := range sba.rules {
		for _, taintRule := range rule.TaintRules {
			if taintFindings := sba.analyzeTaintFlow(symbolTable, rule, taintRule); len(taintFindings) > 0 {
				findings = append(findings, taintFindings...)
			}
		}
	}

	return findings
}

// Helper methods

func (sba *SymbolBasedAnalyzer) addSymbolRule(rule *SymbolBasedRule) {
	sba.rules[rule.Type] = rule
}

func (sba *SymbolBasedAnalyzer) ruleAppliesToSymbol(symbol *lsp.ScopeNode, rule *SymbolBasedRule) bool {
	// Check if rule applies to the symbol's language or is universal
	return len(rule.Languages) == 0 ||
		contains(rule.Languages, "*") ||
		contains(rule.Languages, strings.ToLower(string(symbol.Kind)))
}

func (sba *SymbolBasedAnalyzer) symbolMatchesPattern(symbol *lsp.ScopeNode, matcher SymbolMatcher) bool {
	// Check symbol kind
	if len(matcher.SymbolKinds) > 0 && !containsSymbolKind(matcher.SymbolKinds, symbol.Kind) {
		return false
	}

	// Check name patterns
	if len(matcher.NamePatterns) > 0 && !sba.nameMatchesPatterns(symbol.Name, matcher.NamePatterns) {
		return false
	}

	// Check security flags
	return sba.securityFlagsMatch(symbol.SecurityFlags, matcher.SecurityFlags)
}

func (sba *SymbolBasedAnalyzer) nameMatchesPatterns(name string, patterns []string) bool {
	lowerName := strings.ToLower(name)
	for _, pattern := range patterns {
		if strings.Contains(lowerName, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (sba *SymbolBasedAnalyzer) securityFlagsMatch(flags lsp.SecurityFlags, matcher SecurityFlagMatcher) bool {
	if matcher.RequireUserInput && !flags.HandlesUserInput {
		return false
	}
	if matcher.RequireSQLQuery && !flags.ExecutesSQLQueries {
		return false
	}
	if matcher.RequireCommand && !flags.ExecutesCommands {
		return false
	}
	if matcher.RequireFilesystem && !flags.AccessesFilesystem {
		return false
	}
	if matcher.RequireAuth && !flags.HandlesAuthentication {
		return false
	}
	if matcher.RequireCrypto && !flags.UsesCrypto {
		return false
	}
	if matcher.RequireTaintedData && len(flags.TaintedSources) == 0 {
		return false
	}
	return true
}

func (sba *SymbolBasedAnalyzer) generateContextualDescription(rule *SymbolBasedRule, symbol *lsp.ScopeNode) string {
	return fmt.Sprintf("%s detected in symbol '%s' (%s)",
		rule.Description, symbol.Name, symbol.NamePath)
}

func (sba *SymbolBasedAnalyzer) symbolToLocation(symbol *lsp.ScopeNode, symbolTable *lsp.SymbolTable) Location {
	return Location{
		File:   symbolTable.FileURI,
		Line:   symbol.Range.Start.Line + 1,
		Column: symbol.Range.Start.Character + 1,
		Range:  symbol.Range,
	}
}

func (sba *SymbolBasedAnalyzer) calculateConfidence(symbol *lsp.ScopeNode, matcher SymbolMatcher) int {
	confidence := 50 // Base confidence

	// Increase confidence based on security flags
	if symbol.SecurityFlags.HandlesUserInput {
		confidence += 20
	}
	if symbol.SecurityFlags.ExecutesSQLQueries {
		confidence += 25
	}
	if symbol.SecurityFlags.ExecutesCommands {
		confidence += 25
	}
	if len(symbol.SecurityFlags.TaintedSources) > 0 {
		confidence += 15
	}

	// Cap at 100
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}

func (sba *SymbolBasedAnalyzer) extractSymbolContext(symbol *lsp.ScopeNode, symbolTable *lsp.SymbolTable) []string {
	var context []string

	// Add symbol information
	context = append(context, fmt.Sprintf("Symbol: %s (%s)", symbol.Name, symbol.Kind))
	context = append(context, fmt.Sprintf("Path: %s", symbol.NamePath))

	if symbol.Detail != "" {
		context = append(context, fmt.Sprintf("Detail: %s", symbol.Detail))
	}

	// Add security flags
	flags := symbol.SecurityFlags
	if flags.HandlesUserInput {
		context = append(context, "⚠️  Handles user input")
	}
	if flags.ExecutesSQLQueries {
		context = append(context, "⚠️  Executes SQL queries")
	}
	if flags.ExecutesCommands {
		context = append(context, "⚠️  Executes system commands")
	}
	if len(flags.TaintedSources) > 0 {
		context = append(context, fmt.Sprintf("⚠️  Tainted sources: %s", strings.Join(flags.TaintedSources, ", ")))
	}

	return context
}

func (sba *SymbolBasedAnalyzer) analyzeDataFlow(symbolTable *lsp.SymbolTable, rule *SymbolBasedRule, analyzer FlowAnalyzer) []*SecurityFinding {
	// This would implement sophisticated data flow analysis
	// For now, return empty slice - this is a complex algorithm that would require
	// building control flow graphs and tracking variable assignments
	return []*SecurityFinding{}
}

func (sba *SymbolBasedAnalyzer) analyzeTaintFlow(symbolTable *lsp.SymbolTable, rule *SymbolBasedRule, taintRule TaintRule) []*SecurityFinding {
	// This would implement taint analysis
	// Similar to data flow analysis, this is complex and would require
	// tracking how tainted data propagates through the program
	return []*SecurityFinding{}
}

// SecurityFinding represents a security finding from symbol analysis
type SecurityFinding struct {
	RuleID      string               `json:"rule_id"`
	Type        VulnerabilityType    `json:"type"`
	Severity    config.SeverityLevel `json:"severity"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Location    Location             `json:"location"`
	Symbol      *lsp.ScopeNode       `json:"symbol,omitempty"`
	Confidence  int                  `json:"confidence"`
	Context     []string             `json:"context"`
	Remediation string               `json:"remediation"`
}

// Location represents a location in source code
type Location struct {
	File   string    `json:"file"`
	Line   int       `json:"line"`
	Column int       `json:"column"`
	Range  lsp.Range `json:"range"`
}

// Utility functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsSymbolKind(slice []lsp.SymbolKind, item lsp.SymbolKind) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
