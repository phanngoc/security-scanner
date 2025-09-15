package hir

import (
	"fmt"
	"go/token"
	"regexp"
	"strings"
)

// CFGRuleEngine provides precise vulnerability detection using CFG analysis
type CFGRuleEngine struct {
	program     *HIRProgram
	cfgBuilder  *AdvancedCFGBuilder
	rules       []*CFGSecurityRule
	taintEngine *CFGTaintAnalyzer
}

// CFGSecurityRule represents a CFG-based security detection rule
type CFGSecurityRule struct {
	ID          string
	Name        string
	Description string
	OWASP       string
	CWE         string
	Severity    Severity
	Language    string

	// CFG-based detection patterns
	SourcePatterns []CFGPattern
	SinkPatterns   []CFGPattern
	FlowRules      []CFGFlowRule
	ContextRules   []CFGContextRule
}

// CFGPattern represents patterns detectable through CFG analysis
type CFGPattern struct {
	Type        CFGPatternType
	StmtType    HIRStmtType
	FunctionCall string
	Parameters   []string
	Conditions   []CFGCondition
	TaintFlow    TaintFlowPattern
}

type CFGPatternType int

const (
	PatternSource CFGPatternType = iota // Taint source
	PatternSink                         // Vulnerability sink
	PatternSanitizer                    // Sanitization function
	PatternValidator                    // Validation function
	PatternBarrier                      // Security barrier
)

// CFGFlowRule defines data flow requirements for vulnerability detection
type CFGFlowRule struct {
	SourceRequired bool
	SinkRequired   bool
	PathRequired   bool
	NoSanitizerBetween bool
	MaxHops        int
	AllowedPaths   []string
}

// CFGContextRule defines context requirements for vulnerability detection
type CFGContextRule struct {
	RequiredContext []string
	ForbiddenContext []string
	ScopeRestriction ScopeType
	CallDepthLimit   int
}

// CFGCondition represents conditions for pattern matching
type CFGCondition struct {
	Field    string
	Operator ConditionOperator
	Value    interface{}
}

type ConditionOperator int

const (
	OpEquals ConditionOperator = iota
	OpContains
	OpStartsWith
	OpRegex
	OpExists
	OpNotExists
)

// TaintFlowPattern defines taint propagation patterns
type TaintFlowPattern struct {
	Propagates   bool
	Sources      []TaintKind
	Sinks        []TaintKind
	Transformers []string
}

// CFGTaintAnalyzer performs CFG-based taint analysis
type CFGTaintAnalyzer struct {
	program *HIRProgram
	taintedVars map[VariableID]*TaintState
	flowPaths   []*DataFlowPath
}

// TaintState tracks taint information for variables
type TaintState struct {
	Variable     *Variable
	IsTainted    bool
	Sources      []TaintSource
	PropagatedTo []VariableID
	SanitizedBy  []string
	LastUpdate   token.Pos
}

// DataFlowPath represents a path from source to sink
type DataFlowPath struct {
	ID          string
	Source      *TaintSource
	Sink        *SinkLocation
	Path        []*CFGNode
	Variables   []VariableID
	Sanitized   bool
	Confidence  float64
}

// NewCFGRuleEngine creates a new CFG-based rule engine
func NewCFGRuleEngine(program *HIRProgram) *CFGRuleEngine {
	engine := &CFGRuleEngine{
		program:     program,
		cfgBuilder:  NewAdvancedCFGBuilder(program),
		rules:       make([]*CFGSecurityRule, 0),
		taintEngine: NewCFGTaintAnalyzer(program),
	}

	engine.loadSecurityRules()
	return engine
}

// loadSecurityRules loads predefined security rules for OWASP patterns
func (engine *CFGRuleEngine) loadSecurityRules() {
	// SQL Injection Rule (OWASP A03)
	engine.rules = append(engine.rules, &CFGSecurityRule{
		ID:          "CFG-SQL-001",
		Name:        "SQL Injection via String Concatenation",
		Description: "Detects SQL injection through direct string concatenation",
		OWASP:       "A03:2021",
		CWE:         "CWE-89",
		Severity:    SeverityHigh,
		Language:    "php",
		SourcePatterns: []CFGPattern{
			{
				Type:     PatternSource,
				StmtType: HIRCall,
				FunctionCall: "getQuery|getData|getPost|request",
				TaintFlow: TaintFlowPattern{
					Propagates: true,
					Sources:    []TaintKind{TaintUserInput},
				},
			},
		},
		SinkPatterns: []CFGPattern{
			{
				Type:     PatternSink,
				StmtType: HIRCall,
				FunctionCall: "execute|query|mysql_query|mysqli_query",
				TaintFlow: TaintFlowPattern{
					Sinks: []TaintKind{TaintDatabase},
				},
			},
		},
		FlowRules: []CFGFlowRule{
			{
				SourceRequired:     true,
				SinkRequired:       true,
				PathRequired:       true,
				NoSanitizerBetween: true,
				MaxHops:            10,
			},
		},
	})

	// XSS Rule (OWASP A03)
	engine.rules = append(engine.rules, &CFGSecurityRule{
		ID:          "CFG-XSS-001",
		Name:        "Cross-Site Scripting via Direct Output",
		Description: "Detects XSS through unescaped user input output",
		OWASP:       "A03:2021",
		CWE:         "CWE-79",
		Severity:    SeverityHigh,
		Language:    "php",
		SourcePatterns: []CFGPattern{
			{
				Type:     PatternSource,
				StmtType: HIRCall,
				FunctionCall: "getQuery|getData|getPost|request",
				TaintFlow: TaintFlowPattern{
					Propagates: true,
					Sources:    []TaintKind{TaintUserInput},
				},
			},
		},
		SinkPatterns: []CFGPattern{
			{
				Type:     PatternSink,
				StmtType: HIREcho,
				FunctionCall: "echo|print|printf|response->body",
				TaintFlow: TaintFlowPattern{
					Sinks: []TaintKind{TaintUserInput},
				},
			},
		},
		FlowRules: []CFGFlowRule{
			{
				SourceRequired:     true,
				SinkRequired:       true,
				NoSanitizerBetween: true,
				MaxHops:            8,
			},
		},
	})

	// Path Traversal Rule (OWASP A01)
	engine.rules = append(engine.rules, &CFGSecurityRule{
		ID:          "CFG-PATH-001",
		Name:        "Path Traversal via File Operations",
		Description: "Detects path traversal through unsafe file operations",
		OWASP:       "A01:2021",
		CWE:         "CWE-22",
		Severity:    SeverityHigh,
		Language:    "php",
		SourcePatterns: []CFGPattern{
			{
				Type:     PatternSource,
				StmtType: HIRCall,
				FunctionCall: "getQuery|getData|getPost",
				TaintFlow: TaintFlowPattern{
					Propagates: true,
					Sources:    []TaintKind{TaintUserInput},
				},
			},
		},
		SinkPatterns: []CFGPattern{
			{
				Type:     PatternSink,
				StmtType: HIRCall,
				FunctionCall: "file_get_contents|fopen|include|require|readfile|unlink|copy|rename",
				TaintFlow: TaintFlowPattern{
					Sinks: []TaintKind{TaintFile},
				},
			},
		},
		FlowRules: []CFGFlowRule{
			{
				SourceRequired:     true,
				SinkRequired:       true,
				NoSanitizerBetween: true,
				MaxHops:            6,
			},
		},
	})

	// Command Injection Rule (OWASP A03)
	engine.rules = append(engine.rules, &CFGSecurityRule{
		ID:          "CFG-CMD-001",
		Name:        "Command Injection via System Calls",
		Description: "Detects command injection through system execution",
		OWASP:       "A03:2021",
		CWE:         "CWE-78",
		Severity:    SeverityCritical,
		Language:    "php",
		SourcePatterns: []CFGPattern{
			{
				Type:     PatternSource,
				StmtType: HIRCall,
				FunctionCall: "getQuery|getData|getPost",
				TaintFlow: TaintFlowPattern{
					Propagates: true,
					Sources:    []TaintKind{TaintUserInput},
				},
			},
		},
		SinkPatterns: []CFGPattern{
			{
				Type:     PatternSink,
				StmtType: HIRCall,
				FunctionCall: "system|exec|shell_exec|passthru|popen|proc_open",
				TaintFlow: TaintFlowPattern{
					Sinks: []TaintKind{TaintNetwork},
				},
			},
		},
		FlowRules: []CFGFlowRule{
			{
				SourceRequired:     true,
				SinkRequired:       true,
				NoSanitizerBetween: true,
				MaxHops:            5,
			},
		},
	})
}

// AnalyzeWithCFG performs comprehensive CFG-based security analysis
func (engine *CFGRuleEngine) AnalyzeWithCFG(filePath string, content []byte) []*SecurityFinding {
	findings := make([]*SecurityFinding, 0)

	// Parse file and build HIR
	hirFile, err := engine.parseFileToHIR(filePath, content)
	if err != nil {
		return findings
	}

	// Build CFGs for all functions
	for _, unit := range hirFile.Units {
		if unit.Symbol.Kind == SymFunction || unit.Symbol.Kind == SymMethod {
			cfg, err := engine.cfgBuilder.BuildAdvancedCFG(unit.Symbol, unit)
			if err != nil {
				continue
			}

			// Perform CFG-based rule analysis
			unitFindings := engine.analyzeCFGUnit(cfg, unit)
			findings = append(findings, unitFindings...)
		}
	}

	// Perform interprocedural analysis
	interFindings := engine.performInterproceduralAnalysis(hirFile)
	findings = append(findings, interFindings...)

	return findings
}

// analyzeCFGUnit analyzes a single CFG unit for vulnerabilities
func (engine *CFGRuleEngine) analyzeCFGUnit(cfg *CFG, unit *HIRUnit) []*SecurityFinding {
	findings := make([]*SecurityFinding, 0)

	// Initialize taint analysis for this CFG
	engine.taintEngine.InitializeForCFG(cfg)

	// Apply each security rule
	for _, rule := range engine.rules {
		if rule.Language != "" && rule.Language != "php" {
			continue // Skip non-matching language rules
		}

		ruleFindings := engine.applyRuleToCFG(rule, cfg, unit)
		findings = append(findings, ruleFindings...)
	}

	return findings
}

// applyRuleToCFG applies a specific rule to a CFG
func (engine *CFGRuleEngine) applyRuleToCFG(rule *CFGSecurityRule, cfg *CFG, unit *HIRUnit) []*SecurityFinding {
	findings := make([]*SecurityFinding, 0)

	// Find sources and sinks
	sources := engine.findSourcesInCFG(cfg, rule.SourcePatterns)
	sinks := engine.findSinksInCFG(cfg, rule.SinkPatterns)

	// Check flow rules
	for _, flowRule := range rule.FlowRules {
		if flowRule.SourceRequired && len(sources) == 0 {
			continue
		}
		if flowRule.SinkRequired && len(sinks) == 0 {
			continue
		}

		// Find data flow paths from sources to sinks
		paths := engine.findDataFlowPaths(cfg, sources, sinks, flowRule)

		for _, path := range paths {
			if engine.validateFlowRule(path, flowRule) {
				finding := engine.createFindingFromPath(rule, path, unit)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// findSourcesInCFG finds taint sources in a CFG based on patterns
func (engine *CFGRuleEngine) findSourcesInCFG(cfg *CFG, patterns []CFGPattern) []*SourceLocation {
	sources := make([]*SourceLocation, 0)

	for _, node := range cfg.Nodes {
		for _, stmt := range node.Block.Stmts {
			for _, pattern := range patterns {
				if engine.matchesPattern(stmt, pattern) {
					source := &SourceLocation{
						Position: stmt.Position,
						Type:     SourceUserInput,
						Variable: engine.extractVariableID(stmt),
					}
					sources = append(sources, source)
				}
			}
		}
	}

	return sources
}

// findSinksInCFG finds vulnerability sinks in a CFG based on patterns
func (engine *CFGRuleEngine) findSinksInCFG(cfg *CFG, patterns []CFGPattern) []*SinkLocation {
	sinks := make([]*SinkLocation, 0)

	for _, node := range cfg.Nodes {
		for _, stmt := range node.Block.Stmts {
			for _, pattern := range patterns {
				if engine.matchesPattern(stmt, pattern) {
					sink := &SinkLocation{
						Position: stmt.Position,
						Type:     engine.getSinkType(pattern),
						Function: engine.getFunctionName(stmt),
						Variable: engine.extractVariableID(stmt),
					}
					sinks = append(sinks, sink)
				}
			}
		}
	}

	return sinks
}

// matchesPattern checks if a statement matches a CFG pattern
func (engine *CFGRuleEngine) matchesPattern(stmt *HIRStmt, pattern CFGPattern) bool {
	// Check statement type
	if pattern.StmtType != 0 && stmt.Type != pattern.StmtType {
		return false
	}

	// Check function call pattern
	if pattern.FunctionCall != "" {
		funcName := engine.getFunctionName(stmt)
		if funcName == "" {
			return false
		}

		// Use regex matching for function patterns
		regex := regexp.MustCompile(pattern.FunctionCall)
		if !regex.MatchString(funcName) {
			return false
		}
	}

	// Check conditions
	for _, condition := range pattern.Conditions {
		if !engine.evaluateCondition(stmt, condition) {
			return false
		}
	}

	return true
}

// findDataFlowPaths finds paths from sources to sinks through CFG
func (engine *CFGRuleEngine) findDataFlowPaths(cfg *CFG, sources []*SourceLocation, sinks []*SinkLocation, flowRule CFGFlowRule) []*DataFlowPath {
	paths := make([]*DataFlowPath, 0)

	for _, source := range sources {
		for _, sink := range sinks {
			cfgPath := engine.findCFGPath(cfg, source.Position, sink.Position, flowRule.MaxHops)
			if cfgPath != nil {
				path := &DataFlowPath{
					ID:         fmt.Sprintf("path_%d_%d", source.Position, sink.Position),
					Source:     &TaintSource{Kind: TaintUserInput, Location: source.Position},
					Sink:       sink,
					Path:       cfgPath,
					Variables:  engine.extractVariablesFromPath(cfgPath),
					Sanitized:  engine.checkPathSanitization(cfgPath),
					Confidence: engine.calculatePathConfidence(cfgPath),
				}
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// findCFGPath finds a path through the CFG from source to sink position
func (engine *CFGRuleEngine) findCFGPath(cfg *CFG, sourcePos, sinkPos token.Pos, maxHops int) []*CFGNode {
	// Find source and sink nodes
	sourceNode := engine.findNodeByPosition(cfg, sourcePos)
	sinkNode := engine.findNodeByPosition(cfg, sinkPos)

	if sourceNode == nil || sinkNode == nil {
		return nil
	}

	// BFS to find path
	queue := [][]*CFGNode{{sourceNode}}
	visited := make(map[BlockID]bool)

	for len(queue) > 0 && len(queue[0]) <= maxHops {
		path := queue[0]
		queue = queue[1:]

		current := path[len(path)-1]
		if current.ID == sinkNode.ID {
			return path
		}

		if visited[current.ID] {
			continue
		}
		visited[current.ID] = true

		// Add successors to queue
		for _, edge := range cfg.Edges {
			if edge.From.ID == current.ID {
				newPath := append([]*CFGNode{}, path...)
				newPath = append(newPath, edge.To)
				queue = append(queue, newPath)
			}
		}
	}

	return nil
}

// validateFlowRule checks if a path satisfies the flow rule requirements
func (engine *CFGRuleEngine) validateFlowRule(path *DataFlowPath, rule CFGFlowRule) bool {
	if rule.NoSanitizerBetween && path.Sanitized {
		return false
	}

	if rule.MaxHops > 0 && len(path.Path) > rule.MaxHops {
		return false
	}

	if rule.PathRequired && len(path.Path) == 0 {
		return false
	}

	return true
}

// createFindingFromPath creates a security finding from a data flow path
func (engine *CFGRuleEngine) createFindingFromPath(rule *CFGSecurityRule, path *DataFlowPath, unit *HIRUnit) *SecurityFinding {
	return &SecurityFinding{
		ID:          fmt.Sprintf("%s_%s", rule.ID, path.ID),
		Type:        engine.getVulnerabilityType(rule),
		Severity:    rule.Severity,
		Confidence:  path.Confidence,
		Message:     fmt.Sprintf("%s detected via CFG analysis", rule.Name),
		Description: rule.Description,
		File:        unit.Symbol.File,
		Position:    path.Source.Location,
		CWE:         rule.CWE,
		OWASP:       rule.OWASP,
		Sources:     []SourceLocation{*path.Source.ToSourceLocation()},
		Sinks:       []SinkLocation{*path.Sink},
		DataFlow:    engine.createDataFlowSteps(path),
		Remediation: engine.getRemediation(rule),
	}
}

// Helper methods

func (engine *CFGRuleEngine) parseFileToHIR(filePath string, content []byte) (*HIRFile, error) {
	transformer := NewBasicTransformer(engine.program)
	return transformer.TransformBasicFile(filePath, content)
}

func (engine *CFGRuleEngine) performInterproceduralAnalysis(hirFile *HIRFile) []*SecurityFinding {
	// Placeholder for interprocedural analysis
	return make([]*SecurityFinding, 0)
}

func (engine *CFGRuleEngine) getFunctionName(stmt *HIRStmt) string {
	if funcName, ok := stmt.Meta["function"].(string); ok {
		return funcName
	}
	if method, ok := stmt.Meta["method"].(string); ok {
		return method
	}
	return ""
}

func (engine *CFGRuleEngine) extractVariableID(stmt *HIRStmt) VariableID {
	if varName, ok := stmt.Meta["variable"].(string); ok {
		return VariableID(len(varName)) // Simplified ID generation
	}
	return 0
}

func (engine *CFGRuleEngine) getSinkType(pattern CFGPattern) SinkType {
	funcCall := strings.ToLower(pattern.FunctionCall)
	if strings.Contains(funcCall, "query") || strings.Contains(funcCall, "execute") {
		return SinkSQL
	}
	if strings.Contains(funcCall, "echo") || strings.Contains(funcCall, "print") {
		return SinkXSS
	}
	if strings.Contains(funcCall, "system") || strings.Contains(funcCall, "exec") {
		return SinkCommand
	}
	if strings.Contains(funcCall, "file") || strings.Contains(funcCall, "include") {
		return SinkFile
	}
	return SinkXSS
}

func (engine *CFGRuleEngine) evaluateCondition(stmt *HIRStmt, condition CFGCondition) bool {
	value, exists := stmt.Meta[condition.Field]

	switch condition.Operator {
	case OpExists:
		return exists
	case OpNotExists:
		return !exists
	case OpEquals:
		return exists && value == condition.Value
	case OpContains:
		if str, ok := value.(string); ok {
			if searchStr, ok := condition.Value.(string); ok {
				return strings.Contains(str, searchStr)
			}
		}
	case OpRegex:
		if str, ok := value.(string); ok {
			if regexStr, ok := condition.Value.(string); ok {
				matched, _ := regexp.MatchString(regexStr, str)
				return matched
			}
		}
	}

	return false
}

func (engine *CFGRuleEngine) findNodeByPosition(cfg *CFG, pos token.Pos) *CFGNode {
	for _, node := range cfg.Nodes {
		for _, stmt := range node.Block.Stmts {
			if stmt.Position == pos {
				return node
			}
		}
	}
	return nil
}

func (engine *CFGRuleEngine) extractVariablesFromPath(path []*CFGNode) []VariableID {
	variables := make([]VariableID, 0)
	for _, node := range path {
		for _, stmt := range node.Block.Stmts {
			if varID := engine.extractVariableID(stmt); varID != 0 {
				variables = append(variables, varID)
			}
		}
	}
	return variables
}

func (engine *CFGRuleEngine) checkPathSanitization(path []*CFGNode) bool {
	sanitizers := []string{"htmlspecialchars", "mysqli_real_escape_string", "escapeshellarg", "filter_var"}

	for _, node := range path {
		for _, stmt := range node.Block.Stmts {
			funcName := engine.getFunctionName(stmt)
			for _, sanitizer := range sanitizers {
				if strings.Contains(strings.ToLower(funcName), sanitizer) {
					return true
				}
			}
		}
	}
	return false
}

func (engine *CFGRuleEngine) calculatePathConfidence(path []*CFGNode) float64 {
	// Simple confidence calculation based on path characteristics
	confidence := 0.8 // Base confidence

	if len(path) > 5 {
		confidence -= 0.1 // Reduce confidence for long paths
	}
	if len(path) < 3 {
		confidence += 0.1 // Increase confidence for short paths
	}

	return confidence
}

func (engine *CFGRuleEngine) getVulnerabilityType(rule *CFGSecurityRule) VulnerabilityType {
	switch rule.CWE {
	case "CWE-89":
		return VulnSQLInjection
	case "CWE-79":
		return VulnXSS
	case "CWE-78":
		return VulnCommandInjection
	case "CWE-22":
		return VulnPathTraversal
	default:
		return VulnSQLInjection
	}
}

func (engine *CFGRuleEngine) createDataFlowSteps(path *DataFlowPath) []DataFlowStep {
	steps := make([]DataFlowStep, 0)

	for i, node := range path.Path {
		for _, stmt := range node.Block.Stmts {
			step := DataFlowStep{
				Position:  stmt.Position,
				Operation: fmt.Sprintf("Step %d: %s", i+1, stmt.Type.String()),
				Variable:  engine.extractVariableID(stmt),
				Tainted:   true,
				Sanitized: false,
			}
			steps = append(steps, step)
		}
	}

	return steps
}

func (engine *CFGRuleEngine) getRemediation(rule *CFGSecurityRule) string {
	switch rule.CWE {
	case "CWE-89":
		return "Use prepared statements or parameterized queries instead of string concatenation"
	case "CWE-79":
		return "Escape output using htmlspecialchars() or similar functions"
	case "CWE-78":
		return "Use escapeshellarg() or avoid system calls with user input"
	case "CWE-22":
		return "Validate and sanitize file paths, use basename() or whitelist allowed files"
	default:
		return "Validate and sanitize all user input"
	}
}

// NewCFGTaintAnalyzer creates a new CFG-based taint analyzer
func NewCFGTaintAnalyzer(program *HIRProgram) *CFGTaintAnalyzer {
	return &CFGTaintAnalyzer{
		program:     program,
		taintedVars: make(map[VariableID]*TaintState),
		flowPaths:   make([]*DataFlowPath, 0),
	}
}

// InitializeForCFG initializes taint analysis for a specific CFG
func (analyzer *CFGTaintAnalyzer) InitializeForCFG(cfg *CFG) {
	// Clear previous analysis
	analyzer.taintedVars = make(map[VariableID]*TaintState)
	analyzer.flowPaths = make([]*DataFlowPath, 0)

	// Initialize taint sources
	analyzer.identifyTaintSources(cfg)
}

// identifyTaintSources identifies taint sources in the CFG
func (analyzer *CFGTaintAnalyzer) identifyTaintSources(cfg *CFG) {
	taintSources := []string{"getQuery", "getData", "getPost", "$_GET", "$_POST", "$_REQUEST"}

	for _, node := range cfg.Nodes {
		for _, stmt := range node.Block.Stmts {
			funcName := analyzer.getFunctionName(stmt)
			for _, source := range taintSources {
				if strings.Contains(strings.ToLower(funcName), strings.ToLower(source)) {
					varID := analyzer.extractVariableID(stmt)
					if varID != 0 {
						analyzer.taintedVars[varID] = &TaintState{
							IsTainted:  true,
							Sources:    []TaintSource{{Kind: TaintUserInput, Location: stmt.Position}},
							LastUpdate: stmt.Position,
						}
					}
				}
			}
		}
	}
}

func (analyzer *CFGTaintAnalyzer) getFunctionName(stmt *HIRStmt) string {
	if funcName, ok := stmt.Meta["function"].(string); ok {
		return funcName
	}
	return ""
}

func (analyzer *CFGTaintAnalyzer) extractVariableID(stmt *HIRStmt) VariableID {
	if varName, ok := stmt.Meta["variable"].(string); ok {
		return VariableID(len(varName))
	}
	return 0
}

// Extension methods for existing types

func (ts *TaintSource) ToSourceLocation() *SourceLocation {
	return &SourceLocation{
		Position: ts.Location,
		Type:     SourceUserInput,
		Variable: 0, // Simplified
	}
}