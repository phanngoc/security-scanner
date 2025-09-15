package hir

import (
	"fmt"
	"go/token"
	"path/filepath"
	"strings"
)

// BasicTransformer provides a minimal working HIR transformer
type BasicTransformer struct {
	program     *HIRProgram
	nextStmtID  StmtID
	nextVarID   VariableID
	nextBlockID BlockID
	ruleEngine  RuleEngine
}

// NewBasicTransformer creates a new basic transformer
func NewBasicTransformer(program *HIRProgram) *BasicTransformer {
	return &BasicTransformer{
		program:     program,
		nextStmtID:  1,
		nextVarID:   1,
		nextBlockID: 1,
		ruleEngine:  nil, // Will be set later
	}
}

// NewBasicTransformerWithRules creates a new basic transformer with rule engine
func NewBasicTransformerWithRules(program *HIRProgram, ruleEngine RuleEngine) *BasicTransformer {
	return &BasicTransformer{
		program:     program,
		nextStmtID:  1,
		nextVarID:   1,
		nextBlockID: 1,
		ruleEngine:  ruleEngine,
	}
}

// SetRuleEngine sets the rule engine for the transformer
func (t *BasicTransformer) SetRuleEngine(ruleEngine RuleEngine) {
	t.ruleEngine = ruleEngine
}

// TransformBasicFile creates a basic HIR file by analyzing real code
func (t *BasicTransformer) TransformBasicFile(filePath string, content []byte) (*HIRFile, error) {
	// Determine language from file extension
	language := t.detectLanguage(filePath)

	// Create HIR file structure
	hirFile := &HIRFile{
		Path:     filePath,
		Language: language,
		Symbols:  make([]*Symbol, 0),
		Units:    make([]*HIRUnit, 0),
		Includes: make([]*Include, 0),
	}

	// Parse the actual file content for security-relevant patterns
	t.parseFileContent(hirFile, content)

	return hirFile, nil
}

// detectLanguage determines the programming language from file extension
func (t *BasicTransformer) detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".php":
		return "php"
	case ".go":
		return "go"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".cs":
		return "csharp"
	default:
		return "unknown"
	}
}

// parseFileContent parses the actual file content for security-relevant patterns
func (t *BasicTransformer) parseFileContent(hirFile *HIRFile, content []byte) {
	// Use dynamic rule engine if available
	if t.ruleEngine != nil {
		t.parseFileContentWithRules(hirFile, content)
		return
	}

	// If no rule engine is available, create a basic HIR structure
	// without security analysis - this should be handled by the rule engine
}

// parseFileContentWithRules uses the dynamic rule engine for analysis
func (t *BasicTransformer) parseFileContentWithRules(hirFile *HIRFile, content []byte) {
	// Analyze file using dynamic rule engine
	findings := t.ruleEngine.AnalyzeFile(hirFile.Path, hirFile.Language, content)

	// Convert findings to HIR representation
	for _, finding := range findings {
		t.createSecurityVulnerabilityHIRFromFinding(hirFile, finding)
	}
}

// createSecurityVulnerabilityHIR creates HIR representation for any security vulnerability
func (t *BasicTransformer) createSecurityVulnerabilityHIR(hirFile *HIRFile, lineNum int, line string, riskType string) {
	// Create a symbol for the vulnerability
	symbol := &Symbol{
		ID:       SymbolID(fmt.Sprintf("%s::line_%d", hirFile.Path, lineNum)),
		FQN:      fmt.Sprintf("line_%d", lineNum),
		Kind:     SymFunction,
		File:     hirFile.Path,
		Position: token.Pos(lineNum),
		Traits: SymbolTraits{
			Visibility: VisPublic,
			IsStatic:   false,
		},
		Meta: map[string]interface{}{
			"vulnerability_type": riskType,
		},
	}

	hirFile.Symbols = append(hirFile.Symbols, symbol)

	// Create HIR unit with the vulnerable statement
	unit := &HIRUnit{
		Symbol:  symbol,
		Params:  make([]*Variable, 0),
		Returns: make([]*Variable, 0),
		Body:    t.createVulnerableBlock(lineNum, line, riskType),
		IsSSA:   false,
	}

	hirFile.Units = append(hirFile.Units, unit)
}

// createVulnerableBlock creates an HIR block representing a real vulnerability
func (t *BasicTransformer) createVulnerableBlock(lineNum int, line string, riskType string) *HIRBlock {
	block := &HIRBlock{
		ID:    t.nextBlockID,
		Stmts: make([]*HIRStmt, 0),
		Preds: make([]*HIRBlock, 0),
		Succs: make([]*HIRBlock, 0),
	}
	t.nextBlockID++

	// Create statement representing the vulnerable code
	callStmt := &HIRStmt{
		ID:       t.nextStmtID,
		Type:     HIRCall,
		Operands: make([]HIRValue, 0),
		Position: token.Pos(lineNum),
		Meta: map[string]interface{}{
			"source_line":   line,
			"security_risk": riskType,
			"line_number":   lineNum,
		},
	}
	t.nextStmtID++

	block.Stmts = append(block.Stmts, callStmt)
	return block
}

// createSecurityVulnerabilityHIRFromFinding creates HIR representation from a security finding
func (t *BasicTransformer) createSecurityVulnerabilityHIRFromFinding(hirFile *HIRFile, finding *SecurityFinding) {
	// Create a symbol for the vulnerability
	symbol := &Symbol{
		ID:       SymbolID(fmt.Sprintf("%s::line_%d", hirFile.Path, int(finding.Position))),
		FQN:      fmt.Sprintf("line_%d", int(finding.Position)),
		Kind:     SymFunction,
		File:     hirFile.Path,
		Position: finding.Position,
		Traits: SymbolTraits{
			Visibility: VisPublic,
			IsStatic:   false,
		},
		Meta: map[string]interface{}{
			"vulnerability_type": string(finding.Type),
			"rule_id":            finding.ID,
			"severity":           finding.Severity.String(),
			"owasp":              finding.OWASP,
			"cwe":                finding.CWE,
			"remediation":        finding.Remediation,
		},
	}

	hirFile.Symbols = append(hirFile.Symbols, symbol)

	// Create HIR unit with the vulnerable statement
	unit := &HIRUnit{
		Symbol:  symbol,
		Params:  make([]*Variable, 0),
		Returns: make([]*Variable, 0),
		Body:    t.createVulnerableBlockFromFinding(finding),
		IsSSA:   false,
	}

	hirFile.Units = append(hirFile.Units, unit)
}

// createVulnerableBlockFromFinding creates an HIR block from a security finding
func (t *BasicTransformer) createVulnerableBlockFromFinding(finding *SecurityFinding) *HIRBlock {
	block := &HIRBlock{
		ID:    t.nextBlockID,
		Stmts: make([]*HIRStmt, 0),
		Preds: make([]*HIRBlock, 0),
		Succs: make([]*HIRBlock, 0),
	}
	t.nextBlockID++

	// Create statement representing the vulnerable code
	callStmt := &HIRStmt{
		ID:       t.nextStmtID,
		Type:     HIRCall,
		Operands: make([]HIRValue, 0),
		Position: finding.Position,
		Meta: map[string]interface{}{
			"security_risk":   string(finding.Type),
			"line_number":     int(finding.Position),
			"rule_id":         finding.ID,
			"severity":        finding.Severity.String(),
			"message":         finding.Message,
			"remediation":     finding.Remediation,
			"owasp_reference": finding.OWASP,
			"cwe_reference":   finding.CWE,
		},
	}
	t.nextStmtID++

	block.Stmts = append(block.Stmts, callStmt)
	return block
}
