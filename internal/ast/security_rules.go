package ast

import (
	"fmt"
	"regexp"
	"strings"
)

// SecurityRuleEngine manages and executes security rules on AST
type SecurityRuleEngine struct {
	rules []SecurityRule
}

// NewSecurityRuleEngine creates a new security rule engine
func NewSecurityRuleEngine() *SecurityRuleEngine {
	engine := &SecurityRuleEngine{
		rules: make([]SecurityRule, 0),
	}
	
	// Register default security rules
	engine.RegisterDefaultRules()
	
	return engine
}

// RegisterRule adds a security rule to the engine
func (sre *SecurityRuleEngine) RegisterRule(rule SecurityRule) {
	sre.rules = append(sre.rules, rule)
}

// RegisterDefaultRules registers all default security rules
func (sre *SecurityRuleEngine) RegisterDefaultRules() {
	// SQL Injection rules
	sre.RegisterRule(NewSQLInjectionRule())
	sre.RegisterRule(NewPDOSQLInjectionRule())
	
	// XSS rules
	sre.RegisterRule(NewXSSRule())
	sre.RegisterRule(NewReflectedXSSRule())
	
	// Command Injection rules
	sre.RegisterRule(NewCommandInjectionRule())
	
	// Path Traversal rules
	sre.RegisterRule(NewPathTraversalRule())
	
	// Hardcoded Secrets rules
	sre.RegisterRule(NewHardcodedSecretsRule())
	
	// Insecure Cryptography rules
	sre.RegisterRule(NewWeakCryptographyRule())
	
	// File Upload rules
	sre.RegisterRule(NewInsecureFileUploadRule())
	
	// Authentication/Authorization rules
	sre.RegisterRule(NewWeakAuthenticationRule())
	
	// Session Security rules
	sre.RegisterRule(NewInsecureSessionRule())
	
	// LDAP Injection rules
	sre.RegisterRule(NewLDAPInjectionRule())
	
	// XXE rules
	sre.RegisterRule(NewXXERule())
	
	// Deserialization rules
	sre.RegisterRule(NewUnsafeDeserializationRule())
}

// AnalyzeAST analyzes an AST and returns security findings
func (sre *SecurityRuleEngine) AnalyzeAST(ast *ProgramNode, symbolTable *SymbolTable) ([]SecurityFinding, error) {
	var findings []SecurityFinding
	
	analyzer := NewSecurityAnalyzer(symbolTable)
	for _, rule := range sre.rules {
		analyzer.AddRule(rule)
	}
	
	ruleFindings, err := analyzer.Analyze(ast)
	if err != nil {
		return nil, err
	}
	
	findings = append(findings, ruleFindings...)
	
	return findings, nil
}

// Base rule implementations

// SQLInjectionRule detects SQL injection vulnerabilities
type SQLInjectionRule struct {
	id       string
	name     string
	severity Severity
}

func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{
		id:       "SQL-001",
		name:     "SQL Injection",
		severity: SeverityHigh,
	}
}

func (r *SQLInjectionRule) GetID() string     { return r.id }
func (r *SQLInjectionRule) GetName() string   { return r.name }
func (r *SQLInjectionRule) GetSeverity() Severity { return r.severity }

func (r *SQLInjectionRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if callNode, ok := node.(*FunctionCallNode); ok {
		// Check for dangerous SQL functions
		dangerousFunctions := []string{
			"mysql_query", "mysqli_query", "pg_query", "sqlite_query",
			"query", "exec", "execute", "prepare",
		}
		
		for _, dangerous := range dangerousFunctions {
			if strings.Contains(strings.ToLower(callNode.Function), strings.ToLower(dangerous)) {
				// Check if any arguments come from user input
				if r.hasUserInput(callNode, st) {
					finding := SecurityFinding{
						RuleID:     r.id,
						Message:    fmt.Sprintf("Potential SQL injection in %s call", callNode.Function),
						Position:   callNode.Position,
						Severity:   r.severity,
						CWE:        "CWE-89",
						OWASP:      "A03:2021",
						Confidence: 85,
						Context:    fmt.Sprintf("Function: %s", callNode.Function),
					}
					findings = append(findings, finding)
				}
			}
		}
	}
	
	return findings
}

func (r *SQLInjectionRule) hasUserInput(callNode *FunctionCallNode, st *SymbolTable) bool {
	// Check if any argument is tainted (comes from user input)
	for _, arg := range callNode.Arguments {
		if varNode, ok := arg.(*VariableNode); ok {
			if varSymbol, exists := st.Variables[varNode.Name]; exists {
				if varSymbol.IsTainted {
					return true
				}
			}
		}
	}
	return false
}

// PDOSQLInjectionRule detects SQL injection in PDO statements
type PDOSQLInjectionRule struct {
	id       string
	name     string
	severity Severity
}

func NewPDOSQLInjectionRule() *PDOSQLInjectionRule {
	return &PDOSQLInjectionRule{
		id:       "SQL-002",
		name:     "PDO SQL Injection",
		severity: SeverityHigh,
	}
}

func (r *PDOSQLInjectionRule) GetID() string     { return r.id }
func (r *PDOSQLInjectionRule) GetName() string   { return r.name }
func (r *PDOSQLInjectionRule) GetSeverity() Severity { return r.severity }

func (r *PDOSQLInjectionRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if callNode, ok := node.(*FunctionCallNode); ok {
		pdoMethods := []string{"query", "exec", "prepare"}
		
		for _, method := range pdoMethods {
			if strings.ToLower(callNode.Function) == method {
				// Check for string concatenation in SQL
				if r.hasStringConcatenation(callNode) {
					finding := SecurityFinding{
						RuleID:     r.id,
						Message:    "SQL query uses string concatenation, potential injection vulnerability",
						Position:   callNode.Position,
						Severity:   r.severity,
						CWE:        "CWE-89",
						OWASP:      "A03:2021",
						Confidence: 90,
						Context:    fmt.Sprintf("PDO method: %s", callNode.Function),
					}
					findings = append(findings, finding)
				}
			}
		}
	}
	
	return findings
}

func (r *PDOSQLInjectionRule) hasStringConcatenation(callNode *FunctionCallNode) bool {
	for _, arg := range callNode.Arguments {
		if binOp, ok := arg.(*BinaryOpNode); ok {
			if binOp.Operator == "." || binOp.Operator == "+" {
				return true
			}
		}
	}
	return false
}

// XSSRule detects Cross-Site Scripting vulnerabilities
type XSSRule struct {
	id       string
	name     string
	severity Severity
}

func NewXSSRule() *XSSRule {
	return &XSSRule{
		id:       "XSS-001",
		name:     "Cross-Site Scripting (XSS)",
		severity: SeverityHigh,
	}
}

func (r *XSSRule) GetID() string     { return r.id }
func (r *XSSRule) GetName() string   { return r.name }
func (r *XSSRule) GetSeverity() Severity { return r.severity }

func (r *XSSRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if callNode, ok := node.(*FunctionCallNode); ok {
		outputFunctions := []string{
			"echo", "print", "printf", "sprintf", "print_r", "var_dump",
		}
		
		for _, outputFunc := range outputFunctions {
			if strings.ToLower(callNode.Function) == outputFunc {
				if r.hasUnescapedUserInput(callNode, st) {
					finding := SecurityFinding{
						RuleID:     r.id,
						Message:    fmt.Sprintf("Potential XSS vulnerability in %s output", callNode.Function),
						Position:   callNode.Position,
						Severity:   r.severity,
						CWE:        "CWE-79",
						OWASP:      "A03:2021",
						Confidence: 80,
						Context:    fmt.Sprintf("Output function: %s", callNode.Function),
					}
					findings = append(findings, finding)
				}
			}
		}
	}
	
	return findings
}

func (r *XSSRule) hasUnescapedUserInput(callNode *FunctionCallNode, st *SymbolTable) bool {
	for _, arg := range callNode.Arguments {
		if varNode, ok := arg.(*VariableNode); ok {
			if varSymbol, exists := st.Variables[varNode.Name]; exists {
				if varSymbol.IsTainted && !r.isEscaped(varNode, st) {
					return true
				}
			}
		}
	}
	return false
}

func (r *XSSRule) isEscaped(varNode *VariableNode, st *SymbolTable) bool {
	// Check if variable has been through escaping functions
	if varSymbol, exists := st.Variables[varNode.Name]; exists {
		for _, assignment := range varSymbol.Assignments {
			// Check if assignment value is an escaped function call
			if callNode, ok := assignment.Value.(*FunctionCallNode); ok {
				escapeFunctions := []string{"htmlspecialchars", "htmlentities", "strip_tags", "filter_var"}
				for _, escapeFunc := range escapeFunctions {
					if strings.ToLower(callNode.Function) == escapeFunc {
						return true
					}
				}
			}
		}
	}
	return false
}

// ReflectedXSSRule detects reflected XSS vulnerabilities
type ReflectedXSSRule struct {
	id       string
	name     string
	severity Severity
}

func NewReflectedXSSRule() *ReflectedXSSRule {
	return &ReflectedXSSRule{
		id:       "XSS-002",
		name:     "Reflected Cross-Site Scripting",
		severity: SeverityHigh,
	}
}

func (r *ReflectedXSSRule) GetID() string     { return r.id }
func (r *ReflectedXSSRule) GetName() string   { return r.name }
func (r *ReflectedXSSRule) GetSeverity() Severity { return r.severity }

func (r *ReflectedXSSRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if assignNode, ok := node.(*AssignmentNode); ok {
		// Check if assignment directly uses $_GET, $_POST, $_REQUEST
		if r.usesSuperglobal(assignNode) {
			finding := SecurityFinding{
				RuleID:     r.id,
				Message:    "Direct use of user input superglobals without validation",
				Position:   assignNode.Position,
				Severity:   r.severity,
				CWE:        "CWE-79",
				OWASP:      "A03:2021",
				Confidence: 75,
				Context:    "Direct superglobal assignment",
			}
			findings = append(findings, finding)
		}
	}
	
	return findings
}

func (r *ReflectedXSSRule) usesSuperglobal(assignNode *AssignmentNode) bool {
	// Check if right side uses $_GET, $_POST, $_REQUEST, $_COOKIE
	if varNode, ok := assignNode.Right.(*VariableNode); ok {
		superglobals := []string{"_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER"}
		for _, global := range superglobals {
			if strings.Contains(varNode.Name, global) {
				return true
			}
		}
	}
	return false
}

// CommandInjectionRule detects command injection vulnerabilities
type CommandInjectionRule struct {
	id       string
	name     string
	severity Severity
}

func NewCommandInjectionRule() *CommandInjectionRule {
	return &CommandInjectionRule{
		id:       "CMD-001",
		name:     "Command Injection",
		severity: SeverityCritical,
	}
}

func (r *CommandInjectionRule) GetID() string     { return r.id }
func (r *CommandInjectionRule) GetName() string   { return r.name }
func (r *CommandInjectionRule) GetSeverity() Severity { return r.severity }

func (r *CommandInjectionRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if callNode, ok := node.(*FunctionCallNode); ok {
		dangerousFunctions := []string{
			"exec", "system", "shell_exec", "passthru", "eval",
			"popen", "proc_open", "backticks",
		}
		
		for _, dangerous := range dangerousFunctions {
			if strings.ToLower(callNode.Function) == dangerous {
				if r.hasUserInput(callNode, st) {
					finding := SecurityFinding{
						RuleID:     r.id,
						Message:    fmt.Sprintf("Potential command injection in %s", callNode.Function),
						Position:   callNode.Position,
						Severity:   r.severity,
						CWE:        "CWE-78",
						OWASP:      "A03:2021",
						Confidence: 90,
						Context:    fmt.Sprintf("Command function: %s", callNode.Function),
					}
					findings = append(findings, finding)
				}
			}
		}
	}
	
	return findings
}

func (r *CommandInjectionRule) hasUserInput(callNode *FunctionCallNode, st *SymbolTable) bool {
	for _, arg := range callNode.Arguments {
		if varNode, ok := arg.(*VariableNode); ok {
			if varSymbol, exists := st.Variables[varNode.Name]; exists {
				if varSymbol.IsTainted {
					return true
				}
			}
		}
	}
	return false
}

// PathTraversalRule detects path traversal vulnerabilities
type PathTraversalRule struct {
	id       string
	name     string
	severity Severity
}

func NewPathTraversalRule() *PathTraversalRule {
	return &PathTraversalRule{
		id:       "PATH-001",
		name:     "Path Traversal",
		severity: SeverityHigh,
	}
}

func (r *PathTraversalRule) GetID() string     { return r.id }
func (r *PathTraversalRule) GetName() string   { return r.name }
func (r *PathTraversalRule) GetSeverity() Severity { return r.severity }

func (r *PathTraversalRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if callNode, ok := node.(*FunctionCallNode); ok {
		fileFunctions := []string{
			"file_get_contents", "file_put_contents", "fopen", "readfile",
			"include", "require", "include_once", "require_once",
		}
		
		for _, fileFunc := range fileFunctions {
			if strings.ToLower(callNode.Function) == fileFunc {
				if r.hasPathTraversalRisk(callNode, st) {
					finding := SecurityFinding{
						RuleID:     r.id,
						Message:    fmt.Sprintf("Potential path traversal in %s", callNode.Function),
						Position:   callNode.Position,
						Severity:   r.severity,
						CWE:        "CWE-22",
						OWASP:      "A01:2021",
						Confidence: 85,
						Context:    fmt.Sprintf("File function: %s", callNode.Function),
					}
					findings = append(findings, finding)
				}
			}
		}
	}
	
	return findings
}

func (r *PathTraversalRule) hasPathTraversalRisk(callNode *FunctionCallNode, st *SymbolTable) bool {
	for _, arg := range callNode.Arguments {
		if varNode, ok := arg.(*VariableNode); ok {
			if varSymbol, exists := st.Variables[varNode.Name]; exists {
				if varSymbol.IsTainted && !r.isPathValidated(varNode, st) {
					return true
				}
			}
		}
		// Check for literal path traversal patterns
		if literalNode, ok := arg.(*LiteralNode); ok {
			if literalNode.Kind == LiteralString {
				if str, ok := literalNode.Value.(string); ok {
					if strings.Contains(str, "../") || strings.Contains(str, "..\\") {
						return true
					}
				}
			}
		}
	}
	return false
}

func (r *PathTraversalRule) isPathValidated(varNode *VariableNode, st *SymbolTable) bool {
	// Check if path has been validated/sanitized
	if varSymbol, exists := st.Variables[varNode.Name]; exists {
		for _, assignment := range varSymbol.Assignments {
			if callNode, ok := assignment.Value.(*FunctionCallNode); ok {
				validationFunctions := []string{"realpath", "basename", "pathinfo", "filter_var"}
				for _, validFunc := range validationFunctions {
					if strings.ToLower(callNode.Function) == validFunc {
						return true
					}
				}
			}
		}
	}
	return false
}

// HardcodedSecretsRule detects hardcoded secrets
type HardcodedSecretsRule struct {
	id       string
	name     string
	severity Severity
	patterns []*regexp.Regexp
}

func NewHardcodedSecretsRule() *HardcodedSecretsRule {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|pwd|pass)\s*=\s*["'][^"']{8,}["']`),
		regexp.MustCompile(`(?i)(api_key|apikey|access_key)\s*=\s*["'][^"']{16,}["']`),
		regexp.MustCompile(`(?i)(secret|token)\s*=\s*["'][^"']{12,}["']`),
		regexp.MustCompile(`(?i)(db_pass|database_password)\s*=\s*["'][^"']{4,}["']`),
	}
	
	return &HardcodedSecretsRule{
		id:       "SEC-001",
		name:     "Hardcoded Secrets",
		severity: SeverityHigh,
		patterns: patterns,
	}
}

func (r *HardcodedSecretsRule) GetID() string     { return r.id }
func (r *HardcodedSecretsRule) GetName() string   { return r.name }
func (r *HardcodedSecretsRule) GetSeverity() Severity { return r.severity }

func (r *HardcodedSecretsRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if assignNode, ok := node.(*AssignmentNode); ok {
		if literalNode, ok := assignNode.Right.(*LiteralNode); ok {
			if literalNode.Kind == LiteralString {
				if value, ok := literalNode.Value.(string); ok {
					for _, pattern := range r.patterns {
						if pattern.MatchString(value) {
							finding := SecurityFinding{
								RuleID:     r.id,
								Message:    "Hardcoded secret detected in assignment",
								Position:   assignNode.Position,
								Severity:   r.severity,
								CWE:        "CWE-798",
								OWASP:      "A02:2021",
								Confidence: 95,
								Context:    "Hardcoded credential",
							}
							findings = append(findings, finding)
						}
					}
				}
			}
		}
	}
	
	return findings
}

// WeakCryptographyRule detects weak cryptographic practices
type WeakCryptographyRule struct {
	id       string
	name     string
	severity Severity
}

func NewWeakCryptographyRule() *WeakCryptographyRule {
	return &WeakCryptographyRule{
		id:       "CRYPTO-001",
		name:     "Weak Cryptography",
		severity: SeverityMedium,
	}
}

func (r *WeakCryptographyRule) GetID() string     { return r.id }
func (r *WeakCryptographyRule) GetName() string   { return r.name }
func (r *WeakCryptographyRule) GetSeverity() Severity { return r.severity }

func (r *WeakCryptographyRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if callNode, ok := node.(*FunctionCallNode); ok {
		weakFunctions := map[string]string{
			"md5":     "MD5 is cryptographically broken",
			"sha1":    "SHA1 is cryptographically weak",
			"crypt":   "crypt() uses weak algorithms by default",
			"mcrypt":  "mcrypt is deprecated and insecure",
		}
		
		for weakFunc, message := range weakFunctions {
			if strings.ToLower(callNode.Function) == weakFunc {
				finding := SecurityFinding{
					RuleID:     r.id,
					Message:    message,
					Position:   callNode.Position,
					Severity:   r.severity,
					CWE:        "CWE-327",
					OWASP:      "A02:2021",
					Confidence: 90,
					Context:    fmt.Sprintf("Weak crypto function: %s", callNode.Function),
				}
				findings = append(findings, finding)
			}
		}
	}
	
	return findings
}

// Additional security rules (simplified implementations)

type InsecureFileUploadRule struct {
	id, name string
	severity Severity
}

func NewInsecureFileUploadRule() *InsecureFileUploadRule {
	return &InsecureFileUploadRule{"UPLOAD-001", "Insecure File Upload", SeverityHigh}
}

func (r *InsecureFileUploadRule) GetID() string       { return r.id }
func (r *InsecureFileUploadRule) GetName() string     { return r.name }
func (r *InsecureFileUploadRule) GetSeverity() Severity { return r.severity }
func (r *InsecureFileUploadRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	// Implementation for file upload security checks
	return []SecurityFinding{}
}

type WeakAuthenticationRule struct {
	id, name string
	severity Severity
}

func NewWeakAuthenticationRule() *WeakAuthenticationRule {
	return &WeakAuthenticationRule{"AUTH-001", "Weak Authentication", SeverityHigh}
}

func (r *WeakAuthenticationRule) GetID() string       { return r.id }
func (r *WeakAuthenticationRule) GetName() string     { return r.name }
func (r *WeakAuthenticationRule) GetSeverity() Severity { return r.severity }
func (r *WeakAuthenticationRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	// Implementation for authentication security checks
	return []SecurityFinding{}
}

type InsecureSessionRule struct {
	id, name string
	severity Severity
}

func NewInsecureSessionRule() *InsecureSessionRule {
	return &InsecureSessionRule{"SESSION-001", "Insecure Session", SeverityMedium}
}

func (r *InsecureSessionRule) GetID() string       { return r.id }
func (r *InsecureSessionRule) GetName() string     { return r.name }
func (r *InsecureSessionRule) GetSeverity() Severity { return r.severity }
func (r *InsecureSessionRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	// Implementation for session security checks
	return []SecurityFinding{}
}

type LDAPInjectionRule struct {
	id, name string
	severity Severity
}

func NewLDAPInjectionRule() *LDAPInjectionRule {
	return &LDAPInjectionRule{"LDAP-001", "LDAP Injection", SeverityHigh}
}

func (r *LDAPInjectionRule) GetID() string       { return r.id }
func (r *LDAPInjectionRule) GetName() string     { return r.name }
func (r *LDAPInjectionRule) GetSeverity() Severity { return r.severity }
func (r *LDAPInjectionRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	// Implementation for LDAP injection checks
	return []SecurityFinding{}
}

type XXERule struct {
	id, name string
	severity Severity
}

func NewXXERule() *XXERule {
	return &XXERule{"XXE-001", "XML External Entity", SeverityHigh}
}

func (r *XXERule) GetID() string       { return r.id }
func (r *XXERule) GetName() string     { return r.name }
func (r *XXERule) GetSeverity() Severity { return r.severity }
func (r *XXERule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	// Implementation for XXE vulnerability checks
	return []SecurityFinding{}
}

type UnsafeDeserializationRule struct {
	id, name string
	severity Severity
}

func NewUnsafeDeserializationRule() *UnsafeDeserializationRule {
	return &UnsafeDeserializationRule{"DESER-001", "Unsafe Deserialization", SeverityHigh}
}

func (r *UnsafeDeserializationRule) GetID() string       { return r.id }
func (r *UnsafeDeserializationRule) GetName() string     { return r.name }
func (r *UnsafeDeserializationRule) GetSeverity() Severity { return r.severity }
func (r *UnsafeDeserializationRule) Check(node ASTNode, st *SymbolTable) []SecurityFinding {
	var findings []SecurityFinding
	
	if callNode, ok := node.(*FunctionCallNode); ok {
		dangerousFunctions := []string{"unserialize", "eval"}
		
		for _, dangerous := range dangerousFunctions {
			if strings.ToLower(callNode.Function) == dangerous {
				finding := SecurityFinding{
					RuleID:     r.id,
					Message:    fmt.Sprintf("Unsafe deserialization using %s", callNode.Function),
					Position:   callNode.Position,
					Severity:   r.severity,
					CWE:        "CWE-502",
					OWASP:      "A08:2021",
					Confidence: 85,
					Context:    fmt.Sprintf("Dangerous function: %s", callNode.Function),
				}
				findings = append(findings, finding)
			}
		}
	}
	
	return findings
}