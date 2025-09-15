package owasp

import (
	"context"
	"fmt"
	"strings"

	"github.com/le-company/security-scanner/internal/analyzer"
	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// SQLInjectionAnalyzer implements the Analyzer interface for SQL injection detection
type SQLInjectionAnalyzer struct {
	rule *SQLInjectionRule
}

// NewSQLInjectionAnalyzer creates a new SQL injection analyzer
func NewSQLInjectionAnalyzer() *SQLInjectionAnalyzer {
	return &SQLInjectionAnalyzer{
		rule: NewSQLInjectionRule(),
	}
}

// GetID returns the unique identifier for this analyzer
func (a *SQLInjectionAnalyzer) GetID() string {
	return "sql_injection_analyzer"
}

// GetName returns the human-readable name of this analyzer
func (a *SQLInjectionAnalyzer) GetName() string {
	return "SQL Injection Detection Analyzer"
}

// GetDescription returns a description of what this analyzer does
func (a *SQLInjectionAnalyzer) GetDescription() string {
	return "Detects SQL injection vulnerabilities by analyzing unparameterized queries using CFG-based analysis"
}

// GetSupportedLanguages returns the languages this analyzer supports
func (a *SQLInjectionAnalyzer) GetSupportedLanguages() []string {
	return []string{"php", "javascript", "python", "java", "csharp", "go"}
}

// GetRequiredCapabilities returns the capabilities this analyzer needs
func (a *SQLInjectionAnalyzer) GetRequiredCapabilities() []analyzer.Capability {
	return []analyzer.Capability{
		analyzer.CapabilitySymbolTable,
		analyzer.CapabilityCFG,
		analyzer.CapabilityDataFlow,
	}
}

// Analyze performs the security analysis on the given file
func (a *SQLInjectionAnalyzer) Analyze(ctx context.Context, job *analyzer.AnalysisJob) ([]*types.SecurityFinding, error) {
	var findings []*types.SecurityFinding

	// Use CFG-based analysis
	sqlFlowFindings := a.rule.AnalyzeSQLFlowWithCFG(job.Path, job.Language, job.Content)
	findings = append(findings, sqlFlowFindings...)

	// If we have symbol table, perform additional analysis
	if job.SymbolTable != nil {
		symbolFindings := a.analyzeWithSymbolTable(job)
		findings = append(findings, symbolFindings...)
	}

	// If we have CFG, perform flow analysis
	if job.CFG != nil {
		cfgFindings := a.analyzeWithCFG(job)
		findings = append(findings, cfgFindings...)
	}

	return findings, nil
}

// CanAnalyze checks if this analyzer can analyze the given file
func (a *SQLInjectionAnalyzer) CanAnalyze(job *analyzer.AnalysisJob) bool {
	// Check if language is supported
	supportedLanguages := a.GetSupportedLanguages()
	for _, lang := range supportedLanguages {
		if strings.EqualFold(job.Language, lang) {
			return true
		}
	}
	return false
}

// analyzeWithSymbolTable performs analysis using symbol table information
func (a *SQLInjectionAnalyzer) analyzeWithSymbolTable(job *analyzer.AnalysisJob) []*types.SecurityFinding {
	var findings []*types.SecurityFinding

	// Look for SQL-related symbols in the symbol table
	for symbolName, symbolData := range job.SymbolTable {
		if a.isSQLSymbol(symbolName) {
			// Check if this symbol is used in dangerous ways
			if a.isDangerousSymbolUsage(symbolName, symbolData) {
				finding := &types.SecurityFinding{
					RuleID:      "S017",
					RuleName:    "SQL Injection Prevention",
					VulnType:    types.SQLInjection,
					Severity:    config.SeverityHigh,
					Message:     fmt.Sprintf("SQL-related symbol '%s' may be used insecurely without parameterization", symbolName),
					File:        job.Path,
					Line:        0, // Would be extracted from symbol data
					Column:      0,
					Remediation: "Always use parameterized queries (prepared statements) to prevent SQL injection. Never concatenate user input directly into SQL queries.",
					CWE:         "CWE-89",
					OWASP:       types.OWASPReference{Top10_2021: "A03:2021"},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// analyzeWithCFG performs analysis using CFG information
func (a *SQLInjectionAnalyzer) analyzeWithCFG(job *analyzer.AnalysisJob) []*types.SecurityFinding {
	var findings []*types.SecurityFinding

	// Use the CFG to trace data flow from user input to SQL sinks
	if job.CFG != nil {
		// This would implement CFG-based flow analysis
		// For now, we'll use the existing CFG analysis from the rule
		sqlFlowFindings := a.rule.AnalyzeSQLFlowWithCFG(job.Path, job.Language, job.Content)
		findings = append(findings, sqlFlowFindings...)
	}

	return findings
}

// isSQLSymbol checks if a symbol name is SQL-related
func (a *SQLInjectionAnalyzer) isSQLSymbol(symbolName string) bool {
	sqlKeywords := []string{
		"query", "sql", "execute", "prepare", "statement",
		"connection", "database", "db", "select", "insert",
		"update", "delete", "where", "join", "from",
	}

	lowerName := strings.ToLower(symbolName)
	for _, keyword := range sqlKeywords {
		if strings.Contains(lowerName, keyword) {
			return true
		}
	}

	return false
}

// isDangerousSymbolUsage checks if a symbol is used in a dangerous way
func (a *SQLInjectionAnalyzer) isDangerousSymbolUsage(symbolName string, symbolData interface{}) bool {
	// This would implement more sophisticated analysis
	// For now, we'll do basic checks

	// Check if symbol is assigned a concatenated SQL value
	if symbolMap, ok := symbolData.(map[string]interface{}); ok {
		// Look for evidence of string concatenation with user input
		// This would need to be implemented based on the symbol data structure
		_ = symbolMap // Placeholder
	}

	return false // For now, return false as this needs more implementation
}