package rules

import (
	"regexp"

	"github.com/le-company/security-scanner/internal/config"
)

// VulnerabilityType represents different types of security vulnerabilities
type VulnerabilityType string

const (
	SQLInjection          VulnerabilityType = "sql_injection"
	XSS                   VulnerabilityType = "xss"
	PathTraversal         VulnerabilityType = "path_traversal"
	CommandInjection      VulnerabilityType = "command_injection"
	HardcodedSecrets      VulnerabilityType = "hardcoded_secrets"
	WeakCrypto            VulnerabilityType = "weak_crypto"
	InsecureRandom        VulnerabilityType = "insecure_random"
	XXE                   VulnerabilityType = "xxe"
	LDAPInjection         VulnerabilityType = "ldap_injection"
	UnsafeDeserialization VulnerabilityType = "unsafe_deserialization"
	CSRFVuln              VulnerabilityType = "csrf"
	WeakAuthentication    VulnerabilityType = "weak_authentication"
	InsecureTransport     VulnerabilityType = "insecure_transport"
	BufferOverflow        VulnerabilityType = "buffer_overflow"
	RaceCondition         VulnerabilityType = "race_condition"
)

// Rule represents a security rule
type Rule struct {
	ID          string               `json:"id"`
	Type        VulnerabilityType    `json:"type"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Severity    config.SeverityLevel `json:"severity"`
	Languages   []string             `json:"languages"`
	Patterns    []Pattern            `json:"patterns"`
	OWASP       OWASPReference       `json:"owasp"`
	CWE         string               `json:"cwe"`
	Remediation string               `json:"remediation"`
}

// Pattern represents a detection pattern
type Pattern struct {
	Type        PatternType    `json:"type"`
	Pattern     string         `json:"pattern"`
	Regex       *regexp.Regexp `json:"-"`
	Description string         `json:"description"`
	Context     string         `json:"context"`
}

// CompileRegex compiles the regex pattern for performance
func (p *Pattern) CompileRegex() error {
	if p.Type == PatternRegex {
		regex, err := regexp.Compile(p.Pattern)
		if err != nil {
			return err
		}
		p.Regex = regex
	}
	return nil
}

// PatternType represents the type of pattern
type PatternType string

const (
	PatternRegex    PatternType = "regex"
	PatternLiteral  PatternType = "literal"
	PatternFunction PatternType = "function"
	PatternAST      PatternType = "ast"
)

// OWASPReference contains OWASP mapping information
type OWASPReference struct {
	Top10_2021 string `json:"top10_2021"`
	Category   string `json:"category"`
}

// SecurityFinding represents a security vulnerability finding
type SecurityFinding struct {
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	VulnType    VulnerabilityType      `json:"vulnerability_type"`
	Severity    config.SeverityLevel   `json:"severity"`
	File        string                 `json:"file"`
	Line        int                    `json:"line"`
	Column      int                    `json:"column"`
	Message     string                 `json:"message"`
	Code        string                 `json:"code"`
	Remediation string                 `json:"remediation"`
	OWASP       OWASPReference         `json:"owasp"`
	CWE         string                 `json:"cwe"`
	Context     string                 `json:"context"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GetOWASPReference returns the OWASP reference as a string
func (sf *SecurityFinding) GetOWASPReference() string {
	if sf.OWASP.Top10_2021 != "" {
		return "OWASP Top 10 2021: " + sf.OWASP.Top10_2021
	}
	return ""
}
