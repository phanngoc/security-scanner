package types

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

// RuleProvider defines the interface that all security rules must implement
type RuleProvider interface {
	// GetRule returns the rule definition
	GetRule() *Rule

	// GetID returns the unique identifier for this rule
	GetID() string

	// GetType returns the vulnerability type this rule detects
	GetType() VulnerabilityType

	// IsEnabled checks if this rule is enabled based on configuration
	IsEnabled(cfg *config.Config) bool

	// GetMetadata returns additional metadata about the rule
	GetMetadata() RuleMetadata
}

// RuleMetadata contains additional information about a rule
type RuleMetadata struct {
	Author      string   `json:"author"`
	Version     string   `json:"version"`
	LastUpdated string   `json:"last_updated"`
	Tags        []string `json:"tags"`
	References  []string `json:"references"`
}

// BaseRule provides a default implementation of common RuleProvider methods
type BaseRule struct {
	rule     *Rule
	metadata RuleMetadata
}

// NewBaseRule creates a new BaseRule instance
func NewBaseRule(rule *Rule, metadata RuleMetadata) *BaseRule {
	return &BaseRule{
		rule:     rule,
		metadata: metadata,
	}
}

// GetRule returns the rule definition
func (br *BaseRule) GetRule() *Rule {
	return br.rule
}

// GetID returns the unique identifier for this rule
func (br *BaseRule) GetID() string {
	return br.rule.ID
}

// GetType returns the vulnerability type this rule detects
func (br *BaseRule) GetType() VulnerabilityType {
	return br.rule.Type
}

// IsEnabled checks if this rule is enabled based on configuration
func (br *BaseRule) IsEnabled(cfg *config.Config) bool {
	// Check if rule is explicitly enabled
	for _, enabled := range cfg.Rules.Enabled {
		if enabled == string(br.rule.Type) {
			return true
		}
	}

	// Check if rule is explicitly disabled
	for _, disabled := range cfg.Rules.Disabled {
		if disabled == string(br.rule.Type) {
			return false
		}
	}

	// Default behavior based on severity
	return br.rule.Severity >= config.SeverityMedium
}

// GetMetadata returns additional metadata about the rule
func (br *BaseRule) GetMetadata() RuleMetadata {
	return br.metadata
}
