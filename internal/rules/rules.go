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

// RuleEngine manages security rules
type RuleEngine struct {
	rules   map[VulnerabilityType]*Rule
	enabled map[VulnerabilityType]bool
}

// NewRuleEngine creates a new rule engine with OWASP-compliant rules
func NewRuleEngine(cfg *config.Config) *RuleEngine {
	engine := &RuleEngine{
		rules:   make(map[VulnerabilityType]*Rule),
		enabled: make(map[VulnerabilityType]bool),
	}

	// Initialize all OWASP rules
	engine.initializeOWASPRules()

	// Configure enabled rules
	for _, ruleName := range cfg.Rules.Enabled {
		if vulnType := VulnerabilityType(ruleName); engine.rules[vulnType] != nil {
			engine.enabled[vulnType] = true
		}
	}

	// Disable explicitly disabled rules
	for _, ruleName := range cfg.Rules.Disabled {
		if vulnType := VulnerabilityType(ruleName); engine.rules[vulnType] != nil {
			engine.enabled[vulnType] = false
		}
	}

	return engine
}

// initializeOWASPRules initializes all OWASP Top 10 security rules
func (re *RuleEngine) initializeOWASPRules() {
	// A03:2021 – Injection (SQL Injection)
	re.addRule(&Rule{
		ID:          "OWASP-A03-001",
		Type:        SQLInjection,
		Name:        "SQL Injection Vulnerability",
		Description: "Direct concatenation of user input into SQL queries without proper escaping or parameterization",
		Severity:    config.SeverityCritical,
		Languages:   []string{"php", "java", "csharp", "python", "javascript", "go"},
		Patterns: []Pattern{
			{
				Type:        PatternRegex,
				Pattern:     `(?i)(select|insert|update|delete|drop|create|alter|exec|execute)\s+.*\$_(GET|POST|REQUEST|COOKIE|SESSION)`,
				Description: "SQL query with direct user input concatenation",
				Context:     "database_query",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)(mysql_query|mysqli_query|pg_query)\s*\(\s*[^$]*\$_(GET|POST|REQUEST)`,
				Description: "Database query function with user input",
				Context:     "php_mysql",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)query\s*\(\s*["'][^"']*["']\s*\+\s*.*\$_(GET|POST|REQUEST)`,
				Description: "String concatenation in SQL queries",
				Context:     "query_concatenation",
			},
		},
		OWASP: OWASPReference{
			Top10_2021: "A03:2021",
			Category:   "Injection",
		},
		CWE:         "CWE-89",
		Remediation: "Use parameterized queries or prepared statements. Validate and sanitize all user inputs.",
	})

	// A03:2021 – Cross-Site Scripting (XSS)
	re.addRule(&Rule{
		ID:          "OWASP-A03-002",
		Type:        XSS,
		Name:        "Cross-Site Scripting Vulnerability",
		Description: "User input displayed without proper encoding or validation",
		Severity:    config.SeverityHigh,
		Languages:   []string{"php", "javascript", "html", "java", "csharp", "python"},
		Patterns: []Pattern{
			{
				Type:        PatternRegex,
				Pattern:     `(?i)echo\s+\$_(GET|POST|REQUEST|COOKIE|SESSION)`,
				Description: "Direct output of user input without encoding",
				Context:     "php_output",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)innerHTML\s*=\s*.*\$_(GET|POST|REQUEST)`,
				Description: "Dynamic HTML content from user input",
				Context:     "javascript_dom",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)document\.write\s*\(\s*.*\$_(GET|POST|REQUEST)`,
				Description: "Document.write with user input",
				Context:     "javascript_write",
			},
		},
		OWASP: OWASPReference{
			Top10_2021: "A03:2021",
			Category:   "Injection",
		},
		CWE:         "CWE-79",
		Remediation: "Always encode output data. Use HTML entity encoding for HTML context, JavaScript encoding for JS context.",
	})

	// A01:2021 – Broken Access Control (Path Traversal)
	re.addRule(&Rule{
		ID:          "OWASP-A01-001",
		Type:        PathTraversal,
		Name:        "Path Traversal Vulnerability",
		Description: "User input used in file paths without proper validation",
		Severity:    config.SeverityHigh,
		Languages:   []string{"php", "java", "python", "javascript", "go", "csharp"},
		Patterns: []Pattern{
			{
				Type:        PatternRegex,
				Pattern:     `(?i)(file_get_contents|fopen|include|require)\s*\(\s*.*\$_(GET|POST|REQUEST)`,
				Description: "File operations with user input",
				Context:     "php_file_ops",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)\.\.\/|\.\.\\`,
				Description: "Directory traversal patterns",
				Context:     "path_traversal",
			},
		},
		OWASP: OWASPReference{
			Top10_2021: "A01:2021",
			Category:   "Broken Access Control",
		},
		CWE:         "CWE-22",
		Remediation: "Validate file paths against a whitelist. Use absolute paths and avoid user input in file operations.",
	})

	// A03:2021 – Command Injection
	re.addRule(&Rule{
		ID:          "OWASP-A03-003",
		Type:        CommandInjection,
		Name:        "Command Injection Vulnerability",
		Description: "User input used in system commands without proper validation",
		Severity:    config.SeverityCritical,
		Languages:   []string{"php", "python", "java", "javascript", "go", "ruby"},
		Patterns: []Pattern{
			{
				Type:        PatternRegex,
				Pattern:     `(?i)(system|exec|shell_exec|passthru|popen)\s*\(\s*.*\$_(GET|POST|REQUEST)`,
				Description: "System command execution with user input",
				Context:     "php_system",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)os\.(system|popen|exec)\s*\(\s*.*request\.`,
				Description: "Python system command with user input",
				Context:     "python_os",
			},
		},
		OWASP: OWASPReference{
			Top10_2021: "A03:2021",
			Category:   "Injection",
		},
		CWE:         "CWE-78",
		Remediation: "Never use user input in system commands. Use parameterized APIs or validate input against strict whitelists.",
	})

	// A02:2021 – Hardcoded Secrets
	re.addRule(&Rule{
		ID:          "OWASP-A02-001",
		Type:        HardcodedSecrets,
		Name:        "Hardcoded Secrets",
		Description: "Hardcoded passwords, API keys, or other sensitive data",
		Severity:    config.SeverityHigh,
		Languages:   []string{"*"},
		Patterns: []Pattern{
			{
				Type:        PatternRegex,
				Pattern:     `(?i)(password|passwd|pwd)\s*=\s*["'][^"']{8,}["']`,
				Description: "Hardcoded password",
				Context:     "hardcoded_password",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)(api[_-]?key|apikey|secret[_-]?key)\s*=\s*["'][^"']{16,}["']`,
				Description: "Hardcoded API key",
				Context:     "api_key",
			},
			{
				Type:        PatternRegex,
				Pattern:     `(?i)(private[_-]?key|secret)\s*=\s*["']-----BEGIN`,
				Description: "Hardcoded private key",
				Context:     "private_key",
			},
		},
		OWASP: OWASPReference{
			Top10_2021: "A02:2021",
			Category:   "Cryptographic Failures",
		},
		CWE:         "CWE-798",
		Remediation: "Use environment variables or secure configuration management for secrets.",
	})

	// Compile regex patterns
	for _, rule := range re.rules {
		for i := range rule.Patterns {
			if rule.Patterns[i].Type == PatternRegex {
				compiled, err := regexp.Compile(rule.Patterns[i].Pattern)
				if err == nil {
					rule.Patterns[i].Regex = compiled
				}
			}
		}
	}
}

// addRule adds a rule to the engine
func (re *RuleEngine) addRule(rule *Rule) {
	re.rules[rule.Type] = rule
}

// GetEnabledRules returns all enabled rules
func (re *RuleEngine) GetEnabledRules() []*Rule {
	var rules []*Rule
	for vulnType, rule := range re.rules {
		if re.enabled[vulnType] {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetRule returns a specific rule by type
func (re *RuleEngine) GetRule(vulnType VulnerabilityType) *Rule {
	return re.rules[vulnType]
}

// IsEnabled checks if a rule is enabled
func (re *RuleEngine) IsEnabled(vulnType VulnerabilityType) bool {
	return re.enabled[vulnType]
}
