package custom

import (
	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules"
)

// TemplateRule implements detection for [VULNERABILITY_NAME] vulnerabilities
// Replace "Template" with your rule name and update all fields accordingly
type TemplateRule struct {
	*rules.BaseRule
}

// NewTemplateRule creates a new [VULNERABILITY_NAME] rule instance
// Replace "Template" with your rule name
func NewTemplateRule() *TemplateRule {
	rule := &rules.Rule{
		// Unique identifier for your rule (use format: CUSTOM-XXX-### or ORG-RULETYPE-###)
		ID: "CUSTOM-001",

		// Vulnerability type - use existing types or create new ones in rules.go
		Type: rules.VulnerabilityType("custom_vulnerability_type"),

		// Human-readable name for the vulnerability
		Name: "Template Vulnerability",

		// Detailed description of what this rule detects
		Description: "Description of the security vulnerability detected by this rule",

		// Severity level: SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical
		Severity: config.SeverityMedium,

		// Programming languages this rule applies to (use "*" for all languages)
		Languages: []string{"go", "java", "python", "javascript"},

		// Detection patterns - add as many as needed
		Patterns: []rules.Pattern{
			{
				Type:        rules.PatternRegex,
				Pattern:     `(?i)dangerous_function\s*\(\s*.*user_input`,
				Description: "Description of what this pattern detects",
				Context:     "function_call",
			},
			{
				Type:        rules.PatternRegex,
				Pattern:     `(?i)another_pattern.*\$_(GET|POST|REQUEST)`,
				Description: "Description of another pattern",
				Context:     "user_input",
			},
		},

		// OWASP mapping (if applicable)
		OWASP: rules.OWASPReference{
			Top10_2021: "A03:2021", // Map to appropriate OWASP category
			Category:   "Injection",
		},

		// CWE (Common Weakness Enumeration) identifier
		CWE: "CWE-XXX",

		// Remediation advice for developers
		Remediation: "Detailed advice on how to fix this vulnerability, including code examples if helpful.",
	}

	metadata := rules.RuleMetadata{
		Author:      "Your Name or Organization",
		Version:     "1.0.0",
		LastUpdated: "2024-01-15", // Update this date
		Tags:        []string{"custom", "security", "relevant-tags"},
		References: []string{
			"https://example.com/vulnerability-reference",
			"https://cwe.mitre.org/data/definitions/XXX.html",
		},
	}

	templateRule := &TemplateRule{
		BaseRule: rules.NewBaseRule(rule, metadata),
	}

	return templateRule
}

// GetAdvancedPatterns returns more sophisticated detection patterns (optional)
func (r *TemplateRule) GetAdvancedPatterns() []rules.Pattern {
	return []rules.Pattern{
		{
			Type:        rules.PatternRegex,
			Pattern:     `(?i)advanced_pattern_here`,
			Description: "Advanced pattern description",
			Context:     "advanced_context",
		},
	}
}

// IsVulnerable performs custom vulnerability detection logic (optional)
// This method allows you to implement complex detection logic beyond simple regex patterns
func (r *TemplateRule) IsVulnerable(code string, context string) bool {
	rule := r.GetRule()

	// Check standard patterns
	for _, pattern := range rule.Patterns {
		if pattern.Regex != nil && pattern.Regex.MatchString(code) {
			return true
		}
	}

	// Check advanced patterns
	for _, pattern := range r.GetAdvancedPatterns() {
		if err := pattern.CompileRegex(); err == nil && pattern.Regex != nil {
			if pattern.Regex.MatchString(code) {
				return true
			}
		}
	}

	// Add custom detection logic here
	// Example: check for specific conditions, context analysis, etc.

	return false
}

// GetRecommendations returns language-specific recommendations (optional)
func (r *TemplateRule) GetRecommendations(language string) []string {
	recommendations := []string{
		"General recommendation that applies to all languages",
		"Another general recommendation",
	}

	// Add language-specific recommendations
	switch language {
	case "go":
		recommendations = append(recommendations,
			"Go-specific recommendation with code example",
			"Another Go-specific tip",
		)
	case "java":
		recommendations = append(recommendations,
			"Java-specific recommendation",
			"Use secure Java APIs like X instead of Y",
		)
	case "python":
		recommendations = append(recommendations,
			"Python-specific recommendation",
			"Use library X for safe handling",
		)
	case "javascript", "nodejs":
		recommendations = append(recommendations,
			"JavaScript-specific recommendation",
			"Use modern ES6+ features for better security",
		)
	}

	return recommendations
}

// Additional helper methods can be added as needed
// Examples:
// - GetContextSpecificPatterns() for different code contexts
// - GetConfigurationOptions() for rule customization
// - GetTestCases() for validation examples