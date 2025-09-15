package rules

import (
	"strings"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// DynamicRuleEngine provides a dynamic rule execution engine
type DynamicRuleEngine struct {
	providers    map[types.VulnerabilityType]RuleProvider
	enabled      map[types.VulnerabilityType]bool
	config       *config.Config
	flowAnalyzer *FlowAnalyzer
}

// NewDynamicRuleEngine creates a new dynamic rule engine
func NewDynamicRuleEngine(cfg *config.Config) *DynamicRuleEngine {
	return &DynamicRuleEngine{
		providers:    make(map[types.VulnerabilityType]RuleProvider),
		enabled:      make(map[types.VulnerabilityType]bool),
		config:       cfg,
		flowAnalyzer: NewFlowAnalyzer(),
	}
}

// RegisterProvider registers a rule provider
func (dre *DynamicRuleEngine) RegisterProvider(provider RuleProvider) {
	dre.providers[provider.GetType()] = provider
	dre.enabled[provider.GetType()] = provider.IsEnabled(dre.config)
}

// RegisterProviders registers multiple rule providers
func (dre *DynamicRuleEngine) RegisterProviders(providers map[types.VulnerabilityType]RuleProvider) {
	for _, provider := range providers {
		dre.RegisterProvider(provider)
	}
}

// AnalyzeFile analyzes a file using all enabled rules
func (dre *DynamicRuleEngine) AnalyzeFile(filePath string, language string, content []byte) []*types.SecurityFinding {
	var findings []*types.SecurityFinding
	contentStr := string(content)

	// Only analyze files that contain actual security-relevant code
	if len(contentStr) < 5 || strings.TrimSpace(contentStr) == "" {
		return findings // Skip empty or very small files
	}

	// Skip files that only contain language tags
	if dre.isOnlyLanguageTag(contentStr) {
		return findings
	}

	// 1. Flow-based analysis (primary method)
	flowFindings := dre.flowAnalyzer.AnalyzeFlow(filePath, language, content)
	findings = append(findings, flowFindings...)

	// 2. Pattern-based analysis (secondary method for rules not covered by flow analysis)
	patternFindings := dre.analyzePatterns(filePath, language, content)
	findings = append(findings, patternFindings...)

	return findings
}

// analyzePatterns performs pattern-based analysis using rule providers
func (dre *DynamicRuleEngine) analyzePatterns(filePath string, language string, content []byte) []*types.SecurityFinding {
	var findings []*types.SecurityFinding
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")

	// Run all enabled rules
	for vulnType, provider := range dre.providers {
		if !dre.enabled[vulnType] {
			continue
		}

		// Check if rule applies to this language
		rule := provider.GetRule()
		if !dre.isLanguageSupported(rule.Languages, language) {
			continue
		}

		// Analyze each line
		for lineNum, line := range lines {
			line = strings.TrimSpace(line)
			if dre.shouldSkipLine(line, language) {
				continue
			}

			// Check if line is vulnerable
			if dre.isVulnerable(provider, line, language) {
				finding := &types.SecurityFinding{
					RuleID:      rule.ID,
					RuleName:    rule.Name,
					VulnType:    vulnType,
					Severity:    rule.Severity,
					File:        filePath,
					Line:        lineNum + 1,
					Column:      0, // Could be enhanced to detect column
					Message:     rule.Description,
					Code:        line,
					Remediation: rule.Remediation,
					OWASP:       rule.OWASP,
					CWE:         rule.CWE,
					Context:     language,
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// isVulnerable checks if a line is vulnerable using the rule provider
func (dre *DynamicRuleEngine) isVulnerable(provider RuleProvider, line string, language string) bool {
	// Try to cast to YAMLRuleProvider for advanced checking
	if yamlProvider, ok := provider.(*YAMLRuleProvider); ok {
		return yamlProvider.IsVulnerable(line, language)
	}

	// Fallback to basic pattern matching
	rule := provider.GetRule()
	for _, pattern := range rule.Patterns {
		if pattern.Regex != nil && pattern.Regex.MatchString(line) {
			return true
		}
	}

	return false
}

// isLanguageSupported checks if a rule supports the given language
func (dre *DynamicRuleEngine) isLanguageSupported(supportedLanguages []string, language string) bool {
	if len(supportedLanguages) == 0 {
		return true // No language restriction
	}

	for _, supported := range supportedLanguages {
		if strings.EqualFold(supported, language) {
			return true
		}
	}
	return false
}

// shouldSkipLine determines if a line should be skipped during analysis
func (dre *DynamicRuleEngine) shouldSkipLine(line string, language string) bool {
	if line == "" {
		return true
	}

	// Skip comments based on language
	switch language {
	case "php":
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") ||
			strings.HasPrefix(line, "use ") || strings.HasPrefix(line, "namespace ") ||
			strings.HasPrefix(line, "<?php")
	case "go":
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*")
	case "javascript", "typescript":
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*")
	case "python":
		return strings.HasPrefix(line, "#") || strings.HasPrefix(line, "\"\"\"")
	case "java", "csharp":
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*")
	default:
		return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*")
	}
}

// isOnlyLanguageTag checks if the file contains only language opening tags
func (dre *DynamicRuleEngine) isOnlyLanguageTag(content string) bool {
	trimmed := strings.TrimSpace(content)
	// Check for files that only contain <?php or similar opening tags
	return trimmed == "<?php" || trimmed == "<?php\n" || len(trimmed) < 10
}

// GetEnabledRules returns all enabled rule providers
func (dre *DynamicRuleEngine) GetEnabledRules() []RuleProvider {
	var enabled []RuleProvider
	for vulnType, provider := range dre.providers {
		if dre.enabled[vulnType] {
			enabled = append(enabled, provider)
		}
	}
	return enabled
}

// GetRuleStatistics returns statistics about loaded rules
func (dre *DynamicRuleEngine) GetRuleStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["total_rules"] = len(dre.providers)

	enabledCount := 0
	severityCount := make(map[string]int)
	languageCount := make(map[string]int)

	for vulnType, provider := range dre.providers {
		if dre.enabled[vulnType] {
			enabledCount++
		}

		rule := provider.GetRule()
		severity := rule.Severity.String()
		severityCount[severity]++

		for _, lang := range rule.Languages {
			languageCount[lang]++
		}
	}

	stats["enabled_rules"] = enabledCount
	stats["disabled_rules"] = len(dre.providers) - enabledCount
	stats["by_severity"] = severityCount
	stats["by_language"] = languageCount

	return stats
}
