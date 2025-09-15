package rules

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
	"gopkg.in/yaml.v2"
)

// YAMLRuleConfig represents the YAML configuration for a security rule
type YAMLRuleConfig struct {
	ID          string             `yaml:"id"`
	Type        string             `yaml:"type"`
	Name        string             `yaml:"name"`
	Description string             `yaml:"description"`
	Severity    string             `yaml:"severity"`
	Languages   []string           `yaml:"languages"`
	Patterns    []YAMLPattern      `yaml:"patterns"`
	OWASP       YAMLOWASPReference `yaml:"owasp"`
	CWE         string             `yaml:"cwe"`
	Remediation string             `yaml:"remediation"`
	Metadata    YAMLRuleMetadata   `yaml:"metadata"`
	Enabled     bool               `yaml:"enabled"`
	Conditions  []YAMLCondition    `yaml:"conditions"`
	Exclusions  []YAMLExclusion    `yaml:"exclusions"`
}

// YAMLPattern represents a detection pattern in YAML
type YAMLPattern struct {
	Type        string `yaml:"type"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Context     string `yaml:"context"`
	Flags       string `yaml:"flags"`
	Priority    int    `yaml:"priority"`
}

// YAMLOWASPReference represents OWASP mapping in YAML
type YAMLOWASPReference struct {
	Top10_2021 string `yaml:"top10_2021"`
	Category   string `yaml:"category"`
}

// YAMLRuleMetadata represents rule metadata in YAML
type YAMLRuleMetadata struct {
	Author      string   `yaml:"author"`
	Version     string   `yaml:"version"`
	LastUpdated string   `yaml:"last_updated"`
	Tags        []string `yaml:"tags"`
	References  []string `yaml:"references"`
}

// YAMLCondition represents a condition for rule activation
type YAMLCondition struct {
	Type     string `yaml:"type"`
	Pattern  string `yaml:"pattern"`
	Operator string `yaml:"operator"`
	Value    string `yaml:"value"`
}

// YAMLExclusion represents patterns to exclude from detection
type YAMLExclusion struct {
	Type    string `yaml:"type"`
	Pattern string `yaml:"pattern"`
	Context string `yaml:"context"`
}

// YAMLRuleProvider implements RuleProvider for YAML-based rules
type YAMLRuleProvider struct {
	*BaseRule
	config     *YAMLRuleConfig
	conditions []*regexp.Regexp
	exclusions []*regexp.Regexp
}

// NewYAMLRuleProvider creates a new YAML rule provider
func NewYAMLRuleProvider(config *YAMLRuleConfig) (*YAMLRuleProvider, error) {
	// Convert YAML config to Rule
	rule, err := convertYAMLToRule(config)
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML config to rule: %w", err)
	}

	// Create metadata
	metadata := types.RuleMetadata{
		Author:      config.Metadata.Author,
		Version:     config.Metadata.Version,
		LastUpdated: config.Metadata.LastUpdated,
		Tags:        config.Metadata.Tags,
		References:  config.Metadata.References,
	}

	provider := &YAMLRuleProvider{
		BaseRule: NewBaseRule(rule, metadata),
		config:   config,
	}

	// Compile conditions
	if err := provider.compileConditions(); err != nil {
		return nil, fmt.Errorf("failed to compile conditions: %w", err)
	}

	// Compile exclusions
	if err := provider.compileExclusions(); err != nil {
		return nil, fmt.Errorf("failed to compile exclusions: %w", err)
	}

	return provider, nil
}

// IsEnabled checks if the rule is enabled based on configuration
func (yrp *YAMLRuleProvider) IsEnabled(cfg *config.Config) bool {
	// Check if explicitly disabled in YAML
	if !yrp.config.Enabled {
		return false
	}

	// Use base rule logic
	return yrp.BaseRule.IsEnabled(cfg)
}

// IsVulnerable performs vulnerability detection with conditions and exclusions
func (yrp *YAMLRuleProvider) IsVulnerable(code string, context string) bool {
	// Check exclusions first
	for _, exclusion := range yrp.exclusions {
		if exclusion.MatchString(code) {
			return false
		}
	}

	// Check conditions
	if !yrp.checkConditions(code, context) {
		return false
	}

	// Use base rule patterns
	rule := yrp.GetRule()
	for _, pattern := range rule.Patterns {
		if pattern.Regex != nil && pattern.Regex.MatchString(code) {
			return true
		}
	}

	return false
}

// checkConditions verifies all conditions are met
func (yrp *YAMLRuleProvider) checkConditions(code string, context string) bool {
	for _, condition := range yrp.config.Conditions {
		if !yrp.evaluateCondition(condition, code, context) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (yrp *YAMLRuleProvider) evaluateCondition(condition YAMLCondition, code string, context string) bool {
	switch condition.Type {
	case "regex":
		regex, err := regexp.Compile(condition.Pattern)
		if err != nil {
			return false
		}
		return regex.MatchString(code)
	case "context":
		return strings.Contains(strings.ToLower(context), strings.ToLower(condition.Value))
	case "language":
		return strings.Contains(strings.ToLower(context), strings.ToLower(condition.Value))
	default:
		return true
	}
}

// compileConditions compiles regex conditions
func (yrp *YAMLRuleProvider) compileConditions() error {
	yrp.conditions = make([]*regexp.Regexp, 0)
	for _, condition := range yrp.config.Conditions {
		if condition.Type == "regex" {
			regex, err := regexp.Compile(condition.Pattern)
			if err != nil {
				return fmt.Errorf("invalid condition regex %s: %w", condition.Pattern, err)
			}
			yrp.conditions = append(yrp.conditions, regex)
		}
	}
	return nil
}

// compileExclusions compiles exclusion patterns
func (yrp *YAMLRuleProvider) compileExclusions() error {
	yrp.exclusions = make([]*regexp.Regexp, 0)
	for _, exclusion := range yrp.config.Exclusions {
		if exclusion.Type == "regex" {
			regex, err := regexp.Compile(exclusion.Pattern)
			if err != nil {
				return fmt.Errorf("invalid exclusion regex %s: %w", exclusion.Pattern, err)
			}
			yrp.exclusions = append(yrp.exclusions, regex)
		}
	}
	return nil
}

// YAMLRuleLoader handles loading rules from YAML files
type YAMLRuleLoader struct {
	ruleDir string
}

// NewYAMLRuleLoader creates a new YAML rule loader
func NewYAMLRuleLoader(ruleDir string) *YAMLRuleLoader {
	return &YAMLRuleLoader{
		ruleDir: ruleDir,
	}
}

// LoadRules loads all YAML rules from the specified directory
func (yrl *YAMLRuleLoader) LoadRules() (map[types.VulnerabilityType]RuleProvider, error) {
	providers := make(map[types.VulnerabilityType]RuleProvider)

	// Find all YAML files in the rule directory
	yamlFiles, err := filepath.Glob(filepath.Join(yrl.ruleDir, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to find YAML files: %w", err)
	}

	ymlFiles, err := filepath.Glob(filepath.Join(yrl.ruleDir, "*.yml"))
	if err == nil {
		yamlFiles = append(yamlFiles, ymlFiles...)
	}

	for _, yamlFile := range yamlFiles {
		// Skip if file doesn't exist
		if _, err := os.Stat(yamlFile); os.IsNotExist(err) {
			continue
		}

		provider, err := yrl.loadRuleFromFile(yamlFile)
		if err != nil {
			// Log error but continue loading other rules
			fmt.Printf("Warning: failed to load rule from %s: %v\n", yamlFile, err)
			continue
		}

		providers[provider.GetType()] = provider
	}

	return providers, nil
}

// loadRuleFromFile loads a single rule from a YAML file
func (yrl *YAMLRuleLoader) loadRuleFromFile(filePath string) (RuleProvider, error) {
	// Read YAML file
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Parse YAML
	var config YAMLRuleConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML from %s: %w", filePath, err)
	}

	// Validate required fields
	if err := validateYAMLConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid YAML config in %s: %w", filePath, err)
	}

	// Create rule provider
	provider, err := NewYAMLRuleProvider(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule provider from %s: %w", filePath, err)
	}

	return provider, nil
}

// validateYAMLConfig validates a YAML rule configuration
func validateYAMLConfig(config *YAMLRuleConfig) error {
	if config.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if config.Type == "" {
		return fmt.Errorf("rule type is required")
	}
	if config.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if len(config.Patterns) == 0 {
		return fmt.Errorf("at least one pattern is required")
	}

	// Validate patterns
	for i, pattern := range config.Patterns {
		if pattern.Type == "" {
			return fmt.Errorf("pattern %d: type is required", i)
		}
		if pattern.Pattern == "" {
			return fmt.Errorf("pattern %d: pattern is required", i)
		}
	}

	return nil
}

// convertYAMLToRule converts YAML config to Rule struct
func convertYAMLToRule(config *YAMLRuleConfig) (*types.Rule, error) {
	// Convert severity
	severity, err := parseSeverity(config.Severity)
	if err != nil {
		return nil, fmt.Errorf("invalid severity %s: %w", config.Severity, err)
	}

	// Convert vulnerability type
	vulnType, err := parseVulnerabilityType(config.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid vulnerability type %s: %w", config.Type, err)
	}

	// Convert patterns
	patterns := make([]types.Pattern, len(config.Patterns))
	for i, yamlPattern := range config.Patterns {
		pattern, err := convertYAMLPattern(yamlPattern)
		if err != nil {
			return nil, fmt.Errorf("failed to convert pattern %d: %w", i, err)
		}
		patterns[i] = pattern
	}

	// Convert OWASP reference
	owaspRef := types.OWASPReference{
		Top10_2021: config.OWASP.Top10_2021,
		Category:   config.OWASP.Category,
	}

	rule := &types.Rule{
		ID:          config.ID,
		Type:        vulnType,
		Name:        config.Name,
		Description: config.Description,
		Severity:    severity,
		Languages:   config.Languages,
		Patterns:    patterns,
		OWASP:       owaspRef,
		CWE:         config.CWE,
		Remediation: config.Remediation,
	}

	return rule, nil
}

// convertYAMLPattern converts YAML pattern to Pattern struct
func convertYAMLPattern(yamlPattern YAMLPattern) (types.Pattern, error) {
	patternType, err := parsePatternType(yamlPattern.Type)
	if err != nil {
		return types.Pattern{}, fmt.Errorf("invalid pattern type %s: %w", yamlPattern.Type, err)
	}

	pattern := types.Pattern{
		Type:        patternType,
		Pattern:     yamlPattern.Pattern,
		Description: yamlPattern.Description,
		Context:     yamlPattern.Context,
	}

	// Compile regex if it's a regex pattern
	if patternType == types.PatternRegex {
		flags := yamlPattern.Flags
		if flags == "" {
			flags = "i" // Default to case-insensitive
		}

		regex, err := regexp.Compile("(?i)" + yamlPattern.Pattern)
		if err != nil {
			return types.Pattern{}, fmt.Errorf("invalid regex pattern %s: %w", yamlPattern.Pattern, err)
		}
		pattern.Regex = regex
	}

	return pattern, nil
}

// parseSeverity parses severity string to SeverityLevel
func parseSeverity(severity string) (config.SeverityLevel, error) {
	switch strings.ToLower(severity) {
	case "critical":
		return config.SeverityCritical, nil
	case "high":
		return config.SeverityHigh, nil
	case "medium":
		return config.SeverityMedium, nil
	case "low":
		return config.SeverityLow, nil
	case "info":
		return config.SeverityLow, nil
	default:
		return config.SeverityMedium, fmt.Errorf("unknown severity level: %s", severity)
	}
}

// parseVulnerabilityType parses vulnerability type string
func parseVulnerabilityType(vulnType string) (types.VulnerabilityType, error) {
	switch strings.ToLower(vulnType) {
	case "sql_injection":
		return types.SQLInjection, nil
	case "xss":
		return types.XSS, nil
	case "path_traversal":
		return types.PathTraversal, nil
	case "command_injection":
		return types.CommandInjection, nil
	case "hardcoded_secrets":
		return types.HardcodedSecrets, nil
	case "weak_crypto":
		return types.WeakCrypto, nil
	case "insecure_random":
		return types.InsecureRandom, nil
	case "xxe":
		return types.XXE, nil
	case "ldap_injection":
		return types.LDAPInjection, nil
	case "unsafe_deserialization":
		return types.UnsafeDeserialization, nil
	case "csrf":
		return types.CSRFVuln, nil
	case "weak_authentication":
		return types.WeakAuthentication, nil
	case "insecure_transport":
		return types.InsecureTransport, nil
	case "buffer_overflow":
		return types.BufferOverflow, nil
	case "race_condition":
		return types.RaceCondition, nil
	default:
		return types.SQLInjection, fmt.Errorf("unknown vulnerability type: %s", vulnType)
	}
}

// parsePatternType parses pattern type string
func parsePatternType(patternType string) (types.PatternType, error) {
	switch strings.ToLower(patternType) {
	case "regex":
		return types.PatternRegex, nil
	case "literal":
		return types.PatternLiteral, nil
	case "function":
		return types.PatternFunction, nil
	case "ast":
		return types.PatternAST, nil
	default:
		return types.PatternRegex, fmt.Errorf("unknown pattern type: %s", patternType)
	}
}
