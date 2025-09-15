package rules

import (
	"github.com/le-company/security-scanner/internal/analyzer"
	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// RuleEngine manages security rules
type RuleEngine struct {
	rules    map[types.VulnerabilityType]*types.Rule
	enabled  map[types.VulnerabilityType]bool
	loader   *RuleLoader
	registry *RuleRegistry
}

// NewRuleEngine creates a new rule engine with OWASP-compliant rules
func NewRuleEngine(cfg *config.Config) *RuleEngine {
	loader := NewRuleLoader()

	// Create analyzer registry for dynamic loading
	analyzerRegistry := analyzer.NewAnalyzerRegistry()

	// Load all rules (built-in and custom)
	if err := loader.LoadAllRules(analyzerRegistry); err != nil {
		// Log error but continue with available rules
		// TODO: Add proper logging
	}

	// Validate loaded rules
	if err := loader.ValidateRules(); err != nil {
		// Log validation errors but continue
		// TODO: Add proper logging
	}

	ruleRegistry := loader.GetRegistry()

	engine := &RuleEngine{
		rules:    make(map[types.VulnerabilityType]*types.Rule),
		enabled:  make(map[types.VulnerabilityType]bool),
		loader:   loader,
		registry: ruleRegistry,
	}

	// Convert registry rules to the legacy format for compatibility
	for vulnType, provider := range ruleRegistry.GetAllProviders() {
		rule := provider.GetRule()
		engine.rules[vulnType] = rule

		// Configure enabled rules based on configuration
		engine.enabled[vulnType] = provider.IsEnabled(cfg)
	}

	// Override with explicit configuration
	for _, ruleName := range cfg.Rules.Enabled {
		if vulnType := types.VulnerabilityType(ruleName); engine.rules[vulnType] != nil {
			engine.enabled[vulnType] = true
		}
	}

	// Disable explicitly disabled rules
	for _, ruleName := range cfg.Rules.Disabled {
		if vulnType := types.VulnerabilityType(ruleName); engine.rules[vulnType] != nil {
			engine.enabled[vulnType] = false
		}
	}

	return engine
}

// GetRuleProvider returns a rule provider by vulnerability type
func (re *RuleEngine) GetRuleProvider(vulnType types.VulnerabilityType) RuleProvider {
	if re.registry != nil {
		return re.registry.GetProvider(vulnType)
	}
	return nil
}

// GetAllRuleProviders returns all registered rule providers
func (re *RuleEngine) GetAllRuleProviders() map[types.VulnerabilityType]RuleProvider {
	if re.registry != nil {
		return re.registry.GetAllProviders()
	}
	return make(map[types.VulnerabilityType]RuleProvider)
}

// GetEnabledRuleProviders returns only enabled rule providers
func (re *RuleEngine) GetEnabledRuleProviders() []RuleProvider {
	var enabled []RuleProvider
	if re.registry != nil {
		for vulnType, provider := range re.registry.GetAllProviders() {
			if re.enabled[vulnType] {
				enabled = append(enabled, provider)
			}
		}
	}
	return enabled
}

// GetRuleStatistics returns statistics about loaded rules
func (re *RuleEngine) GetRuleStatistics() map[string]interface{} {
	if re.loader != nil {
		return re.loader.GetStatistics()
	}
	return make(map[string]interface{})
}

// ReloadRules reloads all rules from their sources
func (re *RuleEngine) ReloadRules(cfg *config.Config) error {
	if re.loader != nil {
		// Create analyzer registry for dynamic loading
		registry := analyzer.NewAnalyzerRegistry()
		return re.loader.LoadAllRules(registry)
	}
	return nil
}

// addRule adds a rule to the engine (legacy compatibility)
func (re *RuleEngine) addRule(rule *types.Rule) {
	re.rules[rule.Type] = rule
}

// GetEnabledRules returns all enabled rules
func (re *RuleEngine) GetEnabledRules() []*types.Rule {
	var rules []*types.Rule
	for vulnType, rule := range re.rules {
		if re.enabled[vulnType] {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetRule returns a specific rule by type
func (re *RuleEngine) GetRule(vulnType types.VulnerabilityType) *types.Rule {
	return re.rules[vulnType]
}

// IsEnabled checks if a rule is enabled
func (re *RuleEngine) IsEnabled(vulnType types.VulnerabilityType) bool {
	return re.enabled[vulnType]
}
