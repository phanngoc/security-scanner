package rules

import (
	"fmt"
	"path/filepath"
	"plugin"
	"reflect"

	"go.uber.org/zap"

	"github.com/le-company/security-scanner/internal/analyzer"
	otpRules "github.com/le-company/security-scanner/internal/rules/S077_OTP"
	sqlRules "github.com/le-company/security-scanner/internal/rules/S017_SQLInjection"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// RuleLoader handles dynamic loading of security rules
type RuleLoader struct {
	registry     *RuleRegistry
	builtinRules map[types.VulnerabilityType]RuleProvider
	logger       *zap.Logger
}

// NewRuleLoader creates a new rule loader
func NewRuleLoader() *RuleLoader {
	return &RuleLoader{
		registry:     NewRuleRegistry(),
		builtinRules: make(map[types.VulnerabilityType]RuleProvider),
	}
}

// NewLoader creates a new rule loader with logger
func NewLoader(logger *zap.Logger) *RuleLoader {
	return &RuleLoader{
		registry:     NewRuleRegistry(),
		builtinRules: make(map[types.VulnerabilityType]RuleProvider),
		logger:       logger,
	}
}

// LoadAllRules loads all rules and registers them with the analyzer registry
func (rl *RuleLoader) LoadAllRules(registry *analyzer.AnalyzerRegistry) error {
	// Load and register OTP analyzer
	otpAnalyzer := otpRules.NewOTPAnalyzer()
	registry.Register(otpAnalyzer)

	// Load and register SQL Injection analyzer
	sqlAnalyzer := sqlRules.NewSQLInjectionAnalyzer()
	registry.Register(sqlAnalyzer)

	// Load built-in OWASP rules
	if err := rl.LoadBuiltinRules(); err != nil {
		if rl.logger != nil {
			rl.logger.Warn("Failed to load built-in rules", zap.Error(err))
		}
	}

	if rl.logger != nil {
		rl.logger.Info("Successfully loaded security rules")
	}
	return nil
}

// LoadBuiltinRules loads all built-in security rules
func (rl *RuleLoader) LoadBuiltinRules() error {
	// For now, only load OTP rules
	// Other rules can be added later
	if rl.logger != nil {
		rl.logger.Info("Loading built-in security rules")
	}

	return nil
}

// registerBuiltinRule registers a built-in rule provider
func (rl *RuleLoader) registerBuiltinRule(provider RuleProvider) {
	rl.builtinRules[provider.GetType()] = provider
	rl.registry.Register(provider)
}

// LoadCustomRules loads custom rules from the specified directory
func (rl *RuleLoader) LoadCustomRules(customRulesPath string) error {
	if customRulesPath == "" {
		return nil // No custom rules path specified
	}

	// Load YAML-based rules
	yamlLoader := NewYAMLRuleLoader(customRulesPath)
	yamlProviders, err := yamlLoader.LoadRules()
	if err != nil {
		return fmt.Errorf("failed to load YAML rules: %w", err)
	}

	// Register YAML rule providers
	for vulnType, provider := range yamlProviders {
		rl.registry.Register(provider)
		fmt.Printf("Loaded YAML rule: %s (%s)\n", provider.GetID(), vulnType)
	}

	// Load plugin-based rules
	pluginPattern := filepath.Join(customRulesPath, "*.so")
	pluginFiles, err := filepath.Glob(pluginPattern)
	if err != nil {
		return fmt.Errorf("error finding plugin files: %w", err)
	}

	for _, pluginFile := range pluginFiles {
		if err := rl.loadPluginRule(pluginFile); err != nil {
			// Log error but continue loading other plugins
			fmt.Printf("Warning: failed to load plugin rule from %s: %v\n", pluginFile, err)
		}
	}

	return nil
}

// loadPluginRule loads a single plugin-based rule
func (rl *RuleLoader) loadPluginRule(pluginPath string) error {
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", pluginPath, err)
	}

	// Look for the standard rule provider symbol
	symProvider, err := p.Lookup("RuleProvider")
	if err != nil {
		return fmt.Errorf("plugin %s does not export RuleProvider symbol: %w", pluginPath, err)
	}

	// Verify the symbol implements RuleProvider interface
	provider, ok := symProvider.(RuleProvider)
	if !ok {
		return fmt.Errorf("plugin %s RuleProvider does not implement the correct interface", pluginPath)
	}

	// Register the plugin rule
	rl.registry.Register(provider)
	return nil
}

// GetRegistry returns the rule registry
func (rl *RuleLoader) GetRegistry() *RuleRegistry {
	return rl.registry
}

// ValidateRules validates all loaded rules
func (rl *RuleLoader) ValidateRules() error {
	for vulnType, provider := range rl.registry.GetAllProviders() {
		rule := provider.GetRule()
		if rule == nil {
			return fmt.Errorf("rule provider for %s returned nil rule", vulnType)
		}

		// Validate rule structure
		if rule.ID == "" {
			return fmt.Errorf("rule %s has empty ID", vulnType)
		}

		if rule.Name == "" {
			return fmt.Errorf("rule %s has empty Name", rule.ID)
		}

		if len(rule.Patterns) == 0 {
			return fmt.Errorf("rule %s has no patterns defined", rule.ID)
		}

		// Compile regex patterns
		for i := range rule.Patterns {
			if err := rule.Patterns[i].CompileRegex(); err != nil {
				return fmt.Errorf("rule %s has invalid regex pattern: %w", rule.ID, err)
			}
		}
	}

	return nil
}

// GetStatistics returns statistics about loaded rules
func (rl *RuleLoader) GetStatistics() map[string]interface{} {
	allProviders := rl.registry.GetAllProviders()

	stats := make(map[string]interface{})
	stats["total_rules"] = len(allProviders)
	stats["builtin_rules"] = len(rl.builtinRules)
	stats["custom_rules"] = len(allProviders) - len(rl.builtinRules)

	// Count by severity
	severityCount := make(map[string]int)
	for _, provider := range allProviders {
		severity := provider.GetRule().Severity.String()
		severityCount[severity]++
	}
	stats["by_severity"] = severityCount

	// Count by OWASP category
	owaspCount := make(map[string]int)
	for _, provider := range allProviders {
		category := provider.GetRule().OWASP.Category
		if category != "" {
			owaspCount[category]++
		}
	}
	stats["by_owasp_category"] = owaspCount

	return stats
}

// isValidRuleProvider checks if a value implements RuleProvider interface
func isValidRuleProvider(v interface{}) bool {
	providerType := reflect.TypeOf((*RuleProvider)(nil)).Elem()
	return reflect.TypeOf(v).Implements(providerType)
}
