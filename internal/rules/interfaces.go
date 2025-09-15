package rules

import (
	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// RuleProvider defines the interface that all security rules must implement
type RuleProvider interface {
	// GetRule returns the rule definition
	GetRule() *types.Rule

	// GetID returns the unique identifier for this rule
	GetID() string

	// GetType returns the vulnerability type this rule detects
	GetType() types.VulnerabilityType

	// IsEnabled checks if this rule is enabled based on configuration
	IsEnabled(cfg *config.Config) bool

	// GetMetadata returns additional metadata about the rule
	GetMetadata() types.RuleMetadata
}

// BaseRule provides a default implementation of common RuleProvider methods
type BaseRule struct {
	rule     *types.Rule
	metadata types.RuleMetadata
}

// NewBaseRule creates a new BaseRule instance
func NewBaseRule(rule *types.Rule, metadata types.RuleMetadata) *BaseRule {
	return &BaseRule{
		rule:     rule,
		metadata: metadata,
	}
}

// GetRule returns the rule definition
func (br *BaseRule) GetRule() *types.Rule {
	return br.rule
}

// GetID returns the unique identifier for this rule
func (br *BaseRule) GetID() string {
	return br.rule.ID
}

// GetType returns the vulnerability type this rule detects
func (br *BaseRule) GetType() types.VulnerabilityType {
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
func (br *BaseRule) GetMetadata() types.RuleMetadata {
	return br.metadata
}

// RuleRegistry manages the registration and discovery of rule providers
type RuleRegistry struct {
	providers map[types.VulnerabilityType]RuleProvider
}

// NewRuleRegistry creates a new rule registry
func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{
		providers: make(map[types.VulnerabilityType]RuleProvider),
	}
}

// Register adds a rule provider to the registry
func (rr *RuleRegistry) Register(provider RuleProvider) {
	rr.providers[provider.GetType()] = provider
}

// GetProvider returns a rule provider by vulnerability type
func (rr *RuleRegistry) GetProvider(vulnType types.VulnerabilityType) RuleProvider {
	return rr.providers[vulnType]
}

// GetAllProviders returns all registered rule providers
func (rr *RuleRegistry) GetAllProviders() map[types.VulnerabilityType]RuleProvider {
	return rr.providers
}

// GetEnabledProviders returns only enabled rule providers based on configuration
func (rr *RuleRegistry) GetEnabledProviders(cfg *config.Config) []RuleProvider {
	var enabled []RuleProvider
	for _, provider := range rr.providers {
		if provider.IsEnabled(cfg) {
			enabled = append(enabled, provider)
		}
	}
	return enabled
}
