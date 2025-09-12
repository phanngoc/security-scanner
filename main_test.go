package main

import (
	"testing"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules"
)

func TestRuleEngine(t *testing.T) {
	cfg := &config.Config{
		Rules: config.RulesConfig{
			Enabled: []string{"sql_injection", "xss"},
		},
	}

	engine := rules.NewRuleEngine(cfg)
	enabledRules := engine.GetEnabledRules()

	if len(enabledRules) != 2 {
		t.Errorf("Expected 2 enabled rules, got %d", len(enabledRules))
	}

	// Test SQL injection rule
	sqlRule := engine.GetRule(rules.SQLInjection)
	if sqlRule == nil {
		t.Error("SQL injection rule not found")
	}

	if !engine.IsEnabled(rules.SQLInjection) {
		t.Error("SQL injection rule should be enabled")
	}

	// Test disabled rule
	if engine.IsEnabled(rules.CommandInjection) {
		t.Error("Command injection rule should be disabled")
	}
}

func TestConfigLoad(t *testing.T) {
	cfg := config.Load()

	if cfg == nil {
		t.Error("Config should not be nil")
	}

	if cfg.Parallel <= 0 {
		t.Error("Parallel workers should be > 0")
	}

	if len(cfg.Rules.Enabled) == 0 {
		t.Error("Should have enabled rules by default")
	}
}

func TestSeverityParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected config.SeverityLevel
	}{
		{"low", config.SeverityLow},
		{"medium", config.SeverityMedium},
		{"high", config.SeverityHigh},
		{"critical", config.SeverityCritical},
		{"invalid", config.SeverityMedium},
	}

	for _, test := range tests {
		result := config.ParseSeverity(test.input)
		if result != test.expected {
			t.Errorf("ParseSeverity(%s) = %v, expected %v", test.input, result, test.expected)
		}
	}
}
