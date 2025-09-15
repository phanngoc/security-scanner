# Contributing Security Rules

This guide explains how to contribute custom security rules to the security scanner. The modular architecture makes it easy for developers to add new rules while maintaining code quality and consistency.

## Architecture Overview

The security scanner uses a modular rule system with the following structure:

```
internal/rules/
├── interfaces.go          # Rule interfaces and base classes
├── loader.go              # Rule discovery and loading
├── rules.go               # Main rule engine
├── owasp/                 # Built-in OWASP rules
│   ├── sql_injection.go
│   ├── xss.go
│   ├── path_traversal.go
│   ├── command_injection.go
│   └── hardcoded_secrets.go
├── custom/                # Custom rules directory
├── templates/             # Rule templates and examples
│   └── rule_template.go
```

## Quick Start

1. **Copy the template**: Start with `/internal/rules/templates/rule_template.go`
2. **Customize the rule**: Follow the template comments to implement your detection logic
3. **Test the rule**: Create test cases and validate detection accuracy
4. **Register the rule**: Add it to the rule loader (for built-in rules)

## Creating a New Rule

### Step 1: Define Your Rule Structure

Create a new file in the appropriate directory:
- `/internal/rules/owasp/` - For OWASP-compliant rules
- `/internal/rules/custom/` - For custom or organization-specific rules

```go
package owasp  // or 'custom' for custom rules

import (
    "github.com/le-company/security-scanner/internal/config"
    "github.com/le-company/security-scanner/internal/rules"
)

type MyCustomRule struct {
    *rules.BaseRule
}

func NewMyCustomRule() *MyCustomRule {
    // Implementation here
}
```

### Step 2: Implement Rule Definition

Fill in the rule structure with your detection patterns:

```go
rule := &rules.Rule{
    ID:          "CUSTOM-001",
    Type:        rules.VulnerabilityType("my_vulnerability"),
    Name:        "My Custom Vulnerability",
    Description: "Detailed description of what this detects",
    Severity:    config.SeverityHigh,
    Languages:   []string{"go", "java", "python"},
    Patterns: []rules.Pattern{
        {
            Type:        rules.PatternRegex,
            Pattern:     `(?i)dangerous_function\s*\([^)]*user_input`,
            Description: "Function call with user input",
            Context:     "function_call",
        },
    },
    OWASP:       rules.OWASPReference{...},
    CWE:         "CWE-XXX",
    Remediation: "How to fix this vulnerability",
}
```

### Step 3: Add Detection Patterns

#### Pattern Types

- **PatternRegex**: Regular expression matching (most common)
- **PatternLiteral**: Exact string matching
- **PatternFunction**: Custom function-based detection
- **PatternAST**: Abstract Syntax Tree analysis

#### Writing Effective Regex Patterns

```go
patterns := []rules.Pattern{
    // Basic user input detection
    {
        Pattern: `\$_(GET|POST|REQUEST|COOKIE)\[`,
        Context: "php_user_input",
    },

    // Function calls with user input
    {
        Pattern: `(?i)(dangerous_func)\s*\(\s*.*\$_(GET|POST)`,
        Context: "function_with_input",
    },

    // Cross-language patterns
    {
        Pattern: `(?i)(request\.(query|body|params)|req\.(query|body))`,
        Context: "nodejs_user_input",
    },
}
```

### Step 4: Implement Custom Detection Logic (Optional)

For complex detection beyond regex patterns:

```go
func (r *MyCustomRule) IsVulnerable(code string, context string) bool {
    // Check standard patterns first
    rule := r.GetRule()
    for _, pattern := range rule.Patterns {
        if pattern.Regex != nil && pattern.Regex.MatchString(code) {
            return true
        }
    }

    // Add custom logic
    if r.hasComplexVulnerability(code, context) {
        return true
    }

    return false
}

func (r *MyCustomRule) hasComplexVulnerability(code string, context string) bool {
    // Implement sophisticated detection logic
    // Example: AST analysis, multi-line pattern matching, etc.
    return false
}
```

### Step 5: Add Language-Specific Recommendations

```go
func (r *MyCustomRule) GetRecommendations(language string) []string {
    recommendations := []string{
        "General security recommendation",
    }

    switch language {
    case "go":
        recommendations = append(recommendations,
            "Use Go-specific secure functions",
            "Example: Use html/template instead of text/template",
        )
    case "java":
        recommendations = append(recommendations,
            "Use Java security APIs",
            "Example: Use PreparedStatement for SQL queries",
        )
    }

    return recommendations
}
```

## Rule Registration

### Built-in Rules

For built-in rules, add them to the `LoadBuiltinRules()` method in `loader.go`:

```go
func (rl *RuleLoader) LoadBuiltinRules() error {
    // Existing rules...
    rl.registerBuiltinRule(owasp.NewMyCustomRule())

    return nil
}
```

### Plugin Rules

For external plugin rules, compile as a shared library:

```bash
go build -buildmode=plugin -o my_rule.so my_rule.go
```

The plugin must export a `RuleProvider` symbol:

```go
var RuleProvider rules.RuleProvider = NewMyCustomRule()
```

## Testing Rules

### Unit Tests

Create comprehensive unit tests for your rule:

```go
func TestMyCustomRule(t *testing.T) {
    rule := NewMyCustomRule()

    // Test positive cases
    vulnerableCode := `dangerous_function($_GET['input'])`
    if !rule.IsVulnerable(vulnerableCode, "php") {
        t.Error("Should detect vulnerability")
    }

    // Test negative cases
    safeCode := `safe_function(validated_input)`
    if rule.IsVulnerable(safeCode, "php") {
        t.Error("Should not detect false positive")
    }
}
```

### Integration Tests

Test with real code samples:

```go
func TestMyCustomRuleIntegration(t *testing.T) {
    // Load test files
    testFiles := []string{
        "testdata/vulnerable_sample.php",
        "testdata/safe_sample.php",
    }

    rule := NewMyCustomRule()

    for _, file := range testFiles {
        content := readFile(file)
        result := rule.IsVulnerable(content, "php")
        // Assert expected results
    }
}
```

## Best Practices

### 1. Pattern Design

- **Be specific**: Avoid overly broad patterns that cause false positives
- **Use case-insensitive matching**: `(?i)` flag for better coverage
- **Consider language variations**: Different ways to express the same concept
- **Test edge cases**: Empty strings, special characters, multi-line code

### 2. False Positive Reduction

```go
// Good: Specific function with user input
pattern := `(?i)system\s*\(\s*.*\$_(GET|POST|REQUEST)`

// Bad: Too broad, many false positives
pattern := `(?i)system\s*\(`
```

### 3. Performance Considerations

- **Compile regex once**: Use `CompileRegex()` method
- **Efficient patterns**: Avoid catastrophic backtracking
- **Limit scope**: Use context to reduce unnecessary checks

### 4. Documentation

- **Clear descriptions**: Explain what the rule detects
- **Provide examples**: Show vulnerable and safe code patterns
- **Reference standards**: Link to CWE, OWASP, or other security resources
- **Update metadata**: Keep version, author, and update dates current

### 5. Remediation Guidance

Provide actionable remediation advice:

```go
Remediation: `Replace direct user input concatenation with parameterized queries:

BAD:  query := "SELECT * FROM users WHERE id = " + userInput
GOOD: query := "SELECT * FROM users WHERE id = ?"
      stmt.Exec(query, userInput)

Use prepared statements or ORM frameworks with built-in protections.`
```

## Rule Validation Checklist

Before submitting a rule, ensure:

- [ ] **Accurate Detection**: Rule detects intended vulnerabilities
- [ ] **Low False Positives**: Minimal incorrect detections
- [ ] **Clear Documentation**: Well-documented patterns and remediation
- [ ] **Test Coverage**: Comprehensive unit and integration tests
- [ ] **Performance**: Efficient regex patterns and logic
- [ ] **Language Support**: Appropriate language coverage
- [ ] **Metadata Complete**: All required fields filled
- [ ] **OWASP/CWE Mapping**: Proper security standard references

## Configuration

Rules can be enabled/disabled via configuration:

```yaml
rules:
  enabled:
    - sql_injection
    - xss
    - my_custom_rule
  disabled:
    - some_other_rule
  custom_rules_path: "/path/to/custom/rules"
```

## Advanced Features

### Custom Pattern Types

Implement custom pattern matching:

```go
type CustomPatternMatcher struct{}

func (c *CustomPatternMatcher) Match(code string, pattern string) bool {
    // Custom matching logic
    return false
}
```

### Context-Aware Detection

Use code context for better accuracy:

```go
func (r *MyRule) IsVulnerable(code string, context string) bool {
    switch context {
    case "function_parameter":
        return r.checkParameterVulnerability(code)
    case "variable_assignment":
        return r.checkAssignmentVulnerability(code)
    }
    return false
}
```

### Multi-Language Support

Design patterns for cross-language compatibility:

```go
patterns := map[string][]rules.Pattern{
    "php": {
        {Pattern: `\$_(GET|POST|REQUEST)`, Context: "user_input"},
    },
    "javascript": {
        {Pattern: `req\.(query|body|params)`, Context: "user_input"},
    },
    "python": {
        {Pattern: `request\.(GET|POST)`, Context: "user_input"},
    },
}
```

## Support and Community

- **Issues**: Report bugs or request features on GitHub
- **Discussions**: Join security discussions in the community forum
- **Documentation**: Contribute to documentation improvements
- **Examples**: Share real-world rule examples

## Rule Contribution Process

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/my-custom-rule`
3. **Implement the rule** following this guide
4. **Add comprehensive tests**
5. **Update documentation** if needed
6. **Submit a pull request** with detailed description

## Examples

See the `/internal/rules/owasp/` directory for comprehensive examples of well-implemented security rules. Each rule demonstrates different patterns and techniques for effective vulnerability detection.