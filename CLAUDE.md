# Security Scanner - Claude Development Guide

## Overview
A Go-based security scanner that detects vulnerabilities and code quality issues across multiple programming languages. Features OWASP Top 10 compliance, parallel processing, and multiple output formats.

## Development Commands

### Build
```bash
go build -o security-scanner main.go
```

### Test
```bash
go test ./...
go test -v ./internal/...
```

### Run
```bash
# Build and run locally
./security-scanner .

# Run with specific options
./security-scanner --format json --output report.json --severity high .
./security-scanner --parallel 8 --verbose .
```

### Lint & Quality
```bash
go fmt ./...
go vet ./...
golangci-lint run
```

## Project Structure

```
security-scanner/
├── main.go                    # Entry point
├── cmd/                       # CLI command definitions
│   └── root.go
├── internal/
│   ├── cache/                 # Caching functionality
│   ├── config/                # Configuration management
│   ├── lsp/                   # Language Server Protocol client
│   ├── parser/                # AST parsing
│   ├── reporter/              # Output formatting
│   ├── rules/                 # Security rule definitions
│   └── scanner/               # Core scanning logic
├── examples/                  # Test cases and examples
└── test-cache-demo/          # Cache demonstration code
```

## Key Components

### Scanner Engine (`internal/scanner/`)
- Multi-threaded file processing
- Language detection and AST parsing
- Rule execution pipeline

### Security Rules (`internal/rules/`)
- OWASP Top 10 2021 mapping
- CWE classification
- Pattern matching (regex, literal, AST-based)
- Language-specific implementations

### LSP Integration (`internal/lsp/`)
- Symbol table generation using Serena MCP
- Deep code analysis and context understanding
- Function calls and variable tracking

### Configuration (`internal/config/`)
- YAML-based configuration
- Rule enable/disable
- Performance tuning options

## Adding New Security Rules

1. Define rule structure in `internal/rules/rules.go`:
```go
rule := &Rule{
    ID:          "CUSTOM-001",
    Name:        "Custom Vulnerability",
    Description: "Description of the issue",
    Severity:    config.SeverityHigh,
    Languages:   []string{"go", "php", "js"},
    Patterns: []Pattern{
        {Type: PatternRegex, Pattern: `vulnerable-pattern`},
    },
    OWASP:       OWASPReference{Top10_2021: "A03:2021"},
    CWE:         "CWE-XXX",
    Remediation: "How to fix this vulnerability",
}
```

2. Add pattern matching logic
3. Include language-specific implementations
4. Add test cases

## Configuration File

Create `.security-scanner.yaml` in project root:
```yaml
rules:
  enabled:
    - sql_injection
    - xss
    - hardcoded_secrets
  ignore_patterns:
    - "vendor/"
    - "node_modules/"

output:
  format: "json"
  severity: "medium"

performance:
  parallel: 4
```

## Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration management
- `go.uber.org/zap` - Structured logging

## Supported Languages
- Go, PHP, JavaScript, TypeScript
- Java, Python, Ruby
- C#, C/C++

## Output Formats
- **Text**: Human-readable reports
- **JSON**: Structured data for CI/CD integration
- **SARIF**: Industry standard static analysis format

## Performance Notes
- ~1000 lines/second per core
- ~50MB memory for 100k+ lines of code
- Configurable parallel workers
- Streaming file processing

## Testing
- Unit tests for each component
- Integration tests with sample vulnerable code
- Performance benchmarks
- CI/CD pipeline integration tests