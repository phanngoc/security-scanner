# Security Scanner

A powerful, fast, and OWASP-compliant security scanner for source code that helps developers detect security vulnerabilities and code quality issues.

## Features

- ✅ **OWASP Top 10 Coverage**: Comprehensive security rules based on OWASP Top 10 2021
- ⚡ **Fast Parallel Processing**: Multi-threaded scanning with configurable worker pools
- 🔍 **Multi-Language Support**: Go, PHP, JavaScript, TypeScript, Java, Python, Ruby, C#, C/C++
- 🧠 **Symbol Table Analysis**: Deep AST parsing and symbol table generation using Serena MCP
- 📊 **Multiple Output Formats**: Text, JSON, and SARIF reports
- 🎯 **Severity Filtering**: Filter results by severity levels (low, medium, high, critical)
- ⚙️ **Configurable Rules**: Enable/disable rules and customize patterns
- 🔧 **CLI Interface**: Easy-to-use command-line interface

## Security Rules Covered

### OWASP Top 10 2021 Mapping

| OWASP Category | Security Rules | CWE |
|---|---|---|
| **A01:2021 – Broken Access Control** | Path Traversal | CWE-22 |
| **A02:2021 – Cryptographic Failures** | Hardcoded Secrets, Weak Crypto | CWE-798, CWE-327 |
| **A03:2021 – Injection** | SQL Injection, XSS, Command Injection, LDAP Injection | CWE-89, CWE-79, CWE-78, CWE-90 |
| **A04:2021 – Insecure Design** | Race Conditions, Weak Authentication | CWE-362, CWE-287 |
| **A05:2021 – Security Misconfiguration** | Insecure Transport | CWE-319 |
| **A06:2021 – Vulnerable Components** | Buffer Overflow | CWE-120 |
| **A08:2021 – Software Data Integrity** | Unsafe Deserialization | CWE-502 |
| **A09:2021 – Security Logging** | XXE | CWE-611 |
| **A10:2021 – SSRF** | CSRF | CWE-352 |

## Installation

```bash
# Clone the repository
git clone https://github.com/le-company/security-scanner.git
cd security-scanner

# Build the scanner
go build -o security-scanner main.go

# Or install directly
go install github.com/le-company/security-scanner@latest
```

## Quick Start

```bash
# Scan current directory
./security-scanner .

# Scan with JSON output
./security-scanner --format json --output report.json /path/to/code

# Scan with specific severity level
./security-scanner --severity high /path/to/code

# Use custom number of parallel workers
./security-scanner --parallel 8 /path/to/code

# Verbose output
./security-scanner --verbose /path/to/code
```

## Configuration

Create a `.security-scanner.yaml` file in your project root:

```yaml
rules:
  enabled:
    - sql_injection
    - xss
    - hardcoded_secrets
  ignore_patterns:
    - "vendor/"
    - "node_modules/"
  file_extensions:
    - ".go"
    - ".php"
    - ".js"

output:
  format: "json"
  severity: "medium"

performance:
  parallel: 4
```

## Command Line Options

```
Usage: security-scanner [path]

Flags:
  -c, --config string      Config file (default ".security-scanner.yaml")
  -f, --format string      Output format (text, json, sarif) (default "text")
  -o, --output string      Output file (default: stdout)
  -p, --parallel int       Number of parallel workers (0 = auto) (default 0)
  -s, --severity string    Minimum severity level (low, medium, high, critical) (default "medium")
  -v, --verbose            Verbose output
  -h, --help              Help for security-scanner
```

## Output Formats

### Text Format (Default)
Human-readable report with detailed findings, context, and remediation suggestions.

### JSON Format
Structured JSON output suitable for integration with CI/CD pipelines and other tools.

### SARIF Format
Static Analysis Results Interchange Format (SARIF) - industry standard for static analysis tools.

## Pipeline Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    - name: Install Security Scanner
      run: go install github.com/le-company/security-scanner@latest
    - name: Run Security Scan
      run: security-scanner --format sarif --output results.sarif .
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: golang:1.21
  script:
    - go install github.com/le-company/security-scanner@latest
    - security-scanner --format json --output security-report.json .
  artifacts:
    reports:
      security: security-report.json
```

## Architecture

### Parallel Processing Pipeline

The scanner uses a multi-stage pipeline architecture:

1. **File Discovery**: Walks directory tree and identifies files to scan
2. **Language Detection**: Determines programming language for each file
3. **Symbol Table Generation**: Parses AST and builds symbol tables using Serena MCP
4. **Rule Execution**: Applies security rules in parallel workers
5. **Result Aggregation**: Collects and filters findings
6. **Report Generation**: Formats output in requested format

### Symbol Table Analysis

The scanner builds comprehensive symbol tables including:
- Function definitions and calls
- Variable declarations and usage
- Import/include statements
- Type information
- Control flow analysis

### Security Rules Engine

Each rule includes:
- Pattern matching (regex, literal, AST-based)
- Severity classification
- OWASP and CWE mappings
- Remediation guidance
- Language-specific implementations

## Performance

- **Parallel Processing**: Utilizes all available CPU cores by default
- **Memory Efficient**: Streams file processing without loading entire codebase
- **Fast AST Parsing**: Native Go parser with optimized symbol table generation
- **Configurable Workers**: Adjust parallelism based on system resources

Typical performance on a modern system:
- ~1000 lines/second per core
- ~50MB memory usage for 100k+ lines of code
- Scales linearly with CPU cores

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Implement your changes with tests
4. Run the test suite: `go test ./...`
5. Submit a pull request

### Adding New Security Rules

```go
// Add to internal/rules/rules.go
rule := &Rule{
    ID:          "CUSTOM-001",
    Type:        CustomVulnerability,
    Name:        "Custom Security Rule",
    Description: "Description of the vulnerability",
    Severity:    config.SeverityHigh,
    Languages:   []string{"go", "java"},
    Patterns: []Pattern{
        {
            Type:    PatternRegex,
            Pattern: `vulnerable-pattern-regex`,
        },
    },
    OWASP:       OWASPReference{Top10_2021: "A03:2021", Category: "Injection"},
    CWE:         "CWE-XXX",
    Remediation: "How to fix this vulnerability",
}
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security

If you discover a security vulnerability in this tool, please report it privately to [security@le-company.com](mailto:security@le-company.com).

## Acknowledgments

- OWASP Foundation for security guidelines
- Go team for excellent AST parsing capabilities
- Static analysis community for SARIF standard
- Contributors and security researchers
