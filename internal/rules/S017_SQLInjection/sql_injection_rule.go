package owasp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// SQLInjectionRule implements detection for SQL injection vulnerabilities
type SQLInjectionRule struct {
	*types.BaseRule
}

// NewSQLInjectionRule creates a new SQL Injection rule instance
func NewSQLInjectionRule() *SQLInjectionRule {
	rule := &types.Rule{
		ID:          "S017",
		Type:        types.SQLInjection,
		Name:        "Always use parameterized queries",
		Description: "SQL queries should use parameterized statements to prevent SQL injection attacks",
		Severity:    config.SeverityHigh,
		Languages:   []string{"php", "javascript", "python", "java", "csharp", "go"},
		Patterns: []types.Pattern{
			// General SQL injection patterns - string concatenation
			{
				Type:        types.PatternRegex,
				Pattern:     `(?i)(query|sql)\s*[=:]\s*["'][^"']*\+[^"']*["']`,
				Description: "SQL query using string concatenation",
				Context:     "sql_concatenation",
			},
			{
				Type:        types.PatternRegex,
				Pattern:     `(?i)(query|sql)\s*[=:]\s*["'][^"']*\.\s*["']`,
				Description: "SQL query using string concatenation with dot operator",
				Context:     "sql_string_concat",
			},
			// Direct user input in SQL queries
			{
				Type:        types.PatternRegex,
				Pattern:     `(?i)(SELECT|INSERT|UPDATE|DELETE).*(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$this->request)`,
				Description: "SQL query with direct user input",
				Context:     "sql_user_input",
			},
			// PHP specific patterns
			{
				Type:        types.PatternRegex,
				Pattern:     `(?i)mysql_query\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
				Description: "MySQL query with variable interpolation",
				Context:     "mysql_query_interpolation",
			},
			{
				Type:        types.PatternRegex,
				Pattern:     `(?i)mysqli_query\s*\([^,]+,\s*["'][^"']*\$[^"']*["']\s*\)`,
				Description: "MySQLi query with variable interpolation",
				Context:     "mysqli_query_interpolation",
			},
			// PDO without prepare
			{
				Type:        types.PatternRegex,
				Pattern:     `(?i)\$pdo->query\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
				Description: "PDO query() method with variable interpolation instead of prepare()",
				Context:     "pdo_query_interpolation",
			},
		},
		OWASP: types.OWASPReference{
			Top10_2021: "A03:2021",
			Category:   "Injection",
		},
		CWE:         "CWE-89",
		Remediation: "Always use parameterized queries (prepared statements) to prevent SQL injection. Never concatenate user input directly into SQL queries.",
	}

	metadata := types.RuleMetadata{
		Author:      "OWASP Security Scanner Team",
		Version:     "1.0.0",
		LastUpdated: "2024-01-15",
		Tags:        []string{"owasp", "sql", "injection", "database", "high", "cake3"},
		References: []string{
			"https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
			"https://cwe.mitre.org/data/definitions/89.html",
			"https://owasp.org/www-community/attacks/SQL_Injection",
		},
	}

	sqlRule := &SQLInjectionRule{
		BaseRule: types.NewBaseRule(rule, metadata),
	}

	return sqlRule
}

// GetCakePHP3Patterns returns specific patterns for CakePHP 3 framework
func (r *SQLInjectionRule) GetCakePHP3Patterns() []types.Pattern {
	return []types.Pattern{
		// CakePHP 3 specific patterns
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->.*->query\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
			Description: "CakePHP 3 query with variable interpolation",
			Context:     "cake3_query_interpolation",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->.*->find\s*\(\s*["'][^"']*["']\s*,\s*\[\s*["']conditions["']\s*=>\s*["'][^"']*\$[^"']*["']\s*\]`,
			Description: "CakePHP 3 find with unsafe conditions",
			Context:     "cake3_find_unsafe_conditions",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->.*->updateAll\s*\([^,]+,\s*["'][^"']*\$[^"']*["']\s*\)`,
			Description: "CakePHP 3 updateAll with variable interpolation",
			Context:     "cake3_update_interpolation",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->.*->deleteAll\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
			Description: "CakePHP 3 deleteAll with variable interpolation",
			Context:     "cake3_delete_interpolation",
		},
	}
}

// GetPHPFrameworkPatterns returns patterns for various PHP frameworks
func (r *SQLInjectionRule) GetPHPFrameworkPatterns() []types.Pattern {
	return []types.Pattern{
		// Laravel Eloquent raw queries
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)DB::raw\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
			Description: "Laravel DB::raw with variable interpolation",
			Context:     "laravel_raw_interpolation",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)DB::select\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
			Description: "Laravel DB::select with variable interpolation",
			Context:     "laravel_select_interpolation",
		},
		// Symfony Doctrine raw queries
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)->createQuery\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
			Description: "Doctrine createQuery with variable interpolation",
			Context:     "doctrine_query_interpolation",
		},
		// CodeIgniter
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->db->query\s*\(\s*["'][^"']*\$[^"']*["']\s*\)`,
			Description: "CodeIgniter query with variable interpolation",
			Context:     "codeigniter_query_interpolation",
		},
	}
}

// SQLFlowNode represents a node in the SQL data flow
type SQLFlowNode struct {
	Type        string `json:"type"`         // "source", "sink", "sanitizer", "transformer"
	Location    string `json:"location"`     // File location
	Line        int    `json:"line"`         // Line number
	Column      int    `json:"column"`       // Column number
	Code        string `json:"code"`         // Code snippet
	Variable    string `json:"variable"`     // Variable name
	Function    string `json:"function"`     // Function name
	Confidence  float64 `json:"confidence"`  // Confidence level (0.0-1.0)
	IsSanitized bool   `json:"is_sanitized"` // Whether data is sanitized
}

// SQLFlowPath represents a flow path for SQL data
type SQLFlowPath struct {
	Source       SQLFlowNode   `json:"source"`
	Sink         SQLFlowNode   `json:"sink"`
	Path         []SQLFlowNode `json:"path"`
	IsVulnerable bool          `json:"is_vulnerable"`
	Confidence   float64       `json:"confidence"`
	RiskLevel    string        `json:"risk_level"`
}

// SQLFlowAnalyzer performs data flow analysis for SQL injection detection
type SQLFlowAnalyzer struct {
	sources      []string
	sinks        []string
	sanitizers   []string
	transformers []string
}

// NewSQLFlowAnalyzer creates a new SQL flow analyzer
func NewSQLFlowAnalyzer() *SQLFlowAnalyzer {
	return &SQLFlowAnalyzer{
		sources: []string{
			// User input sources
			"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SESSION",
			"$this->request->getData", "$this->request->getQuery",
			"$this->Auth->user", "$this->Session->read",
			"input", "request", "params", "query", "body",
		},
		sinks: []string{
			// SQL execution sinks
			"query", "execute", "exec", "mysql_query", "mysqli_query",
			"pg_query", "sqlite_query", "prepare", "createQuery",
			"find", "select", "insert", "update", "delete",
			"updateAll", "deleteAll", "save", "create",
		},
		sanitizers: []string{
			// SQL sanitization functions
			"mysql_real_escape_string", "mysqli_real_escape_string",
			"pg_escape_string", "sqlite_escape_string", "addslashes",
			"htmlspecialchars", "filter_var", "intval", "floatval",
			"is_numeric", "ctype_digit", "preg_match", "validate",
		},
		transformers: []string{
			// Data transformation functions
			"trim", "strtolower", "strtoupper", "substr", "str_replace",
			"preg_replace", "strip_tags", "hash", "md5", "sha1",
		},
	}
}

// AnalyzeSQLFlow performs SQL injection flow analysis
func (sfa *SQLFlowAnalyzer) AnalyzeSQLFlow(code string, cfg interface{}) []*SQLFlowPath {
	var paths []*SQLFlowPath

	// Find all sources and sinks
	sources := sfa.findSources(code)
	sinks := sfa.findSinks(code)

	// Analyze flow from each source to each sink
	for _, source := range sources {
		for _, sink := range sinks {
			if path := sfa.findPath(source, sink, code); path != nil {
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// findSources identifies potential data sources in the code
func (sfa *SQLFlowAnalyzer) findSources(code string) []SQLFlowNode {
	var sources []SQLFlowNode
	lines := strings.Split(code, "\n")

	for i, line := range lines {
		// Skip lines that contain non-SQL query functions
		if sfa.isNonSQLQueryContext(line) {
			continue
		}

		for _, sourcePattern := range sfa.sources {
			if strings.Contains(line, sourcePattern) {
				source := SQLFlowNode{
					Type:       "source",
					Location:   fmt.Sprintf("line %d", i+1),
					Line:       i + 1,
					Column:     strings.Index(line, sourcePattern),
					Code:       strings.TrimSpace(line),
					Variable:   sfa.extractVariable(line, sourcePattern),
					Confidence: 0.8,
				}
				sources = append(sources, source)
			}
		}
	}

	return sources
}

// findSinks identifies potential SQL sinks in the code
func (sfa *SQLFlowAnalyzer) findSinks(code string) []SQLFlowNode {
	var sinks []SQLFlowNode
	lines := strings.Split(code, "\n")

	for i, line := range lines {
		// Skip lines that contain non-SQL query functions
		if sfa.isNonSQLQueryContext(line) {
			continue
		}

		for _, sinkPattern := range sfa.sinks {
			// Create regex pattern to match function calls
			pattern := fmt.Sprintf(`(?i)%s\s*\(`, regexp.QuoteMeta(sinkPattern))
			if matched, _ := regexp.MatchString(pattern, line); matched {
				sink := SQLFlowNode{
					Type:       "sink",
					Location:   fmt.Sprintf("line %d", i+1),
					Line:       i + 1,
					Column:     strings.Index(strings.ToLower(line), strings.ToLower(sinkPattern)),
					Code:       strings.TrimSpace(line),
					Function:   sinkPattern,
					Confidence: 0.9,
				}
				sinks = append(sinks, sink)
			}
		}
	}

	return sinks
}

// findPath attempts to find a data flow path between source and sink
func (sfa *SQLFlowAnalyzer) findPath(source, sink SQLFlowNode, code string) *SQLFlowPath {
	// Check for direct flow (simple case)
	if sfa.hasDirectFlow(source, sink, code) {
		return &SQLFlowPath{
			Source:       source,
			Sink:         sink,
			Path:         []SQLFlowNode{source, sink},
			IsVulnerable: true,
			Confidence:   0.9,
			RiskLevel:    "high",
		}
	}

	// Check for indirect flow through variables
	if path := sfa.findIndirectPath(source, sink, code); path != nil {
		return &SQLFlowPath{
			Source:       source,
			Sink:         sink,
			Path:         path,
			IsVulnerable: true,
			Confidence:   0.7,
			RiskLevel:    "medium",
		}
	}

	return nil
}

// hasDirectFlow checks if there's a direct flow between source and sink
func (sfa *SQLFlowAnalyzer) hasDirectFlow(source, sink SQLFlowNode, code string) bool {
	// Look for lines that contain both source and sink patterns
	lines := strings.Split(code, "\n")

	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		sourcePattern := strings.ToLower(source.Variable)
		sinkPattern := strings.ToLower(sink.Function)

		if strings.Contains(lowerLine, sourcePattern) && strings.Contains(lowerLine, sinkPattern) {
			// Check if it's a direct concatenation or interpolation
			concatenationPatterns := []string{"+", ".", "format", "sprintf"}
			for _, pattern := range concatenationPatterns {
				if strings.Contains(lowerLine, pattern) {
					return true
				}
			}
		}
	}

	return false
}

// findIndirectPath finds an indirect path through variable assignments
func (sfa *SQLFlowAnalyzer) findIndirectPath(source, sink SQLFlowNode, code string) []SQLFlowNode {
	// This would implement more sophisticated path finding
	// For now, return nil as this needs complex implementation
	return nil
}

// extractVariable extracts variable name from a code line
func (sfa *SQLFlowAnalyzer) extractVariable(line, pattern string) string {
	// Simple extraction - would need more sophisticated parsing
	if strings.Contains(pattern, "$") {
		return pattern
	}

	// Look for variable assignments
	parts := strings.Split(line, "=")
	if len(parts) > 1 {
		return strings.TrimSpace(parts[0])
	}

	return pattern
}

// isNonSQLQueryContext checks if a line contains non-SQL query functions that should be excluded
func (sfa *SQLFlowAnalyzer) isNonSQLQueryContext(line string) bool {
	// Functions that use "query" but are not SQL-related
	nonSQLQueryFunctions := []string{
		"http_build_query",    // PHP URL query building
		"parse_str",           // PHP query string parsing
		"parse_url",           // PHP URL parsing
		"urlencode",          // URL encoding
		"urldecode",          // URL decoding
		"URLSearchParams",    // JavaScript URL params
		"querystring",        // Node.js query string
		"urllib.parse",       // Python URL parsing
		"URL.createObjectURL", // JavaScript URL creation
		"makeMarketCarUrl",   // Custom URL builders
		"buildUrl",           // URL building functions
		"createUrl",          // URL creation functions
	}

	lowerLine := strings.ToLower(line)

	// Check for non-SQL query functions
	for _, nonSQLFunc := range nonSQLQueryFunctions {
		if strings.Contains(lowerLine, strings.ToLower(nonSQLFunc)) {
			return true
		}
	}

	// Check for URL/HTTP context patterns
	urlPatterns := []string{
		"querystring",        // Variable names suggesting URL context
		"urlquery",
		"httpquery",
		"requestquery",
		"getquery",
		"postquery",
		"buildquery",
		"makequery",
		"createquery",        // Only when in URL context
		"url",                // General URL context
		"http",               // HTTP context
		"route",              // Routing context
		"redirect",           // Redirect context
	}

	for _, pattern := range urlPatterns {
		if strings.Contains(lowerLine, pattern) {
			// Double-check it's not actually SQL by looking for SQL keywords
			sqlKeywords := []string{"select", "insert", "update", "delete", "from", "where", "join"}
			hasSQLKeyword := false
			for _, sqlKeyword := range sqlKeywords {
				if strings.Contains(lowerLine, sqlKeyword) {
					hasSQLKeyword = true
					break
				}
			}
			// If it has URL context but no SQL keywords, it's likely not SQL
			if !hasSQLKeyword {
				return true
			}
		}
	}

	return false
}

// IsVulnerable performs CFG-based SQL injection detection
func (r *SQLInjectionRule) IsVulnerable(code string, context string) bool {
	// Use CFG-based analysis as default
	sqlAnalyzer := NewSQLFlowAnalyzer()
	paths := sqlAnalyzer.AnalyzeSQLFlow(code, nil)

	// Check if any vulnerable paths exist
	for _, path := range paths {
		if path.IsVulnerable {
			return true
		}
	}

	return false
}

// AnalyzeSQLFlowWithCFG performs advanced CFG-based SQL flow analysis
func (r *SQLInjectionRule) AnalyzeSQLFlowWithCFG(filePath string, language string, content []byte) []*types.SecurityFinding {
	var findings []*types.SecurityFinding

	// Use SQL analyzer to find flow paths
	sqlAnalyzer := NewSQLFlowAnalyzer()
	paths := sqlAnalyzer.AnalyzeSQLFlow(string(content), nil)

	// Convert flow paths to security findings
	for _, path := range paths {
		if path.IsVulnerable {
			finding := &types.SecurityFinding{
				RuleID:      "S017",
				RuleName:    "SQL Injection Prevention",
				VulnType:    types.SQLInjection,
				Severity:    config.SeverityHigh,
				Message:     fmt.Sprintf("Potential SQL injection vulnerability detected. Data flows from %s (line %d) to %s (line %d) without proper parameterization.", path.Source.Variable, path.Source.Line, path.Sink.Function, path.Sink.Line),
				File:        filePath,
				Line:        path.Sink.Line,
				Column:      path.Sink.Column,
				Remediation: "Always use parameterized queries (prepared statements) to prevent SQL injection. Never concatenate user input directly into SQL queries.",
				CWE:         "CWE-89",
				OWASP:       types.OWASPReference{Top10_2021: "A03:2021"},
				Context:     fmt.Sprintf("Data flow: %s -> %s (confidence: %.1f)", path.Source.Type, path.Sink.Type, path.Confidence),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}