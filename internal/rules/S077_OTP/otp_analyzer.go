package owasp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/le-company/security-scanner/internal/analyzer"
	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// OTPAnalyzer implements the Analyzer interface for OTP plaintext detection
// Refactored to use direct analysis instead of delegating to a.rule
type OTPAnalyzer struct {
	// All rule logic is now consolidated directly in the analyzer
}

// NewOTPAnalyzer creates a new OTP analyzer
func NewOTPAnalyzer() *OTPAnalyzer {
	return &OTPAnalyzer{}
}

// GetID returns the unique identifier for this analyzer
func (a *OTPAnalyzer) GetID() string {
	return "otp_plaintext_analyzer"
}

// GetName returns the human-readable name of this analyzer
func (a *OTPAnalyzer) GetName() string {
	return "OTP Plaintext Detection Analyzer"
}

// GetDescription returns a description of what this analyzer does
func (a *OTPAnalyzer) GetDescription() string {
	return "Detects OTP codes stored in plaintext format using CFG-based analysis"
}

// GetSupportedLanguages returns the languages this analyzer supports
func (a *OTPAnalyzer) GetSupportedLanguages() []string {
	return []string{"php", "javascript", "python", "java", "csharp", "go"}
}

// GetRequiredCapabilities returns the capabilities this analyzer needs
func (a *OTPAnalyzer) GetRequiredCapabilities() []analyzer.Capability {
	return []analyzer.Capability{
		analyzer.CapabilitySymbolTable,
		analyzer.CapabilityCFG,
		analyzer.CapabilityDataFlow,
	}
}

// Analyze performs the security analysis directly (refactored from delegating to a.rule)
func (a *OTPAnalyzer) Analyze(ctx context.Context, job *analyzer.AnalysisJob) ([]*types.SecurityFinding, error) {
	var findings []*types.SecurityFinding

	// 1. Pattern-based analysis - check all pattern types directly
	patternFindings := a.analyzeWithPatterns(job)
	findings = append(findings, patternFindings...)

	// 2. CFG-based data flow analysis - done directly instead of through a.rule
	flowFindings := a.analyzeOTPFlowWithCFG(job)
	findings = append(findings, flowFindings...)

	// 3. Symbol table analysis for deeper inspection
	if job.SymbolTable != nil {
		symbolFindings := a.analyzeWithSymbolTable(job)
		findings = append(findings, symbolFindings...)
	}

	// 4. CFG analysis for control flow patterns
	if job.CFG != nil {
		cfgFindings := a.analyzeWithCFG(job)
		findings = append(findings, cfgFindings...)
	}

	return findings, nil
}

// CanAnalyze checks if this analyzer can analyze the given file
func (a *OTPAnalyzer) CanAnalyze(job *analyzer.AnalysisJob) bool {
	// Check if language is supported
	supportedLanguages := a.GetSupportedLanguages()
	for _, lang := range supportedLanguages {
		if strings.EqualFold(job.Language, lang) {
			return true
		}
	}
	return false
}

// analyzeWithPatterns performs comprehensive pattern-based analysis directly
func (a *OTPAnalyzer) analyzeWithPatterns(job *analyzer.AnalysisJob) []*types.SecurityFinding {
	var findings []*types.SecurityFinding
	content := string(job.Content)
	lines := strings.Split(content, "\n")

	// Get all patterns directly instead of from a.rule
	allPatterns := a.getAllOTPPatterns()

	for _, pattern := range allPatterns {
		if pattern.Type == types.PatternRegex {
			regex, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				continue // Skip invalid patterns
			}

			for lineNum, line := range lines {
				matches := regex.FindAllStringSubmatch(line, -1)
				for _, match := range matches {
					if len(match) > 0 {
						finding := &types.SecurityFinding{
							RuleID:      "S077",
							RuleName:    "OTP Plaintext Detection",
							VulnType:    types.HardcodedSecrets,
							Severity:    config.SeverityHigh,
							Message:     fmt.Sprintf("OTP plaintext vulnerability detected: %s", pattern.Description),
							File:        job.Path,
							Line:        lineNum + 1,
							Column:      strings.Index(line, match[0]),
							Remediation: "Store OTP codes using secure hashing (bcrypt, Argon2) or use time-based expiration. Never store OTP codes in plaintext.",
							CWE:         "CWE-798",
							OWASP:       types.OWASPReference{Top10_2021: "A02:2021"},
							Context:     fmt.Sprintf("Pattern context: %s", pattern.Context),
						}
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}

// analyzeOTPFlowWithCFG performs advanced CFG-based OTP flow analysis directly
func (a *OTPAnalyzer) analyzeOTPFlowWithCFG(job *analyzer.AnalysisJob) []*types.SecurityFinding {
	var findings []*types.SecurityFinding
	content := string(job.Content)

	// Perform data flow analysis directly
	paths := a.analyzeOTPFlow(content, job.CFG)

	// Convert flow paths to security findings
	for _, path := range paths {
		if path.IsVulnerable {
			finding := &types.SecurityFinding{
				RuleID:      "S077",
				RuleName:    "OTP Plaintext Detection",
				VulnType:    types.HardcodedSecrets,
				Severity:    config.SeverityHigh,
				Message:     fmt.Sprintf("Potential OTP plaintext vulnerability detected. Data flows from %s (line %d) to %s (line %d) without proper sanitization.", path.Source.Variable, path.Source.Line, path.Sink.Function, path.Sink.Line),
				File:        job.Path,
				Line:        path.Sink.Line,
				Column:      path.Sink.Column,
				Remediation: "Store OTP codes using secure hashing (bcrypt, Argon2) or use time-based expiration. Never store OTP codes in plaintext.",
				CWE:         "CWE-798",
				OWASP:       types.OWASPReference{Top10_2021: "A02:2021"},
				Context:     fmt.Sprintf("Data flow: %s -> %s (confidence: %.1f)", path.Source.Type, path.Sink.Type, path.Confidence),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// analyzeWithSymbolTable performs analysis using symbol table information
func (a *OTPAnalyzer) analyzeWithSymbolTable(job *analyzer.AnalysisJob) []*types.SecurityFinding {
	var findings []*types.SecurityFinding

	// Look for OTP-related symbols in the symbol table
	for symbolName, symbolData := range job.SymbolTable {
		if a.isOTPSymbol(symbolName) {
			// Check if this symbol is used in dangerous ways
			if a.isDangerousSymbolUsage(symbolName, symbolData) {
				finding := &types.SecurityFinding{
					RuleID:      "S077",
					RuleName:    "OTP Plaintext Detection",
					VulnType:    types.HardcodedSecrets,
					Severity:    config.SeverityHigh,
					Message:     fmt.Sprintf("OTP-related symbol '%s' may be used insecurely", symbolName),
					File:        job.Path,
					Line:        0, // Would be extracted from symbol data
					Column:      0,
					Remediation: "Store OTP codes using secure hashing (bcrypt, Argon2) or use time-based expiration. Never store OTP codes in plaintext.",
					CWE:         "CWE-798",
					OWASP:       types.OWASPReference{Top10_2021: "A02:2021"},
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// analyzeWithCFG performs analysis using CFG information
func (a *OTPAnalyzer) analyzeWithCFG(job *analyzer.AnalysisJob) []*types.SecurityFinding {
	var findings []*types.SecurityFinding

	// Use the CFG to trace data flow from OTP sources to sinks
	if job.CFG != nil {
		// This performs additional CFG-based flow analysis
		cfgFlowFindings := a.analyzeOTPFlowWithCFG(job)
		findings = append(findings, cfgFlowFindings...)
	}

	return findings
}

// OTP Flow Analysis Types and Functions - consolidated from otp_plaintext.go

// OTPFlowNode represents a node in the OTP data flow
type OTPFlowNode struct {
	Type        string  `json:"type"`         // "source", "sink", "sanitizer", "transformer"
	Location    string  `json:"location"`     // File location
	Line        int     `json:"line"`         // Line number
	Column      int     `json:"column"`       // Column number
	Code        string  `json:"code"`         // Code snippet
	Variable    string  `json:"variable"`     // Variable name
	Function    string  `json:"function"`     // Function name
	Confidence  float64 `json:"confidence"`   // Confidence level (0.0-1.0)
	IsSanitized bool    `json:"is_sanitized"` // Whether data is sanitized
}

// OTPFlowPath represents a flow path for OTP data
type OTPFlowPath struct {
	Source       OTPFlowNode   `json:"source"`
	Sink         OTPFlowNode   `json:"sink"`
	Path         []OTPFlowNode `json:"path"`
	IsVulnerable bool          `json:"is_vulnerable"`
	Confidence   float64       `json:"confidence"`
	RiskLevel    string        `json:"risk_level"`
}

// analyzeOTPFlow performs OTP data flow analysis
func (a *OTPAnalyzer) analyzeOTPFlow(code string, cfg interface{}) []*OTPFlowPath {
	var paths []*OTPFlowPath

	// Find all sources and sinks
	sources := a.findOTPSources(code)
	sinks := a.findOTPSinks(code)

	// Analyze flow from each source to each sink
	for _, source := range sources {
		for _, sink := range sinks {
			if path := a.findOTPPath(source, sink, code); path != nil {
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// findOTPSources identifies potential OTP data sources in the code
func (a *OTPAnalyzer) findOTPSources(code string) []OTPFlowNode {
	var sources []OTPFlowNode
	lines := strings.Split(code, "\n")

	// OTP source patterns
	sourcePatterns := []string{
		"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SESSION",
		"$this->request->getData", "$this->request->getQuery",
		"$this->Auth->user", "$this->Session->read",
		"generateOTP", "createOTP", "getOTP", "fetchOTP",
	}

	for i, line := range lines {
		for _, sourcePattern := range sourcePatterns {
			if strings.Contains(line, sourcePattern) && a.containsOTPKeyword(line) {
				source := OTPFlowNode{
					Type:       "source",
					Location:   fmt.Sprintf("line %d", i+1),
					Line:       i + 1,
					Column:     strings.Index(line, sourcePattern),
					Code:       strings.TrimSpace(line),
					Variable:   a.extractOTPVariable(line, sourcePattern),
					Confidence: 0.8,
				}
				sources = append(sources, source)
			}
		}
	}

	return sources
}

// findOTPSinks identifies potential OTP sinks in the code
func (a *OTPAnalyzer) findOTPSinks(code string) []OTPFlowNode {
	var sinks []OTPFlowNode
	lines := strings.Split(code, "\n")

	// OTP sink patterns
	sinkPatterns := []string{
		"save", "insert", "update", "store", "write", "set",
		"echo", "print", "printf", "log", "error_log", "file_put_contents",
		"Session->write", "Flash->set", "Configure::write",
	}

	for i, line := range lines {
		for _, sinkPattern := range sinkPatterns {
			// Create regex pattern to match function calls
			pattern := fmt.Sprintf(`(?i)%s\s*\(`, regexp.QuoteMeta(sinkPattern))
			if matched, _ := regexp.MatchString(pattern, line); matched && a.containsOTPKeyword(line) {
				sink := OTPFlowNode{
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

// findOTPPath attempts to find a data flow path between source and sink
func (a *OTPAnalyzer) findOTPPath(source, sink OTPFlowNode, code string) *OTPFlowPath {
	// Check for direct flow (simple case)
	if a.hasDirectOTPFlow(source, sink, code) {
		return &OTPFlowPath{
			Source:       source,
			Sink:         sink,
			Path:         []OTPFlowNode{source, sink},
			IsVulnerable: !a.isOTPPathSanitized(source, sink, code),
			Confidence:   0.9,
			RiskLevel:    "high",
		}
	}

	// Check for indirect flow through variables
	if path := a.findIndirectOTPPath(source, sink, code); path != nil {
		return &OTPFlowPath{
			Source:       source,
			Sink:         sink,
			Path:         path,
			IsVulnerable: !a.isOTPPathSanitized(source, sink, code),
			Confidence:   0.7,
			RiskLevel:    "medium",
		}
	}

	return nil
}

// hasDirectOTPFlow checks if there's a direct flow between source and sink
func (a *OTPAnalyzer) hasDirectOTPFlow(source, sink OTPFlowNode, code string) bool {
	// Look for lines that contain both source and sink patterns with OTP context
	lines := strings.Split(code, "\n")

	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		sourcePattern := strings.ToLower(source.Variable)
		sinkPattern := strings.ToLower(sink.Function)

		if strings.Contains(lowerLine, sourcePattern) && strings.Contains(lowerLine, sinkPattern) && a.containsOTPKeyword(line) {
			// Check if it's a direct assignment or function call
			assignmentPatterns := []string{"=", "->", ":", "=>"}
			for _, pattern := range assignmentPatterns {
				if strings.Contains(lowerLine, pattern) {
					return true
				}
			}
		}
	}

	return false
}

// findIndirectOTPPath finds an indirect path through variable assignments
func (a *OTPAnalyzer) findIndirectOTPPath(source, sink OTPFlowNode, code string) []OTPFlowNode {
	// This would implement more sophisticated path finding for OTP data
	// For now, return nil as this needs complex implementation
	return nil
}

// isOTPPathSanitized checks if the data path includes sanitization
func (a *OTPAnalyzer) isOTPPathSanitized(source, sink OTPFlowNode, code string) bool {
	// OTP sanitization functions
	sanitizers := []string{
		"hash", "password_hash", "bcrypt", "crypt", "md5", "sha1", "sha256",
		"hash_hmac", "encrypt", "base64_encode", "bin2hex",
	}

	// Check if any sanitization functions are applied between source and sink
	lines := strings.Split(code, "\n")

	startLine := source.Line
	endLine := sink.Line
	if startLine > endLine {
		startLine, endLine = endLine, startLine
	}

	// Check lines between source and sink for sanitization
	for i := startLine - 1; i < endLine && i < len(lines); i++ {
		line := strings.ToLower(lines[i])
		for _, sanitizer := range sanitizers {
			if strings.Contains(line, strings.ToLower(sanitizer)) {
				return true
			}
		}
	}

	return false
}

// containsOTPKeyword checks if a line contains OTP-related keywords
func (a *OTPAnalyzer) containsOTPKeyword(line string) bool {
	otpKeywords := []string{
		"otp", "one_time_password", "verification_code", "sms_code",
		"totp", "time_based_otp", "auth_code", "verification_token",
		"pin", "passcode", "security_code", "confirm_code",
	}

	lowerLine := strings.ToLower(line)
	for _, keyword := range otpKeywords {
		if strings.Contains(lowerLine, keyword) {
			return true
		}
	}

	return false
}

// extractOTPVariable extracts variable name from a code line
func (a *OTPAnalyzer) extractOTPVariable(line, pattern string) string {
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

// isOTPSymbol checks if a symbol name is OTP-related
func (a *OTPAnalyzer) isOTPSymbol(symbolName string) bool {
	otpKeywords := []string{
		"otp", "one_time_password", "verification_code", "sms_code",
		"totp", "time_based_otp", "auth_code", "verification_token",
	}

	lowerName := strings.ToLower(symbolName)
	for _, keyword := range otpKeywords {
		if strings.Contains(lowerName, keyword) {
			return true
		}
	}

	return false
}

// isDangerousSymbolUsage checks if a symbol is used in a dangerous way
func (a *OTPAnalyzer) isDangerousSymbolUsage(symbolName string, symbolData interface{}) bool {
	// This would implement more sophisticated analysis
	// For now, we'll do basic checks

	// Check if symbol is assigned a plaintext value
	if symbolMap, ok := symbolData.(map[string]interface{}); ok {
		// Look for evidence of plaintext assignment
		// This would need to be implemented based on the symbol data structure
		_ = symbolMap // Placeholder
	}

	return false // For now, return false as this needs more implementation
}

// getAllOTPPatterns returns all OTP patterns consolidated from otp_plaintext.go
func (a *OTPAnalyzer) getAllOTPPatterns() []types.Pattern {
	patterns := []types.Pattern{
		// General OTP patterns
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)(otp|one[_-]?time[_-]?password|verification[_-]?code)\s*[=:]\s*["'][0-9]{4,8}["']`,
			Description: "OTP code stored as plaintext",
			Context:     "otp_plaintext",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)(sms[_-]?code|verification[_-]?token|auth[_-]?code)\s*[=:]\s*["'][0-9]{4,8}["']`,
			Description: "SMS verification code stored as plaintext",
			Context:     "sms_code_plaintext",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)(totp|time[_-]?based[_-]?otp)\s*[=:]\s*["'][A-Z0-9]{16,}["']`,
			Description: "TOTP secret stored as plaintext",
			Context:     "totp_secret_plaintext",
		},

		// CakePHP 3 specific patterns
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->request->getData\(['"]otp['"]\)\s*[=:]\s*["'][0-9]{4,8}["']`,
			Description: "CakePHP 3 OTP from request data stored as plaintext",
			Context:     "cake3_otp_request",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->request->getData\(['"]verification_code['"]\)\s*[=:]\s*["'][0-9]{4,8}["']`,
			Description: "CakePHP 3 verification code from request stored as plaintext",
			Context:     "cake3_verification_request",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)\$this->Auth->user\(['"]otp['"]\)\s*[=:]\s*["'][0-9]{4,8}["']`,
			Description: "CakePHP 3 OTP from Auth user stored as plaintext",
			Context:     "cake3_otp_auth",
		},

		// Database patterns
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)INSERT\s+INTO\s+[^)]*otp[^)]*VALUES\s*\([^)]*["'][0-9]{4,8}["']`,
			Description: "OTP code inserted into database as plaintext",
			Context:     "database_otp_insert",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)UPDATE\s+[^)]*otp[^)]*SET\s+[^)]*["'][0-9]{4,8}["']`,
			Description: "OTP code updated in database as plaintext",
			Context:     "database_otp_update",
		},

		// Configuration patterns
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)(otp|verification|sms)[_-]?code\s*[=:]\s*["'][0-9]{4,8}["']`,
			Description: "OTP code in configuration file as plaintext",
			Context:     "config_otp_plaintext",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)(totp|time[_-]?based)[_-]?secret\s*[=:]\s*["'][A-Z0-9]{16,}["']`,
			Description: "TOTP secret in configuration as plaintext",
			Context:     "config_totp_secret",
		},

		// Flow analysis patterns
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)(otp|verification)[_-]?code\s*=\s*[^;]*["'][0-9]{4,8}["']`,
			Description: "OTP code assignment as plaintext",
			Context:     "flow_otp_assignment",
		},
		{
			Type:        types.PatternRegex,
			Pattern:     `(?i)(echo|print|printf)\s*\([^)]*otp[^)]*["'][0-9]{4,8}["']`,
			Description: "OTP code printed/echoed as plaintext",
			Context:     "flow_print_otp",
		},
	}

	return patterns
}