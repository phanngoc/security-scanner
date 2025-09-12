package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/scanner"
)

// Reporter generates security scan reports
type Reporter struct {
	config *config.Config
	logger *zap.Logger
}

// New creates a new reporter instance
func New(cfg *config.Config, logger *zap.Logger) *Reporter {
	return &Reporter{
		config: cfg,
		logger: logger,
	}
}

// Generate generates a report from scan results
func (r *Reporter) Generate(results *scanner.ScanResult) error {
	var output string
	var err error

	switch strings.ToLower(r.config.Format) {
	case "json":
		output, err = r.generateJSON(results)
	case "sarif":
		output, err = r.generateSARIF(results)
	case "text", "":
		output, err = r.generateText(results)
	default:
		return fmt.Errorf("unsupported output format: %s", r.config.Format)
	}

	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Write to file or stdout
	if r.config.OutputFile != "" {
		if err := os.WriteFile(r.config.OutputFile, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write report to file: %w", err)
		}
		r.logger.Info("Report written", zap.String("file", r.config.OutputFile))
	} else {
		fmt.Print(output)
	}

	return nil
}

// generateText generates a human-readable text report
func (r *Reporter) generateText(results *scanner.ScanResult) (string, error) {
	var sb strings.Builder

	// Header
	sb.WriteString("=== Security Scanner Report ===\n\n")
	sb.WriteString(fmt.Sprintf("Scan completed at: %s\n", results.EndTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Scan duration: %s\n", results.Duration.String()))
	sb.WriteString(fmt.Sprintf("Files scanned: %d\n", results.Statistics.FilesScanned))
	sb.WriteString(fmt.Sprintf("Files skipped: %d\n", results.Statistics.FilesSkipped))
	sb.WriteString(fmt.Sprintf("Lines scanned: %d\n", results.Statistics.LinesScanned))
	sb.WriteString(fmt.Sprintf("Total findings: %d\n\n", len(results.Findings)))

	// Summary by severity
	sb.WriteString("Findings by Severity:\n")
	for severity := config.SeverityCritical; severity >= config.SeverityLow; severity-- {
		count := results.Statistics.BySeverity[severity]
		if count > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d\n",
				strings.ToUpper(severity.String()), count))
		}
	}
	sb.WriteString("\n")

	// Filter findings by minimum severity
	minSeverity := config.ParseSeverity(r.config.Severity)
	filteredFindings := r.filterBySeverity(results.Findings, minSeverity)

	if len(filteredFindings) == 0 {
		sb.WriteString("No findings match the specified severity criteria.\n")
		return sb.String(), nil
	}

	// Sort findings by severity and then by file
	sort.Slice(filteredFindings, func(i, j int) bool {
		if filteredFindings[i].Severity != filteredFindings[j].Severity {
			return filteredFindings[i].Severity > filteredFindings[j].Severity
		}
		if filteredFindings[i].File != filteredFindings[j].File {
			return filteredFindings[i].File < filteredFindings[j].File
		}
		return filteredFindings[i].Line < filteredFindings[j].Line
	})

	// Detailed findings
	sb.WriteString("=== Detailed Findings ===\n\n")
	for i, finding := range filteredFindings {
		sb.WriteString(fmt.Sprintf("[%d] %s\n", i+1, finding.Title))
		sb.WriteString(fmt.Sprintf("    Severity: %s\n", strings.ToUpper(finding.Severity.String())))
		sb.WriteString(fmt.Sprintf("    File: %s:%d:%d\n", finding.File, finding.Line, finding.Column))
		sb.WriteString(fmt.Sprintf("    Type: %s\n", finding.Type))
		sb.WriteString(fmt.Sprintf("    Rule: %s\n", finding.RuleID))

		if finding.CWE != "" {
			sb.WriteString(fmt.Sprintf("    CWE: %s\n", finding.CWE))
		}

		if finding.OWASP.Top10_2021 != "" {
			sb.WriteString(fmt.Sprintf("    OWASP: %s (%s)\n", finding.OWASP.Top10_2021, finding.OWASP.Category))
		}

		sb.WriteString(fmt.Sprintf("    Description: %s\n", finding.Description))

		if finding.Code != "" {
			sb.WriteString(fmt.Sprintf("    Code: %s\n", finding.Code))
		}

		if len(finding.Context) > 0 {
			sb.WriteString("    Context:\n")
			for _, line := range finding.Context {
				sb.WriteString(fmt.Sprintf("      %s\n", line))
			}
		}

		if finding.Remediation != "" {
			sb.WriteString(fmt.Sprintf("    Remediation: %s\n", finding.Remediation))
		}

		sb.WriteString(fmt.Sprintf("    Confidence: %d%%\n", finding.Confidence))
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// generateJSON generates a JSON report
func (r *Reporter) generateJSON(results *scanner.ScanResult) (string, error) {
	// Filter findings by minimum severity
	minSeverity := config.ParseSeverity(r.config.Severity)
	filteredResults := *results
	filteredResults.Findings = r.filterBySeverity(results.Findings, minSeverity)

	data, err := json.MarshalIndent(filteredResults, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(data), nil
}

// generateSARIF generates a SARIF format report
func (r *Reporter) generateSARIF(results *scanner.ScanResult) (string, error) {
	// Filter findings by minimum severity
	minSeverity := config.ParseSeverity(r.config.Severity)
	filteredFindings := r.filterBySeverity(results.Findings, minSeverity)

	// Build SARIF structure
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "security-scanner",
						"version":        "1.0.0",
						"informationUri": "https://github.com/le-company/security-scanner",
						"shortDescription": map[string]interface{}{
							"text": "OWASP-compliant security scanner for source code",
						},
						"fullDescription": map[string]interface{}{
							"text": "A fast, parallel security scanner that detects vulnerabilities in source code following OWASP security guidelines",
						},
						"rules": r.buildSARIFRules(filteredFindings),
					},
				},
				"results": r.buildSARIFResults(filteredFindings),
			},
		},
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	return string(data), nil
}

// buildSARIFRules builds SARIF rule definitions
func (r *Reporter) buildSARIFRules(findings []*scanner.Finding) []map[string]interface{} {
	ruleMap := make(map[string]*scanner.Finding)

	// Collect unique rules
	for _, finding := range findings {
		if _, exists := ruleMap[finding.RuleID]; !exists {
			ruleMap[finding.RuleID] = finding
		}
	}

	// Build rule definitions
	var rules []map[string]interface{}
	for _, finding := range ruleMap {
		rule := map[string]interface{}{
			"id":   finding.RuleID,
			"name": finding.Title,
			"shortDescription": map[string]interface{}{
				"text": finding.Title,
			},
			"fullDescription": map[string]interface{}{
				"text": finding.Description,
			},
			"defaultConfiguration": map[string]interface{}{
				"level": r.severityToSARIFLevel(finding.Severity),
			},
			"properties": map[string]interface{}{
				"tags": []string{
					string(finding.Type),
					finding.Severity.String(),
				},
			},
		}

		if finding.CWE != "" {
			rule["properties"].(map[string]interface{})["cwe"] = finding.CWE
		}

		if finding.OWASP.Top10_2021 != "" {
			rule["properties"].(map[string]interface{})["owasp"] = finding.OWASP.Top10_2021
		}

		rules = append(rules, rule)
	}

	return rules
}

// buildSARIFResults builds SARIF result entries
func (r *Reporter) buildSARIFResults(findings []*scanner.Finding) []map[string]interface{} {
	var results []map[string]interface{}

	for _, finding := range findings {
		result := map[string]interface{}{
			"ruleId": finding.RuleID,
			"message": map[string]interface{}{
				"text": finding.Description,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": finding.File,
						},
						"region": map[string]interface{}{
							"startLine":   finding.Line,
							"startColumn": finding.Column,
						},
					},
				},
			},
			"level": r.severityToSARIFLevel(finding.Severity),
		}

		if finding.Code != "" {
			result["locations"].([]map[string]interface{})[0]["physicalLocation"].(map[string]interface{})["contextRegion"] = map[string]interface{}{
				"snippet": map[string]interface{}{
					"text": finding.Code,
				},
			}
		}

		results = append(results, result)
	}

	return results
}

// severityToSARIFLevel converts severity to SARIF level
func (r *Reporter) severityToSARIFLevel(severity config.SeverityLevel) string {
	switch severity {
	case config.SeverityCritical:
		return "error"
	case config.SeverityHigh:
		return "error"
	case config.SeverityMedium:
		return "warning"
	case config.SeverityLow:
		return "note"
	default:
		return "warning"
	}
}

// filterBySeverity filters findings by minimum severity level
func (r *Reporter) filterBySeverity(findings []*scanner.Finding, minSeverity config.SeverityLevel) []*scanner.Finding {
	var filtered []*scanner.Finding

	for _, finding := range findings {
		if finding.Severity >= minSeverity {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}
