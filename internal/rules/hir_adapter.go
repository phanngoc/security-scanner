package rules

import (
	"go/token"

	"github.com/le-company/security-scanner/internal/hir"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// HIRAdapter adapts the DynamicRuleEngine to the HIR RuleEngine interface
type HIRAdapter struct {
	engine *DynamicRuleEngine
}

// NewHIRAdapter creates a new HIR adapter
func NewHIRAdapter(engine *DynamicRuleEngine) *HIRAdapter {
	return &HIRAdapter{
		engine: engine,
	}
}

// AnalyzeFile implements the HIR RuleEngine interface
func (adapter *HIRAdapter) AnalyzeFile(filePath string, language string, content []byte) []*hir.SecurityFinding {
	// Get findings from the dynamic rule engine
	findings := adapter.engine.AnalyzeFile(filePath, language, content)

	// Convert to HIR SecurityFinding format
	hirFindings := make([]*hir.SecurityFinding, len(findings))
	for i, finding := range findings {
		// Convert vulnerability type
		var vulnType hir.VulnerabilityType
		switch finding.VulnType {
		case types.SQLInjection:
			vulnType = hir.VulnSQLInjection
		case types.XSS:
			vulnType = hir.VulnXSS
		case types.CommandInjection:
			vulnType = hir.VulnCommandInjection
		case types.PathTraversal:
			vulnType = hir.VulnPathTraversal
		case types.HardcodedSecrets:
			vulnType = hir.VulnHardcodedSecret
		default:
			vulnType = hir.VulnSQLInjection // Default fallback
		}

		// Convert severity
		var severity hir.Severity
		switch finding.Severity.String() {
		case "critical":
			severity = hir.SeverityCritical
		case "high":
			severity = hir.SeverityHigh
		case "medium":
			severity = hir.SeverityMedium
		case "low":
			severity = hir.SeverityLow
		default:
			severity = hir.SeverityMedium
		}

		hirFindings[i] = &hir.SecurityFinding{
			ID:          finding.RuleID,
			Type:        vulnType,
			Severity:    severity,
			Confidence:  0.8, // Default confidence
			Message:     finding.Message,
			Description: finding.Message,
			File:        finding.File,
			Position:    token.Pos(finding.Line),
			Span: hir.Span{
				Start: token.Pos(finding.Line),
				End:   token.Pos(finding.Line),
			},
			CWE:         finding.CWE,
			OWASP:       finding.GetOWASPReference(),
			Remediation: finding.Remediation,
		}
	}

	return hirFindings
}
