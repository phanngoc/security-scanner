package hir

// RuleEngine defines the interface for rule engines
type RuleEngine interface {
	AnalyzeFile(filePath string, language string, content []byte) []*SecurityFinding
}
