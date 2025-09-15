package rules

import (
	"fmt"
	"go/token"
	"strings"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// FlowAnalyzer provides flow-based security analysis
type FlowAnalyzer struct {
	taintSources map[string]TaintSource
	taintSinks   map[string]TaintSink
	dataFlow     map[string][]DataFlowNode
}

// TaintSource represents a source of potentially tainted data
type TaintSource struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Pattern     string   `json:"pattern"`
	Languages   []string `json:"languages"`
	Confidence  float64  `json:"confidence"`
	Description string   `json:"description"`
}

// TaintSink represents a sink that could be exploited with tainted data
type TaintSink struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Pattern     string   `json:"pattern"`
	Languages   []string `json:"languages"`
	VulnType    string   `json:"vulnerability_type"`
	Confidence  float64  `json:"confidence"`
	Description string   `json:"description"`
}

// DataFlowNode represents a node in the data flow graph
type DataFlowNode struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Position   token.Pos              `json:"position"`
	Variables  []string               `json:"variables"`
	Operations []string               `json:"operations"`
	Properties map[string]string      `json:"properties"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// DataFlowEdge represents an edge in the data flow graph
type DataFlowEdge struct {
	From       string  `json:"from"`
	To         string  `json:"to"`
	Type       string  `json:"type"`
	Confidence float64 `json:"confidence"`
}

// FlowRule represents a flow-based security rule
type FlowRule struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Sources     []TaintSource   `json:"sources"`
	Sinks       []TaintSink     `json:"sinks"`
	Conditions  []FlowCondition `json:"conditions"`
	Severity    string          `json:"severity"`
}

// FlowCondition represents a condition for flow analysis
type FlowCondition struct {
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Operator    string `json:"operator"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// NewFlowAnalyzer creates a new flow analyzer
func NewFlowAnalyzer() *FlowAnalyzer {
	analyzer := &FlowAnalyzer{
		taintSources: make(map[string]TaintSource),
		taintSinks:   make(map[string]TaintSink),
		dataFlow:     make(map[string][]DataFlowNode),
	}

	// Initialize with common taint sources and sinks
	analyzer.initializeCommonSources()
	analyzer.initializeCommonSinks()

	return analyzer
}

// initializeCommonSources sets up common taint sources
func (fa *FlowAnalyzer) initializeCommonSources() {
	// HTTP request sources
	fa.taintSources["http_get"] = TaintSource{
		Name:        "HTTP GET Parameter",
		Type:        "http_input",
		Pattern:     `\$_GET\[`,
		Languages:   []string{"php"},
		Confidence:  0.9,
		Description: "HTTP GET parameter from user input",
	}

	fa.taintSources["http_post"] = TaintSource{
		Name:        "HTTP POST Parameter",
		Type:        "http_input",
		Pattern:     `\$_POST\[`,
		Languages:   []string{"php"},
		Confidence:  0.9,
		Description: "HTTP POST parameter from user input",
	}

	fa.taintSources["http_request"] = TaintSource{
		Name:        "HTTP Request Parameter",
		Type:        "http_input",
		Pattern:     `\$_REQUEST\[`,
		Languages:   []string{"php"},
		Confidence:  0.9,
		Description: "HTTP request parameter from user input",
	}

	fa.taintSources["http_cookie"] = TaintSource{
		Name:        "HTTP Cookie",
		Type:        "http_input",
		Pattern:     `\$_COOKIE\[`,
		Languages:   []string{"php"},
		Confidence:  0.8,
		Description: "HTTP cookie from user input",
	}

	// JavaScript DOM sources
	fa.taintSources["js_dom_input"] = TaintSource{
		Name:        "JavaScript DOM Input",
		Type:        "dom_input",
		Pattern:     `\.value|\.innerHTML|\.textContent`,
		Languages:   []string{"javascript", "typescript"},
		Confidence:  0.8,
		Description: "JavaScript DOM element input",
	}

	fa.taintSources["js_url_param"] = TaintSource{
		Name:        "JavaScript URL Parameter",
		Type:        "url_input",
		Pattern:     `location\.search|URLSearchParams|window\.location`,
		Languages:   []string{"javascript", "typescript"},
		Confidence:  0.9,
		Description: "JavaScript URL parameter",
	}

	// Python sources
	fa.taintSources["python_input"] = TaintSource{
		Name:        "Python Input",
		Type:        "user_input",
		Pattern:     `input\(|raw_input\(|sys\.argv`,
		Languages:   []string{"python"},
		Confidence:  0.9,
		Description: "Python user input",
	}

	fa.taintSources["python_request"] = TaintSource{
		Name:        "Python Request",
		Type:        "http_input",
		Pattern:     `request\.(args|form|values)`,
		Languages:   []string{"python"},
		Confidence:  0.9,
		Description: "Python web request parameter",
	}
}

// initializeCommonSinks sets up common taint sinks
func (fa *FlowAnalyzer) initializeCommonSinks() {
	// SQL injection sinks
	fa.taintSinks["sql_query"] = TaintSink{
		Name:        "SQL Query",
		Type:        "database",
		Pattern:     `mysql_query|mysqli_query|pg_query|sqlite_exec|->query|->execute`,
		Languages:   []string{"php"},
		VulnType:    "sql_injection",
		Confidence:  0.9,
		Description: "SQL query execution",
	}

	fa.taintSinks["sql_execute"] = TaintSink{
		Name:        "SQL Execute",
		Type:        "database",
		Pattern:     `cursor\.execute|db\.execute|\.execute\s*\(`,
		Languages:   []string{"python", "java", "csharp"},
		VulnType:    "sql_injection",
		Confidence:  0.9,
		Description: "SQL query execution",
	}

	// XSS sinks
	fa.taintSinks["html_output"] = TaintSink{
		Name:        "HTML Output",
		Type:        "html_output",
		Pattern:     `echo|print|innerHTML|outerHTML|document\.write`,
		Languages:   []string{"php", "javascript", "typescript"},
		VulnType:    "xss",
		Confidence:  0.8,
		Description: "HTML output without escaping",
	}

	fa.taintSinks["template_render"] = TaintSink{
		Name:        "Template Render",
		Type:        "template_output",
		Pattern:     `render_template|template\.render|\.render\s*\(`,
		Languages:   []string{"python", "javascript", "go"},
		VulnType:    "xss",
		Confidence:  0.8,
		Description: "Template rendering",
	}

	// Command injection sinks
	fa.taintSinks["command_exec"] = TaintSink{
		Name:        "Command Execution",
		Type:        "system_command",
		Pattern:     `system|exec|shell_exec|passthru|popen|proc_open|os\.system|subprocess`,
		Languages:   []string{"php", "python", "go"},
		VulnType:    "command_injection",
		Confidence:  0.9,
		Description: "System command execution",
	}

	fa.taintSinks["eval_exec"] = TaintSink{
		Name:        "Code Evaluation",
		Type:        "code_execution",
		Pattern:     `eval\(|exec\(|Function\(`,
		Languages:   []string{"php", "python", "javascript", "typescript"},
		VulnType:    "code_injection",
		Confidence:  0.9,
		Description: "Dynamic code evaluation",
	}
}

// AnalyzeFlow performs flow-based analysis on source code
func (fa *FlowAnalyzer) AnalyzeFlow(filePath string, language string, content []byte) []*types.SecurityFinding {
	var findings []*types.SecurityFinding

	// Parse the source code into an AST (simplified for this example)
	// In a real implementation, you would use proper language parsers

	// Build data flow graph
	flowGraph := fa.buildDataFlowGraph(filePath, language, content)

	// Analyze taint flow
	taintPaths := fa.findTaintPaths(flowGraph)

	// Generate findings from taint paths
	for _, path := range taintPaths {
		if finding := fa.createFindingFromPath(path, filePath); finding != nil {
			findings = append(findings, finding)
		}
	}

	return findings
}

// buildDataFlowGraph builds a data flow graph from source code
func (fa *FlowAnalyzer) buildDataFlowGraph(filePath string, language string, content []byte) map[string][]DataFlowNode {
	// Simplified implementation - in reality you'd parse the AST properly
	graph := make(map[string][]DataFlowNode)

	lines := strings.Split(string(content), "\n")

	for lineNum, line := range lines {
		nodeID := fmt.Sprintf("%s:%d", filePath, lineNum+1)

		// Identify variables and operations in this line
		variables := fa.extractVariables(line, language)
		operations := fa.extractOperations(line, language)

		node := DataFlowNode{
			ID:         nodeID,
			Type:       "statement",
			Position:   token.Pos(lineNum + 1),
			Variables:  variables,
			Operations: operations,
			Properties: make(map[string]string),
			Metadata:   make(map[string]interface{}),
		}

		graph[nodeID] = []DataFlowNode{node}
	}

	return graph
}

// extractVariables extracts variable names from a line of code
func (fa *FlowAnalyzer) extractVariables(line string, language string) []string {
	var variables []string

	switch language {
	case "php":
		// Extract PHP variables ($var)
		// This is simplified - real implementation would use proper parsing
		words := strings.Fields(line)
		for _, word := range words {
			if strings.HasPrefix(word, "$") {
				variables = append(variables, word)
			}
		}
	case "javascript", "typescript":
		// Extract JavaScript variables
		// Simplified implementation
		if strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) > 0 {
				varName := strings.TrimSpace(parts[0])
				variables = append(variables, varName)
			}
		}
	}

	return variables
}

// extractOperations extracts operations from a line of code
func (fa *FlowAnalyzer) extractOperations(line string, language string) []string {
	var operations []string

	// Check for common operations
	if strings.Contains(line, "echo") || strings.Contains(line, "print") {
		operations = append(operations, "output")
	}
	if strings.Contains(line, "mysql_query") || strings.Contains(line, "->query") {
		operations = append(operations, "sql_query")
	}
	if strings.Contains(line, "system") || strings.Contains(line, "exec") {
		operations = append(operations, "command_exec")
	}
	if strings.Contains(line, "innerHTML") || strings.Contains(line, "document.write") {
		operations = append(operations, "html_output")
	}

	return operations
}

// findTaintPaths finds paths from taint sources to taint sinks
func (fa *FlowAnalyzer) findTaintPaths(flowGraph map[string][]DataFlowNode) []TaintPath {
	var paths []TaintPath

	// Simplified implementation - in reality you'd do proper graph traversal
	for _, nodes := range flowGraph {
		for _, node := range nodes {
			// Check if this node is a taint source
			if source := fa.isTaintSource(node); source != nil {
				// Find paths to taint sinks
				sinkPaths := fa.findPathsToSinks(node, flowGraph)
				for _, sinkPath := range sinkPaths {
					path := TaintPath{
						Source:     *source,
						Sink:       sinkPath.Sink,
						Path:       sinkPath.Path,
						Confidence: sinkPath.Confidence,
					}
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

// TaintPath represents a path from a taint source to a taint sink
type TaintPath struct {
	Source     TaintSource    `json:"source"`
	Sink       TaintSink      `json:"sink"`
	Path       []DataFlowNode `json:"path"`
	Confidence float64        `json:"confidence"`
}

// isTaintSource checks if a node represents a taint source
func (fa *FlowAnalyzer) isTaintSource(node DataFlowNode) *TaintSource {
	// Simplified implementation - check if node contains taint source patterns
	for _, source := range fa.taintSources {
		for _, variable := range node.Variables {
			if strings.Contains(variable, source.Pattern) {
				return &source
			}
		}
	}
	return nil
}

// findPathsToSinks finds paths from a source node to sink nodes
func (fa *FlowAnalyzer) findPathsToSinks(sourceNode DataFlowNode, flowGraph map[string][]DataFlowNode) []TaintPath {
	var paths []TaintPath

	// Simplified implementation - in reality you'd do proper graph traversal
	for _, nodes := range flowGraph {
		for _, node := range nodes {
			// Check if this node is a taint sink
			if sink := fa.isTaintSink(node); sink != nil {
				path := TaintPath{
					Source:     fa.getTaintSourceForNode(sourceNode),
					Sink:       *sink,
					Path:       []DataFlowNode{sourceNode, node},
					Confidence: 0.8,
				}
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// isTaintSink checks if a node represents a taint sink
func (fa *FlowAnalyzer) isTaintSink(node DataFlowNode) *TaintSink {
	// Check if node contains taint sink patterns
	for _, sink := range fa.taintSinks {
		for _, operation := range node.Operations {
			if strings.Contains(operation, sink.Type) {
				return &sink
			}
		}
	}
	return nil
}

// getTaintSourceForNode gets the taint source for a node
func (fa *FlowAnalyzer) getTaintSourceForNode(node DataFlowNode) TaintSource {
	// Simplified implementation
	for _, source := range fa.taintSources {
		for _, variable := range node.Variables {
			if strings.Contains(variable, source.Pattern) {
				return source
			}
		}
	}
	return TaintSource{}
}

// createFindingFromPath creates a security finding from a taint path
func (fa *FlowAnalyzer) createFindingFromPath(path TaintPath, filePath string) *types.SecurityFinding {
	if len(path.Path) == 0 {
		return nil
	}

	// Get the sink node (last node in path)
	sinkNode := path.Path[len(path.Path)-1]

	return &types.SecurityFinding{
		RuleID:      fmt.Sprintf("FLOW-%s", path.Sink.VulnType),
		RuleName:    fmt.Sprintf("Flow-based %s Detection", strings.Title(path.Sink.VulnType)),
		VulnType:    types.VulnerabilityType(path.Sink.VulnType),
		Severity:    fa.getSeverityForVulnType(path.Sink.VulnType),
		File:        filePath,
		Line:        int(sinkNode.Position),
		Column:      0,
		Message:     fmt.Sprintf("Tainted data flows from %s to %s", path.Source.Name, path.Sink.Name),
		Code:        "", // Would be populated with actual code
		Remediation: fa.getRemediationForVulnType(path.Sink.VulnType),
		OWASP:       types.OWASPReference{},
		CWE:         fa.getCWEForVulnType(path.Sink.VulnType),
		Context:     path.Sink.Type,
	}
}

// getSeverityForVulnType returns the severity level for a vulnerability type
func (fa *FlowAnalyzer) getSeverityForVulnType(vulnType string) config.SeverityLevel {
	switch vulnType {
	case "sql_injection":
		return config.SeverityCritical
	case "xss":
		return config.SeverityHigh
	case "command_injection":
		return config.SeverityCritical
	case "code_injection":
		return config.SeverityCritical
	default:
		return config.SeverityMedium
	}
}

// getRemediationForVulnType returns remediation advice for a vulnerability type
func (fa *FlowAnalyzer) getRemediationForVulnType(vulnType string) string {
	switch vulnType {
	case "sql_injection":
		return "Use parameterized queries or prepared statements to prevent SQL injection"
	case "xss":
		return "Encode output data for the specific context (HTML, JavaScript, CSS, URL)"
	case "command_injection":
		return "Validate and sanitize all user inputs before using them in system commands"
	case "code_injection":
		return "Avoid dynamic code evaluation; use safer alternatives when possible"
	default:
		return "Review the code for potential security vulnerabilities"
	}
}

// getCWEForVulnType returns the CWE identifier for a vulnerability type
func (fa *FlowAnalyzer) getCWEForVulnType(vulnType string) string {
	switch vulnType {
	case "sql_injection":
		return "CWE-89"
	case "xss":
		return "CWE-79"
	case "command_injection":
		return "CWE-78"
	case "code_injection":
		return "CWE-95"
	default:
		return ""
	}
}
