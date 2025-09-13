package ast

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SimplePHPASTParser implements a simplified PHP AST parser
// This is a basic implementation that focuses on security pattern detection
type SimplePHPASTParser struct {
	*BaseASTParser
}

// NewSimplePHPASTParser creates a new simplified PHP AST parser
func NewSimplePHPASTParser() *SimplePHPASTParser {
	base := NewBaseASTParser("php", []string{".php", ".phtml", ".php3", ".php4", ".php5", ".php7"})

	return &SimplePHPASTParser{
		BaseASTParser: base,
	}
}

// Parse parses PHP source code using regex-based analysis
func (p *SimplePHPASTParser) Parse(content []byte, filename string) (*ProgramNode, *ParseStats, error) {
	stats := &ParseStats{
		StartTime:   time.Now(),
		Language:    "php",
		FileSize:    int64(len(content)),
		LinesOfCode: strings.Count(string(content), "\n") + 1,
	}

	sourceCode := string(content)

	// Create program node
	programNode := &ProgramNode{
		BaseNode: BaseNode{
			Type:     NodeProgram,
			Position: Position{Filename: filename, Line: 1, Column: 1},
			Children: make([]ASTNode, 0),
			Metadata: make(map[string]interface{}),
		},
		Language:   "php",
		SourceCode: sourceCode,
		Imports:    make([]*ImportNode, 0),
		Functions:  make([]*FunctionNode, 0),
		Classes:    make([]*ClassNode, 0),
		Variables:  make([]*VariableNode, 0),
	}

	// Parse using regex patterns
	err := p.parseWithRegex(sourceCode, programNode)
	if err != nil {
		stats.AddError(err)
		return nil, stats, fmt.Errorf("PHP parsing failed: %w", err)
	}

	stats.EndTime = time.Now()
	stats.Duration = stats.EndTime.Sub(stats.StartTime)
	stats.NodesCreated = p.countNodes(programNode)

	return programNode, stats, nil
}

// parseWithRegex parses PHP code using regex patterns
func (p *SimplePHPASTParser) parseWithRegex(sourceCode string, programNode *ProgramNode) error {
	lines := strings.Split(sourceCode, "\n")

	// Parse functions
	p.parseFunctions(lines, programNode)

	// Parse classes
	p.parseClasses(lines, programNode)

	// Parse variables
	p.parseVariables(lines, programNode)

	// Parse function calls
	p.parseFunctionCalls(lines, programNode)

	return nil
}

// parseFunctions extracts function definitions
func (p *SimplePHPASTParser) parseFunctions(lines []string, programNode *ProgramNode) {
	funcPattern := regexp.MustCompile(`function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)

	for lineNum, line := range lines {
		matches := funcPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				funcName := match[1]
				paramStr := match[2]

				funcNode := &FunctionNode{
					BaseNode: BaseNode{
						Type:     NodeFunction,
						Position: Position{Filename: programNode.Position.Filename, Line: lineNum + 1, Column: 1},
					},
					Name:       funcName,
					Parameters: p.parseParameters(paramStr),
				}

				programNode.Functions = append(programNode.Functions, funcNode)
				programNode.AddChild(funcNode)
			}
		}
	}
}

// parseClasses extracts class definitions
func (p *SimplePHPASTParser) parseClasses(lines []string, programNode *ProgramNode) {
	classPattern := regexp.MustCompile(`class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:extends\s+([a-zA-Z_][a-zA-Z0-9_]*))?\s*(?:implements\s+([^{]+))?\s*{`)

	for lineNum, line := range lines {
		matches := classPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				className := match[1]

				classNode := &ClassNode{
					BaseNode: BaseNode{
						Type:     NodeClass,
						Position: Position{Filename: programNode.Position.Filename, Line: lineNum + 1, Column: 1},
					},
					Name:       className,
					Properties: make([]*PropertyNode, 0),
					Methods:    make([]*FunctionNode, 0),
				}

				if len(match) > 2 && match[2] != "" {
					classNode.Extends = match[2]
				}

				if len(match) > 3 && match[3] != "" {
					implements := strings.Split(strings.TrimSpace(match[3]), ",")
					for _, impl := range implements {
						classNode.Implements = append(classNode.Implements, strings.TrimSpace(impl))
					}
				}

				programNode.Classes = append(programNode.Classes, classNode)
				programNode.AddChild(classNode)
			}
		}
	}
}

// parseVariables extracts variable assignments
func (p *SimplePHPASTParser) parseVariables(lines []string, programNode *ProgramNode) {
	varPattern := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+);`)

	for lineNum, line := range lines {
		matches := varPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 3 {
				varName := match[1]
				value := strings.TrimSpace(match[2])

				varNode := &VariableNode{
					BaseNode: BaseNode{
						Type:     NodeVariable,
						Position: Position{Filename: programNode.Position.Filename, Line: lineNum + 1, Column: 1},
					},
					Name: varName,
				}

				// Check if value comes from user input
				if p.isUserInput(value) {
					varNode.IsTainted = true
					varNode.Source = "user_input"
				}

				programNode.Variables = append(programNode.Variables, varNode)
				programNode.AddChild(varNode)
			}
		}
	}
}

// parseFunctionCalls extracts function calls
func (p *SimplePHPASTParser) parseFunctionCalls(lines []string, programNode *ProgramNode) {
	callPattern := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)

	for lineNum, line := range lines {
		matches := callPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				funcName := match[1]

				// Skip language constructs
				if p.isLanguageConstruct(funcName) {
					continue
				}

				callNode := &FunctionCallNode{
					BaseNode: BaseNode{
						Type:     NodeFunctionCall,
						Position: Position{Filename: programNode.Position.Filename, Line: lineNum + 1, Column: 1},
					},
					Function:  funcName,
					Arguments: make([]ASTNode, 0),
				}

				// Parse arguments (simplified)
				if len(match) > 2 && match[2] != "" {
					args := strings.Split(match[2], ",")
					for _, arg := range args {
						arg = strings.TrimSpace(arg)
						if arg != "" {
							// Create a simple argument node
							argNode := &BaseNode{
								Type:     NodeExpression,
								Position: callNode.Position,
							}
							callNode.Arguments = append(callNode.Arguments, argNode)
						}
					}
				}

				programNode.AddChild(callNode)
			}
		}
	}
}

// parseParameters parses function parameters
func (p *SimplePHPASTParser) parseParameters(paramStr string) []*ParameterNode {
	var params []*ParameterNode

	if strings.TrimSpace(paramStr) == "" {
		return params
	}

	paramPattern := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)`)
	matches := paramPattern.FindAllStringSubmatch(paramStr, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			paramName := match[1]
			param := &ParameterNode{
				BaseNode: BaseNode{
					Type: NodeVariable,
				},
				Name: paramName,
				Type: "mixed",
			}
			params = append(params, param)
		}
	}

	return params
}

// isUserInput checks if a value comes from user input
func (p *SimplePHPASTParser) isUserInput(value string) bool {
	userInputSources := []string{"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"}

	for _, source := range userInputSources {
		if strings.Contains(value, source) {
			return true
		}
	}

	return false
}

// isLanguageConstruct checks if a function name is a language construct
func (p *SimplePHPASTParser) isLanguageConstruct(name string) bool {
	constructs := map[string]bool{
		"if":       true,
		"else":     true,
		"elseif":   true,
		"while":    true,
		"for":      true,
		"foreach":  true,
		"switch":   true,
		"case":     true,
		"default":  true,
		"class":    true,
		"function": true,
		"return":   true,
		"break":    true,
		"continue": true,
	}

	return constructs[strings.ToLower(name)]
}

// BuildSymbolTable builds a symbol table from the AST
func (p *SimplePHPASTParser) BuildSymbolTable(ast *ProgramNode) (*SymbolTable, error) {
	symbolTable := NewSymbolTable()

	// Push global scope
	symbolTable.PushScope(ScopeGlobal)

	// Add functions to symbol table
	for _, function := range ast.Functions {
		symbol := &Symbol{
			Name:     function.Name,
			Type:     "function",
			Kind:     SymbolFunction,
			Position: function.Position,
			Scope:    symbolTable.CurrentScope,
			Node:     function,
		}

		funcSymbol := &FunctionSymbol{
			Symbol:     symbol,
			Parameters: make([]*ParameterSymbol, 0),
			CallSites:  make([]*CallSite, 0),
		}

		// Add parameters
		for _, param := range function.Parameters {
			paramSymbol := &ParameterSymbol{
				VariableSymbol: &VariableSymbol{
					Symbol: &Symbol{
						Name:     param.Name,
						Type:     param.Type,
						Kind:     SymbolParameter,
						Position: param.Position,
						Scope:    symbolTable.CurrentScope,
						Node:     param,
					},
				},
				IsOptional: param.IsOptional,
				IsVariadic: param.IsVariadic,
			}
			funcSymbol.Parameters = append(funcSymbol.Parameters, paramSymbol)
		}

		symbolTable.AddSymbol(symbol)
		symbolTable.Functions[function.Name] = funcSymbol
	}

	// Add classes to symbol table
	for _, class := range ast.Classes {
		symbol := &Symbol{
			Name:     class.Name,
			Type:     "class",
			Kind:     SymbolClass,
			Position: class.Position,
			Scope:    symbolTable.CurrentScope,
			Node:     class,
		}

		classSymbol := &ClassSymbol{
			Symbol:     symbol,
			Methods:    make([]*FunctionSymbol, 0),
			Properties: make([]*VariableSymbol, 0),
			Extends:    class.Extends,
			Implements: class.Implements,
		}

		symbolTable.AddSymbol(symbol)
		symbolTable.Classes[class.Name] = classSymbol
	}

	// Add variables to symbol table
	for _, variable := range ast.Variables {
		symbol := &Symbol{
			Name:     variable.Name,
			Type:     variable.Type,
			Kind:     SymbolVariable,
			Position: variable.Position,
			Scope:    symbolTable.CurrentScope,
			Node:     variable,
		}

		varSymbol := &VariableSymbol{
			Symbol:      symbol,
			DataType:    variable.Type,
			IsTainted:   variable.IsTainted,
			Assignments: make([]*AssignmentSite, 0),
		}

		if variable.IsTainted {
			varSymbol.TaintSources = []string{variable.Source}
		}

		symbolTable.AddSymbol(symbol)
		symbolTable.Variables[variable.Name] = varSymbol
	}

	return symbolTable, nil
}

// countNodes counts total nodes in the AST
func (p *SimplePHPASTParser) countNodes(node ASTNode) int {
	count := 1
	for _, child := range node.GetChildren() {
		count += p.countNodes(child)
	}
	return count
}
