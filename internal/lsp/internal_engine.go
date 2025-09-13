package lsp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// InternalEngine provides LSP-like functionality without external servers
type InternalEngine struct {
	logger *zap.Logger
}

// NewInternalEngine creates a new internal LSP engine
func NewInternalEngine(logger *zap.Logger) *InternalEngine {
	return &InternalEngine{
		logger: logger,
	}
}

// ParseFile parses a file and returns a symbol table using internal parsing
func (e *InternalEngine) ParseFile(filePath string, content []byte, language string) (*SymbolTable, error) {
	switch language {
	case "go":
		return e.parseGoFile(filePath, content)
	case "php":
		return e.parsePHPFile(filePath, content)
	case "javascript", "js":
		return e.parseJavaScriptFile(filePath, content)
	case "typescript", "ts":
		return e.parseTypeScriptFile(filePath, content)
	case "python":
		return e.parsePythonFile(filePath, content)
	case "java":
		return e.parseJavaFile(filePath, content)
	default:
		return e.parseGenericFile(filePath, content, language)
	}
}

// parseGoFile parses Go files using the built-in Go AST parser
func (e *InternalEngine) parseGoFile(filePath string, content []byte) (*SymbolTable, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Go file: %w", err)
	}

	uri := FileToURI(filePath)
	symbolTable := NewSymbolTable(uri, "go", e.logger)

	symbols := e.extractGoSymbols(file, fset)
	return symbolTable, symbolTable.BuildFromLSPSymbols(symbols, string(content))
}

// extractGoSymbols extracts symbols from Go AST
func (e *InternalEngine) extractGoSymbols(file *ast.File, fset *token.FileSet) []DocumentSymbol {
	var symbols []DocumentSymbol

	// Extract package declaration
	if file.Name != nil {
		pos := fset.Position(file.Name.Pos())
		end := fset.Position(file.Name.End())
		symbols = append(symbols, DocumentSymbol{
			Name: file.Name.Name,
			Kind: SymbolKindPackage,
			Range: Range{
				Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
				End:   Position{Line: end.Line - 1, Character: end.Column - 1},
			},
			SelectionRange: Range{
				Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
				End:   Position{Line: end.Line - 1, Character: end.Column - 1},
			},
		})
	}

	// Extract imports
	for _, imp := range file.Imports {
		pos := fset.Position(imp.Pos())
		end := fset.Position(imp.End())
		name := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil {
			name = imp.Name.Name + " " + name
		}
		symbols = append(symbols, DocumentSymbol{
			Name: name,
			Kind: SymbolKindModule,
			Range: Range{
				Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
				End:   Position{Line: end.Line - 1, Character: end.Column - 1},
			},
			SelectionRange: Range{
				Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
				End:   Position{Line: end.Line - 1, Character: end.Column - 1},
			},
		})
	}

	// Walk the AST to extract declarations
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			symbols = append(symbols, e.extractGoFunction(node, fset))
		case *ast.TypeSpec:
			symbols = append(symbols, e.extractGoType(node, fset))
		case *ast.ValueSpec:
			symbols = append(symbols, e.extractGoValue(node, fset)...)
		}
		return true
	})

	return symbols
}

// extractGoFunction extracts function symbols
func (e *InternalEngine) extractGoFunction(funcDecl *ast.FuncDecl, fset *token.FileSet) DocumentSymbol {
	pos := fset.Position(funcDecl.Pos())
	end := fset.Position(funcDecl.End())
	namePos := fset.Position(funcDecl.Name.Pos())
	nameEnd := fset.Position(funcDecl.Name.End())

	symbol := DocumentSymbol{
		Name: funcDecl.Name.Name,
		Kind: SymbolKindFunction,
		Range: Range{
			Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
			End:   Position{Line: end.Line - 1, Character: end.Column - 1},
		},
		SelectionRange: Range{
			Start: Position{Line: namePos.Line - 1, Character: namePos.Column - 1},
			End:   Position{Line: nameEnd.Line - 1, Character: nameEnd.Column - 1},
		},
	}

	// Check if it's a method
	if funcDecl.Recv != nil {
		symbol.Kind = SymbolKindMethod
	}

	// Extract parameters as children
	if funcDecl.Type.Params != nil {
		for _, param := range funcDecl.Type.Params.List {
			for _, name := range param.Names {
				paramPos := fset.Position(name.Pos())
				paramEnd := fset.Position(name.End())
				symbol.Children = append(symbol.Children, DocumentSymbol{
					Name: name.Name,
					Kind: SymbolKindVariable,
					Range: Range{
						Start: Position{Line: paramPos.Line - 1, Character: paramPos.Column - 1},
						End:   Position{Line: paramEnd.Line - 1, Character: paramEnd.Column - 1},
					},
					SelectionRange: Range{
						Start: Position{Line: paramPos.Line - 1, Character: paramPos.Column - 1},
						End:   Position{Line: paramEnd.Line - 1, Character: paramEnd.Column - 1},
					},
				})
			}
		}
	}

	return symbol
}

// extractGoType extracts type symbols
func (e *InternalEngine) extractGoType(typeSpec *ast.TypeSpec, fset *token.FileSet) DocumentSymbol {
	pos := fset.Position(typeSpec.Pos())
	end := fset.Position(typeSpec.End())
	namePos := fset.Position(typeSpec.Name.Pos())
	nameEnd := fset.Position(typeSpec.Name.End())

	kind := SymbolKindStruct
	switch typeSpec.Type.(type) {
	case *ast.InterfaceType:
		kind = SymbolKindInterface
	case *ast.StructType:
		kind = SymbolKindStruct
	}

	return DocumentSymbol{
		Name: typeSpec.Name.Name,
		Kind: kind,
		Range: Range{
			Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
			End:   Position{Line: end.Line - 1, Character: end.Column - 1},
		},
		SelectionRange: Range{
			Start: Position{Line: namePos.Line - 1, Character: namePos.Column - 1},
			End:   Position{Line: nameEnd.Line - 1, Character: nameEnd.Column - 1},
		},
	}
}

// extractGoValue extracts variable/constant symbols
func (e *InternalEngine) extractGoValue(valueSpec *ast.ValueSpec, fset *token.FileSet) []DocumentSymbol {
	var symbols []DocumentSymbol
	for _, name := range valueSpec.Names {
		pos := fset.Position(name.Pos())
		end := fset.Position(name.End())
		symbols = append(symbols, DocumentSymbol{
			Name: name.Name,
			Kind: SymbolKindVariable,
			Range: Range{
				Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
				End:   Position{Line: end.Line - 1, Character: end.Column - 1},
			},
			SelectionRange: Range{
				Start: Position{Line: pos.Line - 1, Character: pos.Column - 1},
				End:   Position{Line: end.Line - 1, Character: end.Column - 1},
			},
		})
	}
	return symbols
}

// parsePHPFile parses PHP files using regex patterns
func (e *InternalEngine) parsePHPFile(filePath string, content []byte) (*SymbolTable, error) {
	uri := FileToURI(filePath)
	symbolTable := NewSymbolTable(uri, "php", e.logger)
	contentStr := string(content)

	symbols := e.extractPHPSymbols(contentStr)
	return symbolTable, symbolTable.BuildFromLSPSymbols(symbols, contentStr)
}

// extractPHPSymbols extracts symbols from PHP content using regex
func (e *InternalEngine) extractPHPSymbols(content string) []DocumentSymbol {
	var symbols []DocumentSymbol
	lines := strings.Split(content, "\n")

	// Extract classes
	classRegex := regexp.MustCompile(`(?m)^\s*(?:abstract\s+|final\s+)?class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:extends\s+[a-zA-Z_][a-zA-Z0-9_]*\s*)?(?:implements\s+[a-zA-Z_][a-zA-Z0-9_,\s]*\s*)?\{`)
	classMatches := classRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range classMatches {
		if len(match) >= 4 {
			className := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: className,
				Kind: SymbolKindClass,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	// Extract functions/methods
	funcRegex := regexp.MustCompile(`(?m)^\s*(?:public\s+|private\s+|protected\s+|static\s+)*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	funcMatches := funcRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range funcMatches {
		if len(match) >= 4 {
			funcName := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: funcName,
				Kind: SymbolKindFunction,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	// Extract variables
	varRegex := regexp.MustCompile(`(?m)^\s*(?:public\s+|private\s+|protected\s+|static\s+)*\$([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;]`)
	varMatches := varRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range varMatches {
		if len(match) >= 4 {
			varName := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: varName,
				Kind: SymbolKindVariable,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	return symbols
}

// parseJavaScriptFile parses JavaScript files using regex patterns
func (e *InternalEngine) parseJavaScriptFile(filePath string, content []byte) (*SymbolTable, error) {
	return e.parseGenericJSFile(filePath, content, "javascript")
}

// parseTypeScriptFile parses TypeScript files using regex patterns
func (e *InternalEngine) parseTypeScriptFile(filePath string, content []byte) (*SymbolTable, error) {
	return e.parseGenericJSFile(filePath, content, "typescript")
}

// parseGenericJSFile parses JavaScript/TypeScript files
func (e *InternalEngine) parseGenericJSFile(filePath string, content []byte, language string) (*SymbolTable, error) {
	uri := FileToURI(filePath)
	symbolTable := NewSymbolTable(uri, language, e.logger)
	contentStr := string(content)

	symbols := e.extractJSSymbols(contentStr)
	return symbolTable, symbolTable.BuildFromLSPSymbols(symbols, contentStr)
}

// extractJSSymbols extracts symbols from JavaScript/TypeScript content
func (e *InternalEngine) extractJSSymbols(content string) []DocumentSymbol {
	var symbols []DocumentSymbol
	lines := strings.Split(content, "\n")

	// Extract function declarations
	funcRegex := regexp.MustCompile(`(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(`)
	funcMatches := funcRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range funcMatches {
		if len(match) >= 4 {
			funcName := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: funcName,
				Kind: SymbolKindFunction,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	// Extract class declarations
	classRegex := regexp.MustCompile(`(?m)^\s*(?:export\s+)?class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:extends\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*)?\{`)
	classMatches := classRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range classMatches {
		if len(match) >= 4 {
			className := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: className,
				Kind: SymbolKindClass,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	// Extract variable declarations
	varRegex := regexp.MustCompile(`(?m)^\s*(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[=;]`)
	varMatches := varRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range varMatches {
		if len(match) >= 4 {
			varName := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: varName,
				Kind: SymbolKindVariable,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	return symbols
}

// parsePythonFile parses Python files using regex patterns
func (e *InternalEngine) parsePythonFile(filePath string, content []byte) (*SymbolTable, error) {
	uri := FileToURI(filePath)
	symbolTable := NewSymbolTable(uri, "python", e.logger)
	contentStr := string(content)

	symbols := e.extractPythonSymbols(contentStr)
	return symbolTable, symbolTable.BuildFromLSPSymbols(symbols, contentStr)
}

// extractPythonSymbols extracts symbols from Python content
func (e *InternalEngine) extractPythonSymbols(content string) []DocumentSymbol {
	var symbols []DocumentSymbol
	lines := strings.Split(content, "\n")

	// Extract class definitions
	classRegex := regexp.MustCompile(`(?m)^\s*class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*:`)
	classMatches := classRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range classMatches {
		if len(match) >= 4 {
			className := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: className,
				Kind: SymbolKindClass,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	// Extract function definitions
	funcRegex := regexp.MustCompile(`(?m)^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	funcMatches := funcRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range funcMatches {
		if len(match) >= 4 {
			funcName := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: funcName,
				Kind: SymbolKindFunction,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	return symbols
}

// parseJavaFile parses Java files using regex patterns
func (e *InternalEngine) parseJavaFile(filePath string, content []byte) (*SymbolTable, error) {
	uri := FileToURI(filePath)
	symbolTable := NewSymbolTable(uri, "java", e.logger)
	contentStr := string(content)

	symbols := e.extractJavaSymbols(contentStr)
	return symbolTable, symbolTable.BuildFromLSPSymbols(symbols, contentStr)
}

// extractJavaSymbols extracts symbols from Java content
func (e *InternalEngine) extractJavaSymbols(content string) []DocumentSymbol {
	var symbols []DocumentSymbol
	lines := strings.Split(content, "\n")

	// Extract class declarations
	classRegex := regexp.MustCompile(`(?m)^\s*(?:public\s+|private\s+|protected\s+)?(?:abstract\s+|final\s+)?class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:extends\s+[a-zA-Z_][a-zA-Z0-9_]*\s*)?(?:implements\s+[a-zA-Z_][a-zA-Z0-9_,\s]*\s*)?\{`)
	classMatches := classRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range classMatches {
		if len(match) >= 4 {
			className := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: className,
				Kind: SymbolKindClass,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	// Extract method declarations
	methodRegex := regexp.MustCompile(`(?m)^\s*(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:abstract\s+|final\s+)?[a-zA-Z_<>\[\]]+\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	methodMatches := methodRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range methodMatches {
		if len(match) >= 4 {
			methodName := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: methodName,
				Kind: SymbolKindMethod,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	return symbols
}

// parseGenericFile provides basic symbol extraction for unsupported languages
func (e *InternalEngine) parseGenericFile(filePath string, content []byte, language string) (*SymbolTable, error) {
	uri := FileToURI(filePath)
	symbolTable := NewSymbolTable(uri, language, e.logger)
	contentStr := string(content)

	// Very basic symbol extraction using common patterns
	symbols := e.extractGenericSymbols(contentStr)
	return symbolTable, symbolTable.BuildFromLSPSymbols(symbols, contentStr)
}

// extractGenericSymbols extracts basic symbols from generic content
func (e *InternalEngine) extractGenericSymbols(content string) []DocumentSymbol {
	var symbols []DocumentSymbol
	lines := strings.Split(content, "\n")

	// Extract function-like patterns
	funcRegex := regexp.MustCompile(`(?m)^\s*(?:function|def|func|sub|procedure)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[\(\{]`)
	funcMatches := funcRegex.FindAllStringSubmatchIndex(content, -1)
	for _, match := range funcMatches {
		if len(match) >= 4 {
			funcName := content[match[2]:match[3]]
			startLine, startChar := e.findLineColumn(lines, match[0])
			endLine, endChar := e.findLineColumn(lines, match[1])

			symbols = append(symbols, DocumentSymbol{
				Name: funcName,
				Kind: SymbolKindFunction,
				Range: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
				SelectionRange: Range{
					Start: Position{Line: startLine, Character: startChar},
					End:   Position{Line: endLine, Character: endChar},
				},
			})
		}
	}

	return symbols
}

// findLineColumn finds the line and column number for a byte offset
func (e *InternalEngine) findLineColumn(lines []string, offset int) (int, int) {
	currentOffset := 0
	for lineNum, line := range lines {
		lineLength := len(line) + 1 // +1 for newline
		if currentOffset+lineLength > offset {
			return lineNum, offset - currentOffset
		}
		currentOffset += lineLength
	}
	return len(lines) - 1, 0
}
