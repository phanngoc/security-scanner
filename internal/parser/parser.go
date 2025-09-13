package parser

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/le-company/security-scanner/internal/cache"
	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/lsp"
	"github.com/le-company/security-scanner/internal/rules"
	"go.uber.org/zap"
)

// SymbolTable represents a symbol table for code analysis
type SymbolTable struct {
	Functions map[string]*FunctionInfo
	Variables map[string]*VariableInfo
	Imports   map[string]string
	FileSet   *token.FileSet
	File      *ast.File
	Language  string
	FilePath  string
}

// FunctionInfo contains information about a function
type FunctionInfo struct {
	Name       string
	Parameters []Parameter
	Returns    []string
	StartPos   token.Pos
	EndPos     token.Pos
	Body       []string
	Calls      []string
}

// Parameter represents a function parameter
type Parameter struct {
	Name string
	Type string
}

// VariableInfo contains information about a variable
type VariableInfo struct {
	Name     string
	Type     string
	Value    string
	StartPos token.Pos
	EndPos   token.Pos
	Scope    string
}

// Parser interface for different languages
type Parser interface {
	Parse(filePath string, content []byte) (*SymbolTable, error)
	GetLanguage() string
	GetSupportedExtensions() []string
}

// GoParser implements Parser for Go language
type GoParser struct{}

// NewGoParser creates a new Go parser
func NewGoParser() *GoParser {
	return &GoParser{}
}

// Parse parses Go source code and builds symbol table
func (p *GoParser) Parse(filePath string, content []byte) (*SymbolTable, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, content, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	symbolTable := &SymbolTable{
		Functions: make(map[string]*FunctionInfo),
		Variables: make(map[string]*VariableInfo),
		Imports:   make(map[string]string),
		FileSet:   fset,
		File:      file,
		Language:  "go",
		FilePath:  filePath,
	}

	// Extract imports
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := filepath.Base(path)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		symbolTable.Imports[name] = path
	}

	// Walk AST and extract symbols
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			p.extractFunction(symbolTable, node)
		case *ast.GenDecl:
			p.extractVariables(symbolTable, node)
		}
		return true
	})

	return symbolTable, nil
}

// GetLanguage returns the parser language
func (p *GoParser) GetLanguage() string {
	return "go"
}

// GetSupportedExtensions returns supported file extensions
func (p *GoParser) GetSupportedExtensions() []string {
	return []string{".go"}
}

// extractFunction extracts function information from AST
func (p *GoParser) extractFunction(symbolTable *SymbolTable, funcDecl *ast.FuncDecl) {
	if funcDecl.Name == nil {
		return
	}

	funcInfo := &FunctionInfo{
		Name:     funcDecl.Name.Name,
		StartPos: funcDecl.Pos(),
		EndPos:   funcDecl.End(),
	}

	// Extract parameters
	if funcDecl.Type.Params != nil {
		for _, param := range funcDecl.Type.Params.List {
			paramType := ""
			if param.Type != nil {
				paramType = p.typeToString(param.Type)
			}

			if param.Names != nil {
				for _, name := range param.Names {
					funcInfo.Parameters = append(funcInfo.Parameters, Parameter{
						Name: name.Name,
						Type: paramType,
					})
				}
			}
		}
	}

	// Extract return types
	if funcDecl.Type.Results != nil {
		for _, result := range funcDecl.Type.Results.List {
			if result.Type != nil {
				funcInfo.Returns = append(funcInfo.Returns, p.typeToString(result.Type))
			}
		}
	}

	// Extract function calls from body
	if funcDecl.Body != nil {
		ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
			if callExpr, ok := n.(*ast.CallExpr); ok {
				if ident, ok := callExpr.Fun.(*ast.Ident); ok {
					funcInfo.Calls = append(funcInfo.Calls, ident.Name)
				} else if selExpr, ok := callExpr.Fun.(*ast.SelectorExpr); ok {
					if x, ok := selExpr.X.(*ast.Ident); ok {
						funcInfo.Calls = append(funcInfo.Calls, x.Name+"."+selExpr.Sel.Name)
					}
				}
			}
			return true
		})
	}

	symbolTable.Functions[funcInfo.Name] = funcInfo
}

// extractVariables extracts variable information from AST
func (p *GoParser) extractVariables(symbolTable *SymbolTable, genDecl *ast.GenDecl) {
	for _, spec := range genDecl.Specs {
		if valueSpec, ok := spec.(*ast.ValueSpec); ok {
			varType := ""
			if valueSpec.Type != nil {
				varType = p.typeToString(valueSpec.Type)
			}

			for i, name := range valueSpec.Names {
				varInfo := &VariableInfo{
					Name:     name.Name,
					Type:     varType,
					StartPos: name.Pos(),
					EndPos:   name.End(),
					Scope:    "global",
				}

				// Extract initial value if present
				if valueSpec.Values != nil && i < len(valueSpec.Values) {
					varInfo.Value = p.exprToString(valueSpec.Values[i])
				}

				symbolTable.Variables[varInfo.Name] = varInfo
			}
		}
	}
}

// typeToString converts AST type to string representation
func (p *GoParser) typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
	case *ast.StarExpr:
		return "*" + p.typeToString(t.X)
	case *ast.ArrayType:
		return "[]" + p.typeToString(t.Elt)
	case *ast.MapType:
		return "map[" + p.typeToString(t.Key) + "]" + p.typeToString(t.Value)
	}
	return "unknown"
}

// exprToString converts AST expression to string representation
func (p *GoParser) exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Value
	case *ast.Ident:
		return e.Name
	case *ast.BinaryExpr:
		return p.exprToString(e.X) + " " + e.Op.String() + " " + p.exprToString(e.Y)
	}
	return "complex_expr"
}

// PHPParser implements Parser for PHP language (basic implementation)
type PHPParser struct{}

// NewPHPParser creates a new PHP parser
func NewPHPParser() *PHPParser {
	return &PHPParser{}
}

// Parse parses PHP source code (simplified implementation)
func (p *PHPParser) Parse(filePath string, content []byte) (*SymbolTable, error) {
	symbolTable := &SymbolTable{
		Functions: make(map[string]*FunctionInfo),
		Variables: make(map[string]*VariableInfo),
		Imports:   make(map[string]string),
		Language:  "php",
		FilePath:  filePath,
	}
	
	// Basic regex-based parsing for functions and classes
	contentStr := string(content)
	
	// Extract functions using regex
	funcRegex := regexp.MustCompile(`(?m)^\s*(?:public|private|protected|static|\s)*\s*function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)
	funcMatches := funcRegex.FindAllStringSubmatch(contentStr, -1)
	
	for _, match := range funcMatches {
		if len(match) >= 2 {
			funcName := match[1]
			paramStr := ""
			if len(match) >= 3 {
				paramStr = match[2]
			}
			
			funcInfo := &FunctionInfo{
				Name:       funcName,
				Parameters: []Parameter{},
				StartPos:   0, // Would need proper parsing for positions
				EndPos:     0,
			}
			
			// Basic parameter parsing
			if paramStr != "" {
				params := strings.Split(paramStr, ",")
				for _, param := range params {
					param = strings.TrimSpace(param)
					if param != "" {
						// Extract parameter name (very basic)
						parts := strings.Fields(param)
						if len(parts) > 0 {
							paramName := parts[len(parts)-1]
							if strings.HasPrefix(paramName, "$") {
								paramName = paramName[1:] // Remove $ prefix
							}
							funcInfo.Parameters = append(funcInfo.Parameters, Parameter{
								Name: paramName,
								Type: "mixed", // PHP is dynamically typed
							})
						}
					}
				}
			}
			
			symbolTable.Functions[funcName] = funcInfo
		}
	}
	
	// Extract class variables
	varRegex := regexp.MustCompile(`(?m)^\s*(?:public|private|protected|static|\s)*\s*\$([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;]`)
	varMatches := varRegex.FindAllStringSubmatch(contentStr, -1)
	
	for _, match := range varMatches {
		if len(match) >= 2 {
			varName := match[1]
			symbolTable.Variables[varName] = &VariableInfo{
				Name:     varName,
				Type:     "mixed",
				StartPos: 0,
				EndPos:   0,
				Scope:    "class",
			}
		}
	}
	
	// Extract use statements (imports)
	useRegex := regexp.MustCompile(`(?m)^\s*use\s+([a-zA-Z0-9_\\]+)(?:\s+as\s+([a-zA-Z_][a-zA-Z0-9_]*))?\s*;`)
	useMatches := useRegex.FindAllStringSubmatch(contentStr, -1)
	
	for _, match := range useMatches {
		if len(match) >= 2 {
			fullName := match[1]
			alias := ""
			if len(match) >= 3 && match[2] != "" {
				alias = match[2]
			} else {
				// Use last part of namespace as alias
				parts := strings.Split(fullName, "\\")
				alias = parts[len(parts)-1]
			}
			symbolTable.Imports[alias] = fullName
		}
	}
	
	return symbolTable, nil
}

// GetLanguage returns the parser language
func (p *PHPParser) GetLanguage() string {
	return "php"
}

// GetSupportedExtensions returns supported file extensions
func (p *PHPParser) GetSupportedExtensions() []string {
	return []string{".php"}
}

// ParserRegistry manages language parsers
type ParserRegistry struct {
	parsers       map[string]Parser
	lspClients    map[string]*lsp.LSPClient
	cache         *cache.SymbolTableCache
	config        *config.Config
	logger        *zap.Logger
	workspaceRoot string
}

// NewParserRegistry creates a new parser registry
func NewParserRegistry(workspaceRoot string, cfg *config.Config, logger *zap.Logger) *ParserRegistry {
	registry := &ParserRegistry{
		parsers:       make(map[string]Parser),
		lspClients:    make(map[string]*lsp.LSPClient),
		config:        cfg,
		logger:        logger,
		workspaceRoot: workspaceRoot,
	}

	// Initialize cache using configured directory
	var cacheDir string
	if cfg.Cache.Enabled {
		cacheDir = cfg.Cache.Directory
		if !filepath.IsAbs(cacheDir) {
			cacheDir = filepath.Join(workspaceRoot, cacheDir)
		}
	} else {
		cacheDir = filepath.Join(workspaceRoot, ".cache")
	}
	
	if cfg.Cache.Enabled {
		if symbolCache, err := cache.NewSymbolTableCache(cacheDir, logger); err != nil {
			logger.Warn("Failed to initialize symbol table cache", zap.Error(err))
		} else {
			registry.cache = symbolCache
		}
	}

	// Register default parsers
	registry.RegisterParser(NewGoParser())
	registry.RegisterParser(NewPHPParser())

	return registry
}

// RegisterParser registers a new parser
func (pr *ParserRegistry) RegisterParser(parser Parser) {
	for _, ext := range parser.GetSupportedExtensions() {
		pr.parsers[ext] = parser
	}
}

// GetParser returns a parser for the given file extension
func (pr *ParserRegistry) GetParser(extension string) Parser {
	return pr.parsers[extension]
}

// GetSupportedExtensions returns all supported file extensions
func (pr *ParserRegistry) GetSupportedExtensions() []string {
	var extensions []string
	for ext := range pr.parsers {
		extensions = append(extensions, ext)
	}
	return extensions
}

// GetOrCreateLSPClient gets or creates an LSP client for a language
func (pr *ParserRegistry) GetOrCreateLSPClient(language string) (*lsp.LSPClient, error) {
	// Check if LSP is disabled in config first
	if pr.config != nil && pr.config.NoLsp {
		return nil, fmt.Errorf("LSP is disabled in configuration")
	}
	
	if client, exists := pr.lspClients[language]; exists {
		return client, nil
	}

	client, err := lsp.NewLSPClient(language, pr.workspaceRoot, pr.logger)
	if err != nil {
		return nil, err
	}

	pr.lspClients[language] = client
	return client, nil
}

// ParseWithLSP parses a file using LSP for enhanced symbol information
func (pr *ParserRegistry) ParseWithLSP(filePath string, content []byte, language string) (*lsp.SymbolTable, error) {
	// Check if LSP is disabled in config
	if pr.config != nil && pr.config.NoLsp {
		pr.logger.Debug("LSP disabled in configuration, using basic parsing",
			zap.String("language", language))
		return pr.parseWithoutLSP(filePath, content, language)
	}
	
	client, err := pr.GetOrCreateLSPClient(language)
	if err != nil {
		pr.logger.Warn("LSP client unavailable, falling back to basic parsing",
			zap.String("language", language),
			zap.Error(err))
		return pr.parseWithoutLSP(filePath, content, language)
	}

	// Create file URI
	uri := lsp.FileToURI(filePath)

	// Open document in LSP
	err = client.OpenDocument(uri, language, string(content), 1)
	if err != nil {
		pr.logger.Warn("Failed to open document in LSP",
			zap.String("uri", uri),
			zap.Error(err))
		return pr.parseWithoutLSP(filePath, content, language)
	}

	// Get document symbols
	symbols, err := client.GetDocumentSymbols(uri)
	if err != nil {
		pr.logger.Warn("Failed to get document symbols",
			zap.String("uri", uri),
			zap.Error(err))
		// Close document and fallback
		client.CloseDocument(uri)
		return pr.parseWithoutLSP(filePath, content, language)
	}

	// Build enhanced symbol table
	symbolTable := lsp.NewSymbolTable(uri, language, pr.logger)
	err = symbolTable.BuildFromLSPSymbols(symbols, string(content))
	if err != nil {
		pr.logger.Error("Failed to build symbol table",
			zap.String("uri", uri),
			zap.Error(err))
		client.CloseDocument(uri)
		return pr.parseWithoutLSP(filePath, content, language)
	}

	// Close document (we've extracted what we need)
	client.CloseDocument(uri)

	return symbolTable, nil
}

// parseWithoutLSP falls back to basic parsing without LSP
func (pr *ParserRegistry) parseWithoutLSP(filePath string, content []byte, language string) (*lsp.SymbolTable, error) {
	// Create basic symbol table
	symbolTable := lsp.NewSymbolTable(lsp.FileToURI(filePath), language, pr.logger)

	// Use traditional parser if available
	ext := filepath.Ext(filePath)
	if parser := pr.GetParser(ext); parser != nil {
		basicSymbolTable, err := parser.Parse(filePath, content)
		if err != nil {
			pr.logger.Warn("Basic parser failed", zap.Error(err))
		} else {
			// Convert basic symbol table to enhanced format
			pr.convertBasicToEnhanced(basicSymbolTable, symbolTable)
		}
	}

	return symbolTable, nil
}

// convertBasicToEnhanced converts basic symbol table to enhanced LSP format
func (pr *ParserRegistry) convertBasicToEnhanced(basic *SymbolTable, enhanced *lsp.SymbolTable) {
	// This is a simplified conversion - in production you'd want more sophisticated mapping
	// For now, we'll just extract basic function and variable information

	var symbols []lsp.DocumentSymbol

	// Convert functions
	for name, funcInfo := range basic.Functions {
		symbol := lsp.DocumentSymbol{
			Name: name,
			Kind: lsp.SymbolKindFunction,
			Range: lsp.Range{
				Start: lsp.Position{Line: 0, Character: 0}, // Would need proper conversion
				End:   lsp.Position{Line: 0, Character: 0},
			},
			SelectionRange: lsp.Range{
				Start: lsp.Position{Line: 0, Character: 0},
				End:   lsp.Position{Line: 0, Character: 0},
			},
		}

		// Add parameters as children
		for _, param := range funcInfo.Parameters {
			child := lsp.DocumentSymbol{
				Name: param.Name,
				Kind: lsp.SymbolKindVariable,
			}
			symbol.Children = append(symbol.Children, child)
		}

		symbols = append(symbols, symbol)
	}

	// Convert variables
	for name, varInfo := range basic.Variables {
		symbol := lsp.DocumentSymbol{
			Name:   name,
			Detail: varInfo.Type,
			Kind:   lsp.SymbolKindVariable,
		}
		symbols = append(symbols, symbol)
	}

	// Build the enhanced symbol table
	enhanced.BuildFromLSPSymbols(symbols, "")
}

// AnalyzeFile analyzes a single file using symbol table analysis
func (pr *ParserRegistry) AnalyzeFile(filePath string) ([]*rules.SecurityFinding, error) {
	language := pr.detectLanguage(filePath)

	var symbolTable *lsp.SymbolTable

	// Try to get from cache first
	if pr.cache != nil {
		if cachedTable, found := pr.cache.Get(filePath); found {
			pr.logger.Debug("Using cached symbol table", zap.String("file", filePath))
			symbolTable = cachedTable
		}
	}

	// If not cached, build symbol table
	if symbolTable == nil {
		// Read file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		// Try LSP-based analysis first
		symbolTable, err = pr.ParseWithLSP(filePath, content, language)
		if err != nil {
			pr.logger.Warn("LSP analysis failed, falling back to basic parser",
				zap.String("file", filePath),
				zap.Error(err))

			// Fallback to basic parser
			symbolTable, err = pr.parseWithoutLSP(filePath, content, language)
			if err != nil {
				return nil, fmt.Errorf("failed to parse file: %w", err)
			}
		}

		// Cache the newly built symbol table
		if pr.cache != nil && symbolTable != nil {
			if err := pr.cache.Set(filePath, symbolTable); err != nil {
				pr.logger.Warn("Failed to cache symbol table",
					zap.String("file", filePath),
					zap.Error(err))
			}
		}
	}

	// Create symbol-based analyzer
	analyzer := rules.NewSymbolBasedAnalyzer()

	// Analyze using symbol table
	findings := analyzer.AnalyzeSymbolTable(symbolTable)

	// Return findings directly (they are already in correct format)
	return findings, nil
}

// GetSymbolTable gets symbol table for a file with caching support
func (pr *ParserRegistry) GetSymbolTable(filePath string) (*lsp.SymbolTable, error) {
	language := pr.detectLanguage(filePath)

	// Try to get from cache first
	if pr.cache != nil {
		if cachedTable, found := pr.cache.Get(filePath); found {
			pr.logger.Debug("Using cached symbol table", zap.String("file", filePath))
			return cachedTable, nil
		}
	}

	// If not cached, build symbol table
	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try LSP-based analysis first
	symbolTable, err := pr.ParseWithLSP(filePath, content, language)
	if err != nil {
		pr.logger.Warn("LSP analysis failed, falling back to basic parser",
			zap.String("file", filePath),
			zap.Error(err))

		// Fallback to basic parser
		symbolTable, err = pr.parseWithoutLSP(filePath, content, language)
		if err != nil {
			return nil, fmt.Errorf("failed to parse file: %w", err)
		}
	}

	// Cache the newly built symbol table
	if pr.cache != nil && symbolTable != nil {
		if err := pr.cache.Set(filePath, symbolTable); err != nil {
			pr.logger.Warn("Failed to cache symbol table",
				zap.String("file", filePath),
				zap.Error(err))
		}
	}

	return symbolTable, nil
}

// detectLanguage detects the programming language from file extension
func (pr *ParserRegistry) detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".go":
		return "go"
	case ".php":
		return "php"
	case ".java":
		return "java"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".c":
		return "c"
	case ".cpp", ".cc", ".cxx":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".rb":
		return "ruby"
	default:
		return "unknown"
	}
}

// Close closes all LSP clients
func (pr *ParserRegistry) Close() {
	for _, client := range pr.lspClients {
		client.Close()
	}
}
