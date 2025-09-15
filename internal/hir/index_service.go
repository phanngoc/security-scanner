package hir

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/token"
	"os"
	"regexp"
	"strings"

	"go.uber.org/zap"
)

// IndexService manages HIR index operations
type IndexService struct {
	index  *WorkspaceIndex
	logger *zap.Logger
}

// NewIndexService creates a new index service
func NewIndexService(workspacePath string, logger *zap.Logger) (*IndexService, error) {
	index, err := NewWorkspaceIndex(workspacePath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace index: %w", err)
	}

	return &IndexService{
		index:  index,
		logger: logger,
	}, nil
}

// EnsureFileIndexed ensures a file is indexed with all required data
func (s *IndexService) EnsureFileIndexed(ctx context.Context, filePath string, content []byte, language string) error {
	// Calculate file hash and metadata
	hash := s.calculateFileHash(content)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Check if file is already up to date
	upToDate, err := s.index.IsFileUpToDate(filePath, hash, fileInfo.ModTime())
	if err != nil {
		return fmt.Errorf("failed to check if file is up to date: %w", err)
	}

	if upToDate {
		s.logger.Debug("File already indexed and up to date", zap.String("file", filePath))
		return nil
	}

	s.logger.Info("Indexing file", zap.String("file", filePath), zap.String("language", language))

	// Build HIR for the file
	hirFile, err := s.buildHIRFile(filePath, content, language)
	if err != nil {
		return fmt.Errorf("failed to build HIR file: %w", err)
	}

	// Store file record
	fileRecord, err := s.index.StoreFile(hirFile, hash, fileInfo.ModTime(), fileInfo.Size())
	if err != nil {
		return fmt.Errorf("failed to store file record: %w", err)
	}

	// Store symbols
	if err := s.index.StoreSymbols(fileRecord.ID, hirFile.Symbols); err != nil {
		return fmt.Errorf("failed to store symbols: %w", err)
	}

	// Build and store HIR units with CFG
	for _, symbol := range hirFile.Symbols {
		// Build HIR unit for this symbol
		unit, err := s.buildHIRUnit(symbol, hirFile)
		if err != nil {
			s.logger.Warn("Failed to build HIR unit for symbol",
				zap.String("symbol", string(symbol.ID)),
				zap.Error(err))
			continue
		}

		// Store HIR unit
		if err := s.index.StoreHIRUnit(fileRecord.ID, unit); err != nil {
			s.logger.Warn("Failed to store HIR unit",
				zap.String("symbol", string(symbol.ID)),
				zap.Error(err))
			continue
		}
	}

	// Build call graph and store call edges if we have multiple symbols
	if len(hirFile.Symbols) > 1 {
		if err := s.buildAndStoreCallGraph(hirFile, fileRecord.ID); err != nil {
			s.logger.Warn("Failed to build and store call graph",
				zap.String("file", filePath),
				zap.Error(err))
		}
	}

	s.logger.Info("Successfully indexed file",
		zap.String("file", filePath),
		zap.Int("symbols", len(hirFile.Symbols)))

	return nil
}

// GetSymbolTableForFile retrieves symbol table for a file
func (s *IndexService) GetSymbolTableForFile(ctx context.Context, filePath string) (map[string]interface{}, error) {
	// Get file record
	fileRecord, err := s.index.GetFileByPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not found in index: %w", err)
	}

	// Get symbols for this file
	symbolRecords, err := s.index.GetSymbolsByFile(fileRecord.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get symbols: %w", err)
	}

	// Convert to symbol table format
	symbolTable := make(map[string]interface{})
	for _, record := range symbolRecords {
		symbolTable[record.FQN] = map[string]interface{}{
			"id":          record.SymbolID,
			"fqn":         record.FQN,
			"kind":        record.Kind,
			"start_pos":   record.StartPos,
			"end_pos":     record.EndPos,
			"visibility":  record.Visibility,
			"is_static":   record.IsStatic,
			"is_abstract": record.IsAbstract,
			"is_final":    record.IsFinal,
		}
	}

	return symbolTable, nil
}

// GetCFGForFile retrieves CFG for a file
func (s *IndexService) GetCFGForFile(ctx context.Context, filePath string) (*CFG, error) {
	// Get file record
	fileRecord, err := s.index.GetFileByPath(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not found in index: %w", err)
	}

	// Get symbols for this file
	symbolRecords, err := s.index.GetSymbolsByFile(fileRecord.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get symbols: %w", err)
	}

	// Try to load CFG from the first symbol (main function/class)
	if len(symbolRecords) > 0 {
		hirUnit, err := s.index.LoadHIRUnit(symbolRecords[0].SymbolID)
		if err != nil {
			return nil, fmt.Errorf("failed to load HIR unit: %w", err)
		}
		return hirUnit.CFG, nil
	}

	return nil, nil
}

// GetHIRFileForFile retrieves HIR file for a file
func (s *IndexService) GetHIRFileForFile(ctx context.Context, filePath string) (*HIRFile, error) {
	// This would reconstruct the HIR file from stored data
	// For now, return nil as this needs more implementation
	return nil, nil
}

// generateUniqueSymbolID creates a globally unique symbol ID by including the file path
func (s *IndexService) generateUniqueSymbolID(filePath, symbolName string) string {
	// Use the relative file path to make the ID shorter but still unique
	// Remove the file extension for cleaner IDs
	relPath := strings.TrimSuffix(filePath, ".php")
	relPath = strings.TrimPrefix(relPath, "./")
	relPath = strings.TrimPrefix(relPath, "../")

	// Replace path separators with double colons for better readability
	relPath = strings.ReplaceAll(relPath, "/", "::")
	relPath = strings.ReplaceAll(relPath, "\\", "::")

	// Create the unique ID: path::symbolName
	return fmt.Sprintf("%s::%s", relPath, symbolName)
}

// buildHIRFile builds HIR file from source code
func (s *IndexService) buildHIRFile(filePath string, content []byte, language string) (*HIRFile, error) {
	// Create a basic HIR file
	hirFile := &HIRFile{
		Path:     filePath,
		Language: language,
		Content:  string(content), // Store the source code content
		Symbols:  []*Symbol{},
	}

	// Build symbols based on language
	switch language {
	case "php":
		return s.buildPHPSymbols(hirFile, content)
	case "javascript", "typescript":
		return s.buildJSSymbols(hirFile, content)
	case "python":
		return s.buildPythonSymbols(hirFile, content)
	case "java":
		return s.buildJavaSymbols(hirFile, content)
	case "csharp":
		return s.buildCSharpSymbols(hirFile, content)
	case "go":
		return s.buildGoSymbols(hirFile, content)
	default:
		return hirFile, nil // Return empty HIR file for unsupported languages
	}
}

// buildHIRUnit builds HIR unit for a symbol
func (s *IndexService) buildHIRUnit(symbol *Symbol, hirFile *HIRFile) (*HIRUnit, error) {
	// Create basic HIR unit
	unit := &HIRUnit{
		Symbol: symbol,
		CFG:    nil, // CFG would be built here
	}

	// Build CFG for this symbol
	cfg, err := s.buildCFGForSymbol(symbol, hirFile)
	if err != nil {
		s.logger.Warn("Failed to build CFG for symbol",
			zap.String("symbol", string(symbol.ID)),
			zap.Error(err))
	} else {
		unit.CFG = cfg
	}

	return unit, nil
}

// buildCFGForSymbol builds CFG for a specific symbol
func (s *IndexService) buildCFGForSymbol(symbol *Symbol, hirFile *HIRFile) (*CFG, error) {
	// This would implement CFG building for the symbol
	// For now, return nil as this needs more implementation
	return nil, nil
}

// Language-specific symbol building methods

func (s *IndexService) buildPHPSymbols(hirFile *HIRFile, content []byte) (*HIRFile, error) {
	sourceCode := string(content)
	lines := strings.Split(sourceCode, "\n")

	// Parse functions
	s.parsePHPFunctions(lines, hirFile)

	// Parse classes and methods
	s.parsePHPClasses(lines, hirFile)

	s.logger.Debug("Parsed PHP file",
		zap.String("file", hirFile.Path),
		zap.Int("symbols", len(hirFile.Symbols)))

	return hirFile, nil
}

// parsePHPFunctions extracts function definitions using regex
func (s *IndexService) parsePHPFunctions(lines []string, hirFile *HIRFile) {
	funcPattern := regexp.MustCompile(`function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)

	for lineNum, line := range lines {
		matches := funcPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				funcName := match[1]
				uniqueID := s.generateUniqueSymbolID(hirFile.Path, funcName)

				symbol := &Symbol{
					ID:       SymbolID(uniqueID),
					FQN:      funcName, // Keep FQN as just the function name for display
					Kind:     SymbolKind(1), // Function kind
					Position: token.Pos(lineNum + 1),
					Span:     Span{Start: token.Pos(lineNum + 1), End: token.Pos(lineNum + 1)},
					Traits: SymbolTraits{
						Visibility: Visibility(1), // Public visibility
						IsStatic:   false,
					},
				}

				hirFile.Symbols = append(hirFile.Symbols, symbol)
			}
		}
	}
}

// parsePHPClasses extracts class definitions and methods
func (s *IndexService) parsePHPClasses(lines []string, hirFile *HIRFile) {
	classPattern := regexp.MustCompile(`class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:extends\s+([a-zA-Z_][a-zA-Z0-9_]*))?\s*(?:implements\s+([^{]+))?\s*`)
	methodPattern := regexp.MustCompile(`(?:public|private|protected)?\s*(?:static\s+)?function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)

	var currentClass string

	for lineNum, line := range lines {
		// Check for class definition
		classMatches := classPattern.FindAllStringSubmatch(line, -1)
		for _, match := range classMatches {
			if len(match) >= 2 {
				currentClass = match[1]
				uniqueClassID := s.generateUniqueSymbolID(hirFile.Path, currentClass)

				// Add class symbol
				classSymbol := &Symbol{
					ID:       SymbolID(uniqueClassID),
					FQN:      currentClass, // Keep FQN as just the class name for display
					Kind:     SymbolKind(5), // Class kind
					Position: token.Pos(lineNum + 1),
					Span:     Span{Start: token.Pos(lineNum + 1), End: token.Pos(lineNum + 1)},
					Traits: SymbolTraits{
						Visibility: Visibility(1), // Public visibility
						IsStatic:   false,
					},
				}

				hirFile.Symbols = append(hirFile.Symbols, classSymbol)
			}
		}

		// Check for method definition within class
		if currentClass != "" {
			methodMatches := methodPattern.FindAllStringSubmatch(line, -1)
			for _, match := range methodMatches {
				if len(match) >= 2 {
					methodName := match[1]
					fullName := currentClass + "::" + methodName
					uniqueMethodID := s.generateUniqueSymbolID(hirFile.Path, fullName)

					symbol := &Symbol{
						ID:       SymbolID(uniqueMethodID),
						FQN:      fullName, // Keep FQN as class::method for display
						Kind:     SymbolKind(6), // Method kind
						Position: token.Pos(lineNum + 1),
						Span:     Span{Start: token.Pos(lineNum + 1), End: token.Pos(lineNum + 1)},
						Traits: SymbolTraits{
							Visibility: Visibility(1), // Public visibility
							IsStatic:   false,
						},
					}

					hirFile.Symbols = append(hirFile.Symbols, symbol)
				}
			}
		}

		// Reset current class when we hit closing brace at start of line
		if strings.TrimSpace(line) == "}" && currentClass != "" {
			currentClass = ""
		}
	}
}

func (s *IndexService) buildJSSymbols(hirFile *HIRFile, content []byte) (*HIRFile, error) {
	// Basic JavaScript symbol extraction
	// This would use a proper JavaScript parser in a real implementation
	return hirFile, nil
}

func (s *IndexService) buildPythonSymbols(hirFile *HIRFile, content []byte) (*HIRFile, error) {
	// Basic Python symbol extraction
	// This would use a proper Python parser in a real implementation
	return hirFile, nil
}

func (s *IndexService) buildJavaSymbols(hirFile *HIRFile, content []byte) (*HIRFile, error) {
	// Basic Java symbol extraction
	// This would use a proper Java parser in a real implementation
	return hirFile, nil
}

func (s *IndexService) buildCSharpSymbols(hirFile *HIRFile, content []byte) (*HIRFile, error) {
	// Basic C# symbol extraction
	// This would use a proper C# parser in a real implementation
	return hirFile, nil
}

func (s *IndexService) buildGoSymbols(hirFile *HIRFile, content []byte) (*HIRFile, error) {
	// Basic Go symbol extraction
	// This would use a proper Go parser in a real implementation
	return hirFile, nil
}

// calculateFileHash calculates SHA256 hash of file content
func (s *IndexService) calculateFileHash(content []byte) string {
	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash)
}

// Close closes the index service
func (s *IndexService) Close() error {
	return s.index.Close()
}

// Vacuum optimizes the database
func (s *IndexService) Vacuum() error {
	return s.index.Vacuum()
}

// GetDatabaseSize returns the size of the database
func (s *IndexService) GetDatabaseSize() (int64, error) {
	return s.index.GetDatabaseSize()
}

// buildAndStoreCallGraph builds call graph for the file and stores call edges
func (s *IndexService) buildAndStoreCallGraph(hirFile *HIRFile, fileID int64) error {
	// Use the actual source code content
	sourceCode := hirFile.Content
	if sourceCode == "" {
		return nil // Skip if no source code available
	}

	// Parse function calls using regex
	callPattern := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*\(`)
	lines := strings.Split(sourceCode, "\n")

	// Create a map of available functions for quick lookup by function/method name
	availableFunctions := make(map[string]*Symbol)
	for _, symbol := range hirFile.Symbols {
		if symbol.Kind == SymbolKind(1) || symbol.Kind == SymbolKind(6) { // Function or Method
			// Extract the function name from FQN for lookup
			// For functions: FQN is just the function name
			// For methods: FQN is "ClassName::methodName"
			var functionName string
			if strings.Contains(symbol.FQN, "::") {
				// Method: extract just the method name
				parts := strings.Split(symbol.FQN, "::")
				functionName = parts[len(parts)-1]
			} else {
				// Function: use the full FQN
				functionName = symbol.FQN
			}
			availableFunctions[functionName] = symbol
		}
	}

	// Find function calls and create edges
	edgeCount := 0
	for lineNum, line := range lines {
		matches := callPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				funcName := match[1]

				// Skip language constructs
				if s.isPHPLanguageConstruct(funcName) {
					continue
				}

				// Check if this is a call to one of our functions
				if callee, exists := availableFunctions[funcName]; exists {
					// Find the caller (function containing this line)
					caller := s.findContainingFunction(lineNum+1, hirFile.Symbols)
					if caller != nil && caller.ID != callee.ID {
						// Create and store call edge
						edge := &CallEdge{
							Caller:   &CallNode{Symbol: caller},
							Callee:   &CallNode{Symbol: callee},
							IsDirect: true,
							Context:  fmt.Sprintf("line %d: %s", lineNum+1, strings.TrimSpace(line)),
						}

						// Store the call edge in database
						if err := s.index.StoreCallEdge(edge, fileID, int64(lineNum+1)); err != nil {
							s.logger.Warn("Failed to store call edge",
								zap.String("caller", string(caller.ID)),
								zap.String("callee", string(callee.ID)),
								zap.Error(err))
						} else {
							s.logger.Debug("Stored call edge",
								zap.String("caller", string(caller.ID)),
								zap.String("callee", string(callee.ID)),
								zap.Int("line", lineNum+1))
							edgeCount++
						}

						// Also store symbol reference for the function call
						matchStart := strings.Index(line, funcName)
						if matchStart >= 0 {
							refStart := int64(matchStart)
							refEnd := int64(matchStart + len(funcName))
							context := fmt.Sprintf("function call at line %d", lineNum+1)

							if err := s.index.StoreSymbolReference(fileID, refStart, refEnd, string(callee.ID), RefCall, context); err != nil {
								s.logger.Debug("Failed to store symbol reference",
									zap.String("symbol", string(callee.ID)),
									zap.Error(err))
							}
						}
					}
				}
			}
		}
	}

	s.logger.Debug("Built and stored call graph",
		zap.String("file", hirFile.Path),
		zap.Int("edges", edgeCount))

	return nil
}

// findContainingFunction finds which function contains the given line
func (s *IndexService) findContainingFunction(line int, symbols []*Symbol) *Symbol {
	// Simple heuristic: find the closest function before this line
	var bestMatch *Symbol
	for _, symbol := range symbols {
		if symbol.Kind == SymbolKind(1) || symbol.Kind == SymbolKind(6) { // Function or Method
			symbolLine := int(symbol.Position)
			if symbolLine <= line {
				if bestMatch == nil || symbolLine > int(bestMatch.Position) {
					bestMatch = symbol
				}
			}
		}
	}
	return bestMatch
}

// isPHPLanguageConstruct checks if a function name is a language construct
func (s *IndexService) isPHPLanguageConstruct(name string) bool {
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
		"echo":     true,
		"print":    true,
		"isset":    true,
		"empty":    true,
		"unset":    true,
	}

	return constructs[strings.ToLower(name)]
}

// GetIndex returns the workspace index
func (s *IndexService) GetIndex() *WorkspaceIndex {
	return s.index
}
