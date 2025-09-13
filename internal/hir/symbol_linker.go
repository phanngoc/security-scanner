package hir

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SymbolLinker resolves cross-file symbol references
type SymbolLinker struct {
	program     *HIRProgram
	resolver    *NameResolver
	callGraph   *CallGraphBuilder
	includeGraph *IncludeGraphBuilder
}

// NewSymbolLinker creates a new symbol linker
func NewSymbolLinker(program *HIRProgram) *SymbolLinker {
	return &SymbolLinker{
		program:      program,
		resolver:     NewNameResolver(program),
		callGraph:    NewCallGraphBuilder(program),
		includeGraph: NewIncludeGraphBuilder(program),
	}
}

// LinkSymbols performs symbol resolution and linking across files
func (sl *SymbolLinker) LinkSymbols() error {
	// Step 1: Resolve use/import statements
	if err := sl.resolver.ResolveUseStatements(); err != nil {
		return fmt.Errorf("failed to resolve use statements: %w", err)
	}

	// Step 2: Resolve class inheritance (extends/implements)
	if err := sl.resolver.ResolveInheritance(); err != nil {
		return fmt.Errorf("failed to resolve inheritance: %w", err)
	}

	// Step 3: Build call graph
	if err := sl.callGraph.BuildCallGraph(); err != nil {
		return fmt.Errorf("failed to build call graph: %w", err)
	}

	// Step 4: Build include graph
	if err := sl.includeGraph.BuildIncludeGraph(); err != nil {
		return fmt.Errorf("failed to build include graph: %w", err)
	}

	// Step 5: Resolve function/method calls
	if err := sl.resolver.ResolveFunctionCalls(); err != nil {
		return fmt.Errorf("failed to resolve function calls: %w", err)
	}

	// Step 6: Build dependency graph
	if err := sl.buildDependencyGraph(); err != nil {
		return fmt.Errorf("failed to build dependency graph: %w", err)
	}

	return nil
}

// buildDependencyGraph builds file dependency graph for incremental analysis
func (sl *SymbolLinker) buildDependencyGraph() error {
	// Create dependency graph based on:
	// 1. Include/require statements
	// 2. Class references (extends/implements/use)
	// 3. Function calls

	depGraph := NewDependencyGraph()

	for filePath, file := range sl.program.Files {
		node := &DependencyNode{
			File:         filePath,
			Dependencies: make([]string, 0),
			Dependents:   make([]string, 0),
		}

		// Add include dependencies
		for _, include := range file.Includes {
			if include.IsStatic && include.Path != "" {
				resolved := sl.resolveIncludePath(include.Path, filePath)
				if resolved != "" {
					node.Dependencies = append(node.Dependencies, resolved)
					depGraph.AddDependency(filePath, resolved)
				}
			}
		}

		// Add class reference dependencies
		for _, symbol := range file.Symbols {
			if symbol.Kind == SymClass {
				// Find file containing extended/implemented classes
				deps := sl.findClassDependencies(symbol)
				for _, dep := range deps {
					if dep != filePath {
						node.Dependencies = append(node.Dependencies, dep)
						depGraph.AddDependency(filePath, dep)
					}
				}
			}
		}

		depGraph.Nodes[filePath] = node
	}

	sl.program.DependencyGraph = depGraph
	return nil
}

// NameResolver handles name resolution across files
type NameResolver struct {
	program *HIRProgram
}

// NewNameResolver creates a new name resolver
func NewNameResolver(program *HIRProgram) *NameResolver {
	return &NameResolver{program: program}
}

// ResolveUseStatements resolves use/import statements
func (nr *NameResolver) ResolveUseStatements() error {
	for _, file := range nr.program.Files {
		namespace := nr.extractNamespace(file)

		// Process use bindings for this file
		for key, binding := range nr.program.Symbols.Uses {
			if strings.HasPrefix(key, file.Path+"::") {
				// Resolve FQN
				fqn := nr.resolveFQN(binding.FQN, namespace)
				binding.FQN = fqn

				// Add to namespace context
				if ns, exists := nr.program.Symbols.Namespaces[namespace]; exists {
					ns.Uses[binding.Alias] = fqn
				} else {
					ns := &Namespace{
						FQN:     namespace,
						Symbols: make(map[string]*Symbol),
						Uses:    make(map[string]string),
					}
					ns.Uses[binding.Alias] = fqn
					nr.program.Symbols.Namespaces[namespace] = ns
				}
			}
		}
	}
	return nil
}

// ResolveInheritance resolves class inheritance relationships
func (nr *NameResolver) ResolveInheritance() error {
	classes := nr.program.Symbols.GetSymbolsByKind(SymClass)

	for _, class := range classes {
		// Resolve extends and implements references
		if classSymbol, ok := class.Meta["inheritance"]; ok {
			if inheritance, ok := classSymbol.(ClassInheritance); ok {
				// Resolve parent class
				if inheritance.Extends != "" {
					parentFQN := nr.resolveClassName(inheritance.Extends, class.File)
					inheritance.Extends = parentFQN
				}

				// Resolve implemented interfaces
				for i, iface := range inheritance.Implements {
					ifaceFQN := nr.resolveClassName(iface, class.File)
					inheritance.Implements[i] = ifaceFQN
				}

				class.Meta["inheritance"] = inheritance
			}
		}
	}
	return nil
}

// ResolveFunctionCalls resolves function and method calls
func (nr *NameResolver) ResolveFunctionCalls() error {
	for _, file := range nr.program.Files {
		for _, unit := range file.Units {
			if unit.Body != nil {
				nr.resolveFunctionCallsInBlock(unit.Body, file.Path)
			}
		}
	}
	return nil
}

// resolveFunctionCallsInBlock resolves function calls in a HIR block
func (nr *NameResolver) resolveFunctionCallsInBlock(block *HIRBlock, filePath string) {
	for _, stmt := range block.Stmts {
		if stmt.Type == HIRCall {
			if funcName, ok := stmt.Meta["function"].(string); ok {
				resolvedFQN := nr.resolveFunctionName(funcName, filePath)
				stmt.Meta["resolved_function"] = resolvedFQN
			} else if methodName, ok := stmt.Meta["method"].(string); ok {
				// Method resolution requires type information
				// This is simplified - full implementation would track object types
				stmt.Meta["resolved_method"] = methodName
			}
		}
	}
}

// ClassInheritance represents class inheritance information
type ClassInheritance struct {
	Extends    string
	Implements []string
	Traits     []string
}

// CallGraphBuilder builds function call graphs
type CallGraphBuilder struct {
	program *HIRProgram
}

// NewCallGraphBuilder creates a new call graph builder
func NewCallGraphBuilder(program *HIRProgram) *CallGraphBuilder {
	return &CallGraphBuilder{program: program}
}

// BuildCallGraph builds the global call graph
func (cgb *CallGraphBuilder) BuildCallGraph() error {
	callGraph := cgb.program.CallGraph

	// Create nodes for all functions and methods
	functions := cgb.program.Symbols.GetSymbolsByKind(SymFunction)
	methods := cgb.program.Symbols.GetSymbolsByKind(SymMethod)

	for _, function := range functions {
		node := &CallNode{
			Symbol:  function,
			Callers: make([]*CallEdge, 0),
			Callees: make([]*CallEdge, 0),
		}
		callGraph.Nodes[function.ID] = node
	}

	for _, method := range methods {
		node := &CallNode{
			Symbol:  method,
			Callers: make([]*CallEdge, 0),
			Callees: make([]*CallEdge, 0),
		}
		callGraph.Nodes[method.ID] = node
	}

	// Find call relationships
	for _, file := range cgb.program.Files {
		for _, unit := range file.Units {
			if unit.Body != nil {
				cgb.findCallsInBlock(unit.Body, unit.Symbol, callGraph)
			}
		}
	}

	return nil
}

// findCallsInBlock finds function calls in a HIR block
func (cgb *CallGraphBuilder) findCallsInBlock(block *HIRBlock, caller *Symbol, callGraph *CallGraph) {
	for _, stmt := range block.Stmts {
		if stmt.Type == HIRCall {
			var calleeFQN string
			isDirect := true

			if resolvedFunc, ok := stmt.Meta["resolved_function"].(string); ok {
				calleeFQN = resolvedFunc
			} else if funcName, ok := stmt.Meta["function"].(string); ok {
				calleeFQN = funcName
				isDirect = false // Unresolved call
			}

			if calleeFQN != "" {
				// Find callee symbol
				calleeID := SymbolID(calleeFQN)
				if calleeNode, exists := callGraph.Nodes[calleeID]; exists {
					callerNode := callGraph.Nodes[caller.ID]

					// Create call edge
					edge := &CallEdge{
						Caller:   callerNode,
						Callee:   calleeNode,
						CallSite: stmt.Position,
						IsDirect: isDirect,
						Context:  "direct_call",
					}

					callGraph.Edges = append(callGraph.Edges, edge)
					callerNode.Callees = append(callerNode.Callees, edge)
					calleeNode.Callers = append(calleeNode.Callers, edge)
				}
			}
		}
	}
}

// IncludeGraphBuilder builds include/require graphs
type IncludeGraphBuilder struct {
	program *HIRProgram
}

// NewIncludeGraphBuilder creates a new include graph builder
func NewIncludeGraphBuilder(program *HIRProgram) *IncludeGraphBuilder {
	return &IncludeGraphBuilder{program: program}
}

// BuildIncludeGraph builds the include dependency graph
func (igb *IncludeGraphBuilder) BuildIncludeGraph() error {
	includeGraph := NewIncludeGraph()

	for filePath, file := range igb.program.Files {
		node := &IncludeNode{
			File:     filePath,
			Includes: make([]string, 0),
			IncludedBy: make([]string, 0),
		}

		// Process include statements
		for _, unit := range file.Units {
			if unit.Body != nil {
				includes := igb.findIncludesInBlock(unit.Body, filePath)
				node.Includes = append(node.Includes, includes...)
			}
		}

		includeGraph.Nodes[filePath] = node
	}

	// Build reverse relationships
	for filePath, node := range includeGraph.Nodes {
		for _, includedFile := range node.Includes {
			if includedNode, exists := includeGraph.Nodes[includedFile]; exists {
				includedNode.IncludedBy = append(includedNode.IncludedBy, filePath)
			}
		}
	}

	igb.program.IncludeGraph = includeGraph
	return nil
}

// findIncludesInBlock finds include statements in a HIR block
func (igb *IncludeGraphBuilder) findIncludesInBlock(block *HIRBlock, currentFile string) []string {
	includes := make([]string, 0)

	for _, stmt := range block.Stmts {
		if stmt.Type == HIRInclude {
			// Try to resolve include path
			if includePath, ok := stmt.Meta["path"].(string); ok {
				resolved := igb.resolveIncludePath(includePath, currentFile)
				if resolved != "" {
					includes = append(includes, resolved)
				}
			}
		}
	}

	return includes
}

// resolveIncludePath resolves relative include paths
func (igb *IncludeGraphBuilder) resolveIncludePath(includePath, currentFile string) string {
	// Handle absolute paths
	if filepath.IsAbs(includePath) {
		return includePath
	}

	// Handle relative paths
	currentDir := filepath.Dir(currentFile)
	resolved := filepath.Join(currentDir, includePath)
	resolved = filepath.Clean(resolved)

	// Check if file exists in our program
	if _, exists := igb.program.Files[resolved]; exists {
		return resolved
	}

	return ""
}

// DependencyGraph represents file dependencies
type DependencyGraph struct {
	Nodes map[string]*DependencyNode
}

// DependencyNode represents a file and its dependencies
type DependencyNode struct {
	File         string
	Dependencies []string // Files this file depends on
	Dependents   []string // Files that depend on this file
}

// NewDependencyGraph creates a new dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Nodes: make(map[string]*DependencyNode),
	}
}

// AddDependency adds a dependency relationship
func (dg *DependencyGraph) AddDependency(from, to string) {
	if fromNode, exists := dg.Nodes[from]; exists {
		fromNode.Dependencies = append(fromNode.Dependencies, to)
	}

	if toNode, exists := dg.Nodes[to]; exists {
		toNode.Dependents = append(toNode.Dependents, from)
	}
}

// GetAffectedFiles returns files affected by changes to the given file
func (dg *DependencyGraph) GetAffectedFiles(changedFile string, maxDepth int) []string {
	affected := make(map[string]bool)
	visited := make(map[string]bool)

	var dfs func(file string, depth int)
	dfs = func(file string, depth int) {
		if depth > maxDepth || visited[file] {
			return
		}

		visited[file] = true
		affected[file] = true

		if node, exists := dg.Nodes[file]; exists {
			for _, dependent := range node.Dependents {
				dfs(dependent, depth+1)
			}
		}
	}

	dfs(changedFile, 0)

	result := make([]string, 0, len(affected))
	for file := range affected {
		result = append(result, file)
	}

	return result
}

// IncludeGraph represents include relationships
type IncludeGraph struct {
	Nodes map[string]*IncludeNode
}

// IncludeNode represents a file in the include graph
type IncludeNode struct {
	File       string
	Includes   []string // Files included by this file
	IncludedBy []string // Files that include this file
}

// NewIncludeGraph creates a new include graph
func NewIncludeGraph() *IncludeGraph {
	return &IncludeGraph{
		Nodes: make(map[string]*IncludeNode),
	}
}

// Helper methods for name resolution

func (nr *NameResolver) extractNamespace(file *HIRFile) string {
	// Extract namespace from file symbols or path
	// This is simplified - real implementation would parse namespace declarations
	return "\\"
}

func (nr *NameResolver) resolveFQN(name, namespace string) string {
	if strings.HasPrefix(name, "\\") {
		return name // Already FQN
	}
	return namespace + name
}

func (nr *NameResolver) resolveClassName(className, filePath string) string {
	// Check use statements for this file
	fileKey := filePath + "::" + className
	if binding, exists := nr.program.Symbols.Uses[fileKey]; exists {
		return binding.FQN
	}

	// Default to current namespace + class name
	namespace := nr.extractNamespace(nr.program.Files[filePath])
	return nr.resolveFQN(className, namespace)
}

func (nr *NameResolver) resolveFunctionName(funcName, filePath string) string {
	// Check if it's already FQN
	if strings.HasPrefix(funcName, "\\") {
		return funcName
	}

	// Check use statements
	fileKey := filePath + "::" + funcName
	if binding, exists := nr.program.Symbols.Uses[fileKey]; exists {
		return binding.FQN
	}

	// Check if function exists in global scope
	globalFQN := "\\" + funcName
	if nr.program.Symbols.GetSymbol(SymbolID(globalFQN)) != nil {
		return globalFQN
	}

	// Default to current namespace
	namespace := nr.extractNamespace(nr.program.Files[filePath])
	return nr.resolveFQN(funcName, namespace)
}

func (sl *SymbolLinker) resolveIncludePath(includePath, currentFile string) string {
	return sl.includeGraph.resolveIncludePath(includePath, currentFile)
}

func (sl *SymbolLinker) findClassDependencies(symbol *Symbol) []string {
	deps := make([]string, 0)

	if inheritance, ok := symbol.Meta["inheritance"].(ClassInheritance); ok {
		// Find files containing extended class
		if inheritance.Extends != "" {
			if parentSymbol := sl.program.Symbols.GetSymbol(SymbolID(inheritance.Extends)); parentSymbol != nil {
				deps = append(deps, parentSymbol.File)
			}
		}

		// Find files containing implemented interfaces
		for _, iface := range inheritance.Implements {
			if ifaceSymbol := sl.program.Symbols.GetSymbol(SymbolID(iface)); ifaceSymbol != nil {
				deps = append(deps, ifaceSymbol.File)
			}
		}
	}

	return deps
}

// Add these to HIRProgram if not already present
func (hp *HIRProgram) GetDependencyGraph() *DependencyGraph {
	if hp.DependencyGraph == nil {
		hp.DependencyGraph = NewDependencyGraph()
	}
	return hp.DependencyGraph
}

func (hp *HIRProgram) GetIncludeGraph() *IncludeGraph {
	if hp.IncludeGraph == nil {
		hp.IncludeGraph = NewIncludeGraph()
	}
	return hp.IncludeGraph
}

// Add these fields to HIRProgram struct if needed
type HIRProgramExtended struct {
	*HIRProgram
	DependencyGraph *DependencyGraph
	IncludeGraph    *IncludeGraph
}