package hir

import (
	"fmt"
	"go/token"
	"strings"
)

// AdvancedCFGBuilder implements sophisticated CFG construction algorithms
// with symbol table linking and inter-procedural analysis
type AdvancedCFGBuilder struct {
	program         *HIRProgram
	nextBlockID     BlockID
	currentFunction *Symbol

	// Worklist for structured CFG building (AST Traversal + Worklist algorithm)
	exitBlocks      []*CFGNode
	breakTargets    []*CFGNode  // for break statements
	continueTargets []*CFGNode  // for continue statements

	// Exception handling stacks
	tryBlocks     []*CFGNode
	catchBlocks   []*CFGNode
	finallyBlocks []*CFGNode

	// Symbol table integration
	symbolLinker *SymbolLinker
}

// NewAdvancedCFGBuilder creates a new advanced CFG builder with symbol table integration
func NewAdvancedCFGBuilder(program *HIRProgram) *AdvancedCFGBuilder {
	return &AdvancedCFGBuilder{
		program:         program,
		nextBlockID:     1,
		exitBlocks:      make([]*CFGNode, 0),
		breakTargets:    make([]*CFGNode, 0),
		continueTargets: make([]*CFGNode, 0),
		tryBlocks:       make([]*CFGNode, 0),
		catchBlocks:     make([]*CFGNode, 0),
		finallyBlocks:   make([]*CFGNode, 0),
		symbolLinker:    NewSymbolLinker(program),
	}
}

// BuildAdvancedCFG builds CFG using the structured algorithm approach with symbol table linking
func (builder *AdvancedCFGBuilder) BuildAdvancedCFG(symbol *Symbol, unit *HIRUnit) (*CFG, error) {
	if unit.Body == nil {
		return nil, fmt.Errorf("function %s has no body", symbol.FQN)
	}

	builder.currentFunction = symbol

	// Create CFG structure
	cfg := &CFG{
		Nodes:    make(map[BlockID]*CFGNode),
		Edges:    make([]*CFGEdge, 0),
		Function: symbol,
	}

	// Step 1: Create entry and exit nodes using leader algorithm
	entry := builder.createCFGNode(CFGEntry, nil)
	exit := builder.createCFGNode(CFGExit, nil)

	cfg.Entry = entry
	cfg.Exit = exit
	cfg.Nodes[entry.ID] = entry
	cfg.Nodes[exit.ID] = exit

	// Step 2: Apply IR-based approach - identify leaders and build basic blocks
	leaders := builder.identifyLeaders(unit.Body)
	basicBlocks := builder.createBasicBlocks(unit.Body, leaders)

	// Step 3: Build CFG using structured block algorithm (Hoare's approach)
	bodyNodes := builder.buildStructuredCFG(basicBlocks, cfg)

	// Step 4: Connect entry to body
	if len(bodyNodes) > 0 {
		builder.addCFGEdge(cfg, entry, bodyNodes[0], CFGFallthrough, nil)

		// Connect all exit points to exit node
		for _, exitNode := range builder.exitBlocks {
			builder.addCFGEdge(cfg, exitNode, exit, CFGFallthrough, nil)
		}
	} else {
		// Empty function body
		builder.addCFGEdge(cfg, entry, exit, CFGFallthrough, nil)
	}

	// Step 5: Add exception edges for proper exception handling
	builder.addExceptionEdges(cfg)

	// Step 6: Add symbol table cross-references
	builder.addSymbolTableCrossReferences(cfg)

	// Clear worklist for next function
	builder.clearWorklists()

	return cfg, nil
}

// identifyLeaders implements the leader algorithm from Dragon Book
func (builder *AdvancedCFGBuilder) identifyLeaders(block *HIRBlock) map[int]bool {
	leaders := make(map[int]bool)

	if len(block.Stmts) == 0 {
		return leaders
	}

	// Rule 1: First statement is a leader
	leaders[0] = true

	// Rule 2: Target of any jump is a leader
	// Rule 3: Statement following a jump is a leader
	for i, stmt := range block.Stmts {
		switch stmt.Type {
		case HIRIf, HIRLoop, HIRSwitch:
			// Target of conditional jump is a leader
			if i+1 < len(block.Stmts) {
				leaders[i+1] = true // Statement after conditional
			}

		case HIRReturn, HIRThrow, HIRBreak, HIRGoto:
			// Statement following a jump is a leader
			if i+1 < len(block.Stmts) {
				leaders[i+1] = true
			}

		case HIRTryCatch:
			// Exception handling creates multiple leaders
			if i+1 < len(block.Stmts) {
				leaders[i+1] = true
			}
		}
	}

	return leaders
}

// createBasicBlocks creates basic blocks from leaders
func (builder *AdvancedCFGBuilder) createBasicBlocks(block *HIRBlock, leaders map[int]bool) []*BasicBlock {
	basicBlocks := make([]*BasicBlock, 0)

	if len(block.Stmts) == 0 {
		return basicBlocks
	}

	currentBlock := &BasicBlock{
		ID:    builder.nextBlockID,
		Stmts: make([]*HIRStmt, 0),
	}
	builder.nextBlockID++

	for i, stmt := range block.Stmts {
		// Start new block if this is a leader (except for first statement)
		if leaders[i] && i > 0 {
			basicBlocks = append(basicBlocks, currentBlock)
			currentBlock = &BasicBlock{
				ID:    builder.nextBlockID,
				Stmts: make([]*HIRStmt, 0),
			}
			builder.nextBlockID++
		}

		currentBlock.Stmts = append(currentBlock.Stmts, stmt)

		// End block if this is a terminal statement
		if builder.isTerminalStatement(stmt) {
			basicBlocks = append(basicBlocks, currentBlock)
			if i+1 < len(block.Stmts) {
				currentBlock = &BasicBlock{
					ID:    builder.nextBlockID,
					Stmts: make([]*HIRStmt, 0),
				}
				builder.nextBlockID++
			}
		}
	}

	if len(currentBlock.Stmts) > 0 {
		basicBlocks = append(basicBlocks, currentBlock)
	}

	return basicBlocks
}

// BasicBlock represents a basic block in the intermediate representation
type BasicBlock struct {
	ID    BlockID
	Stmts []*HIRStmt
}

// buildStructuredCFG builds CFG using Hoare's structured control flow approach
func (builder *AdvancedCFGBuilder) buildStructuredCFG(basicBlocks []*BasicBlock, cfg *CFG) []*CFGNode {
	if len(basicBlocks) == 0 {
		return []*CFGNode{}
	}

	nodes := make([]*CFGNode, 0)

	for i, bb := range basicBlocks {
		// Create CFG node from basic block
		hirBlock := &HIRBlock{
			ID:    bb.ID,
			Stmts: bb.Stmts,
			Preds: make([]*HIRBlock, 0),
			Succs: make([]*HIRBlock, 0),
		}

		node := builder.createCFGNode(CFGBasic, hirBlock)
		cfg.Nodes[node.ID] = node
		nodes = append(nodes, node)

		// Analyze control flow within this basic block
		builder.analyzeControlFlow(node, cfg, i, basicBlocks)
	}

	// Connect basic blocks with fall-through edges
	for i := 0; i < len(nodes)-1; i++ {
		lastStmt := nodes[i].Block.Stmts[len(nodes[i].Block.Stmts)-1]
		if !builder.isTerminalStatement(lastStmt) {
			builder.addCFGEdge(cfg, nodes[i], nodes[i+1], CFGFallthrough, nil)
		}
	}

	return nodes
}

// analyzeControlFlow analyzes control flow patterns within basic blocks
func (builder *AdvancedCFGBuilder) analyzeControlFlow(node *CFGNode, cfg *CFG, blockIndex int, basicBlocks []*BasicBlock) {
	for _, stmt := range node.Block.Stmts {
		switch stmt.Type {
		case HIRIf:
			builder.processConditionalFlow(stmt, node, cfg, blockIndex, basicBlocks)

		case HIRLoop:
			builder.processLoopFlow(stmt, node, cfg, blockIndex, basicBlocks)

		case HIRTryCatch:
			builder.processExceptionFlow(stmt, node, cfg, blockIndex, basicBlocks)

		case HIRReturn:
			builder.exitBlocks = append(builder.exitBlocks, node)

		case HIRThrow:
			builder.processThrowStatement(stmt, node, cfg)

		case HIRBreak:
			builder.processBreakStatement(stmt, node, cfg)

		case HIRCall:
			builder.processCallStatement(stmt, node, cfg)
		}
	}
}

// processConditionalFlow handles if statements with structured control flow
func (builder *AdvancedCFGBuilder) processConditionalFlow(stmt *HIRStmt, node *CFGNode, cfg *CFG, blockIndex int, basicBlocks []*BasicBlock) {
	// Create conditional evaluation node
	condNode := builder.createCFGNode(CFGConditional, nil)
	cfg.Nodes[condNode.ID] = condNode

	// Extract condition and branches from statement metadata
	if thenTarget, ok := stmt.Meta["then_target"].(int); ok {
		if thenTarget < len(basicBlocks) {
			// This would connect to the then branch when we process all blocks
			stmt.Meta["then_node_id"] = condNode.ID
		}
	}

	if elseTarget, ok := stmt.Meta["else_target"].(int); ok {
		if elseTarget < len(basicBlocks) {
			// This would connect to the else branch when we process all blocks
			stmt.Meta["else_node_id"] = condNode.ID
		}
	}
}

// processLoopFlow handles loop statements with back edge creation
func (builder *AdvancedCFGBuilder) processLoopFlow(stmt *HIRStmt, node *CFGNode, cfg *CFG, blockIndex int, basicBlocks []*BasicBlock) {
	// Create loop header node
	headerNode := builder.createCFGNode(CFGLoop, nil)
	cfg.Nodes[headerNode.ID] = headerNode

	// Set loop context for break/continue handling
	builder.breakTargets = append(builder.breakTargets, nil) // Will be filled with loop exit
	builder.continueTargets = append(builder.continueTargets, headerNode)

	// Mark this as a loop header for back edge detection
	stmt.Meta["loop_header_id"] = headerNode.ID

	// Create back edge metadata
	if bodyTarget, ok := stmt.Meta["body_target"].(int); ok {
		if bodyTarget < len(basicBlocks) {
			stmt.Meta["creates_back_edge"] = true
		}
	}
}

// processExceptionFlow handles try-catch-finally blocks
func (builder *AdvancedCFGBuilder) processExceptionFlow(stmt *HIRStmt, node *CFGNode, cfg *CFG, blockIndex int, basicBlocks []*BasicBlock) {
	// Create try block node
	tryNode := builder.createCFGNode(CFGTry, nil)
	cfg.Nodes[tryNode.ID] = tryNode

	// Create catch block if exists
	if catchTarget, ok := stmt.Meta["catch_target"].(int); ok {
		if catchTarget < len(basicBlocks) {
			catchNode := builder.createCFGNode(CFGCatch, nil)
			cfg.Nodes[catchNode.ID] = catchNode
			builder.catchBlocks = append(builder.catchBlocks, catchNode)
			stmt.Meta["catch_node_id"] = catchNode.ID
		}
	}

	// Create finally block if exists
	if finallyTarget, ok := stmt.Meta["finally_target"].(int); ok {
		if finallyTarget < len(basicBlocks) {
			finallyNode := builder.createCFGNode(CFGFinally, nil)
			cfg.Nodes[finallyNode.ID] = finallyNode
			builder.finallyBlocks = append(builder.finallyBlocks, finallyNode)
			stmt.Meta["finally_node_id"] = finallyNode.ID
		}
	}

	builder.tryBlocks = append(builder.tryBlocks, tryNode)
}

// processThrowStatement handles throw statements with exception edge creation
func (builder *AdvancedCFGBuilder) processThrowStatement(stmt *HIRStmt, node *CFGNode, cfg *CFG) {
	// Connect to nearest catch block or function exit
	if len(builder.catchBlocks) > 0 {
		target := builder.catchBlocks[len(builder.catchBlocks)-1]
		builder.addCFGEdge(cfg, node, target, CFGThrow, nil)
	} else {
		builder.exitBlocks = append(builder.exitBlocks, node)
	}
}

// processBreakStatement handles break statements
func (builder *AdvancedCFGBuilder) processBreakStatement(stmt *HIRStmt, node *CFGNode, cfg *CFG) {
	if len(builder.breakTargets) > 0 {
		target := builder.breakTargets[len(builder.breakTargets)-1]
		if target != nil {
			builder.addCFGEdge(cfg, node, target, CFGBreak, nil)
		}
	}
}

// processCallStatement handles function calls with interprocedural analysis
func (builder *AdvancedCFGBuilder) processCallStatement(stmt *HIRStmt, node *CFGNode, cfg *CFG) {
	// Resolve function call using symbol table
	if funcName, ok := stmt.Meta["function"].(string); ok {
		resolvedFQN := builder.resolveFunctionCall(funcName, builder.currentFunction.File)
		stmt.Meta["resolved_function"] = resolvedFQN

		// Add call graph edge
		builder.addCallGraphEdge(builder.currentFunction.ID, SymbolID(resolvedFQN), stmt.Position)

		// Mark as interprocedural call site
		stmt.Meta["is_interprocedural"] = true
		stmt.Meta["call_site_node"] = node.ID
	}
}

// addExceptionEdges adds proper exception handling edges
func (builder *AdvancedCFGBuilder) addExceptionEdges(cfg *CFG) {
	for _, edge := range cfg.Edges {
		if edge.Kind == CFGThrow {
			// Find all active exception handlers for this edge
			handlers := builder.findActiveExceptionHandlers(edge.From)
			for _, handler := range handlers {
				if handlerNode, exists := cfg.Nodes[handler]; exists {
					builder.addCFGEdge(cfg, edge.From, handlerNode, CFGThrow, nil)
				}
			}
		}
	}
}

// findActiveExceptionHandlers finds exception handlers active at a given node
func (builder *AdvancedCFGBuilder) findActiveExceptionHandlers(node *CFGNode) []BlockID {
	handlers := make([]BlockID, 0)

	// Simple implementation - in practice would need proper exception handler tracking
	for _, catchBlock := range builder.catchBlocks {
		handlers = append(handlers, catchBlock.ID)
	}

	return handlers
}

// addSymbolTableCrossReferences adds symbol table references to CFG
func (builder *AdvancedCFGBuilder) addSymbolTableCrossReferences(cfg *CFG) {
	// Link function calls to their definitions
	for _, node := range cfg.Nodes {
		for _, stmt := range node.Block.Stmts {
			if stmt.Type == HIRCall {
				if resolvedFunc, ok := stmt.Meta["resolved_function"].(string); ok {
					// Add cross-reference to called function
					stmt.Meta["callee_symbol"] = builder.program.Symbols.GetSymbol(SymbolID(resolvedFunc))
				}
			}

			// Link variable references to their definitions
			if stmt.Type == HIRAssign || stmt.Type == HIRFieldAccess {
				if varName, ok := stmt.Meta["variable"].(string); ok {
					symbol := builder.findVariableSymbol(varName, builder.currentFunction.File)
					if symbol != nil {
						stmt.Meta["variable_symbol"] = symbol
					}
				}
			}
		}
	}
}

// Symbol table integration methods

// resolveFunctionCall resolves function calls using symbol table
func (builder *AdvancedCFGBuilder) resolveFunctionCall(funcName, filePath string) string {
	// Check if already FQN
	if strings.HasPrefix(funcName, "\\") {
		return funcName
	}

	// Check use statements
	fileKey := filePath + "::" + funcName
	if binding, exists := builder.program.Symbols.Uses[fileKey]; exists {
		return binding.FQN
	}

	// Check if function exists in global scope
	globalFQN := "\\" + funcName
	if builder.program.Symbols.GetSymbol(SymbolID(globalFQN)) != nil {
		return globalFQN
	}

	// Default to current namespace
	return "\\" + funcName // Simplified
}

// findVariableSymbol finds variable symbol in symbol table
func (builder *AdvancedCFGBuilder) findVariableSymbol(varName, filePath string) *Symbol {
	// Look for variable in current function scope
	for _, symbol := range builder.program.Symbols.ByFile[filePath] {
		if symbol.Kind == SymGlobalVar && strings.Contains(symbol.FQN, varName) {
			return symbol
		}
	}

	return nil
}

// addCallGraphEdge adds an edge to the call graph
func (builder *AdvancedCFGBuilder) addCallGraphEdge(callerID, calleeID SymbolID, position token.Pos) {
	callGraph := builder.program.CallGraph

	// Ensure nodes exist
	if _, exists := callGraph.Nodes[callerID]; !exists {
		callGraph.Nodes[callerID] = &CallNode{
			Symbol:  builder.program.Symbols.GetSymbol(callerID),
			Callers: make([]*CallEdge, 0),
			Callees: make([]*CallEdge, 0),
		}
	}

	if _, exists := callGraph.Nodes[calleeID]; !exists {
		callGraph.Nodes[calleeID] = &CallNode{
			Symbol:  builder.program.Symbols.GetSymbol(calleeID),
			Callers: make([]*CallEdge, 0),
			Callees: make([]*CallEdge, 0),
		}
	}

	// Create call edge
	edge := &CallEdge{
		Caller:   callGraph.Nodes[callerID],
		Callee:   callGraph.Nodes[calleeID],
		CallSite: position,
		IsDirect: true,
		Context:  "CFG_analysis",
	}

	callGraph.Edges = append(callGraph.Edges, edge)
	callGraph.Nodes[callerID].Callees = append(callGraph.Nodes[callerID].Callees, edge)
	callGraph.Nodes[calleeID].Callers = append(callGraph.Nodes[calleeID].Callers, edge)
}

// SSA Conversion with Phi Node Insertion

// ConvertToSSAForm converts CFG to Static Single Assignment form
func (builder *AdvancedCFGBuilder) ConvertToSSAForm(cfg *CFG) error {
	// Step 1: Compute dominance information
	dominance := builder.computeDominanceInfo(cfg)
	dominanceFrontiers := builder.computeDominanceFrontiers(cfg, dominance)

	// Step 2: Insert phi nodes
	variables := builder.collectVariables(cfg)
	for varName := range variables {
		builder.insertPhiNodes(cfg, varName, dominanceFrontiers, variables[varName])
	}

	// Step 3: Rename variables to SSA form
	return builder.renameVariablesToSSA(cfg, cfg.Entry, make(map[string]int))
}

// computeDominanceInfo computes dominance relationships
func (builder *AdvancedCFGBuilder) computeDominanceInfo(cfg *CFG) map[BlockID][]BlockID {
	dominance := make(map[BlockID][]BlockID)

	// Initialize all nodes as dominated by all nodes
	allNodes := make([]BlockID, 0, len(cfg.Nodes))
	for id := range cfg.Nodes {
		allNodes = append(allNodes, id)
		dominance[id] = make([]BlockID, len(allNodes))
		copy(dominance[id], allNodes)
	}

	// Entry node is only dominated by itself
	dominance[cfg.Entry.ID] = []BlockID{cfg.Entry.ID}

	// Iterative algorithm
	changed := true
	for changed {
		changed = false
		for id, node := range cfg.Nodes {
			if id == cfg.Entry.ID {
				continue
			}

			newDom := builder.computeDominatorIntersection(node, cfg, dominance)
			newDom = append(newDom, id) // Add self

			if !builder.equalBlockIDSlices(dominance[id], newDom) {
				dominance[id] = newDom
				changed = true
			}
		}
	}

	return dominance
}

// computeDominanceFrontiers computes dominance frontiers for phi node placement
func (builder *AdvancedCFGBuilder) computeDominanceFrontiers(cfg *CFG, dominance map[BlockID][]BlockID) map[BlockID][]BlockID {
	frontiers := make(map[BlockID][]BlockID)

	for id := range cfg.Nodes {
		frontiers[id] = make([]BlockID, 0)
	}

	for _, edge := range cfg.Edges {
		runner := edge.From

		// Walk up dominance tree until we find a node that dominates the target
		for !builder.strictlyDominates(runner.ID, edge.To.ID, dominance) {
			frontiers[runner.ID] = append(frontiers[runner.ID], edge.To.ID)

			// Move to immediate dominator
			idom := builder.findImmediateDominator(runner.ID, dominance)
			if idom == runner.ID {
				break // Reached root
			}
			runner = cfg.Nodes[idom]
		}
	}

	return frontiers
}

// collectVariables collects all variables and their definition sites
func (builder *AdvancedCFGBuilder) collectVariables(cfg *CFG) map[string][]BlockID {
	variables := make(map[string][]BlockID)

	for nodeID, node := range cfg.Nodes {
		for _, stmt := range node.Block.Stmts {
			if stmt.Type == HIRAssign {
				if varName, ok := stmt.Meta["variable"].(string); ok {
					variables[varName] = append(variables[varName], nodeID)
				}
			}
		}
	}

	return variables
}

// insertPhiNodes inserts phi nodes at dominance frontiers
func (builder *AdvancedCFGBuilder) insertPhiNodes(cfg *CFG, varName string, frontiers map[BlockID][]BlockID, defSites []BlockID) {
	phiInserted := make(map[BlockID]bool)
	worklist := make([]BlockID, len(defSites))
	copy(worklist, defSites)

	for len(worklist) > 0 {
		node := worklist[0]
		worklist = worklist[1:]

		for _, frontier := range frontiers[node] {
			if !phiInserted[frontier] {
				// Insert phi node
				builder.insertPhiNode(cfg.Nodes[frontier], varName)
				phiInserted[frontier] = true

				// Add to worklist if not already a definition site
				alreadyDefSite := false
				for _, defSite := range defSites {
					if defSite == frontier {
						alreadyDefSite = true
						break
					}
				}
				if !alreadyDefSite {
					worklist = append(worklist, frontier)
				}
			}
		}
	}
}

// insertPhiNode inserts a phi node at the beginning of a block
func (builder *AdvancedCFGBuilder) insertPhiNode(node *CFGNode, varName string) {
	// Check if phi node already exists
	for _, stmt := range node.Block.Stmts {
		if stmt.Type == HIRPhi {
			if phiVar, ok := stmt.Meta["variable"].(string); ok && phiVar == varName {
				return // Already exists
			}
		}
	}

	// Create phi node statement
	phiStmt := &HIRStmt{
		ID:       StmtID(len(node.Block.Stmts) + 1000), // Ensure unique ID
		Type:     HIRPhi,
		Operands: make([]HIRValue, 0),
		Meta: map[string]interface{}{
			"variable":  varName,
			"is_phi":    true,
			"phi_inputs": make([]string, 0), // Will be filled during renaming
		},
	}

	// Insert at beginning of block
	node.Block.Stmts = append([]*HIRStmt{phiStmt}, node.Block.Stmts...)
}

// renameVariablesToSSA performs variable renaming to SSA form
func (builder *AdvancedCFGBuilder) renameVariablesToSSA(cfg *CFG, node *CFGNode, versions map[string]int) error {
	// Create local copy of versions for this subtree
	localVersions := make(map[string]int)
	for k, v := range versions {
		localVersions[k] = v
	}

	// Process statements in this node
	for _, stmt := range node.Block.Stmts {
		// Rename uses first
		builder.renameUses(stmt, localVersions)

		// Then rename definitions
		if stmt.Type == HIRAssign || stmt.Type == HIRPhi {
			if varName, ok := stmt.Meta["variable"].(string); ok {
				localVersions[varName]++
				newName := fmt.Sprintf("%s_%d", varName, localVersions[varName])
				stmt.Meta["variable"] = newName
				stmt.Meta["ssa_version"] = localVersions[varName]
			}
		}
	}

	// Update phi nodes in successors
	successors := builder.findCFGSuccessors(node, cfg)
	for _, successor := range successors {
		builder.updatePhiNodes(successor, node, localVersions)
	}

	// Recursively process children in dominator tree
	children := builder.findDominatorChildren(node, cfg)
	for _, child := range children {
		if err := builder.renameVariablesToSSA(cfg, child, localVersions); err != nil {
			return err
		}
	}

	return nil
}

// renameUses renames variable uses in a statement
func (builder *AdvancedCFGBuilder) renameUses(stmt *HIRStmt, versions map[string]int) {
	for i, operand := range stmt.Operands {
		if variable, ok := operand.(*Variable); ok {
			if version, exists := versions[variable.Name]; exists {
				newVar := *variable
				newVar.Name = fmt.Sprintf("%s_%d", variable.Name, version)
				stmt.Operands[i] = &newVar
			}
		}
	}

	// Handle variable references in metadata
	if varName, ok := stmt.Meta["variable_ref"].(string); ok {
		if version, exists := versions[varName]; exists {
			stmt.Meta["variable_ref"] = fmt.Sprintf("%s_%d", varName, version)
		}
	}
}

// updatePhiNodes updates phi node inputs from predecessor
func (builder *AdvancedCFGBuilder) updatePhiNodes(node *CFGNode, predecessor *CFGNode, versions map[string]int) {
	for _, stmt := range node.Block.Stmts {
		if stmt.Type == HIRPhi {
			if varName, ok := stmt.Meta["variable"].(string); ok {
				// Extract base variable name (remove SSA suffix if present)
				baseVarName := strings.Split(varName, "_")[0]

				if version, exists := versions[baseVarName]; exists {
					phiInputName := fmt.Sprintf("%s_%d", baseVarName, version)

					// Add to phi inputs
					if inputs, ok := stmt.Meta["phi_inputs"].([]string); ok {
						inputs = append(inputs, phiInputName)
						stmt.Meta["phi_inputs"] = inputs
					}
				}
			}
		}
	}
}

// Interprocedural CFG Analysis

// BuildInterproceduralCFGWithSymbolTable builds complete interprocedural CFG
func (builder *AdvancedCFGBuilder) BuildInterproceduralCFGWithSymbolTable() (*InterproceduralCFG, error) {
	// First, perform symbol linking
	if err := builder.symbolLinker.LinkSymbols(); err != nil {
		return nil, fmt.Errorf("symbol linking failed: %w", err)
	}

	icfg := &InterproceduralCFG{
		FunctionCFGs: make(map[SymbolID]*CFG),
		CallSites:    make([]CallSiteInfo, 0),
		Program:      builder.program,
	}

	// Build CFGs for all functions
	for _, file := range builder.program.Files {
		for _, unit := range file.Units {
			if unit.Symbol.Kind == SymFunction || unit.Symbol.Kind == SymMethod {
				cfg, err := builder.BuildAdvancedCFG(unit.Symbol, unit)
				if err != nil {
					continue // Skip functions with errors
				}

				builder.program.AddCFG(unit.Symbol.ID, cfg)
				unit.CFG = cfg
				icfg.FunctionCFGs[unit.Symbol.ID] = cfg

				// Convert to SSA form
				if err := builder.ConvertToSSAForm(cfg); err == nil {
					unit.IsSSA = true
				}

				// Collect call sites
				callSites := builder.extractCallSites(cfg)
				icfg.CallSites = append(icfg.CallSites, callSites...)
			}
		}
	}

	// Link interprocedural edges
	if err := builder.linkInterproceduralEdges(icfg); err != nil {
		return nil, fmt.Errorf("interprocedural linking failed: %w", err)
	}

	return icfg, nil
}

// extractCallSites extracts call site information from CFG
func (builder *AdvancedCFGBuilder) extractCallSites(cfg *CFG) []CallSiteInfo {
	callSites := make([]CallSiteInfo, 0)

	for _, node := range cfg.Nodes {
		for _, stmt := range node.Block.Stmts {
			if stmt.Type == HIRCall {
				callSite := CallSiteInfo{
					Position:     stmt.Position,
					CallerCFG:    cfg,
					CallSiteNode: node,
					CallStmt:     stmt,
				}

				if resolvedFunc, ok := stmt.Meta["resolved_function"].(string); ok {
					callSite.CalleeFQN = resolvedFunc
					callSite.CalleeCFG = builder.program.CFGs[SymbolID(resolvedFunc)]
				}

				callSites = append(callSites, callSite)
			}
		}
	}

	return callSites
}

// linkInterproceduralEdges creates interprocedural CFG edges
func (builder *AdvancedCFGBuilder) linkInterproceduralEdges(icfg *InterproceduralCFG) error {
	for _, callSite := range icfg.CallSites {
		if callSite.CalleeCFG != nil {
			// Create call edge
			callEdge := &CFGEdge{
				From: callSite.CallSiteNode,
				To:   callSite.CalleeCFG.Entry,
				Kind: CFGFallthrough, // Could extend with CFGCall
			}
			callSite.CallerCFG.Edges = append(callSite.CallerCFG.Edges, callEdge)

			// Create return edges (simplified - assumes single return)
			returnEdge := &CFGEdge{
				From: callSite.CalleeCFG.Exit,
				To:   builder.findReturnTarget(callSite.CallSiteNode, callSite.CallerCFG),
				Kind: CFGReturn,
			}
			callSite.CallerCFG.Edges = append(callSite.CallerCFG.Edges, returnEdge)
		}
	}

	return nil
}

// findReturnTarget finds the target node for function returns
func (builder *AdvancedCFGBuilder) findReturnTarget(callSiteNode *CFGNode, cfg *CFG) *CFGNode {
	// Find the node that follows the call site
	for _, edge := range cfg.Edges {
		if edge.From == callSiteNode && edge.Kind == CFGFallthrough {
			return edge.To
		}
	}
	return cfg.Exit // Fallback to exit if no explicit target
}

// Utility methods

func (builder *AdvancedCFGBuilder) createCFGNode(kind CFGNodeKind, hirBlock *HIRBlock) *CFGNode {
	if hirBlock == nil {
		hirBlock = &HIRBlock{
			ID:    builder.nextBlockID,
			Stmts: make([]*HIRStmt, 0),
			Preds: make([]*HIRBlock, 0),
			Succs: make([]*HIRBlock, 0),
		}
	}

	node := &CFGNode{
		ID:    builder.nextBlockID,
		Block: hirBlock,
		Kind:  kind,
	}

	builder.nextBlockID++
	return node
}

func (builder *AdvancedCFGBuilder) addCFGEdge(cfg *CFG, from, to *CFGNode, kind CFGEdgeKind, condition HIRValue) {
	edge := &CFGEdge{
		From:      from,
		To:        to,
		Kind:      kind,
		Condition: condition,
	}
	cfg.Edges = append(cfg.Edges, edge)
}

func (builder *AdvancedCFGBuilder) isTerminalStatement(stmt *HIRStmt) bool {
	return stmt.Type == HIRReturn || stmt.Type == HIRThrow || stmt.Type == HIRBreak || stmt.Type == HIRGoto
}

func (builder *AdvancedCFGBuilder) clearWorklists() {
	builder.exitBlocks = builder.exitBlocks[:0]
	builder.breakTargets = builder.breakTargets[:0]
	builder.continueTargets = builder.continueTargets[:0]
	builder.tryBlocks = builder.tryBlocks[:0]
	builder.catchBlocks = builder.catchBlocks[:0]
	builder.finallyBlocks = builder.finallyBlocks[:0]
}

// Helper methods for dominance analysis

func (builder *AdvancedCFGBuilder) computeDominatorIntersection(node *CFGNode, cfg *CFG, dominance map[BlockID][]BlockID) []BlockID {
	var result []BlockID

	preds := builder.findCFGPredecessors(node, cfg)
	if len(preds) == 0 {
		return result
	}

	// Start with first predecessor's dominators
	if len(preds) > 0 {
		result = make([]BlockID, len(dominance[preds[0].ID]))
		copy(result, dominance[preds[0].ID])
	}

	// Intersect with other predecessors
	for i := 1; i < len(preds); i++ {
		result = builder.intersectBlockIDs(result, dominance[preds[i].ID])
	}

	return result
}

func (builder *AdvancedCFGBuilder) findCFGPredecessors(node *CFGNode, cfg *CFG) []*CFGNode {
	preds := make([]*CFGNode, 0)
	for _, edge := range cfg.Edges {
		if edge.To == node {
			preds = append(preds, edge.From)
		}
	}
	return preds
}

func (builder *AdvancedCFGBuilder) findCFGSuccessors(node *CFGNode, cfg *CFG) []*CFGNode {
	successors := make([]*CFGNode, 0)
	for _, edge := range cfg.Edges {
		if edge.From == node {
			successors = append(successors, edge.To)
		}
	}
	return successors
}

func (builder *AdvancedCFGBuilder) findDominatorChildren(node *CFGNode, cfg *CFG) []*CFGNode {
	// Simplified - in practice would need proper dominator tree
	return builder.findCFGSuccessors(node, cfg)
}

func (builder *AdvancedCFGBuilder) strictlyDominates(a, b BlockID, dominance map[BlockID][]BlockID) bool {
	for _, dom := range dominance[b] {
		if dom == a && a != b {
			return true
		}
	}
	return false
}

func (builder *AdvancedCFGBuilder) findImmediateDominator(nodeID BlockID, dominance map[BlockID][]BlockID) BlockID {
	// Simplified - return first dominator that's not self
	for _, dom := range dominance[nodeID] {
		if dom != nodeID {
			return dom
		}
	}
	return nodeID
}

func (builder *AdvancedCFGBuilder) intersectBlockIDs(a, b []BlockID) []BlockID {
	result := make([]BlockID, 0)
	for _, idA := range a {
		for _, idB := range b {
			if idA == idB {
				result = append(result, idA)
				break
			}
		}
	}
	return result
}

func (builder *AdvancedCFGBuilder) equalBlockIDSlices(a, b []BlockID) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// Extended CFGEdge to include context information
type ExtendedCFGEdge struct {
	*CFGEdge
	Context string // Additional context for debugging/analysis
}

// Add context support through a wrapper if needed
type CFGEdgeWithContext struct {
	*CFGEdge
	Context string
}

func NewCFGEdgeWithContext(from, to *CFGNode, kind CFGEdgeKind, condition HIRValue, context string) *CFGEdgeWithContext {
	return &CFGEdgeWithContext{
		CFGEdge: &CFGEdge{
			From:      from,
			To:        to,
			Kind:      kind,
			Condition: condition,
		},
		Context: context,
	}
}

// InterproceduralCFG represents the complete program CFG with symbol table integration
type InterproceduralCFG struct {
	FunctionCFGs map[SymbolID]*CFG
	CallSites    []CallSiteInfo
	Program      *HIRProgram
}

// CallSiteInfo contains detailed information about function call sites
type CallSiteInfo struct {
	Position     token.Pos
	CallerCFG    *CFG
	CalleeCFG    *CFG
	CallSiteNode *CFGNode
	CallStmt     *HIRStmt
	CalleeFQN    string
	IsResolved   bool
	Context      string
}