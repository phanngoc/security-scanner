package hir

import (
	"fmt"
)

// CFGBuilder builds Control Flow Graphs from HIR
type CFGBuilder struct {
	nextNodeID int
	cfg        *CFG
}

// NewCFGBuilder creates a new CFG builder
func NewCFGBuilder() *CFGBuilder {
	return &CFGBuilder{
		nextNodeID: 1,
	}
}

// BuildCFG builds a CFG for a HIR unit (function/method)
func (cb *CFGBuilder) BuildCFG(unit *HIRUnit) (*CFG, error) {
	cfg := &CFG{
		Nodes:    make(map[BlockID]*CFGNode),
		Edges:    make([]*CFGEdge, 0),
		Function: unit.Symbol,
	}
	cb.cfg = cfg

	// Create entry and exit nodes
	entry := cb.createNode(CFGEntry, nil)
	exit := cb.createNode(CFGExit, nil)
	cfg.Entry = entry
	cfg.Exit = exit

	if unit.Body == nil {
		// Empty function - just connect entry to exit
		cb.addEdge(entry, exit, nil, CFGFallthrough)
		return cfg, nil
	}

	// Build CFG from the function body
	startNode := cb.buildBlockCFG(unit.Body, entry, exit)
	if startNode != entry {
		cb.addEdge(entry, startNode, nil, CFGFallthrough)
	}

	// Store CFG in unit
	unit.CFG = cfg

	return cfg, nil
}

// buildBlockCFG builds CFG for a HIR block
func (cb *CFGBuilder) buildBlockCFG(block *HIRBlock, entry, exit *CFGNode) *CFGNode {
	if block == nil || len(block.Stmts) == 0 {
		return entry
	}

	currentNode := entry
	var blockNode *CFGNode

	// Create a basic block node for regular statements
	hasRegularStmts := false
	for _, stmt := range block.Stmts {
		if !cb.isControlFlowStmt(stmt) {
			hasRegularStmts = true
			break
		}
	}

	if hasRegularStmts {
		blockNode = cb.createNode(CFGBasic, block)
		if currentNode != entry {
			cb.addEdge(currentNode, blockNode, nil, CFGFallthrough)
		}
		currentNode = blockNode
	}

	// Process statements
	for _, stmt := range block.Stmts {
		switch stmt.Type {
		case HIRIf:
			currentNode = cb.buildIfCFG(stmt, currentNode, exit)
		case HIRLoop:
			currentNode = cb.buildLoopCFG(stmt, currentNode, exit)
		case HIRSwitch:
			currentNode = cb.buildSwitchCFG(stmt, currentNode, exit)
		case HIRTryCatch:
			currentNode = cb.buildTryCatchCFG(stmt, currentNode, exit)
		case HIRReturn:
			returnNode := cb.createNode(CFGBasic, block)
			cb.addEdge(currentNode, returnNode, nil, CFGFallthrough)
			cb.addEdge(returnNode, exit, nil, CFGReturn)
			// Return statements don't have successors in normal flow
			currentNode = cb.createNode(CFGBasic, nil) // Unreachable node
		case HIRThrow:
			throwNode := cb.createNode(CFGBasic, block)
			cb.addEdge(currentNode, throwNode, nil, CFGFallthrough)
			cb.addEdge(throwNode, exit, nil, CFGThrow)
			// Throw statements don't have successors in normal flow
			currentNode = cb.createNode(CFGBasic, nil) // Unreachable node
		case HIRBreak:
			breakNode := cb.createNode(CFGBasic, block)
			cb.addEdge(currentNode, breakNode, nil, CFGFallthrough)
			// Break edges will be connected by loop handling
			currentNode = cb.createNode(CFGBasic, nil) // Unreachable node
		}
	}

	return currentNode
}

// buildIfCFG builds CFG for if statements
func (cb *CFGBuilder) buildIfCFG(stmt *HIRStmt, current, exit *CFGNode) *CFGNode {
	condNode := cb.createNode(CFGConditional, nil)
	cb.addEdge(current, condNode, nil, CFGFallthrough)

	// Create nodes for then and else branches
	thenNode := cb.createNode(CFGBasic, nil)
	elseNode := cb.createNode(CFGBasic, nil)
	mergeNode := cb.createNode(CFGBasic, nil)

	// Connect condition to branches
	cb.addEdge(condNode, thenNode, nil, CFGTrue)
	cb.addEdge(condNode, elseNode, nil, CFGFalse)

	// Connect branches to merge point
	cb.addEdge(thenNode, mergeNode, nil, CFGFallthrough)
	cb.addEdge(elseNode, mergeNode, nil, CFGFallthrough)

	return mergeNode
}

// buildLoopCFG builds CFG for loop statements
func (cb *CFGBuilder) buildLoopCFG(stmt *HIRStmt, current, exit *CFGNode) *CFGNode {
	// Create loop nodes
	loopHeader := cb.createNode(CFGLoop, nil)
	loopBody := cb.createNode(CFGBasic, nil)
	loopExit := cb.createNode(CFGBasic, nil)

	// Connect entry to loop header
	cb.addEdge(current, loopHeader, nil, CFGFallthrough)

	// Loop condition
	cb.addEdge(loopHeader, loopBody, nil, CFGTrue)    // Continue loop
	cb.addEdge(loopHeader, loopExit, nil, CFGFalse)   // Exit loop

	// Loop body back to header
	cb.addEdge(loopBody, loopHeader, nil, CFGFallthrough)

	// Break and continue will connect to appropriate nodes
	// (This would be handled when processing break/continue statements)

	return loopExit
}

// buildSwitchCFG builds CFG for switch statements
func (cb *CFGBuilder) buildSwitchCFG(stmt *HIRStmt, current, exit *CFGNode) *CFGNode {
	switchNode := cb.createNode(CFGConditional, nil)
	mergeNode := cb.createNode(CFGBasic, nil)

	cb.addEdge(current, switchNode, nil, CFGFallthrough)

	// For simplicity, treat switch as multiple if-else
	// In a full implementation, we'd analyze each case
	defaultNode := cb.createNode(CFGBasic, nil)
	cb.addEdge(switchNode, defaultNode, nil, CFGFallthrough)
	cb.addEdge(defaultNode, mergeNode, nil, CFGFallthrough)

	return mergeNode
}

// buildTryCatchCFG builds CFG for try-catch statements
func (cb *CFGBuilder) buildTryCatchCFG(stmt *HIRStmt, current, exit *CFGNode) *CFGNode {
	tryNode := cb.createNode(CFGTry, nil)
	catchNode := cb.createNode(CFGCatch, nil)
	finallyNode := cb.createNode(CFGFinally, nil)
	mergeNode := cb.createNode(CFGBasic, nil)

	// Connect to try block
	cb.addEdge(current, tryNode, nil, CFGFallthrough)

	// Normal flow: try -> finally -> merge
	cb.addEdge(tryNode, finallyNode, nil, CFGFallthrough)
	cb.addEdge(finallyNode, mergeNode, nil, CFGFallthrough)

	// Exception flow: try -> catch -> finally -> merge
	cb.addEdge(tryNode, catchNode, nil, CFGThrow)
	cb.addEdge(catchNode, finallyNode, nil, CFGFallthrough)

	return mergeNode
}

// isControlFlowStmt checks if a statement affects control flow
func (cb *CFGBuilder) isControlFlowStmt(stmt *HIRStmt) bool {
	switch stmt.Type {
	case HIRIf, HIRLoop, HIRSwitch, HIRTryCatch, HIRReturn, HIRThrow, HIRBreak:
		return true
	default:
		return false
	}
}

// createNode creates a new CFG node
func (cb *CFGBuilder) createNode(kind CFGNodeKind, block *HIRBlock) *CFGNode {
	node := &CFGNode{
		ID:    BlockID(cb.nextNodeID),
		Block: block,
		Kind:  kind,
	}
	cb.nextNodeID++
	cb.cfg.Nodes[node.ID] = node
	return node
}

// addEdge adds an edge between two CFG nodes
func (cb *CFGBuilder) addEdge(from, to *CFGNode, condition HIRValue, kind CFGEdgeKind) {
	edge := &CFGEdge{
		From:      from,
		To:        to,
		Condition: condition,
		Kind:      kind,
	}
	cb.cfg.Edges = append(cb.cfg.Edges, edge)
}

// CFGAnalyzer provides analysis capabilities for CFGs
type CFGAnalyzer struct {
	cfg *CFG
}

// NewCFGAnalyzer creates a new CFG analyzer
func NewCFGAnalyzer(cfg *CFG) *CFGAnalyzer {
	return &CFGAnalyzer{cfg: cfg}
}

// GetDominators computes dominator sets for all nodes
func (ca *CFGAnalyzer) GetDominators() map[BlockID]map[BlockID]bool {
	dominators := make(map[BlockID]map[BlockID]bool)
	
	// Initialize dominator sets
	for nodeID := range ca.cfg.Nodes {
		dominators[nodeID] = make(map[BlockID]bool)
		
		// Entry node dominates only itself
		if nodeID == ca.cfg.Entry.ID {
			dominators[nodeID][nodeID] = true
		} else {
			// All other nodes initially dominated by all nodes
			for otherID := range ca.cfg.Nodes {
				dominators[nodeID][otherID] = true
			}
		}
	}
	
	// Iterative algorithm to compute dominators
	changed := true
	for changed {
		changed = false
		
		for nodeID, node := range ca.cfg.Nodes {
			if nodeID == ca.cfg.Entry.ID {
				continue // Skip entry node
			}
			
			// New dominator set = {node} ∪ (∩ dominators of predecessors)
			newDoms := make(map[BlockID]bool)
			newDoms[nodeID] = true // Node always dominates itself
			
			// Find predecessors
			preds := ca.getPredecessors(node)
			if len(preds) > 0 {
				// Intersection of predecessor dominators
				for domID := range ca.cfg.Nodes {
					dominatedByAll := true
					for _, pred := range preds {
						if !dominators[pred.ID][domID] {
							dominatedByAll = false
							break
						}
					}
					if dominatedByAll {
						newDoms[domID] = true
					}
				}
			}
			
			// Check if dominator set changed
			if !ca.dominatorSetsEqual(dominators[nodeID], newDoms) {
				dominators[nodeID] = newDoms
				changed = true
			}
		}
	}
	
	return dominators
}

// GetReachableNodes returns all nodes reachable from entry
func (ca *CFGAnalyzer) GetReachableNodes() map[BlockID]bool {
	reachable := make(map[BlockID]bool)
	visited := make(map[BlockID]bool)
	
	var dfs func(*CFGNode)
	dfs = func(node *CFGNode) {
		if visited[node.ID] {
			return
		}
		visited[node.ID] = true
		reachable[node.ID] = true
		
		// Visit successors
		for _, edge := range ca.cfg.Edges {
			if edge.From.ID == node.ID {
				dfs(edge.To)
			}
		}
	}
	
	dfs(ca.cfg.Entry)
	return reachable
}

// GetLoops identifies natural loops in the CFG
func (ca *CFGAnalyzer) GetLoops() []*Loop {
	loops := make([]*Loop, 0)
	dominators := ca.GetDominators()
	
	// Find back edges (edges where target dominates source)
	for _, edge := range ca.cfg.Edges {
		if dominators[edge.From.ID][edge.To.ID] {
			// This is a back edge - forms a natural loop
			loop := &Loop{
				Header: edge.To,
				Latch:  edge.From,
				Nodes:  make(map[BlockID]*CFGNode),
			}
			
			// Find all nodes in the loop
			ca.findLoopNodes(loop, edge.To, edge.From)
			loops = append(loops, loop)
		}
	}
	
	return loops
}

// Loop represents a natural loop in the CFG
type Loop struct {
	Header *CFGNode                  // Loop header (dominates all nodes in loop)
	Latch  *CFGNode                  // Loop latch (has back edge to header)
	Nodes  map[BlockID]*CFGNode      // All nodes in the loop
}

// findLoopNodes finds all nodes that belong to a natural loop
func (ca *CFGAnalyzer) findLoopNodes(loop *Loop, header, latch *CFGNode) {
	loop.Nodes[header.ID] = header
	loop.Nodes[latch.ID] = latch
	
	// Worklist algorithm to find all nodes in the loop
	worklist := []*CFGNode{latch}
	
	for len(worklist) > 0 {
		node := worklist[0]
		worklist = worklist[1:]
		
		// Add predecessors to the loop if not already included
		preds := ca.getPredecessors(node)
		for _, pred := range preds {
			if _, inLoop := loop.Nodes[pred.ID]; !inLoop {
				loop.Nodes[pred.ID] = pred
				worklist = append(worklist, pred)
			}
		}
	}
}

// getPredecessors returns all predecessor nodes
func (ca *CFGAnalyzer) getPredecessors(node *CFGNode) []*CFGNode {
	preds := make([]*CFGNode, 0)
	for _, edge := range ca.cfg.Edges {
		if edge.To.ID == node.ID {
			preds = append(preds, edge.From)
		}
	}
	return preds
}

// getSuccessors returns all successor nodes
func (ca *CFGAnalyzer) getSuccessors(node *CFGNode) []*CFGNode {
	succs := make([]*CFGNode, 0)
	for _, edge := range ca.cfg.Edges {
		if edge.From.ID == node.ID {
			succs = append(succs, edge.To)
		}
	}
	return succs
}

// dominatorSetsEqual checks if two dominator sets are equal
func (ca *CFGAnalyzer) dominatorSetsEqual(set1, set2 map[BlockID]bool) bool {
	if len(set1) != len(set2) {
		return false
	}
	
	for id := range set1 {
		if !set2[id] {
			return false
		}
	}
	
	return true
}

// CFGVisualizer provides visualization utilities for CFGs
type CFGVisualizer struct {
	cfg *CFG
}

// NewCFGVisualizer creates a new CFG visualizer
func NewCFGVisualizer(cfg *CFG) *CFGVisualizer {
	return &CFGVisualizer{cfg: cfg}
}

// ToDotFormat exports CFG to DOT format for visualization
func (cv *CFGVisualizer) ToDotFormat() string {
	result := "digraph CFG {\n"
	result += "  rankdir=TB;\n"
	result += "  node [shape=box];\n\n"
	
	// Add nodes
	for _, node := range cv.cfg.Nodes {
		label := cv.getNodeLabel(node)
		shape := cv.getNodeShape(node)
		result += fmt.Sprintf("  %d [label=\"%s\", shape=%s];\n", node.ID, label, shape)
	}
	
	result += "\n"
	
	// Add edges
	for _, edge := range cv.cfg.Edges {
		edgeLabel := cv.getEdgeLabel(edge)
		style := cv.getEdgeStyle(edge)
		result += fmt.Sprintf("  %d -> %d [label=\"%s\", style=%s];\n", 
			edge.From.ID, edge.To.ID, edgeLabel, style)
	}
	
	result += "}\n"
	return result
}

// getNodeLabel returns a descriptive label for a CFG node
func (cv *CFGVisualizer) getNodeLabel(node *CFGNode) string {
	switch node.Kind {
	case CFGEntry:
		return "ENTRY"
	case CFGExit:
		return "EXIT"
	case CFGConditional:
		return "CONDITION"
	case CFGLoop:
		return "LOOP"
	case CFGTry:
		return "TRY"
	case CFGCatch:
		return "CATCH"
	case CFGFinally:
		return "FINALLY"
	default:
		if node.Block != nil {
			return fmt.Sprintf("Block %d\\n(%d stmts)", node.ID, len(node.Block.Stmts))
		}
		return fmt.Sprintf("Block %d", node.ID)
	}
}

// getNodeShape returns the shape for a CFG node
func (cv *CFGVisualizer) getNodeShape(node *CFGNode) string {
	switch node.Kind {
	case CFGEntry, CFGExit:
		return "ellipse"
	case CFGConditional:
		return "diamond"
	case CFGLoop:
		return "hexagon"
	case CFGTry, CFGCatch, CFGFinally:
		return "trapezium"
	default:
		return "box"
	}
}

// getEdgeLabel returns a label for a CFG edge
func (cv *CFGVisualizer) getEdgeLabel(edge *CFGEdge) string {
	switch edge.Kind {
	case CFGTrue:
		return "true"
	case CFGFalse:
		return "false"
	case CFGThrow:
		return "throw"
	case CFGReturn:
		return "return"
	case CFGBreak:
		return "break"
	case CFGContinue:
		return "continue"
	default:
		return ""
	}
}

// getEdgeStyle returns the style for a CFG edge
func (cv *CFGVisualizer) getEdgeStyle(edge *CFGEdge) string {
	switch edge.Kind {
	case CFGThrow:
		return "dashed"
	case CFGReturn:
		return "bold"
	default:
		return "solid"
	}
}

// CFGMetrics computes various metrics for CFGs
type CFGMetrics struct {
	NodeCount       int
	EdgeCount       int
	CyclomaticComplexity int
	MaxDepth        int
	LoopCount       int
	ReachableNodes  int
	UnreachableNodes int
}

// ComputeMetrics computes metrics for a CFG
func (ca *CFGAnalyzer) ComputeMetrics() *CFGMetrics {
	metrics := &CFGMetrics{}
	
	metrics.NodeCount = len(ca.cfg.Nodes)
	metrics.EdgeCount = len(ca.cfg.Edges)
	
	// Cyclomatic complexity: E - N + 2 (for connected graph)
	metrics.CyclomaticComplexity = metrics.EdgeCount - metrics.NodeCount + 2
	
	// Count reachable nodes
	reachable := ca.GetReachableNodes()
	metrics.ReachableNodes = len(reachable)
	metrics.UnreachableNodes = metrics.NodeCount - metrics.ReachableNodes
	
	// Count loops
	loops := ca.GetLoops()
	metrics.LoopCount = len(loops)
	
	// Compute max depth (longest path from entry)
	metrics.MaxDepth = ca.computeMaxDepth()
	
	return metrics
}

// computeMaxDepth computes the maximum depth from entry node
func (ca *CFGAnalyzer) computeMaxDepth() int {
	depths := make(map[BlockID]int)
	visited := make(map[BlockID]bool)
	
	var dfs func(*CFGNode, int) int
	dfs = func(node *CFGNode, depth int) int {
		if visited[node.ID] {
			return depths[node.ID]
		}
		
		visited[node.ID] = true
		depths[node.ID] = depth
		
		maxChildDepth := depth
		successors := ca.getSuccessors(node)
		for _, succ := range successors {
			childDepth := dfs(succ, depth+1)
			if childDepth > maxChildDepth {
				maxChildDepth = childDepth
			}
		}
		
		depths[node.ID] = maxChildDepth
		return maxChildDepth
	}
	
	return dfs(ca.cfg.Entry, 0)
}