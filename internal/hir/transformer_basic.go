package hir

import (
	"fmt"
	"go/token"
)

// BasicTransformer provides a minimal working HIR transformer
type BasicTransformer struct {
	program     *HIRProgram
	nextStmtID  StmtID
	nextVarID   VariableID
	nextBlockID BlockID
}

// NewBasicTransformer creates a new basic transformer
func NewBasicTransformer(program *HIRProgram) *BasicTransformer {
	return &BasicTransformer{
		program:     program,
		nextStmtID:  1,
		nextVarID:   1,
		nextBlockID: 1,
	}
}

// TransformBasicFile creates a basic HIR file for testing
func (t *BasicTransformer) TransformBasicFile(filePath string, content []byte) (*HIRFile, error) {
	// Create a basic HIR file with demo content
	hirFile := &HIRFile{
		Path:     filePath,
		Language: "php",
		Symbols:  make([]*Symbol, 0),
		Units:    make([]*HIRUnit, 0),
		Includes: make([]*Include, 0),
	}

	// Add a demo function symbol
	functionSymbol := &Symbol{
		ID:       SymbolID(fmt.Sprintf("%s::testFunction", filePath)),
		FQN:      "\\testFunction",
		Kind:     SymFunction,
		File:     filePath,
		Position: token.Pos(1),
		Traits: SymbolTraits{
			Visibility: VisPublic,
			IsStatic:   false,
		},
		Meta: make(map[string]interface{}),
	}

	hirFile.Symbols = append(hirFile.Symbols, functionSymbol)

	// Add a demo HIR unit (function body)
	unit := &HIRUnit{
		Symbol:  functionSymbol,
		Params:  make([]*Variable, 0),
		Returns: make([]*Variable, 0),
		Body:    t.createBasicBlock(),
		IsSSA:   false,
	}

	hirFile.Units = append(hirFile.Units, unit)

	return hirFile, nil
}

// createBasicBlock creates a basic HIR block with demo statements
func (t *BasicTransformer) createBasicBlock() *HIRBlock {
	block := &HIRBlock{
		ID:    t.nextBlockID,
		Stmts: make([]*HIRStmt, 0),
		Preds: make([]*HIRBlock, 0),
		Succs: make([]*HIRBlock, 0),
	}
	t.nextBlockID++

	// Add demo assignment statement
	assignStmt := &HIRStmt{
		ID:       t.nextStmtID,
		Type:     HIRAssign,
		Operands: make([]HIRValue, 0),
		Position: token.Pos(1),
		Meta:     make(map[string]interface{}),
	}
	t.nextStmtID++

	// Add demo variable
	variable := &Variable{
		ID:           t.nextVarID,
		Name:         "$userInput",
		Type:         "string",
		tainted:      true,
		TaintSources: []TaintSource{{Kind: TaintUserInput, Location: token.Pos(1), Details: "User input"}},
		DefSites:     []StmtID{assignStmt.ID},
		UseSites:     make([]StmtID, 0),
		Scope:        ScopeLocal,
	}
	t.nextVarID++

	assignStmt.Meta["target"] = variable
	assignStmt.Meta["tainted"] = true

	block.Stmts = append(block.Stmts, assignStmt)

	// Add demo function call
	callStmt := &HIRStmt{
		ID:       t.nextStmtID,
		Type:     HIRCall,
		Operands: make([]HIRValue, 0),
		Position: token.Pos(2),
		Meta: map[string]interface{}{
			"function": "mysqli_query",
			"args":     []string{"$connection", "$userInput"},
			"security_risk": "SQL Injection",
		},
	}
	t.nextStmtID++

	block.Stmts = append(block.Stmts, callStmt)

	return block
}