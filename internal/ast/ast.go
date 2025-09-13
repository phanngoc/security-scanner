package ast

import (
	"fmt"
	"time"
)

// ASTNode represents a generic AST node interface for all languages
type ASTNode interface {
	GetType() NodeType
	GetPosition() Position
	GetChildren() []ASTNode
	GetParent() ASTNode
	SetParent(parent ASTNode)
	Accept(visitor NodeVisitor) error
	String() string
}

// NodeType represents different types of AST nodes
type NodeType int

const (
	// Program structure
	NodeProgram NodeType = iota
	NodePackage
	NodeImport
	NodeClass
	NodeInterface
	NodeTrait

	// Functions and methods
	NodeFunction
	NodeMethod
	NodeConstructor
	NodeDestructor
	NodeProperty

	// Variables and expressions
	NodeVariable
	NodeConstant
	NodeLiteral
	NodeExpression
	NodeBinaryOp
	NodeUnaryOp
	NodeAssignment
	NodeMethodCall
	NodeFunctionCall
	NodePropertyAccess

	// Control flow
	NodeIf
	NodeElse
	NodeSwitch
	NodeCase
	NodeFor
	NodeWhile
	NodeForeach
	NodeBreak
	NodeContinue
	NodeReturn
	NodeThrow
	NodeTryCatch

	// Security-relevant nodes
	NodeSQLQuery
	NodeUserInput
	NodeFileOperation
	NodeNetworkCall
	NodeCryptographic
	NodeAuthentication
	NodeAuthorization
	NodeValidation
	NodeSanitization
)

// Position represents a position in source code
type Position struct {
	Filename string
	Line     int
	Column   int
	Offset   int
}

// Range represents a range in source code
type Range struct {
	Start Position
	End   Position
}

// BaseNode provides common functionality for all AST nodes
type BaseNode struct {
	Type     NodeType
	Position Position
	Range    Range
	Parent   ASTNode
	Children []ASTNode
	Metadata map[string]interface{}
}

func (b *BaseNode) GetType() NodeType {
	return b.Type
}

func (b *BaseNode) GetPosition() Position {
	return b.Position
}

func (b *BaseNode) GetChildren() []ASTNode {
	return b.Children
}

func (b *BaseNode) GetParent() ASTNode {
	return b.Parent
}

func (b *BaseNode) SetParent(parent ASTNode) {
	b.Parent = parent
}

func (b *BaseNode) AddChild(child ASTNode) {
	b.Children = append(b.Children, child)
	child.SetParent(b)
}

func (b *BaseNode) Accept(visitor NodeVisitor) error {
	return visitor.Visit(b)
}

func (b *BaseNode) String() string {
	return fmt.Sprintf("Node %d at %s:%d", b.Type, b.Position.Filename, b.Position.Line)
}

// Specific AST node types

// ProgramNode represents the root of an AST
type ProgramNode struct {
	BaseNode
	Language   string
	SourceCode string
	Imports    []*ImportNode
	Functions  []*FunctionNode
	Classes    []*ClassNode
	Variables  []*VariableNode
	Namespace  string
}

// FunctionNode represents a function declaration
type FunctionNode struct {
	BaseNode
	Name         string
	Parameters   []*ParameterNode
	ReturnType   string
	Body         *BlockNode
	Visibility   string
	IsStatic     bool
	IsAbstract   bool
	Annotations  []string
	CallsUnsafe  bool // Security flag
	HasUserInput bool // Security flag
}

// ClassNode represents a class declaration
type ClassNode struct {
	BaseNode
	Name        string
	Extends     string
	Implements  []string
	Properties  []*PropertyNode
	Methods     []*FunctionNode
	Visibility  string
	IsAbstract  bool
	IsFinal     bool
	Annotations []string
}

// VariableNode represents a variable declaration or usage
type VariableNode struct {
	BaseNode
	Name      string
	Type      string
	Value     ASTNode
	Scope     string
	IsGlobal  bool
	IsTainted bool   // Security flag for data flow analysis
	Source    string // Where the data comes from (user input, database, etc.)
}

// ParameterNode represents a function parameter
type ParameterNode struct {
	BaseNode
	Name         string
	Type         string
	DefaultValue ASTNode
	IsOptional   bool
	IsVariadic   bool
	IsTainted    bool // Security flag
}

// ImportNode represents an import/include statement
type ImportNode struct {
	BaseNode
	Path       string
	Alias      string
	IsRelative bool
}

// PropertyNode represents a class property
type PropertyNode struct {
	BaseNode
	Name         string
	Type         string
	DefaultValue ASTNode
	Visibility   string
	IsStatic     bool
	IsConstant   bool
}

// BlockNode represents a block of statements
type BlockNode struct {
	BaseNode
	Statements []ASTNode
}

// FunctionCallNode represents a function call
type FunctionCallNode struct {
	BaseNode
	Function         string
	Arguments        []ASTNode
	Receiver         ASTNode // For method calls
	IsSafe           bool    // Security flag
	IsUserControlled bool    // If arguments are user-controlled
}

// LiteralNode represents a literal value
type LiteralNode struct {
	BaseNode
	Value interface{}
	Kind  LiteralKind
}

type LiteralKind int

const (
	LiteralString LiteralKind = iota
	LiteralInteger
	LiteralFloat
	LiteralBoolean
	LiteralNull
	LiteralArray
	LiteralObject
)

// BinaryOpNode represents a binary operation
type BinaryOpNode struct {
	BaseNode
	Left     ASTNode
	Right    ASTNode
	Operator string
}

// AssignmentNode represents an assignment
type AssignmentNode struct {
	BaseNode
	Left     ASTNode
	Right    ASTNode
	Operator string
}

// ConditionalNode represents if/else statements
type ConditionalNode struct {
	BaseNode
	Condition ASTNode
	ThenBlock *BlockNode
	ElseBlock *BlockNode
}

// LoopNode represents loops (for, while, foreach)
type LoopNode struct {
	BaseNode
	LoopType  LoopType
	Init      ASTNode
	Condition ASTNode
	Update    ASTNode
	Body      *BlockNode
	Variable  *VariableNode // For foreach loops
	Iterable  ASTNode       // For foreach loops
}

type LoopType int

const (
	LoopFor LoopType = iota
	LoopWhile
	LoopForeach
	LoopDoWhile
)

// NodeVisitor interface for implementing visitor pattern
type NodeVisitor interface {
	Visit(node ASTNode) error
	VisitProgram(node *ProgramNode) error
	VisitFunction(node *FunctionNode) error
	VisitClass(node *ClassNode) error
	VisitVariable(node *VariableNode) error
	VisitFunctionCall(node *FunctionCallNode) error
	VisitLiteral(node *LiteralNode) error
	VisitBinaryOp(node *BinaryOpNode) error
	VisitAssignment(node *AssignmentNode) error
	VisitConditional(node *ConditionalNode) error
	VisitLoop(node *LoopNode) error
}

// BaseVisitor provides default implementations for visitor methods
type BaseVisitor struct{}

func (v *BaseVisitor) Visit(node ASTNode) error {
	switch n := node.(type) {
	case *ProgramNode:
		return v.VisitProgram(n)
	case *FunctionNode:
		return v.VisitFunction(n)
	case *ClassNode:
		return v.VisitClass(n)
	case *VariableNode:
		return v.VisitVariable(n)
	case *FunctionCallNode:
		return v.VisitFunctionCall(n)
	case *LiteralNode:
		return v.VisitLiteral(n)
	case *BinaryOpNode:
		return v.VisitBinaryOp(n)
	case *AssignmentNode:
		return v.VisitAssignment(n)
	case *ConditionalNode:
		return v.VisitConditional(n)
	case *LoopNode:
		return v.VisitLoop(n)
	default:
		return nil
	}
}

func (v *BaseVisitor) VisitProgram(node *ProgramNode) error           { return nil }
func (v *BaseVisitor) VisitFunction(node *FunctionNode) error         { return nil }
func (v *BaseVisitor) VisitClass(node *ClassNode) error               { return nil }
func (v *BaseVisitor) VisitVariable(node *VariableNode) error         { return nil }
func (v *BaseVisitor) VisitFunctionCall(node *FunctionCallNode) error { return nil }
func (v *BaseVisitor) VisitLiteral(node *LiteralNode) error           { return nil }
func (v *BaseVisitor) VisitBinaryOp(node *BinaryOpNode) error         { return nil }
func (v *BaseVisitor) VisitAssignment(node *AssignmentNode) error     { return nil }
func (v *BaseVisitor) VisitConditional(node *ConditionalNode) error   { return nil }
func (v *BaseVisitor) VisitLoop(node *LoopNode) error                 { return nil }

// SecurityContext provides security-related metadata for AST nodes
type SecurityContext struct {
	IsTainted        bool
	TaintSource      string
	IsValidated      bool
	IsSanitized      bool
	IsUserInput      bool
	RequiresAuth     bool
	SensitivityLevel int
	CWEReferences    []string
	OWASPCategory    string
}

// SymbolTable maintains symbol information with security context
type SymbolTable struct {
	Symbols         map[string]*Symbol
	Functions       map[string]*FunctionSymbol
	Classes         map[string]*ClassSymbol
	Variables       map[string]*VariableSymbol
	Scopes          []*Scope
	CurrentScope    *Scope
	SecurityContext map[string]*SecurityContext
	DataFlow        *DataFlowGraph
	CallGraph       *CallGraph
}

// Symbol represents a symbol in the symbol table
type Symbol struct {
	Name        string
	Type        string
	Kind        SymbolKind
	Position    Position
	Scope       *Scope
	Node        ASTNode
	SecurityCtx *SecurityContext
}

type SymbolKind int

const (
	SymbolFunction SymbolKind = iota
	SymbolVariable
	SymbolClass
	SymbolInterface
	SymbolConstant
	SymbolParameter
	SymbolProperty
	SymbolMethod
)

// FunctionSymbol represents function-specific symbol information
type FunctionSymbol struct {
	*Symbol
	Parameters []*ParameterSymbol
	ReturnType string
	CallSites  []*CallSite
	IsSafe     bool
	TaintFlow  *TaintFlow
}

// ClassSymbol represents class-specific symbol information
type ClassSymbol struct {
	*Symbol
	Methods    []*FunctionSymbol
	Properties []*VariableSymbol
	Extends    string
	Implements []string
}

// VariableSymbol represents variable-specific symbol information
type VariableSymbol struct {
	*Symbol
	DataType     string
	IsTainted    bool
	TaintSources []string
	Assignments  []*AssignmentSite
}

// ParameterSymbol represents parameter-specific symbol information
type ParameterSymbol struct {
	*VariableSymbol
	IsOptional bool
	IsVariadic bool
}

// Scope represents a lexical scope
type Scope struct {
	Parent   *Scope
	Children []*Scope
	Symbols  map[string]*Symbol
	Level    int
	Type     ScopeType
}

type ScopeType int

const (
	ScopeGlobal ScopeType = iota
	ScopeFunction
	ScopeClass
	ScopeBlock
	ScopeIf
	ScopeLoop
)

// CallSite represents a function call location
type CallSite struct {
	Position  Position
	Arguments []ASTNode
	Context   *SecurityContext
}

// AssignmentSite represents a variable assignment location
type AssignmentSite struct {
	Position Position
	Value    ASTNode
	Context  *SecurityContext
}

// TaintFlow represents data flow for taint analysis
type TaintFlow struct {
	Sources []Position
	Sinks   []Position
	Path    []Position
}

// DataFlowGraph represents data flow in the program
type DataFlowGraph struct {
	Nodes map[string]*DataFlowNode
	Edges []*DataFlowEdge
}

// DataFlowNode represents a node in data flow graph
type DataFlowNode struct {
	ID       string
	Position Position
	Type     string
	IsTaint  bool
}

// DataFlowEdge represents an edge in data flow graph
type DataFlowEdge struct {
	From *DataFlowNode
	To   *DataFlowNode
	Type string
}

// CallGraph represents function call relationships
type CallGraph struct {
	Nodes map[string]*CallGraphNode
	Edges []*CallGraphEdge
}

// CallGraphNode represents a function in call graph
type CallGraphNode struct {
	Function string
	Position Position
	IsSafe   bool
}

// CallGraphEdge represents a function call relationship
type CallGraphEdge struct {
	Caller *CallGraphNode
	Callee *CallGraphNode
	Site   Position
}

// NewSymbolTable creates a new symbol table
func NewSymbolTable() *SymbolTable {
	return &SymbolTable{
		Symbols:         make(map[string]*Symbol),
		Functions:       make(map[string]*FunctionSymbol),
		Classes:         make(map[string]*ClassSymbol),
		Variables:       make(map[string]*VariableSymbol),
		Scopes:          make([]*Scope, 0),
		SecurityContext: make(map[string]*SecurityContext),
		DataFlow:        &DataFlowGraph{Nodes: make(map[string]*DataFlowNode)},
		CallGraph:       &CallGraph{Nodes: make(map[string]*CallGraphNode)},
	}
}

// PushScope creates a new scope
func (st *SymbolTable) PushScope(scopeType ScopeType) *Scope {
	scope := &Scope{
		Parent:  st.CurrentScope,
		Symbols: make(map[string]*Symbol),
		Level:   len(st.Scopes),
		Type:    scopeType,
	}

	if st.CurrentScope != nil {
		st.CurrentScope.Children = append(st.CurrentScope.Children, scope)
	}

	st.Scopes = append(st.Scopes, scope)
	st.CurrentScope = scope
	return scope
}

// PopScope removes the current scope
func (st *SymbolTable) PopScope() {
	if st.CurrentScope != nil {
		st.CurrentScope = st.CurrentScope.Parent
	}
}

// AddSymbol adds a symbol to the current scope
func (st *SymbolTable) AddSymbol(symbol *Symbol) {
	if st.CurrentScope != nil {
		st.CurrentScope.Symbols[symbol.Name] = symbol
	}
	st.Symbols[symbol.Name] = symbol
}

// LookupSymbol looks up a symbol by name
func (st *SymbolTable) LookupSymbol(name string) *Symbol {
	scope := st.CurrentScope
	for scope != nil {
		if symbol, exists := scope.Symbols[name]; exists {
			return symbol
		}
		scope = scope.Parent
	}
	return nil
}

// ParseStats represents parsing statistics
type ParseStats struct {
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	NodesCreated int
	LinesOfCode  int
	FileSize     int64
	Language     string
	Errors       []error
	Warnings     []error
}

// AddError adds an error to parse stats
func (ps *ParseStats) AddError(err error) {
	ps.Errors = append(ps.Errors, err)
}

// AddWarning adds a warning to parse stats
func (ps *ParseStats) AddWarning(err error) {
	ps.Warnings = append(ps.Warnings, err)
}

// HasErrors returns true if there are parsing errors
func (ps *ParseStats) HasErrors() bool {
	return len(ps.Errors) > 0
}

// HasWarnings returns true if there are parsing warnings
func (ps *ParseStats) HasWarnings() bool {
	return len(ps.Warnings) > 0
}
