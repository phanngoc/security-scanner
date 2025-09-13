package hir

import (
	"fmt"
	"go/token"
	"time"
)

// HIR (High-level Intermediate Representation) for multi-language security analysis
// This provides a simplified, stable IR for security analysis that abstracts
// away language-specific details while preserving security-relevant semantics

// HIRProgram represents the top-level HIR structure
type HIRProgram struct {
	Files           map[string]*HIRFile  // filename -> HIR file
	Symbols         *GlobalSymbolTable   // Global symbol table
	CallGraph       *CallGraph           // Global call graph
	CFGs            map[SymbolID]*CFG    // function/method -> CFG
	DependencyGraph *DependencyGraph     // File dependency graph
	IncludeGraph    *IncludeGraph        // Include/require graph
	CreatedAt       time.Time
}

// HIRFile represents a single file in HIR
type HIRFile struct {
	Path        string
	Language    string
	Symbols     []*Symbol
	Units       []*HIRUnit  // Functions, methods, closures
	Includes    []*Include  // Include/require statements
	Hash        string      // Content hash for invalidation
	ModTime     time.Time
}

// HIRUnit represents a function, method, or closure
type HIRUnit struct {
	Symbol   *Symbol
	Params   []*Variable
	Returns  []*Variable
	Body     *HIRBlock
	CFG      *CFG
	IsSSA    bool  // Whether converted to SSA form
}

// HIRBlock represents a basic block in HIR
type HIRBlock struct {
	ID    BlockID
	Stmts []*HIRStmt
	Preds []*HIRBlock  // Predecessor blocks
	Succs []*HIRBlock  // Successor blocks
}

type BlockID int

// HIRStmt represents statements in HIR (simplified from original AST)
type HIRStmt struct {
	ID       StmtID
	Type     HIRStmtType
	Operands []HIRValue
	Position token.Pos
	Span     Span
	Meta     map[string]interface{}
}

type StmtID int
type Span struct {
	Start, End token.Pos
}

type HIRStmtType int

const (
	// Core statements for security analysis
	HIRCall HIRStmtType = iota     // function/method call
	HIRAssign                      // assignment (=, +=, etc.)
	HIRConcat                      // string concatenation
	HIRInclude                     // include/require
	HIREcho                        // output (echo, print, etc.)
	HIRNew                         // object instantiation
	HIRArrayDim                    // array access
	HIRReturn                      // return statement
	HIRIf                          // conditional
	HIRLoop                        // loops (for, while, foreach)
	HIRThrow                       // throw exception
	HIRTryCatch                    // try-catch
	HIRSwitch                      // switch statement
	HIRBreak                       // break/continue
	HIRYield                       // yield (generators)
	HIRGoto                        // goto (if supported)
	HIRFieldAccess                 // object property access
	HIRStaticAccess                // static property/method access
	HIRCast                        // type casting
	HIRBinaryOp                    // binary operations
	HIRUnaryOp                     // unary operations
	HIRPhi                         // SSA phi node
)

// HIRValue represents values in HIR
type HIRValue interface {
	GetType() HIRValueType
	IsConstant() bool
	IsTainted() bool
	GetTaintSources() []TaintSource
	String() string
}

type HIRValueType int

const (
	HIRVariable HIRValueType = iota
	HIRConstant
	HIRFunction
	HIRClass
	HIRArray
	HIRSuperglobal
	HIRPhiValue
)

// Variable represents variables in HIR
type Variable struct {
	ID           VariableID
	Name         string
	Type         string
	tainted      bool          // private field to avoid method conflict
	TaintSources []TaintSource
	DefSites     []StmtID     // Definition sites (for SSA)
	UseSites     []StmtID     // Use sites
	Scope        ScopeType
}

type VariableID int

// TaintSource represents where taint originates
type TaintSource struct {
	Kind     TaintKind
	Location token.Pos
	Details  string
}

type TaintKind int

const (
	TaintUserInput TaintKind = iota  // $_GET, $_POST, etc.
	TaintDatabase                    // Database results
	TaintFile                        // File contents
	TaintNetwork                     // Network responses
	TaintArgument                    // Function arguments
	TaintReturn                      // Function returns
	TaintGlobal                      // Global variables
	TaintSession                     // Session data
	TaintCookie                      // Cookie data
	TaintHeader                      // HTTP headers
)

// ScopeType represents variable scope
type ScopeType int

const (
	ScopeGlobal ScopeType = iota
	ScopeFunction
	ScopeClass
	ScopeMethod
	ScopeLocal
	ScopeParameter
)

// Symbol represents various symbol types
type Symbol struct {
	ID       SymbolID
	FQN      string        // Fully Qualified Name
	Kind     SymbolKind
	File     string
	Position token.Pos
	Span     Span
	Traits   SymbolTraits
	Meta     map[string]interface{}
}

type SymbolID string

type SymbolKind int

const (
	SymFunction SymbolKind = iota
	SymMethod
	SymClass
	SymInterface
	SymTrait
	SymConst
	SymProperty
	SymGlobalVar
	SymNamespace
	SymUse
	SymClosure
)

// SymbolTraits contains additional symbol information
type SymbolTraits struct {
	Visibility   Visibility
	IsStatic     bool
	IsAbstract   bool
	IsFinal      bool
	IsAsync      bool
	IsGenerator  bool
	IsMagic      bool      // __construct, __destruct, etc.
	SecurityTags []string  // @security, @trusted, etc.
}

type Visibility int

const (
	VisPublic Visibility = iota
	VisProtected
	VisPrivate
)

// GlobalSymbolTable manages symbols across files
type GlobalSymbolTable struct {
	Symbols    map[SymbolID]*Symbol
	ByKind     map[SymbolKind][]*Symbol
	ByFile     map[string][]*Symbol
	Namespaces map[string]*Namespace
	Uses       map[string]*UseBinding  // alias -> FQN mapping
	PSR4       map[string]string       // namespace prefix -> path
}

// Namespace represents a namespace scope
type Namespace struct {
	FQN     string
	Symbols map[string]*Symbol
	Uses    map[string]string  // local alias -> FQN
}

// UseBinding represents use/import statements
type UseBinding struct {
	Alias  string
	FQN    string
	Kind   UseKind
	File   string
}

type UseKind int

const (
	UseClass UseKind = iota
	UseFunction
	UseConstant
)

// Include represents include/require statements
type Include struct {
	Type     IncludeType
	Path     string      // Resolved path (best effort)
	PathExpr HIRValue    // Original expression
	IsStatic bool        // Can be resolved statically
}

type IncludeType int

const (
	IncludeOnce IncludeType = iota
	IncludeNormal
	RequireOnce
	Require
)

// CFG (Control Flow Graph) for function/method analysis
type CFG struct {
	Entry    *CFGNode
	Exit     *CFGNode
	Nodes    map[BlockID]*CFGNode
	Edges    []*CFGEdge
	Function *Symbol
}

// CFGNode represents a node in the control flow graph
type CFGNode struct {
	ID    BlockID
	Block *HIRBlock
	Kind  CFGNodeKind
}

type CFGNodeKind int

const (
	CFGEntry CFGNodeKind = iota
	CFGExit
	CFGBasic
	CFGConditional
	CFGLoop
	CFGTry
	CFGCatch
	CFGFinally
)

// CFGEdge represents an edge in the control flow graph
type CFGEdge struct {
	From      *CFGNode
	To        *CFGNode
	Condition HIRValue  // For conditional edges
	Kind      CFGEdgeKind
}

type CFGEdgeKind int

const (
	CFGFallthrough CFGEdgeKind = iota
	CFGTrue
	CFGFalse
	CFGThrow
	CFGReturn
	CFGBreak
	CFGContinue
)

// CallGraph represents function call relationships
type CallGraph struct {
	Nodes map[SymbolID]*CallNode
	Edges []*CallEdge
}

// CallNode represents a function/method in the call graph
type CallNode struct {
	Symbol   *Symbol
	Callers  []*CallEdge
	Callees  []*CallEdge
	IsEntry  bool  // Entry point (main, constructor, etc.)
}

// CallEdge represents a call relationship
type CallEdge struct {
	Caller   *CallNode
	Callee   *CallNode
	CallSite token.Pos
	IsDirect bool      // Direct vs. indirect call
	Context  string    // Additional context
}

// SSA (Static Single Assignment) support for better taint tracking
type SSAValue struct {
	Variable  *Variable
	Version   int
	DefSite   StmtID
	PhiInputs []*SSAValue  // For phi nodes
}

// PhiNode represents SSA phi nodes
type PhiNode struct {
	Target  *SSAValue
	Inputs  []*SSAValue
	Block   *HIRBlock
}

// Security Analysis Support

// SecurityContext provides security-relevant information
type SecurityContext struct {
	TaintedVars    map[VariableID]*TaintInfo
	SinkLocations  []SinkLocation
	SourceLocations []SourceLocation
	Sanitizers     []SanitizerLocation
	Barriers       []BarrierLocation
}

// TaintInfo tracks taint propagation
type TaintInfo struct {
	Variable    *Variable
	Sources     []TaintSource
	Propagation []TaintPropagation
	IsSanitized bool
	Sanitizers  []SanitizerLocation
}

// TaintPropagation represents how taint flows
type TaintPropagation struct {
	From     VariableID
	To       VariableID
	Via      StmtID     // Statement that caused propagation
	Method   PropagationMethod
}

type PropagationMethod int

const (
	PropAssignment PropagationMethod = iota
	PropConcat
	PropFunctionCall
	PropReturn
	PropArrayAccess
	PropFieldAccess
)

// SinkLocation represents a potential vulnerability sink
type SinkLocation struct {
	Position token.Pos
	Type     SinkType
	Function string
	Variable VariableID
}

type SinkType int

const (
	SinkSQL SinkType = iota
	SinkXSS
	SinkCommand
	SinkFile
	SinkEval
	SinkHeader
	SinkRedirect
	SinkLog
	SinkCrypto
)

// SourceLocation represents taint sources
type SourceLocation struct {
	Position token.Pos
	Type     SourceType
	Variable VariableID
}

type SourceType int

const (
	SourceUserInput SourceType = iota
	SourceDatabase
	SourceFile
	SourceNetwork
	SourceEnvironment
)

// SanitizerLocation represents sanitization points
type SanitizerLocation struct {
	Position  token.Pos
	Function  string
	Type      SanitizerType
	Variable  VariableID
}

type SanitizerType int

const (
	SanitizeHTML SanitizerType = iota
	SanitizeSQL
	SanitizeShell
	SanitizePath
	SanitizeURL
	SanitizeEmail
)

// BarrierLocation represents security barriers (auth checks, etc.)
type BarrierLocation struct {
	Position token.Pos
	Type     BarrierType
	Condition HIRValue
}

type BarrierType int

const (
	BarrierAuth BarrierType = iota
	BarrierPermission
	BarrierValidation
	BarrierRateLimit
	BarrierCSRF
)

// Analysis Results

// HIRAnalysisResult contains analysis results for HIR
type HIRAnalysisResult struct {
	Program    *HIRProgram
	Context    *SecurityContext
	Findings   []*SecurityFinding
	Metrics    *HIRMetrics
	Duration   time.Duration
}

// SecurityFinding represents a security vulnerability found via HIR analysis
type SecurityFinding struct {
	ID          string
	Type        VulnerabilityType
	Severity    Severity
	Confidence  float64
	Message     string
	Description string
	
	// Location information
	File        string
	Position    token.Pos
	Span        Span
	
	// Security classification
	CWE         string
	OWASP       string
	CVE         string
	
	// Dataflow information
	Sources     []SourceLocation
	Sinks       []SinkLocation
	DataFlow    []DataFlowStep
	
	// Remediation
	Remediation string
	References  []string
}

type VulnerabilityType int

const (
	VulnSQLInjection VulnerabilityType = iota
	VulnXSS
	VulnCommandInjection
	VulnPathTraversal
	VulnFileInclusion
	VulnCodeInjection
	VulnLDAPInjection
	VulnXXE
	VulnDeserialize
	VulnAuthBypass
	VulnPrivEscalation
	VulnCSRF
	VulnSessionFixation
	VulnWeakCrypto
	VulnHardcodedSecret
	VulnInsecureTransport
	VulnBufferOverflow
	VulnRaceCondition
	VulnDOS
	VulnInformationDisclosure
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// DataFlowStep represents a step in data flow analysis
type DataFlowStep struct {
	Position   token.Pos
	Operation  string
	Variable   VariableID
	Tainted    bool
	Sanitized  bool
}

// HIRMetrics contains metrics about HIR analysis
type HIRMetrics struct {
	FilesAnalyzed    int
	SymbolsExtracted int
	CFGsGenerated    int
	CallGraphEdges   int
	TaintPaths       int
	SecurityFindings int
	AnalysisTime     time.Duration
}

// Builder and utility functions

// NewHIRProgram creates a new HIR program
func NewHIRProgram() *HIRProgram {
	return &HIRProgram{
		Files:     make(map[string]*HIRFile),
		Symbols:   NewGlobalSymbolTable(),
		CallGraph: NewCallGraph(),
		CFGs:      make(map[SymbolID]*CFG),
		CreatedAt: time.Now(),
	}
}

// NewGlobalSymbolTable creates a new global symbol table
func NewGlobalSymbolTable() *GlobalSymbolTable {
	return &GlobalSymbolTable{
		Symbols:    make(map[SymbolID]*Symbol),
		ByKind:     make(map[SymbolKind][]*Symbol),
		ByFile:     make(map[string][]*Symbol),
		Namespaces: make(map[string]*Namespace),
		Uses:       make(map[string]*UseBinding),
		PSR4:       make(map[string]string),
	}
}

// NewCallGraph creates a new call graph
func NewCallGraph() *CallGraph {
	return &CallGraph{
		Nodes: make(map[SymbolID]*CallNode),
		Edges: make([]*CallEdge, 0),
	}
}

// AddSymbol adds a symbol to the global symbol table
func (gst *GlobalSymbolTable) AddSymbol(symbol *Symbol) {
	gst.Symbols[symbol.ID] = symbol
	gst.ByKind[symbol.Kind] = append(gst.ByKind[symbol.Kind], symbol)
	gst.ByFile[symbol.File] = append(gst.ByFile[symbol.File], symbol)
}

// GetSymbol retrieves a symbol by ID
func (gst *GlobalSymbolTable) GetSymbol(id SymbolID) *Symbol {
	return gst.Symbols[id]
}

// GetSymbolsByKind returns all symbols of a specific kind
func (gst *GlobalSymbolTable) GetSymbolsByKind(kind SymbolKind) []*Symbol {
	return gst.ByKind[kind]
}

// ResolveFQN resolves a fully qualified name considering use statements
func (gst *GlobalSymbolTable) ResolveFQN(name string, file string) string {
	// Check if it's already an FQN
	if name[0] == '\\' {
		return name
	}
	
	// Check use bindings for this file
	if binding, exists := gst.Uses[file+"::"+name]; exists {
		return binding.FQN
	}
	
	// Default to current namespace + name
	// This is simplified - real implementation would track namespace context
	return "\\" + name
}

// Helper functions for taint analysis

// IsTainted checks if a variable is tainted
func (v *Variable) IsTainted() bool {
	return v.tainted
}

// GetTaintSources returns taint sources for a variable
func (v *Variable) GetTaintSources() []TaintSource {
	return v.TaintSources
}

// AddTaintSource adds a taint source to a variable
func (v *Variable) AddTaintSource(source TaintSource) {
	v.TaintSources = append(v.TaintSources, source)
	v.tainted = true
}

// String implementations for debugging

func (st HIRStmtType) String() string {
	names := []string{
		"Call", "Assign", "Concat", "Include", "Echo", "New", "ArrayDim",
		"Return", "If", "Loop", "Throw", "TryCatch", "Switch", "Break",
		"Yield", "Goto", "FieldAccess", "StaticAccess", "Cast", "BinaryOp",
		"UnaryOp", "Phi",
	}
	if int(st) < len(names) {
		return names[st]
	}
	return fmt.Sprintf("HIRStmtType(%d)", st)
}

func (sk SymbolKind) String() string {
	names := []string{
		"Function", "Method", "Class", "Interface", "Trait", "Const",
		"Property", "GlobalVar", "Namespace", "Use", "Closure",
	}
	if int(sk) < len(names) {
		return names[sk]
	}
	return fmt.Sprintf("SymbolKind(%d)", sk)
}

func (vt VulnerabilityType) String() string {
	names := []string{
		"SQLInjection", "XSS", "CommandInjection", "PathTraversal",
		"FileInclusion", "CodeInjection", "LDAPInjection", "XXE",
		"Deserialization", "AuthBypass", "PrivEscalation", "CSRF",
		"SessionFixation", "WeakCrypto", "HardcodedSecret",
		"InsecureTransport", "BufferOverflow", "RaceCondition",
		"DOS", "InformationDisclosure",
	}
	if int(vt) < len(names) {
		return names[vt]
	}
	return fmt.Sprintf("VulnerabilityType(%d)", vt)
}

func (s Severity) String() string {
	names := []string{"Info", "Low", "Medium", "High", "Critical"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("Severity(%d)", s)
}