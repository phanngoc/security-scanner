# HIR API Reference - Tài liệu API

## 📋 Tổng quan

Tài liệu này cung cấp reference đầy đủ cho tất cả các API trong hệ thống HIR (High-level Intermediate Representation).

## 🏗️ Core APIs

### HIRProgram

#### NewHIRProgram()
```go
func NewHIRProgram() *HIRProgram
```
Tạo một HIR program mới.

**Returns**: `*HIRProgram` - HIR program instance

**Example**:
```go
hirProgram := hir.NewHIRProgram()
```

#### AddFile(file *HIRFile)
```go
func (hp *HIRProgram) AddFile(file *HIRFile)
```
Thêm file vào HIR program (thread-safe).

**Parameters**:
- `file *HIRFile` - HIR file cần thêm

**Example**:
```go
hirProgram.AddFile(hirFile)
```

#### GetFile(path string) (*HIRFile, bool)
```go
func (hp *HIRProgram) GetFile(path string) (*HIRFile, bool)
```
Lấy file từ HIR program (thread-safe).

**Parameters**:
- `path string` - Đường dẫn file

**Returns**:
- `*HIRFile` - HIR file nếu tìm thấy
- `bool` - true nếu tìm thấy, false nếu không

**Example**:
```go
hirFile, exists := hirProgram.GetFile("example.php")
if exists {
    fmt.Printf("Found file: %s\n", hirFile.Path)
}
```

#### AddSymbols(symbols []*Symbol)
```go
func (hp *HIRProgram) AddSymbols(symbols []*Symbol)
```
Thêm symbols vào global symbol table (thread-safe).

**Parameters**:
- `symbols []*Symbol` - Danh sách symbols cần thêm

**Example**:
```go
hirProgram.AddSymbols(hirFile.Symbols)
```

#### AddCFG(symbolID SymbolID, cfg *CFG)
```go
func (hp *HIRProgram) AddCFG(symbolID SymbolID, cfg *CFG)
```
Thêm CFG vào program (thread-safe).

**Parameters**:
- `symbolID SymbolID` - ID của symbol
- `cfg *CFG` - Control Flow Graph

**Example**:
```go
hirProgram.AddCFG(unit.Symbol.ID, cfg)
```

#### SafeSymbolLinking() error
```go
func (hp *HIRProgram) SafeSymbolLinking() error
```
Thực hiện symbol linking với proper locking.

**Returns**: `error` - Lỗi nếu có

**Example**:
```go
err := hirProgram.SafeSymbolLinking()
if err != nil {
    log.Fatal(err)
}
```

### BasicTransformer

#### NewBasicTransformer(program *HIRProgram) *BasicTransformer
```go
func NewBasicTransformer(program *HIRProgram) *BasicTransformer
```
Tạo basic transformer mới.

**Parameters**:
- `program *HIRProgram` - HIR program

**Returns**: `*BasicTransformer` - Transformer instance

**Example**:
```go
transformer := hir.NewBasicTransformer(hirProgram)
```

#### NewBasicTransformerWithRules(program *HIRProgram, ruleEngine *rules.DynamicRuleEngine) *BasicTransformer
```go
func NewBasicTransformerWithRules(program *HIRProgram, ruleEngine *rules.DynamicRuleEngine) *BasicTransformer
```
Tạo basic transformer với rule engine.

**Parameters**:
- `program *HIRProgram` - HIR program
- `ruleEngine *rules.DynamicRuleEngine` - Dynamic rule engine

**Returns**: `*BasicTransformer` - Transformer instance

**Example**:
```go
ruleEngine := rules.NewDynamicRuleEngine(config)
transformer := hir.NewBasicTransformerWithRules(hirProgram, ruleEngine)
```

#### TransformBasicFile(filePath string, content []byte) (*HIRFile, error)
```go
func (t *BasicTransformer) TransformBasicFile(filePath string, content []byte) (*HIRFile, error)
```
Chuyển đổi file thành HIR representation.

**Parameters**:
- `filePath string` - Đường dẫn file
- `content []byte` - Nội dung file

**Returns**:
- `*HIRFile` - HIR file
- `error` - Lỗi nếu có

**Example**:
```go
content, err := os.ReadFile("example.php")
if err != nil {
    log.Fatal(err)
}

hirFile, err := transformer.TransformBasicFile("example.php", content)
if err != nil {
    log.Fatal(err)
}
```

#### SetRuleEngine(ruleEngine *rules.DynamicRuleEngine)
```go
func (t *BasicTransformer) SetRuleEngine(ruleEngine *rules.DynamicRuleEngine)
```
Set rule engine cho transformer.

**Parameters**:
- `ruleEngine *rules.DynamicRuleEngine` - Rule engine

**Example**:
```go
transformer.SetRuleEngine(ruleEngine)
```

### CFGBuilder

#### NewCFGBuilder() *CFGBuilder
```go
func NewCFGBuilder() *CFGBuilder
```
Tạo CFG builder mới.

**Returns**: `*CFGBuilder` - CFG builder instance

**Example**:
```go
cfgBuilder := hir.NewCFGBuilder()
```

#### BuildCFG(unit *HIRUnit) (*CFG, error)
```go
func (cb *CFGBuilder) BuildCFG(unit *HIRUnit) (*CFG, error)
```
Xây dựng CFG cho HIR unit.

**Parameters**:
- `unit *HIRUnit` - HIR unit

**Returns**:
- `*CFG` - Control Flow Graph
- `error` - Lỗi nếu có

**Example**:
```go
cfg, err := cfgBuilder.BuildCFG(unit)
if err != nil {
    log.Printf("CFG building failed: %v", err)
    return
}
```

### CFGAnalyzer

#### NewCFGAnalyzer(cfg *CFG) *CFGAnalyzer
```go
func NewCFGAnalyzer(cfg *CFG) *CFGAnalyzer
```
Tạo CFG analyzer mới.

**Parameters**:
- `cfg *CFG` - Control Flow Graph

**Returns**: `*CFGAnalyzer` - CFG analyzer instance

**Example**:
```go
analyzer := hir.NewCFGAnalyzer(cfg)
```

#### GetDominators() map[BlockID]map[BlockID]bool
```go
func (ca *CFGAnalyzer) GetDominators() map[BlockID]map[BlockID]bool
```
Tính toán dominator sets cho tất cả nodes.

**Returns**: `map[BlockID]map[BlockID]bool` - Dominator sets

**Example**:
```go
dominators := analyzer.GetDominators()
for nodeID, doms := range dominators {
    fmt.Printf("Node %d is dominated by: %v\n", nodeID, doms)
}
```

#### GetReachableNodes() map[BlockID]bool
```go
func (ca *CFGAnalyzer) GetReachableNodes() map[BlockID]bool
```
Trả về tất cả nodes có thể reach từ entry.

**Returns**: `map[BlockID]bool` - Reachable nodes

**Example**:
```go
reachable := analyzer.GetReachableNodes()
fmt.Printf("Reachable nodes: %d\n", len(reachable))
```

#### GetLoops() []*Loop
```go
func (ca *CFGAnalyzer) GetLoops() []*Loop
```
Xác định natural loops trong CFG.

**Returns**: `[]*Loop` - Danh sách loops

**Example**:
```go
loops := analyzer.GetLoops()
for _, loop := range loops {
    fmt.Printf("Loop header: %d, latch: %d\n", loop.Header.ID, loop.Latch.ID)
}
```

#### ComputeMetrics() *CFGMetrics
```go
func (ca *CFGAnalyzer) ComputeMetrics() *CFGMetrics
```
Tính toán metrics cho CFG.

**Returns**: `*CFGMetrics` - CFG metrics

**Example**:
```go
metrics := analyzer.ComputeMetrics()
fmt.Printf("Cyclomatic complexity: %d\n", metrics.CyclomaticComplexity)
```

### CFGVisualizer

#### NewCFGVisualizer(cfg *CFG) *CFGVisualizer
```go
func NewCFGVisualizer(cfg *CFG) *CFGVisualizer
```
Tạo CFG visualizer mới.

**Parameters**:
- `cfg *CFG` - Control Flow Graph

**Returns**: `*CFGVisualizer` - CFG visualizer instance

**Example**:
```go
visualizer := hir.NewCFGVisualizer(cfg)
```

#### ToDotFormat() string
```go
func (cv *CFGVisualizer) ToDotFormat() string
```
Export CFG sang DOT format để visualization.

**Returns**: `string` - DOT format content

**Example**:
```go
dotContent := visualizer.ToDotFormat()
err := os.WriteFile("cfg.dot", []byte(dotContent), 0644)
if err != nil {
    log.Printf("Failed to save CFG: %v", err)
}
```

## 🗄️ Storage APIs

### WorkspaceIndex

#### NewWorkspaceIndex(workspacePath string, logger *zap.Logger) (*WorkspaceIndex, error)
```go
func NewWorkspaceIndex(workspacePath string, logger *zap.Logger) (*WorkspaceIndex, error)
```
Tạo workspace index mới.

**Parameters**:
- `workspacePath string` - Đường dẫn workspace
- `logger *zap.Logger` - Logger instance

**Returns**:
- `*WorkspaceIndex` - Workspace index instance
- `error` - Lỗi nếu có

**Example**:
```go
workspace, err := hir.NewWorkspaceIndex("/path/to/workspace", logger)
if err != nil {
    log.Fatal(err)
}
```

#### StoreFile(file *HIRFile, hash string, mtime time.Time, size int64) (*FileRecord, error)
```go
func (wi *WorkspaceIndex) StoreFile(file *HIRFile, hash string, mtime time.Time, size int64) (*FileRecord, error)
```
Lưu file vào workspace index.

**Parameters**:
- `file *HIRFile` - HIR file
- `hash string` - File hash
- `mtime time.Time` - Modification time
- `size int64` - File size

**Returns**:
- `*FileRecord` - File record
- `error` - Lỗi nếu có

**Example**:
```go
fileInfo, _ := os.Stat("example.php")
hash := calculateHash("example.php")
fileRecord, err := workspace.StoreFile(hirFile, hash, fileInfo.ModTime(), fileInfo.Size())
if err != nil {
    log.Fatal(err)
}
```

#### StoreSymbols(fileID int64, symbols []*Symbol) error
```go
func (wi *WorkspaceIndex) StoreSymbols(fileID int64, symbols []*Symbol) error
```
Lưu symbols vào workspace index.

**Parameters**:
- `fileID int64` - File ID
- `symbols []*Symbol` - Danh sách symbols

**Returns**: `error` - Lỗi nếu có

**Example**:
```go
err := workspace.StoreSymbols(fileRecord.ID, hirFile.Symbols)
if err != nil {
    log.Fatal(err)
}
```

#### StoreHIRUnit(fileID int64, unit *HIRUnit) error
```go
func (wi *WorkspaceIndex) StoreHIRUnit(fileID int64, unit *HIRUnit) error
```
Lưu HIR unit vào workspace index.

**Parameters**:
- `fileID int64` - File ID
- `unit *HIRUnit` - HIR unit

**Returns**: `error` - Lỗi nếu có

**Example**:
```go
err := workspace.StoreHIRUnit(fileRecord.ID, unit)
if err != nil {
    log.Fatal(err)
}
```

#### LoadHIRUnit(symbolID string) (*HIRUnit, error)
```go
func (wi *WorkspaceIndex) LoadHIRUnit(symbolID string) (*HIRUnit, error)
```
Load HIR unit từ workspace index.

**Parameters**:
- `symbolID string` - Symbol ID

**Returns**:
- `*HIRUnit` - HIR unit
- `error` - Lỗi nếu có

**Example**:
```go
unit, err := workspace.LoadHIRUnit("example.php::function1")
if err != nil {
    log.Printf("Failed to load unit: %v", err)
    return
}
```

#### IsFileUpToDate(path, hash string, mtime time.Time) (bool, error)
```go
func (wi *WorkspaceIndex) IsFileUpToDate(path, hash string, mtime time.Time) (bool, error)
```
Kiểm tra file có up-to-date không.

**Parameters**:
- `path string` - File path
- `hash string` - File hash
- `mtime time.Time` - Modification time

**Returns**:
- `bool` - true nếu up-to-date
- `error` - Lỗi nếu có

**Example**:
```go
upToDate, err := workspace.IsFileUpToDate("example.php", hash, mtime)
if err != nil {
    log.Printf("Failed to check file status: %v", err)
    return
}

if !upToDate {
    // File needs processing
}
```

#### Close() error
```go
func (wi *WorkspaceIndex) Close() error
```
Đóng database connection.

**Returns**: `error` - Lỗi nếu có

**Example**:
```go
err := workspace.Close()
if err != nil {
    log.Printf("Failed to close workspace: %v", err)
}
```

## 🔄 Incremental Analysis APIs

### IncrementalAnalyzer

#### NewIncrementalAnalyzer(workspacePath string, logger *zap.Logger) (*IncrementalAnalyzer, error)
```go
func NewIncrementalAnalyzer(workspacePath string, logger *zap.Logger) (*IncrementalAnalyzer, error)
```
Tạo incremental analyzer mới.

**Parameters**:
- `workspacePath string` - Đường dẫn workspace
- `logger *zap.Logger` - Logger instance

**Returns**:
- `*IncrementalAnalyzer` - Incremental analyzer instance
- `error` - Lỗi nếu có

**Example**:
```go
analyzer, err := hir.NewIncrementalAnalyzer("/path/to/workspace", logger)
if err != nil {
    log.Fatal(err)
}
```

#### AnalyzeIncremental(request *AnalysisRequest) (*AnalysisResponse, error)
```go
func (ia *IncrementalAnalyzer) AnalyzeIncremental(request *AnalysisRequest) (*AnalysisResponse, error)
```
Thực hiện incremental analysis.

**Parameters**:
- `request *AnalysisRequest` - Analysis request

**Returns**:
- `*AnalysisResponse` - Analysis response
- `error` - Lỗi nếu có

**Example**:
```go
request := &hir.AnalysisRequest{
    Files:        []string{"file1.php", "file2.php"},
    ChangedFiles: []string{"file1.php"},
    ForceRebuild: false,
}

response, err := analyzer.AnalyzeIncremental(request)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Processed %d files, found %d issues\n", 
    len(response.ProcessedFiles), len(response.Findings))
```

#### SetMaxDependencyDepth(depth int)
```go
func (ia *IncrementalAnalyzer) SetMaxDependencyDepth(depth int)
```
Set max dependency depth.

**Parameters**:
- `depth int` - Max depth

**Example**:
```go
analyzer.SetMaxDependencyDepth(3)
```

#### SetEnableTaintAnalysis(enable bool)
```go
func (ia *IncrementalAnalyzer) SetEnableTaintAnalysis(enable bool)
```
Enable/disable taint analysis.

**Parameters**:
- `enable bool` - Enable flag

**Example**:
```go
analyzer.SetEnableTaintAnalysis(true)
```

#### SetEnableCallGraph(enable bool)
```go
func (ia *IncrementalAnalyzer) SetEnableCallGraph(enable bool)
```
Enable/disable call graph building.

**Parameters**:
- `enable bool` - Enable flag

**Example**:
```go
analyzer.SetEnableCallGraph(true)
```

#### Close() error
```go
func (ia *IncrementalAnalyzer) Close() error
```
Đóng incremental analyzer.

**Returns**: `error` - Lỗi nếu có

**Example**:
```go
err := analyzer.Close()
if err != nil {
    log.Printf("Failed to close analyzer: %v", err)
}
```

## 🛡️ Security Analysis APIs

### HIRSecurityAnalyzer

#### NewHIRSecurityAnalyzer(program *HIRProgram) *HIRSecurityAnalyzer
```go
func NewHIRSecurityAnalyzer(program *HIRProgram) *HIRSecurityAnalyzer
```
Tạo HIR security analyzer mới.

**Parameters**:
- `program *HIRProgram` - HIR program

**Returns**: `*HIRSecurityAnalyzer` - Security analyzer instance

**Example**:
```go
analyzer := hir.NewHIRSecurityAnalyzer(hirProgram)
```

#### AnalyzeFile(file *HIRFile) ([]*SecurityFinding, error)
```go
func (hsa *HIRSecurityAnalyzer) AnalyzeFile(file *HIRFile) ([]*SecurityFinding, error)
```
Phân tích file để tìm security issues.

**Parameters**:
- `file *HIRFile` - HIR file

**Returns**:
- `[]*SecurityFinding` - Danh sách security findings
- `error` - Lỗi nếu có

**Example**:
```go
findings, err := analyzer.AnalyzeFile(hirFile)
if err != nil {
    log.Fatal(err)
}

for _, finding := range findings {
    fmt.Printf("Vulnerability: %s at %s:%d\n", 
        finding.Type, finding.File, finding.Position)
}
```

### HIRSecurityRule Interface

```go
type HIRSecurityRule interface {
    ID() string
    Name() string
    Description() string
    Severity() Severity
    Check(file *HIRFile, program *HIRProgram) ([]*SecurityFinding, error)
}
```

**Example Implementation**:
```go
type MyCustomRule struct {
    id          string
    name        string
    description string
    severity    hir.Severity
}

func (r *MyCustomRule) ID() string {
    return r.id
}

func (r *MyCustomRule) Name() string {
    return r.name
}

func (r *MyCustomRule) Description() string {
    return r.description
}

func (r *MyCustomRule) Severity() hir.Severity {
    return r.severity
}

func (r *MyCustomRule) Check(file *hir.HIRFile, program *hir.HIRProgram) ([]*hir.SecurityFinding, error) {
    var findings []*hir.SecurityFinding
    
    // Implement your security analysis logic here
    for _, unit := range file.Units {
        if unit.Body != nil {
            for _, stmt := range unit.Body.Stmts {
                if r.isVulnerable(stmt) {
                    finding := &hir.SecurityFinding{
                        ID:          r.id,
                        Type:        hir.VulnSQLInjection,
                        Severity:    r.severity,
                        Confidence:  0.9,
                        Message:     "Custom vulnerability detected",
                        Description: "Detailed description of the issue",
                        File:        file.Path,
                        Position:    stmt.Position,
                    }
                    findings = append(findings, finding)
                }
            }
        }
    }
    
    return findings, nil
}

func (r *MyCustomRule) isVulnerable(stmt *hir.HIRStmt) bool {
    // Implement your vulnerability detection logic
    return false
}
```

## 📊 Data Types

### HIRFile
```go
type HIRFile struct {
    Path     string      // File path
    Language string      // Programming language
    Symbols  []*Symbol   // Symbols in this file
    Units    []*HIRUnit  // Functions, methods, closures
    Includes []*Include  // Include/require statements
    Hash     string      // Content hash for invalidation
    ModTime  time.Time   // Modification time
}
```

### HIRUnit
```go
type HIRUnit struct {
    Symbol  *Symbol      // Symbol information
    Params  []*Variable  // Parameters
    Returns []*Variable  // Return values
    Body    *HIRBlock    // Function body
    CFG     *CFG         // Control Flow Graph
    IsSSA   bool         // Whether converted to SSA form
}
```

### HIRBlock
```go
type HIRBlock struct {
    ID    BlockID        // Block identifier
    Stmts []*HIRStmt     // Statements in this block
    Preds []*HIRBlock    // Predecessor blocks
    Succs []*HIRBlock    // Successor blocks
}
```

### HIRStmt
```go
type HIRStmt struct {
    ID       StmtID
    Type     HIRStmtType
    Operands []HIRValue
    Position token.Pos
    Span     Span
    Meta     map[string]interface{}
}
```

### Symbol
```go
type Symbol struct {
    ID       SymbolID
    FQN      string // Fully Qualified Name
    Kind     SymbolKind
    File     string
    Position token.Pos
    Span     Span
    Traits   SymbolTraits
    Meta     map[string]interface{}
}
```

### SecurityFinding
```go
type SecurityFinding struct {
    ID          string
    Type        VulnerabilityType
    Severity    Severity
    Confidence  float64
    Message     string
    Description string
    
    // Location information
    File     string
    Position token.Pos
    Span     Span
    
    // Security classification
    CWE   string
    OWASP string
    CVE   string
    
    // Dataflow information
    Sources  []SourceLocation
    Sinks    []SinkLocation
    DataFlow []DataFlowStep
    
    // Remediation
    Remediation string
    References  []string
}
```

## 🔧 Configuration

### AnalysisRequest
```go
type AnalysisRequest struct {
    Files        []string // Files to analyze
    ChangedFiles []string // Files that have changed
    ForceRebuild bool     // Force full rebuild
    MaxDepth     int      // Max dependency depth (0 = use default)
}
```

### AnalysisResponse
```go
type AnalysisResponse struct {
    ProcessedFiles []string           // Files that were processed
    AffectedFiles  []string           // Files affected by changes
    SkippedFiles   []string           // Files skipped (up to date)
    Findings       []*SecurityFinding // Security findings
    Metrics        *AnalysisMetrics   // Analysis metrics
    Duration       time.Duration      // Total analysis time
    Errors         []error            // Analysis errors
}
```

### AnalysisMetrics
```go
type AnalysisMetrics struct {
    FilesScanned     int
    FilesUpToDate    int
    FilesRebuilt     int
    SymbolsExtracted int
    CallGraphEdges   int
    DependencyEdges  int
    SecurityFindings int
    CacheHits        int
    CacheMisses      int
}
```

## 🚨 Error Handling

### Common Error Types

1. **Transformation Errors**
   - File read errors
   - Language detection failures
   - Pattern matching errors

2. **CFG Building Errors**
   - Invalid HIR structure
   - Circular dependencies
   - Missing control flow information

3. **Storage Errors**
   - Database connection failures
   - Serialization errors
   - File system errors

4. **Analysis Errors**
   - Rule execution failures
   - Memory allocation errors
   - Timeout errors

### Error Handling Best Practices

```go
// Always check for errors
hirFile, err := transformer.TransformBasicFile(filePath, content)
if err != nil {
    log.Printf("Transformation failed for %s: %v", filePath, err)
    return err
}

// Use context for cancellation
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Handle specific error types
switch err := someFunction(); err.(type) {
case *TransformationError:
    log.Printf("Transformation error: %v", err)
case *StorageError:
    log.Printf("Storage error: %v", err)
default:
    log.Printf("Unknown error: %v", err)
}
```

## 📈 Performance Considerations

### Memory Management
- Sử dụng object pooling cho HIR objects
- Implement proper cleanup
- Monitor memory usage

### Concurrency
- Sử dụng mutex cho thread-safe operations
- Implement proper locking strategies
- Avoid race conditions

### Caching
- Implement intelligent caching
- Use incremental analysis
- Cache expensive computations

---

**Lưu ý**: API này có thể thay đổi trong các phiên bản tương lai. Vui lòng kiểm tra changelog trước khi upgrade.
