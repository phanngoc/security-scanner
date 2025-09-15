# HIR Developer Guidelines - Hướng dẫn cho Developers

## 📋 Tổng quan

Tài liệu này cung cấp hướng dẫn chi tiết cho developers muốn hiểu, sử dụng và mở rộng hệ thống HIR (High-level Intermediate Representation) trong security scanner.

## 🎯 Mục tiêu

- Giúp developers hiểu nhanh về kiến trúc HIR
- Cung cấp hướng dẫn thực hành để sử dụng HIR
- Hướng dẫn cách mở rộng và tùy chỉnh hệ thống
- Best practices và common pitfalls

## 🚀 Quick Start

### 1. Hiểu cấu trúc cơ bản

```go
// HIR Program là cấu trúc trung tâm
type HIRProgram struct {
    Files           map[string]*HIRFile // filename -> HIR file
    Symbols         *GlobalSymbolTable  // Global symbol table
    CallGraph       *CallGraph          // Global call graph
    CFGs            map[SymbolID]*CFG   // function/method -> CFG
    DependencyGraph *DependencyGraph    // File dependency graph
    IncludeGraph    *IncludeGraph       // Include/require graph
}
```

### 2. Tạo HIR từ source code

```go
// Bước 1: Tạo HIR program
hirProgram := hir.NewHIRProgram()

// Bước 2: Tạo transformer
transformer := hir.NewBasicTransformer(hirProgram)

// Bước 3: Transform file
content, _ := os.ReadFile("example.php")
hirFile, err := transformer.TransformBasicFile("example.php", content)
if err != nil {
    log.Fatal(err)
}

// Bước 4: Thêm vào program
hirProgram.AddFile(hirFile)
```

### 3. Phân tích bảo mật

```go
// Tạo security analyzer
analyzer := hir.NewHIRSecurityAnalyzer(hirProgram)

// Phân tích file
findings, err := analyzer.AnalyzeFile(hirFile)
if err != nil {
    log.Fatal(err)
}

// Xử lý kết quả
for _, finding := range findings {
    fmt.Printf("Vulnerability: %s at %s:%d\n", 
        finding.Type, finding.File, finding.Position)
}
```

## 🏗️ Kiến trúc chi tiết

### 1. HIR Data Structures

#### HIRFile
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

#### HIRUnit (Function/Method)
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

#### HIRBlock (Basic Block)
```go
type HIRBlock struct {
    ID    BlockID        // Block identifier
    Stmts []*HIRStmt     // Statements in this block
    Preds []*HIRBlock    // Predecessor blocks
    Succs []*HIRBlock    // Successor blocks
}
```

### 2. Symbol System

#### Symbol Types
```go
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
```

#### Symbol Resolution
```go
// Resolve FQN considering use statements
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
    return "\\" + name
}
```

### 3. Control Flow Graph (CFG)

#### CFG Nodes
```go
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
```

#### CFG Building
```go
// Tạo CFG builder
cfgBuilder := hir.NewCFGBuilder()

// Xây dựng CFG cho unit
cfg, err := cfgBuilder.BuildCFG(unit)
if err != nil {
    log.Printf("CFG building failed: %v", err)
    return
}

// Lưu CFG
hirProgram.AddCFG(unit.Symbol.ID, cfg)
```

## 🔧 Sử dụng HIR trong thực tế

### 1. Tích hợp vào Scanner

```go
// Trong scanner.go
func (s *Scanner) analyzeWithHIR(job *FileJob) ([]*Finding, error) {
    // 1. Transform file content to HIR
    hirFile, err := s.hirTransformer.TransformBasicFile(job.Path, job.Content)
    if err != nil {
        return nil, fmt.Errorf("HIR transformation failed: %w", err)
    }
    
    // 2. Add file to HIR program
    s.hirProgram.AddFile(hirFile)
    
    // 3. Add symbols to global symbol table
    s.hirProgram.AddSymbols(hirFile.Symbols)
    
    // 4. Perform symbol linking
    if err := s.hirProgram.SafeSymbolLinking(); err != nil {
        return nil, fmt.Errorf("symbol linking failed: %w", err)
    }
    
    // 5. Create CFG for each unit
    for _, unit := range hirFile.Units {
        cfg, err := cfgBuilder.BuildCFG(unit)
        if err != nil {
            continue // Skip failed CFG
        }
        s.hirProgram.AddCFG(unit.Symbol.ID, cfg)
    }
    
    // 6. Run security analysis
    analyzer := hir.NewHIRSecurityAnalyzer(s.hirProgram)
    findings, err := analyzer.AnalyzeFile(hirFile)
    if err != nil {
        return nil, fmt.Errorf("security analysis failed: %w", err)
    }
    
    // 7. Convert to scanner findings
    return s.convertHIRFindingsToScannerFindings(findings, job), nil
}
```

### 2. Incremental Analysis

```go
// Sử dụng incremental analyzer
analyzer, err := hir.NewIncrementalAnalyzer(workspacePath, logger)
if err != nil {
    log.Fatal(err)
}

// Cấu hình analyzer
analyzer.SetMaxDependencyDepth(3)
analyzer.SetEnableTaintAnalysis(true)
analyzer.SetEnableCallGraph(true)

// Thực hiện phân tích tăng dần
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

### 3. Workspace Management

```go
// Tạo workspace index
workspace, err := hir.NewWorkspaceIndex(workspacePath, logger)
if err != nil {
    log.Fatal(err)
}

// Lưu file
fileRecord, err := workspace.StoreFile(hirFile, hash, mtime, size)
if err != nil {
    log.Fatal(err)
}

// Lưu symbols
err = workspace.StoreSymbols(fileRecord.ID, hirFile.Symbols)
if err != nil {
    log.Fatal(err)
}

// Lưu HIR units
for _, unit := range hirFile.Units {
    err = workspace.StoreHIRUnit(fileRecord.ID, unit)
    if err != nil {
        log.Fatal(err)
    }
}
```

## 🛡️ Tạo Security Rules mới

### 1. Implement HIRSecurityRule Interface

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
                // Check for specific patterns
                if r.isVulnerable(stmt) {
                    finding := &hir.SecurityFinding{
                        ID:          r.id,
                        Type:        hir.VulnSQLInjection, // or appropriate type
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

### 2. Đăng ký Rule

```go
func (hsa *HIRSecurityAnalyzer) registerCustomRules() {
    customRules := []HIRSecurityRule{
        &MyCustomRule{
            id:          "CUSTOM-001",
            name:        "My Custom Rule",
            description: "Detects custom security issues",
            severity:    hir.SeverityHigh,
        },
    }
    
    hsa.rules = append(hsa.rules, customRules...)
}
```

### 3. Sử dụng Dynamic Rule Engine

```go
// Tạo transformer với rule engine
ruleEngine := rules.NewDynamicRuleEngine(config)
transformer := hir.NewBasicTransformerWithRules(hirProgram, ruleEngine)

// Rule engine sẽ tự động load rules từ YAML files
```

## 🔍 Debugging và Troubleshooting

### 1. Enable Debug Logging

```go
// Cấu hình logger với debug level
config := zap.NewDevelopmentConfig()
config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
logger, _ := config.Build()

// Sử dụng trong HIR
analyzer := hir.NewHIRSecurityAnalyzer(hirProgram)
analyzer.SetLogger(logger)
```

### 2. HIR Visualization

```go
// Export CFG to DOT format
cfgVisualizer := hir.NewCFGVisualizer(cfg)
dotContent := cfgVisualizer.ToDotFormat()

// Save to file
err := os.WriteFile("cfg.dot", []byte(dotContent), 0644)
if err != nil {
    log.Printf("Failed to save CFG: %v", err)
}
```

### 3. Performance Profiling

```go
// Sử dụng pprof để profile
import _ "net/http/pprof"

go func() {
    log.Println(http.ListenAndServe("localhost:6060", nil))
}()

// Trong code HIR
func (hsa *HIRSecurityAnalyzer) AnalyzeFile(file *HIRFile) ([]*SecurityFinding, error) {
    // Profile memory usage
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    log.Printf("Memory before analysis: %d KB", m.Alloc/1024)
    
    // ... analysis code ...
    
    runtime.ReadMemStats(&m)
    log.Printf("Memory after analysis: %d KB", m.Alloc/1024)
    
    return findings, nil
}
```

## 📊 Performance Optimization

### 1. Memory Management

```go
// Sử dụng object pooling cho HIR objects
var hirFilePool = sync.Pool{
    New: func() interface{} {
        return &HIRFile{
            Symbols:  make([]*Symbol, 0, 100),
            Units:    make([]*HIRUnit, 0, 50),
            Includes: make([]*Include, 0, 20),
        }
    },
}

func getHIRFile() *HIRFile {
    return hirFilePool.Get().(*HIRFile)
}

func putHIRFile(file *HIRFile) {
    // Reset file
    file.Symbols = file.Symbols[:0]
    file.Units = file.Units[:0]
    file.Includes = file.Includes[:0]
    hirFilePool.Put(file)
}
```

### 2. Parallel Processing

```go
// Sử dụng worker pool cho HIR processing
func (s *Scanner) processFilesInParallel(files []string) {
    jobs := make(chan string, len(files))
    results := make(chan *HIRFile, len(files))
    
    // Start workers
    for i := 0; i < runtime.NumCPU(); i++ {
        go s.hirWorker(jobs, results)
    }
    
    // Send jobs
    for _, file := range files {
        jobs <- file
    }
    close(jobs)
    
    // Collect results
    for i := 0; i < len(files); i++ {
        hirFile := <-results
        s.hirProgram.AddFile(hirFile)
    }
}
```

### 3. Caching Strategy

```go
// Implement intelligent caching
type HIRCache struct {
    files    map[string]*HIRFile
    symbols  map[string][]*Symbol
    cfgs     map[string]*CFG
    mutex    sync.RWMutex
}

func (cache *HIRCache) GetFile(path string) (*HIRFile, bool) {
    cache.mutex.RLock()
    defer cache.mutex.RUnlock()
    
    file, exists := cache.files[path]
    return file, exists
}

func (cache *HIRCache) SetFile(path string, file *HIRFile) {
    cache.mutex.Lock()
    defer cache.mutex.Unlock()
    
    cache.files[path] = file
}
```

## 🧪 Testing HIR Components

### 1. Unit Tests

```go
func TestHIRTransformation(t *testing.T) {
    // Setup
    hirProgram := hir.NewHIRProgram()
    transformer := hir.NewBasicTransformer(hirProgram)
    
    // Test data
    content := []byte(`<?php
$userInput = $_GET['input'];
$query = "SELECT * FROM users WHERE name = '" . $userInput . "'";
mysqli_query($connection, $query);
?>`)
    
    // Transform
    hirFile, err := transformer.TransformBasicFile("test.php", content)
    assert.NoError(t, err)
    assert.NotNil(t, hirFile)
    
    // Verify HIR structure
    assert.Len(t, hirFile.Units, 1)
    assert.Len(t, hirFile.Symbols, 1)
    
    // Verify vulnerability detection
    unit := hirFile.Units[0]
    assert.Contains(t, unit.Body.Stmts[0].Meta, "security_risk")
    assert.Equal(t, "SQL Injection", unit.Body.Stmts[0].Meta["security_risk"])
}
```

### 2. Integration Tests

```go
func TestHIRSecurityAnalysis(t *testing.T) {
    // Setup
    hirProgram := hir.NewHIRProgram()
    transformer := hir.NewBasicTransformer(hirProgram)
    analyzer := hir.NewHIRSecurityAnalyzer(hirProgram)
    
    // Test files
    testFiles := []string{
        "test_sql_injection.php",
        "test_xss.php",
        "test_command_injection.php",
    }
    
    for _, testFile := range testFiles {
        content, err := os.ReadFile(testFile)
        assert.NoError(t, err)
        
        // Transform
        hirFile, err := transformer.TransformBasicFile(testFile, content)
        assert.NoError(t, err)
        
        // Add to program
        hirProgram.AddFile(hirFile)
        
        // Analyze
        findings, err := analyzer.AnalyzeFile(hirFile)
        assert.NoError(t, err)
        
        // Verify findings
        assert.Greater(t, len(findings), 0)
    }
}
```

### 3. Benchmark Tests

```go
func BenchmarkHIRTransformation(b *testing.B) {
    content := []byte(`<?php
// Large PHP file with many functions
function test1() { /* ... */ }
function test2() { /* ... */ }
// ... more functions
?>`)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        hirProgram := hir.NewHIRProgram()
        transformer := hir.NewBasicTransformer(hirProgram)
        _, err := transformer.TransformBasicFile("benchmark.php", content)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## 🚨 Common Pitfalls và Solutions

### 1. Memory Leaks

**Vấn đề**: HIR objects không được giải phóng đúng cách
**Giải pháp**:
```go
// Sử dụng defer để cleanup
func processFile(content []byte) error {
    hirProgram := hir.NewHIRProgram()
    defer func() {
        // Cleanup resources
        hirProgram = nil
    }()
    
    // ... processing code ...
}
```

### 2. Race Conditions

**Vấn đề**: Concurrent access đến HIR data structures
**Giải pháp**:
```go
// Sử dụng mutex cho thread-safe access
func (hp *HIRProgram) AddFile(file *HIRFile) {
    hp.mu.Lock()
    defer hp.mu.Unlock()
    hp.Files[file.Path] = file
}
```

### 3. Performance Issues

**Vấn đề**: HIR analysis quá chậm
**Giải pháp**:
- Sử dụng incremental analysis
- Implement caching
- Optimize pattern matching
- Use parallel processing

### 4. False Positives

**Vấn đề**: Quá nhiều false positives
**Giải pháp**:
```go
// Cải thiện pattern matching
func (t *BasicTransformer) isLikelySQLInjection(line string) bool {
    // Thêm context checks
    if strings.Contains(line, "return ") && !strings.Contains(line, "select") {
        return false
    }
    
    // Skip router, parser calls
    if strings.Contains(line, "router") || strings.Contains(line, "parse_url") {
        return false
    }
    
    // Must contain SQL keywords AND variable usage
    hasSQLKeywords := strings.Contains(line, "select") || strings.Contains(line, "insert")
    hasVariableUsage := strings.Contains(line, "$") && strings.Contains(line, ".")
    
    return hasSQLKeywords && hasVariableUsage
}
```

## 📚 Tài liệu tham khảo

### 1. Internal Documentation
- [HIR Architecture Guide](./HIR_ARCHITECTURE_GUIDE.md)
- [HIR Flow Run Guide](./HIR_FLOW_RUN_GUIDE.md)
- [API Documentation](./api.md)

### 2. External Resources
- [Go Concurrency Patterns](https://golang.org/doc/effective_go.html#concurrency)
- [SQLite Documentation](https://www.sqlite.org/docs.html)
- [Zap Logging](https://pkg.go.dev/go.uber.org/zap)

### 3. Security References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## 🤝 Contributing

### 1. Code Style
- Follow Go conventions
- Use meaningful variable names
- Add comprehensive comments
- Write unit tests

### 2. Pull Request Process
1. Fork repository
2. Create feature branch
3. Make changes
4. Add tests
5. Update documentation
6. Submit PR

### 3. Code Review Checklist
- [ ] Code follows Go conventions
- [ ] Tests are comprehensive
- [ ] Documentation is updated
- [ ] Performance impact is considered
- [ ] Security implications are reviewed

---

**Lưu ý**: Tài liệu này được cập nhật thường xuyên. Vui lòng kiểm tra phiên bản mới nhất và đóng góp cải thiện nếu cần.
