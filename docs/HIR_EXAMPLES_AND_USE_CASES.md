# HIR Examples và Use Cases - Ví dụ và Trường hợp sử dụng

## 📋 Tổng quan

Tài liệu này cung cấp các ví dụ thực tế và trường hợp sử dụng cụ thể cho hệ thống HIR (High-level Intermediate Representation).

## 🚀 Quick Start Examples

### 1. Basic HIR Analysis

```go
package main

import (
    "fmt"
    "log"
    "os"
    
    "github.com/le-company/security-scanner/internal/hir"
)

func main() {
    // 1. Tạo HIR program
    hirProgram := hir.NewHIRProgram()
    
    // 2. Tạo transformer
    transformer := hir.NewBasicTransformer(hirProgram)
    
    // 3. Đọc file PHP
    content, err := os.ReadFile("vulnerable.php")
    if err != nil {
        log.Fatal(err)
    }
    
    // 4. Transform sang HIR
    hirFile, err := transformer.TransformBasicFile("vulnerable.php", content)
    if err != nil {
        log.Fatal(err)
    }
    
    // 5. Thêm vào program
    hirProgram.AddFile(hirFile)
    
    // 6. Phân tích bảo mật
    analyzer := hir.NewHIRSecurityAnalyzer(hirProgram)
    findings, err := analyzer.AnalyzeFile(hirFile)
    if err != nil {
        log.Fatal(err)
    }
    
    // 7. In kết quả
    for _, finding := range findings {
        fmt.Printf("Vulnerability: %s at %s:%d\n", 
            finding.Type, finding.File, finding.Position)
    }
}
```

### 2. Incremental Analysis

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/le-company/security-scanner/internal/hir"
    "go.uber.org/zap"
)

func main() {
    // 1. Tạo logger
    logger, _ := zap.NewDevelopment()
    
    // 2. Tạo incremental analyzer
    analyzer, err := hir.NewIncrementalAnalyzer("/path/to/workspace", logger)
    if err != nil {
        log.Fatal(err)
    }
    defer analyzer.Close()
    
    // 3. Cấu hình analyzer
    analyzer.SetMaxDependencyDepth(3)
    analyzer.SetEnableTaintAnalysis(true)
    analyzer.SetEnableCallGraph(true)
    
    // 4. Thực hiện phân tích tăng dần
    request := &hir.AnalysisRequest{
        Files:        []string{"file1.php", "file2.php", "file3.php"},
        ChangedFiles: []string{"file1.php"},
        ForceRebuild: false,
    }
    
    response, err := analyzer.AnalyzeIncremental(request)
    if err != nil {
        log.Fatal(err)
    }
    
    // 5. Xử lý kết quả
    fmt.Printf("Analysis completed in %v\n", response.Duration)
    fmt.Printf("Processed files: %d\n", len(response.ProcessedFiles))
    fmt.Printf("Affected files: %d\n", len(response.AffectedFiles))
    fmt.Printf("Skipped files: %d\n", len(response.SkippedFiles))
    fmt.Printf("Security findings: %d\n", len(response.Findings))
    
    for _, finding := range response.Findings {
        fmt.Printf("- %s: %s at %s:%d\n", 
            finding.Severity, finding.Type, finding.File, finding.Position)
    }
}
```

## 🔍 Security Analysis Examples

### 1. SQL Injection Detection

**Vulnerable Code**:
```php
<?php
$userInput = $_GET['username'];
$query = "SELECT * FROM users WHERE name = '" . $userInput . "'";
$result = mysqli_query($connection, $query);
?>
```

**HIR Analysis**:
```go
func analyzeSQLInjection(hirFile *hir.HIRFile) {
    for _, unit := range hirFile.Units {
        if unit.Body != nil {
            for _, stmt := range unit.Body.Stmts {
                if stmt.Type == hir.HIRCall {
                    // Check for SQL injection pattern
                    if risk, ok := stmt.Meta["security_risk"].(string); ok && risk == "SQL Injection" {
                        fmt.Printf("SQL Injection detected at line %d\n", stmt.Position)
                        fmt.Printf("Code: %s\n", stmt.Meta["source_line"])
                    }
                }
            }
        }
    }
}
```

**Expected Output**:
```
SQL Injection detected at line 3
Code: $result = mysqli_query($connection, $query);
```

### 2. XSS Detection

**Vulnerable Code**:
```php
<?php
$userInput = $_GET['name'];
echo "<h1>Hello " . $userInput . "</h1>";
?>
```

**HIR Analysis**:
```go
func analyzeXSS(hirFile *hir.HIRFile) {
    for _, unit := range hirFile.Units {
        if unit.Body != nil {
            for _, stmt := range unit.Body.Stmts {
                if stmt.Type == hir.HIREcho {
                    // Check for XSS pattern
                    if risk, ok := stmt.Meta["security_risk"].(string); ok && risk == "Cross-Site Scripting (XSS)" {
                        fmt.Printf("XSS detected at line %d\n", stmt.Position)
                        fmt.Printf("Code: %s\n", stmt.Meta["source_line"])
                    }
                }
            }
        }
    }
}
```

**Expected Output**:
```
XSS detected at line 3
Code: echo "<h1>Hello " . $userInput . "</h1>";
```

### 3. Command Injection Detection

**Vulnerable Code**:
```php
<?php
$userInput = $_GET['command'];
system("ls " . $userInput);
?>
```

**HIR Analysis**:
```go
func analyzeCommandInjection(hirFile *hir.HIRFile) {
    for _, unit := range hirFile.Units {
        if unit.Body != nil {
            for _, stmt := range unit.Body.Stmts {
                if stmt.Type == hir.HIRCall {
                    // Check for command injection pattern
                    if risk, ok := stmt.Meta["security_risk"].(string); ok && risk == "Command Injection" {
                        fmt.Printf("Command Injection detected at line %d\n", stmt.Position)
                        fmt.Printf("Code: %s\n", stmt.Meta["source_line"])
                    }
                }
            }
        }
    }
}
```

**Expected Output**:
```
Command Injection detected at line 3
Code: system("ls " . $userInput);
```

## 🏗️ CFG Analysis Examples

### 1. Basic CFG Building

```go
func buildCFGExample() {
    // Tạo HIR unit
    unit := &hir.HIRUnit{
        Symbol: &hir.Symbol{
            ID:   "example::test_function",
            FQN:  "test_function",
            Kind: hir.SymFunction,
        },
        Body: &hir.HIRBlock{
            ID: 1,
            Stmts: []*hir.HIRStmt{
                {
                    ID:   1,
                    Type: hir.HIRAssign,
                    Meta: map[string]interface{}{
                        "variable": "x",
                        "value":    "1",
                    },
                },
                {
                    ID:   2,
                    Type: hir.HIRIf,
                    Meta: map[string]interface{}{
                        "condition": "x > 0",
                    },
                },
                {
                    ID:   3,
                    Type: hir.HIRReturn,
                    Meta: map[string]interface{}{
                        "value": "x",
                    },
                },
            },
        },
    }
    
    // Xây dựng CFG
    cfgBuilder := hir.NewCFGBuilder()
    cfg, err := cfgBuilder.BuildCFG(unit)
    if err != nil {
        log.Fatal(err)
    }
    
    // Phân tích CFG
    analyzer := hir.NewCFGAnalyzer(cfg)
    
    // Tính toán metrics
    metrics := analyzer.ComputeMetrics()
    fmt.Printf("Cyclomatic complexity: %d\n", metrics.CyclomaticComplexity)
    fmt.Printf("Node count: %d\n", metrics.NodeCount)
    fmt.Printf("Edge count: %d\n", metrics.EdgeCount)
    
    // Tìm loops
    loops := analyzer.GetLoops()
    fmt.Printf("Loops found: %d\n", len(loops))
    
    // Export CFG visualization
    visualizer := hir.NewCFGVisualizer(cfg)
    dotContent := visualizer.ToDotFormat()
    fmt.Println("CFG DOT format:")
    fmt.Println(dotContent)
}
```

### 2. Complex Control Flow Analysis

**Source Code**:
```php
<?php
function processUser($userId) {
    if ($userId <= 0) {
        return false;
    }
    
    $user = getUserById($userId);
    if (!$user) {
        return false;
    }
    
    while ($user->isActive) {
        $user->lastLogin = time();
        updateUser($user);
        
        if ($user->isAdmin) {
            logAdminActivity($user);
        }
    }
    
    return true;
}
```

**CFG Analysis**:
```go
func analyzeComplexCFG(hirFile *hir.HIRFile) {
    for _, unit := range hirFile.Units {
        if unit.CFG != nil {
            analyzer := hir.NewCFGAnalyzer(unit.CFG)
            
            // Tính toán dominators
            dominators := analyzer.GetDominators()
            fmt.Printf("Dominators for function %s:\n", unit.Symbol.FQN)
            for nodeID, doms := range dominators {
                fmt.Printf("  Node %d dominated by: %v\n", nodeID, doms)
            }
            
            // Tìm reachable nodes
            reachable := analyzer.GetReachableNodes()
            fmt.Printf("Reachable nodes: %d\n", len(reachable))
            
            // Tìm loops
            loops := analyzer.GetLoops()
            for _, loop := range loops {
                fmt.Printf("Loop: header=%d, latch=%d, nodes=%d\n", 
                    loop.Header.ID, loop.Latch.ID, len(loop.Nodes))
            }
            
            // Tính toán metrics
            metrics := analyzer.ComputeMetrics()
            fmt.Printf("Cyclomatic complexity: %d\n", metrics.CyclomaticComplexity)
            fmt.Printf("Max depth: %d\n", metrics.MaxDepth)
        }
    }
}
```

## 🔄 Incremental Analysis Examples

### 1. File Change Detection

```go
func detectFileChanges(workspacePath string) {
    // Tạo workspace index
    logger, _ := zap.NewDevelopment()
    workspace, err := hir.NewWorkspaceIndex(workspacePath, logger)
    if err != nil {
        log.Fatal(err)
    }
    defer workspace.Close()
    
    // Kiểm tra file status
    files := []string{"file1.php", "file2.php", "file3.php"}
    
    for _, filePath := range files {
        // Get file info
        fileInfo, err := os.Stat(filePath)
        if err != nil {
            continue
        }
        
        // Calculate hash
        hash := calculateFileHash(filePath)
        
        // Check if up to date
        upToDate, err := workspace.IsFileUpToDate(filePath, hash, fileInfo.ModTime())
        if err != nil {
            log.Printf("Error checking file %s: %v", filePath, err)
            continue
        }
        
        if upToDate {
            fmt.Printf("File %s is up to date\n", filePath)
        } else {
            fmt.Printf("File %s needs processing\n", filePath)
        }
    }
}
```

### 2. Dependency Analysis

```go
func analyzeDependencies(workspacePath string) {
    logger, _ := zap.NewDevelopment()
    analyzer, err := hir.NewIncrementalAnalyzer(workspacePath, logger)
    if err != nil {
        log.Fatal(err)
    }
    defer analyzer.Close()
    
    // Tìm files phụ thuộc
    changedFile := "core/User.php"
    dependents, err := analyzer.findDependentFiles(changedFile, 3)
    if err != nil {
        log.Printf("Error finding dependents: %v", err)
        return
    }
    
    fmt.Printf("Files dependent on %s:\n", changedFile)
    for _, dep := range dependents {
        fmt.Printf("- %s\n", dep)
    }
}
```

## 🛡️ Custom Security Rules

### 1. Tạo Custom Rule

```go
type CustomSQLInjectionRule struct {
    id          string
    name        string
    description string
    severity    hir.Severity
}

func NewCustomSQLInjectionRule() *CustomSQLInjectionRule {
    return &CustomSQLInjectionRule{
        id:          "CUSTOM-SQL-001",
        name:        "Custom SQL Injection Detection",
        description: "Advanced SQL injection detection with context analysis",
        severity:    hir.SeverityHigh,
    }
}

func (r *CustomSQLInjectionRule) ID() string {
    return r.id
}

func (r *CustomSQLInjectionRule) Name() string {
    return r.name
}

func (r *CustomSQLInjectionRule) Description() string {
    return r.description
}

func (r *CustomSQLInjectionRule) Severity() hir.Severity {
    return r.severity
}

func (r *CustomSQLInjectionRule) Check(file *hir.HIRFile, program *hir.HIRProgram) ([]*hir.SecurityFinding, error) {
    var findings []*hir.SecurityFinding
    
    for _, unit := range file.Units {
        if unit.Body != nil {
            for _, stmt := range unit.Body.Stmts {
                if r.isSQLInjectionVulnerable(stmt, unit) {
                    finding := &hir.SecurityFinding{
                        ID:          r.id,
                        Type:        hir.VulnSQLInjection,
                        Severity:    r.severity,
                        Confidence:  0.95,
                        Message:     "Advanced SQL injection vulnerability detected",
                        Description: "User input flows into SQL query without proper sanitization",
                        File:        file.Path,
                        Position:    stmt.Position,
                        CWE:         "CWE-89",
                        OWASP:       "A03:2021",
                        Remediation: "Use parameterized queries or prepared statements",
                    }
                    findings = append(findings, finding)
                }
            }
        }
    }
    
    return findings, nil
}

func (r *CustomSQLInjectionRule) isSQLInjectionVulnerable(stmt *hir.HIRStmt, unit *hir.HIRUnit) bool {
    // Advanced SQL injection detection logic
    if stmt.Type != hir.HIRCall {
        return false
    }
    
    // Check for SQL functions
    sqlFunctions := []string{"mysql_query", "mysqli_query", "pg_query", "sqlite_exec"}
    for _, funcName := range sqlFunctions {
        if strings.Contains(stmt.Meta["source_line"].(string), funcName) {
            // Check for string concatenation
            if strings.Contains(stmt.Meta["source_line"].(string), ".") {
                // Check for user input variables
                if strings.Contains(stmt.Meta["source_line"].(string), "$_") {
                    return true
                }
            }
        }
    }
    
    return false
}
```

### 2. Sử dụng Custom Rule

```go
func useCustomRule() {
    // Tạo HIR program
    hirProgram := hir.NewHIRProgram()
    
    // Tạo analyzer
    analyzer := hir.NewHIRSecurityAnalyzer(hirProgram)
    
    // Thêm custom rule
    customRule := NewCustomSQLInjectionRule()
    analyzer.AddRule(customRule)
    
    // Phân tích file
    // ... (code để load và analyze file)
}
```

## 📊 Performance Monitoring Examples

### 1. Memory Usage Monitoring

```go
func monitorMemoryUsage() {
    var m runtime.MemStats
    
    // Before analysis
    runtime.ReadMemStats(&m)
    fmt.Printf("Memory before: %d KB\n", m.Alloc/1024)
    
    // Perform analysis
    // ... (HIR analysis code)
    
    // After analysis
    runtime.ReadMemStats(&m)
    fmt.Printf("Memory after: %d KB\n", m.Alloc/1024)
    fmt.Printf("Memory delta: %d KB\n", (m.Alloc-allocBefore)/1024)
}
```

### 2. Performance Profiling

```go
func profileHIRAnalysis() {
    // Enable profiling
    f, err := os.Create("hir_analysis.prof")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    
    pprof.StartCPUProfile(f)
    defer pprof.StopCPUProfile()
    
    // Perform HIR analysis
    // ... (analysis code)
    
    // Memory profiling
    mf, err := os.Create("hir_analysis_mem.prof")
    if err != nil {
        log.Fatal(err)
    }
    defer mf.Close()
    
    pprof.WriteHeapProfile(mf)
}
```

### 3. Metrics Collection

```go
func collectMetrics(analyzer *hir.IncrementalAnalyzer) {
    metrics, err := analyzer.GetMetrics()
    if err != nil {
        log.Printf("Failed to get metrics: %v", err)
        return
    }
    
    fmt.Printf("Analysis Metrics:\n")
    fmt.Printf("- Files scanned: %d\n", metrics.FilesScanned)
    fmt.Printf("- Files up to date: %d\n", metrics.FilesUpToDate)
    fmt.Printf("- Files rebuilt: %d\n", metrics.FilesRebuilt)
    fmt.Printf("- Symbols extracted: %d\n", metrics.SymbolsExtracted)
    fmt.Printf("- Call graph edges: %d\n", metrics.CallGraphEdges)
    fmt.Printf("- Security findings: %d\n", metrics.SecurityFindings)
    fmt.Printf("- Cache hits: %d\n", metrics.CacheHits)
    fmt.Printf("- Cache misses: %d\n", metrics.CacheMisses)
    
    if metrics.CacheHits+metrics.CacheMisses > 0 {
        hitRate := float64(metrics.CacheHits) / float64(metrics.CacheHits+metrics.CacheMisses) * 100
        fmt.Printf("- Cache hit rate: %.2f%%\n", hitRate)
    }
}
```

## 🔧 Integration Examples

### 1. CI/CD Integration

```go
func integrateWithCI() {
    // Tạo analyzer
    logger, _ := zap.NewProduction()
    analyzer, err := hir.NewIncrementalAnalyzer(".", logger)
    if err != nil {
        log.Fatal(err)
    }
    defer analyzer.Close()
    
    // Lấy changed files từ git
    changedFiles := getChangedFilesFromGit()
    
    // Phân tích incremental
    request := &hir.AnalysisRequest{
        Files:        changedFiles,
        ChangedFiles: changedFiles,
        ForceRebuild: false,
    }
    
    response, err := analyzer.AnalyzeIncremental(request)
    if err != nil {
        log.Fatal(err)
    }
    
    // Kiểm tra findings
    if len(response.Findings) > 0 {
        fmt.Printf("Found %d security issues:\n", len(response.Findings))
        for _, finding := range response.Findings {
            fmt.Printf("- %s: %s at %s:%d\n", 
                finding.Severity, finding.Type, finding.File, finding.Position)
        }
        
        // Exit with error code nếu có critical issues
        for _, finding := range response.Findings {
            if finding.Severity == hir.SeverityCritical {
                os.Exit(1)
            }
        }
    }
}
```

### 2. IDE Integration

```go
func integrateWithIDE() {
    // Tạo LSP server
    server := lsp.NewServer()
    
    // Register HIR analysis handlers
    server.RegisterHandler("textDocument/didChange", handleDocumentChange)
    server.RegisterHandler("textDocument/didSave", handleDocumentSave)
    server.RegisterHandler("textDocument/didOpen", handleDocumentOpen)
    
    // Start server
    server.Start()
}

func handleDocumentChange(params lsp.DidChangeTextDocumentParams) {
    // Trigger incremental analysis
    analyzer := getIncrementalAnalyzer()
    
    request := &hir.AnalysisRequest{
        Files:        []string{params.TextDocument.URI},
        ChangedFiles: []string{params.TextDocument.URI},
        ForceRebuild: false,
    }
    
    response, err := analyzer.AnalyzeIncremental(request)
    if err != nil {
        log.Printf("Analysis failed: %v", err)
        return
    }
    
    // Send diagnostics to IDE
    for _, finding := range response.Findings {
        diagnostic := lsp.Diagnostic{
            Range: lsp.Range{
                Start: lsp.Position{Line: int(finding.Position) - 1, Character: 0},
                End:   lsp.Position{Line: int(finding.Position) - 1, Character: 100},
            },
            Severity: convertSeverity(finding.Severity),
            Message:  finding.Message,
            Source:   "HIR Security Scanner",
        }
        
        sendDiagnostic(diagnostic)
    }
}
```

## 🧪 Testing Examples

### 1. Unit Tests

```go
func TestHIRTransformation(t *testing.T) {
    tests := []struct {
        name     string
        code     string
        expected int
    }{
        {
            name: "SQL Injection",
            code: `<?php
$userInput = $_GET['input'];
$query = "SELECT * FROM users WHERE name = '" . $userInput . "'";
mysqli_query($connection, $query);
?>`,
            expected: 1,
        },
        {
            name: "XSS",
            code: `<?php
$userInput = $_GET['name'];
echo "<h1>Hello " . $userInput . "</h1>";
?>`,
            expected: 1,
        },
        {
            name: "Safe Code",
            code: `<?php
$userInput = $_GET['input'];
$query = "SELECT * FROM users WHERE name = ?";
$stmt = $pdo->prepare($query);
$stmt->execute([$userInput]);
?>`,
            expected: 0,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup
            hirProgram := hir.NewHIRProgram()
            transformer := hir.NewBasicTransformer(hirProgram)
            
            // Transform
            hirFile, err := transformer.TransformBasicFile("test.php", []byte(tt.code))
            assert.NoError(t, err)
            
            // Analyze
            analyzer := hir.NewHIRSecurityAnalyzer(hirProgram)
            findings, err := analyzer.AnalyzeFile(hirFile)
            assert.NoError(t, err)
            
            // Assert
            assert.Equal(t, tt.expected, len(findings))
        })
    }
}
```

### 2. Integration Tests

```go
func TestIncrementalAnalysis(t *testing.T) {
    // Setup workspace
    workspaceDir := t.TempDir()
    logger, _ := zap.NewDevelopment()
    
    analyzer, err := hir.NewIncrementalAnalyzer(workspaceDir, logger)
    assert.NoError(t, err)
    defer analyzer.Close()
    
    // Create test files
    testFiles := []string{"file1.php", "file2.php", "file3.php"}
    for _, file := range testFiles {
        content := fmt.Sprintf(`<?php
// Test file %s
$input = $_GET['input'];
echo $input;
?>`, file)
        
        err := os.WriteFile(filepath.Join(workspaceDir, file), []byte(content), 0644)
        assert.NoError(t, err)
    }
    
    // First analysis
    request := &hir.AnalysisRequest{
        Files:        testFiles,
        ChangedFiles: testFiles,
        ForceRebuild: true,
    }
    
    response, err := analyzer.AnalyzeIncremental(request)
    assert.NoError(t, err)
    assert.Greater(t, len(response.Findings), 0)
    
    // Second analysis (should be incremental)
    request2 := &hir.AnalysisRequest{
        Files:        testFiles,
        ChangedFiles: []string{}, // No changes
        ForceRebuild: false,
    }
    
    response2, err := analyzer.AnalyzeIncremental(request2)
    assert.NoError(t, err)
    assert.Equal(t, 0, len(response2.ProcessedFiles)) // Should skip all files
}
```

### 3. Benchmark Tests

```go
func BenchmarkHIRTransformation(b *testing.B) {
    // Load test file
    content, err := os.ReadFile("test_files/large_php_file.php")
    if err != nil {
        b.Skip("Test file not found")
    }
    
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

func BenchmarkIncrementalAnalysis(b *testing.B) {
    workspaceDir := b.TempDir()
    logger, _ := zap.NewDevelopment()
    
    analyzer, err := hir.NewIncrementalAnalyzer(workspaceDir, logger)
    if err != nil {
        b.Fatal(err)
    }
    defer analyzer.Close()
    
    // Setup test files
    // ... (setup code)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        request := &hir.AnalysisRequest{
            Files:        []string{"test.php"},
            ChangedFiles: []string{"test.php"},
            ForceRebuild: false,
        }
        
        _, err := analyzer.AnalyzeIncremental(request)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## 📚 Real-world Use Cases

### 1. E-commerce Security Audit

```go
func auditEcommerceSite(sitePath string) {
    logger, _ := zap.NewProduction()
    analyzer, err := hir.NewIncrementalAnalyzer(sitePath, logger)
    if err != nil {
        log.Fatal(err)
    }
    defer analyzer.Close()
    
    // Cấu hình cho e-commerce
    analyzer.SetMaxDependencyDepth(5) // Deep dependency analysis
    analyzer.SetEnableTaintAnalysis(true)
    analyzer.SetEnableCallGraph(true)
    
    // Phân tích toàn bộ site
    request := &hir.AnalysisRequest{
        Files:        getAllPHPFiles(sitePath),
        ChangedFiles: []string{},
        ForceRebuild: true,
    }
    
    response, err := analyzer.AnalyzeIncremental(request)
    if err != nil {
        log.Fatal(err)
    }
    
    // Phân loại findings theo mức độ nghiêm trọng
    critical := filterFindingsBySeverity(response.Findings, hir.SeverityCritical)
    high := filterFindingsBySeverity(response.Findings, hir.SeverityHigh)
    medium := filterFindingsBySeverity(response.Findings, hir.SeverityMedium)
    
    // Tạo báo cáo
    generateSecurityReport(critical, high, medium)
}
```

### 2. Legacy Code Migration

```go
func migrateLegacyCode(legacyPath string) {
    logger, _ := zap.NewDevelopment()
    analyzer, err := hir.NewIncrementalAnalyzer(legacyPath, logger)
    if err != nil {
        log.Fatal(err)
    }
    defer analyzer.Close()
    
    // Phân tích từng module
    modules := getModules(legacyPath)
    
    for _, module := range modules {
        fmt.Printf("Analyzing module: %s\n", module.Name)
        
        request := &hir.AnalysisRequest{
            Files:        module.Files,
            ChangedFiles: module.Files,
            ForceRebuild: true,
        }
        
        response, err := analyzer.AnalyzeIncremental(request)
        if err != nil {
            log.Printf("Failed to analyze module %s: %v", module.Name, err)
            continue
        }
        
        // Tạo migration plan
        migrationPlan := createMigrationPlan(response.Findings, module)
        saveMigrationPlan(module.Name, migrationPlan)
    }
}
```

### 3. Continuous Security Monitoring

```go
func continuousSecurityMonitoring() {
    logger, _ := zap.NewProduction()
    analyzer, err := hir.NewIncrementalAnalyzer(".", logger)
    if err != nil {
        log.Fatal(err)
    }
    defer analyzer.Close()
    
    // Monitor file changes
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        log.Fatal(err)
    }
    defer watcher.Close()
    
    // Watch for changes
    go func() {
        for {
            select {
            case event := <-watcher.Events:
                if event.Op&fsnotify.Write == fsnotify.Write {
                    // File changed, trigger analysis
                    go analyzeChangedFile(event.Name, analyzer)
                }
            case err := <-watcher.Errors:
                log.Printf("Watcher error: %v", err)
            }
        }
    }()
    
    // Add directories to watch
    err = watcher.Add(".")
    if err != nil {
        log.Fatal(err)
    }
    
    // Keep running
    select {}
}

func analyzeChangedFile(filePath string, analyzer *hir.IncrementalAnalyzer) {
    request := &hir.AnalysisRequest{
        Files:        []string{filePath},
        ChangedFiles: []string{filePath},
        ForceRebuild: false,
    }
    
    response, err := analyzer.AnalyzeIncremental(request)
    if err != nil {
        log.Printf("Analysis failed for %s: %v", filePath, err)
        return
    }
    
    if len(response.Findings) > 0 {
        // Send notification
        sendSecurityAlert(filePath, response.Findings)
    }
}
```

---

**Lưu ý**: Các ví dụ này được thiết kế để minh họa cách sử dụng HIR system. Trong thực tế, bạn có thể cần điều chỉnh để phù hợp với môi trường cụ thể của mình.
