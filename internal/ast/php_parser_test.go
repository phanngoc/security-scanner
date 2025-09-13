package ast

import (
	"testing"
)

func TestSimplePHPASTParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		phpCode  string
		wantErr  bool
		checkAST func(*ProgramNode) bool
	}{
		{
			name: "simple PHP script",
			phpCode: `<?php
echo "Hello World";
?>`,
			wantErr: false,
			checkAST: func(ast *ProgramNode) bool {
				return ast.Language == "php" && len(ast.Children) > 0
			},
		},
		{
			name: "PHP function definition",
			phpCode: `<?php
function test($param) {
    return $param * 2;
}
?>`,
			wantErr: false,
			checkAST: func(ast *ProgramNode) bool {
				return len(ast.Functions) > 0 && ast.Functions[0].Name == "test"
			},
		},
		{
			name: "PHP class definition",
			phpCode: `<?php
class TestClass {
    private $property;
    
    public function method() {
        return $this->property;
    }
}
?>`,
			wantErr: false,
			checkAST: func(ast *ProgramNode) bool {
				return len(ast.Classes) > 0 && ast.Classes[0].Name == "TestClass"
			},
		},
		{
			name: "PHP with SQL injection vulnerability",
			phpCode: `<?php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
mysqli_query($connection, $query);
?>`,
			wantErr: false,
			checkAST: func(ast *ProgramNode) bool {
				return len(ast.Variables) > 0 || len(ast.Children) > 0
			},
		},
		{
			name: "invalid PHP syntax",
			phpCode: `<?php
function test( {
    echo "broken";
}
?>`,
			wantErr: true,
			checkAST: func(ast *ProgramNode) bool {
				return ast == nil
			},
		},
	}

	parser := NewSimplePHPASTParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, stats, err := parser.Parse([]byte(tt.phpCode), "test.php")

			if (err != nil) != tt.wantErr {
				t.Errorf("SimplePHPASTParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if ast == nil {
					t.Error("Expected AST but got nil")
					return
				}

				if stats == nil {
					t.Error("Expected stats but got nil")
					return
				}

				if !tt.checkAST(ast) {
					t.Error("AST validation failed")
				}

				// Verify stats
				if stats.Language != "php" {
					t.Errorf("Expected language 'php', got %s", stats.Language)
				}

				if stats.NodesCreated == 0 && !tt.wantErr {
					t.Error("Expected nodes to be created")
				}
			}
		})
	}
}

func TestSimplePHPASTParser_BuildSymbolTable(t *testing.T) {
	phpCode := `<?php
class TestClass {
    private $property = "value";
    
    public function testMethod($param1, $param2) {
        $local_var = $param1 + $param2;
        return $local_var;
    }
}

function globalFunction($arg) {
    return $arg * 2;
}

$global_var = "test";
?>`

	parser := NewSimplePHPASTParser()
	ast, _, err := parser.Parse([]byte(phpCode), "test.php")

	if err != nil {
		t.Fatalf("Failed to parse PHP code: %v", err)
	}

	symbolTable, err := parser.BuildSymbolTable(ast)
	if err != nil {
		t.Fatalf("Failed to build symbol table: %v", err)
	}

	// Check if symbol table was created
	if symbolTable == nil {
		t.Fatal("Symbol table is nil")
	}

	// Check if symbols were extracted
	if len(symbolTable.Functions) == 0 {
		t.Error("No functions found in symbol table")
	}

	if len(symbolTable.Classes) == 0 {
		t.Error("No classes found in symbol table")
	}

	// Verify specific symbols
	if _, exists := symbolTable.Functions["globalFunction"]; !exists {
		t.Error("Global function not found in symbol table")
	}

	if _, exists := symbolTable.Classes["TestClass"]; !exists {
		t.Error("Test class not found in symbol table")
	}
}

func TestSecurityRuleEngine_AnalyzeAST(t *testing.T) {
	vulnerableCode := `<?php
// SQL Injection vulnerability
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
mysqli_query($connection, $query);

// XSS vulnerability  
$user_input = $_POST['comment'];
echo $user_input;

// Command injection vulnerability
$filename = $_GET['file'];
exec("cat " . $filename);

// Hardcoded secret
$api_key = "secret_key_12345678901234567890";
?>`

	parser := NewSimplePHPASTParser()
	ast, _, err := parser.Parse([]byte(vulnerableCode), "vulnerable.php")

	if err != nil {
		t.Fatalf("Failed to parse vulnerable code: %v", err)
	}

	symbolTable, err := parser.BuildSymbolTable(ast)
	if err != nil {
		t.Fatalf("Failed to build symbol table: %v", err)
	}

	// Mark variables as tainted (simulate user input detection)
	if userIdVar, exists := symbolTable.Variables["user_id"]; exists {
		userIdVar.IsTainted = true
		userIdVar.TaintSources = []string{"_GET"}
	}

	if userInputVar, exists := symbolTable.Variables["user_input"]; exists {
		userInputVar.IsTainted = true
		userInputVar.TaintSources = []string{"_POST"}
	}

	if filenameVar, exists := symbolTable.Variables["filename"]; exists {
		filenameVar.IsTainted = true
		filenameVar.TaintSources = []string{"_GET"}
	}

	ruleEngine := NewSecurityRuleEngine()
	findings, err := ruleEngine.AnalyzeAST(ast, symbolTable)

	if err != nil {
		t.Fatalf("Security analysis failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("Expected security findings but got none")
	}

	// Check for specific vulnerability types
	foundSQL := false
	foundXSS := false
	foundCmd := false
	foundSecret := false

	for _, finding := range findings {
		switch {
		case finding.RuleID == "SQL-001" || finding.RuleID == "SQL-002":
			foundSQL = true
		case finding.RuleID == "XSS-001" || finding.RuleID == "XSS-002":
			foundXSS = true
		case finding.RuleID == "CMD-001":
			foundCmd = true
		case finding.RuleID == "SEC-001":
			foundSecret = true
		}
	}

	if !foundSQL {
		t.Error("Expected SQL injection finding")
	}

	if !foundXSS {
		t.Error("Expected XSS finding")
	}

	if !foundCmd {
		t.Error("Expected command injection finding")
	}

	if !foundSecret {
		t.Error("Expected hardcoded secret finding")
	}

	t.Logf("Found %d security findings:", len(findings))
	for _, finding := range findings {
		t.Logf("- %s: %s (Severity: %v)", finding.RuleID, finding.Message, finding.Severity)
	}
}

func TestParserIntegration(t *testing.T) {
	phpCode := `<?php
class DatabaseConnection {
    private $host = "localhost";
    private $password = "hardcoded_password_123";
    
    public function query($sql) {
        return mysqli_query($this->connection, $sql);
    }
}

$user_data = $_POST['data'];
$db = new DatabaseConnection();
$result = $db->query("SELECT * FROM users WHERE name = '" . $user_data . "'");
echo $result;
?>`

	integration := NewParserIntegration(nil) // Using nil logger for test

	result, err := integration.ParseAndAnalyze("test.php", []byte(phpCode))
	if err != nil {
		t.Fatalf("Integration analysis failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected analysis result but got nil")
	}

	// Check result properties
	if result.Language != "php" {
		t.Errorf("Expected language 'php', got %s", result.Language)
	}

	if result.AST == nil {
		t.Error("Expected AST but got nil")
	}

	if result.SymbolTable == nil {
		t.Error("Expected symbol table but got nil")
	}

	if result.Metrics == nil {
		t.Error("Expected metrics but got nil")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected security findings but got none")
	}

	// Test helper methods
	if !result.HasHighSeverityFindings() && len(result.Findings) > 0 {
		// Check if there are any high severity findings
		hasHigh := false
		for _, finding := range result.Findings {
			if finding.Severity == SeverityHigh {
				hasHigh = true
				break
			}
		}
		if hasHigh {
			t.Error("HasHighSeverityFindings() returned false but high severity findings exist")
		}
	}

	findingsBySeverity := result.GetFindingsBySeverity()
	if len(findingsBySeverity) == 0 && len(result.Findings) > 0 {
		t.Error("GetFindingsBySeverity() returned empty map but findings exist")
	}

	findingsByRule := result.GetFindingsByRule()
	if len(findingsByRule) == 0 && len(result.Findings) > 0 {
		t.Error("GetFindingsByRule() returned empty map but findings exist")
	}
}

func TestTaintAnalyzer(t *testing.T) {
	phpCode := `<?php
$user_input = $_GET['input'];
$processed = strtolower($user_input);
echo $processed;
?>`

	parser := NewSimplePHPASTParser()
	ast, _, err := parser.Parse([]byte(phpCode), "taint_test.php")

	if err != nil {
		t.Fatalf("Failed to parse code for taint analysis: %v", err)
	}

	symbolTable, err := parser.BuildSymbolTable(ast)
	if err != nil {
		t.Fatalf("Failed to build symbol table: %v", err)
	}

	analyzer := NewTaintAnalyzer(symbolTable)
	paths := analyzer.PerformTaintAnalysis(ast)

	// We expect at least one taint path from $_GET to echo
	if len(paths) == 0 {
		t.Error("Expected taint paths but got none")
	}

	// Verify taint propagation
	if userInputVar, exists := symbolTable.Variables["user_input"]; exists {
		if !userInputVar.IsTainted {
			t.Error("Expected user_input variable to be tainted")
		}
	}
}

func BenchmarkSimplePHPASTParser_Parse(b *testing.B) {
	phpCode := `<?php
class LargeClass {
    private $prop1, $prop2, $prop3, $prop4, $prop5;
    
    public function method1() { return 1; }
    public function method2() { return 2; }
    public function method3() { return 3; }
    public function method4() { return 4; }
    public function method5() { return 5; }
}

function func1() { return 1; }
function func2() { return 2; }
function func3() { return 3; }
function func4() { return 4; }
function func5() { return 5; }

$var1 = "value1";
$var2 = "value2";
$var3 = "value3";
$var4 = "value4";
$var5 = "value5";
?>`

	parser := NewSimplePHPASTParser()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := parser.Parse([]byte(phpCode), "benchmark.php")
		if err != nil {
			b.Fatalf("Parse failed: %v", err)
		}
	}
}

func BenchmarkSecurityRuleEngine_AnalyzeAST(b *testing.B) {
	phpCode := `<?php
$data = $_POST['data'];
mysqli_query($conn, "SELECT * FROM table WHERE col = " . $data);
echo $data;
exec("ls " . $data);
$secret = "api_key_1234567890123456";
?>`

	parser := NewSimplePHPASTParser()
	ast, _, err := parser.Parse([]byte(phpCode), "benchmark.php")
	if err != nil {
		b.Fatalf("Parse failed: %v", err)
	}

	symbolTable, err := parser.BuildSymbolTable(ast)
	if err != nil {
		b.Fatalf("Symbol table building failed: %v", err)
	}

	// Mark data as tainted
	if dataVar, exists := symbolTable.Variables["data"]; exists {
		dataVar.IsTainted = true
	}

	ruleEngine := NewSecurityRuleEngine()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ruleEngine.AnalyzeAST(ast, symbolTable)
		if err != nil {
			b.Fatalf("Analysis failed: %v", err)
		}
	}
}
