package hir

import (
	"fmt"
	"time"

	"go.uber.org/zap"
)

// DemoHIRSystem demonstrates the HIR/CFG functionality
func DemoHIRSystem() error {
	// Create logger
	logger, _ := zap.NewDevelopment()

	// Initialize HIR program
	program := &HIRProgram{
		Files:           make(map[string]*HIRFile),
		Symbols:         NewGlobalSymbolTable(),
		CallGraph:       NewCallGraph(),
		CFGs:            make(map[SymbolID]*CFG),
		DependencyGraph: NewDependencyGraph(),
		IncludeGraph:    NewIncludeGraph(),
		CreatedAt:       time.Now(),
	}

	// Create workspace index
	workspace, err := NewWorkspaceIndex("/tmp/test-workspace", logger)
	if err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	defer workspace.Close()

	// Create basic transformer
	transformer := NewBasicTransformer(program)

	// Transform a demo PHP file
	demoCode := []byte(`<?php
$userInput = $_GET['input'];
$query = "SELECT * FROM users WHERE name = '" . $userInput . "'";
mysqli_query($connection, $query);
?>`)

	hirFile, err := transformer.TransformBasicFile("demo.php", demoCode)
	if err != nil {
		return fmt.Errorf("transformation failed: %w", err)
	}

	// Add file to program
	program.Files[hirFile.Path] = hirFile

	// Add symbols to global symbol table
	for _, symbol := range hirFile.Symbols {
		program.Symbols.AddSymbol(symbol)
	}

	// Create symbol linker
	linker := NewSymbolLinker(program)
	if err := linker.LinkSymbols(); err != nil {
		return fmt.Errorf("symbol linking failed: %w", err)
	}

	// Create CFG builder
	cfgBuilder := NewCFGBuilder()
	for _, unit := range hirFile.Units {
		cfg, err := cfgBuilder.BuildCFG(unit)
		if err != nil {
			return fmt.Errorf("CFG building failed: %w", err)
		}
		program.CFGs[unit.Symbol.ID] = cfg
	}

	// Demonstrate incremental analysis
	analyzer, err := NewIncrementalAnalyzer("/tmp/test-workspace", logger)
	if err != nil {
		return fmt.Errorf("failed to create analyzer: %w", err)
	}

	request := &AnalysisRequest{
		Files: []string{"demo.php"},
	}

	_, err = analyzer.AnalyzeIncremental(request)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Print results
	fmt.Printf("HIR/CFG Demo Results:\n")
	fmt.Printf("- Files processed: %d\n", len(request.Files))
	fmt.Printf("- Symbols found: %d\n", len(program.Symbols.Symbols))
	fmt.Printf("- CFGs built: %d\n", len(program.CFGs))
	fmt.Printf("- Analysis completed successfully\n")

	// Run enhanced HIR security analysis
	fmt.Printf("\nRunning Enhanced HIR Security Analysis:\n")
	securityAnalyzer := NewHIRSecurityAnalyzer(program)

	// Analyze the demo file
	for _, hirFile := range program.Files {
		securityFindings, err := securityAnalyzer.AnalyzeFile(hirFile)
		if err != nil {
			return fmt.Errorf("security analysis failed: %w", err)
		}

		// Print detailed security findings
		fmt.Printf("- Security findings: %d\n", len(securityFindings))
		for i, finding := range securityFindings {
			fmt.Printf("  [%d] %s (%s)\n", i+1, finding.Message, finding.Severity)
			fmt.Printf("      ID: %s | Type: %s\n", finding.ID, finding.Type)
			fmt.Printf("      Confidence: %.1f%% | File: %s\n", finding.Confidence*100, finding.File)
			fmt.Printf("      Description: %s\n", finding.Description)
		}
		break // Only analyze first file for demo
	}

	// Print basic findings from demo transformer
	if len(hirFile.Units) > 0 {
		unit := hirFile.Units[0]
		if unit.Body != nil {
			fmt.Printf("Basic HIR Analysis Results:\n")
			for _, stmt := range unit.Body.Stmts {
				if stmt.Type == HIRCall {
					if risk, ok := stmt.Meta["security_risk"].(string); ok {
						fmt.Printf("  * %s detected in statement at position %d\n", risk, stmt.Position)
					}
				}
			}
		}
	}

	return nil
}
