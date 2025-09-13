package main

import (
	"fmt"
	"log"

	"github.com/le-company/security-scanner/internal/hir"
)

func main() {
	fmt.Println("Testing HIR/CFG Security Analysis System")
	fmt.Println("=======================================")

	if err := hir.DemoHIRSystem(); err != nil {
		log.Fatalf("HIR demo failed: %v", err)
	}

	fmt.Println("\nHIR/CFG system test completed successfully!")
	fmt.Println("The system can now:")
	fmt.Println("- Parse code into High-level Intermediate Representation (HIR)")
	fmt.Println("- Build Control Flow Graphs (CFG) for security analysis")
	fmt.Println("- Track tainted data flow for vulnerability detection")
	fmt.Println("- Provide incremental analysis for performance")
	fmt.Println("- Store analysis results persistently with SQLite")
}