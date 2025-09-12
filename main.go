package main

import (
	"fmt"
	"os"

	"github.com/le-company/security-scanner/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
