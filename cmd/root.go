package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/reporter"
	"github.com/le-company/security-scanner/internal/scanner"
)

var (
	cfgFile      string
	outputFile   string
	format       string
	severity     string
	parallel     int
	verbose      bool
	allowedDirs  []string
	excludedDirs []string
)

var rootCmd = &cobra.Command{
	Use:   "security-scanner [path]",
	Short: "OWASP-compliant security scanner for source code",
	Long: `A fast, parallel security scanner that detects vulnerabilities in source code
following OWASP security guidelines. Supports multiple languages and provides
detailed security reports with remediation suggestions.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .security-scanner.yaml)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&format, "format", "f", "text", "output format (text, json, sarif)")
	rootCmd.PersistentFlags().StringVarP(&severity, "severity", "s", "medium", "minimum severity level (low, medium, high, critical)")
	rootCmd.PersistentFlags().IntVarP(&parallel, "parallel", "p", 0, "number of parallel workers (0 = auto)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringSliceVar(&allowedDirs, "allow-dir", []string{}, "allowed directories to scan (improves performance)")
	rootCmd.PersistentFlags().StringSliceVar(&excludedDirs, "exclude-dir", []string{}, "directories to exclude from scanning")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(".")
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".security-scanner")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("SECURITY_SCANNER")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Initialize logger
	logger := initLogger()
	defer logger.Sync()

	// Get scan path
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	// Make path absolute
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Load configuration
	cfg := config.Load()
	cfg.ScanPath = absPath
	cfg.OutputFile = outputFile
	cfg.Format = format
	cfg.Severity = severity
	cfg.Parallel = parallel
	cfg.Verbose = verbose
	cfg.AllowedDirs = allowedDirs
	cfg.ExcludedDirs = excludedDirs

	// Initialize scanner
	s := scanner.New(cfg, logger)

	// Run scan
	results, err := s.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Generate report
	r := reporter.New(cfg, logger)
	if err := r.Generate(results); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}

func initLogger() *zap.Logger {
	var logger *zap.Logger
	var err error

	if verbose {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	return logger
}
