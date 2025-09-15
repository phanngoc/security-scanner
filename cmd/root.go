package cmd

import (
	"context"
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
	maxFiles     int
	noLsp        bool
	// Indexing flags
	indexOnly    bool
	useIndex     bool
	updateIndex  bool
	forceReindex bool
	indexDir     string
	cleanIndex   bool
	indexStatus  bool
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
	rootCmd.PersistentFlags().IntVar(&maxFiles, "max-files", 0, "maximum number of files to process (0 = unlimited, useful for testing)")
	rootCmd.PersistentFlags().BoolVar(&noLsp, "no-lsp", false, "disable LSP integration (fallback to basic parsing)")

	// Indexing flags
	rootCmd.PersistentFlags().BoolVar(&indexOnly, "index-only", false, "build HIR index without scanning (for large projects)")
	rootCmd.PersistentFlags().BoolVar(&useIndex, "use-index", false, "use existing HIR index for faster scanning")
	rootCmd.PersistentFlags().BoolVar(&updateIndex, "update-index", false, "update HIR index for changed files only")
	rootCmd.PersistentFlags().BoolVar(&forceReindex, "force-reindex", false, "force rebuild entire index from scratch")
	rootCmd.PersistentFlags().StringVar(&indexDir, "index-dir", ".security-scanner", "custom index directory (default: .security-scanner)")
	rootCmd.PersistentFlags().BoolVar(&cleanIndex, "clean-index", false, "clean old index data")
	rootCmd.PersistentFlags().BoolVar(&indexStatus, "index-status", false, "check index status")
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
	if parallel > 0 {
		cfg.Parallel = parallel
	}
	cfg.Verbose = verbose
	cfg.AllowedDirs = allowedDirs
	cfg.ExcludedDirs = excludedDirs
	cfg.MaxFiles = maxFiles
	cfg.NoLsp = noLsp

	// Handle indexing operations
	if indexOnly || updateIndex || forceReindex || cleanIndex || indexStatus {
		return handleIndexOperations(cfg, logger, absPath)
	}

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

func handleIndexOperations(cfg *config.Config, logger *zap.Logger, scanPath string) error {
	// Import hir package for index operations
	// Note: This would need to be added to imports at the top
	// import "github.com/le-company/security-scanner/internal/hir"

	if indexStatus {
		return handleIndexStatus(cfg, logger, scanPath)
	}

	if cleanIndex {
		return handleCleanIndex(cfg, logger, scanPath)
	}

	if indexOnly || updateIndex || forceReindex {
		return handleIndexBuild(cfg, logger, scanPath)
	}

	return nil
}

func handleIndexStatus(cfg *config.Config, logger *zap.Logger, scanPath string) error {
	fmt.Printf("Index Status for: %s\n", scanPath)
	fmt.Printf("Index Directory: %s\n", indexDir)

	// Check if index exists
	indexPath := filepath.Join(indexDir, "index.db")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		fmt.Println("Status: No index found")
		return nil
	}

	fmt.Println("Status: Index exists")
	// TODO: Add more detailed status information
	return nil
}

func handleCleanIndex(cfg *config.Config, logger *zap.Logger, scanPath string) error {
	fmt.Printf("Cleaning index in: %s\n", indexDir)

	// Remove index directory
	if err := os.RemoveAll(indexDir); err != nil {
		return fmt.Errorf("failed to clean index: %w", err)
	}

	fmt.Println("Index cleaned successfully")
	return nil
}

func handleIndexBuild(cfg *config.Config, logger *zap.Logger, scanPath string) error {
	fmt.Printf("Building index for: %s\n", scanPath)

	// Initialize scanner for indexing
	s := scanner.New(cfg, logger)
	defer s.Close()

	// Use the scanner's index service to build index
	if s.GetIndexService() != nil {
		fmt.Println("Starting index build...")

		// Walk through all files and index them
		err := filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			// Skip non-source files
			if !isSourceFile(path) {
				return nil
			}

			// Read file content
			content, err := os.ReadFile(path)
			if err != nil {
				logger.Warn("Failed to read file", zap.String("file", path), zap.Error(err))
				return nil
			}

			// Determine language
			language := detectLanguage(path)

			// Index the file
			if err := s.GetIndexService().EnsureFileIndexed(context.Background(), path, content, language); err != nil {
				logger.Warn("Failed to index file", zap.String("file", path), zap.Error(err))
			} else {
				fmt.Printf("Indexed: %s (%s)\n", path, language)
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to walk directory: %w", err)
		}

		fmt.Println("Index build completed successfully")
	} else {
		return fmt.Errorf("index service not available")
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

// isSourceFile checks if a file is a source code file
func isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	sourceExts := []string{".go", ".php", ".js", ".ts", ".py", ".java", ".c", ".cpp", ".cs", ".rb", ".swift", ".kt"}

	for _, sourceExt := range sourceExts {
		if ext == sourceExt {
			return true
		}
	}
	return false
}

// detectLanguage detects programming language from file extension
func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))

	languageMap := map[string]string{
		".go":    "go",
		".php":   "php",
		".js":    "javascript",
		".ts":    "typescript",
		".py":    "python",
		".java":  "java",
		".c":     "c",
		".cpp":   "cpp",
		".cs":    "csharp",
		".rb":    "ruby",
		".swift": "swift",
		".kt":    "kotlin",
	}

	if lang, exists := languageMap[ext]; exists {
		return lang
	}
	return "unknown"
}
