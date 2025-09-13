package config

import (
	"runtime"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	ScanPath     string
	OutputFile   string
	Format       string
	Severity     string
	Parallel     int
	Verbose      bool
	AllowedDirs  []string
	ExcludedDirs []string
	Cache        CacheConfig
	Rules        RulesConfig
	LSP          LSPConfig `mapstructure:"lsp"`
	MaxFiles     int       // Maximum number of files to process (0 = unlimited)
	NoLsp        bool      // Disable LSP integration
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Directory string `mapstructure:"directory"`
	MaxSize   int64  `mapstructure:"max_size"`  // in bytes
	MaxAge    int    `mapstructure:"max_age"`   // in hours
	MaxFiles  int    `mapstructure:"max_files"` // Maximum files to cache (0 = unlimited)
}

// RulesConfig holds security rules configuration
type RulesConfig struct {
	Enabled         []string `mapstructure:"enabled"`
	Disabled        []string `mapstructure:"disabled"`
	CustomRulesPath string   `mapstructure:"custom_rules_path"`
	IgnorePatterns  []string `mapstructure:"ignore_patterns"`
	FileExtensions  []string `mapstructure:"file_extensions"`
	AllowedDirs     []string `mapstructure:"allowed_dirs"`
	ExcludedDirs    []string `mapstructure:"excluded_dirs"`
}

// LSPConfig holds LSP configuration
type LSPConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// Load loads configuration from various sources
func Load() *Config {
	cfg := &Config{
		Format:   "text",
		Severity: "medium",
		Parallel: runtime.NumCPU(),
		MaxFiles: 0, // Default: unlimited
		Cache: CacheConfig{
			Enabled:   true,
			Directory: ".cache",
			MaxSize:   1024 * 1024 * 1024, // 1GB
			MaxAge:    168,                // 7 days in hours
			MaxFiles:  0,                  // Default: unlimited
		},
		LSP: LSPConfig{
			Enabled: false, // Default: LSP disabled to avoid timeout issues
		},
		Rules: RulesConfig{
			Enabled: []string{
				"sql_injection",
				"xss",
				"path_traversal",
				"command_injection",
				"hardcoded_secrets",
				"weak_crypto",
				"insecure_random",
				"xxe",
				"ldap_injection",
				"unsafe_deserialization",
			},
			FileExtensions: []string{
				".go", ".php", ".js", ".ts", ".java", ".py", ".rb", ".cs",
				".cpp", ".c", ".h", ".hpp", ".jsx", ".tsx", ".vue", ".html",
			},
			IgnorePatterns: []string{
				"vendor/",
				"node_modules/",
				".git/",
				"*.min.js",
				"*.test.*",
				"*_test.go",
			},
			ExcludedDirs: []string{
				"vendor",
				"node_modules",
				".git",
				".svn",
				".hg",
				"build",
				"dist",
				"target",
				"bin",
				"obj",
				"tmp",
				"temp",
				"cache",
				"logs",
				".vscode",
				".idea",
				".DS_Store",
				"coverage",
				"__pycache__",
				".pytest_cache",
				".tox",
				".mypy_cache",
			},
		},
	}

	// Override with viper values
	if viper.IsSet("format") {
		cfg.Format = viper.GetString("format")
	}
	if viper.IsSet("severity") {
		cfg.Severity = viper.GetString("severity")
	}
	if viper.IsSet("parallel") {
		cfg.Parallel = viper.GetInt("parallel")
	}
	if viper.IsSet("verbose") {
		cfg.Verbose = viper.GetBool("verbose")
	}

	// Load rules configuration
	if viper.IsSet("rules") {
		viper.UnmarshalKey("rules", &cfg.Rules)
	}

	// Load LSP configuration
	if viper.IsSet("lsp") {
		viper.UnmarshalKey("lsp", &cfg.LSP)
	}

	// Set NoLsp based on LSP.Enabled
	cfg.NoLsp = !cfg.LSP.Enabled

	// Auto-detect parallel workers
	if cfg.Parallel <= 0 {
		cfg.Parallel = runtime.NumCPU()
	}

	return cfg
}

// SeverityLevel represents vulnerability severity levels
type SeverityLevel int

const (
	SeverityLow SeverityLevel = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns string representation of severity level
func (s SeverityLevel) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity parses severity level from string
func ParseSeverity(s string) SeverityLevel {
	switch s {
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityMedium
	}
}
