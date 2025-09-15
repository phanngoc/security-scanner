package analyzer

import (
	"context"
	"fmt"
	"time"

	"github.com/le-company/security-scanner/internal/config"
	"github.com/le-company/security-scanner/internal/hir"
	"github.com/le-company/security-scanner/internal/rules/types"
)

// Analyzer interface defines the contract for security analyzers
type Analyzer interface {
	// GetID returns the unique identifier for this analyzer
	GetID() string

	// GetName returns the human-readable name of this analyzer
	GetName() string

	// GetDescription returns a description of what this analyzer does
	GetDescription() string

	// GetSupportedLanguages returns the languages this analyzer supports
	GetSupportedLanguages() []string

	// GetRequiredCapabilities returns the capabilities this analyzer needs
	GetRequiredCapabilities() []Capability

	// Analyze performs the security analysis on the given file
	Analyze(ctx context.Context, job *AnalysisJob) ([]*types.SecurityFinding, error)

	// CanAnalyze checks if this analyzer can analyze the given file
	CanAnalyze(job *AnalysisJob) bool
}

// Capability represents what an analyzer needs to function
type Capability int

const (
	CapabilitySymbolTable Capability = iota
	CapabilityCFG
	CapabilityDataFlow
	CapabilityCallGraph
	CapabilityHIR
	CapabilityAST
)

// AnalysisJob represents a file to be analyzed
type AnalysisJob struct {
	Path        string
	Language    string
	Content     []byte
	HIRFile     *hir.HIRFile
	SymbolTable map[string]interface{}
	CFG         *hir.CFG
	Metadata    map[string]interface{}
}

// AnalysisContext provides context for analysis
type AnalysisContext struct {
	WorkspaceIndex *hir.WorkspaceIndex
	Config         *config.Config
	Logger         interface{} // Will be typed properly
	Timeout        time.Duration
}

// AnalyzerRegistry manages available analyzers
type AnalyzerRegistry struct {
	analyzers    map[string]Analyzer
	byLanguage   map[string][]Analyzer
	byCapability map[Capability][]Analyzer
}

// NewAnalyzerRegistry creates a new analyzer registry
func NewAnalyzerRegistry() *AnalyzerRegistry {
	return &AnalyzerRegistry{
		analyzers:    make(map[string]Analyzer),
		byLanguage:   make(map[string][]Analyzer),
		byCapability: make(map[Capability][]Analyzer),
	}
}

// Register adds an analyzer to the registry
func (r *AnalyzerRegistry) Register(analyzer Analyzer) {
	r.analyzers[analyzer.GetID()] = analyzer

	// Index by language
	for _, lang := range analyzer.GetSupportedLanguages() {
		r.byLanguage[lang] = append(r.byLanguage[lang], analyzer)
	}

	// Index by capability
	for _, cap := range analyzer.GetRequiredCapabilities() {
		r.byCapability[cap] = append(r.byCapability[cap], analyzer)
	}
}

// GetAnalyzer returns an analyzer by ID
func (r *AnalyzerRegistry) GetAnalyzer(id string) (Analyzer, bool) {
	analyzer, exists := r.analyzers[id]
	return analyzer, exists
}

// GetAnalyzersForLanguage returns analyzers that support the given language
func (r *AnalyzerRegistry) GetAnalyzersForLanguage(language string) []Analyzer {
	return r.byLanguage[language]
}

// GetAnalyzersWithCapability returns analyzers that have the given capability
func (r *AnalyzerRegistry) GetAnalyzersWithCapability(cap Capability) []Analyzer {
	return r.byCapability[cap]
}

// GetAllAnalyzers returns all registered analyzers
func (r *AnalyzerRegistry) GetAllAnalyzers() []Analyzer {
	var analyzers []Analyzer
	for _, analyzer := range r.analyzers {
		analyzers = append(analyzers, analyzer)
	}
	return analyzers
}

// AnalysisEngine orchestrates security analysis
type AnalysisEngine struct {
	registry *AnalyzerRegistry
	context  *AnalysisContext
}

// NewAnalysisEngine creates a new analysis engine
func NewAnalysisEngine(registry *AnalyzerRegistry, context *AnalysisContext) *AnalysisEngine {
	return &AnalysisEngine{
		registry: registry,
		context:  context,
	}
}

// AnalyzeFile performs comprehensive security analysis on a file
func (e *AnalysisEngine) AnalyzeFile(ctx context.Context, job *AnalysisJob) ([]*types.SecurityFinding, error) {
	var allFindings []*types.SecurityFinding

	// Get analyzers that can handle this file
	analyzers := e.registry.GetAnalyzersForLanguage(job.Language)

	// Filter analyzers that can actually analyze this file
	var applicableAnalyzers []Analyzer
	for _, analyzer := range analyzers {
		if analyzer.CanAnalyze(job) {
			applicableAnalyzers = append(applicableAnalyzers, analyzer)
		}
	}

	// Run each applicable analyzer
	for _, analyzer := range applicableAnalyzers {
		// Check if we have the required capabilities
		if !e.hasRequiredCapabilities(analyzer) {
			continue
		}

		// Prepare the job with required data
		preparedJob, err := e.prepareJob(ctx, job, analyzer)
		if err != nil {
			continue // Skip this analyzer if preparation fails
		}

		// Run the analyzer
		findings, err := analyzer.Analyze(ctx, preparedJob)
		if err != nil {
			continue // Skip this analyzer if analysis fails
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// hasRequiredCapabilities checks if we have the required capabilities for an analyzer
func (e *AnalysisEngine) hasRequiredCapabilities(analyzer Analyzer) bool {
	requiredCaps := analyzer.GetRequiredCapabilities()

	for _, cap := range requiredCaps {
		switch cap {
		case CapabilitySymbolTable:
			// Check if we have symbol table data
			// This will be implemented based on HIR index
		case CapabilityCFG:
			// Check if we have CFG data
		case CapabilityDataFlow:
			// Check if we have data flow analysis capability
		case CapabilityCallGraph:
			// Check if we have call graph data
		case CapabilityHIR:
			// Check if we have HIR data
		case CapabilityAST:
			// Check if we have AST data
		}
	}

	return true // For now, assume we have all capabilities
}

// prepareJob prepares the analysis job with required data
func (e *AnalysisEngine) prepareJob(ctx context.Context, job *AnalysisJob, analyzer Analyzer) (*AnalysisJob, error) {
	preparedJob := &AnalysisJob{
		Path:        job.Path,
		Language:    job.Language,
		Content:     job.Content,
		HIRFile:     job.HIRFile,
		SymbolTable: job.SymbolTable,
		CFG:         job.CFG,
		Metadata:    job.Metadata,
	}

	// Load additional data based on required capabilities
	requiredCaps := analyzer.GetRequiredCapabilities()

	for _, cap := range requiredCaps {
		switch cap {
		case CapabilitySymbolTable:
			if preparedJob.SymbolTable == nil {
				symbols, err := e.loadSymbolTable(ctx, job.Path)
				if err != nil {
					return nil, err
				}
				preparedJob.SymbolTable = symbols
			}
		case CapabilityCFG:
			if preparedJob.CFG == nil {
				cfg, err := e.loadCFG(ctx, job.Path)
				if err != nil {
					return nil, err
				}
				preparedJob.CFG = cfg
			}
		case CapabilityHIR:
			if preparedJob.HIRFile == nil {
				hirFile, err := e.loadHIRFile(ctx, job.Path)
				if err != nil {
					return nil, err
				}
				preparedJob.HIRFile = hirFile
			}
		}
	}

	return preparedJob, nil
}

// loadSymbolTable loads symbol table from HIR index
func (e *AnalysisEngine) loadSymbolTable(ctx context.Context, filePath string) (map[string]interface{}, error) {
	if e.context.WorkspaceIndex == nil {
		return nil, fmt.Errorf("workspace index not available")
	}

	// Get file record from index
	fileRecord, err := e.context.WorkspaceIndex.GetFileByPath(filePath)
	if err != nil {
		return nil, err
	}

	// Get symbols for this file
	symbolRecords, err := e.context.WorkspaceIndex.GetSymbolsByFile(fileRecord.ID)
	if err != nil {
		return nil, err
	}

	// Convert to symbol table format
	symbolTable := make(map[string]interface{})
	for _, record := range symbolRecords {
		symbolTable[record.FQN] = map[string]interface{}{
			"id":          record.SymbolID,
			"fqn":         record.FQN,
			"kind":        record.Kind,
			"start_pos":   record.StartPos,
			"end_pos":     record.EndPos,
			"visibility":  record.Visibility,
			"is_static":   record.IsStatic,
			"is_abstract": record.IsAbstract,
			"is_final":    record.IsFinal,
		}
	}

	return symbolTable, nil
}

// loadCFG loads CFG from HIR index
func (e *AnalysisEngine) loadCFG(ctx context.Context, filePath string) (*hir.CFG, error) {
	if e.context.WorkspaceIndex == nil {
		return nil, fmt.Errorf("workspace index not available")
	}

	// Get file record from index
	fileRecord, err := e.context.WorkspaceIndex.GetFileByPath(filePath)
	if err != nil {
		return nil, err
	}

	// Get symbols for this file to find the main symbol
	symbolRecords, err := e.context.WorkspaceIndex.GetSymbolsByFile(fileRecord.ID)
	if err != nil {
		return nil, err
	}

	// For now, try to load CFG from the first symbol
	// In a real implementation, you'd determine which symbol's CFG to load
	if len(symbolRecords) > 0 {
		hirUnit, err := e.context.WorkspaceIndex.LoadHIRUnit(symbolRecords[0].SymbolID)
		if err != nil {
			return nil, err
		}
		return hirUnit.CFG, nil
	}

	return nil, nil
}

// loadHIRFile loads HIR file from index
func (e *AnalysisEngine) loadHIRFile(ctx context.Context, filePath string) (*hir.HIRFile, error) {
	if e.context.WorkspaceIndex == nil {
		return nil, fmt.Errorf("workspace index not available")
	}

	// This would load the HIR file from the index
	// For now, return nil as this would need to be implemented
	// based on how HIR files are stored in the index
	return nil, nil
}
