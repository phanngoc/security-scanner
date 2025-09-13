package hir

import (
	"database/sql"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
)

// WorkspaceIndex manages persistent storage for HIR data
type WorkspaceIndex struct {
	db     *sql.DB
	logger *zap.Logger
	dbPath string
}

// NewWorkspaceIndex creates a new workspace index
func NewWorkspaceIndex(workspacePath string, logger *zap.Logger) (*WorkspaceIndex, error) {
	dbPath := filepath.Join(workspacePath, ".security-scanner", "index.db")

	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("failed to create index directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_fk=true&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	index := &WorkspaceIndex{
		db:     db,
		logger: logger,
		dbPath: dbPath,
	}

	if err := index.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return index, nil
}

// initSchema creates database tables if they don't exist
func (wi *WorkspaceIndex) initSchema() error {
	schema := `
	-- Files table
	CREATE TABLE IF NOT EXISTS files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path TEXT UNIQUE NOT NULL,
		language TEXT NOT NULL,
		hash TEXT NOT NULL,
		mtime INTEGER NOT NULL,
		size INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);

	-- Symbols table
	CREATE TABLE IF NOT EXISTS symbols (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		symbol_id TEXT UNIQUE NOT NULL,
		fqn TEXT NOT NULL,
		kind INTEGER NOT NULL,
		file_id INTEGER NOT NULL,
		start_pos INTEGER NOT NULL,
		end_pos INTEGER NOT NULL,
		visibility INTEGER,
		is_static BOOLEAN,
		is_abstract BOOLEAN,
		is_final BOOLEAN,
		metadata TEXT, -- JSON
		created_at INTEGER NOT NULL,
		FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
	);

	-- Symbol references table (symbol usage)
	CREATE TABLE IF NOT EXISTS symbol_references (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_id INTEGER NOT NULL,
		start_pos INTEGER NOT NULL,
		end_pos INTEGER NOT NULL,
		target_symbol_id TEXT NOT NULL,
		reference_type INTEGER NOT NULL, -- call, instantiation, inheritance, etc.
		context TEXT,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
	);

	-- HIR storage (serialized HIR units)
	CREATE TABLE IF NOT EXISTS hir_units (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		symbol_id TEXT NOT NULL,
		file_id INTEGER NOT NULL,
		hir_data BLOB NOT NULL, -- Serialized HIR
		cfg_data BLOB, -- Serialized CFG
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
	);

	-- Dependencies table
	CREATE TABLE IF NOT EXISTS dependencies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		from_file_id INTEGER NOT NULL,
		to_file_id INTEGER NOT NULL,
		dependency_type INTEGER NOT NULL, -- include, class_ref, function_call
		created_at INTEGER NOT NULL,
		FOREIGN KEY (from_file_id) REFERENCES files(id) ON DELETE CASCADE,
		FOREIGN KEY (to_file_id) REFERENCES files(id) ON DELETE CASCADE,
		UNIQUE(from_file_id, to_file_id, dependency_type)
	);

	-- Call graph edges
	CREATE TABLE IF NOT EXISTS call_edges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		caller_symbol_id TEXT NOT NULL,
		callee_symbol_id TEXT NOT NULL,
		call_site_file_id INTEGER NOT NULL,
		call_site_pos INTEGER NOT NULL,
		is_direct BOOLEAN NOT NULL,
		context TEXT,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (call_site_file_id) REFERENCES files(id) ON DELETE CASCADE
	);

	-- Security findings cache
	CREATE TABLE IF NOT EXISTS security_findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_id INTEGER NOT NULL,
		rule_id TEXT NOT NULL,
		vulnerability_type INTEGER NOT NULL,
		severity INTEGER NOT NULL,
		confidence REAL NOT NULL,
		message TEXT NOT NULL,
		start_pos INTEGER NOT NULL,
		end_pos INTEGER NOT NULL,
		cwe TEXT,
		owasp TEXT,
		data_flow TEXT, -- JSON serialized data flow
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
	CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash);
	CREATE INDEX IF NOT EXISTS idx_symbols_fqn ON symbols(fqn);
	CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
	CREATE INDEX IF NOT EXISTS idx_symbols_file_id ON symbols(file_id);
	CREATE INDEX IF NOT EXISTS idx_symbol_references_file_id ON symbol_references(file_id);
	CREATE INDEX IF NOT EXISTS idx_symbol_references_target ON symbol_references(target_symbol_id);
	CREATE INDEX IF NOT EXISTS idx_dependencies_from ON dependencies(from_file_id);
	CREATE INDEX IF NOT EXISTS idx_dependencies_to ON dependencies(to_file_id);
	CREATE INDEX IF NOT EXISTS idx_call_edges_caller ON call_edges(caller_symbol_id);
	CREATE INDEX IF NOT EXISTS idx_call_edges_callee ON call_edges(callee_symbol_id);
	CREATE INDEX IF NOT EXISTS idx_findings_file_id ON security_findings(file_id);
	CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON security_findings(rule_id);
	`

	_, err := wi.db.Exec(schema)
	return err
}

// FileRecord represents a file in the index
type FileRecord struct {
	ID        int64
	Path      string
	Language  string
	Hash      string
	MTime     time.Time
	Size      int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SymbolRecord represents a symbol in the index
type SymbolRecord struct {
	ID         int64
	SymbolID   string
	FQN        string
	Kind       SymbolKind
	FileID     int64
	StartPos   int64
	EndPos     int64
	Visibility *Visibility
	IsStatic   bool
	IsAbstract bool
	IsFinal    bool
	Metadata   string
	CreatedAt  time.Time
}

// ReferenceRecord represents a symbol reference
type ReferenceRecord struct {
	ID             int64
	FileID         int64
	StartPos       int64
	EndPos         int64
	TargetSymbolID string
	ReferenceType  ReferenceType
	Context        string
	CreatedAt      time.Time
}

type ReferenceType int

const (
	RefCall ReferenceType = iota
	RefInstantiation
	RefInheritance
	RefImplementation
	RefUse
	RefAssignment
	RefAccess
)

// HIRUnitRecord represents stored HIR data
type HIRUnitRecord struct {
	ID        int64
	SymbolID  string
	FileID    int64
	HIRData   []byte
	CFGData   []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// StoreFile stores or updates a file record
func (wi *WorkspaceIndex) StoreFile(file *HIRFile, hash string, mtime time.Time, size int64) (*FileRecord, error) {
	now := time.Now()

	// Check if file already exists
	var existingID int64
	err := wi.db.QueryRow(
		"SELECT id FROM files WHERE path = ?", file.Path,
	).Scan(&existingID)

	if err == sql.ErrNoRows {
		// Insert new file
		result, err := wi.db.Exec(`
			INSERT INTO files (path, language, hash, mtime, size, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			file.Path, file.Language, hash, mtime.Unix(), size, now.Unix(), now.Unix())
		if err != nil {
			return nil, fmt.Errorf("failed to insert file: %w", err)
		}

		id, err := result.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("failed to get insert ID: %w", err)
		}

		return &FileRecord{
			ID:        id,
			Path:      file.Path,
			Language:  file.Language,
			Hash:      hash,
			MTime:     mtime,
			Size:      size,
			CreatedAt: now,
			UpdatedAt: now,
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to check existing file: %w", err)
	}

	// Update existing file
	_, err = wi.db.Exec(`
		UPDATE files SET language = ?, hash = ?, mtime = ?, size = ?, updated_at = ?
		WHERE id = ?`,
		file.Language, hash, mtime.Unix(), size, now.Unix(), existingID)
	if err != nil {
		return nil, fmt.Errorf("failed to update file: %w", err)
	}

	return &FileRecord{
		ID:        existingID,
		Path:      file.Path,
		Language:  file.Language,
		Hash:      hash,
		MTime:     mtime,
		Size:      size,
		UpdatedAt: now,
	}, nil
}

// StoreSymbols stores symbols for a file
func (wi *WorkspaceIndex) StoreSymbols(fileID int64, symbols []*Symbol) error {
	tx, err := wi.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing symbols for this file
	_, err = tx.Exec("DELETE FROM symbols WHERE file_id = ?", fileID)
	if err != nil {
		return fmt.Errorf("failed to delete existing symbols: %w", err)
	}

	// Insert new symbols
	stmt, err := tx.Prepare(`
		INSERT INTO symbols (symbol_id, fqn, kind, file_id, start_pos, end_pos, 
			visibility, is_static, is_abstract, is_final, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare symbol insert: %w", err)
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, symbol := range symbols {
		var visibility *int
		if symbol.Traits.Visibility != 0 {
			v := int(symbol.Traits.Visibility)
			visibility = &v
		}

		_, err = stmt.Exec(
			string(symbol.ID), symbol.FQN, int(symbol.Kind), fileID,
			int64(symbol.Position), int64(symbol.Span.End),
			visibility, symbol.Traits.IsStatic, symbol.Traits.IsAbstract,
			symbol.Traits.IsFinal, "", now)
		if err != nil {
			return fmt.Errorf("failed to insert symbol %s: %w", symbol.ID, err)
		}
	}

	return tx.Commit()
}

// StoreHIRUnit stores a HIR unit with its CFG
func (wi *WorkspaceIndex) StoreHIRUnit(fileID int64, unit *HIRUnit) error {
	// Serialize HIR unit
	hirData, err := wi.serializeHIRUnit(unit)
	if err != nil {
		return fmt.Errorf("failed to serialize HIR unit: %w", err)
	}

	// Serialize CFG if present
	var cfgData []byte
	if unit.CFG != nil {
		cfgData, err = wi.serializeCFG(unit.CFG)
		if err != nil {
			return fmt.Errorf("failed to serialize CFG: %w", err)
		}
	}

	now := time.Now().Unix()

	// Insert or update HIR unit
	_, err = wi.db.Exec(`
		INSERT OR REPLACE INTO hir_units (symbol_id, file_id, hir_data, cfg_data, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		string(unit.Symbol.ID), fileID, hirData, cfgData, now, now)

	return err
}

// LoadHIRUnit loads a HIR unit from storage
func (wi *WorkspaceIndex) LoadHIRUnit(symbolID string) (*HIRUnit, error) {
	var hirData, cfgData []byte
	err := wi.db.QueryRow(
		"SELECT hir_data, cfg_data FROM hir_units WHERE symbol_id = ?",
		symbolID,
	).Scan(&hirData, &cfgData)
	if err != nil {
		return nil, fmt.Errorf("failed to load HIR unit: %w", err)
	}

	// Deserialize HIR unit
	unit, err := wi.deserializeHIRUnit(hirData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize HIR unit: %w", err)
	}

	// Deserialize CFG if present
	if len(cfgData) > 0 {
		cfg, err := wi.deserializeCFG(cfgData)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize CFG: %w", err)
		}
		unit.CFG = cfg
	}

	return unit, nil
}

// StoreDependencies stores file dependencies
func (wi *WorkspaceIndex) StoreDependencies(fromFileID, toFileID int64, depType DependencyType) error {
	now := time.Now().Unix()
	_, err := wi.db.Exec(`
		INSERT OR IGNORE INTO dependencies (from_file_id, to_file_id, dependency_type, created_at)
		VALUES (?, ?, ?, ?)`,
		fromFileID, toFileID, int(depType), now)
	return err
}

// GetDependents returns files that depend on the given file
func (wi *WorkspaceIndex) GetDependents(fileID int64) ([]int64, error) {
	rows, err := wi.db.Query(
		"SELECT from_file_id FROM dependencies WHERE to_file_id = ?",
		fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var dependents []int64
	for rows.Next() {
		var depID int64
		if err := rows.Scan(&depID); err != nil {
			return nil, err
		}
		dependents = append(dependents, depID)
	}

	return dependents, rows.Err()
}

// StoreCallEdge stores a call graph edge
func (wi *WorkspaceIndex) StoreCallEdge(edge *CallEdge, callSiteFileID int64, callSitePos int64) error {
	now := time.Now().Unix()
	_, err := wi.db.Exec(`
		INSERT OR REPLACE INTO call_edges 
		(caller_symbol_id, callee_symbol_id, call_site_file_id, call_site_pos, is_direct, context, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		string(edge.Caller.Symbol.ID), string(edge.Callee.Symbol.ID),
		callSiteFileID, callSitePos, edge.IsDirect, edge.Context, now)
	return err
}

// StoreSecurityFindings stores security analysis results
func (wi *WorkspaceIndex) StoreSecurityFindings(fileID int64, findings []*SecurityFinding) error {
	tx, err := wi.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing findings for this file
	_, err = tx.Exec("DELETE FROM security_findings WHERE file_id = ?", fileID)
	if err != nil {
		return fmt.Errorf("failed to delete existing findings: %w", err)
	}

	// Insert new findings
	stmt, err := tx.Prepare(`
		INSERT INTO security_findings 
		(file_id, rule_id, vulnerability_type, severity, confidence, message, 
		 start_pos, end_pos, cwe, owasp, data_flow, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("failed to prepare finding insert: %w", err)
	}
	defer stmt.Close()

	now := time.Now().Unix()
	for _, finding := range findings {
		dataFlow := ""
		if len(finding.DataFlow) > 0 {
			// Serialize data flow as JSON (simplified)
			dataFlow = fmt.Sprintf("%v", finding.DataFlow)
		}

		_, err = stmt.Exec(
			fileID, finding.ID, int(finding.Type), int(finding.Severity),
			finding.Confidence, finding.Message,
			int64(finding.Position), int64(finding.Span.End),
			finding.CWE, finding.OWASP, dataFlow, now, now)
		if err != nil {
			return fmt.Errorf("failed to insert finding %s: %w", finding.ID, err)
		}
	}

	return tx.Commit()
}

// GetFileByPath retrieves a file record by path
func (wi *WorkspaceIndex) GetFileByPath(path string) (*FileRecord, error) {
	var record FileRecord
	var mtimeUnix, createdUnix, updatedUnix int64

	err := wi.db.QueryRow(`
		SELECT id, path, language, hash, mtime, size, created_at, updated_at
		FROM files WHERE path = ?`, path).Scan(
		&record.ID, &record.Path, &record.Language, &record.Hash,
		&mtimeUnix, &record.Size, &createdUnix, &updatedUnix)

	if err != nil {
		return nil, err
	}

	record.MTime = time.Unix(mtimeUnix, 0)
	record.CreatedAt = time.Unix(createdUnix, 0)
	record.UpdatedAt = time.Unix(updatedUnix, 0)

	return &record, nil
}

// GetSymbolsByFile retrieves all symbols for a file
func (wi *WorkspaceIndex) GetSymbolsByFile(fileID int64) ([]*SymbolRecord, error) {
	rows, err := wi.db.Query(`
		SELECT id, symbol_id, fqn, kind, file_id, start_pos, end_pos,
			   visibility, is_static, is_abstract, is_final, metadata, created_at
		FROM symbols WHERE file_id = ?`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var symbols []*SymbolRecord
	for rows.Next() {
		var record SymbolRecord
		var visibilityInt *int
		var createdUnix int64

		err := rows.Scan(
			&record.ID, &record.SymbolID, &record.FQN, &record.Kind,
			&record.FileID, &record.StartPos, &record.EndPos,
			&visibilityInt, &record.IsStatic, &record.IsAbstract,
			&record.IsFinal, &record.Metadata, &createdUnix)
		if err != nil {
			return nil, err
		}

		if visibilityInt != nil {
			vis := Visibility(*visibilityInt)
			record.Visibility = &vis
		}
		record.CreatedAt = time.Unix(createdUnix, 0)

		symbols = append(symbols, &record)
	}

	return symbols, rows.Err()
}

// IsFileUpToDate checks if a file's index data is up to date
func (wi *WorkspaceIndex) IsFileUpToDate(path, hash string, mtime time.Time) (bool, error) {
	var storedHash string
	var storedMtime int64

	err := wi.db.QueryRow(
		"SELECT hash, mtime FROM files WHERE path = ?", path,
	).Scan(&storedHash, &storedMtime)

	if err == sql.ErrNoRows {
		return false, nil // File not indexed yet
	}
	if err != nil {
		return false, err
	}

	return storedHash == hash && time.Unix(storedMtime, 0).Equal(mtime), nil
}

// DependencyType represents types of file dependencies
type DependencyType int

const (
	DepInclude DependencyType = iota
	DepClassRef
	DepFunctionCall
)

// Serialization helpers

func (wi *WorkspaceIndex) serializeHIRUnit(unit *HIRUnit) ([]byte, error) {
	var buf strings.Builder
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(unit)
	if err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func (wi *WorkspaceIndex) deserializeHIRUnit(data []byte) (*HIRUnit, error) {
	var unit HIRUnit
	decoder := gob.NewDecoder(strings.NewReader(string(data)))
	err := decoder.Decode(&unit)
	return &unit, err
}

func (wi *WorkspaceIndex) serializeCFG(cfg *CFG) ([]byte, error) {
	var buf strings.Builder
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(cfg)
	if err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func (wi *WorkspaceIndex) deserializeCFG(data []byte) (*CFG, error) {
	var cfg CFG
	decoder := gob.NewDecoder(strings.NewReader(string(data)))
	err := decoder.Decode(&cfg)
	return &cfg, err
}

// Close closes the database connection
func (wi *WorkspaceIndex) Close() error {
	return wi.db.Close()
}

// Vacuum optimizes the database
func (wi *WorkspaceIndex) Vacuum() error {
	_, err := wi.db.Exec("VACUUM")
	return err
}

// GetDatabaseSize returns the size of the database file
func (wi *WorkspaceIndex) GetDatabaseSize() (int64, error) {
	var size int64
	err := wi.db.QueryRow("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()").Scan(&size)
	return size, err
}

// Helper function to ensure directory exists
func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}
