package lsp

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SymbolTable represents an enhanced symbol table with LSP integration
type SymbolTable struct {
	// Core structures
	ScopeTree       *ScopeNode              `json:"scope_tree"`
	NameIndex       map[string]*PostingList `json:"name_index"`
	IntervalTree    *IntervalTree           `json:"interval_tree"`
	DependencyGraph *DependencyGraph        `json:"dependency_graph"`

	// Metadata
	FileURI     string    `json:"file_uri"`
	Language    string    `json:"language"`
	Version     int       `json:"version"`
	LastUpdated time.Time `json:"last_updated"`

	// String interning for memory efficiency
	stringPool map[string]string
	mu         sync.RWMutex
	logger     *zap.Logger
}

// ScopeNode represents a node in the scope tree (Serena's forest structure)
type ScopeNode struct {
	SymbolID       string       `json:"symbol_id"`
	Name           string       `json:"name"`
	NamePath       string       `json:"name_path"`
	Kind           SymbolKind   `json:"kind"`
	Range          Range        `json:"range"`
	SelectionRange Range        `json:"selection_range"`
	Detail         string       `json:"detail,omitempty"`
	Deprecated     bool         `json:"deprecated,omitempty"`
	Children       []*ScopeNode `json:"children,omitempty"`
	Parent         *ScopeNode   `json:"-"` // Don't serialize parent to avoid cycles

	// Security analysis metadata
	SecurityFlags SecurityFlags `json:"security_flags"`
	CallGraph     []string      `json:"call_graph,omitempty"`
	References    []Location    `json:"references,omitempty"`
}

// SecurityFlags represents security-related flags for a symbol
type SecurityFlags struct {
	HandlesUserInput      bool     `json:"handles_user_input"`
	ExecutesSQLQueries    bool     `json:"executes_sql_queries"`
	ExecutesCommands      bool     `json:"executes_commands"`
	AccessesFilesystem    bool     `json:"accesses_filesystem"`
	HandlesAuthentication bool     `json:"handles_authentication"`
	UsesCrypto            bool     `json:"uses_crypto"`
	TaintedSources        []string `json:"tainted_sources,omitempty"`
	DataFlow              []string `json:"data_flow,omitempty"`
}

// PostingList represents an inverted index entry for name lookups
type PostingList struct {
	Term    string         `json:"term"`
	Entries []PostingEntry `json:"entries"`
	mu      sync.RWMutex
}

// PostingEntry represents an entry in a posting list
type PostingEntry struct {
	SymbolID string     `json:"symbol_id"`
	Score    float64    `json:"score"`
	NamePath string     `json:"name_path"`
	Kind     SymbolKind `json:"kind"`
	FileURI  string     `json:"file_uri"`
}

// IntervalTree provides fast position-based symbol lookups
type IntervalTree struct {
	Root *IntervalNode `json:"root"`
	mu   sync.RWMutex
}

// IntervalNode represents a node in the interval tree
type IntervalNode struct {
	Interval Interval      `json:"interval"`
	SymbolID string        `json:"symbol_id"`
	Left     *IntervalNode `json:"left,omitempty"`
	Right    *IntervalNode `json:"right,omitempty"`
	Max      int           `json:"max"`
}

// Interval represents a range interval
type Interval struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Data  string `json:"data"`
}

// DependencyGraph tracks file/module dependencies
type DependencyGraph struct {
	Nodes map[string]*DependencyNode `json:"nodes"`
	Edges map[string][]string        `json:"edges"`
	mu    sync.RWMutex
}

// DependencyNode represents a file/module in the dependency graph
type DependencyNode struct {
	URI          string            `json:"uri"`
	Language     string            `json:"language"`
	LastModified time.Time         `json:"last_modified"`
	Exports      map[string]string `json:"exports"`
	Imports      map[string]string `json:"imports"`
	Stale        bool              `json:"stale"`
}

// NewSymbolTable creates a new enhanced symbol table
func NewSymbolTable(fileURI, language string, logger *zap.Logger) *SymbolTable {
	return &SymbolTable{
		NameIndex:    make(map[string]*PostingList),
		IntervalTree: &IntervalTree{},
		DependencyGraph: &DependencyGraph{
			Nodes: make(map[string]*DependencyNode),
			Edges: make(map[string][]string),
		},
		FileURI:     fileURI,
		Language:    language,
		LastUpdated: time.Now(),
		stringPool:  make(map[string]string),
		logger:      logger,
	}
}

// BuildFromLSPSymbols builds symbol table from LSP document symbols
func (st *SymbolTable) BuildFromLSPSymbols(symbols []DocumentSymbol, content string) error {
	st.mu.Lock()
	defer st.mu.Unlock()

	// Build scope tree
	st.ScopeTree = st.buildScopeTree(symbols, "")

	// Build name index
	st.buildNameIndex(st.ScopeTree)

	// Build interval tree
	st.buildIntervalTree(st.ScopeTree)

	// Analyze security patterns
	st.analyzeSecurityPatterns(st.ScopeTree, content)

	st.LastUpdated = time.Now()

	return nil
}

// buildScopeTree recursively builds the scope tree from LSP symbols
func (st *SymbolTable) buildScopeTree(symbols []DocumentSymbol, parentPath string) *ScopeNode {
	if len(symbols) == 0 {
		return nil
	}

	// Create root or use first symbol as root
	var root *ScopeNode

	for i, symbol := range symbols {
		namePath := parentPath
		if namePath != "" {
			namePath += "."
		}
		namePath += symbol.Name

		symbolID := st.generateSymbolID(st.FileURI, symbol.Range, symbol.Kind)

		node := &ScopeNode{
			SymbolID:       symbolID,
			Name:           st.intern(symbol.Name),
			NamePath:       st.intern(namePath),
			Kind:           symbol.Kind,
			Range:          symbol.Range,
			SelectionRange: symbol.SelectionRange,
			Detail:         symbol.Detail,
			Deprecated:     symbol.Deprecated,
			SecurityFlags:  SecurityFlags{},
		}

		// Recursively build children
		if len(symbol.Children) > 0 {
			for _, child := range symbol.Children {
				childNode := st.buildScopeTree([]DocumentSymbol{child}, namePath)
				if childNode != nil {
					childNode.Parent = node
					node.Children = append(node.Children, childNode)
				}
			}
		}

		if i == 0 {
			root = node
		} else if root != nil {
			// Add as sibling
			root.Children = append(root.Children, node)
		}
	}

	return root
}

// buildNameIndex builds the inverted index for name-based lookups
func (st *SymbolTable) buildNameIndex(root *ScopeNode) {
	if root == nil {
		return
	}

	st.indexSymbol(root)

	for _, child := range root.Children {
		st.buildNameIndex(child)
	}
}

// indexSymbol adds a symbol to the name index
func (st *SymbolTable) indexSymbol(node *ScopeNode) {
	// Index by exact name
	st.addToIndex(node.Name, node, 1.0)

	// Index by name path components
	parts := strings.Split(node.NamePath, ".")
	for i, part := range parts {
		score := 1.0 / float64(i+1) // Decrease score for deeper components
		st.addToIndex(part, node, score)
	}

	// Index normalized variations (camelCase -> snake_case)
	normalized := st.normalizeIdentifier(node.Name)
	if normalized != node.Name {
		st.addToIndex(normalized, node, 0.8)
	}
}

// addToIndex adds an entry to the posting list for a term
func (st *SymbolTable) addToIndex(term string, node *ScopeNode, score float64) {
	term = strings.ToLower(term)

	if _, exists := st.NameIndex[term]; !exists {
		st.NameIndex[term] = &PostingList{
			Term:    term,
			Entries: make([]PostingEntry, 0),
		}
	}

	entry := PostingEntry{
		SymbolID: node.SymbolID,
		Score:    score,
		NamePath: node.NamePath,
		Kind:     node.Kind,
		FileURI:  st.FileURI,
	}

	st.NameIndex[term].Entries = append(st.NameIndex[term].Entries, entry)
}

// buildIntervalTree builds the interval tree for position-based lookups
func (st *SymbolTable) buildIntervalTree(root *ScopeNode) {
	if root == nil {
		return
	}

	intervals := st.collectIntervals(root)
	st.IntervalTree.Root = st.buildIntervalTreeRecursive(intervals, 0, len(intervals)-1)
}

// collectIntervals collects all intervals from the scope tree
func (st *SymbolTable) collectIntervals(root *ScopeNode) []IntervalNode {
	var intervals []IntervalNode
	st.collectIntervalsRecursive(root, &intervals)

	// Sort by start position
	sort.Slice(intervals, func(i, j int) bool {
		return intervals[i].Interval.Start < intervals[j].Interval.Start
	})

	return intervals
}

// collectIntervalsRecursive recursively collects intervals
func (st *SymbolTable) collectIntervalsRecursive(node *ScopeNode, intervals *[]IntervalNode) {
	if node == nil {
		return
	}

	start := node.Range.Start.Line*1000000 + node.Range.Start.Character
	end := node.Range.End.Line*1000000 + node.Range.End.Character

	*intervals = append(*intervals, IntervalNode{
		Interval: Interval{
			Start: start,
			End:   end,
			Data:  node.SymbolID,
		},
		SymbolID: node.SymbolID,
		Max:      end,
	})

	for _, child := range node.Children {
		st.collectIntervalsRecursive(child, intervals)
	}
}

// buildIntervalTreeRecursive builds interval tree recursively
func (st *SymbolTable) buildIntervalTreeRecursive(intervals []IntervalNode, start, end int) *IntervalNode {
	if start > end {
		return nil
	}

	mid := (start + end) / 2
	node := intervals[mid]

	node.Left = st.buildIntervalTreeRecursive(intervals, start, mid-1)
	node.Right = st.buildIntervalTreeRecursive(intervals, mid+1, end)

	// Update max value
	node.Max = node.Interval.End
	if node.Left != nil && node.Left.Max > node.Max {
		node.Max = node.Left.Max
	}
	if node.Right != nil && node.Right.Max > node.Max {
		node.Max = node.Right.Max
	}

	return &node
}

// analyzeSecurityPatterns analyzes symbols for security patterns
func (st *SymbolTable) analyzeSecurityPatterns(root *ScopeNode, content string) {
	if root == nil {
		return
	}

	st.analyzeSymbolSecurity(root, content)

	for _, child := range root.Children {
		st.analyzeSecurityPatterns(child, content)
	}
}

// analyzeSymbolSecurity analyzes a single symbol for security patterns
func (st *SymbolTable) analyzeSymbolSecurity(node *ScopeNode, content string) {
	// Extract function/method body for analysis
	lines := strings.Split(content, "\n")
	if node.Range.Start.Line >= len(lines) || node.Range.End.Line >= len(lines) {
		return
	}

	var body strings.Builder
	for i := node.Range.Start.Line; i <= node.Range.End.Line; i++ {
		if i < len(lines) {
			body.WriteString(lines[i])
			body.WriteString("\n")
		}
	}

	bodyText := strings.ToLower(body.String())

	// Analyze for security patterns
	node.SecurityFlags.HandlesUserInput = st.checkUserInputPatterns(bodyText)
	node.SecurityFlags.ExecutesSQLQueries = st.checkSQLPatterns(bodyText)
	node.SecurityFlags.ExecutesCommands = st.checkCommandPatterns(bodyText)
	node.SecurityFlags.AccessesFilesystem = st.checkFilesystemPatterns(bodyText)
	node.SecurityFlags.HandlesAuthentication = st.checkAuthPatterns(bodyText)
	node.SecurityFlags.UsesCrypto = st.checkCryptoPatterns(bodyText)

	// Track data flow for taint analysis
	node.SecurityFlags.TaintedSources = st.findTaintedSources(bodyText)
}

// Security pattern detection methods
func (st *SymbolTable) checkUserInputPatterns(body string) bool {
	patterns := []string{
		"$_get", "$_post", "$_request", "$_cookie", "$_session",
		"request.query", "request.body", "request.params",
		"http.request", "r.url.query", "r.form",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func (st *SymbolTable) checkSQLPatterns(body string) bool {
	patterns := []string{
		"select ", "insert ", "update ", "delete ", "drop ",
		"mysql_query", "mysqli_query", "pg_query", "db.query",
		"execute(", "prepare(", "query(",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func (st *SymbolTable) checkCommandPatterns(body string) bool {
	patterns := []string{
		"system(", "exec(", "shell_exec(", "passthru(",
		"os.system", "subprocess.", "exec.command",
		"runtime.exec", "processbuilder",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func (st *SymbolTable) checkFilesystemPatterns(body string) bool {
	patterns := []string{
		"file_get_contents", "fopen(", "fwrite(", "include(",
		"require(", "readfile(", "os.open", "open(",
		"ioutil.readfile", "os.readfile", "filepath.walk",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func (st *SymbolTable) checkAuthPatterns(body string) bool {
	patterns := []string{
		"password", "authenticate", "login", "session",
		"jwt", "token", "auth", "credential",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func (st *SymbolTable) checkCryptoPatterns(body string) bool {
	patterns := []string{
		"md5(", "sha1(", "crypt(", "hash(",
		"encrypt", "decrypt", "cipher", "crypto.",
		"bcrypt", "scrypt", "pbkdf2",
	}

	for _, pattern := range patterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}

func (st *SymbolTable) findTaintedSources(body string) []string {
	var sources []string

	taintSources := []string{
		"$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
		"request.query", "request.body", "request.params",
		"http.Request", "user input", "external data",
	}

	for _, source := range taintSources {
		if strings.Contains(strings.ToLower(body), strings.ToLower(source)) {
			sources = append(sources, source)
		}
	}

	return sources
}

// Query methods

// FindSymbol finds symbols by name with fuzzy matching
func (st *SymbolTable) FindSymbol(nameQuery string, depth int, kinds []SymbolKind) []PostingEntry {
	st.mu.RLock()
	defer st.mu.RUnlock()

	var results []PostingEntry
	normalizedQuery := strings.ToLower(nameQuery)

	// Exact match
	if postingList, exists := st.NameIndex[normalizedQuery]; exists {
		results = append(results, st.filterByKind(postingList.Entries, kinds)...)
	}

	// Fuzzy matching
	for term, postingList := range st.NameIndex {
		if strings.Contains(term, normalizedQuery) && term != normalizedQuery {
			entries := st.filterByKind(postingList.Entries, kinds)
			// Reduce score for fuzzy matches
			for i := range entries {
				entries[i].Score *= 0.7
			}
			results = append(results, entries...)
		}
	}

	// Sort by score
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	return results
}

// FindSymbolAtPosition finds the symbol at a specific position
func (st *SymbolTable) FindSymbolAtPosition(line, character int) *ScopeNode {
	st.mu.RLock()
	defer st.mu.RUnlock()

	position := line*1000000 + character
	node := st.searchInterval(st.IntervalTree.Root, position)
	if node != nil {
		return st.findSymbolByID(node.SymbolID)
	}
	return nil
}

// GetSecurityVulnerabilities returns symbols with security concerns
func (st *SymbolTable) GetSecurityVulnerabilities() []*ScopeNode {
	st.mu.RLock()
	defer st.mu.RUnlock()

	var vulnSymbols []*ScopeNode
	st.collectVulnerableSymbols(st.ScopeTree, &vulnSymbols)
	return vulnSymbols
}

// Helper methods

func (st *SymbolTable) filterByKind(entries []PostingEntry, kinds []SymbolKind) []PostingEntry {
	if len(kinds) == 0 {
		return entries
	}

	var filtered []PostingEntry
	kindMap := make(map[SymbolKind]bool)
	for _, kind := range kinds {
		kindMap[kind] = true
	}

	for _, entry := range entries {
		if kindMap[entry.Kind] {
			filtered = append(filtered, entry)
		}
	}

	return filtered
}

func (st *SymbolTable) searchInterval(node *IntervalNode, position int) *IntervalNode {
	if node == nil {
		return nil
	}

	if position >= node.Interval.Start && position <= node.Interval.End {
		return node
	}

	if node.Left != nil && node.Left.Max >= position {
		return st.searchInterval(node.Left, position)
	}

	return st.searchInterval(node.Right, position)
}

func (st *SymbolTable) findSymbolByID(symbolID string) *ScopeNode {
	return st.findSymbolByIDRecursive(st.ScopeTree, symbolID)
}

func (st *SymbolTable) findSymbolByIDRecursive(node *ScopeNode, symbolID string) *ScopeNode {
	if node == nil {
		return nil
	}

	if node.SymbolID == symbolID {
		return node
	}

	for _, child := range node.Children {
		if found := st.findSymbolByIDRecursive(child, symbolID); found != nil {
			return found
		}
	}

	return nil
}

func (st *SymbolTable) collectVulnerableSymbols(node *ScopeNode, result *[]*ScopeNode) {
	if node == nil {
		return
	}

	// Check if symbol has security concerns
	flags := node.SecurityFlags
	if flags.HandlesUserInput || flags.ExecutesSQLQueries || flags.ExecutesCommands ||
		flags.AccessesFilesystem || len(flags.TaintedSources) > 0 {
		*result = append(*result, node)
	}

	for _, child := range node.Children {
		st.collectVulnerableSymbols(child, result)
	}
}

func (st *SymbolTable) generateSymbolID(uri string, r Range, kind SymbolKind) string {
	data := fmt.Sprintf("%s:%d:%d:%d:%d:%d", uri, r.Start.Line, r.Start.Character, r.End.Line, r.End.Character, int(kind))
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

func (st *SymbolTable) intern(s string) string {
	if interned, exists := st.stringPool[s]; exists {
		return interned
	}
	st.stringPool[s] = s
	return s
}

func (st *SymbolTable) normalizeIdentifier(name string) string {
	// Convert camelCase to snake_case
	var result strings.Builder
	for i, r := range name {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}
