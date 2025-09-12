package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/le-company/security-scanner/internal/lsp"
	"go.uber.org/zap"
)

// SymbolTableCache manages cached symbol tables for improved performance
type SymbolTableCache struct {
	cacheDir string
	logger   *zap.Logger
	maxSize  int64 // Maximum cache size in bytes
	maxAge   time.Duration
}

// CacheEntry represents a cached symbol table entry
type CacheEntry struct {
	FileHash    string           `json:"file_hash"`
	ModTime     time.Time        `json:"mod_time"`
	FileSize    int64            `json:"file_size"`
	Language    string           `json:"language"`
	CreatedAt   time.Time        `json:"created_at"`
	SymbolTable *lsp.SymbolTable `json:"symbol_table"`
	Version     string           `json:"version"`
}

// CacheMetadata tracks cache statistics and management info
type CacheMetadata struct {
	Entries     map[string]*CacheEntryInfo `json:"entries"`
	TotalSize   int64                      `json:"total_size"`
	LastCleanup time.Time                  `json:"last_cleanup"`
	Version     string                     `json:"version"`
}

// CacheEntryInfo contains metadata about a cache entry without the full symbol table
type CacheEntryInfo struct {
	FileHash  string    `json:"file_hash"`
	ModTime   time.Time `json:"mod_time"`
	FileSize  int64     `json:"file_size"`
	Language  string    `json:"language"`
	CreatedAt time.Time `json:"created_at"`
	CacheSize int64     `json:"cache_size"`
}

const (
	CacheVersion     = "1.0"
	DefaultMaxSize   = 1024 * 1024 * 1024 // 1GB
	DefaultMaxAge    = 7 * 24 * time.Hour // 7 days
	MetadataFileName = "cache_metadata.json"
)

// NewSymbolTableCache creates a new symbol table cache
func NewSymbolTableCache(cacheDir string, logger *zap.Logger) (*SymbolTableCache, error) {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	cache := &SymbolTableCache{
		cacheDir: cacheDir,
		logger:   logger,
		maxSize:  DefaultMaxSize,
		maxAge:   DefaultMaxAge,
	}

	// Initialize cache metadata
	if _, err := cache.loadMetadata(); err != nil {
		cache.logger.Warn("Failed to load cache metadata, creating new", zap.Error(err))
		cache.initializeMetadata()
	}

	return cache, nil
}

// Get retrieves a symbol table from cache if available and valid
func (c *SymbolTableCache) Get(filePath string) (*lsp.SymbolTable, bool) {
	// Calculate cache key
	cacheKey := c.getCacheKey(filePath)
	cachePath := c.getCachePath(cacheKey)

	// Check if cache file exists
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		c.logger.Debug("Cache miss - file not found", zap.String("file", filePath))
		return nil, false
	}

	// Get file info for validation
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		c.logger.Debug("Cache miss - source file not accessible", zap.String("file", filePath), zap.Error(err))
		return nil, false
	}

	// Calculate file hash for validation
	fileHash, err := c.calculateFileHash(filePath)
	if err != nil {
		c.logger.Debug("Cache miss - failed to calculate file hash", zap.String("file", filePath), zap.Error(err))
		return nil, false
	}

	// Load cache entry
	entry, err := c.loadCacheEntry(cachePath)
	if err != nil {
		c.logger.Debug("Cache miss - failed to load cache entry", zap.String("file", filePath), zap.Error(err))
		return nil, false
	}

	// Validate cache entry
	if !c.isCacheValid(entry, fileHash, fileInfo.ModTime(), fileInfo.Size()) {
		c.logger.Debug("Cache miss - entry invalid", zap.String("file", filePath))
		// Remove invalid cache entry
		c.Remove(filePath)
		return nil, false
	}

	c.logger.Debug("Cache hit", zap.String("file", filePath))
	return entry.SymbolTable, true
}

// Set stores a symbol table in cache
func (c *SymbolTableCache) Set(filePath string, symbolTable *lsp.SymbolTable) error {
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	// Calculate file hash
	fileHash, err := c.calculateFileHash(filePath)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}

	// Detect language
	language := c.detectLanguage(filePath)

	// Create cache entry
	entry := &CacheEntry{
		FileHash:    fileHash,
		ModTime:     fileInfo.ModTime(),
		FileSize:    fileInfo.Size(),
		Language:    language,
		CreatedAt:   time.Now(),
		SymbolTable: symbolTable,
		Version:     CacheVersion,
	}

	// Save cache entry
	cacheKey := c.getCacheKey(filePath)
	cachePath := c.getCachePath(cacheKey)

	if err := c.saveCacheEntry(cachePath, entry); err != nil {
		return fmt.Errorf("failed to save cache entry: %w", err)
	}

	// Update metadata
	c.updateMetadata(filePath, entry, cachePath)

	c.logger.Debug("Cached symbol table", zap.String("file", filePath))
	return nil
}

// Remove removes a cache entry
func (c *SymbolTableCache) Remove(filePath string) error {
	cacheKey := c.getCacheKey(filePath)
	cachePath := c.getCachePath(cacheKey)

	// Remove cache file
	if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cache file: %w", err)
	}

	// Remove from metadata
	c.removeFromMetadata(filePath)

	c.logger.Debug("Removed cache entry", zap.String("file", filePath))
	return nil
}

// Clear removes all cache entries
func (c *SymbolTableCache) Clear() error {
	// Remove all cache files
	entries, err := os.ReadDir(c.cacheDir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != MetadataFileName {
			if err := os.Remove(filepath.Join(c.cacheDir, entry.Name())); err != nil {
				c.logger.Warn("Failed to remove cache file", zap.String("file", entry.Name()), zap.Error(err))
			}
		}
	}

	// Reset metadata
	c.initializeMetadata()

	c.logger.Info("Cleared all cache entries")
	return nil
}

// Cleanup removes expired and oversized cache entries
func (c *SymbolTableCache) Cleanup() error {
	metadata, err := c.loadMetadata()
	if err != nil {
		return fmt.Errorf("failed to load metadata for cleanup: %w", err)
	}

	now := time.Now()
	var removedCount int
	var reclaimedSize int64

	// Remove expired entries
	for filePath, entryInfo := range metadata.Entries {
		if now.Sub(entryInfo.CreatedAt) > c.maxAge {
			if err := c.Remove(filePath); err != nil {
				c.logger.Warn("Failed to remove expired cache entry", zap.String("file", filePath), zap.Error(err))
			} else {
				removedCount++
				reclaimedSize += entryInfo.CacheSize
			}
		}
	}

	// If still over size limit, remove oldest entries
	if metadata.TotalSize > c.maxSize {
		// Sort entries by creation time and remove oldest
		type entryWithPath struct {
			path string
			info *CacheEntryInfo
		}

		var entries []entryWithPath
		for path, info := range metadata.Entries {
			entries = append(entries, entryWithPath{path: path, info: info})
		}

		// Sort by creation time (oldest first)
		for i := 0; i < len(entries)-1; i++ {
			for j := i + 1; j < len(entries); j++ {
				if entries[i].info.CreatedAt.After(entries[j].info.CreatedAt) {
					entries[i], entries[j] = entries[j], entries[i]
				}
			}
		}

		// Remove oldest entries until under size limit
		for _, entry := range entries {
			if metadata.TotalSize <= c.maxSize {
				break
			}
			if err := c.Remove(entry.path); err != nil {
				c.logger.Warn("Failed to remove oversized cache entry", zap.String("file", entry.path), zap.Error(err))
			} else {
				removedCount++
				reclaimedSize += entry.info.CacheSize
				metadata.TotalSize -= entry.info.CacheSize
			}
		}
	}

	metadata.LastCleanup = now
	c.saveMetadata(metadata)

	if removedCount > 0 {
		c.logger.Info("Cache cleanup completed",
			zap.Int("removed_entries", removedCount),
			zap.Int64("reclaimed_bytes", reclaimedSize))
	}

	return nil
}

// GetStats returns cache statistics
func (c *SymbolTableCache) GetStats() (map[string]interface{}, error) {
	metadata, err := c.loadMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to load metadata: %w", err)
	}

	return map[string]interface{}{
		"total_entries": len(metadata.Entries),
		"total_size":    metadata.TotalSize,
		"cache_dir":     c.cacheDir,
		"max_size":      c.maxSize,
		"max_age":       c.maxAge.String(),
		"last_cleanup":  metadata.LastCleanup,
		"version":       metadata.Version,
	}, nil
}

// Helper methods

func (c *SymbolTableCache) getCacheKey(filePath string) string {
	absPath, _ := filepath.Abs(filePath)
	hash := sha256.Sum256([]byte(absPath))
	return hex.EncodeToString(hash[:])
}

func (c *SymbolTableCache) getCachePath(cacheKey string) string {
	return filepath.Join(c.cacheDir, cacheKey+".json")
}

func (c *SymbolTableCache) calculateFileHash(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:]), nil
}

func (c *SymbolTableCache) detectLanguage(filePath string) string {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".go":
		return "go"
	case ".php":
		return "php"
	case ".js", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".java":
		return "java"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".cs":
		return "csharp"
	case ".cpp", ".cc", ".cxx":
		return "cpp"
	case ".c":
		return "c"
	default:
		return "unknown"
	}
}

func (c *SymbolTableCache) isCacheValid(entry *CacheEntry, fileHash string, modTime time.Time, fileSize int64) bool {
	// Check version compatibility
	if entry.Version != CacheVersion {
		return false
	}

	// Check file hash
	if entry.FileHash != fileHash {
		return false
	}

	// Check modification time
	if !entry.ModTime.Equal(modTime) {
		return false
	}

	// Check file size
	if entry.FileSize != fileSize {
		return false
	}

	// Check age
	if time.Since(entry.CreatedAt) > c.maxAge {
		return false
	}

	return true
}

func (c *SymbolTableCache) loadCacheEntry(cachePath string) (*CacheEntry, error) {
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	var entry CacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

func (c *SymbolTableCache) saveCacheEntry(cachePath string, entry *CacheEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return os.WriteFile(cachePath, data, 0644)
}

func (c *SymbolTableCache) loadMetadata() (*CacheMetadata, error) {
	metadataPath := filepath.Join(c.cacheDir, MetadataFileName)

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, err
	}

	var metadata CacheMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func (c *SymbolTableCache) saveMetadata(metadata *CacheMetadata) error {
	metadataPath := filepath.Join(c.cacheDir, MetadataFileName)

	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	return os.WriteFile(metadataPath, data, 0644)
}

func (c *SymbolTableCache) initializeMetadata() {
	metadata := &CacheMetadata{
		Entries:     make(map[string]*CacheEntryInfo),
		TotalSize:   0,
		LastCleanup: time.Now(),
		Version:     CacheVersion,
	}
	c.saveMetadata(metadata)
}

func (c *SymbolTableCache) updateMetadata(filePath string, entry *CacheEntry, cachePath string) {
	metadata, err := c.loadMetadata()
	if err != nil {
		c.logger.Warn("Failed to load metadata for update", zap.Error(err))
		return
	}

	// Get cache file size
	cacheInfo, err := os.Stat(cachePath)
	var cacheSize int64
	if err == nil {
		cacheSize = cacheInfo.Size()
	}

	// Remove old entry size if exists
	if oldInfo, exists := metadata.Entries[filePath]; exists {
		metadata.TotalSize -= oldInfo.CacheSize
	}

	// Add new entry
	metadata.Entries[filePath] = &CacheEntryInfo{
		FileHash:  entry.FileHash,
		ModTime:   entry.ModTime,
		FileSize:  entry.FileSize,
		Language:  entry.Language,
		CreatedAt: entry.CreatedAt,
		CacheSize: cacheSize,
	}
	metadata.TotalSize += cacheSize

	c.saveMetadata(metadata)
}

func (c *SymbolTableCache) removeFromMetadata(filePath string) {
	metadata, err := c.loadMetadata()
	if err != nil {
		c.logger.Warn("Failed to load metadata for removal", zap.Error(err))
		return
	}

	if entryInfo, exists := metadata.Entries[filePath]; exists {
		metadata.TotalSize -= entryInfo.CacheSize
		delete(metadata.Entries, filePath)
		c.saveMetadata(metadata)
	}
}
