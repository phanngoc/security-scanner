package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// LSPClient represents a Language Server Protocol client
type LSPClient struct {
	cmd           *exec.Cmd
	stdin         io.WriteCloser
	stdout        io.ReadCloser
	stderr        io.ReadCloser
	logger        *zap.Logger
	requestID     int
	responses     map[int]chan *Response
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	workspaceRoot string
	language      string
}

// LSPMessage represents the base LSP message structure
type LSPMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int        `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// Response represents an LSP response
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *LSPError       `json:"error,omitempty"`
}

// LSPError represents an LSP error
type LSPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Position represents a position in a document
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range represents a range in a document
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Location represents a location in a document
type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// SymbolKind represents the kind of a symbol
type SymbolKind int

const (
	SymbolKindFile          SymbolKind = 1
	SymbolKindModule        SymbolKind = 2
	SymbolKindNamespace     SymbolKind = 3
	SymbolKindPackage       SymbolKind = 4
	SymbolKindClass         SymbolKind = 5
	SymbolKindMethod        SymbolKind = 6
	SymbolKindProperty      SymbolKind = 7
	SymbolKindField         SymbolKind = 8
	SymbolKindConstructor   SymbolKind = 9
	SymbolKindEnum          SymbolKind = 10
	SymbolKindInterface     SymbolKind = 11
	SymbolKindFunction      SymbolKind = 12
	SymbolKindVariable      SymbolKind = 13
	SymbolKindConstant      SymbolKind = 14
	SymbolKindString        SymbolKind = 15
	SymbolKindNumber        SymbolKind = 16
	SymbolKindBoolean       SymbolKind = 17
	SymbolKindArray         SymbolKind = 18
	SymbolKindObject        SymbolKind = 19
	SymbolKindKey           SymbolKind = 20
	SymbolKindNull          SymbolKind = 21
	SymbolKindEnumMember    SymbolKind = 22
	SymbolKindStruct        SymbolKind = 23
	SymbolKindEvent         SymbolKind = 24
	SymbolKindOperator      SymbolKind = 25
	SymbolKindTypeParameter SymbolKind = 26
)

// DocumentSymbol represents a symbol in a document
type DocumentSymbol struct {
	Name           string           `json:"name"`
	Detail         string           `json:"detail,omitempty"`
	Kind           SymbolKind       `json:"kind"`
	Deprecated     bool             `json:"deprecated,omitempty"`
	Range          Range            `json:"range"`
	SelectionRange Range            `json:"selectionRange"`
	Children       []DocumentSymbol `json:"children,omitempty"`
}

// WorkspaceSymbol represents a symbol in the workspace
type WorkspaceSymbol struct {
	Name          string     `json:"name"`
	Kind          SymbolKind `json:"kind"`
	Location      Location   `json:"location"`
	ContainerName string     `json:"containerName,omitempty"`
}

// Reference represents a reference to a symbol
type Reference struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// NewLSPClient creates a new LSP client for the specified language
func NewLSPClient(language, workspaceRoot string, logger *zap.Logger) (*LSPClient, error) {
	ctx, cancel := context.WithCancel(context.Background())

	client := &LSPClient{
		logger:        logger,
		responses:     make(map[int]chan *Response),
		ctx:           ctx,
		cancel:        cancel,
		workspaceRoot: workspaceRoot,
		language:      language,
	}

	if err := client.startLanguageServer(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start language server: %w", err)
	}

	go client.handleResponses()

	if err := client.initialize(); err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to initialize LSP: %w", err)
	}

	return client, nil
}

// startLanguageServer starts the appropriate language server
func (c *LSPClient) startLanguageServer() error {
	var serverCmd string
	var args []string

	switch c.language {
	case "go":
		// Use gopls (Go language server)
		serverCmd = "gopls"
		args = []string{"serve"}
	case "php":
		// Use Intelephense PHP language server
		serverCmd = "intelephense"
		args = []string{"--stdio"}
	case "javascript", "typescript":
		// Use TypeScript language server
		serverCmd = "typescript-language-server"
		args = []string{"--stdio"}
	case "python":
		// Use Pylsp or Pyright
		serverCmd = "pylsp"
		args = []string{}
	default:
		return fmt.Errorf("unsupported language: %s", c.language)
	}

	// Check if the language server is available
	if _, err := exec.LookPath(serverCmd); err != nil {
		return fmt.Errorf("language server '%s' not found in PATH. Please install it first", serverCmd)
	}

	c.cmd = exec.CommandContext(c.ctx, serverCmd, args...)
	
	c.logger.Info("Starting language server",
		zap.String("language", c.language),
		zap.String("command", serverCmd),
		zap.Strings("args", args))

	var err error
	c.stdin, err = c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	c.stdout, err = c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	c.stderr, err = c.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start language server: %w", err)
	}

	c.logger.Info("Started language server",
		zap.String("language", c.language),
		zap.Int("pid", c.cmd.Process.Pid))

	return nil
}

// initialize sends the initialize request to the language server
func (c *LSPClient) initialize() error {
	params := map[string]interface{}{
		"processId": os.Getpid(),
		"rootUri":   fmt.Sprintf("file://%s", c.workspaceRoot),
		"capabilities": map[string]interface{}{
			"textDocument": map[string]interface{}{
				"documentSymbol": map[string]interface{}{
					"dynamicRegistration": false,
					"symbolKind": map[string]interface{}{
						"valueSet": []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26},
					},
					"hierarchicalDocumentSymbolSupport": true,
				},
				"definition": map[string]interface{}{
					"dynamicRegistration": false,
					"linkSupport":         false,
				},
				"references": map[string]interface{}{
					"dynamicRegistration": false,
				},
			},
			"workspace": map[string]interface{}{
				"symbol": map[string]interface{}{
					"dynamicRegistration": false,
					"symbolKind": map[string]interface{}{
						"valueSet": []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26},
					},
				},
			},
		},
	}

	// Add initialization timeout
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	// Create a channel to handle the initialization
	initDone := make(chan error, 1)

	go func() {
		resp, err := c.sendRequest("initialize", params)
		if err != nil {
			initDone <- fmt.Errorf("initialize request failed: %w", err)
			return
		}

		if resp.Error != nil {
			initDone <- fmt.Errorf("initialize error: %s", resp.Error.Message)
			return
		}

		// Send initialized notification
		err = c.sendNotification("initialized", map[string]interface{}{})
		initDone <- err
	}()

	select {
	case err := <-initDone:
		return err
	case <-ctx.Done():
		return fmt.Errorf("LSP initialization timeout after 10 seconds")
	}
}

// sendRequest sends a request and waits for response
func (c *LSPClient) sendRequest(method string, params interface{}) (*Response, error) {
	c.mu.Lock()
	c.requestID++
	id := c.requestID
	respChan := make(chan *Response, 1)
	c.responses[id] = respChan
	c.mu.Unlock()

	msg := LSPMessage{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  method,
		Params:  params,
	}

	if err := c.sendMessage(msg); err != nil {
		c.mu.Lock()
		delete(c.responses, id)
		c.mu.Unlock()
		return nil, err
	}

	select {
	case resp := <-respChan:
		c.mu.Lock()
		delete(c.responses, id)
		c.mu.Unlock()
		return resp, nil
	case <-time.After(30 * time.Second):
		c.mu.Lock()
		delete(c.responses, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("request timeout")
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// sendNotification sends a notification (no response expected)
func (c *LSPClient) sendNotification(method string, params interface{}) error {
	msg := LSPMessage{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	}
	return c.sendMessage(msg)
}

// sendMessage sends an LSP message
func (c *LSPClient) sendMessage(msg LSPMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	content := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(data), data)

	c.logger.Debug("Sending LSP message",
		zap.String("method", msg.Method),
		zap.String("content", content))

	_, err = c.stdin.Write([]byte(content))
	return err
}

// handleResponses handles incoming responses from the language server
func (c *LSPClient) handleResponses() {
	scanner := bufio.NewScanner(c.stdout)
	var contentLength int

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Content-Length: ") {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
			continue
		}

		if line == "" && contentLength > 0 {
			// Read the JSON content
			content := make([]byte, contentLength)
			if _, err := io.ReadFull(c.stdout, content); err != nil {
				c.logger.Error("Failed to read LSP response content", zap.Error(err))
				continue
			}

			c.logger.Debug("Received LSP response", zap.String("content", string(content)))

			var resp Response
			if err := json.Unmarshal(content, &resp); err != nil {
				c.logger.Error("Failed to unmarshal LSP response", zap.Error(err))
				continue
			}

			c.mu.RLock()
			if respChan, exists := c.responses[resp.ID]; exists {
				select {
				case respChan <- &resp:
				default:
					c.logger.Warn("Response channel full", zap.Int("id", resp.ID))
				}
			}
			c.mu.RUnlock()

			contentLength = 0
		}
	}
}

// GetDocumentSymbols gets symbols for a document
func (c *LSPClient) GetDocumentSymbols(uri string) ([]DocumentSymbol, error) {
	params := map[string]interface{}{
		"textDocument": map[string]string{
			"uri": uri,
		},
	}

	resp, err := c.sendRequest("textDocument/documentSymbol", params)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("documentSymbol error: %s", resp.Error.Message)
	}

	var symbols []DocumentSymbol
	if err := json.Unmarshal(resp.Result, &symbols); err != nil {
		return nil, fmt.Errorf("failed to unmarshal document symbols: %w", err)
	}

	return symbols, nil
}

// GetWorkspaceSymbols gets symbols matching a query in the workspace
func (c *LSPClient) GetWorkspaceSymbols(query string) ([]WorkspaceSymbol, error) {
	params := map[string]interface{}{
		"query": query,
	}

	resp, err := c.sendRequest("workspace/symbol", params)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("workspace/symbol error: %s", resp.Error.Message)
	}

	var symbols []WorkspaceSymbol
	if err := json.Unmarshal(resp.Result, &symbols); err != nil {
		return nil, fmt.Errorf("failed to unmarshal workspace symbols: %w", err)
	}

	return symbols, nil
}

// GetDefinition gets the definition location for a symbol at a position
func (c *LSPClient) GetDefinition(uri string, position Position) ([]Location, error) {
	params := map[string]interface{}{
		"textDocument": map[string]string{
			"uri": uri,
		},
		"position": position,
	}

	resp, err := c.sendRequest("textDocument/definition", params)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("definition error: %s", resp.Error.Message)
	}

	var locations []Location
	if err := json.Unmarshal(resp.Result, &locations); err != nil {
		// Try single location format
		var location Location
		if err2 := json.Unmarshal(resp.Result, &location); err2 != nil {
			return nil, fmt.Errorf("failed to unmarshal definition: %w", err)
		}
		locations = []Location{location}
	}

	return locations, nil
}

// GetReferences gets all references to a symbol at a position
func (c *LSPClient) GetReferences(uri string, position Position, includeDeclaration bool) ([]Location, error) {
	params := map[string]interface{}{
		"textDocument": map[string]string{
			"uri": uri,
		},
		"position": position,
		"context": map[string]bool{
			"includeDeclaration": includeDeclaration,
		},
	}

	resp, err := c.sendRequest("textDocument/references", params)
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("references error: %s", resp.Error.Message)
	}

	var locations []Location
	if err := json.Unmarshal(resp.Result, &locations); err != nil {
		return nil, fmt.Errorf("failed to unmarshal references: %w", err)
	}

	return locations, nil
}

// OpenDocument notifies the server that a document is open
func (c *LSPClient) OpenDocument(uri, languageId, text string, version int) error {
	params := map[string]interface{}{
		"textDocument": map[string]interface{}{
			"uri":        uri,
			"languageId": languageId,
			"version":    version,
			"text":       text,
		},
	}

	return c.sendNotification("textDocument/didOpen", params)
}

// CloseDocument notifies the server that a document is closed
func (c *LSPClient) CloseDocument(uri string) error {
	params := map[string]interface{}{
		"textDocument": map[string]string{
			"uri": uri,
		},
	}

	return c.sendNotification("textDocument/didClose", params)
}

// Close closes the LSP client and terminates the language server
func (c *LSPClient) Close() error {
	if c.cancel != nil {
		c.cancel()
	}

	if c.stdin != nil {
		c.stdin.Close()
	}

	if c.cmd != nil && c.cmd.Process != nil {
		return c.cmd.Process.Kill()
	}

	return nil
}

// FileToURI converts a file path to a URI
func FileToURI(filePath string) string {
	absPath, _ := filepath.Abs(filePath)
	return "file://" + absPath
}

// URIToFile converts a URI to a file path
func URIToFile(uri string) string {
	return strings.TrimPrefix(uri, "file://")
}
