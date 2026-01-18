package main

//go:generate goversioninfo

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Command represents a scheduled command to run on agents
type Command struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	IntervalSec int    `json:"interval_sec"`
	OS          string `json:"os"` // "linux", "windows", or "all"
	CreatedAt   string `json:"created_at"`
}

// CommandResult represents the result of a command execution
type CommandResult struct {
	AgentID       string  `json:"agent_id"`
	CommandID     string  `json:"command_id"`
	Command       string  `json:"command"`
	Stdout        string  `json:"stdout"`
	Stderr        string  `json:"stderr"`
	ReturnCode    int     `json:"return_code"`
	StartTime     string  `json:"start_time"`
	ExecutionTime float64 `json:"execution_time_sec"`
	RemoteAddr    string  `json:"remote_addr,omitempty"`
	XForwardedFor string  `json:"x_forwarded_for,omitempty"`
}

// Agent represents a connected agent
type Agent struct {
	ID            string `json:"id"`
	OS            string `json:"os"`
	ConnectedAt   string `json:"connected_at"`
	LastSeen      string `json:"last_seen"`
	Connected     bool   `json:"connected"`
	RemoteAddr    string `json:"remote_addr,omitempty"`
	XForwardedFor string `json:"x_forwarded_for,omitempty"`
	conn          *websocket.Conn
	mu            sync.Mutex
}

// SyncFile represents a file available for sync
type SyncFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	ModTime  string `json:"mod_time"`
	Checksum string `json:"checksum"`
}

// ServerConfig holds the server configuration
type ServerConfig struct {
	AdminToken string `json:"admin_token"`
	AgentToken string `json:"agent_token"`
	Port       int    `json:"port"`
}

// LogRotationConfig holds log rotation settings
type LogRotationConfig struct {
	Enabled     bool // Whether rotation is enabled
	RotateDaily bool // Rotate at midnight UTC
	MaxSizeMB   int  // Rotate when file exceeds this size (0 = no size limit)
	MaxAgeDays  int  // Delete logs older than this (0 = keep forever)
	MaxFiles    int  // Maximum number of rotated files to keep (0 = unlimited)
}

// Message types for websocket communication
type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type CommandListPayload struct {
	Commands []Command `json:"commands"`
}

type SyncFileListPayload struct {
	Files []SyncFile `json:"files"`
}

type FileRequestPayload struct {
	Filename string `json:"filename"`
}

type FileDataPayload struct {
	Filename string `json:"filename"`
	Data     string `json:"data"` // base64 encoded
}

// AdHocCommand represents a one-time command to run on a specific agent
type AdHocCommand struct {
	ID         string `json:"id"`
	AgentID    string `json:"agent_id"`
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeout_sec,omitempty"` // Optional timeout (default 60s)
}

// AdHocCommandRequest is the API request for running an ad-hoc command
type AdHocCommandRequest struct {
	AgentID    string `json:"agent_id"`
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	Wait       bool   `json:"wait,omitempty"` // If true, wait for result before responding
}

// AdHocCommandResponse is the API response for ad-hoc commands
type AdHocCommandResponse struct {
	ID      string         `json:"id"`
	AgentID string         `json:"agent_id"`
	Command string         `json:"command"`
	Status  string         `json:"status"` // "pending", "completed", "timeout", "error"
	Result  *CommandResult `json:"result,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// PendingAdHocCommand tracks an ad-hoc command waiting for results
type PendingAdHocCommand struct {
	Request    AdHocCommandRequest
	ResultChan chan CommandResult
	CreatedAt  time.Time
}

// Server state
type Server struct {
	config         ServerConfig
	commands       map[string]Command
	agents         map[string]*Agent
	syncDir        string
	dataDir        string
	commandsMu     sync.RWMutex
	agentsMu       sync.RWMutex
	upgrader       websocket.Upgrader
	resultLog      *os.File
	resultLogMu    sync.Mutex
	gzWriter       *gzip.Writer
	logRotation    LogRotationConfig
	currentLogDay  int // Day of year for current log file
	logStartTime   time.Time
	pendingAdHoc   map[string]*PendingAdHocCommand // Keyed by command ID
	pendingAdHocMu sync.RWMutex
}

// Agent state
type AgentState struct {
	id         string
	serverURL  string
	agentToken string
	dataDir    string // Base directory for agent data
	stateDir   string // Directory for agent state (ID, last run times)
	syncDir    string // Directory for synced files
	lastRun    map[string]time.Time
	lastRunMu  sync.Mutex
	commands   map[string]Command // Persisted commands
	commandsMu sync.RWMutex
	conn       *websocket.Conn
	connMu     sync.Mutex
}

func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func nowISO8601() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func parseISO8601(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// ==================== SERVER ====================

// loadOrGenerateToken loads a token from a file if it exists, otherwise generates
// a new token and saves it to the file for persistence across restarts.
func loadOrGenerateToken(dataDir, tokenName string) string {
	tokenFile := filepath.Join(dataDir, "."+tokenName)

	// Try to read existing token
	if data, err := os.ReadFile(tokenFile); err == nil {
		existingToken := strings.TrimSpace(string(data))
		if existingToken != "" {
			log.Printf("Loaded %s from disk", tokenName)
			return existingToken
		}
	}

	// Generate new token and persist it
	token := generateToken()
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		log.Printf("Warning: could not persist %s: %v", tokenName, err)
	} else {
		log.Printf("Generated and saved new %s", tokenName)
	}

	return token
}

func NewServer(port int, dataDir string, adminToken, agentToken string, logRotation LogRotationConfig) *Server {
	// Ensure data directory exists before trying to load tokens
	os.MkdirAll(dataDir, 0755)

	// Load or generate tokens
	if adminToken == "" {
		adminToken = loadOrGenerateToken(dataDir, "admin_token")
	}
	if agentToken == "" {
		agentToken = loadOrGenerateToken(dataDir, "agent_token")
	}

	syncDir := filepath.Join(dataDir, "sync")
	os.MkdirAll(syncDir, 0755)
	os.MkdirAll(filepath.Join(syncDir, "linux"), 0755)
	os.MkdirAll(filepath.Join(syncDir, "windows"), 0755)
	os.MkdirAll(dataDir, 0755)

	now := time.Now().UTC()
	s := &Server{
		config: ServerConfig{
			AdminToken: adminToken,
			AgentToken: agentToken,
			Port:       port,
		},
		commands:      make(map[string]Command),
		agents:        make(map[string]*Agent),
		pendingAdHoc:  make(map[string]*PendingAdHocCommand),
		syncDir:       syncDir,
		dataDir:       dataDir,
		logRotation:   logRotation,
		currentLogDay: now.YearDay(),
		logStartTime:  now,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}

	s.loadCommands()
	s.openResultLog()

	// Start log rotation checker if enabled
	if logRotation.Enabled {
		go s.logRotationLoop()
	}

	return s
}

func (s *Server) loadCommands() {
	path := filepath.Join(s.dataDir, "commands.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var commands []Command
	if err := json.Unmarshal(data, &commands); err != nil {
		log.Printf("Error loading commands: %v", err)
		return
	}
	for _, cmd := range commands {
		s.commands[cmd.ID] = cmd
	}
	log.Printf("Loaded %d commands from disk", len(commands))
}

func (s *Server) saveCommands() error {
	s.commandsMu.RLock()
	commands := make([]Command, 0, len(s.commands))
	for _, cmd := range s.commands {
		commands = append(commands, cmd)
	}
	s.commandsMu.RUnlock()

	data, err := json.MarshalIndent(commands, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dataDir, "commands.json")
	return os.WriteFile(path, data, 0644)
}

func (s *Server) openResultLog() {
	path := s.currentLogPath()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open result log: %v", err)
	}
	s.resultLog = f
	s.logStartTime = time.Now().UTC()
	s.currentLogDay = time.Now().UTC().YearDay()
}

func (s *Server) currentLogPath() string {
	return filepath.Join(s.dataDir, "results.json")
}

func (s *Server) rotatedLogPath(t time.Time) string {
	timestamp := t.Format("2006-01-02T15-04-05")
	return filepath.Join(s.dataDir, fmt.Sprintf("results-%s.json.gz", timestamp))
}

func (s *Server) logResult(result CommandResult) {
	s.resultLogMu.Lock()
	defer s.resultLogMu.Unlock()

	// Check if we need to rotate before writing
	if s.shouldRotate() {
		s.rotateLogLocked()
	}

	data, _ := json.Marshal(result)
	s.resultLog.Write(data)
	s.resultLog.Write([]byte("\n"))
	s.resultLog.Sync()
}

func (s *Server) shouldRotate() bool {
	if !s.logRotation.Enabled {
		return false
	}

	now := time.Now().UTC()

	// Check daily rotation (at midnight UTC)
	if s.logRotation.RotateDaily && now.YearDay() != s.currentLogDay {
		return true
	}

	// Check size-based rotation
	if s.logRotation.MaxSizeMB > 0 {
		if info, err := s.resultLog.Stat(); err == nil {
			maxBytes := int64(s.logRotation.MaxSizeMB) * 1024 * 1024
			if info.Size() >= maxBytes {
				return true
			}
		}
	}

	return false
}

func (s *Server) rotateLogLocked() {
	// Close current log
	if s.resultLog != nil {
		s.resultLog.Close()
	}

	// Compress and rename current log with timestamp
	currentPath := s.currentLogPath()
	if _, err := os.Stat(currentPath); err == nil {
		rotatedPath := s.rotatedLogPath(s.logStartTime)

		// Compress the file
		if err := compressFile(currentPath, rotatedPath); err != nil {
			log.Printf("Error compressing log: %v", err)
		} else {
			// Remove the uncompressed original
			os.Remove(currentPath)
			log.Printf("Rotated and compressed log to: %s", filepath.Base(rotatedPath))
		}
	}

	// Open new log
	s.openResultLog()

	// Clean up old logs
	s.cleanupOldLogs()
}

// compressFile compresses src to dst using gzip
func compressFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	gzWriter := gzip.NewWriter(dstFile)
	defer gzWriter.Close()

	_, err = io.Copy(gzWriter, srcFile)
	return err
}

func (s *Server) cleanupOldLogs() {
	if s.logRotation.MaxAgeDays <= 0 && s.logRotation.MaxFiles <= 0 {
		return
	}

	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return
	}

	type logFile struct {
		name    string
		modTime time.Time
	}

	var logFiles []logFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Match rotated log files: results-YYYY-MM-DDTHH-MM-SS.json.gz
		if strings.HasPrefix(name, "results-") && strings.HasSuffix(name, ".json.gz") && name != "results.json.gz" {
			if info, err := entry.Info(); err == nil {
				logFiles = append(logFiles, logFile{name: name, modTime: info.ModTime()})
			}
		}
	}

	// Sort by modification time (oldest first)
	for i := 0; i < len(logFiles)-1; i++ {
		for j := i + 1; j < len(logFiles); j++ {
			if logFiles[i].modTime.After(logFiles[j].modTime) {
				logFiles[i], logFiles[j] = logFiles[j], logFiles[i]
			}
		}
	}

	now := time.Now().UTC()
	deleted := 0

	for i, lf := range logFiles {
		shouldDelete := false

		// Check age
		if s.logRotation.MaxAgeDays > 0 {
			age := now.Sub(lf.modTime)
			if age > time.Duration(s.logRotation.MaxAgeDays)*24*time.Hour {
				shouldDelete = true
			}
		}

		// Check file count (keep newest MaxFiles)
		if s.logRotation.MaxFiles > 0 {
			filesRemaining := len(logFiles) - i - deleted
			if filesRemaining > s.logRotation.MaxFiles {
				shouldDelete = true
			}
		}

		if shouldDelete {
			path := filepath.Join(s.dataDir, lf.name)
			if err := os.Remove(path); err == nil {
				log.Printf("Deleted old log: %s", lf.name)
				deleted++
			}
		}
	}
}

func (s *Server) logRotationLoop() {
	// Check every minute for rotation conditions
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.resultLogMu.Lock()
		if s.shouldRotate() {
			s.rotateLogLocked()
		}
		s.resultLogMu.Unlock()
	}
}

func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("admin_token")
		} else {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AdminToken)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleCommands(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.commandsMu.RLock()
		commands := make([]Command, 0, len(s.commands))
		for _, cmd := range s.commands {
			commands = append(commands, cmd)
		}
		s.commandsMu.RUnlock()
		json.NewEncoder(w).Encode(commands)

	case http.MethodPost:
		var cmd Command
		if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if cmd.ID == "" {
			cmd.ID = generateToken()[:16]
		}
		if cmd.OS == "" {
			cmd.OS = "all"
		}
		cmd.CreatedAt = nowISO8601()

		s.commandsMu.Lock()
		s.commands[cmd.ID] = cmd
		s.commandsMu.Unlock()

		if err := s.saveCommands(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.broadcastCommands()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(cmd)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}

		s.commandsMu.Lock()
		delete(s.commands, id)
		s.commandsMu.Unlock()

		if err := s.saveCommands(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.broadcastCommands()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"deleted": id})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.agentsMu.RLock()
	agents := make([]map[string]interface{}, 0, len(s.agents))
	for _, agent := range s.agents {
		agents = append(agents, map[string]interface{}{
			"id":           agent.ID,
			"os":           agent.OS,
			"connected_at": agent.ConnectedAt,
			"last_seen":    agent.LastSeen,
			"connected":    agent.Connected,
		})
	}
	s.agentsMu.RUnlock()

	json.NewEncoder(w).Encode(agents)
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	// Get OS type from query parameter (required for all operations)
	osType := r.URL.Query().Get("os")
	if osType != "linux" && osType != "windows" {
		http.Error(w, "os parameter required (linux or windows)", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List files for the specified OS
		files := s.listSyncFiles(osType)
		json.NewEncoder(w).Encode(files)

	case http.MethodPost:
		// Upload file
		if err := r.ParseMultipartForm(100 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		filename := filepath.Base(header.Filename)
		destPath := filepath.Join(s.syncDir, osType, filename)
		dest, err := os.Create(destPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer dest.Close()

		io.Copy(dest, file)
		s.broadcastFileList()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"uploaded": filename, "os": osType})

	case http.MethodDelete:
		filename := r.URL.Query().Get("filename")
		if filename == "" {
			http.Error(w, "filename required", http.StatusBadRequest)
			return
		}

		// Sanitize filename to prevent directory traversal
		filename = filepath.Base(filename)
		filePath := filepath.Join(s.syncDir, osType, filename)

		if err := os.Remove(filePath); err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "File not found", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		s.broadcastFileList()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"deleted": filename, "os": osType})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	osType := r.URL.Query().Get("os")
	if osType != "linux" && osType != "windows" {
		http.Error(w, "os parameter required (linux or windows)", http.StatusBadRequest)
		return
	}

	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "filename required", http.StatusBadRequest)
		return
	}

	// Sanitize filename
	filename = filepath.Base(filename)
	filePath := filepath.Join(s.syncDir, osType, filename)

	http.ServeFile(w, r, filePath)
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AdHocCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	if req.Command == "" {
		http.Error(w, "command is required", http.StatusBadRequest)
		return
	}

	// Set default timeout
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = 60
	}

	// Check if agent exists and is connected
	s.agentsMu.RLock()
	agent, exists := s.agents[req.AgentID]
	s.agentsMu.RUnlock()

	if !exists {
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	if !agent.Connected {
		http.Error(w, "Agent not connected", http.StatusServiceUnavailable)
		return
	}

	// Generate command ID
	cmdID := "adhoc-" + generateToken()[:16]

	// Create ad-hoc command
	adHocCmd := AdHocCommand{
		ID:         cmdID,
		AgentID:    req.AgentID,
		Command:    req.Command,
		TimeoutSec: req.TimeoutSec,
	}

	response := AdHocCommandResponse{
		ID:      cmdID,
		AgentID: req.AgentID,
		Command: req.Command,
		Status:  "pending",
	}

	if req.Wait {
		// Create pending command with result channel
		resultChan := make(chan CommandResult, 1)
		pending := &PendingAdHocCommand{
			Request:    req,
			ResultChan: resultChan,
			CreatedAt:  time.Now(),
		}

		s.pendingAdHocMu.Lock()
		s.pendingAdHoc[cmdID] = pending
		s.pendingAdHocMu.Unlock()

		// Clean up when done
		defer func() {
			s.pendingAdHocMu.Lock()
			delete(s.pendingAdHoc, cmdID)
			s.pendingAdHocMu.Unlock()
			close(resultChan)
		}()

		// Send command to agent
		if err := s.sendAdHocCommandToAgent(agent, adHocCmd); err != nil {
			response.Status = "error"
			response.Error = "Failed to send command: " + err.Error()
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		// Wait for result with timeout
		select {
		case result := <-resultChan:
			response.Status = "completed"
			response.Result = &result
		case <-time.After(time.Duration(req.TimeoutSec) * time.Second):
			response.Status = "timeout"
			response.Error = fmt.Sprintf("Command timed out after %d seconds", req.TimeoutSec)
		}
	} else {
		// Fire and forget
		if err := s.sendAdHocCommandToAgent(agent, adHocCmd); err != nil {
			response.Status = "error"
			response.Error = "Failed to send command: " + err.Error()
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}
		response.Status = "sent"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) sendAdHocCommandToAgent(agent *Agent, cmd AdHocCommand) error {
	payload, _ := json.Marshal(cmd)
	msg := WSMessage{Type: "exec", Payload: payload}
	data, _ := json.Marshal(msg)

	agent.mu.Lock()
	defer agent.mu.Unlock()

	if agent.conn == nil {
		return fmt.Errorf("agent connection is nil")
	}

	return agent.conn.WriteMessage(websocket.TextMessage, data)
}

func (s *Server) listSyncFiles(osType string) []SyncFile {
	files := make([]SyncFile, 0)

	// Validate OS type
	if osType != "linux" && osType != "windows" {
		return files
	}

	osDir := filepath.Join(s.syncDir, osType)
	entries, err := os.ReadDir(osDir)
	if err != nil {
		return files
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, SyncFile{
			Name:    entry.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	return files
}

func (s *Server) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("agent_token")
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.config.AgentToken)) != 1 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	agentID := r.URL.Query().Get("agent_id")
	agentOS := r.URL.Query().Get("os")
	if agentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}

	// Check for existing connected agent with same ID
	s.agentsMu.Lock()
	existingAgent, exists := s.agents[agentID]
	if exists && existingAgent.Connected {
		// Close the old connection to allow reconnection
		// This handles cases where network connectivity was lost but server didn't detect it
		log.Printf("Closing stale connection for agent %s to allow reconnection", agentID)
		existingAgent.mu.Lock()
		existingAgent.Connected = false
		if existingAgent.conn != nil {
			existingAgent.conn.Close()
		}
		existingAgent.mu.Unlock()
	}
	s.agentsMu.Unlock()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}

	// Set up ping/pong handlers for connection health monitoring
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Get remote address and X-Forwarded-For header
	remoteAddr := r.RemoteAddr
	xForwardedFor := r.Header.Get("X-Forwarded-For")

	now := nowISO8601()
	agent := &Agent{
		ID:            agentID,
		OS:            agentOS,
		ConnectedAt:   now,
		LastSeen:      now,
		Connected:     true,
		RemoteAddr:    remoteAddr,
		XForwardedFor: xForwardedFor,
		conn:          conn,
	}

	s.agentsMu.Lock()
	s.agents[agentID] = agent
	s.agentsMu.Unlock()

	log.Printf("Agent connected: %s (OS: %s)", agentID, agentOS)

	// Send current commands
	s.sendCommandsToAgent(agent)
	// Send file list
	s.sendFileListToAgent(agent)

	// Start ping goroutine to keep connection alive and detect dead connections
	go s.pingAgent(agent)

	// Handle incoming messages
	go s.handleAgentMessages(agent)
}

func (s *Server) pingAgent(agent *Agent) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		agent.mu.Lock()
		if !agent.Connected || agent.conn == nil {
			agent.mu.Unlock()
			return
		}
		err := agent.conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second))
		agent.mu.Unlock()

		if err != nil {
			log.Printf("Ping failed for agent %s: %v", agent.ID, err)
			return
		}
	}
}

func (s *Server) handleAgentMessages(agent *Agent) {
	defer func() {
		agent.mu.Lock()
		agent.Connected = false
		agent.conn.Close()
		agent.mu.Unlock()
		log.Printf("Agent disconnected: %s", agent.ID)
	}()

	for {
		_, message, err := agent.conn.ReadMessage()
		if err != nil {
			return
		}

		agent.mu.Lock()
		agent.LastSeen = nowISO8601()
		agent.mu.Unlock()

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "result":
			var result CommandResult
			if err := json.Unmarshal(msg.Payload, &result); err == nil {
				result.AgentID = agent.ID
				result.RemoteAddr = agent.RemoteAddr
				result.XForwardedFor = agent.XForwardedFor
				s.logResult(result)
				log.Printf("Result from %s: command=%s, rc=%d", agent.ID, result.CommandID, result.ReturnCode)

				// Check if this is a pending ad-hoc command
				s.pendingAdHocMu.RLock()
				pending, exists := s.pendingAdHoc[result.CommandID]
				s.pendingAdHocMu.RUnlock()

				if exists && pending.ResultChan != nil {
					select {
					case pending.ResultChan <- result:
					default:
						// Channel full or closed, ignore
					}
				}
			}
		case "file_request":
			var req FileRequestPayload
			if err := json.Unmarshal(msg.Payload, &req); err == nil {
				s.sendFileToAgent(agent, req.Filename)
			}
		}
	}
}

func (s *Server) sendCommandsToAgent(agent *Agent) {
	s.commandsMu.RLock()
	commands := make([]Command, 0, len(s.commands))
	for _, cmd := range s.commands {
		commands = append(commands, cmd)
	}
	s.commandsMu.RUnlock()

	payload, _ := json.Marshal(CommandListPayload{Commands: commands})
	msg := WSMessage{Type: "commands", Payload: payload}
	data, _ := json.Marshal(msg)

	agent.mu.Lock()
	agent.conn.WriteMessage(websocket.TextMessage, data)
	agent.mu.Unlock()
}

func (s *Server) sendFileListToAgent(agent *Agent) {
	// Send files filtered by agent's OS
	files := s.listSyncFiles(agent.OS)
	payload, _ := json.Marshal(SyncFileListPayload{Files: files})
	msg := WSMessage{Type: "files", Payload: payload}
	data, _ := json.Marshal(msg)

	agent.mu.Lock()
	agent.conn.WriteMessage(websocket.TextMessage, data)
	agent.mu.Unlock()
}

func (s *Server) sendFileToAgent(agent *Agent, filename string) {
	filename = filepath.Base(filename)
	// Read from OS-specific subdirectory
	filePath := filepath.Join(s.syncDir, agent.OS, filename)

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v", filename, err)
		return
	}

	payload, _ := json.Marshal(FileDataPayload{
		Filename: filename,
		Data:     base64.StdEncoding.EncodeToString(data),
	})
	msg := WSMessage{Type: "file_data", Payload: payload}
	msgData, _ := json.Marshal(msg)

	agent.mu.Lock()
	agent.conn.WriteMessage(websocket.TextMessage, msgData)
	agent.mu.Unlock()
}

func (s *Server) broadcastCommands() {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	for _, agent := range s.agents {
		if agent.Connected {
			s.sendCommandsToAgent(agent)
		}
	}
}

func (s *Server) broadcastFileList() {
	s.agentsMu.RLock()
	defer s.agentsMu.RUnlock()

	for _, agent := range s.agents {
		if agent.Connected {
			s.sendFileListToAgent(agent)
		}
	}
}

func (s *Server) Run() {
	mux := http.NewServeMux()

	// Admin API endpoints
	mux.HandleFunc("/api/commands", s.adminAuth(s.handleCommands))
	mux.HandleFunc("/api/agents", s.adminAuth(s.handleAgents))
	mux.HandleFunc("/api/files", s.adminAuth(s.handleFiles))
	mux.HandleFunc("/api/files/download", s.adminAuth(s.handleFileDownload))
	mux.HandleFunc("/api/exec", s.adminAuth(s.handleExec))

	// Agent WebSocket endpoint
	mux.HandleFunc("/ws/agent", s.handleAgentWS)

	fmt.Println("========================================")
	fmt.Println("Rikugan Server")
	fmt.Println("github.com/nickadam/rikugan")
	fmt.Println("========================================")
	fmt.Printf("Port: %d\n", s.config.Port)
	fmt.Printf("Admin Token: %s\n", s.config.AdminToken)
	fmt.Printf("Agent Token: %s\n", s.config.AgentToken)
	fmt.Printf("Data Directory: %s\n", s.dataDir)
	fmt.Printf("Sync Directory: %s\n", s.syncDir)
	fmt.Println("----------------------------------------")
	fmt.Println("Log Rotation:")
	if s.logRotation.Enabled {
		fmt.Println("  Status: ENABLED")
		if s.logRotation.RotateDaily {
			fmt.Println("  Daily rotation: Yes (at midnight UTC)")
		}
		if s.logRotation.MaxSizeMB > 0 {
			fmt.Printf("  Max size: %d MB\n", s.logRotation.MaxSizeMB)
		}
		if s.logRotation.MaxAgeDays > 0 {
			fmt.Printf("  Max age: %d days\n", s.logRotation.MaxAgeDays)
		}
		if s.logRotation.MaxFiles > 0 {
			fmt.Printf("  Max files: %d\n", s.logRotation.MaxFiles)
		}
	} else {
		fmt.Println("  Status: DISABLED (use -log-rotate to enable)")
	}
	fmt.Println("========================================")
	fmt.Println("API Endpoints (require admin_token):")
	fmt.Println("  GET    /api/commands              - List commands")
	fmt.Println("  POST   /api/commands              - Add command")
	fmt.Println("  DELETE /api/commands?id=X         - Delete command")
	fmt.Println("  GET    /api/agents                - List agents")
	fmt.Println("  POST   /api/exec                  - Execute ad-hoc command")
	fmt.Println("  GET    /api/files?os=X            - List sync files (os=linux|windows)")
	fmt.Println("  POST   /api/files?os=X            - Upload file")
	fmt.Println("  DELETE /api/files?os=X&filename=Y - Delete file")
	fmt.Println("  GET    /api/files/download?os=X&filename=Y - Download file")
	fmt.Println("========================================")
	fmt.Println("Agent WebSocket: /ws/agent?agent_token=X&agent_id=Y&os=Z")
	fmt.Println("========================================")

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", s.config.Port), mux))
}

// ==================== AGENT ====================

// getOrCreateAgentID returns a persistent unique agent ID.
// Format: hostname-uuid (e.g., "workstation-a1b2c3d4")
// The UUID is stored in a file to persist across restarts.
func getOrCreateAgentID(dataDir string) string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Ensure data directory exists
	os.MkdirAll(dataDir, 0755)

	idFile := filepath.Join(dataDir, ".agent-id")

	// Try to read existing ID
	if data, err := os.ReadFile(idFile); err == nil {
		existingID := strings.TrimSpace(string(data))
		if existingID != "" {
			return existingID
		}
	}

	// Generate new ID: hostname-shortUUID
	uuid := generateToken()[:8]
	agentID := fmt.Sprintf("%s-%s", hostname, uuid)

	// Persist the ID
	if err := os.WriteFile(idFile, []byte(agentID), 0644); err != nil {
		log.Printf("Warning: could not persist agent ID: %v", err)
	}

	return agentID
}

func NewAgent(serverURL, agentToken, agentID, dataDir string) *AgentState {
	// Clean up the data directory path
	// Remove trailing slashes/backslashes and any quote characters that might
	// have been included due to Windows command-line escaping issues
	dataDir = strings.TrimSpace(dataDir)
	dataDir = strings.TrimRight(dataDir, `/\"'`)

	if dataDir == "" {
		dataDir = "./agent_data"
	}

	// Create directory structure
	stateDir := filepath.Join(dataDir, "state")
	syncDir := filepath.Join(dataDir, "sync")
	os.MkdirAll(stateDir, 0755)
	os.MkdirAll(syncDir, 0755)

	// Trim whitespace from agent ID
	agentID = strings.TrimSpace(agentID)

	// If no agent ID specified (empty or whitespace), generate/load a persistent one
	if agentID == "" {
		agentID = getOrCreateAgentID(stateDir)
	} else {
		// If agent ID was explicitly provided, save it to the state file
		// so it persists even if the service args change later
		idFile := filepath.Join(stateDir, ".agent-id")
		existingID := ""
		if data, err := os.ReadFile(idFile); err == nil {
			existingID = strings.TrimSpace(string(data))
		}
		// Only write if different (avoid unnecessary writes)
		if existingID != agentID {
			os.WriteFile(idFile, []byte(agentID), 0644)
		}
	}

	a := &AgentState{
		id:         agentID,
		serverURL:  serverURL,
		agentToken: agentToken,
		dataDir:    dataDir,
		stateDir:   stateDir,
		syncDir:    syncDir,
		lastRun:    make(map[string]time.Time),
		commands:   make(map[string]Command),
	}

	// Load persisted commands
	a.loadAgentCommands()

	return a
}

func (a *AgentState) loadAgentCommands() {
	path := filepath.Join(a.stateDir, "commands.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var commands []Command
	if err := json.Unmarshal(data, &commands); err != nil {
		log.Printf("Error loading agent commands: %v", err)
		return
	}
	a.commandsMu.Lock()
	for _, cmd := range commands {
		a.commands[cmd.ID] = cmd
	}
	a.commandsMu.Unlock()
	log.Printf("Loaded %d commands from disk", len(commands))
}

func (a *AgentState) saveAgentCommands() error {
	a.commandsMu.RLock()
	commands := make([]Command, 0, len(a.commands))
	for _, cmd := range a.commands {
		commands = append(commands, cmd)
	}
	a.commandsMu.RUnlock()

	data, err := json.MarshalIndent(commands, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(a.stateDir, "commands.json")
	return os.WriteFile(path, data, 0644)
}

func (a *AgentState) connect() error {
	osType := runtime.GOOS
	url := fmt.Sprintf("%s/ws/agent?agent_token=%s&agent_id=%s&os=%s",
		a.serverURL, a.agentToken, a.id, osType)

	// Convert http(s) to ws(s)
	url = strings.Replace(url, "https://", "wss://", 1)
	url = strings.Replace(url, "http://", "ws://", 1)

	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return err
	}

	a.connMu.Lock()
	a.conn = conn
	a.connMu.Unlock()

	return nil
}

func (a *AgentState) Run() {
	// Set RIKUGAN_SYNC_DIR environment variable so all child processes can access it
	os.Setenv("RIKUGAN_SYNC_DIR", a.syncDir)

	fmt.Println("========================================")
	fmt.Println("Rikugan Agent")
	fmt.Println("github.com/nickadam/rikugan")
	fmt.Println("========================================")
	fmt.Printf("Agent ID: %s\n", a.id)
	fmt.Printf("OS: %s\n", runtime.GOOS)
	fmt.Printf("Server: %s\n", a.serverURL)
	fmt.Println("----------------------------------------")
	fmt.Printf("Data Directory: %s\n", a.dataDir)
	fmt.Printf("  State: %s\n", a.stateDir)
	fmt.Printf("  Sync:  %s\n", a.syncDir)
	fmt.Printf("  Env:   RIKUGAN_SYNC_DIR=%s\n", a.syncDir)
	fmt.Println("========================================")

	// Start command executor goroutine - runs independently of connection
	// This ensures commands continue to run even when disconnected from server
	go a.runCommandExecutor()

	for {
		if err := a.connect(); err != nil {
			log.Printf("Connection failed: %v, retrying in 5s...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Println("Connected to server")
		a.handleMessages()
		log.Println("Disconnected, reconnecting in 5s...")
		time.Sleep(5 * time.Second)
	}
}

func (a *AgentState) runCommandExecutor() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		a.commandsMu.RLock()
		for _, cmd := range a.commands {
			if a.shouldRunCommand(cmd) {
				go a.executeCommand(cmd)
			}
		}
		a.commandsMu.RUnlock()
	}
}

func (a *AgentState) handleMessages() {
	for {
		a.connMu.Lock()
		conn := a.conn
		a.connMu.Unlock()

		if conn == nil {
			return
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "commands":
			var payload CommandListPayload
			if err := json.Unmarshal(msg.Payload, &payload); err == nil {
				// Update the shared commands map
				a.commandsMu.Lock()
				a.commands = make(map[string]Command)
				for _, cmd := range payload.Commands {
					a.commands[cmd.ID] = cmd
				}
				a.commandsMu.Unlock()

				// Persist commands to disk so they survive restarts
				if err := a.saveAgentCommands(); err != nil {
					log.Printf("Error saving commands: %v", err)
				}

				// Clean up lastRun entries for deleted commands
				a.lastRunMu.Lock()
				a.commandsMu.RLock()
				for cmdID := range a.lastRun {
					if _, exists := a.commands[cmdID]; !exists {
						delete(a.lastRun, cmdID)
						log.Printf("Cleaned up deleted command: %s", cmdID)
					}
				}
				a.commandsMu.RUnlock()
				a.lastRunMu.Unlock()

				log.Printf("Received %d commands (persisted to disk)", len(payload.Commands))
			}

		case "exec":
			// Ad-hoc command execution
			var adHocCmd AdHocCommand
			if err := json.Unmarshal(msg.Payload, &adHocCmd); err == nil {
				log.Printf("Received ad-hoc command: %s", adHocCmd.Command)
				go a.executeAdHocCommand(adHocCmd)
			}

		case "files":
			var payload SyncFileListPayload
			if err := json.Unmarshal(msg.Payload, &payload); err == nil {
				a.syncFiles(payload.Files)
			}

		case "file_data":
			var payload FileDataPayload
			if err := json.Unmarshal(msg.Payload, &payload); err == nil {
				a.saveFile(payload.Filename, payload.Data)
			}
		}
	}
}

func (a *AgentState) shouldRunCommand(cmd Command) bool {
	// Check OS compatibility
	osType := runtime.GOOS
	if cmd.OS != "all" && cmd.OS != osType {
		return false
	}

	a.lastRunMu.Lock()
	defer a.lastRunMu.Unlock()

	lastRun, exists := a.lastRun[cmd.ID]
	if !exists {
		return true
	}

	return time.Since(lastRun).Seconds() >= float64(cmd.IntervalSec)
}

func (a *AgentState) executeCommand(cmd Command) {
	a.lastRunMu.Lock()
	a.lastRun[cmd.ID] = time.Now()
	a.lastRunMu.Unlock()

	startTime := time.Now()
	startTimeISO := startTime.UTC().Format(time.RFC3339)

	var execCmd *exec.Cmd
	if runtime.GOOS == "windows" {
		execCmd = exec.Command("cmd", "/C", cmd.Command)
	} else {
		execCmd = exec.Command("sh", "-c", cmd.Command)
	}

	var stdout, stderr strings.Builder
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	err := execCmd.Run()
	executionTime := time.Since(startTime).Seconds()

	returnCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			returnCode = exitErr.ExitCode()
		} else {
			returnCode = -1
		}
	}

	result := CommandResult{
		CommandID:     cmd.ID,
		Command:       cmd.Command,
		Stdout:        stdout.String(),
		Stderr:        stderr.String(),
		ReturnCode:    returnCode,
		StartTime:     startTimeISO,
		ExecutionTime: executionTime,
	}

	log.Printf("Executed: %s (rc=%d, time=%.2fs)", cmd.Command, returnCode, executionTime)
	a.sendResult(result)
}

func (a *AgentState) executeAdHocCommand(cmd AdHocCommand) {
	startTime := time.Now()
	startTimeISO := startTime.UTC().Format(time.RFC3339)

	var stdout, stderr strings.Builder
	var execCmd *exec.Cmd
	var err error

	// Default timeout to 60 seconds if not specified
	timeout := cmd.TimeoutSec
	if timeout <= 0 {
		timeout = 60
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Create a temp file for the script to avoid shell parsing issues
	var tempFile *os.File
	var tempPath string

	if runtime.GOOS == "windows" {
		tempFile, err = os.CreateTemp("", "rikugan-*.bat")
		if err != nil {
			stderr.WriteString("Failed to create temp script file: " + err.Error())
			result := CommandResult{
				CommandID:     cmd.ID,
				Command:       cmd.Command,
				Stdout:        "",
				Stderr:        stderr.String(),
				ReturnCode:    -1,
				StartTime:     startTimeISO,
				ExecutionTime: time.Since(startTime).Seconds(),
			}
			a.sendResult(result)
			return
		}
		tempPath = tempFile.Name()
		tempFile.WriteString("@echo off\r\n")
		tempFile.WriteString(cmd.Command)
		tempFile.Close()
		defer os.Remove(tempPath)

		execCmd = exec.CommandContext(ctx, "cmd", "/C", tempPath)
	} else {
		tempFile, err = os.CreateTemp("", "rikugan-*.sh")
		if err != nil {
			stderr.WriteString("Failed to create temp script file: " + err.Error())
			result := CommandResult{
				CommandID:     cmd.ID,
				Command:       cmd.Command,
				Stdout:        "",
				Stderr:        stderr.String(),
				ReturnCode:    -1,
				StartTime:     startTimeISO,
				ExecutionTime: time.Since(startTime).Seconds(),
			}
			a.sendResult(result)
			return
		}
		tempPath = tempFile.Name()
		tempFile.WriteString("#!/bin/sh\n")
		tempFile.WriteString(cmd.Command)
		tempFile.Close()
		os.Chmod(tempPath, 0700)
		defer os.Remove(tempPath)

		execCmd = exec.CommandContext(ctx, "/bin/sh", tempPath)
	}
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	log.Printf("Executing ad-hoc command: [%s]", cmd.Command)
	err = execCmd.Run()
	executionTime := time.Since(startTime).Seconds()

	returnCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			returnCode = exitErr.ExitCode()
		} else {
			returnCode = -1
			// Add error info to stderr if it's not an exit error
			if stderr.Len() == 0 {
				stderr.WriteString(err.Error())
			}
		}
	}

	result := CommandResult{
		CommandID:     cmd.ID,
		Command:       cmd.Command,
		Stdout:        stdout.String(),
		Stderr:        stderr.String(),
		ReturnCode:    returnCode,
		StartTime:     startTimeISO,
		ExecutionTime: executionTime,
	}

	log.Printf("Executed ad-hoc: %s (rc=%d, time=%.2fs)", cmd.Command, returnCode, executionTime)
	a.sendResult(result)
}

func (a *AgentState) sendResult(result CommandResult) {
	payload, _ := json.Marshal(result)
	msg := WSMessage{Type: "result", Payload: payload}
	data, _ := json.Marshal(msg)

	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.conn != nil {
		a.conn.WriteMessage(websocket.TextMessage, data)
	}
}

func (a *AgentState) syncFiles(serverFiles []SyncFile) {
	// Build a map of server files for quick lookup
	serverFileMap := make(map[string]SyncFile)
	for _, sf := range serverFiles {
		serverFileMap[sf.Name] = sf
	}

	// Check local files and delete any that don't exist on server
	entries, err := os.ReadDir(a.syncDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			filename := entry.Name()
			// If file exists locally but not on server, delete it
			if _, exists := serverFileMap[filename]; !exists {
				localPath := filepath.Join(a.syncDir, filename)
				if err := os.Remove(localPath); err == nil {
					log.Printf("Deleted file (removed from server): %s", filename)
				} else {
					log.Printf("Error deleting file %s: %v", filename, err)
				}
			}
		}
	}

	// Check which files we need to download or update
	for _, sf := range serverFiles {
		localPath := filepath.Join(a.syncDir, sf.Name)
		needSync := false

		info, err := os.Stat(localPath)
		if os.IsNotExist(err) {
			needSync = true
		} else if err == nil {
			// Compare mod time
			serverMod, _ := parseISO8601(sf.ModTime)
			if info.ModTime().Before(serverMod) || info.Size() != sf.Size {
				needSync = true
			}
		}

		if needSync {
			log.Printf("Requesting file: %s", sf.Name)
			a.requestFile(sf.Name)
		}
	}
}

func (a *AgentState) requestFile(filename string) {
	payload, _ := json.Marshal(FileRequestPayload{Filename: filename})
	msg := WSMessage{Type: "file_request", Payload: payload}
	data, _ := json.Marshal(msg)

	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.conn != nil {
		a.conn.WriteMessage(websocket.TextMessage, data)
	}
}

func (a *AgentState) saveFile(filename string, b64data string) {
	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		log.Printf("Error decoding file %s: %v", filename, err)
		return
	}

	filename = filepath.Base(filename)
	path := filepath.Join(a.syncDir, filename)

	if err := os.WriteFile(path, data, 0755); err != nil {
		log.Printf("Error saving file %s: %v", filename, err)
		return
	}

	log.Printf("Synced file: %s (%d bytes)", filename, len(data))
}

// ==================== MAIN ====================

func main() {
	// Mode flags
	serverMode := flag.Bool("server", false, "Run in server mode")
	agentMode := flag.Bool("agent", false, "Run in agent mode")

	// Server flags
	port := flag.Int("port", 8080, "Server port")
	dataDir := flag.String("data-dir", "./data", "Server data directory")
	adminToken := flag.String("admin-token", "", "Admin authentication token (auto-generated if empty)")
	agentTokenFlag := flag.String("agent-token", "", "Agent authentication token (auto-generated if empty)")

	// Log rotation flags
	logRotate := flag.Bool("log-rotate", false, "Enable log rotation")
	logRotateDaily := flag.Bool("log-rotate-daily", true, "Rotate logs daily at midnight UTC")
	logMaxSizeMB := flag.Int("log-max-size-mb", 100, "Rotate when log exceeds this size in MB (0 = no size limit)")
	logMaxAgeDays := flag.Int("log-max-age-days", 30, "Delete logs older than this many days (0 = keep forever)")
	logMaxFiles := flag.Int("log-max-files", 0, "Maximum rotated log files to keep (0 = unlimited)")

	// Agent flags
	serverURL := flag.String("server-url", "", "Server URL for agent mode")
	agentToken := flag.String("token", "", "Agent token for authentication")
	agentID := flag.String("agent-id", "", "Agent ID (defaults to hostname-uuid)")
	agentDataDir := flag.String("agent-data-dir", "./agent_data", "Agent data directory (contains state/ and sync/)")

	flag.Parse()

	// If no mode specified, default to server mode
	if !*serverMode && !*agentMode {
		*serverMode = true
	}

	if *serverMode {
		logRotation := LogRotationConfig{
			Enabled:     *logRotate,
			RotateDaily: *logRotateDaily,
			MaxSizeMB:   *logMaxSizeMB,
			MaxAgeDays:  *logMaxAgeDays,
			MaxFiles:    *logMaxFiles,
		}
		server := NewServer(*port, *dataDir, *adminToken, *agentTokenFlag, logRotation)
		server.Run()
	} else if *agentMode {
		if *serverURL == "" {
			log.Fatal("--server-url is required for agent mode")
		}
		if *agentToken == "" {
			log.Fatal("--token is required for agent mode")
		}

		// Check if running as Windows service
		if isWindowsService() {
			runService("RikuganAgent", *serverURL, *agentToken, *agentID, *agentDataDir)
			return
		}

		// Running interactively
		agent := NewAgent(*serverURL, *agentToken, *agentID, *agentDataDir)
		agent.Run()
	}
}
