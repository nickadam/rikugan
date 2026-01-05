package main

import (
	"compress/gzip"
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
	ID         string `json:"id"`
	Command    string `json:"command"`
	IntervalSec int   `json:"interval_sec"`
	OS         string `json:"os"` // "linux", "windows", or "all"
	CreatedAt  string `json:"created_at"`
}

// CommandResult represents the result of a command execution
type CommandResult struct {
	AgentID       string `json:"agent_id"`
	CommandID     string `json:"command_id"`
	Command       string `json:"command"`
	Stdout        string `json:"stdout"`
	Stderr        string `json:"stderr"`
	ReturnCode    int    `json:"return_code"`
	StartTime     string `json:"start_time"`
	ExecutionTime float64 `json:"execution_time_sec"`
}

// Agent represents a connected agent
type Agent struct {
	ID            string    `json:"id"`
	OS            string    `json:"os"`
	ConnectedAt   string    `json:"connected_at"`
	LastSeen      string    `json:"last_seen"`
	Connected     bool      `json:"connected"`
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

// Server state
type Server struct {
	config      ServerConfig
	commands    map[string]Command
	agents      map[string]*Agent
	syncDir     string
	dataDir     string
	commandsMu  sync.RWMutex
	agentsMu    sync.RWMutex
	upgrader    websocket.Upgrader
	resultLog   *os.File
	resultLogMu sync.Mutex
	gzWriter    *gzip.Writer
}

// Agent state
type AgentState struct {
	id           string
	serverURL    string
	agentToken   string
	syncDir      string
	lastRun      map[string]time.Time
	lastRunMu    sync.Mutex
	conn         *websocket.Conn
	connMu       sync.Mutex
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

func NewServer(port int, dataDir string, adminToken, agentToken string) *Server {
	if adminToken == "" {
		adminToken = generateToken()
	}
	if agentToken == "" {
		agentToken = generateToken()
	}

	syncDir := filepath.Join(dataDir, "sync")
	os.MkdirAll(syncDir, 0755)
	os.MkdirAll(dataDir, 0755)

	s := &Server{
		config: ServerConfig{
			AdminToken: adminToken,
			AgentToken: agentToken,
			Port:       port,
		},
		commands: make(map[string]Command),
		agents:   make(map[string]*Agent),
		syncDir:  syncDir,
		dataDir:  dataDir,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}

	s.loadCommands()
	s.openResultLog()

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
	path := filepath.Join(s.dataDir, "results.json.gz")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open result log: %v", err)
	}
	s.resultLog = f
	s.gzWriter = gzip.NewWriter(f)
}

func (s *Server) logResult(result CommandResult) {
	s.resultLogMu.Lock()
	defer s.resultLogMu.Unlock()

	data, _ := json.Marshal(result)
	s.gzWriter.Write(data)
	s.gzWriter.Write([]byte("\n"))
	s.gzWriter.Flush()
	s.resultLog.Sync()
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
	switch r.Method {
	case http.MethodGet:
		// List files
		files := s.listSyncFiles()
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
		destPath := filepath.Join(s.syncDir, filename)
		dest, err := os.Create(destPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer dest.Close()

		io.Copy(dest, file)
		s.broadcastFileList()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"uploaded": filename})

	case http.MethodDelete:
		filename := r.URL.Query().Get("filename")
		if filename == "" {
			http.Error(w, "filename required", http.StatusBadRequest)
			return
		}
		
		// Sanitize filename to prevent directory traversal
		filename = filepath.Base(filename)
		filePath := filepath.Join(s.syncDir, filename)
		
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
		json.NewEncoder(w).Encode(map[string]string{"deleted": filename})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		http.Error(w, "filename required", http.StatusBadRequest)
		return
	}

	// Sanitize filename
	filename = filepath.Base(filename)
	filePath := filepath.Join(s.syncDir, filename)

	http.ServeFile(w, r, filePath)
}

func (s *Server) listSyncFiles() []SyncFile {
	files := make([]SyncFile, 0)
	entries, err := os.ReadDir(s.syncDir)
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

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}

	now := nowISO8601()
	agent := &Agent{
		ID:          agentID,
		OS:          agentOS,
		ConnectedAt: now,
		LastSeen:    now,
		Connected:   true,
		conn:        conn,
	}

	s.agentsMu.Lock()
	s.agents[agentID] = agent
	s.agentsMu.Unlock()

	log.Printf("Agent connected: %s (OS: %s)", agentID, agentOS)

	// Send current commands
	s.sendCommandsToAgent(agent)
	// Send file list
	s.sendFileListToAgent(agent)

	// Handle incoming messages
	go s.handleAgentMessages(agent)
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
				s.logResult(result)
				log.Printf("Result from %s: command=%s, rc=%d", agent.ID, result.CommandID, result.ReturnCode)
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
	files := s.listSyncFiles()
	payload, _ := json.Marshal(SyncFileListPayload{Files: files})
	msg := WSMessage{Type: "files", Payload: payload}
	data, _ := json.Marshal(msg)

	agent.mu.Lock()
	agent.conn.WriteMessage(websocket.TextMessage, data)
	agent.mu.Unlock()
}

func (s *Server) sendFileToAgent(agent *Agent, filename string) {
	filename = filepath.Base(filename)
	filePath := filepath.Join(s.syncDir, filename)

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

	// Agent WebSocket endpoint
	mux.HandleFunc("/ws/agent", s.handleAgentWS)

	fmt.Println("========================================")
	fmt.Println("Rikugan Server")
	fmt.Println("========================================")
	fmt.Printf("Port: %d\n", s.config.Port)
	fmt.Printf("Admin Token: %s\n", s.config.AdminToken)
	fmt.Printf("Agent Token: %s\n", s.config.AgentToken)
	fmt.Printf("Data Directory: %s\n", s.dataDir)
	fmt.Printf("Sync Directory: %s\n", s.syncDir)
	fmt.Println("========================================")
	fmt.Println("API Endpoints (require admin_token):")
	fmt.Println("  GET    /api/commands         - List commands")
	fmt.Println("  POST   /api/commands         - Add command")
	fmt.Println("  DELETE /api/commands?id=X    - Delete command")
	fmt.Println("  GET    /api/agents           - List agents")
	fmt.Println("  GET    /api/files            - List sync files")
	fmt.Println("  POST   /api/files            - Upload file")
	fmt.Println("  DELETE /api/files?filename=X - Delete file")
	fmt.Println("  GET    /api/files/download   - Download file")
	fmt.Println("========================================")
	fmt.Println("Agent WebSocket: /ws/agent?agent_token=X&agent_id=Y&os=Z")
	fmt.Println("========================================")

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", s.config.Port), mux))
}

// ==================== AGENT ====================

func NewAgent(serverURL, agentToken, agentID, syncDir string) *AgentState {
	if agentID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			agentID = "unknown"
		} else {
			agentID = hostname
		}
	}

	if syncDir == "" {
		syncDir = "./agent_sync"
	}
	os.MkdirAll(syncDir, 0755)

	return &AgentState{
		id:         agentID,
		serverURL:  serverURL,
		agentToken: agentToken,
		syncDir:    syncDir,
		lastRun:    make(map[string]time.Time),
	}
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
	fmt.Println("========================================")
	fmt.Println("Rikugan Agent")
	fmt.Println("========================================")
	fmt.Printf("Agent ID: %s\n", a.id)
	fmt.Printf("OS: %s\n", runtime.GOOS)
	fmt.Printf("Server: %s\n", a.serverURL)
	fmt.Printf("Sync Directory: %s\n", a.syncDir)
	fmt.Println("========================================")

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

func (a *AgentState) handleMessages() {
	commands := make(map[string]Command)
	var commandsMu sync.RWMutex

	// Command executor goroutine
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			commandsMu.RLock()
			for _, cmd := range commands {
				if a.shouldRunCommand(cmd) {
					go a.executeCommand(cmd)
				}
			}
			commandsMu.RUnlock()
		}
	}()

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
				commandsMu.Lock()
				commands = make(map[string]Command)
				for _, cmd := range payload.Commands {
					commands[cmd.ID] = cmd
				}
				commandsMu.Unlock()
				log.Printf("Received %d commands", len(payload.Commands))
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
	// Check which files we need
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

	// Agent flags
	serverURL := flag.String("server-url", "", "Server URL for agent mode")
	agentToken := flag.String("token", "", "Agent token for authentication")
	agentID := flag.String("agent-id", "", "Agent ID (defaults to hostname)")
	syncDir := flag.String("sync-dir", "./agent_sync", "Agent sync directory")

	flag.Parse()

	// If no mode specified, default to server mode
	if !*serverMode && !*agentMode {
		*serverMode = true
	}

	if *serverMode {
		server := NewServer(*port, *dataDir, *adminToken, *agentTokenFlag)
		server.Run()
	} else if *agentMode {
		if *serverURL == "" {
			log.Fatal("--server-url is required for agent mode")
		}
		if *agentToken == "" {
			log.Fatal("--token is required for agent mode")
		}
		agent := NewAgent(*serverURL, *agentToken, *agentID, *syncDir)
		agent.Run()
	}
}
