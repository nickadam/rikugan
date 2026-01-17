package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

// Command represents a scheduled command
type Command struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	IntervalSec int    `json:"interval_sec"`
	OS          string `json:"os"`
	CreatedAt   string `json:"created_at"`
}

// Agent represents a connected agent
type Agent struct {
	ID          string `json:"id"`
	OS          string `json:"os"`
	ConnectedAt string `json:"connected_at"`
	LastSeen    string `json:"last_seen"`
	Connected   bool   `json:"connected"`
}

// SyncFile represents a file available for sync
type SyncFile struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

// AdHocCommandRequest is the request for ad-hoc command execution
type AdHocCommandRequest struct {
	AgentID    string `json:"agent_id"`
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
	Wait       bool   `json:"wait,omitempty"`
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
}

// AdHocCommandResponse is the response for ad-hoc commands
type AdHocCommandResponse struct {
	ID      string         `json:"id"`
	AgentID string         `json:"agent_id"`
	Command string         `json:"command"`
	Status  string         `json:"status"`
	Result  *CommandResult `json:"result,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// Client handles communication with the Rikugan server
type Client struct {
	serverURL  string
	adminToken string
	httpClient *http.Client
}

func NewClient(serverURL, adminToken string) *Client {
	return &Client{
		serverURL:  strings.TrimRight(serverURL, "/"),
		adminToken: adminToken,
		httpClient: &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) doRequest(method, endpoint string, body io.Reader, contentType string) ([]byte, error) {
	url := c.serverURL + endpoint
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.adminToken)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	return data, nil
}

// ListAgents returns all agents
func (c *Client) ListAgents() ([]Agent, error) {
	data, err := c.doRequest("GET", "/api/agents", nil, "")
	if err != nil {
		return nil, err
	}

	var agents []Agent
	if err := json.Unmarshal(data, &agents); err != nil {
		return nil, err
	}
	return agents, nil
}

// ExecCommand executes an ad-hoc command on an agent
func (c *Client) ExecCommand(agentID, command string, timeoutSec int, wait bool) (*AdHocCommandResponse, error) {
	req := AdHocCommandRequest{
		AgentID:    agentID,
		Command:    command,
		TimeoutSec: timeoutSec,
		Wait:       wait,
	}

	body, _ := json.Marshal(req)
	data, err := c.doRequest("POST", "/api/exec", bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	var resp AdHocCommandResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListCommands returns all scheduled commands
func (c *Client) ListCommands() ([]Command, error) {
	data, err := c.doRequest("GET", "/api/commands", nil, "")
	if err != nil {
		return nil, err
	}

	var commands []Command
	if err := json.Unmarshal(data, &commands); err != nil {
		return nil, err
	}
	return commands, nil
}

// AddCommand adds a new scheduled command
func (c *Client) AddCommand(command string, intervalSec int, osType string) (*Command, error) {
	cmd := Command{
		Command:     command,
		IntervalSec: intervalSec,
		OS:          osType,
	}

	body, _ := json.Marshal(cmd)
	data, err := c.doRequest("POST", "/api/commands", bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	var result Command
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RemoveCommand removes a scheduled command by ID
func (c *Client) RemoveCommand(id string) error {
	_, err := c.doRequest("DELETE", "/api/commands?id="+id, nil, "")
	return err
}

// ListFiles returns all sync files for a given OS
func (c *Client) ListFiles(osType string) ([]SyncFile, error) {
	data, err := c.doRequest("GET", "/api/files?os="+osType, nil, "")
	if err != nil {
		return nil, err
	}

	var files []SyncFile
	if err := json.Unmarshal(data, &files); err != nil {
		return nil, err
	}
	return files, nil
}

// AddFile uploads a file to the server
func (c *Client) AddFile(filePath, osType string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(part, file); err != nil {
		return "", err
	}

	writer.Close()

	data, err := c.doRequest("POST", "/api/files?os="+osType, &buf, writer.FormDataContentType())
	if err != nil {
		return "", err
	}

	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil {
		return "", err
	}
	return result["uploaded"], nil
}

// RemoveFile deletes a file from the server
func (c *Client) RemoveFile(filename, osType string) error {
	_, err := c.doRequest("DELETE", "/api/files?os="+osType+"&filename="+filename, nil, "")
	return err
}

func printAgents(agents []Agent) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tOS\tCONNECTED\tLAST SEEN")
	fmt.Fprintln(w, "--\t--\t---------\t---------")
	for _, a := range agents {
		status := "No"
		if a.Connected {
			status = "Yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.ID, a.OS, status, a.LastSeen)
	}
	w.Flush()
}

func printCommands(commands []Command) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tCOMMAND\tINTERVAL\tOS\tCREATED")
	fmt.Fprintln(w, "--\t-------\t--------\t--\t-------")
	for _, cmd := range commands {
		// Truncate long commands for display
		displayCmd := cmd.Command
		if len(displayCmd) > 40 {
			displayCmd = displayCmd[:37] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%ds\t%s\t%s\n", cmd.ID, displayCmd, cmd.IntervalSec, cmd.OS, cmd.CreatedAt)
	}
	w.Flush()
}

func printFiles(files []SyncFile, osType string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Printf("Files for %s:\n", osType)
	fmt.Fprintln(w, "NAME\tSIZE\tMODIFIED")
	fmt.Fprintln(w, "----\t----\t--------")
	for _, f := range files {
		fmt.Fprintf(w, "%s\t%d\t%s\n", f.Name, f.Size, f.ModTime)
	}
	w.Flush()
}

func printExecResult(resp *AdHocCommandResponse) {
	fmt.Printf("Command ID: %s\n", resp.ID)
	fmt.Printf("Agent: %s\n", resp.AgentID)
	fmt.Printf("Status: %s\n", resp.Status)

	if resp.Error != "" {
		fmt.Printf("Error: %s\n", resp.Error)
	}

	if resp.Result != nil {
		fmt.Printf("Return Code: %d\n", resp.Result.ReturnCode)
		fmt.Printf("Execution Time: %.3fs\n", resp.Result.ExecutionTime)
		if resp.Result.Stdout != "" {
			fmt.Println("\n--- STDOUT ---")
			fmt.Print(resp.Result.Stdout)
			if !strings.HasSuffix(resp.Result.Stdout, "\n") {
				fmt.Println()
			}
		}
		if resp.Result.Stderr != "" {
			fmt.Println("\n--- STDERR ---")
			fmt.Print(resp.Result.Stderr)
			if !strings.HasSuffix(resp.Result.Stderr, "\n") {
				fmt.Println()
			}
		}
	}
}

func main() {
	// Global flags
	serverURL := flag.String("server", "", "Rikugan server URL (or set RIKUGAN_SERVER)")
	adminToken := flag.String("token", "", "Admin token (or set RIKUGAN_TOKEN)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Rikugan Client - CLI for Rikugan Server\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [global flags] <command> [command flags]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Global Flags:\n")
		fmt.Fprintf(os.Stderr, "  -server string    Server URL (or set RIKUGAN_SERVER env var)\n")
		fmt.Fprintf(os.Stderr, "  -token string     Admin token (or set RIKUGAN_TOKEN env var)\n")
		fmt.Fprintf(os.Stderr, "\nCommands:\n")
		fmt.Fprintf(os.Stderr, "  agents            List all agents\n")
		fmt.Fprintf(os.Stderr, "  exec              Execute ad-hoc command on an agent\n")
		fmt.Fprintf(os.Stderr, "  commands          List all scheduled commands\n")
		fmt.Fprintf(os.Stderr, "  add-command       Add a scheduled command\n")
		fmt.Fprintf(os.Stderr, "  rm-command        Remove a scheduled command\n")
		fmt.Fprintf(os.Stderr, "  files             List sync files\n")
		fmt.Fprintf(os.Stderr, "  add-file          Upload a file\n")
		fmt.Fprintf(os.Stderr, "  rm-file           Remove a file\n")
		fmt.Fprintf(os.Stderr, "\nRun '%s <command> -h' for command-specific help.\n", os.Args[0])
	}

	// Parse global flags only up to the command
	flag.Parse()

	// Get server URL and token from flags or environment
	server := *serverURL
	if server == "" {
		server = os.Getenv("RIKUGAN_SERVER")
	}

	token := *adminToken
	if token == "" {
		token = os.Getenv("RIKUGAN_TOKEN")
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]
	cmdArgs := args[1:]

	// Commands that don't require server connection
	if command == "help" || command == "-h" || command == "--help" {
		flag.Usage()
		os.Exit(0)
	}

	// Validate server and token
	if server == "" {
		fmt.Fprintln(os.Stderr, "Error: Server URL required. Use -server flag or set RIKUGAN_SERVER environment variable.")
		os.Exit(1)
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: Admin token required. Use -token flag or set RIKUGAN_TOKEN environment variable.")
		os.Exit(1)
	}

	client := NewClient(server, token)

	switch command {
	case "agents":
		agents, err := client.ListAgents()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(agents) == 0 {
			fmt.Println("No agents found.")
		} else {
			printAgents(agents)
		}

	case "exec":
		execFlags := flag.NewFlagSet("exec", flag.ExitOnError)
		agentID := execFlags.String("agent", "", "Agent ID (required)")
		cmd := execFlags.String("cmd", "", "Command to execute (required)")
		timeout := execFlags.Int("timeout", 60, "Timeout in seconds")
		wait := execFlags.Bool("wait", true, "Wait for result")
		execFlags.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: %s exec -agent <id> -cmd <command> [-timeout <sec>] [-wait]\n", os.Args[0])
			execFlags.PrintDefaults()
		}
		execFlags.Parse(cmdArgs)

		if *agentID == "" || *cmd == "" {
			execFlags.Usage()
			os.Exit(1)
		}

		resp, err := client.ExecCommand(*agentID, *cmd, *timeout, *wait)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		printExecResult(resp)

	case "commands":
		commands, err := client.ListCommands()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(commands) == 0 {
			fmt.Println("No commands found.")
		} else {
			printCommands(commands)
		}

	case "add-command":
		addFlags := flag.NewFlagSet("add-command", flag.ExitOnError)
		cmd := addFlags.String("cmd", "", "Command to execute (required)")
		interval := addFlags.Int("interval", 300, "Interval in seconds")
		osType := addFlags.String("os", "all", "Target OS (linux, windows, or all)")
		addFlags.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: %s add-command -cmd <command> [-interval <sec>] [-os <os>]\n", os.Args[0])
			addFlags.PrintDefaults()
		}
		addFlags.Parse(cmdArgs)

		if *cmd == "" {
			addFlags.Usage()
			os.Exit(1)
		}

		result, err := client.AddCommand(*cmd, *interval, *osType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Command added with ID: %s\n", result.ID)

	case "rm-command":
		rmFlags := flag.NewFlagSet("rm-command", flag.ExitOnError)
		id := rmFlags.String("id", "", "Command ID to remove (required)")
		rmFlags.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: %s rm-command -id <command-id>\n", os.Args[0])
			rmFlags.PrintDefaults()
		}
		rmFlags.Parse(cmdArgs)

		if *id == "" {
			rmFlags.Usage()
			os.Exit(1)
		}

		if err := client.RemoveCommand(*id); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Command %s removed.\n", *id)

	case "files":
		filesFlags := flag.NewFlagSet("files", flag.ExitOnError)
		osType := filesFlags.String("os", "", "OS type (linux or windows, required)")
		filesFlags.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: %s files -os <linux|windows>\n", os.Args[0])
			filesFlags.PrintDefaults()
		}
		filesFlags.Parse(cmdArgs)

		if *osType != "linux" && *osType != "windows" {
			filesFlags.Usage()
			os.Exit(1)
		}

		files, err := client.ListFiles(*osType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(files) == 0 {
			fmt.Printf("No files found for %s.\n", *osType)
		} else {
			printFiles(files, *osType)
		}

	case "add-file":
		addFileFlags := flag.NewFlagSet("add-file", flag.ExitOnError)
		filePath := addFileFlags.String("file", "", "Path to file to upload (required)")
		osType := addFileFlags.String("os", "", "Target OS (linux or windows, required)")
		addFileFlags.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: %s add-file -file <path> -os <linux|windows>\n", os.Args[0])
			addFileFlags.PrintDefaults()
		}
		addFileFlags.Parse(cmdArgs)

		if *filePath == "" || (*osType != "linux" && *osType != "windows") {
			addFileFlags.Usage()
			os.Exit(1)
		}

		uploaded, err := client.AddFile(*filePath, *osType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File uploaded: %s (os=%s)\n", uploaded, *osType)

	case "rm-file":
		rmFileFlags := flag.NewFlagSet("rm-file", flag.ExitOnError)
		filename := rmFileFlags.String("name", "", "Filename to remove (required)")
		osType := rmFileFlags.String("os", "", "Target OS (linux or windows, required)")
		rmFileFlags.Usage = func() {
			fmt.Fprintf(os.Stderr, "Usage: %s rm-file -name <filename> -os <linux|windows>\n", os.Args[0])
			rmFileFlags.PrintDefaults()
		}
		rmFileFlags.Parse(cmdArgs)

		if *filename == "" || (*osType != "linux" && *osType != "windows") {
			rmFileFlags.Usage()
			os.Exit(1)
		}

		if err := client.RemoveFile(*filename, *osType); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("File removed: %s (os=%s)\n", *filename, *osType)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}
