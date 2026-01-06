# Rikugan

A remote management and monitoring tool for device management. A single binary that can run as either a server or an agent (client), with websocket communication, scheduled command execution, file synchronization, and comprehensive logging.

## Features

- **Single Binary**: One executable that runs as either server or agent
- **WebSocket Communication**: Real-time bidirectional communication between server and agents
- **Scheduled Commands**: Define commands with intervals; agents track execution times and run commands only when intervals elapse
- **OS-Specific Commands**: Commands can target Linux, Windows, or all operating systems
- **File Synchronization**: Sync scripts and installers between server and agents
- **Dual Authentication**: Separate tokens for admin API access and agent connections
- **Persistent Storage**: Commands persist across server restarts
- **Compressed Logging**: Command results logged in gzip-compressed JSON format
- **ISO 8601 Timestamps**: All times expressed in ISO 8601 format

## Building

```bash
# Ensure Go 1.21+ is installed
go mod tidy
go build -o rikugan .

# Cross-compile for different platforms
GOOS=linux GOARCH=amd64 go build -o rikugan-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o rikugan-windows-amd64.exe .
GOOS=darwin GOARCH=amd64 go build -o rikugan-darwin-amd64 .
GOOS=darwin GOARCH=arm64 go build -o rikugan-darwin-arm64 .
```

## Usage

### Server Mode

Running without parameters starts the server with auto-generated tokens:

```bash
./rikugan
```

Or explicitly:

```bash
./rikugan -server \
  -port 8080 \
  -data-dir ./data \
  -admin-token "your-admin-token" \
  -agent-token "your-agent-token"
```

**Server Options:**
| Flag | Default | Description |
|------|---------|-------------|
| `-server` | (default mode) | Run in server mode |
| `-port` | 8080 | HTTP/WebSocket server port |
| `-data-dir` | ./data | Directory for persistent data |
| `-admin-token` | (auto-generated) | Token for admin API authentication |
| `-agent-token` | (auto-generated) | Token for agent authentication |

**Log Rotation Options:**
| Flag | Default | Description |
|------|---------|-------------|
| `-log-rotate` | false | Enable log rotation |
| `-log-rotate-daily` | true | Rotate logs at midnight UTC |
| `-log-max-size-mb` | 100 | Rotate when log exceeds this size (0 = no limit) |
| `-log-max-age-days` | 30 | Delete logs older than this (0 = keep forever) |
| `-log-max-files` | 0 | Max rotated files to keep (0 = unlimited) |

**Example with log rotation:**
```bash
./rikugan -server \
  -log-rotate \
  -log-rotate-daily \
  -log-max-size-mb 50 \
  -log-max-age-days 7 \
  -log-max-files 10
```

### Agent Mode

```bash
./rikugan -agent \
  -server-url "http://server:8080" \
  -token "agent-token-from-server"
```

**Agent Options:**
| Flag | Default | Description |
|------|---------|-------------|
| `-agent` | | Run in agent mode |
| `-server-url` | (required) | Server URL (http:// or https://) |
| `-token` | (required) | Agent authentication token |
| `-agent-id` | (hostname) | Unique agent identifier |
| `-sync-dir` | ./agent_sync | Directory for synced files |

## API Reference

All admin API endpoints require authentication via:
- Header: `Authorization: Bearer <admin_token>`
- Or query parameter: `?admin_token=<admin_token>`

### Commands

#### List Commands
```bash
GET /api/commands
```

Response:
```json
[
  {
    "id": "abc123",
    "command": "df -h",
    "interval_sec": 300,
    "os": "linux",
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

#### Add Command
```bash
POST /api/commands
Content-Type: application/json

{
  "command": "df -h",
  "interval_sec": 300,
  "os": "linux"
}
```

**Command Fields:**
| Field | Required | Description |
|-------|----------|-------------|
| `command` | Yes | Shell command to execute |
| `interval_sec` | Yes | Minimum seconds between executions |
| `os` | No | Target OS: `linux`, `windows`, or `all` (default: `all`) |
| `id` | No | Custom ID (auto-generated if omitted) |

Response:
```json
{
  "id": "abc123def456",
  "command": "df -h",
  "interval_sec": 300,
  "os": "linux",
  "created_at": "2024-01-15T10:30:00Z"
}
```

#### Delete Command
```bash
DELETE /api/commands?id=abc123
```

Response:
```json
{
  "deleted": "abc123"
}
```

### Agents

#### List Agents
```bash
GET /api/agents
```

Response:
```json
[
  {
    "id": "workstation-001",
    "os": "linux",
    "connected_at": "2024-01-15T09:00:00Z",
    "last_seen": "2024-01-15T10:30:00Z",
    "connected": true
  }
]
```

### Ad-Hoc Command Execution

Execute a one-time command on a specific agent.

#### Execute Command
```bash
POST /api/exec
Content-Type: application/json

{
  "agent_id": "workstation-001",
  "command": "whoami",
  "timeout_sec": 30,
  "wait": true
}
```

**Request Fields:**
| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `agent_id` | Yes | | Target agent ID |
| `command` | Yes | | Shell command to execute |
| `timeout_sec` | No | 60 | Command timeout in seconds |
| `wait` | No | false | If true, wait for result before responding |

**Response (wait=true):**
```json
{
  "id": "adhoc-abc123def456",
  "agent_id": "workstation-001",
  "command": "whoami",
  "status": "completed",
  "result": {
    "agent_id": "workstation-001",
    "command_id": "adhoc-abc123def456",
    "command": "whoami",
    "stdout": "root\n",
    "stderr": "",
    "return_code": 0,
    "start_time": "2024-01-15T10:30:00Z",
    "execution_time_sec": 0.015
  }
}
```

**Response (wait=false):**
```json
{
  "id": "adhoc-abc123def456",
  "agent_id": "workstation-001",
  "command": "whoami",
  "status": "sent"
}
```

**Status Values:**
| Status | Description |
|--------|-------------|
| `sent` | Command sent to agent (fire-and-forget mode) |
| `pending` | Waiting for agent response |
| `completed` | Command executed, result available |
| `timeout` | Command timed out |
| `error` | Error sending command or agent not connected |

### Files

#### List Files
```bash
GET /api/files
```

Response:
```json
[
  {
    "name": "install-agent.sh",
    "size": 1024,
    "mod_time": "2024-01-15T08:00:00Z"
  }
]
```

#### Upload File
```bash
POST /api/files
Content-Type: multipart/form-data

file=@install-agent.sh
```

Response:
```json
{
  "uploaded": "install-agent.sh"
}
```

#### Delete File
```bash
DELETE /api/files?filename=install-agent.sh
```

Response:
```json
{
  "deleted": "install-agent.sh"
}
```

#### Download File
```bash
GET /api/files/download?filename=install-agent.sh
```

## Examples

### Using curl

```bash
# Set your admin token
ADMIN_TOKEN="your-admin-token"
SERVER="http://localhost:8080"

# Add a command to check disk space every 5 minutes (Linux only)
curl -X POST "$SERVER/api/commands" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "df -h",
    "interval_sec": 300,
    "os": "linux"
  }'

# Add a command to get system info every hour (Windows only)
curl -X POST "$SERVER/api/commands" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "systeminfo",
    "interval_sec": 3600,
    "os": "windows"
  }'

# Add a command for all OSes
curl -X POST "$SERVER/api/commands" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "hostname",
    "interval_sec": 60,
    "os": "all"
  }'

# List all commands
curl "$SERVER/api/commands" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Delete a command
curl -X DELETE "$SERVER/api/commands?id=abc123" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# List connected agents
curl "$SERVER/api/agents" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Execute ad-hoc command (fire and forget)
curl -X POST "$SERVER/api/exec" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "workstation-001",
    "command": "whoami"
  }'

# Execute ad-hoc command and wait for result
curl -X POST "$SERVER/api/exec" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "workstation-001",
    "command": "df -h",
    "timeout_sec": 30,
    "wait": true
  }'

# Execute command with longer timeout
curl -X POST "$SERVER/api/exec" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "workstation-001",
    "command": "apt-get update",
    "timeout_sec": 300,
    "wait": true
  }'

# Upload a script for sync
curl -X POST "$SERVER/api/files" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -F "file=@./scripts/install-software.sh"

# List synced files
curl "$SERVER/api/files" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Delete a synced file
curl -X DELETE "$SERVER/api/files?filename=old-script.sh" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Systemd Service (Server)

`/etc/systemd/system/rikugan-server.service`:
```ini
[Unit]
Description=Rikugan Server
After=network.target

[Service]
Type=simple
User=rikugan
ExecStart=/usr/local/bin/rikugan -server -port 8080 -data-dir /var/lib/rikugan
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Systemd Service (Agent)

`/etc/systemd/system/rikugan-agent.service`:
```ini
[Unit]
Description=Rikugan Agent
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rikugan -agent -server-url http://manager.example.com:8080 -token YOUR_AGENT_TOKEN
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Data Storage

### Server Data Directory Structure
```
data/
├── commands.json                      # Persisted command definitions
├── results.json.gz                    # Current compressed command execution logs
├── results-2024-01-15T00-00-00.json.gz  # Rotated log (when rotation enabled)
├── results-2024-01-14T00-00-00.json.gz  # Older rotated log
└── sync/                              # Files for agent synchronization
    ├── install.sh
    └── setup.msi
```

### Result Log Format

Results are stored in `results.json.gz` as newline-delimited JSON:

```json
{"agent_id":"workstation-001","command_id":"abc123","command":"df -h","stdout":"Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   20G   28G  42% /\n","stderr":"","return_code":0,"start_time":"2024-01-15T10:30:00Z","execution_time_sec":0.125}
{"agent_id":"workstation-002","command_id":"abc123","command":"df -h","stdout":"Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1       100G   45G   50G  48% /\n","stderr":"","return_code":0,"start_time":"2024-01-15T10:30:01Z","execution_time_sec":0.098}
```

Read results with:
```bash
# Current log
zcat data/results.json.gz | jq .

# All logs (including rotated)
zcat data/results*.json.gz | jq .

# Search across all logs
zcat data/results*.json.gz | jq 'select(.agent_id == "workstation-001")'
```

### Log Rotation

When log rotation is enabled (`-log-rotate`), the server will:
1. Rotate the current log at midnight UTC (if `-log-rotate-daily`)
2. Rotate when the log exceeds the size limit (if `-log-max-size-mb > 0`)
3. Delete old rotated logs based on age (if `-log-max-age-days > 0`)
4. Keep only the most recent N rotated logs (if `-log-max-files > 0`)

Rotated files are named with ISO 8601 timestamps: `results-YYYY-MM-DDTHH-MM-SS.json.gz`

## Security Considerations

1. **Use HTTPS in Production**: Deploy behind a reverse proxy (nginx, Caddy) with TLS
2. **Protect Tokens**: Store admin and agent tokens securely
3. **Firewall Rules**: Restrict access to the server port
4. **Principle of Least Privilege**: Run agents with minimal required permissions
5. **Audit Logs**: Monitor the results log for unexpected commands

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        SERVER                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │ Admin API   │  │ Commands DB │  │ Results Log (gzip)  │   │
│  │ (HTTP/REST) │  │ (JSON file) │  │ (JSONL file)        │   │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘   │
│         │                │                     │              │
│         ▼                ▼                     ▲              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │              WebSocket Handler                        │    │
│  │  - Broadcasts command updates to agents               │    │
│  │  - Receives execution results                         │    │
│  │  - Handles file sync requests                         │    │
│  └──────────────────────┬───────────────────────────────┘    │
│                         │                                     │
│  ┌──────────────────────┴───────────────────────────────┐    │
│  │                    Sync Files                         │    │
│  │              (scripts, installers)                    │    │
│  └──────────────────────────────────────────────────────┘    │
└─────────────────────────┬────────────────────────────────────┘
                          │ WebSocket
          ┌───────────────┼───────────────┐
          │               │               │
          ▼               ▼               ▼
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │  Agent 1 │    │  Agent 2 │    │  Agent N │
    │ (Linux)  │    │ (Windows)│    │  (...)   │
    └──────────┘    └──────────┘    └──────────┘
```

## Protocol

### WebSocket Messages

**Server → Agent:**
- `commands`: List of commands to execute
- `files`: List of available sync files
- `file_data`: Binary file content (base64 encoded)

**Agent → Server:**
- `result`: Command execution result
- `file_request`: Request for a specific file

## License

MIT License
