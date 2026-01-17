# Rikugan Client (rc)

A command-line client for interacting with the Rikugan server.

## Building

```bash
cd rc
go build -o rc .

# Cross-compile for different platforms
GOOS=linux GOARCH=amd64 go build -o rc-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o rc-windows-amd64.exe .
GOOS=darwin GOARCH=amd64 go build -o rc-darwin-amd64 .
GOOS=darwin GOARCH=arm64 go build -o rc-darwin-arm64 .
```

## Configuration

The client requires a server URL and admin token. These can be provided via:

1. **Command-line flags** (highest priority):
   ```bash
   rc -server http://localhost:8080 -token your-admin-token <command>
   ```

2. **Environment variables**:
   ```bash
   export RIKUGAN_SERVER=http://localhost:8080
   export RIKUGAN_TOKEN=your-admin-token
   rc <command>
   ```

## Commands

### agents

List all connected agents.

```bash
rc agents
```

Output:
```
ID                  OS       CONNECTED  LAST SEEN
--                  --       ---------  ---------
workstation-abc123  linux    Yes        2024-01-15T10:30:00Z
server-def456       windows  Yes        2024-01-15T10:29:55Z
```

### exec

Execute an ad-hoc command on a specific agent.

```bash
rc exec -agent <agent-id> -cmd <command> [-timeout <seconds>] [-wait]
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `-agent` | (required) | Target agent ID |
| `-cmd` | (required) | Command to execute |
| `-timeout` | 60 | Timeout in seconds |
| `-wait` | true | Wait for command result |

**Examples:**

```bash
# Execute a command and wait for result
rc exec -agent workstation-abc123 -cmd "df -h"

# Execute with custom timeout
rc exec -agent workstation-abc123 -cmd "apt-get update" -timeout 300

# Fire and forget (don't wait for result)
rc exec -agent workstation-abc123 -cmd "reboot" -wait=false

# Execute a synced script
rc exec -agent workstation-abc123 -cmd '$RIKUGAN_SYNC_DIR/install.sh'

# Windows command
rc exec -agent server-def456 -cmd "dir c:\\Windows"
```

Output (when waiting):
```
Command ID: adhoc-abc123def456
Agent: workstation-abc123
Status: completed
Return Code: 0
Execution Time: 0.125s

--- STDOUT ---
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   20G   28G  42% /
```

### commands

List all scheduled commands.

```bash
rc commands
```

Output:
```
ID                COMMAND                                   INTERVAL  OS       CREATED
--                -------                                   --------  --       -------
abc123def456      df -h                                     300s      linux    2024-01-15T10:00:00Z
ghi789jkl012      systeminfo                                3600s     windows  2024-01-15T09:00:00Z
```

### add-command

Add a new scheduled command.

```bash
rc add-command -cmd <command> [-interval <seconds>] [-os <os>]
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `-cmd` | (required) | Command to execute |
| `-interval` | 300 | Interval between executions (seconds) |
| `-os` | all | Target OS: `linux`, `windows`, or `all` |

**Examples:**

```bash
# Add a command for all OSes
rc add-command -cmd "hostname" -interval 60

# Add a Linux-only command
rc add-command -cmd "df -h" -interval 300 -os linux

# Add a Windows-only command
rc add-command -cmd "Get-Process | Select-Object -First 10" -interval 600 -os windows
```

Output:
```
Command added with ID: abc123def456
```

### rm-command

Remove a scheduled command.

```bash
rc rm-command -id <command-id>
```

**Example:**

```bash
rc rm-command -id abc123def456
```

Output:
```
Command abc123def456 removed.
```

### files

List sync files for a specific OS.

```bash
rc files -os <linux|windows>
```

**Examples:**

```bash
# List Linux files
rc files -os linux

# List Windows files
rc files -os windows
```

Output:
```
Files for linux:
NAME              SIZE    MODIFIED
----              ----    --------
install.sh        1024    2024-01-15T08:00:00Z
monitor.sh        2048    2024-01-15T09:00:00Z
```

### add-file

Upload a file to the server for syncing to agents.

```bash
rc add-file -file <path> -os <linux|windows>
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `-file` | (required) | Path to file to upload |
| `-os` | (required) | Target OS: `linux` or `windows` |

**Examples:**

```bash
# Upload a script for Linux agents
rc add-file -file ./scripts/install.sh -os linux

# Upload a script for Windows agents
rc add-file -file ./scripts/setup.bat -os windows
```

Output:
```
File uploaded: install.sh (os=linux)
```

### rm-file

Remove a file from the server.

```bash
rc rm-file -name <filename> -os <linux|windows>
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `-name` | (required) | Filename to remove |
| `-os` | (required) | Target OS: `linux` or `windows` |

**Example:**

```bash
rc rm-file -name old-script.sh -os linux
```

Output:
```
File removed: old-script.sh (os=linux)
```

## Shell Aliases

For convenience, you can set up shell aliases:

```bash
# In ~/.bashrc or ~/.zshrc
export RIKUGAN_SERVER=http://your-server:8080
export RIKUGAN_TOKEN=your-admin-token
alias rc='/path/to/rc'
```

## Examples

### Typical Workflow

```bash
# Set environment variables
export RIKUGAN_SERVER=http://localhost:8080
export RIKUGAN_TOKEN=abc123

# Check which agents are connected
rc agents

# Add a scheduled command to run on all Linux agents every 5 minutes
rc add-command -cmd "df -h" -interval 300 -os linux

# Upload a script for Linux agents
rc add-file -file ./deploy.sh -os linux

# Execute the script on a specific agent
rc exec -agent workstation-abc123 -cmd '$RIKUGAN_SYNC_DIR/deploy.sh' -timeout 120

# List current commands
rc commands

# Remove a command that's no longer needed
rc rm-command -id abc123def456

# Clean up old files
rc rm-file -name old-deploy.sh -os linux
```

### Scripting

The client can be used in scripts:

```bash
#!/bin/bash

# Run a command on all connected Linux agents
for agent in $(rc agents | grep linux | grep Yes | awk '{print $1}'); do
    echo "Running on $agent..."
    rc exec -agent "$agent" -cmd "apt-get update && apt-get upgrade -y" -timeout 600
done
```

## Error Handling

The client will exit with a non-zero status code on errors:

- Exit code 1: Command failed or invalid arguments

Error messages are printed to stderr:

```bash
rc exec -agent nonexistent -cmd "whoami"
# Error: HTTP 404: Agent not found
```
