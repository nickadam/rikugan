# Windows Installer Guide

This directory contains tools to package and deploy the Rikugan agent on Windows.

---

## MSI Installer (Enterprise Deployment)

For enterprise deployment via Group Policy, SCCM, or other management tools, you can build an MSI package.

### Prerequisites

1. **WiX Toolset v3.x** - Download from [wixtoolset.org](https://wixtoolset.org/)
2. **Go** - For building the executable
3. `go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest`

### Building the MSI

1. Open Command Prompt in this directory

2. Run the build script:
   ```cmd
   build-msi.bat
   ```

3. Find the MSI in `output\Rikugan-1.0.0-x64.msi`

### Installing the MSI

**Interactive installation:**
```cmd
msiexec /i Rikugan-1.0.0-x64.msi
```

**Silent installation with parameters:**
```cmd
msiexec /i Rikugan-1.0.0-x64.msi /qn ^
    SERVER_URL="http://your-server:8080" ^
    AGENT_TOKEN="your-agent-token"
```

**Group Policy / SCCM deployment:**

Create a transform (.mst) file or use command-line properties:
- `SERVER_URL` - Rikugan server URL
- `AGENT_TOKEN` - Agent authentication token

### Uninstalling

```cmd
msiexec /x Rikugan-1.0.0-x64.msi /qn
```

Or via Programs and Features in Control Panel.

---

## Service Details

| Property | Value |
|----------|-------|
| Service Name | `RikuganAgent` |
| Display Name | `Rikugan Agent` |
| Startup Type | Automatic |
| Run As | Local System |
| Executable | `C:\Program Files\Rikugan\rikugan.exe` |
| Data Directory | `C:\ProgramData\Rikugan\` |
| State Directory | `C:\ProgramData\Rikugan\state\` |
| Sync Directory | `C:\ProgramData\Rikugan\sync\` |
| Logs Directory | `C:\ProgramData\Rikugan\logs\` |

### Directory Structure

```
C:\Program Files\Rikugan\          # Executable location
└── rikugan.exe
└── install-config.txt             # Installation details

C:\ProgramData\Rikugan\            # Data location (persists across updates)
├── state\
│   └── .agent-id                  # Persistent agent identifier
├── sync\
│   └── (synced files from server)
└── logs\
```

### Service Recovery

The service is configured to automatically restart on failure:
- 1st failure: Restart after 5 seconds
- 2nd failure: Restart after 10 seconds
- 3rd failure: Restart after 30 seconds
- Reset failure count after: 24 hours

### Manual Service Control

```powershell
# Start
Start-Service RikuganAgent

# Stop
Stop-Service RikuganAgent

# Restart
Restart-Service RikuganAgent

# Check status
Get-Service RikuganAgent
```

---

## Firewall Configuration

The agent makes outbound connections only. If you have restrictive outbound firewall rules:

```powershell
# Allow outbound to server (adjust port as needed)
New-NetFirewallRule -DisplayName "Rikugan Agent" `
    -Direction Outbound `
    -Program "C:\Program Files\Rikugan\rikugan.exe" `
    -Action Allow
```

---

## Troubleshooting

### Service won't start

1. Check Event Viewer > Windows Logs > Application
2. Verify server URL is accessible: `Test-NetConnection -ComputerName server -Port 8080`
3. Verify agent token is correct

### Service starts but disconnects

1. Check network connectivity to server
2. Verify firewall allows outbound WebSocket connections
3. Check server logs for authentication failures

### Permission issues

1. Ensure service runs as Local System (default)
2. Check sync directory permissions

### View service logs

```powershell
Get-EventLog -LogName Application -Source RikuganAgent -Newest 50 | Format-List
```
