# Windows Installer Guide

This directory contains tools to package and deploy the Rikugan agent on Windows.

## Quick Start (No MSI Required)

The fastest way to deploy the agent is using the PowerShell installer:

### 1. Build the executable

On your build machine (Windows, Linux, or macOS with Go installed):

```bash
# From the project root
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o rikugan.exe .
```

### 2. Deploy to target machine

Copy these files to the target Windows machine:
- `rikugan.exe`
- `installer/windows/install-agent.ps1`
- `installer/windows/install.bat` (optional, for easier command-line install)

### 3. Install

**Option A: Using PowerShell (recommended)**

Run PowerShell as Administrator:

```powershell
.\install-agent.ps1 -ServerUrl "http://your-server:8080" -AgentToken "your-agent-token"

# With custom agent ID:
.\install-agent.ps1 -ServerUrl "http://your-server:8080" -AgentToken "your-agent-token" -AgentId "workstation-001"
```

**Option B: Using batch file**

Run Command Prompt as Administrator:

```cmd
install.bat http://your-server:8080 your-agent-token
install.bat http://your-server:8080 your-agent-token workstation-001
```

### 4. Verify installation

```powershell
# Check service status
Get-Service RikuganAgent

# View recent logs
Get-EventLog -LogName Application -Source RikuganAgent -Newest 20
```

### 5. Uninstall

```powershell
.\install-agent.ps1 -Uninstall
```

---

## MSI Installer (Enterprise Deployment)

For enterprise deployment via Group Policy, SCCM, or other management tools, you can build an MSI package.

### Prerequisites

1. **WiX Toolset v3.x** - Download from [wixtoolset.org](https://wixtoolset.org/)
2. **Go** - For building the executable
3. **Windows** - MSI building must be done on Windows

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
    AGENT_TOKEN="your-agent-token" ^
    AGENT_ID="workstation-001"
```

**Group Policy / SCCM deployment:**

Create a transform (.mst) file or use command-line properties:
- `SERVER_URL` - Rikugan server URL
- `AGENT_TOKEN` - Agent authentication token  
- `AGENT_ID` - Custom agent identifier (optional)

### Uninstalling

```cmd
msiexec /x Rikugan-1.0.0-x64.msi /qn
```

Or via Programs and Features in Control Panel.

---

## Mass Deployment Script

For deploying to multiple machines via PowerShell remoting:

```powershell
# deploy-agents.ps1
$servers = @(
    "workstation-001",
    "workstation-002",
    "workstation-003"
)

$serverUrl = "http://manager.example.com:8080"
$agentToken = "your-agent-token"
$installerPath = "\\fileserver\share\rikugan"

foreach ($server in $servers) {
    Write-Host "Deploying to $server..."
    
    Invoke-Command -ComputerName $server -ScriptBlock {
        param($url, $token, $path, $name)
        
        # Copy files
        Copy-Item "$path\rikugan.exe" "C:\Temp\" -Force
        Copy-Item "$path\install-agent.ps1" "C:\Temp\" -Force
        
        # Install
        & "C:\Temp\install-agent.ps1" -ServerUrl $url -AgentToken $token -AgentId $name
        
        # Cleanup
        Remove-Item "C:\Temp\rikugan.exe" -Force
        Remove-Item "C:\Temp\install-agent.ps1" -Force
        
    } -ArgumentList $serverUrl, $agentToken, $installerPath, $server
}
```

---

## Service Details

| Property | Value |
|----------|-------|
| Service Name | `RikuganAgent` |
| Display Name | `Rikugan Agent` |
| Startup Type | Automatic |
| Run As | Local System |
| Install Location | `C:\Program Files\Rikugan\` |
| Sync Directory | `C:\Program Files\Rikugan\sync\` |

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

---

## Customization

### Change installation directory

PowerShell:
```powershell
.\install-agent.ps1 -ServerUrl "..." -AgentToken "..." -InstallDir "D:\CustomPath\Rikugan"
```

MSI:
```cmd
msiexec /i Rikugan.msi INSTALLFOLDER="D:\CustomPath\Rikugan"
```

### Custom service account

Modify the PowerShell installer or use `sc.exe` after installation:
```cmd
sc.exe config RikuganAgent obj= "DOMAIN\ServiceAccount" password= "password"
```
