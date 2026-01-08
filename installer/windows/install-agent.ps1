<#
.SYNOPSIS
    Installs Rikugan Agent on Windows

.DESCRIPTION
    This script downloads/copies and installs the Rikugan agent as a Windows service.
    It can be used for quick deployment without building an MSI.

.PARAMETER ServerUrl
    The URL of the Rikugan server (required)

.PARAMETER AgentToken
    The agent authentication token (required)

.PARAMETER AgentId
    Custom agent ID (optional, defaults to hostname)

.PARAMETER InstallDir
    Installation directory (default: C:\Program Files\Rikugan)

.PARAMETER SourcePath
    Path to rikugan.exe (if not provided, assumes it's in current directory)

.PARAMETER Uninstall
    Remove the agent and service

.EXAMPLE
    .\install-agent.ps1 -ServerUrl "http://server:8080" -AgentToken "your-token"

.EXAMPLE
    .\install-agent.ps1 -ServerUrl "http://server:8080" -AgentToken "your-token" -AgentId "workstation-001"

.EXAMPLE
    .\install-agent.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ServerUrl,

    [Parameter(Mandatory=$false)]
    [string]$AgentToken,

    [Parameter(Mandatory=$false)]
    [string]$AgentId = "",

    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "C:\Program Files\Rikugan",

    [Parameter(Mandatory=$false)]
    [string]$SourcePath = "",

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName = "RikuganAgent"
$ServiceDisplayName = "Rikugan Agent"
$ServiceDescription = "Remote management and monitoring agent"

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Stop-AgentService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Status "Stopping existing service..."
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 2
        }
    }
}

function Remove-AgentService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Status "Removing existing service..."
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }
}

function Install-Agent {
    # Validate parameters
    if ([string]::IsNullOrEmpty($ServerUrl)) {
        throw "ServerUrl is required. Use -ServerUrl parameter."
    }
    if ([string]::IsNullOrEmpty($AgentToken)) {
        throw "AgentToken is required. Use -AgentToken parameter."
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  Rikugan Agent Installer" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""

    # Check admin rights
    if (-not (Test-Administrator)) {
        throw "This script requires Administrator privileges. Please run as Administrator."
    }

    # Determine source executable
    if ([string]::IsNullOrEmpty($SourcePath)) {
        $SourcePath = Join-Path $PSScriptRoot "rikugan.exe"
    }
    if (-not (Test-Path $SourcePath)) {
        # Try current directory
        $SourcePath = Join-Path (Get-Location) "rikugan.exe"
    }
    if (-not (Test-Path $SourcePath)) {
        throw "Cannot find rikugan.exe. Please specify -SourcePath or place it in the current directory."
    }

    Write-Status "Source: $SourcePath"
    Write-Status "Install directory: $InstallDir"
    Write-Status "Server URL: $ServerUrl"
    Write-Status "Agent ID: $(if ($AgentId) { $AgentId } else { '(auto-generated)' })"

    # Stop existing service
    Stop-AgentService
    Remove-AgentService

    # Create installation directory
    Write-Status "Creating installation directory..."
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Create subdirectories (agent_data with state and sync)
    $agentDataDir = Join-Path $InstallDir "agent_data"
    $stateDir = Join-Path $agentDataDir "state"
    $syncDir = Join-Path $agentDataDir "sync"
    $logsDir = Join-Path $InstallDir "logs"

    if (-not (Test-Path $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    }
    if (-not (Test-Path $syncDir)) {
        New-Item -ItemType Directory -Path $syncDir -Force | Out-Null
    }
    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    }

    # Copy executable
    Write-Status "Copying executable..."
    $exePath = Join-Path $InstallDir "rikugan.exe"
    Copy-Item -Path $SourcePath -Destination $exePath -Force

    # Build service arguments
    $serviceArgs = "-agent -server-url `"$ServerUrl`" -token `"$AgentToken`" -agent-data-dir `"$agentDataDir`""
    if (-not [string]::IsNullOrEmpty($AgentId)) {
        $serviceArgs += " -agent-id `"$AgentId`""
    }

    # Create the service
    Write-Status "Creating Windows service..."
    $binPath = "`"$exePath`" $serviceArgs"

    # Use sc.exe to create service with proper quoting
    $scArgs = @(
        "create", $ServiceName,
        "binPath=", $binPath,
        "DisplayName=", $ServiceDisplayName,
        "start=", "auto",
        "obj=", "LocalSystem"
    )

    & sc.exe create $ServiceName binPath= $binPath DisplayName= $ServiceDisplayName start= auto obj= LocalSystem
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create service"
    }

    # Set service description
    & sc.exe description $ServiceName $ServiceDescription

    # Configure service recovery (restart on failure)
    Write-Status "Configuring service recovery..."
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000

    # Start the service
    Write-Status "Starting service..."
    Start-Service -Name $ServiceName

    # Verify service is running
    Start-Sleep -Seconds 2
    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq "Running") {
        Write-Success "Service installed and running!"
    } else {
        Write-Error "Service installed but not running. Check Event Viewer for details."
    }

    # Save configuration for reference
    $configPath = Join-Path $InstallDir "install-config.txt"
    @"
Rikugan Agent Installation
=================================
Installed: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Server URL: $ServerUrl
Agent ID: $(if ($AgentId) { $AgentId } else { "(auto-generated)" })
Install Directory: $InstallDir
Agent Data Directory: $agentDataDir
  State: $stateDir
  Sync:  $syncDir

Service Name: $ServiceName
Service Status: $($service.Status)

To check status:
  Get-Service $ServiceName

To view logs:
  Get-EventLog -LogName Application -Source $ServiceName -Newest 20

To uninstall:
  .\install-agent.ps1 -Uninstall
"@ | Out-File -FilePath $configPath -Encoding UTF8

    Write-Host ""
    Write-Success "Installation complete!"
    Write-Host ""
    Write-Host "Service status: $($service.Status)" -ForegroundColor White
    Write-Host "Install directory: $InstallDir" -ForegroundColor White
    Write-Host "Configuration saved to: $configPath" -ForegroundColor White
    Write-Host ""
}

function Uninstall-Agent {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  Rikugan Agent Uninstaller" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""

    # Check admin rights
    if (-not (Test-Administrator)) {
        throw "This script requires Administrator privileges. Please run as Administrator."
    }

    # Stop and remove service
    Stop-AgentService
    Remove-AgentService

    # Remove installation directory
    if (Test-Path $InstallDir) {
        Write-Status "Removing installation directory..."

        # Give time for service to fully stop and release files
        Start-Sleep -Seconds 2

        try {
            Remove-Item -Path $InstallDir -Recurse -Force
            Write-Success "Installation directory removed"
        } catch {
            Write-Error "Could not remove all files. You may need to manually delete: $InstallDir"
        }
    }

    Write-Host ""
    Write-Success "Uninstallation complete!"
    Write-Host ""
}

# Main execution
try {
    if ($Uninstall) {
        Uninstall-Agent
    } else {
        Install-Agent
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
