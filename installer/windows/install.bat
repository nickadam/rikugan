@echo off
REM Quick installer wrapper for Rikugan Agent
REM This script calls the PowerShell installer with the provided parameters

setlocal

if "%~1"=="" goto :usage
if "%~2"=="" goto :usage

set SERVER_URL=%~1
set AGENT_TOKEN=%~2
set AGENT_ID=%~3

echo.
echo Rikugan Agent Quick Installer
echo =====================================
echo.

REM Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This installer requires Administrator privileges.
    echo Please right-click and select "Run as Administrator"
    pause
    exit /b 1
)

REM Run PowerShell installer
if "%AGENT_ID%"=="" (
    powershell -ExecutionPolicy Bypass -File "%~dp0install-agent.ps1" -ServerUrl "%SERVER_URL%" -AgentToken "%AGENT_TOKEN%"
) else (
    powershell -ExecutionPolicy Bypass -File "%~dp0install-agent.ps1" -ServerUrl "%SERVER_URL%" -AgentToken "%AGENT_TOKEN%" -AgentId "%AGENT_ID%"
)

goto :end

:usage
echo Usage: install.bat ^<server-url^> ^<agent-token^> [agent-id]
echo.
echo Arguments:
echo   server-url   - URL of the Rikugan server (required)
echo   agent-token  - Agent authentication token (required)
echo   agent-id     - Custom agent ID (optional, defaults to hostname)
echo.
echo Examples:
echo   install.bat http://server:8080 abc123def456
echo   install.bat http://server:8080 abc123def456 workstation-001
echo.
echo For uninstallation, run:
echo   powershell -ExecutionPolicy Bypass -File install-agent.ps1 -Uninstall
echo.

:end
endlocal
