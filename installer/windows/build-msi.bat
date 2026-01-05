@echo off
REM Build script for Rikugan Windows MSI installer
REM Requires: WiX Toolset v3.x (https://wixtoolset.org/)

setlocal enabledelayedexpansion

echo ============================================
echo Rikugan Windows Installer Builder
echo ============================================

REM Configuration
set PRODUCT_VERSION=1.0.0
set BUILD_DIR=%~dp0build
set OUTPUT_DIR=%~dp0output
set WIX_DIR=C:\Program Files (x86)\WiX Toolset v3.11\bin

REM Check for WiX
if not exist "%WIX_DIR%\candle.exe" (
    echo ERROR: WiX Toolset not found at %WIX_DIR%
    echo Please install WiX Toolset from https://wixtoolset.org/
    echo Or update WIX_DIR in this script
    exit /b 1
)

REM Create directories
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo.
echo Step 1: Building Go executable...
echo.

REM Build the Go executable for Windows
pushd %~dp0..\..
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-s -w" -o "%BUILD_DIR%\rikugan.exe" .
if errorlevel 1 (
    echo ERROR: Go build failed
    popd
    exit /b 1
)
popd

echo.
echo Step 2: Creating default config file...
echo.

REM Create a template config file
(
echo # Rikugan Agent Configuration
echo # Edit these values before installing or pass them during installation
echo server_url: "http://your-server:8080"
echo agent_token: "your-agent-token"
echo agent_id: ""  # Leave empty to use hostname
) > "%BUILD_DIR%\agent-config.yaml"

echo.
echo Step 3: Compiling WiX installer...
echo.

REM Compile WiX source
"%WIX_DIR%\candle.exe" -nologo ^
    -dBuildDir="%BUILD_DIR%" ^
    -dProductVersion=%PRODUCT_VERSION% ^
    -arch x64 ^
    -out "%BUILD_DIR%\Product.wixobj" ^
    "%~dp0Product.wxs"

if errorlevel 1 (
    echo ERROR: WiX candle failed
    exit /b 1
)

echo.
echo Step 4: Linking MSI package...
echo.

REM Link to create MSI
"%WIX_DIR%\light.exe" -nologo ^
    -ext WixUIExtension ^
    -ext WixUtilExtension ^
    -out "%OUTPUT_DIR%\Rikugan-%PRODUCT_VERSION%-x64.msi" ^
    "%BUILD_DIR%\Product.wixobj"

if errorlevel 1 (
    echo ERROR: WiX light failed
    exit /b 1
)

echo.
echo ============================================
echo SUCCESS: MSI installer created
echo Output: %OUTPUT_DIR%\Rikugan-%PRODUCT_VERSION%-x64.msi
echo ============================================
echo.
echo Installation options:
echo   msiexec /i Rikugan-%PRODUCT_VERSION%-x64.msi
echo.
echo   With parameters:
echo   msiexec /i Rikugan-%PRODUCT_VERSION%-x64.msi ^
echo       SERVER_URL="http://server:8080" ^
echo       AGENT_TOKEN="your-token" ^
echo       AGENT_ID="custom-id"
echo.
echo   Silent install:
echo   msiexec /i Rikugan-%PRODUCT_VERSION%-x64.msi /qn ^
echo       SERVER_URL="http://server:8080" ^
echo       AGENT_TOKEN="your-token"
echo.

endlocal
