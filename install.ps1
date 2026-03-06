# meshguard Windows installer
# Usage: irm https://raw.githubusercontent.com/igorls/meshguard/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$Repo = "igorls/meshguard"
$InstallDir = "$env:LOCALAPPDATA\meshguard"
$Binary = "meshguard.exe"
$Dll = "wintun.dll"

Write-Host "meshguard Windows installer" -ForegroundColor Cyan
Write-Host ""

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Download latest release
$ReleasesUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $Release = Invoke-RestMethod -Uri $ReleasesUrl -Headers @{ "User-Agent" = "meshguard-installer" }
    $Tag = $Release.tag_name
    Write-Host "  latest release: $Tag"
} catch {
    Write-Host "Error: could not fetch latest release from GitHub." -ForegroundColor Red
    Write-Host "  Check https://github.com/$Repo/releases"
    exit 1
}

$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"

# Download meshguard.exe
Write-Host ""
Write-Host "Downloading $Binary..." -ForegroundColor Yellow
$ExePath = Join-Path $InstallDir $Binary
try {
    Invoke-WebRequest -Uri "$BaseUrl/meshguard-windows-amd64.exe" -OutFile $ExePath -UseBasicParsing
} catch {
    Write-Host "Error: failed to download $Binary" -ForegroundColor Red
    Write-Host "  URL: $BaseUrl/meshguard-windows-amd64.exe"
    exit 1
}

# Download wintun.dll
Write-Host "Downloading $Dll..." -ForegroundColor Yellow
$DllPath = Join-Path $InstallDir $Dll
try {
    Invoke-WebRequest -Uri "$BaseUrl/wintun.dll" -OutFile $DllPath -UseBasicParsing
} catch {
    Write-Host "Error: failed to download $Dll" -ForegroundColor Red
    Write-Host "  URL: $BaseUrl/wintun.dll"
    exit 1
}

# Add to PATH (user-level, persistent)
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host ""
    Write-Host "Adding $InstallDir to PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path = "$env:Path;$InstallDir"
}

# Verify
Write-Host ""
$Version = & $ExePath version 2>&1
Write-Host "Installed: $Version" -ForegroundColor Green
Write-Host "  Location: $InstallDir" -ForegroundColor Gray
Write-Host ""
Write-Host "Get started:" -ForegroundColor Cyan
Write-Host "  meshguard keygen                           # generate identity"
Write-Host "  meshguard up --seed <peer-ip>:51821        # join mesh (run as Admin)"
Write-Host "  meshguard --help                           # see all commands"
Write-Host ""
Write-Host "NOTE: 'meshguard up' requires Administrator privileges." -ForegroundColor Yellow
Write-Host "  Right-click your terminal -> 'Run as Administrator'"
