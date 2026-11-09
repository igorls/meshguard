# meshguard Windows installer
# Usage: irm https://raw.githubusercontent.com/igorls/meshguard/main/install.ps1 | iex
#
# Downloads meshguard.exe and wintun.dll from the latest release, verifies both
# against that release's checksums.txt, and only then places them in the
# install directory.

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

# Resolve the latest release
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
if ($Tag -notmatch '^v[0-9][A-Za-z0-9._-]*$') {
    Write-Host "Error: unexpected release tag '$Tag'." -ForegroundColor Red
    exit 1
}

$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"

# Download into a private temporary directory first; files move into place only
# after their checksums match the release manifest.
$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("meshguard-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $WorkDir | Out-Null

function Get-ReleaseFile($Name) {
    $Target = Join-Path $WorkDir $Name
    Write-Host "Downloading $Name..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "$BaseUrl/$Name" -OutFile $Target -UseBasicParsing
    } catch {
        Write-Host "Error: failed to download $Name" -ForegroundColor Red
        Write-Host "  URL: $BaseUrl/$Name"
        Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
        exit 1
    }
    return $Target
}

# checksums.txt lines are "<sha256 hex>  <name>"; a leading '*' marks binary mode.
function Get-ExpectedHash($Manifest, $Name) {
    foreach ($Line in Get-Content $Manifest) {
        $Parts = ($Line.Trim() -split '\s+', 2)
        if ($Parts.Count -ne 2) { continue }
        if ($Parts[1].TrimStart('*') -eq $Name) { return $Parts[0].ToLowerInvariant() }
    }
    return $null
}

function Assert-Checksum($Manifest, $Path, $Name) {
    $Expected = Get-ExpectedHash $Manifest $Name
    if (-not $Expected) {
        Write-Host "Error: checksums.txt for $Tag has no entry for $Name; refusing to install." -ForegroundColor Red
        Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
        exit 1
    }
    $Actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) {
        Write-Host "Error: checksum mismatch for $Name" -ForegroundColor Red
        Write-Host "  expected: $Expected"
        Write-Host "  actual:   $Actual"
        Write-Host "The download is corrupt or has been tampered with. Nothing was installed."
        Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
        exit 1
    }
}

Write-Host ""
$ExeTemp = Get-ReleaseFile "meshguard-windows-amd64.exe"
$DllTemp = Get-ReleaseFile $Dll
$Manifest = Get-ReleaseFile "checksums.txt"

Assert-Checksum $Manifest $ExeTemp "meshguard-windows-amd64.exe"
Assert-Checksum $Manifest $DllTemp $Dll
Write-Host "Checksums verified." -ForegroundColor Green

$ExePath = Join-Path $InstallDir $Binary
$DllPath = Join-Path $InstallDir $Dll
Move-Item -Force -Path $ExeTemp -Destination $ExePath
Move-Item -Force -Path $DllTemp -Destination $DllPath
Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue

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
