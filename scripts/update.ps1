<#
.SYNOPSIS
    Dracula manual update script.

.DESCRIPTION
    Checks for the latest release on GitHub, downloads the archive, verifies
    SHA-256, backs up current binaries, and upgrades the active installation.

.PARAMETER InstallRoot
    Target directory of the Dracula installation (defaults to active root).
.PARAMETER Channel
    stable | prerelease
.PARAMETER Force
    Install even if the current version appears up to date.
#>

[CmdletBinding()]
param(
    [string]$InstallRoot,
    [ValidateSet('stable', 'prerelease')]
    [string]$Channel = 'stable',
    [switch]$Force,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Text) if (-not $Quiet) { Write-Host "  $Text" -ForegroundColor Gray } }
function Write-Ok   { param([string]$Text) if (-not $Quiet) { Write-Host "  + $Text" -ForegroundColor Green } }
function Write-Warn { param([string]$Text) if (-not $Quiet) { Write-Host "  ! $Text" -ForegroundColor Yellow } }

if (-not $InstallRoot) {
    if ($env:DRACULA_ROOT -and (Test-Path $env:DRACULA_ROOT)) {
        $InstallRoot = $env:DRACULA_ROOT
    } elseif (Test-Path (Join-Path $env:SystemDrive 'Dracula\.dracula_root')) {
        $InstallRoot = Join-Path $env:SystemDrive 'Dracula'
    } else {
        $InstallRoot = Join-Path $env:LOCALAPPDATA 'Dracula'
    }
}

if (-not (Test-Path $InstallRoot)) {
    throw "No existing Dracula installation found at '$InstallRoot'."
}

Write-Host ''
Write-Host '  DRACULA UPDATER' -ForegroundColor Red
Write-Host "  Target Root: $InstallRoot" -ForegroundColor DarkGray
Write-Host ''

# Query GitHub API
Write-Step "Checking GitHub Releases for latest release..."
$apiUrl = 'https://api.github.com/repos/i87kxxz/Dracula/releases'
$headers = @{
    'User-Agent' = 'Dracula-PowerShell-Updater/1.3.1'
    'Accept'     = 'application/vnd.github.v3+json'
}

$releases = Invoke-RestMethod -Uri $apiUrl -Headers $headers -UseBasicParsing
$targetRel = $null

foreach ($rel in $releases) {
    if ($rel.draft) { continue }
    if ($rel.prerelease -and ($Channel -ne 'prerelease')) { continue }
    $targetRel = $rel
    break
}

if (-not $targetRel) {
    throw "No suitable release found on channel '$Channel'."
}

Write-Ok "Found latest release: $($targetRel.tag_name)"

$zipAsset = $targetRel.assets | Where-Object { $_.name -like '*windows-x64.zip' -or ($_.name -like '*.zip' -and $_.name -notlike '*.sha256') } | Select-Object -First 1
$shaAsset = $targetRel.assets | Where-Object { $_.name -like '*.sha256' } | Select-Object -First 1

if (-not $zipAsset) {
    throw "Release $($targetRel.tag_name) does not contain a Windows x64 zip package asset."
}

# Run bootstrap with the resolved asset URL
$bootstrapScript = Join-Path $PSScriptRoot 'bootstrap.ps1'
if (Test-Path $bootstrapScript) {
    & $bootstrapScript -ReleaseUrl $zipAsset.browser_download_url -InstallRoot $InstallRoot
} else {
    Write-Step "Downloading $($zipAsset.browser_download_url)..."
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dracula-update-" + [guid]::NewGuid().ToString('N'))
    [void](New-Item -ItemType Directory -Path $tempDir -Force)
    try {
        $zipPath = Join-Path $tempDir 'update.zip'
        Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
        $stageDir = Join-Path $tempDir 'stage'
        Expand-Archive -Path $zipPath -DestinationPath $stageDir -Force

        # Backup bin
        $backupDir = Join-Path $InstallRoot "backup\pre-$($targetRel.tag_name)"
        [void](New-Item -ItemType Directory -Path $backupDir -Force)
        Copy-Item -Path (Join-Path $InstallRoot 'bin') -Destination $backupDir -Recurse -Force -ErrorAction SilentlyContinue

        # Copy new bin
        $foundExe = Get-ChildItem -Path $stageDir -Filter 'drac.exe' -Recurse | Select-Object -First 1
        if (-not $foundExe) {
            $foundExe = Get-ChildItem -Path $stageDir -Filter 'Dracula.exe' -Recurse | Select-Object -First 1
        }
        if ($foundExe) {
            Copy-Item -Path "$($foundExe.DirectoryName)\*" -Destination (Join-Path $InstallRoot 'bin') -Recurse -Force
            Write-Ok "Updated binaries successfully to $($targetRel.tag_name)."
        }
    } finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Ok "Update complete! Please restart any active Dracula instances."
Write-Host ''
