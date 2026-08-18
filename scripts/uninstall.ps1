<#
.SYNOPSIS
    Dracula uninstaller.

.DESCRIPTION
    Removes Dracula binaries, runtime components, and user PATH entries.
    Durable user projects are preserved by default unless -PurgeProjects is explicitly specified.

.PARAMETER InstallRoot
    Target directory to uninstall from (defaults to DRACULA_ROOT or auto-detected root).
.PARAMETER PurgeProjects
    If set, permanently deletes user projects and logs as well.
.PARAMETER Quiet
    Suppress non-error output.
#>

[CmdletBinding()]
param(
    [string]$InstallRoot,
    [switch]$PurgeProjects,
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
    Write-Warn "No Dracula installation detected at '$InstallRoot'."
    exit 0
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host "  DRACULA UNINSTALLER" -ForegroundColor Red
    Write-Host "  Target: $InstallRoot" -ForegroundColor DarkGray
    Write-Host ''
}

# 1. Remove PATH entry
$binDir = Join-Path $InstallRoot 'bin'
try {
    $regKey = 'HKCU:\Environment'
    $currentPath = (Get-ItemProperty -Path $regKey -Name Path -ErrorAction SilentlyContinue).Path
    if ($currentPath) {
        $segments = ($currentPath -split ';') | Where-Object { $_.Trim() -ne '' -and $_.Trim() -ne $binDir.Trim() }
        $newPath = $segments -join ';'
        Set-ItemProperty -Path $regKey -Name Path -Value $newPath
        Write-Ok "Removed '$binDir' from user PATH."
    }
} catch {
    Write-Warn "Could not update user PATH: $_"
}

# 2. Remove program binaries & runtime data
$itemsToRemove = @('bin', 'tools', 'runtime', 'vm\overlays', 'cache', '.dracula_root', 'backup')
foreach ($item in $itemsToRemove) {
    $target = Join-Path $InstallRoot $item
    if (Test-Path $target) {
        Remove-Item -Path $target -Recurse -Force -ErrorAction SilentlyContinue
        Write-Step "Removed $item"
    }
}

# 3. Handle projects
if ($PurgeProjects) {
    $projectsDir = Join-Path $InstallRoot 'projects'
    if (Test-Path $projectsDir) {
        Remove-Item -Path $projectsDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Purged projects directory."
    }
    Remove-Item -Path $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Entire Dracula directory removed."
} else {
    Write-Ok "Dracula uninstalled successfully."
    if (-not $Quiet) { Write-Host "  User projects preserved at: '$InstallRoot\projects'" -ForegroundColor Cyan }
}

if (-not $Quiet) { Write-Host '' }
