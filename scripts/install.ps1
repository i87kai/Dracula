<#
.SYNOPSIS
    Dracula official installer.

.DESCRIPTION
    Installs Dracula into a location chosen interactively or via parameter,
    creates the workspace hierarchy, and configures the global `drac` command
    on the user's PATH.

.PARAMETER InstallRoot
    Target directory for installation (e.g. C:\Dracula).
.PARAMETER Source
    Source directory containing built binaries or payload files.
.PARAMETER Mode
    install | repair | update | uninstall
.PARAMETER NoPathUpdate
    Do not modify user PATH environment variable.
.PARAMETER Quiet
    Suppress non-error console output.
#>

[CmdletBinding()]
param(
    [string]$InstallRoot,
    [string]$Source,
    [ValidateSet('install', 'repair', 'update', 'uninstall')]
    [string]$Mode = 'install',
    [switch]$NoPathUpdate,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

# Payload manifest
$script:Payload = @(
    @{ Name = 'Dracula.exe';           Target = 'bin\drac.exe';               Required = $true  },
    @{ Name = 'libDraculaAgent64.dll'; Target = 'bin\libDraculaAgent64.dll';  Required = $false },
    @{ Name = 'DraculaAgent64.dll';    Target = 'bin\DraculaAgent64.dll';     Required = $false },
    @{ Name = 'GuestAgent.exe';        Target = 'bin\GuestAgent.exe';         Required = $false },
    @{ Name = 'InjectableDLL.dll';     Target = 'bin\InjectableDLL.dll';      Required = $false }
)

# Workspace directories
$script:Directories = @(
    'bin', 'tools', 'brain', 'runtime',
    'vm', 'vm\base', 'vm\overlays', 'vm\cache',
    'projects', 'cache', 'logs', 'config'
)

function Write-Banner {
    if ($Quiet) { return }
    Write-Host ''
    Write-Host '  DRACULA — Open-Source Binary Intelligence Platform' -ForegroundColor Red
    Write-Host '  Installer & Workspace Configuration' -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Step { param([string]$Text) if (-not $Quiet) { Write-Host "  $Text" -ForegroundColor Gray } }
function Write-Ok   { param([string]$Text) if (-not $Quiet) { Write-Host "  + $Text" -ForegroundColor Green } }
function Write-Warn { param([string]$Text) if (-not $Quiet) { Write-Host "  ! $Text" -ForegroundColor Yellow } }

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N1} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} B' -f $Bytes)
}

function Get-InstallCandidates {
    $candidates = @()
    try {
        $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue
        foreach ($v in $volumes) {
            if (-not $v.FreeSpace) { continue }
            $letter = $v.DeviceID
            $target = Join-Path $letter 'Dracula'
            $desc   = ('{0} ({1} free)' -f $target, (Format-Size $v.FreeSpace))
            $candidates += [PSCustomObject]@{
                Path      = $target
                Drive     = $letter
                FreeBytes = [int64]$v.FreeSpace
                Display   = $desc
            }
        }
    } catch { }

    $localApp = Join-Path $env:LOCALAPPDATA 'Dracula'
    $candidates += [PSCustomObject]@{
        Path      = $localApp
        Drive     = $env:SystemDrive
        FreeBytes = [int64]0
        Display   = "$localApp (user-local fallback)"
    }
    return $candidates
}

function Resolve-PayloadSource {
    param([string]$Explicit)
    if ($Explicit -and (Test-Path $Explicit)) { return (Resolve-Path $Explicit).Path }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $candidates = @(
        $PSScriptRoot,
        (Join-Path $PSScriptRoot 'bin'),
        (Join-Path $repoRoot 'build'),
        (Join-Path $repoRoot 'build\bin'),
        (Join-Path $repoRoot 'build_verify'),
        (Join-Path $repoRoot 'bin')
    )
    foreach ($c in $candidates) {
        if ((Test-Path (Join-Path $c 'Dracula.exe')) -or (Test-Path (Join-Path $c 'drac.exe'))) {
            return $c
        }
    }
    return $null
}

function Install-Payload {
    param([string]$SourceDir, [string]$TargetRoot)

    Write-Step "Creating workspace hierarchy at '$TargetRoot'..."
    foreach ($d in $script:Directories) {
        $dirPath = Join-Path $TargetRoot $d
        if (-not (Test-Path $dirPath)) {
            [void](New-Item -ItemType Directory -Path $dirPath -Force)
        }
    }

    Write-Step "Installing executables and agents..."
    $copied = 0
    foreach ($item in $script:Payload) {
        $srcName = $item.Name
        $srcPath = Join-Path $SourceDir $srcName
        if (-not (Test-Path $srcPath) -and ($srcName -eq 'Dracula.exe')) {
            $srcPath = Join-Path $SourceDir 'drac.exe'
        }

        $dstPath = Join-Path $TargetRoot $item.Target
        $dstDir  = Split-Path $dstPath -Parent
        if (-not (Test-Path $dstDir)) {
            [void](New-Item -ItemType Directory -Path $dstDir -Force)
        }

        if (Test-Path $srcPath) {
            Copy-Item -Path $srcPath -Destination $dstPath -Force
            $copied++
        } elseif ($item.Required) {
            throw "Required payload file '$srcName' not found in '$SourceDir'."
        }
    }

    # Install shipped configs / rules if present
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $configSrc = Join-Path $repoRoot 'config'
    if (Test-Path $configSrc) {
        Copy-Item -Path "$configSrc\*" -Destination (Join-Path $TargetRoot 'config') -Recurse -Force -ErrorAction SilentlyContinue
    }
    $rulesSrc = Join-Path $repoRoot 'rules'
    if (Test-Path $rulesSrc) {
        Copy-Item -Path "$rulesSrc\*" -Destination (Join-Path $TargetRoot 'rules') -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Write root marker
    Set-Content -Path (Join-Path $TargetRoot '.dracula_root') -Value "Dracula Workspace Root`nv1.3.1" -Force

    Write-Ok "Installed $copied binary artifacts successfully."
}

function Update-UserPath {
    param([string]$BinPath)
    if ($NoPathUpdate) { return }

    try {
        $regKey = 'HKCU:\Environment'
        $currentPath = (Get-ItemProperty -Path $regKey -Name Path -ErrorAction SilentlyContinue).Path
        if (-not $currentPath) { $currentPath = '' }

        $segments = ($currentPath -split ';') | Where-Object { $_.Trim() -ne '' }
        if ($segments -notcontains $BinPath) {
            $newPath = ($segments + $BinPath) -join ';'
            Set-ItemProperty -Path $regKey -Name Path -Value $newPath
            Write-Ok "Added '$BinPath' to user PATH."
            $env:PATH = "$env:PATH;$BinPath"
        } else {
            Write-Ok "'$BinPath' is already in user PATH."
        }
    } catch {
        Write-Warn "Could not update user PATH environment: $_"
    }
}

function Remove-UserPath {
    param([string]$BinPath)
    try {
        $regKey = 'HKCU:\Environment'
        $currentPath = (Get-ItemProperty -Path $regKey -Name Path -ErrorAction SilentlyContinue).Path
        if ($currentPath) {
            $segments = ($currentPath -split ';') | Where-Object { $_.Trim() -ne '' -and $_.Trim() -ne $BinPath.Trim() }
            $newPath = $segments -join ';'
            Set-ItemProperty -Path $regKey -Name Path -Value $newPath
            Write-Ok "Removed '$BinPath' from user PATH."
        }
    } catch {
        Write-Warn "Could not update user PATH: $_"
    }
}

# --- Main execution ---
Write-Banner

if (-not $InstallRoot) {
    # Interactive disk selection or default
    $candidates = Get-InstallCandidates
    if ($candidates.Count -gt 0) {
        $InstallRoot = $candidates[0].Path
    } else {
        $InstallRoot = Join-Path $env:LOCALAPPDATA 'Dracula'
    }
}

if ($Mode -eq 'uninstall') {
    Write-Step "Uninstalling Dracula from '$InstallRoot'..."
    $binDir = Join-Path $InstallRoot 'bin'
    Remove-UserPath -BinPath $binDir

    # Remove bin, tools, runtime, vm/overlays but PRESERVE projects
    $itemsToRemove = @('bin', 'tools', 'runtime', 'vm\overlays', '.dracula_root')
    foreach ($item in $itemsToRemove) {
        $target = Join-Path $InstallRoot $item
        if (Test-Path $target) {
            Remove-Item -Path $target -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Ok "Dracula uninstalled. User analysis projects preserved in '$InstallRoot\projects'."
    exit 0
}

$sourceDir = Resolve-PayloadSource -Explicit $Source
if (-not $sourceDir) {
    throw "Could not locate Dracula build artifacts. Build the project or pass -Source <path>."
}

Install-Payload -SourceDir $sourceDir -TargetRoot $InstallRoot
Update-UserPath -BinPath (Join-Path $InstallRoot 'bin')

Write-Host ''
Write-Ok "Dracula installation complete!"
Write-Host "  Launch command: drac" -ForegroundColor Cyan
Write-Host "  Workspace:      $InstallRoot" -ForegroundColor DarkGray
Write-Host ''
