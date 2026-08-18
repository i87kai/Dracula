<#
.SYNOPSIS
    Installs or repairs Dracula for the current Windows user.

.DESCRIPTION
    Copies release components into a selected installation root, creates the
    durable workspace hierarchy, and adds bin\ to the per-user PATH. Repair
    restores missing program files while preserving projects, configuration,
    VM data, reports, and logs.
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

$script:Payload = @(
    @{ Name = 'Dracula.exe';           Target = 'bin\drac.exe';              Required = $true  },
    @{ Name = 'libDraculaAgent64.dll'; Target = 'bin\libDraculaAgent64.dll'; Required = $false },
    @{ Name = 'DraculaAgent64.dll';    Target = 'bin\DraculaAgent64.dll';    Required = $false },
    @{ Name = 'GuestAgent.exe';        Target = 'bin\GuestAgent.exe';        Required = $false },
    @{ Name = 'InjectableDLL.dll';     Target = 'bin\InjectableDLL.dll';     Required = $false },
    @{ Name = 'Dracula.ManagedHost.exe'; Target = 'bin\Dracula.ManagedHost.exe'; Required = $false },
    @{ Name = 'Dracula.ManagedHost.dll'; Target = 'bin\Dracula.ManagedHost.dll'; Required = $false },
    @{ Name = 'Dracula.ManagedHost.deps.json'; Target = 'bin\Dracula.ManagedHost.deps.json'; Required = $false },
    @{ Name = 'Dracula.ManagedHost.runtimeconfig.json'; Target = 'bin\Dracula.ManagedHost.runtimeconfig.json'; Required = $false }
)

$script:Directories = @(
    'bin', 'tools', 'brain', 'brain\skills', 'runtime', 'scripts', 'docs', 'rules',
    'vm', 'vm\base', 'vm\overlays', 'vm\cache',
    'projects', 'cache', 'logs', 'config'
)

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

function Get-FreeBytes {
    param([string]$Path)
    try {
        $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Path))
        return [int64]([System.IO.DriveInfo]::new($root).AvailableFreeSpace)
    } catch { return [int64]0 }
}

function Get-InstallCandidates {
    $items = @()
    $localPath = Join-Path $env:LOCALAPPDATA 'Dracula'
    $localFree = Get-FreeBytes $localPath
    $items += [PSCustomObject]@{
        Path = $localPath
        Display = "$localPath ($(Format-Size $localFree) free, no Administrator required)"
    }

    try {
        $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction SilentlyContinue
        foreach ($volume in $volumes) {
            if ($volume.FreeSpace -eq $null) { continue }
            $path = Join-Path $volume.DeviceID 'Dracula'
            if ($path -eq $localPath) { continue }
            $items += [PSCustomObject]@{
                Path = $path
                Display = "$path ($(Format-Size ([int64]$volume.FreeSpace)) free)"
            }
        }
    } catch { }
    return $items
}

function Select-InstallRoot {
    $candidates = @(Get-InstallCandidates)
    if ($Quiet -or $candidates.Count -eq 0) {
        return $(if ($candidates.Count -gt 0) { $candidates[0].Path } else { Join-Path $env:LOCALAPPDATA 'Dracula' })
    }

    Write-Host ''
    Write-Host '  Choose an installation location:' -ForegroundColor White
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        Write-Host ("    [{0}] {1}" -f ($i + 1), $candidates[$i].Display) -ForegroundColor Gray
    }
    Write-Host '    [C] Custom path' -ForegroundColor Gray
    $choice = Read-Host '  Selection [1]'
    if ([string]::IsNullOrWhiteSpace($choice)) { return $candidates[0].Path }
    if ($choice -match '^[Cc]$') {
        $custom = Read-Host '  Installation path'
        if ([string]::IsNullOrWhiteSpace($custom)) { throw 'An installation path is required.' }
        return $custom
    }
    $index = 0
    if ([int]::TryParse($choice, [ref]$index) -and $index -ge 1 -and $index -le $candidates.Count) {
        return $candidates[$index - 1].Path
    }
    throw "Invalid installation selection '$choice'."
}

function Resolve-PayloadSource {
    param([string]$Explicit)
    if ($Explicit -and (Test-Path -LiteralPath $Explicit -PathType Container)) {
        return (Resolve-Path -LiteralPath $Explicit).Path
    }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    foreach ($candidate in @($PSScriptRoot, (Join-Path $repoRoot 'build'), (Join-Path $repoRoot 'build\bin'))) {
        if ((Test-Path -LiteralPath (Join-Path $candidate 'Dracula.exe')) -or
            (Test-Path -LiteralPath (Join-Path $candidate 'drac.exe'))) {
            return $candidate
        }
    }
    return $null
}

function Copy-DirectoryContents {
    param([string]$SourceDir, [string]$TargetDir, [switch]$PreserveExisting)
    if (-not (Test-Path -LiteralPath $SourceDir -PathType Container)) { return }
    [void](New-Item -ItemType Directory -Path $TargetDir -Force)
    Get-ChildItem -LiteralPath $SourceDir -Recurse -File | ForEach-Object {
        $relative = $_.FullName.Substring($SourceDir.Length).TrimStart('\')
        $destination = Join-Path $TargetDir $relative
        [void](New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force)
        if (-not $PreserveExisting -or -not (Test-Path -LiteralPath $destination)) {
            Copy-Item -LiteralPath $_.FullName -Destination $destination -Force
        }
    }
}

function Get-PayloadVersion {
    param([string]$PackageRoot)
    $marker = Join-Path $PackageRoot '.dracula_root'
    if (Test-Path -LiteralPath $marker -PathType Leaf) {
        $match = Select-String -LiteralPath $marker -Pattern '^v([0-9]+\.[0-9]+\.[0-9]+)$' | Select-Object -First 1
        if ($match) { return $match.Matches[0].Groups[1].Value }
    }
    $cmake = Join-Path $PackageRoot 'CMakeLists.txt'
    if (Test-Path -LiteralPath $cmake -PathType Leaf) {
        $match = Select-String -LiteralPath $cmake -Pattern 'project\(Dracula VERSION ([0-9]+\.[0-9]+\.[0-9]+)' | Select-Object -First 1
        if ($match) { return $match.Matches[0].Groups[1].Value }
    }
    return 'unknown'
}

function Install-Payload {
    param([string]$SourceDir, [string]$TargetRoot)
    foreach ($directory in $script:Directories) {
        [void](New-Item -ItemType Directory -Path (Join-Path $TargetRoot $directory) -Force)
    }

    $copied = 0
    foreach ($item in $script:Payload) {
        $sourcePath = Join-Path $SourceDir $item.Name
        if (-not (Test-Path -LiteralPath $sourcePath) -and $item.Name -eq 'Dracula.exe') {
            $sourcePath = Join-Path $SourceDir 'drac.exe'
        }
        $destination = Join-Path $TargetRoot $item.Target
        if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
            Copy-Item -LiteralPath $sourcePath -Destination $destination -Force
            $copied++
        } elseif ($item.Required) {
            throw "Required payload '$($item.Name)' was not found in '$SourceDir'."
        }
    }

    $packageRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Copy-DirectoryContents (Join-Path $packageRoot 'config') (Join-Path $TargetRoot 'config') -PreserveExisting
    foreach ($name in @('rules', 'scripts', 'docs')) {
        Copy-DirectoryContents (Join-Path $packageRoot $name) (Join-Path $TargetRoot $name)
    }
    foreach ($name in @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md')) {
        $sourcePath = Join-Path $packageRoot $name
        if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
            Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $TargetRoot $name) -Force
        }
    }

    $version = Get-PayloadVersion $packageRoot
    Set-Content -LiteralPath (Join-Path $TargetRoot '.dracula_root') -Value @('Dracula Workspace Root', "v$version") -Encoding ASCII
    Write-Ok "Installed $copied binary components (v$version)."
}

function Update-UserPath {
    param([string]$BinPath)
    if ($NoPathUpdate) { return }
    try {
        $registryKey = 'HKCU:\Environment'
        $current = (Get-ItemProperty -Path $registryKey -Name Path -ErrorAction SilentlyContinue).Path
        $segments = @($current -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($segments -notcontains $BinPath) {
            Set-ItemProperty -Path $registryKey -Name Path -Value (($segments + $BinPath) -join ';')
            $env:PATH = "$env:PATH;$BinPath"
            Write-Ok "Added '$BinPath' to the per-user PATH."
        }
    } catch { Write-Warn "Could not update the per-user PATH: $_" }
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host '  DRACULA' -ForegroundColor Red
    Write-Host '  Installer and Workspace Configuration' -ForegroundColor DarkGray
}

if (-not $InstallRoot) { $InstallRoot = Select-InstallRoot }
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)

if ($Mode -eq 'uninstall') {
    & (Join-Path $PSScriptRoot 'uninstall.ps1') -InstallRoot $InstallRoot -Quiet:$Quiet
    exit $LASTEXITCODE
}

$sourceDir = Resolve-PayloadSource $Source
if (-not $sourceDir) {
    throw 'Could not locate Dracula build artifacts. Build the project or pass -Source <path>.'
}

Write-Step "Installing Dracula to '$InstallRoot'..."
Install-Payload -SourceDir $sourceDir -TargetRoot $InstallRoot
Update-UserPath (Join-Path $InstallRoot 'bin')

Write-Ok "Dracula $Mode complete."
if (-not $Quiet) {
    Write-Host '  Open a fresh terminal and run: drac' -ForegroundColor Cyan
    Write-Host "  Workspace: $InstallRoot" -ForegroundColor DarkGray
    Write-Host ''
}
