<#
.SYNOPSIS
    Dracula installer.

.DESCRIPTION
    Installs Dracula into a location the user chooses, creates the workspace
    hierarchy, and puts the global `drac` command on the user's PATH.

    Design constraints (milestone section 3):
      * terminal-only. No GUI installer.
      * arrow-key disk selection showing REAL free space.
      * per-user by default, so Administrator is not required.
      * re-running detects an existing install and offers Repair / Update /
        Change location / Cancel -- it never silently destroys projects.

.PARAMETER InstallRoot
    Install without prompting. Used by the bootstrap script's -Silent mode and
    by automated tests.

.PARAMETER Source
    Directory holding the built Dracula binaries. Defaults to the repository
    build output when running from a source tree.

.PARAMETER Mode
    install | repair | update | uninstall. Prompted for when omitted and an
    existing installation is found.

.PARAMETER NoPathUpdate
    Skip the PATH change (used by tests that must not touch the environment).
#>

[CmdletBinding()]
param(
    [string]$InstallRoot,
    [string]$Source,
    [ValidateSet('install', 'repair', 'update', 'uninstall')]
    [string]$Mode,
    [switch]$NoPathUpdate,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

# Everything Dracula needs at runtime. The workspace directories below are
# created empty; these are the files that must be copied.
$script:Payload = @(
    @{ Name = 'Dracula.exe';           Target = 'bin\drac.exe';               Required = $true  },
    @{ Name = 'libDraculaAgent64.dll'; Target = 'bin\libDraculaAgent64.dll';  Required = $false },
    @{ Name = 'DraculaAgent64.dll';    Target = 'bin\DraculaAgent64.dll';     Required = $false },
    @{ Name = 'GuestAgent.exe';        Target = 'bin\GuestAgent.exe';         Required = $false },
    @{ Name = 'InjectableDLL.dll';     Target = 'bin\InjectableDLL.dll';      Required = $false }
)

# The workspace hierarchy. "brain" is reserved for future higher-level
# analysis assets and is intentionally created empty.
$script:Directories = @(
    'bin', 'tools', 'brain', 'runtime',
    'vm', 'vm\base', 'vm\overlays', 'vm\cache',
    'projects', 'cache', 'logs', 'config'
)

function Write-Banner {
    if ($Quiet) { return }
    Write-Host ''
    Write-Host '  DRACULA' -ForegroundColor Red
    Write-Host '  Binary analysis workspace installer' -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Step {
    param([string]$Text)
    if ($Quiet) { return }
    Write-Host "  $Text" -ForegroundColor Gray
}

function Write-Ok {
    param([string]$Text)
    if ($Quiet) { return }
    Write-Host "  + $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    if ($Quiet) { return }
    Write-Host "  ! $Text" -ForegroundColor Yellow
}

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N1} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N1} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1} MB' -f ($Bytes / 1MB)) }
    return ('{0:N0} B' -f $Bytes)
}

# Fixed disks only, with their real free space. Network and removable drives
# are excluded: a Dracula workspace holding multi-gigabyte VM images has no
# business living on either.
function Get-InstallCandidates {
    $candidates = @()
    foreach ($volume in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3') {
        $candidates += [pscustomobject]@{
            Drive     = $volume.DeviceID
            FreeBytes = [double]$volume.FreeSpace
            SizeBytes = [double]$volume.Size
            Path      = Join-Path "$($volume.DeviceID)\" 'Dracula'
        }
    }
    return $candidates | Sort-Object -Property FreeBytes -Descending
}

# Arrow-key menu. Falls back to numeric entry when the host cannot read raw
# keys (a redirected or non-interactive console).
function Select-FromMenu {
    param(
        [string]$Title,
        [string[]]$Options,
        [string]$Footer
    )

    $canReadKeys = $true
    try { $null = [Console]::KeyAvailable } catch { $canReadKeys = $false }

    if (-not $canReadKeys -or [Console]::IsInputRedirected) {
        Write-Host ''
        Write-Host "  $Title" -ForegroundColor White
        for ($i = 0; $i -lt $Options.Count; $i++) {
            Write-Host ("    {0}) {1}" -f ($i + 1), $Options[$i])
        }
        if ($Footer) { Write-Host "    $Footer" -ForegroundColor DarkGray }
        $answer = Read-Host '  Selection'
        $index = 0
        if ([int]::TryParse($answer, [ref]$index) -and $index -ge 1 -and $index -le $Options.Count) {
            return $index - 1
        }
        return 0
    }

    $selected = 0
    $firstDraw = $true

    while ($true) {
        if (-not $firstDraw) {
            # Rewind over the block we drew last time.
            $lines = $Options.Count + 2
            if ($Footer) { $lines++ }
            for ($i = 0; $i -lt $lines; $i++) {
                [Console]::SetCursorPosition(0, [Console]::CursorTop - 1)
                Write-Host (' ' * ([Console]::WindowWidth - 1)) -NoNewline
                [Console]::SetCursorPosition(0, [Console]::CursorTop)
            }
        }
        $firstDraw = $false

        Write-Host ''
        Write-Host "  $Title" -ForegroundColor White
        for ($i = 0; $i -lt $Options.Count; $i++) {
            if ($i -eq $selected) {
                Write-Host ("  > {0}" -f $Options[$i]) -ForegroundColor Red
            } else {
                Write-Host ("    {0}" -f $Options[$i]) -ForegroundColor Gray
            }
        }
        if ($Footer) { Write-Host "  $Footer" -ForegroundColor DarkGray }

        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            'UpArrow'   { if ($selected -gt 0) { $selected-- } }
            'DownArrow' { if ($selected -lt $Options.Count - 1) { $selected++ } }
            'Enter'     { return $selected }
            'Escape'    { return -1 }
            default {
                # Numeric shortcuts.
                $char = $key.KeyChar
                if ($char -match '[1-9]') {
                    $index = [int]::Parse($char) - 1
                    if ($index -lt $Options.Count) { return $index }
                }
            }
        }
    }
}

function Test-WritableDirectory {
    param([string]$Path)
    try {
        $null = New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop
        $probe = Join-Path $Path ('.dracula_write_probe_{0}' -f ([guid]::NewGuid().ToString('N')))
        Set-Content -Path $probe -Value 'probe' -ErrorAction Stop
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Resolve-SourceDirectory {
    param([string]$Explicit)

    if ($Explicit) {
        if (-not (Test-Path $Explicit)) { throw "Source directory not found: $Explicit" }
        return (Resolve-Path $Explicit).Path
    }

    # Running from the repository: tools\install\ -> repo root -> build\
    $here = Split-Path -Parent $PSCommandPath
    foreach ($candidate in @(
        (Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'build'),
        $here,
        (Join-Path $here 'payload')
    )) {
        if (Test-Path (Join-Path $candidate 'Dracula.exe')) {
            return (Resolve-Path $candidate).Path
        }
    }

    throw 'Could not locate Dracula.exe. Pass -Source <directory>.'
}

function Get-ExistingInstall {
    # An install records its own root; that marker is the authoritative answer
    # to "is Dracula already installed, and where".
    $recorded = [Environment]::GetEnvironmentVariable('DRACULA_ROOT', 'User')
    if ($recorded -and (Test-Path (Join-Path $recorded 'bin\drac.exe'))) {
        return $recorded
    }
    return $null
}

function Install-Payload {
    param(
        [string]$Root,
        [string]$SourceDir
    )

    foreach ($directory in $script:Directories) {
        $null = New-Item -ItemType Directory -Path (Join-Path $Root $directory) -Force
    }
    Write-Ok "Workspace hierarchy created"

    $copied = 0
    foreach ($item in $script:Payload) {
        $from = Join-Path $SourceDir $item.Name
        $to   = Join-Path $Root $item.Target

        if (-not (Test-Path $from)) {
            if ($item.Required) { throw "Required file missing from source: $($item.Name)" }
            continue
        }

        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force
        Copy-Item -Path $from -Destination $to -Force
        $copied++
    }
    Write-Ok "$copied file(s) installed"

    # Ship the config and rules trees when they are alongside the source, so a
    # fresh install has working QEMU and detection configuration.
    $repoRoot = Split-Path -Parent $SourceDir
    foreach ($tree in @('config', 'rules')) {
        $from = Join-Path $repoRoot $tree
        if (Test-Path $from) {
            Copy-Item -Path $from -Destination $Root -Recurse -Force
            Write-Ok "$tree copied"
        }
    }

    # The install marker lets drac.exe find its own root even when the
    # environment variable is absent (a shell opened before installation).
    Set-Content -Path (Join-Path $Root 'bin\.dracula_root') -Value $Root -Encoding ASCII
}

function Update-UserPath {
    param([string]$BinDirectory)

    if ($NoPathUpdate) {
        Write-Warn 'PATH not modified (-NoPathUpdate)'
        return $false
    }

    # Per-user PATH only. Machine PATH would need Administrator and would
    # affect every account on the box for no benefit.
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -eq $current) { $current = '' }

    $entries = $current -split ';' | Where-Object { $_ -ne '' }
    if ($entries -contains $BinDirectory) {
        Write-Ok 'PATH already contains the Dracula bin directory'
        return $true
    }

    $updated = (($entries + $BinDirectory) -join ';')
    [Environment]::SetEnvironmentVariable('Path', $updated, 'User')

    # Make it work in THIS session too, not just new ones.
    $env:Path = "$env:Path;$BinDirectory"

    Write-Ok "PATH updated (per-user)"
    return $true
}

function Set-InstallRootVariable {
    param([string]$Root)
    [Environment]::SetEnvironmentVariable('DRACULA_ROOT', $Root, 'User')
    $env:DRACULA_ROOT = $Root
    Write-Ok "DRACULA_ROOT set to $Root"
}

function Invoke-Uninstall {
    param([string]$Root)

    Write-Host ''
    Write-Warn "This removes the Dracula program files in $Root"
    Write-Host '    Your projects will NOT be deleted.' -ForegroundColor DarkGray
    Write-Host ''

    foreach ($directory in @('bin', 'tools', 'runtime')) {
        $path = Join-Path $Root $directory
        if (Test-Path $path) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
    }

    $binDirectory = Join-Path $Root 'bin'
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($current) {
        $entries = $current -split ';' | Where-Object { $_ -ne '' -and $_ -ne $binDirectory }
        [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')
    }
    [Environment]::SetEnvironmentVariable('DRACULA_ROOT', $null, 'User')

    Write-Ok 'Dracula program files removed'
    Write-Host ''
    Write-Host "  Projects were kept in: $(Join-Path $Root 'projects')" -ForegroundColor DarkGray
    Write-Host '  Delete that directory yourself if you want them gone.' -ForegroundColor DarkGray
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Banner

$sourceDirectory = Resolve-SourceDirectory -Explicit $Source
Write-Step "Source: $sourceDirectory"

$existing = Get-ExistingInstall

if ($existing -and -not $Mode -and -not $InstallRoot) {
    # Re-running the installer must never silently overwrite.
    $choice = Select-FromMenu `
        -Title "Dracula is already installed at $existing" `
        -Options @(
            'Repair       reinstall program files, keep everything else',
            'Update       reinstall program files (same as repair here)',
            'Change location  install to a different drive',
            'Uninstall    remove program files, keep projects',
            'Cancel'
        ) `
        -Footer 'Up/Down then Enter, or Esc to cancel'

    switch ($choice) {
        0 { $Mode = 'repair';  $InstallRoot = $existing }
        1 { $Mode = 'update';  $InstallRoot = $existing }
        2 { $Mode = 'install' }
        3 { $Mode = 'uninstall'; $InstallRoot = $existing }
        default {
            Write-Host ''
            Write-Host '  Cancelled.' -ForegroundColor DarkGray
            Write-Host ''
            exit 0
        }
    }
}

if (-not $Mode) { $Mode = 'install' }

if ($Mode -eq 'uninstall') {
    if (-not $InstallRoot) { $InstallRoot = $existing }
    if (-not $InstallRoot) { throw 'No Dracula installation found to uninstall.' }
    Invoke-Uninstall -Root $InstallRoot
    exit 0
}

# --- Choose where to install ----------------------------------------------
if (-not $InstallRoot) {
    $candidates = Get-InstallCandidates
    if (-not $candidates) { throw 'No fixed disks found.' }

    $options = @()
    foreach ($candidate in $candidates) {
        $options += ('{0}\   {1} free of {2}' -f `
            $candidate.Drive, (Format-Size $candidate.FreeBytes), (Format-Size $candidate.SizeBytes))
    }
    $options += 'Enter a path manually'

    $choice = Select-FromMenu `
        -Title 'Where should Dracula be installed?' `
        -Options $options `
        -Footer 'Up/Down then Enter, or Esc to cancel'

    if ($choice -lt 0) {
        Write-Host ''
        Write-Host '  Cancelled.' -ForegroundColor DarkGray
        Write-Host ''
        exit 0
    }

    if ($choice -eq $candidates.Count) {
        $manual = Read-Host '  Installation path'
        if (-not $manual) { throw 'No path entered.' }
        $InstallRoot = $manual
    } else {
        $InstallRoot = $candidates[$choice].Path
    }
}

Write-Host ''
Write-Step "Installing to: $InstallRoot"

# --- Validate the destination ---------------------------------------------
# Dracula's workspace holds VM images and memory snapshots, so a few hundred
# megabytes is the practical floor before anything useful can be done.
$requiredBytes = 512MB
$targetDrive = [System.IO.Path]::GetPathRoot($InstallRoot)
if ($targetDrive) {
    $volume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = '$($targetDrive.TrimEnd('\'))'" -ErrorAction SilentlyContinue
    if ($volume -and $volume.FreeSpace -lt $requiredBytes) {
        throw ("Not enough free space on {0}: {1} available, {2} required." -f `
               $targetDrive, (Format-Size $volume.FreeSpace), (Format-Size $requiredBytes))
    }
}

if (-not (Test-WritableDirectory -Path $InstallRoot)) {
    throw "Cannot write to $InstallRoot. Choose a different location, or run as Administrator."
}
Write-Ok 'Destination is writable and has enough space'

# --- Install ---------------------------------------------------------------
Install-Payload -Root $InstallRoot -SourceDir $sourceDirectory
Set-InstallRootVariable -Root $InstallRoot
$pathUpdated = Update-UserPath -BinDirectory (Join-Path $InstallRoot 'bin')

# --- Verify ----------------------------------------------------------------
$dracPath = Join-Path $InstallRoot 'bin\drac.exe'
if (-not (Test-Path $dracPath)) { throw 'Installation failed: drac.exe is missing.' }

Write-Host ''
Write-Host '  Dracula installed.' -ForegroundColor Green
Write-Host ''
Write-Host "    Root      $InstallRoot" -ForegroundColor Gray
Write-Host "    Command   drac" -ForegroundColor Gray
Write-Host "    Projects  $(Join-Path $InstallRoot 'projects')" -ForegroundColor Gray
Write-Host ''
if ($pathUpdated) {
    Write-Host '  Open a NEW terminal and run:' -ForegroundColor DarkGray
    Write-Host '    drac' -ForegroundColor Red
} else {
    Write-Host '  Run it with:' -ForegroundColor DarkGray
    Write-Host "    $dracPath" -ForegroundColor Red
}
Write-Host ''
