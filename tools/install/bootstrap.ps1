<#
    Dracula bootstrap.

    Usage:

        irm https://<host>/install.ps1 | iex

    This script is intentionally tiny. It fetches the Dracula release archive,
    unpacks it to a temporary directory, hands control to Install-Dracula.ps1,
    and removes everything it downloaded when it is done -- successfully or
    not (milestone section 3.11).

    Nothing here needs Administrator: the installer writes to a location the
    user chooses and updates the per-user PATH only.
#>

[CmdletBinding()]
param(
    # Override the release source. Useful for testing against a local build.
    [string]$ReleaseUrl,

    # Install without prompting, to this root.
    [string]$InstallRoot,

    # Install from an already-unpacked directory instead of downloading.
    [string]$FromDirectory,

    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$DefaultReleaseUrl = 'https://github.com/i87kxxz/dracula/releases/latest/download/dracula-windows-x64.zip'

function Write-Line {
    param([string]$Text, [string]$Color = 'Gray')
    if (-not $Quiet) { Write-Host "  $Text" -ForegroundColor $Color }
}

if (-not $Quiet) {
    Write-Host ''
    Write-Host '  DRACULA' -ForegroundColor Red
    Write-Host '  bootstrap' -ForegroundColor DarkGray
    Write-Host ''
}

# --- Environment checks -----------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'Dracula requires PowerShell 5.1 or newer.'
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Dracula requires 64-bit Windows.'
}

# Everything downloaded lives under one temp directory, so cleanup is a single
# recursive delete that runs even when the install throws.
$workspace = Join-Path ([System.IO.Path]::GetTempPath()) ("dracula-bootstrap-" + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $workspace -Force

try {
    $payloadDirectory = $null

    if ($FromDirectory) {
        if (-not (Test-Path $FromDirectory)) {
            throw "Source directory not found: $FromDirectory"
        }
        $payloadDirectory = (Resolve-Path $FromDirectory).Path
        Write-Line "Using local payload: $payloadDirectory"
    }
    else {
        $url = if ($ReleaseUrl) { $ReleaseUrl } else { $DefaultReleaseUrl }
        $archive = Join-Path $workspace 'dracula.zip'

        Write-Line "Downloading $url"

        # TLS 1.2 is not the default on older PowerShell hosts.
        try {
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch { }

        $progressPreferenceSaved = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'   # the bar makes IWR very slow
        try {
            Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
        } finally {
            $ProgressPreference = $progressPreferenceSaved
        }

        if (-not (Test-Path $archive)) { throw 'Download failed.' }
        Write-Line ("Downloaded {0:N1} MB" -f ((Get-Item $archive).Length / 1MB)) 'Green'

        $unpacked = Join-Path $workspace 'payload'
        Expand-Archive -Path $archive -DestinationPath $unpacked -Force
        Write-Line 'Archive unpacked' 'Green'

        # The archive may or may not have a single top-level directory.
        $payloadDirectory = $unpacked
        if (-not (Test-Path (Join-Path $payloadDirectory 'Dracula.exe'))) {
            $nested = Get-ChildItem -Path $unpacked -Directory |
                      Where-Object { Test-Path (Join-Path $_.FullName 'Dracula.exe') } |
                      Select-Object -First 1
            if ($nested) { $payloadDirectory = $nested.FullName }
        }
    }

    $installer = Join-Path $payloadDirectory 'Install-Dracula.ps1'
    if (-not (Test-Path $installer)) {
        # A source tree keeps the installer beside this script.
        $local = Join-Path (Split-Path -Parent $PSCommandPath) 'Install-Dracula.ps1'
        if (Test-Path $local) {
            $installer = $local
        } else {
            throw 'Install-Dracula.ps1 not found in the payload.'
        }
    }

    $arguments = @{ Source = $payloadDirectory }
    if ($InstallRoot) { $arguments['InstallRoot'] = $InstallRoot }
    if ($Quiet)       { $arguments['Quiet'] = $true }

    & $installer @arguments
}
finally {
    # Bootstrap temporary files are always cleaned up (section 3.11).
    if (Test-Path $workspace) {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
