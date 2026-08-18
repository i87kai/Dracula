<#
.SYNOPSIS
    Dracula Web Bootstrap Installer.

.DESCRIPTION
    One-line web installation script:
        irm https://raw.githubusercontent.com/i87kxxz/Dracula/main/scripts/bootstrap.ps1 | iex

    Downloads the verified Dracula release package from GitHub Releases,
    verifies SHA-256 integrity, unpacks, and launches install.ps1.

.PARAMETER ReleaseUrl
    Direct download URL of the release .zip archive (optional override).
.PARAMETER InstallRoot
    Explicit target installation path.
.PARAMETER Quiet
    Suppress banner and non-essential progress lines.
#>

[CmdletBinding()]
param(
    [string]$ReleaseUrl,
    [string]$InstallRoot,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$Repo = 'i87kxxz/Dracula'
$DefaultReleaseZipUrl = "https://github.com/$Repo/releases/latest/download/Dracula-v1.3.1-windows-x64.zip"
$DefaultSha256Url    = "https://github.com/$Repo/releases/latest/download/Dracula-v1.3.1-windows-x64.zip.sha256"

function Write-Step { param([string]$Text) if (-not $Quiet) { Write-Host "  $Text" -ForegroundColor Gray } }
function Write-Ok   { param([string]$Text) if (-not $Quiet) { Write-Host "  + $Text" -ForegroundColor Green } }
function Write-Warn { param([string]$Text) if (-not $Quiet) { Write-Host "  ! $Text" -ForegroundColor Yellow } }

if (-not $Quiet) {
    Write-Host ''
    Write-Host '  DRACULA' -ForegroundColor Red
    Write-Host '  Web Bootstrap Installer' -ForegroundColor DarkGray
    Write-Host ''
}

# Prerequisites
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'Dracula bootstrap requires PowerShell 5.1 or newer.'
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Dracula requires a 64-bit Windows operating system.'
}

# Enable TLS 1.2
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dracula-bootstrap-" + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $tempDir -Force)

try {
    $zipUrl = if ($ReleaseUrl) { $ReleaseUrl } else { $DefaultReleaseZipUrl }
    $shaUrl = if ($ReleaseUrl) { "$ReleaseUrl.sha256" } else { $DefaultSha256Url }

    $zipFile = Join-Path $tempDir 'dracula-release.zip'
    $shaFile = Join-Path $tempDir 'dracula-release.zip.sha256'

    Write-Step "Downloading release package from $zipUrl..."
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
    } finally {
        $ProgressPreference = $prevProgress
    }

    if (-not (Test-Path $zipFile)) {
        throw "Failed to download release archive from $zipUrl"
    }

    $sizeMb = (Get-Item $zipFile).Length / 1MB
    Write-Ok ("Downloaded release package ({0:N2} MB)" -f $sizeMb)

    # Checksum verification
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $shaUrl -OutFile $shaFile -UseBasicParsing -ErrorAction SilentlyContinue
    } catch { }
    finally {
        $ProgressPreference = $prevProgress
    }

    if (Test-Path $shaFile) {
        Write-Step "Verifying package SHA-256 signature..."
        $expectedSha = ((Get-Content $shaFile -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
        $computedSha = (Get-FileHash -Path $zipFile -Algorithm SHA256).Hash.ToLowerInvariant()

        if ($expectedSha -and ($expectedSha -ne $computedSha)) {
            throw "SHA-256 signature verification failed!`nExpected: $expectedSha`nComputed: $computedSha"
        }
        Write-Ok "SHA-256 signature verified ($computedSha)"
    }

    Write-Step "Unpacking payload..."
    $stageDir = Join-Path $tempDir 'stage'
    Expand-Archive -Path $zipFile -DestinationPath $stageDir -Force
    Write-Ok "Payload unpacked."

    # Locate install script inside stage
    $installScript = Join-Path $stageDir 'scripts\install.ps1'
    if (-not (Test-Path $installScript)) {
        $found = Get-ChildItem -Path $stageDir -Filter 'install.ps1' -Recurse | Select-Object -First 1
        if ($found) { $installScript = $found.FullName }
    }

    $payloadBinDir = $stageDir
    $foundExe = Get-ChildItem -Path $stageDir -Filter 'drac.exe' -Recurse | Select-Object -First 1
    if (-not $foundExe) {
        $foundExe = Get-ChildItem -Path $stageDir -Filter 'Dracula.exe' -Recurse | Select-Object -First 1
    }
    if ($foundExe) {
        $payloadBinDir = $foundExe.DirectoryName
    }

    if (Test-Path $installScript) {
        $params = @{
            Source = $payloadBinDir
        }
        if ($InstallRoot) { $params['InstallRoot'] = $InstallRoot }
        if ($Quiet) { $params['Quiet'] = $true }

        & $installScript @params
    } else {
        # Fallback inline installer if script missing
        $targetRoot = if ($InstallRoot) { $InstallRoot } else { Join-Path $env:LOCALAPPDATA 'Dracula' }
        $binTarget = Join-Path $targetRoot 'bin'
        [void](New-Item -ItemType Directory -Path $binTarget -Force)
        Copy-Item -Path "$payloadBinDir\*" -Destination $binTarget -Recurse -Force
        Set-Content -Path (Join-Path $targetRoot '.dracula_root') -Value "Dracula Workspace Root`nv1.3.1" -Force
        Write-Ok "Dracula installed to $targetRoot"
    }

} finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
