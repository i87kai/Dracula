<#
.SYNOPSIS
    Dracula web bootstrap installer.

.DESCRIPTION
    Resolves the latest public Windows x64 release, downloads both the archive
    and its required SHA-256 sidecar, verifies the package, and runs the
    packaged installer. No Administrator privileges are required for the
    default per-user destination.
#>

[CmdletBinding()]
param(
    [string]$ReleaseUrl,
    [string]$InstallRoot,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$Repo = 'i87kai/Dracula'

function Write-Step { param([string]$Text) if (-not $Quiet) { Write-Host "  $Text" -ForegroundColor Gray } }
function Write-Ok   { param([string]$Text) if (-not $Quiet) { Write-Host "  + $Text" -ForegroundColor Green } }

if (-not $Quiet) {
    Write-Host ''
    Write-Host '  DRACULA' -ForegroundColor Red
    Write-Host '  Web Bootstrap Installer' -ForegroundColor DarkGray
    Write-Host ''
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw 'Dracula bootstrap requires PowerShell 5.1 or newer.'
}
if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'Dracula requires a 64-bit Windows operating system.'
}

try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$headers = @{
    'User-Agent' = 'Dracula-Bootstrap'
    'Accept'     = 'application/vnd.github+json'
}

if ($ReleaseUrl) {
    $zipUrl = $ReleaseUrl
    $shaUrl = "$ReleaseUrl.sha256"
} else {
    Write-Step 'Resolving the latest Dracula release from GitHub...'
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers -UseBasicParsing
    $zipAsset = $release.assets | Where-Object { $_.name -match '^Dracula-v[0-9]+\.[0-9]+\.[0-9]+-windows-x64\.zip$' } | Select-Object -First 1
    $shaAsset = $release.assets | Where-Object { $_.name -eq ($zipAsset.name + '.sha256') } | Select-Object -First 1
    if (-not $zipAsset -or -not $shaAsset) {
        throw "The latest release does not contain the required Windows x64 ZIP and SHA-256 assets."
    }
    $zipUrl = $zipAsset.browser_download_url
    $shaUrl = $shaAsset.browser_download_url
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('dracula-bootstrap-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $tempDir -Force)

try {
    $zipFile = Join-Path $tempDir 'dracula-release.zip'
    $shaFile = Join-Path $tempDir 'dracula-release.zip.sha256'
    $previousProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Write-Step "Downloading $zipUrl..."
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile -UseBasicParsing
        Write-Step "Downloading $shaUrl..."
        Invoke-WebRequest -Uri $shaUrl -OutFile $shaFile -UseBasicParsing
    } finally {
        $ProgressPreference = $previousProgress
    }

    if (-not (Test-Path -LiteralPath $zipFile -PathType Leaf) -or
        -not (Test-Path -LiteralPath $shaFile -PathType Leaf)) {
        throw 'Release archive or SHA-256 sidecar download failed.'
    }

    $expectedSha = ((Get-Content -LiteralPath $shaFile -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    if ($expectedSha -notmatch '^[0-9a-f]{64}$') {
        throw 'The release SHA-256 sidecar is missing or malformed.'
    }
    $computedSha = (Get-FileHash -LiteralPath $zipFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expectedSha -ne $computedSha) {
        throw "SHA-256 verification failed. Expected $expectedSha; computed $computedSha."
    }
    Write-Ok "Verified SHA-256 $computedSha"

    $stageDir = Join-Path $tempDir 'stage'
    Expand-Archive -LiteralPath $zipFile -DestinationPath $stageDir -Force

    $installScript = Join-Path $stageDir 'scripts\install.ps1'
    $payloadBinDir = Join-Path $stageDir 'bin'
    if (-not (Test-Path -LiteralPath $installScript -PathType Leaf)) {
        throw 'The verified release is missing scripts\install.ps1.'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $payloadBinDir 'drac.exe') -PathType Leaf)) {
        throw 'The verified release is missing bin\drac.exe.'
    }

    $installParams = @{ Source = $payloadBinDir }
    if ($InstallRoot) { $installParams.InstallRoot = $InstallRoot }
    if ($Quiet) { $installParams.Quiet = $true }
    & $installScript @installParams
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
