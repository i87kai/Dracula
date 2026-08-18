<#
.SYNOPSIS
    Checks for and transactionally installs a Dracula release.
#>

[CmdletBinding()]
param(
    [string]$InstallRoot,
    [ValidateSet('stable', 'prerelease')]
    [string]$Channel = 'stable',
    [string]$ReleasesApiUrl = 'https://api.github.com/repos/i87kai/Dracula/releases',
    [string]$ReleaseMetadataPath,
    [switch]$Force,
    [switch]$Quiet,
    [switch]$NoRestart
)

$ErrorActionPreference = 'Stop'
$Repo = 'i87kai/Dracula'

function Write-Step { param([string]$Text) if (-not $Quiet) { Write-Host "  $Text" -ForegroundColor Gray } }
function Write-Ok   { param([string]$Text) if (-not $Quiet) { Write-Host "  + $Text" -ForegroundColor Green } }

if (-not $InstallRoot) {
    if ($env:DRACULA_ROOT -and (Test-Path -LiteralPath $env:DRACULA_ROOT)) {
        $InstallRoot = $env:DRACULA_ROOT
    } else {
        $InstallRoot = Join-Path $env:LOCALAPPDATA 'Dracula'
    }
}
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
if (-not (Test-Path -LiteralPath (Join-Path $InstallRoot '.dracula_root') -PathType Leaf)) {
    throw "No Dracula installation was found at '$InstallRoot'."
}

$headers = @{
    'User-Agent' = 'Dracula-PowerShell-Updater'
    'Accept'     = 'application/vnd.github+json'
}
Write-Step 'Checking GitHub Releases...'
if ($ReleaseMetadataPath) {
    $releases = Get-Content -LiteralPath $ReleaseMetadataPath -Raw | ConvertFrom-Json
} else {
    $releases = Invoke-RestMethod -Uri $ReleasesApiUrl -Headers $headers -UseBasicParsing
}
$release = $releases | Where-Object { -not $_.draft -and ($Channel -eq 'prerelease' -or -not $_.prerelease) } | Select-Object -First 1
if (-not $release -or $release.tag_name -notmatch '^v([0-9]+\.[0-9]+\.[0-9]+)$') {
    throw "No suitable release was found on the '$Channel' channel."
}
$version = $Matches[1]

$installedExe = Join-Path $InstallRoot 'bin\drac.exe'
$currentText = if (Test-Path -LiteralPath $installedExe) { (& $installedExe --version 2>&1 | Out-String) } else { '' }
$currentVersion = '0.0.0'
if ($currentText -match 'v([0-9]+\.[0-9]+\.[0-9]+)') { $currentVersion = $Matches[1] }
if (-not $Force -and ([version]$version -le [version]$currentVersion)) {
    Write-Ok "Dracula is already up to date (v$currentVersion)."
    exit 0
}

$zipAsset = $release.assets | Where-Object { $_.name -eq "Dracula-v$version-windows-x64.zip" } | Select-Object -First 1
$shaAsset = $release.assets | Where-Object { $_.name -eq "Dracula-v$version-windows-x64.zip.sha256" } | Select-Object -First 1
if (-not $zipAsset -or -not $shaAsset) {
    throw "Release v$version is missing its Windows x64 ZIP or SHA-256 sidecar."
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('dracula-update-' + [guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $tempDir -Force)
try {
    $zipPath = Join-Path $tempDir $zipAsset.name
    $shaPath = "$zipPath.sha256"
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
        Invoke-WebRequest -Uri $shaAsset.browser_download_url -OutFile $shaPath -UseBasicParsing
    } finally { $ProgressPreference = $oldProgress }

    $expected = ((Get-Content -LiteralPath $shaPath -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    $computed = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$' -or $expected -ne $computed) {
        throw "SHA-256 verification failed. Expected $expected; computed $computed."
    }

    $stage = Join-Path $tempDir 'stage'
    Expand-Archive -LiteralPath $zipPath -DestinationPath $stage -Force
    $helper = Join-Path $stage 'scripts\apply-update.ps1'
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
        throw 'The verified release is missing scripts\apply-update.ps1.'
    }

    $helperArgs = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $helper,
        '-InstallRoot', $InstallRoot,
        '-StageRoot', $stage,
        '-ExpectedVersion', $version
    )
    if ($NoRestart) { $helperArgs += '-NoRestart' }
    & (Join-Path $PSHOME 'powershell.exe') @helperArgs
    if ($LASTEXITCODE -ne 0) { throw "Transactional updater exited with code $LASTEXITCODE." }
    Write-Ok "Updated Dracula from v$currentVersion to v$version."
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
