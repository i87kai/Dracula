[CmdletBinding()]
param(
    [string]$Version = '1.3.1',
    [string]$BuildDir,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if (-not $BuildDir) {
    $BuildDir = Join-Path $RepoRoot 'build'
}
if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot 'dist'
}

Write-Host ''
Write-Host ('  DRACULA RELEASE PACKAGING — v' + $Version) -ForegroundColor Red
Write-Host ('  Repo Root: ' + $RepoRoot) -ForegroundColor DarkGray
Write-Host ('  Build Dir: ' + $BuildDir) -ForegroundColor DarkGray
Write-Host ('  Output:    ' + $OutputDir) -ForegroundColor DarkGray
Write-Host ''

# Verify primary binary
$exeSource = Join-Path $BuildDir 'Dracula.exe'
if (-not (Test-Path $exeSource)) {
    $exeSource = Join-Path $BuildDir (Join-Path 'bin' 'Dracula.exe')
}
if (-not (Test-Path $exeSource)) {
    throw ('Dracula.exe not found in ' + $BuildDir + '. Run cmake --build build first.')
}

[void](New-Item -ItemType Directory -Path $OutputDir -Force)

$stageFolderName = 'Dracula-v' + $Version + '-windows-x64'
$stageDir = Join-Path $OutputDir $stageFolderName
if (Test-Path $stageDir) {
    Remove-Item -Path $stageDir -Recurse -Force
}
[void](New-Item -ItemType Directory -Path $stageDir -Force)
[void](New-Item -ItemType Directory -Path (Join-Path $stageDir 'bin') -Force)
[void](New-Item -ItemType Directory -Path (Join-Path $stageDir 'config') -Force)
[void](New-Item -ItemType Directory -Path (Join-Path $stageDir 'rules') -Force)
[void](New-Item -ItemType Directory -Path (Join-Path $stageDir 'scripts') -Force)
[void](New-Item -ItemType Directory -Path (Join-Path $stageDir 'docs') -Force)

Write-Host '  [+] Staging release binaries...' -ForegroundColor Cyan

# Copy main binary as both drac.exe and Dracula.exe
Copy-Item -Path $exeSource -Destination (Join-Path $stageDir (Join-Path 'bin' 'drac.exe')) -Force
Copy-Item -Path $exeSource -Destination (Join-Path $stageDir (Join-Path 'bin' 'Dracula.exe')) -Force

# Optional DLLs and agents
$optionalBinaries = @(
    'libDraculaAgent64.dll',
    'DraculaAgent64.dll',
    'GuestAgent.exe',
    'InjectableDLL.dll'
)
foreach ($bin in $optionalBinaries) {
    $src = Join-Path $BuildDir $bin
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $stageDir (Join-Path 'bin' $bin)) -Force
        Write-Host ('      + bin\' + $bin) -ForegroundColor DarkGray
    }
}

# Copy configs and rules
$configSrc = Join-Path $RepoRoot 'config'
if (Test-Path $configSrc) {
    Copy-Item -Path (Join-Path $configSrc '*') -Destination (Join-Path $stageDir 'config') -Recurse -Force -ErrorAction SilentlyContinue
}
$rulesSrc = Join-Path $RepoRoot 'rules'
if (Test-Path $rulesSrc) {
    Copy-Item -Path (Join-Path $rulesSrc '*') -Destination (Join-Path $stageDir 'rules') -Recurse -Force -ErrorAction SilentlyContinue
}

# Copy scripts
$scriptsToInclude = @('install.ps1', 'uninstall.ps1', 'update.ps1', 'bootstrap.ps1')
foreach ($s in $scriptsToInclude) {
    $scriptSrc = Join-Path (Join-Path $RepoRoot 'scripts') $s
    if (Test-Path $scriptSrc) {
        Copy-Item -Path $scriptSrc -Destination (Join-Path (Join-Path $stageDir 'scripts') $s) -Force
        Write-Host ('      + scripts\' + $s) -ForegroundColor DarkGray
    }
}

# Copy documentation & root notices
$rootFiles = @('LICENSE', 'THIRD_PARTY_NOTICES.md', 'README.md', 'CHANGELOG.txt', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md')
foreach ($rf in $rootFiles) {
    $src = Join-Path $RepoRoot $rf
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $stageDir $rf) -Force
    }
}

# Copy docs
$docsSrc = Join-Path $RepoRoot 'docs'
if (Test-Path $docsSrc) {
    Copy-Item -Path (Join-Path $docsSrc '*') -Destination (Join-Path $stageDir 'docs') -Recurse -Force -ErrorAction SilentlyContinue
}

# Write install marker
$markerFile = Join-Path $stageDir '.dracula_root'
Set-Content -Path $markerFile -Value @('Dracula Workspace Root', ('v' + $Version)) -Force

# Create Zip Archive
$zipName = 'Dracula-v' + $Version + '-windows-x64.zip'
$zipPath = Join-Path $OutputDir $zipName
if (Test-Path $zipPath) {
    Remove-Item -Path $zipPath -Force
}

Write-Host ('  [+] Compressing archive to ' + $zipName + '...') -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $stageDir '*') -DestinationPath $zipPath -CompressionLevel Optimal

# Compute SHA-256
$hash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$shaFile = $zipPath + '.sha256'
Set-Content -Path $shaFile -Value ($hash + '  ' + $zipName) -Force

$zipBytes = (Get-Item $zipPath).Length
$zipSizeMb = [math]::Round(($zipBytes / 1MB), 2)

Write-Host ''
Write-Host '  [OK] Release package created successfully!' -ForegroundColor Green
Write-Host ('  Archive: ' + $zipPath + ' (' + $zipSizeMb + ' MB)')
Write-Host ('  SHA-256: ' + $hash) -ForegroundColor Yellow
Write-Host ('  Digest:  ' + $shaFile)
Write-Host ''
