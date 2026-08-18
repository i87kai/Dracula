[CmdletBinding()]
param(
    [string]$Version,
    [string]$BuildDir,
    [string]$OutputDir
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

$versionMatch = Select-String -LiteralPath (Join-Path $RepoRoot 'CMakeLists.txt') `
    -Pattern 'project\(Dracula VERSION ([0-9]+\.[0-9]+\.[0-9]+)' | Select-Object -First 1
if (-not $versionMatch) {
    throw 'Could not resolve the authoritative version from CMakeLists.txt.'
}
$sourceVersion = $versionMatch.Matches[0].Groups[1].Value
if (-not $Version) { $Version = $sourceVersion }
if ($Version -ne $sourceVersion) {
    throw "Package version '$Version' does not match authoritative version '$sourceVersion'."
}

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

# The installed command is drac. Avoid shipping a duplicate 70+ MB executable.
Copy-Item -Path $exeSource -Destination (Join-Path $stageDir (Join-Path 'bin' 'drac.exe')) -Force

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

$managedRuntimeFiles = @(
    'Dracula.ManagedHost.exe',
    'Dracula.ManagedHost.dll',
    'Dracula.ManagedHost.deps.json',
    'Dracula.ManagedHost.runtimeconfig.json'
)
foreach ($managedName in $managedRuntimeFiles) {
    $managedPath = Join-Path $BuildDir $managedName
    if (-not (Test-Path -LiteralPath $managedPath -PathType Leaf)) { continue }
    $item = Get-Item -LiteralPath $managedPath
    Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $stageDir (Join-Path 'bin' $item.Name)) -Force
    Write-Host ('      + bin\' + $item.Name) -ForegroundColor DarkGray
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
$scriptsToInclude = @('install.ps1', 'uninstall.ps1', 'update.ps1', 'apply-update.ps1', 'bootstrap.ps1')
foreach ($s in $scriptsToInclude) {
    $scriptSrc = Join-Path (Join-Path $RepoRoot 'scripts') $s
    if (Test-Path $scriptSrc) {
        Copy-Item -Path $scriptSrc -Destination (Join-Path (Join-Path $stageDir 'scripts') $s) -Force
        Write-Host ('      + scripts\' + $s) -ForegroundColor DarkGray
    }
}

# Copy documentation & root notices
$rootFiles = @('LICENSE', 'THIRD_PARTY_NOTICES.md', 'README.md', 'CHANGELOG.md', 'CHANGELOG.txt', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md')
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
