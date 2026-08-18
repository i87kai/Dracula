[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,
    [Parameter(Mandatory = $true)]
    [string]$BuildDir,
    [string]$ExpectedVersion = '1.3.3'
)

$ErrorActionPreference = 'Stop'
$script:Assertions = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    $script:Assertions++
    Write-Host "  PASS: $Message"
}

function Assert-FileText {
    param([string]$Path, [string]$Expected, [string]$Message)
    Assert-True ((Test-Path -LiteralPath $Path -PathType Leaf) -and
        ((Get-Content -LiteralPath $Path -Raw) -eq $Expected)) $Message
}

function Invoke-ChildPowerShell {
    param([string[]]$Arguments)
    $hostExe = (Get-Process -Id $PID).Path
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = (& $hostExe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass @Arguments 2>&1 | Out-String)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return [PSCustomObject]@{ ExitCode = $exitCode; Output = $output }
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('dracula-release-' + [guid]::NewGuid().ToString('N'))
$installRoot = Join-Path $testRoot 'install'
$stageRoot = Join-Path $testRoot 'stage'
$installScript = Join-Path $RepoRoot 'scripts\install.ps1'
$uninstallScript = Join-Path $RepoRoot 'scripts\uninstall.ps1'
$applyScript = Join-Path $RepoRoot 'scripts\apply-update.ps1'
$updateScript = Join-Path $RepoRoot 'scripts\update.ps1'
$serverJob = $null

try {
    [void](New-Item -ItemType Directory -Path $testRoot -Force)

    Write-Host 'Release scripts: isolated install'
    & $installScript -InstallRoot $installRoot -Source $BuildDir -NoPathUpdate -Quiet
    Assert-True (Test-Path -LiteralPath (Join-Path $installRoot 'bin\drac.exe')) 'installer places the canonical drac executable'
    Assert-True (Test-Path -LiteralPath (Join-Path $installRoot 'bin\GuestAgent.exe')) 'installer places GuestAgent'
    Assert-True (Test-Path -LiteralPath (Join-Path $installRoot 'brain\skills') -PathType Container) 'installer creates the documented future skills directory'
    Assert-True (Test-Path -LiteralPath (Join-Path $installRoot '.dracula_root')) 'installer writes the install-root marker'

    $version = (& (Join-Path $installRoot 'bin\drac.exe') --version 2>&1 | Out-String)
    Assert-True ($LASTEXITCODE -eq 0 -and $version -match ('v' + [regex]::Escape($ExpectedVersion) + '(\s|$)')) 'installed drac reports the expected version'

    $projectMarker = Join-Path $installRoot 'projects\synthetic\project.json'
    $configMarker = Join-Path $installRoot 'config\release-test.ini'
    $vmMarker = Join-Path $installRoot 'vm\base\release-test.marker'
    [void](New-Item -ItemType Directory -Path (Split-Path $projectMarker -Parent) -Force)
    [void](New-Item -ItemType Directory -Path (Split-Path $vmMarker -Parent) -Force)
    Set-Content -LiteralPath $projectMarker -Value 'synthetic-project' -NoNewline
    Set-Content -LiteralPath $configMarker -Value 'synthetic-config' -NoNewline
    Set-Content -LiteralPath $vmMarker -Value 'synthetic-vm' -NoNewline

    Write-Host 'Release scripts: repair'
    Remove-Item -LiteralPath (Join-Path $installRoot 'bin\GuestAgent.exe') -Force
    & $installScript -InstallRoot $installRoot -Source $BuildDir -Mode repair -NoPathUpdate -Quiet
    Assert-True (Test-Path -LiteralPath (Join-Path $installRoot 'bin\GuestAgent.exe')) 'repair restores a deleted GuestAgent'
    Assert-FileText $projectMarker 'synthetic-project' 'repair preserves projects'
    Assert-FileText $configMarker 'synthetic-config' 'repair preserves configuration'
    Assert-FileText $vmMarker 'synthetic-vm' 'repair preserves VM data'

    Write-Host 'Release scripts: wrong-checksum rejection'
    $httpRoot = Join-Path $testRoot 'http'
    [void](New-Item -ItemType Directory -Path $httpRoot -Force)
    $remoteZipName = 'Dracula-v1.3.4-windows-x64.zip'
    Set-Content -LiteralPath (Join-Path $httpRoot $remoteZipName) -Value 'not a trusted release archive' -NoNewline
    Set-Content -LiteralPath (Join-Path $httpRoot ($remoteZipName + '.sha256')) -Value (('0' * 64) + '  ' + $remoteZipName) -NoNewline
    $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $portProbe.Start()
    $port = ([Net.IPEndPoint]$portProbe.LocalEndpoint).Port
    $portProbe.Stop()
    $baseUrl = "http://127.0.0.1:$port"
    @(
        [PSCustomObject]@{
            tag_name = 'v1.3.4'; draft = $false; prerelease = $false;
            assets = @(
                [PSCustomObject]@{ name = $remoteZipName; browser_download_url = "$baseUrl/$remoteZipName" },
                [PSCustomObject]@{ name = $remoteZipName + '.sha256'; browser_download_url = "$baseUrl/$remoteZipName.sha256" }
            )
        }
    ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $httpRoot 'releases.json') -Encoding UTF8
    $serverJob = Start-Job -ArgumentList $httpRoot, $port -ScriptBlock {
        param($Root, $Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            $done = $false
            while (-not $done) {
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII, $false, 1024, $true)
                    $requestLine = $reader.ReadLine()
                    while ($reader.ReadLine()) { }
                    $requestTarget = ($requestLine -split ' ')[1]
                    $name = [Uri]::UnescapeDataString(($requestTarget -split '\?')[0].TrimStart('/'))
                    $path = Join-Path $Root $name
                    if (Test-Path -LiteralPath $path -PathType Leaf) {
                        $bytes = [IO.File]::ReadAllBytes($path)
                        $statusLine = 'HTTP/1.1 200 OK'
                        $contentType = if ($name.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) {
                            'application/json; charset=utf-8'
                        } else {
                            'application/octet-stream'
                        }
                    } else {
                        $bytes = [byte[]]::new(0)
                        $statusLine = 'HTTP/1.1 404 Not Found'
                        $contentType = 'text/plain'
                    }
                    $header = "$statusLine`r`nContent-Type: $contentType`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                    $headerBytes = [Text.Encoding]::ASCII.GetBytes($header)
                    $stream.Write($headerBytes, 0, $headerBytes.Length)
                    if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
                    $stream.Flush()
                    if ($name.EndsWith('.sha256', [StringComparison]::OrdinalIgnoreCase)) { $done = $true }
                } finally {
                    $client.Close()
                }
            }
        } finally { $listener.Stop() }
    }
    $serverReady = $false
    for ($attempt = 0; $attempt -lt 50 -and -not $serverReady; $attempt++) {
        try {
            $probe = Invoke-WebRequest -Uri "$baseUrl/releases.json" -UseBasicParsing -TimeoutSec 1
            $serverReady = ($probe.StatusCode -eq 200)
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
    Assert-True $serverReady 'local release fixture is ready before updater download'
    $child = Invoke-ChildPowerShell @('-File', $updateScript, '-InstallRoot', $installRoot, '-ReleaseMetadataPath', (Join-Path $httpRoot 'releases.json'), '-NoRestart', '-Quiet')
    if ($child.ExitCode -eq 0 -or $child.Output -notmatch 'SHA-256 verification failed') {
        Write-Host "  Updater child exit code: $($child.ExitCode)"
        Write-Host "  Updater child output: $($child.Output)"
    }
    Assert-True ($child.ExitCode -ne 0 -and $child.Output -match 'SHA-256 verification failed') 'updater rejects a downloaded package with the wrong SHA-256'
    $version = (& (Join-Path $installRoot 'bin\drac.exe') --version 2>&1 | Out-String)
    Assert-True ($LASTEXITCODE -eq 0 -and $version -match ('v' + [regex]::Escape($ExpectedVersion))) 'wrong-checksum rejection leaves the active executable working'
    Assert-FileText $projectMarker 'synthetic-project' 'wrong-checksum rejection preserves projects'
    Stop-Job -Job $serverJob -ErrorAction SilentlyContinue
    Remove-Job -Job $serverJob -Force -ErrorAction SilentlyContinue
    $serverJob = $null

    Write-Host 'Release scripts: successful transactional update'
    [void](New-Item -ItemType Directory -Path $stageRoot -Force)
    foreach ($name in @('bin', 'scripts', 'rules', 'docs')) {
        $source = Join-Path $installRoot $name
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $stageRoot $name) -Recurse -Force
        }
    }
    foreach ($name in @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md')) {
        $source = Join-Path $installRoot $name
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $stageRoot $name) -Force }
    }
    Set-Content -LiteralPath (Join-Path $stageRoot '.dracula_root') -Value @('Dracula Workspace Root', "v$ExpectedVersion") -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $stageRoot 'bin\transaction-marker.txt') -Value 'committed' -NoNewline
    $child = Invoke-ChildPowerShell @('-File', $applyScript, '-InstallRoot', $installRoot, '-StageRoot', $stageRoot, '-ExpectedVersion', $ExpectedVersion, '-NoRestart')
    Assert-True ($child.ExitCode -eq 0) 'transactional updater commits a validated staged release'
    Assert-FileText (Join-Path $installRoot 'bin\transaction-marker.txt') 'committed' 'updated program directory comes from the staged release'
    Assert-FileText $projectMarker 'synthetic-project' 'update preserves projects'
    Assert-FileText $configMarker 'synthetic-config' 'update preserves configuration'
    Assert-FileText $vmMarker 'synthetic-vm' 'update preserves VM data'

    Write-Host 'Release scripts: updater-owned rollback'
    if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $stageRoot -Force)
    foreach ($name in @('bin', 'scripts', 'rules', 'docs')) {
        $source = Join-Path $installRoot $name
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $stageRoot $name) -Recurse -Force
        }
    }
    Set-Content -LiteralPath (Join-Path $stageRoot '.dracula_root') -Value @('Dracula Workspace Root', "v$ExpectedVersion") -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $installRoot 'bin\rollback-marker.txt') -Value 'previous-installation' -NoNewline
    Set-Content -LiteralPath (Join-Path $stageRoot 'bin\rollback-marker.txt') -Value 'uncommitted-update' -NoNewline
    $child = Invoke-ChildPowerShell @('-File', $applyScript, '-InstallRoot', $installRoot, '-StageRoot', $stageRoot, '-ExpectedVersion', $ExpectedVersion, '-NoRestart', '-TestFailPoint', 'after-bin-swap')
    Assert-True ($child.ExitCode -ne 0 -and $child.Output -match 'rolled back') 'injected replacement failure is reported'
    Assert-FileText (Join-Path $installRoot 'bin\rollback-marker.txt') 'previous-installation' 'updater restores its own program backup'
    $rollbackStatus = Get-Content -LiteralPath (Join-Path $installRoot 'logs\last-update.json') -Raw | ConvertFrom-Json
    Assert-True ($rollbackStatus.status -eq 'rolled-back') 'updater records rollback status'
    $version = (& (Join-Path $installRoot 'bin\drac.exe') --version 2>&1 | Out-String)
    Assert-True ($LASTEXITCODE -eq 0 -and $version -match ('v' + [regex]::Escape($ExpectedVersion))) 'previous executable still runs after rollback'

    Write-Host 'Release scripts: uninstall preservation and explicit purge'
    & $uninstallScript -InstallRoot $installRoot -Quiet
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $installRoot 'bin'))) 'default uninstall removes program binaries'
    Assert-FileText $projectMarker 'synthetic-project' 'default uninstall preserves projects'
    Assert-FileText $configMarker 'synthetic-config' 'default uninstall preserves configuration'
    Assert-FileText $vmMarker 'synthetic-vm' 'default uninstall preserves VM data'
    & $uninstallScript -InstallRoot $installRoot -PurgeProjects -Quiet
    Assert-True (-not (Test-Path -LiteralPath $installRoot)) 'explicit purge removes the isolated installation and durable test data'

    Write-Host "Release script acceptance passed ($script:Assertions assertions)."
} finally {
    if ($serverJob) {
        Stop-Job -Job $serverJob -ErrorAction SilentlyContinue
        Remove-Job -Job $serverJob -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
