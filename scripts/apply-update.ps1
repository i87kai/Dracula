<#
.SYNOPSIS
    Applies a staged Dracula update after the running process exits.

.DESCRIPTION
    Internal transactional updater used by Dracula. The staged payload is
    validated before commit. Program directories are swapped with backups and
    restored by this script if any commit step fails. Durable projects,
    configuration, VM bases, overlays, caches, and logs are never part of the
    replacement set.

    TestFailPoint exists only for release acceptance testing of updater-owned
    rollback. It is not used by the normal update path.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot,
    [Parameter(Mandatory = $true)]
    [string]$StageRoot,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedVersion,
    [int]$ParentPid = 0,
    [string]$RestartExecutable,
    [switch]$NoRestart,
    [ValidateSet('', 'after-backup', 'after-bin-swap', 'after-maintenance')]
    [string]$TestFailPoint = ''
)

$ErrorActionPreference = 'Stop'
$script:Swaps = @()
$script:Files = @()

function Resolve-FullPath {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

function Write-Result {
    param([string]$Status, [string]$Message, [string]$Transaction)
    try {
        $logDir = Join-Path $InstallRoot 'logs'
        [void](New-Item -ItemType Directory -Path $logDir -Force)
        [PSCustomObject]@{
            status      = $Status
            message     = $Message
            version     = $ExpectedVersion
            transaction = $Transaction
            timestamp   = [DateTime]::UtcNow.ToString('o')
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logDir 'last-update.json') -Encoding UTF8
    } catch { }
}

function Invoke-FailPoint {
    param([string]$Name)
    if ($TestFailPoint -eq $Name) {
        throw "Injected release-validation failure at '$Name'."
    }
}

function Swap-Directory {
    param([string]$Name, [string]$IncomingRoot, [string]$BackupRoot)
    $incoming = Join-Path $IncomingRoot $Name
    if (-not (Test-Path -LiteralPath $incoming -PathType Container)) { return }

    $destination = Join-Path $InstallRoot $Name
    $backup = Join-Path $BackupRoot $Name
    $hadOriginal = Test-Path -LiteralPath $destination
    if ($hadOriginal) {
        [void](New-Item -ItemType Directory -Path (Split-Path $backup -Parent) -Force)
        Move-Item -LiteralPath $destination -Destination $backup
    }

    $script:Swaps += [PSCustomObject]@{
        Destination = $destination
        Backup      = $backup
        HadOriginal = $hadOriginal
    }
    Move-Item -LiteralPath $incoming -Destination $destination
}

function Replace-File {
    param([string]$Name, [string]$IncomingRoot, [string]$BackupRoot)
    $incoming = Join-Path $IncomingRoot $Name
    if (-not (Test-Path -LiteralPath $incoming -PathType Leaf)) { return }

    $destination = Join-Path $InstallRoot $Name
    $backup = Join-Path $BackupRoot $Name
    $hadOriginal = Test-Path -LiteralPath $destination
    if ($hadOriginal) {
        [void](New-Item -ItemType Directory -Path (Split-Path $backup -Parent) -Force)
        Move-Item -LiteralPath $destination -Destination $backup
    }

    $script:Files += [PSCustomObject]@{
        Destination = $destination
        Backup      = $backup
        HadOriginal = $hadOriginal
    }
    Copy-Item -LiteralPath $incoming -Destination $destination
}

function Restore-Transaction {
    $filesToRestore = @($script:Files)
    [array]::Reverse($filesToRestore)
    foreach ($entry in $filesToRestore) {
        if (Test-Path -LiteralPath $entry.Destination) {
            Remove-Item -LiteralPath $entry.Destination -Force
        }
        if ($entry.HadOriginal -and (Test-Path -LiteralPath $entry.Backup)) {
            Move-Item -LiteralPath $entry.Backup -Destination $entry.Destination
        }
    }
    $directoriesToRestore = @($script:Swaps)
    [array]::Reverse($directoriesToRestore)
    foreach ($entry in $directoriesToRestore) {
        if (Test-Path -LiteralPath $entry.Destination) {
            Remove-Item -LiteralPath $entry.Destination -Recurse -Force
        }
        if ($entry.HadOriginal -and (Test-Path -LiteralPath $entry.Backup)) {
            Move-Item -LiteralPath $entry.Backup -Destination $entry.Destination
        }
    }
}

$transaction = 'update-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

try {
    $InstallRoot = Resolve-FullPath $InstallRoot
    $StageRoot = Resolve-FullPath $StageRoot

    if (-not (Test-Path -LiteralPath (Join-Path $InstallRoot '.dracula_root') -PathType Leaf)) {
        throw "Refusing to update '$InstallRoot': .dracula_root marker is missing."
    }
    if (-not (Test-Path -LiteralPath $StageRoot -PathType Container)) {
        throw "Staged update root does not exist: '$StageRoot'."
    }
    if ($InstallRoot.Equals($StageRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Install root and staged update root must be different.'
    }

    $candidate = Join-Path $StageRoot 'bin\drac.exe'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $candidate = Join-Path $StageRoot 'bin\Dracula.exe'
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'The staged release does not contain bin\drac.exe.'
    }

    $versionOutput = (& $candidate --version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch ('v' + [regex]::Escape($ExpectedVersion) + '(\s|$)')) {
        throw "Staged executable version does not match v$ExpectedVersion."
    }

    $transactionRoot = Join-Path $InstallRoot ('cache\updates\' + $transaction)
    $incomingRoot = Join-Path $transactionRoot 'incoming'
    $backupRoot = Join-Path $InstallRoot ('backup\' + $transaction)
    [void](New-Item -ItemType Directory -Path $incomingRoot -Force)
    [void](New-Item -ItemType Directory -Path $backupRoot -Force)

    foreach ($name in @('bin', 'scripts', 'rules', 'docs')) {
        $source = Join-Path $StageRoot $name
        if (Test-Path -LiteralPath $source -PathType Container) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $incomingRoot $name) -Recurse -Force
        }
    }
    foreach ($name in @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md', '.dracula_root')) {
        $source = Join-Path $StageRoot $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $incomingRoot $name) -Force
        }
    }

    if ($ParentPid -gt 0) {
        try {
            $parent = Get-Process -Id $ParentPid -ErrorAction Stop
            if (-not $parent.WaitForExit(30000)) {
                throw "Dracula process $ParentPid did not exit within 30 seconds."
            }
        } catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
            # The parent exited before the helper began waiting.
        }
    }

    Swap-Directory -Name 'bin' -IncomingRoot $incomingRoot -BackupRoot $backupRoot
    Invoke-FailPoint 'after-backup'
    Invoke-FailPoint 'after-bin-swap'

    foreach ($name in @('scripts', 'rules', 'docs')) {
        Swap-Directory -Name $name -IncomingRoot $incomingRoot -BackupRoot $backupRoot
    }
    Invoke-FailPoint 'after-maintenance'

    foreach ($name in @('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md', '.dracula_root')) {
        Replace-File -Name $name -IncomingRoot $incomingRoot -BackupRoot $backupRoot
    }

    $installedExe = Join-Path $InstallRoot 'bin\drac.exe'
    $installedVersion = (& $installedExe --version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $installedVersion -notmatch ('v' + [regex]::Escape($ExpectedVersion) + '(\s|$)')) {
        throw "Installed executable failed post-commit validation for v$ExpectedVersion."
    }

    Write-Result -Status 'installed' -Message "Updated to v$ExpectedVersion." -Transaction $transaction
    Remove-Item -LiteralPath $transactionRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StageRoot -Recurse -Force -ErrorAction SilentlyContinue

    if (-not $NoRestart) {
        $restart = if ($RestartExecutable) { $RestartExecutable } else { $installedExe }
        Start-Process -FilePath $restart -WorkingDirectory (Split-Path $restart -Parent)
    }
    exit 0
} catch {
    $failure = $_.Exception.Message
    try { Restore-Transaction } catch { $failure += ' Rollback error: ' + $_.Exception.Message }
    Write-Result -Status 'rolled-back' -Message $failure -Transaction $transaction
    Remove-Item -LiteralPath $StageRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Error "Dracula update failed and was rolled back: $failure"
    exit 1
}
