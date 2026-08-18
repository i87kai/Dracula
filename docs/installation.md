# Installation and Maintenance

The supported release installation is per-user and does not require
Administrator privileges at the default location.

## Web bootstrap

```powershell
irm https://raw.githubusercontent.com/i87kai/Dracula/main/scripts/bootstrap.ps1 | iex
```

The bootstrap:

1. resolves the latest public GitHub release;
2. downloads the Windows x64 ZIP and its required SHA-256 sidecar;
3. rejects a missing, malformed, or mismatched digest;
4. extracts only the verified package;
5. shows install locations with actual free-space figures;
6. creates the program and durable workspace directories; and
7. adds `<install>\bin` to the current user's PATH.

The default is `%LOCALAPPDATA%\Dracula`. A fixed-drive root may require
permissions that the default location does not.

Open a fresh terminal and verify:

```powershell
where.exe drac
drac --version
drac --about
```

## Manual ZIP installation

Download the two matching assets from the
[latest release](https://github.com/i87kai/Dracula/releases/latest), then:

```powershell
$zip = Get-Item .\Dracula-v*-windows-x64.zip
$expected = ((Get-Content "$($zip.FullName).sha256" -Raw) -split '\s+')[0]
$actual = (Get-FileHash $zip.FullName -Algorithm SHA256).Hash
if ($actual -ne $expected) { throw 'SHA-256 verification failed' }

Expand-Archive $zip.FullName -DestinationPath .\Dracula
& .\Dracula\scripts\install.ps1
```

Use `-InstallRoot D:\Tools\Dracula` for a non-interactive destination. Use
`-Quiet` for automation and `-NoPathUpdate` for a portable-style test install.

## Installed tree

```text
Dracula/
  bin/               drac.exe, agents, managed host
  scripts/           install, repair, update, uninstall helpers
  docs/
  rules/
  tools/
  brain/
    skills/           reserved future packaged Skills location
  runtime/
  vm/
    base/             user-owned .draculaimg and restored base
    overlays/
    cache/
  projects/           durable project workspaces
  cache/
  logs/
  config/
  .dracula_root
```

Program assets resolve from this root. A release installation does not depend
on a source checkout or developer build directory.

## Repair

Run the installed maintenance script with the original release payload or an
extracted matching release as the source:

```powershell
& .\scripts\install.ps1 -Mode repair -InstallRoot C:\path\to\Dracula -Source .\bin
```

Repair re-copies missing program components such as `GuestAgent.exe` and
refreshes scripts, rules, and documentation. Existing configuration, projects,
VM bases, overlays, reports, and logs are preserved.

## Update

From Dracula:

```text
/update check
/update install
```

Or from PowerShell:

```powershell
& <install>\scripts\update.ps1 -InstallRoot <install>
```

The update path requires the checksum, validates the staged `drac.exe` version,
waits for the running process to exit, and swaps program-owned directories with
an updater-owned backup. A commit failure triggers rollback before any restart.
The result is recorded in `<install>\logs\last-update.json`.

The transaction does not replace `projects`, `config`, `vm`, `cache`, `logs`,
or `brain`.

## Uninstall

Default uninstall removes program files and the PATH entry while retaining
durable data:

```powershell
& <install>\scripts\uninstall.ps1 -InstallRoot <install>
```

Intentional full purge:

```powershell
& <install>\scripts\uninstall.ps1 -InstallRoot <install> -PurgeProjects
```

`-PurgeProjects` removes the entire selected installation root. Verify the
path before using it. Release acceptance tests use synthetic roots, never a
real user workspace.

## PowerShell policy alternative

If local policy blocks the extracted installer during the web bootstrap, use
an allowed signed/policy-controlled PowerShell host or the explicit
process-scoped alternative approved by your organization:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/i87kai/Dracula/main/scripts/bootstrap.ps1 | iex"
```

For an already extracted release:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

This changes policy only for that process; organizational policy may still
prevent it.
