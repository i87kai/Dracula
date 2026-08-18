# Troubleshooting

## `drac` is not found

Open a new terminal after installation, then:

```powershell
where.exe drac
[Environment]::GetEnvironmentVariable('Path', 'User')
```

The expected entry is `<install>\bin`. Re-run `scripts\install.ps1` with the
same `-InstallRoot` to repair the PATH entry.

## Bootstrap or update rejects a checksum

Do not bypass verification. Delete the downloaded files and obtain both assets
again from the same GitHub release. The ZIP and `.sha256` filenames must match.

`<install>\logs\last-update.json` records whether a staged transaction
installed or rolled back.

## PowerShell script policy blocks installation

Use a policy allowed by your organization. For a local extracted release, the
process-scoped form is:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

Group Policy can still override this setting.

## Terminal characters are broken

Use Windows Terminal or force fallbacks:

```powershell
drac --no-unicode
drac --no-color
```

The compact fallback contains no Braille artwork.

## Process attachment is denied

The target may run at a higher integrity level, be protected, or have exited.
Try a benign process at the same integrity level first. Elevation should be
used only when the authorized target requires it.

## Managed host is unavailable

Verify the .NET 10 runtime and packaged host:

```powershell
dotnet --list-runtimes
Get-ChildItem <install>\bin\Dracula.ManagedHost.*
```

Repair from the matching release if the host files are missing.

## QEMU is unavailable

`/sandbox status` reports the paths it tested. Dracula expects
`qemu-system-x86_64.exe` and `qemu-img.exe` in the configured tool location or
PATH. A VM package and restored base are separate requirements.

## Overlays remain after an interrupted run

```text
/sandbox overlays
/sandbox overlays clean
```

Cleanup intentionally refuses an overlay whose owner QEMU PID is still alive.
Use `/sandbox reset` only after confirming the active analysis can stop.

## Submodule build fails

```powershell
git submodule status
git submodule update --init --recursive
```

For MinGW, verify Git for Windows and its shell:

```powershell
Test-Path "$env:ProgramFiles\Git\bin\sh.exe"
```
