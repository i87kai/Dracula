# Getting Started

Dracula is a project-centric Windows analysis workspace. Opening a file or
attaching to a process creates a durable project; later commands operate on the
active project's target rather than requiring the same path or PID each time.

## Requirements

- Windows 10 or 11, x64
- PowerShell 5.1 or newer for installation
- .NET 10 runtime for managed assembly inspection
- QEMU and a user-provided Windows environment only for isolated VM analysis

## Install and launch

```powershell
irm https://raw.githubusercontent.com/i87kxxz/Dracula/main/scripts/bootstrap.ps1 | iex
```

Open a fresh terminal after installation:

```powershell
drac
```

The first-run picker offers file, process, driver, and VM/disk-image workflows.
Press `Esc` to go directly to the command prompt. Type `/` to browse the
registered commands.

## First static project

Use a benign executable you are authorized to inspect:

```text
/target C:\Windows\System32\notepad.exe
/target info
/static
/imports
/strings
/functions
/findings
/project storage
```

The first command copies the target into the project. Static analysis then uses
that project copy, so the workspace stays usable if the original path moves.

## First live project

Start Notepad, then:

```text
/process list
/process attach <notepad-pid>
/process info
/process modules
/memory map
/runtime status
/dll windowscodecs.dll
```

The attach operation records the PID separately from the resolved backing
executable. File-oriented commands use the backing image; process commands use
the live target.

## Continue later

```text
/project list
/project open <id-or-name>
/project info
/artifacts
```

Use `/project cleanup` to remove only disposable project data. Deletion is a
separate, confirmed operation.

## Next reading

- [Installation and maintenance](installation.md)
- [Projects and persistence](projects.md)
- [CLI reference](cli.md)
- [Architecture](architecture.md)
- [Troubleshooting](troubleshooting.md)
