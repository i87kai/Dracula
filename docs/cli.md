# CLI Reference

`drac` opens the interactive project shell. The `CommandRegistry` is the
authoritative source for command names, aliases, usage, subcommands,
requirements, completion, and dispatch. Run `/help <command>` for the exact
build-time reference.

## Navigation

| Input | Action |
|---|---|
| `/` | Open the command palette |
| `Tab` | Complete a command, subcommand, flag value, or path |
| `Up` / `Down` | Navigate palette or command history |
| `PageUp` / `PageDown` | Scroll output |
| Mouse wheel | Scroll output |
| Mouse drag | Select output text |
| `Ctrl+C` | Copy selection or cancel input |
| `Ctrl+Home` / `Ctrl+End` | Oldest/newest output |
| `Ctrl+L` | Repaint |

Use `--no-color` and `--no-unicode` for limited terminals.

## Project and target

| Command | Registered usage |
|---|---|
| `/project` | `/project [info|list|open|new|close|storage|cleanup|delete]` |
| `/session` | `/session [list|use|info|cleanup|delete]` |
| `/target` | `/target <path> \| /target [info|capabilities|close]` |
| `/artifacts` | `/artifacts` |

## Static analysis and inspection

| Command | Registered usage |
|---|---|
| `/analyze` | `/analyze [quick|deep|runtime|full] \| /analyze <file>` |
| `/static` | `/static [info|sections|imports|exports|strings]` |
| `/headers` | `/headers [file]` |
| `/security` | `/security [file]` |
| `/imports` | `/imports [file]` |
| `/exports` | `/exports [file]` |
| `/strings` | `/strings [file] [min_length]` |
| `/entropy` | `/entropy [file]` |
| `/scan` | `/scan [file] <pattern>` |
| `/disasm` | `/disasm [file] [rva] [count]` |
| `/functions` | `/functions [file]` |
| `/cfg` | `/cfg [file] [rva]` |
| `/xrefs` | `/xrefs [file] [rva]` |
| `/antievasion` | `/antievasion [file] [--detect|--compare] [--profile <name>] [--details]` |

When a project is active, optional file operands resolve to the project's
static image. A live-process project supplies its backing executable.

## Process, DLL, memory, and runtime

| Command | Registered usage |
|---|---|
| `/process` | `/process [list|attach <pid>|info|modules|threads]` |
| `/dll` | `/dll [info|exports|imports|functions] [name]` |
| `/memory` | `/memory [map|read|snapshot|snapshots|compare]` |
| `/runtime` | `/runtime [status|events]` |

Examples:

```text
/process attach 1234
/process modules
/dll windowscodecs.dll
/memory read 0x7ff600001000 64
/memory snapshot before
/memory snapshot after
/memory compare before after
/runtime events
```

Only attach to processes you are authorized to inspect. Access to elevated or
protected processes may require a matching integrity level and may still be
denied by Windows.

## Managed, driver, emulation, and sandbox

| Command | Registered usage |
|---|---|
| `/dotnet` | `/dotnet [info|types|method <Type> <Method>|strings|pinvokes]` |
| `/driver` | `/driver [info|imports|sections|runtime]` |
| `/emulate` | `/emulate [file] [--policy bypass|realistic|neutral]` |
| `/sandbox` | `/sandbox [status|image|overlays|reset]` |

`/analyze runtime` is an analysis-orchestration mode. `/sandbox` owns explicit
QEMU environment, image, overlay, and reset operations.

## Findings and reports

| Command | Registered usage |
|---|---|
| `/findings` | `/findings` |
| `/report` | `/report [json|md|txt] [output_path]` |

Project-aware application services also write self-contained HTML artifacts
for large tables even though `/report`'s explicit export formats are JSON,
Markdown, and text.

## System

| Command | Registered usage |
|---|---|
| `/settings` | `/settings [list|set <key> <value>]` |
| `/mcp` | `/mcp` |
| `/changelog` | `/changelog [version]` |
| `/version` | `/version` |
| `/update` | `/update [check|status|install]` |
| `/about` | `/about` |
| `/help` | `/help [command]` |
| `/clear` | `/clear` |
| `/exit` | `/exit` |

Useful one-shot flags include:

```powershell
drac --version
drac --about
drac --help
drac --mcp
drac --process list
```

Unknown first operands are treated as file targets for analysis. Prefer
explicit flags in automation.
