# Dracula Interactive CLI Reference

The Dracula Command Line Interface provides a high-productivity REPL with rich syntax highlighting, hierarchical command palettes, Tab completion, and persistent viewports.

---

## 1. Keyboard Shortcuts & Navigation

| Key Combination | Action |
|---|---|
| `/` | Open hierarchical command palette |
| `Tab` | Auto-complete command or subcommand |
| `PageUp` / `PageDown` | Scroll output history viewport |
| `Mouse Wheel` | Smooth scroll output viewport |
| `Mouse Drag` | Select text in output region (ANSI escape-free) |
| `Ctrl+C` | Copy selected text to clipboard (or cancel prompt input) |
| `Ctrl+Home` / `Ctrl+End` | Jump to oldest / newest output line |
| `Ctrl+L` | Repaint terminal screen |

---

## 2. Command Index

### Analysis Commands
* `/analyze <file>`: Full analysis pipeline (static headers, entropy, disasm, findings).
* `/static [file]`: Deep static inspection of headers and section layout.
* `/entropy [file]`: Shannon entropy curve and packer detection.
* `/antievasion [file]`: Scan for sandbox/VM detection, timing hooks, and anti-debug heuristics.
* `/scan <pattern>`: Scan binary using hex wildcard / AOB signatures.

### Inspection Commands
* `/disasm [va] [count]`: Disassemble instructions using Capstone engine.
* `/headers [file]`: Detailed PE header fields, Data Directories, Section Headers.
* `/security [file]`: Mitigations audit (ASLR, DEP/NX, CFG, SafeSEH, Authenticode).
* `/imports [file]`: Imported DLLs and flagged high-risk Windows APIs.
* `/exports [file]`: Export address table and exported symbol names.
* `/strings [file]`: Classify ASCII and UTF-16 strings with heuristics.
* `/functions [file]`: Function discovery, prologue matching, and entrypoint map.
* `/cfg [va]`: Reconstruct Control Flow Graph and basic block jumps.
* `/xrefs <target>`: Cross-references to functions, strings, and imported APIs.

### Universal Target & Dynamic Commands
* `/target [file]`: Display active target metadata or open a new target.
* `/process attach <pid>`: Attach to a running Windows process.
* `/process list`: List running processes with architectural tags.
* `/memory map`: Virtual memory allocation map and protection flags.
* `/memory snapshot [label]`: Capture full virtual memory snapshot.
* `/memory compare <id1> <id2>`: Compare two memory snapshots and detect injected code.
* `/dotnet [types|methods|pinvoke]`: Inspect managed .NET metadata and IL code.
* `/driver [info|scan]`: Inspect Windows kernel driver targets.
* `/emulate [va] [steps]`: Unicorn 2 CPU emulation with Win32 API hooks.
* `/sandbox [status|image|overlays|reset]`: QEMU disposable sandbox management.

### Project & System Commands
* `/project [list|info|storage|cleanup|delete]`: Manage persistent analysis workspaces.
* `/findings`: List discovered vulnerabilities, evasion techniques, and threat score.
* `/report [html|md|json] [path]`: Export standalone analysis reports.
* `/settings [list|set <key> <value>]`: Read and modify user configuration.
* `/update [check|status|install]`: In-place software update.
* `/about`: Project manifesto and repository coordinates.
* `/version`: Authoritative platform version and engine inventory.
* `/help [command]`: Contextual command reference.
* `/exit`: Terminate shell session.
