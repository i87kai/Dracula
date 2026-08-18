# Dracula Workspace Guide

How Dracula is installed, how projects work, and what each command operates on.

This document covers the v1.3.0 project-centric architecture. For engine and
analysis detail, see `DRACULA_GUIDE.md`.

> **Local Web GUI is future work and is not included.** The engine/service
> boundary described below exists so that a browser front end can be added
> later without touching an analysis engine. Nothing in this release serves
> HTTP or renders a web page.

---

## 1. Installation

### Bootstrap

```powershell
irm https://<host>/install.ps1 | iex
```

The bootstrap script downloads the release, unpacks it to a temporary
directory, runs the installer, and deletes everything it downloaded — whether
the install succeeded or not.

To install from a local build instead:

```powershell
.\tools\install\Install-Dracula.ps1 -Source .\build
```

### Choosing a location

The installer lists every fixed disk with its **real** free space and lets you
pick with the arrow keys:

```
  Where should Dracula be installed?

  > D:\   383.5 GB free of 689.7 GB
    C:\    45.5 GB free of 261.2 GB
    Enter a path manually
```

`Enter` selects, `Esc` cancels, and number keys jump directly. Choosing
*Enter a path manually* accepts any path you can write to.

Before installing, the destination is checked for write permission and for
enough free space. Failures are reported with the actual numbers.

### What gets installed

```
<root>\
    bin\          drac.exe, agent DLLs, GuestAgent
    tools\
    brain\        reserved for future analysis intelligence assets
    runtime\
    vm\
        base\     immutable .draculaimg packages and the operational base
        overlays\ disposable per-run overlays
        cache\
    projects\     durable analysis workspaces
    cache\
    logs\
    config\       settings.json, projects.json, config.ini
```

`brain\` is intentionally empty. It is reserved, not used.

### PATH and the `drac` command

The installer adds `<root>\bin` to your **per-user** PATH. Administrator is
not required and the machine-wide PATH is not touched.

Open a new terminal and run:

```
drac
```

Dracula also drops an install marker beside the executable, so `drac` finds
its own workspace even in a shell that was opened before installation, and
with no environment variable set.

### Re-running the installer

Running the installer again detects the existing install and offers:

- **Repair** — reinstall program files, keep everything else
- **Update** — same, for a newer build
- **Change location** — install to a different drive
- **Uninstall** — remove program files, **keep projects**
- **Cancel**

Projects are never silently destroyed. Uninstall removes `bin`, `tools` and
`runtime` and tells you where your projects still are.

---

## 2. First run

`drac` with no arguments asks what you want to analyze:

```
  DRACULA

  What do you want to analyze?

  > Open Existing Project
    Open File
    Attach to Process
    Driver
    VM / Disk Image
```

`Esc` goes straight to the command prompt. A piped or redirected session skips
the picker entirely.

Target type is detected for you — EXE, DLL, .NET assembly and driver are all
just *Open File*.

---

## 3. Projects

A **project** is Dracula's durable workspace. It survives exit and is reopened
later by ID or name. One project is active at a time, and every command
operates on it.

### Creating one

```
/target D:\Downloads\sample.exe     a file
/process attach 17140               a running process
```

Your original file is **copied** into the project and never modified. Deleting
a project never deletes your file.

### Layout

```
<root>\projects\sample_3f2a1c88\
    project.json      metadata, written atomically with a .bak fallback
    original\         Dracula's immutable copy of the sample
    static\  functions\  modules\
    memory\
        maps\ snapshots\ dumps\
    runtime\          events.jsonl
    sandbox\  reports\  artifacts\  logs\  overlays\  cache\
```

### Identity

Projects are identified by the **SHA-256 of the sample**, not by filename.
Opening the same bytes under a different name continues the same project:

```
An existing Dracula project matched this sample by SHA-256.
Last opened: 2026-08-18T10:50:04
Start an independent project instead with: /project new <path>
```

Commands accept a full ID, an unambiguous short ID (`7f31`), or a display
name. An ambiguous short ID resolves to nothing rather than guessing.

### Commands

| Command | Effect |
|---|---|
| `/project info` | The active project and its target |
| `/project list` | Every project, most recent first |
| `/project open <id\|name>` | Switch projects |
| `/project new <path>` | Independent project for an already-analyzed sample |
| `/project close` | Close; the project stays on disk |
| `/project storage` | Measured disk usage by category |
| `/project cleanup [id]` | Remove disposable data only |
| `/project delete <id> [--force]` | Remove the workspace |

`/session list|use|info|cleanup|delete` are the same durable workspaces under
friendlier names. There is exactly one persistence system — the two command
families operate on identical storage.

### Storage and cleanup

`/project storage` reports what is actually on disk, measured, never estimated:

```
Original sample              4.1 MB
Memory snapshots           622.0 MB
Dumps                      240.0 MB
VM overlays                    0 B
Cache                       32.8 MB
Total                      925.4 MB
Disk free                  221.7 GB
Reclaimable by /project cleanup: 272.8 MB
```

`cleanup` removes only what is marked disposable — overlays, cache, and
intermediate dumps. It always keeps the original sample, project metadata,
reports, retained snapshots and logs.

### Deletion

`/session delete <id>` shows exactly what will go and requires confirmation:

```
Project:         test_sample
Project storage: 55.2 KB

This removes Dracula's project copy, runtime data, reports,
snapshots and project artifacts.
The original external file will NOT be deleted:
  D:\Downloads\sample.exe
```

Pass `--force` to skip confirmation in scripts. Deletion refuses any path that
is not inside the projects directory, so a corrupted index can never become an
arbitrary recursive delete.

---

## 4. Targets and capabilities

A project knows what kind of target it holds and what that target can do.

**A PID is a PID.** A process target records its PID in a numeric field and its
resolved on-disk image separately. Neither is ever stored in a path.

```
/target info

Kind:         Running Process
PID:          17140
Backing:      C:\...\Notepad.exe
Project copy: <project>\original\Notepad.exe
```

Because the backing executable is resolved and copied at attach time,
`/static` works on a process project with no extra steps — and keeps working
after the process exits:

```
/static

Resolved from the process backing image:
  <project>\original\Notepad.exe
Architecture:  x64 (AMD64)
Sections:      6
Imports:       666
```

`/target capabilities` lists what is available. When a command needs something
the target does not have, the error says so and lists what *is* available
rather than reporting a missing file.

---

## 5. Command hierarchy

Type `/` to browse. Typing a command shows its subcommands:

```
/memory     map   read   snapshot   snapshots   compare
```

The palette, Tab completion, `/help` and dispatch all read one registry, so
the interface cannot advertise a command that does not exist.

| Group | Commands |
|---|---|
| Project | `/project` `/session` `/artifacts` |
| Target | `/target` |
| Analysis | `/static` `/analyze` `/functions` `/disasm` `/cfg` `/xrefs` |
| Modules | `/dll` `/process` |
| Memory | `/memory` |
| Runtime | `/runtime` |
| Sandbox | `/sandbox` |
| System | `/settings` `/help` `/version` |

---

## 6. DLL correlation

`/dll` resolves a module **inside the current project** without replacing its
target. When the module is loaded in the live process, static addresses are
correlated to runtime ones:

```
/dll exports windowscodecs.dll

DllCanUnloadNow
    Static RVA   0xBED30
    Preferred VA 0x1800BED30
    Loaded base  0x7FFFE8FD0000
    Live VA      0x7FFFE908ED30

[LIVE-READ VERIFIED] DllCanUnloadNow static RVA 0xBED30 -> live VA 0x7FFFE908ED30
```

Three evidence levels are reported and never conflated:

- **STATIC** — calculated from the file alone
- **RESOLVED** — static RVA plus a real loaded module base
- **LIVE-READ VERIFIED** — the address was actually read back from the process

Dracula verifies a bounded sample of addresses rather than probing thousands,
and reports how many it verified.

---

## 7. Memory

```
/memory map                     summary + HTML report
/memory read 0x7FF... 256       hex dump, live-read verified
/memory snapshot before         capture
/memory snapshot after
/memory snapshots               list
/memory compare before after    diff
```

Snapshot IDs come from a counter persisted in `project.json`. They increment,
never repeat, and continue across restarts — a snapshot taken today can be
compared against one taken last week. Snapshots are addressable by ID or by
label.

Snapshot *structure* is retained (regions, protections, entropy, hashes), not
region contents, which keeps a 1800-region snapshot in the hundreds of KB.

---

## 8. Runtime status

Readiness is reported as what can actually be proven:

```
Agent x64           Available    <path>
ETW Observer        Available    ready to observe PID 17140
DbgEng Adapter      Partial      symbols and memory reads (no execution control)
QEMU                Stopped      installed, not running
GuestAgent          Stopped      not connected (VM stopped)
```

A binary being installed is not the same as being connected. Nothing reports
*Ready* because a file exists.

`/runtime events` shows recorded events, or says plainly that there are none.

---

## 9. Large output and reports

Large tables are never dumped into the terminal. The terminal gets a summary
and the detail is written into the project:

```
/memory map

Regions indexed:  1857
Committed:        612.9 MB
Executable:       259
Full report:      memory/maps/map_0001.html
```

Reports are self-contained HTML with search, sort and filter, and no external
CDN, font or script dependency. `/artifacts` lists everything generated.

Set `reports.auto_open` to open them automatically:

```
/settings set reports.auto_open true
```

A report that fails to open is still a successfully generated report; the path
is always printed.

> These static HTML reports are **not** the future Local Web GUI. They are
> project files you can open in a browser.

---

## 10. Sandbox, VM base and overlays

Dracula runs untrusted samples inside a QEMU guest. **QEMU stays stopped until
an analysis needs it** — opening a project never boots a VM.

### Packaging your VM

You provide your own Windows analysis VM. Dracula packages *your* image; it
never ships one.

```
/sandbox image import D:\VirtualMachines\win10.vdi
```

```
Original size:    17.1 GB
Package size:     8.4 GB
Compression:      49.3% of original
Chunks:           1094
Duration:         254 s
Original SHA-256: e4bb8500...
Package SHA-256:  ee9d4b78...

The source image was only read; it has not been modified or moved.
```

| Command | Effect |
|---|---|
| `/sandbox image info` | Package header |
| `/sandbox image verify` | Structure, every chunk, and the content hash |
| `/sandbox image restore [--force]` | Rebuild the operational base |
| `/sandbox overlays [clean]` | List or sweep run overlays |
| `/sandbox reset` | Stop, sweep, verify, rebuild |
| `/sandbox status` | Factual environment state |

The `.draculaimg` format is chunked and streamed, so a 17 GB image never sits
in memory. Each chunk carries a CRC-32 and corruption is reported **with the
chunk it occurred in**. The original SHA-256 is stored in the header, so a
restored image is provably identical to what was packaged.

### The immutable base

```
windows10.draculaimg      immutable, integrity-checked
        |
        v
verified read-only base   <root>\vm\base\windows10.vdi
        |
        v
per-run overlay           <root>\vm\overlays\run_<id>.qcow2
        |
        v
analysis  ->  evidence retained in the project
        |
        v
overlay deleted           on success AND on failure
```

Guest writes land in a qcow2 overlay whose backing file is the base, so the
base is physically never modified. Overlays record the owning QEMU PID, so a
crashed run is distinguishable from a live one. Dracula never removes an
overlay a running QEMU still owns, and sweeps orphaned ones on demand.

### Recovery

`/sandbox reset` stops any session, sweeps overlays, verifies the package,
compares the base against the package hash, and rebuilds it only if it is
missing or has been modified. It reports the exact state everything ended in.

---

## 11. Terminal

| Input | Effect |
|---|---|
| Mouse wheel | Scroll the output region |
| PageUp / PageDown | Scroll by a page |
| Ctrl+Home / Ctrl+End | Oldest / newest output |
| Drag | Select text |
| Ctrl+C | Copy the selection, or clear the input line |
| Ctrl+L | Repaint |

There is **no selection mode**. Earlier versions required pressing F2 to trade
wheel scrolling for the ability to select text, because Win32 makes those two
mutually exclusive for a console application. Dracula now tracks the selection
itself, so both work at once and F2 is gone.

A proportional scrollbar appears whenever history exceeds the viewport. If you
scroll up, new output does **not** yank you back to the bottom — the footer
reports how many new lines arrived instead.

---

## 12. Settings

```
/settings list
/settings set reports.auto_open true
```

Stored in `<root>\config\settings.json`. Unknown keys are rejected so a typo
cannot become a dead setting.

| Key | Default | Effect |
|---|---|---|
| `reports.auto_open` | `false` | Open generated HTML reports |
| `reports.format` | `html` | Default large-report format |
| `memory.max_read_bytes` | `1048576` | Cap on a single `/memory read` |
| `palette.enabled` | `true` | Show the command palette |
| `tips.enabled` | `true` | Show contextual tips |
| `sandbox.auto_cleanup` | `true` | Delete overlays after every run |

---

## 13. MCP

`drac --mcp` speaks JSON-RPC on stdio and operates on the **same** projects and
services as the CLI.

`target_open` takes either a `target` path or a numeric `pid` field — there is
no combined "path or PID" string to misparse. Project tools:
`project_list`, `project_info`, `project_open`, `project_storage`,
`runtime_status`, `runtime_events`, `artifacts_list`.

Large results are bounded and reference project artifacts rather than inlining
them.

---

## 14. Architecture

```
DraculaCore              analysis engines (UTR, PE, disassembly, emulation)
      |
Application Services     ProjectService, TargetService, StaticService,
      |                  ProcessService, DllService, MemoryService,
      |                  RuntimeService, SandboxService
      |
Command / Operation API  CommandResult + DTOs, no terminal formatting
     /            \
   CLI          Local Web GUI
   now              later
```

Services return structured data (`CommandResult`, `ProjectSummary`,
`TargetSummary`, `MemoryMapSummary`, `FunctionSummary`, `RuntimeStatus`,
`ArtifactReference`, `ErrorDetail`). The CLI is the only place those become
coloured text. A future local web front end will format the same objects
differently without touching an engine — and the CLI will remain fully usable
after it exists.
