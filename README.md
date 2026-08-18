# 🧛 Dracula: Universal Target Runtime & Reverse-Engineering Intelligence Platform

A state-of-the-art, high-performance **C++20 Unified Target Runtime (UTR), CPU Emulator (Unicorn Engine 2), Capstone Disassembler, Safe PE Inspector, Control Flow Graph (CFG) Engine, Win32 High-Level Emulation (HLE) Environment, Memory Transformation Detector, Out-of-Process Managed (.NET) Host, Model Context Protocol (MCP) Server, and Dynamic Sandbox Suite**.

Current Version: **`Dracula v1.3.0`** (Project Workspace Milestone)  
Centerpiece Executable: **`Dracula.exe`**

---

## 🌟 Key Features

* 🌐 **Universal Target Runtime (UTR):**
  * **Unified Target Abstraction (`ITarget`)**: Treats Native EXEs, Native DLLs, Running Processes by PID, Windows Services, .NET Managed Assemblies, Windows Kernel Drivers (`.sys`), and QEMU-isolated VMs as first-class analysis targets.
  * **Deterministic Target Fingerprinting**: Automatically resolves target kind, bitness, architecture, security mitigations, and binds appropriate backends.
* 🧠 **Memory Intelligence & Transformation Engine:**
  * **Virtual Memory Layout**: Full memory mapping, page protection audits, and entropy distribution.
  * **Incremental Zstd-Compressed Snapshots**: Captures point-in-time process memory states into `%LOCALAPPDATA%\Dracula\snapshots\`.
  * **Runtime Transformation Detection**: Identifies dynamic code injection, unpacking, and self-modifying payloads (`PAGE_READWRITE` $\to$ payload write $\to$ `PAGE_EXECUTE_READ` $\to$ execution entry).
* 🎯 **Function Intelligence & Prioritization:**
  * **Centralized Function Graph**: Synthesizes static CFGs, XRefs, strings, and import references into an indexed function database.
  * **Decoupled Scoring**: `InterestScore` (0–100 investigation priority) strictly decoupled from `ThreatScore` (maliciousness).
  * **Runtime Correlation**: Correlates instruction execution traces and Win32 HLE call records to discovered functions.
* 📊 **Evidence Graph & Provenance Tracing:**
  * **Fact Graph Model**: Explicit truth levels (`Observed`, `Inferred`, `Suspected`, `Unknown`) with multi-engine provenance (Capstone, Unicorn, ETW, DbgEng, Agent, QEMU, ClrMD).
  * **Multi-Step Behavior Chains**: Connects discrete observations into reasoned behavioral hypotheses.
* 🧰 **Safe DLL Execution Harness:**
  * Safe export directory enumeration and capability-gated invocation inside isolated test environments.
* ⚡ **Out-of-Process Managed Host (.NET 10):**
  * Subprocess JSON-RPC server (`Dracula.ManagedHost.exe`) with hard 5s timeouts for zero-crash inspection of .NET assembly metadata, type hierarchies, IL disassembly, strings, and P/Invoke declarations.
* 🔌 **Expanded Model Context Protocol (MCP) Server:**
  * Complete stdio JSON-RPC 2.0 interface exposing 15 rich analysis tools for AI pair programming (Claude Desktop, Cursor, Antigravity).
* 📁 **Isolated Runtime Storage:**
  * All database sessions (`dracula_sessions.db`), Zstd snapshots, and exported artifacts are written to `%LOCALAPPDATA%\Dracula\`, ensuring git working trees remain 100% clean.

---

## 🚀 Quick Start

### Install

```powershell
irm https://<host>/install.ps1 | iex
```

The installer lists your fixed disks with their real free space, lets you pick
with the arrow keys, creates the workspace, and puts `drac` on your per-user
PATH. Administrator is not required.

From a local build instead:

```powershell
.\tools\install\Install-Dracula.ps1 -Source .\build
```

Then, in a new terminal:

```powershell
drac
```

Re-running the installer offers Repair / Update / Change location / Uninstall.
Your projects are never destroyed.

### Analyze something

Dracula is **project-centric**. Opening a target creates a durable workspace
that survives exit and is reopened later by ID or name.

```
drac

  What do you want to analyze?

  > Open File
    Attach to Process
    Open Existing Project
```

```
/target D:\Downloads\sample.exe    create or continue a project for a file
/process attach 17140              ... or for a running process

/static                            analyze the project's image
/dll windowscodecs.dll             correlate a loaded module with its file
/memory snapshot before            capture memory state
/memory compare before after       diff two snapshots
/project storage                   measured disk usage
/session delete <id>               remove the workspace (never your file)
```

A PID is recorded as a PID and its backing executable resolved separately, so
`/static` works on a process project without reopening anything — and keeps
working after the process exits.

Large tables are written into the project as self-contained, searchable HTML
rather than flooding the terminal.

**See [`docs/WORKSPACE_GUIDE.md`](docs/WORKSPACE_GUIDE.md)** for installation,
projects, sessions, the command hierarchy, `.draculaimg` VM packaging, the
immutable VM base and overlay lifecycle, and the service architecture.

> A **Local Web GUI is future work and is not included in this release.** The
> engine/service boundary exists so it can be added later without changing an
> analysis engine; the CLI will remain fully usable after it arrives.

### Build with CMake (MinGW-w64 or MSVC)

```powershell
# Configure build directory
cmake -B build -G "MinGW Makefiles"

# Build all targets in Release configuration (Dracula, GuestAgent, Test Suite)
cmake --build build -j 4

# Run 100% automated audit test suite
ctest --test-dir build --output-on-failure
```

### Interactive Shell Mode

Launch Dracula in interactive mode:
```powershell
.\build\Dracula.exe
```

Inside the interactive shell the header describes your work rather than the
engine inventory:

```
  Dracula  v1.3.0  •  x64  •  Release

  Project windowscodecs  •  Target Native DLL - x64  •  Runtime Idle  •  Status Ready

  Tip: /dll <name> correlates a loaded module with its on-disk image.
```

```
  Type / for the command palette • /help for the full reference

dracula ❯ /analyze samples\test_sample.exe
dracula ❯ /security
dracula ❯ /disasm
dracula ❯ /cfg
dracula ❯ /antievasion
dracula ❯ /antievasion --compare
dracula ❯ /findings
dracula ❯ /report json test_report.json
dracula ❯ /session
dracula ❯ /changelog 1.0.0
dracula ❯ /exit
```

### Anti-Evasion Analysis

Find code that behaves differently when it thinks it is being analyzed, and
prove whether the check actually matters:

```
dracula ❯ /help antievasion            # modes, profiles, confidence, evidence
dracula ❯ /analyze sample.exe
dracula ❯ /antievasion                 # reuses the active sample
dracula ❯ /antievasion --compare       # differential execution across profiles
dracula ❯ /antievasion --details       # full evidence and audit trail
```

`/antievasion` also answers to `/antivm`, `/evasion` and `/ae`.

Two modes, and the difference matters:

| Mode | What it does | What it proves |
|---|---|---|
| `--detect` (default) | Static detection plus one controlled emulation run | A check **exists**, and whether its value reaches a branch |
| `--compare` | Runs the sample under several environment profiles and compares coverage, branches, API calls and termination | The check **matters**: behaviour actually changed |

**Environment sensitivity score (0–100)** answers one question: *how strongly
did behaviour change when the analysis environment changed?* Static detection
alone is capped at 25 — finding a check is not the same as watching it fire.
The rest comes from observed divergence: branches that flipped, code only one
run reached, and runs that ended differently.

This score is **not** a malware score, and Dracula keeps the two apart. In the
worked example below the sample scores 72/100 for environment sensitivity and
12/100 for threat, reported as *Clean / Benign* — because detecting a virtual
machine is something development tools, games, licensing systems and
enterprise software all do for entirely legitimate reasons.

Real output from `build/samples/antievasion/ae_cpuid_gate.exe`, a benign probe
built from source in this repository:

```
  Environment sensitivity   72 / 100   Clear
  Confidence                Very High
  Status                    BehaviorDiverged

  Anti-VM CPUID
    RVA           0x10CF
    Confidence    High
    Property      Hypervisor presence
    Control flow  value flows into `test ecx, ecx` and decides the branch
                  `js 0x1400010e7` at RVA 0x10D5

  Differential execution
    Baseline            4 blocks    3 functions    14 instructions
    Realistic           4 blocks    3 functions    14 instructions
    AnalysisFriendly   18 blocks    8 functions    63 instructions

  Key divergence
    RVA 0x10D5   js 0x1400010e7
      Baseline            branch taken -> 0x1400010E7
      AnalysisFriendly    fallthrough -> 0x1400010D7, reaching 16 block(s)
                          the reference run never entered
      Attributed to       CPUID (Hypervisor presence)
```

> Dracula does **not** claim to make a virtual environment indistinguishable
> from physical hardware — no general-purpose VM can be. It reports precisely
> what its environments expose, and records every value it supplies.

### Scripted CLI Mode

```powershell
# Run full static + emulation analysis
Dracula.exe --analyze sample.exe

# Audit security mitigations (ASLR, DEP, CFG, SEH)
Dracula.exe --security sample.exe

# Inspect PE headers and section table
Dracula.exe --headers sample.exe

# Disassemble entrypoint or specific RVA
Dracula.exe --disasm sample.exe 0x1000 50

# Render Control Flow Graph
Dracula.exe --cfg sample.exe

# Detect anti-VM / anti-sandbox / anti-debug behaviour
Dracula.exe --anti-evasion sample.exe

# Prove it by re-running under multiple controlled environment profiles
Dracula.exe --anti-evasion sample.exe --compare

# Scan for wildcard pattern
Dracula.exe --scan sample.exe "48 8B 05 ?? ?? ?? ?? 48 85 C0"

# View changelog release history
Dracula.exe --changelog

# View platform version and engines
Dracula.exe --version

# Launch MCP Server for AI pair programming
Dracula.exe --mcp
```

---

## 🖥️ Terminal Encoding & Troubleshooting

Dracula automatically configures Windows Console and Windows Terminal for **UTF-8 code pages (CP_UTF8)** and enables **Virtual Terminal (VT) processing**.

* **Rich Terminal Mode**: If rich Unicode is supported, Dracula displays crisp glyphs (`dracula ❯`, `┌─│└`, `•`).
* **Safe ASCII Fallback**: If standard ASCII terminal is detected, Dracula automatically degrades to safe characters (`dracula >`, `+-|`, `*`) without showing mojibake or corrupt characters.
* **Color Overrides**:
  * Pass `--no-color` or set the `NO_COLOR=1` environment variable to completely disable ANSI styling.
  * When redirected to a file (`Dracula.exe --version > out.txt`), ANSI sequences are automatically omitted.
* **Unicode Overrides**: Pass `--no-unicode` to force ASCII fallback mode on any terminal.

---

## 🤖 Model Context Protocol (MCP) Configuration

Add Dracula directly to your AI development environment (`claude_desktop_config.json`, `mcp_config.json`):

```json
{
  "mcpServers": {
    "dracula": {
      "command": "d:/Coding/python/AI/jew/build/Dracula.exe",
      "args": ["--mcp"]
    }
  }
}
```

Or via the Python bridge:
```json
{
  "mcpServers": {
    "dracula": {
      "command": "python",
      "args": ["d:/Coding/python/AI/jew/tools/dracula_mcp.py"]
    }
  }
}
```

---

## 📁 Repository Structure

```
.
├── CHANGELOG.txt               # Plain-text version history & release notes
├── CMakeLists.txt              # Production target-based build definition
├── README.md                   # Platform documentation
├── config/
│   └── config.ini              # Engine and sandbox configuration
├── docs/
│   └── DRACULA_GUIDE.md        # Comprehensive technical architecture guide
├── include/
│   ├── cli/
│   │   ├── command_registry.h  # Central command metadata, aliases & handlers
│   │   ├── dracula_shell.h     # Interactive shell & CLI argument parser
│   │   ├── line_editor.h       # Interactive line editor with slash palette
│   │   └── terminal.h          # Terminal capability, theme & encoding subsystem
│   ├── common/
│   │   ├── findings.h          # Unified finding & evidence data structures
│   │   ├── types.h             # Core engine types
│   │   └── version.h           # Central authoritative version definition (v1.0.0)
│   ├── core/
│   │   ├── analysis_orchestrator.h # Central analysis pipeline
│   │   ├── cfg_analyzer.h      # Control flow graph construction
│   │   ├── disassembler.h      # Capstone x86/x64 instruction decoding
│   │   ├── entropy_analyzer.h  # Shannon entropy & YARA scanner
│   │   ├── pattern_scanner.h   # Wildcard AOB scanner
│   │   ├── pe_inspector.h      # Safe bounds-checked PE32/PE32+ parser
│   │   ├── strings_analyzer.h  # ASCII/UTF-16LE classified strings
│   │   ├── threat_evaluator.h  # Multi-signal evidence threat scoring
│   │   ├── unicorn_analyzer.h  # Unicorn 2 CPU instruction tracer
│   │   ├── win32_hle.h         # Win32 HLE, mock TEB/PEB, & anti-debug
│   │   └── xref_analyzer.h     # Cross-reference analysis engine
│   ├── host/report_writer.h    # Multi-format report serializer
│   └── mcp/mcp_server.h        # Native JSON-RPC 2.0 MCP server
├── src/                        # Complete C++20 implementation
├── tests/
│   ├── test_dracula_suite.cpp  # 114/114 automated unit & audit test harness
│   └── test_emulate_buffer.cpp # Unicorn buffer regression test harness
└── tools/                      # Packaged dependencies & MCP helper
```

---

## 🏷️ Versioning & Release Workflow

Dracula strictly follows Semantic Versioning from **ONE authoritative version definition** in `include/common/version.h`.

Whenever a new version is released:
1. Update `DRACULA_VERSION_MAJOR`, `DRACULA_VERSION_MINOR`, `DRACULA_VERSION_PATCH` in `include/common/version.h`.
2. Add a new entry to `CHANGELOG.txt` under `Added`, `Changed`, `Fixed`, `Verified`.
3. Run the automated test suite (`ctest --test-dir build --output-on-failure`).
4. Commit changes with a clean message and create a Git release tag (e.g. `git tag -a v1.0.0 -m "Release v1.0.0"`).

---

## 🛡️ License & Ethics

Dracula is designed strictly for authorized cybersecurity analysis, malware defense research, software reverse-engineering, and vulnerability assessment.
