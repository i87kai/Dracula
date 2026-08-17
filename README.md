# 🧛 Dracula: Unified Binary Intelligence & Reverse-Engineering Platform

A state-of-the-art, high-performance **C++20 Binary Analysis, CPU Emulator (Unicorn Engine 2), Capstone Disassembler, Safe PE Inspector, Control Flow Graph (CFG) Engine, Win32 High-Level Emulation (HLE) Environment, Model Context Protocol (MCP) Server, and Dynamic Sandbox Suite**.

Current Baseline: **`Dracula v1.0.0`**  
Centerpiece Executable: **`Dracula.exe`**

---

## 🌟 Key Features

* 🧛 **Unified Single-Binary Architecture:** Everything is driven from a single, fast portable executable `Dracula.exe` — featuring both an interactive shell with slash command palette (`dracula ❯ `) and scripted CLI flags.
* ⌨️ **Interactive Terminal Shell & Slash Command Palette:**
  * **Real-time interactive line editing**: Left/Right cursor movement, Home/End, Backspace/Delete, and line clearing shortcuts (`Ctrl+A`, `Ctrl+E`, `Ctrl+K`, `Ctrl+U`).
  * **Live Slash Command Palette (`/`)**: Instant filtered popup menu displaying commands and aligned descriptions as you type.
  * **Keyboard Navigation**: `Up`/`Down` arrow selection, `Tab` command acceptance and argument/path completion, `Escape` menu dismissal.
  * **Persistent Command History**: Saved automatically to `%APPDATA%\Dracula\history.txt` with deduplication and bounded size.
  * **Intelligent Path Completion**: Tab-completes file paths and directories with quote and space handling.
* 🛡️ **Safe Bounds-Checked PE Inspector:** Safe zero-copy parsing of DOS, COFF, Optional (PE32 & PE32+ 64-bit), Section Tables, Imports (IAT), Exports (EAT), TLS Callbacks, CLR/.NET, and Native SHA-256/MD5 hashing.
* 🔒 **Security Mitigation Audit:** Real-time auditing for **ASLR**, **High-Entropy ASLR**, **DEP/NX**, **Control Flow Guard (CFG)**, **SEH**, **Authenticode Signatures**, and **RWX Section Memory Hazards**.
* ⚙️ **Unicorn Engine 2 CPU Emulation & Win32 HLE:**
  * Native x86/x64 instruction emulation.
  * **Mock TEB & PEB**: Set up at `0x7FFE0000` / `0x7FFE1000` with `BeingDebugged` policy toggles (`Bypass`, `Realistic`, `Neutral`).
  * **Synthetic HLE Thunks**: Traps API calls at `0x7FFF80000000` to execute native C++ handlers for `VirtualAlloc`, `VirtualProtect`, `IsDebuggerPresent`, `LoadLibrary`, `GetProcAddress`, `Sleep`, `ExitProcess`, and CRT functions.
  * **Dynamic Page Mapping**: On-demand paging in standard mode or strict sandboxing for fault isolation.
* 🧩 **Capstone 5.0.1 Disassembler & Control Flow Graph (CFG) Engine:**
  * Accurate instruction decoding with colored syntax highlighting.
  * Recursive basic block traversal and true/false branch edge resolution.
  * Cross-reference (XRef) analysis detecting code calls, conditional jumps, imports, and data references.
* 🔍 **AOB Hex Pattern Scanner:**
  * Dynamic wildcard pattern scanner accepting arbitrary runtime signatures (e.g. `48 8B 05 ?? ?? ?? ?? 48 85 C0`).
* 📊 **Shannon Entropy & Packer Detector:**
  * Section-by-section mathematical entropy ($H = -\sum p_i \log_2 p_i$) and packer signature detection (UPX, ASPack, Themida, VMProtect, MPRESS).
* 🕵️ **Anti-Evasion Intelligence & Differential Execution:**
  * Detects, locates and explains code that changes behaviour when it believes it is being analyzed — anti-VM, anti-sandbox, anti-debug, timing gates and instrumentation checks.
  * **Controlled environment profiles** (`Baseline`, `Realistic`, `AnalysisFriendly`) decide exactly what a sample can observe about its host: CPUID answers, hypervisor exposure, CPU topology, memory, disk, firmware, MAC prefix, screen, uptime and input activity.
  * **Coherent multi-clock model**: RDTSC, RDTSCP, QueryPerformanceCounter, GetTickCount and uptime all derive from one logical counter, so an accelerated `Sleep(5000)` advances every clock by 5000 ms together instead of contradicting itself.
  * **Bounded branch-influence provenance** separates *"the program asked"* from *"the answer decided what ran"* — the distinction the entire confidence model rests on.
  * **Differential execution** (`--compare`) re-runs the sample under multiple profiles and reports the exact branch RVA that went the other way, the blocks and functions only one run reached, and how each run ended.
  * **Environment coherence validator** catches profiles that contradict themselves (hypervisor bit hidden while the vendor leaf still answers, CPUID topology disagreeing with the OS API, a physical-looking profile exposing a QEMU disk model) and scores how fingerprintable an environment is.
  * **Full normalization audit trail**: every value Dracula supplies that differs from Baseline is recorded with its baseline value, supplied value, source and reason. Nothing is changed silently.
* 🎯 **Evidence-Based Multi-Signal Threat Evaluator:**
  * Transparent corroboration of static, entropy, emulation, and sandbox signals into a 0-100 score and automated **MITRE ATT&CK Matrix**.
* 🤖 **Native Model Context Protocol (MCP) Server:**
  * Clean stdio JSON-RPC 2.0 MCP server connecting Dracula directly with **Claude Desktop**, **Claude Code**, **Cursor**, and **Antigravity**.
* 📦 **Multi-Format Reports:**
  * Instant export to JSON (`report.json`), Markdown (`report.md`), and clean ANSI/plain text summaries.
* 🧪 **Zero-Touch Dynamic QEMU Sandbox:**
  * Isolated dynamic execution with live guest TCP telemetry streaming and instant rollback via volatile `-snapshot` mode.

---

## 🚀 Quick Start

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

Inside the interactive shell:
```
┌─ Dracula ────────────────────────────────────────────────────────────┐
│ Binary Intelligence & Reverse Engineering Platform                   │
│ v1.0.0 (x86_64-w64-mingw32)                                          │
│                                                                      │
│ Capstone 5.0 • Unicorn 2 • Safe PE • Win32 HLE • CFG • MCP           │
└──────────────────────────────────────────────────────────────────────┘

  Working directory: D:\Coding\python\AI\jew
  Type / for command palette • /help for command reference

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
