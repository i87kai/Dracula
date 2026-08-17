# 🧛 Dracula: Unified Binary Intelligence & Reverse-Engineering Platform

A state-of-the-art, high-performance **C++20 Binary Analysis, CPU Emulator (Unicorn Engine 2), Safe PE Inspector, Disassembler, Control Flow Graph (CFG) Engine, Win32 High-Level Emulation (HLE) Environment, Model Context Protocol (MCP) Server, and Dynamic Sandbox Suite**.

Centerpiece Executable: **`Dracula.exe`**

---

## 🌟 Key Features

* 🧛 **Unified Single-Binary Architecture:** Everything is driven from a single, fast portable executable `Dracula.exe` — featuring both an interactive shell (`⚰️ dracula ❯ `) and scripted CLI flags.
* 🛡️ **Safe Bounds-Checked PE Inspector:** Safe zero-copy parsing of DOS, COFF, Optional (PE32 & PE32+ 64-bit), Section Tables, Imports (IAT), Exports (EAT), TLS Callbacks, CLR/.NET, and Native SHA-256/MD5 hashing.
* 🔒 **Security Mitigation Audit:** Real-time auditing for **ASLR**, **High-Entropy ASLR**, **DEP/NX**, **Control Flow Guard (CFG)**, **SEH**, **Authenticode Signatures**, and **RWX Section Memory Hazards**.
* ⚙️ **Unicorn Engine 2 CPU Emulation & Win32 HLE:**
  * Native x86/x64 instruction emulation.
  * **Mock TEB & PEB**: Set up at `0x7FFE0000` / `0x7FFE1000` with `BeingDebugged` policy toggles (`Bypass`, `Realistic`, `Neutral`).
  * **Synthetic HLE Thunks**: Traps API calls at `0x7FFF80000000` to execute native C++ handlers for `VirtualAlloc`, `VirtualProtect`, `IsDebuggerPresent`, `LoadLibrary`, `GetProcAddress`, `Sleep`, `ExitProcess`, and CRT functions (`printf`, `fprintf`, `__iob_func`, `abort`).
  * **Dynamic Page Mapping**: On-demand paging in standard mode or strict sandboxing for fault isolation.
* 🧩 **Disassembly & Control Flow Graph (CFG) Engine:**
  * Recursive basic block traversal and true/false branch edge resolution.
  * ASCII graph visualization and colored disassembly.
* 🔍 **AOB Hex Pattern Scanner:**
  * Dynamic wildcard pattern scanner accepting arbitrary runtime signatures (e.g. `48 8B 05 ?? ?? ?? ?? 48 85 C0`).
* 📊 **Shannon Entropy & Packer Detector:**
  * Section-by-section mathematical entropy ($H = -\sum p_i \log_2 p_i$) and packer signature detection (UPX, ASPack, Themida, VMProtect, MPRESS).
* 🎯 **Evidence-Based Multi-Signal Threat Evaluator:**
  * Transparent corroboration of static, entropy, emulation, and sandbox signals into a 0-100 score and automated **MITRE ATT&CK Matrix**.
* 🤖 **Native Model Context Protocol (MCP) Server:**
  * Native stdio JSON-RPC 2.0 MCP server connecting Dracula directly with **Claude Desktop**, **Claude Code**, **Cursor**, and **Antigravity**.
* 📦 **Multi-Format Reports:**
  * Instant export to JSON (`report.json`), Markdown (`report.md`), and ANSI color text summaries.
* 🧪 **Zero-Touch Dynamic QEMU Sandbox:**
  * Isolated dynamic execution with live guest TCP telemetry streaming and instant rollback via volatile `-snapshot` mode.

---

## 🚀 Quick Start

### Build with CMake (MinGW-w64 or MSVC)

```powershell
# Configure build directory
cmake -B build -G "MinGW Makefiles"

# Build all targets (Dracula, GuestAgent, Test Suite)
cmake --build build -j 4

# Run 100% automated test suite
ctest --test-dir build --output-on-failure
```

### Interactive Shell Mode

Launch Dracula in interactive mode:
```powershell
.\build\Dracula.exe
```

Inside the interactive shell:
```
⚰️ dracula ❯ /analyze samples/advanced_sample.exe
⚰️ dracula ❯ /security
⚰️ dracula ❯ /disasm
⚰️ dracula ❯ /cfg
⚰️ dracula ❯ /findings
⚰️ dracula ❯ /report json advanced_report.json
⚰️ dracula ❯ /exit
```

### Scripted CLI Mode

```powershell
# Run full static + emulation analysis
Dracula.exe --analyze sample.exe

# Audit security mitigations (ASLR, DEP, CFG, SEH)
Dracula.exe --security sample.exe

# Inspect PE headers and section table
Dracula.exe --headers sample.exe

# Disassemble entrypoint
Dracula.exe --disasm sample.exe

# Render Control Flow Graph
Dracula.exe --cfg sample.exe

# Scan for wildcard pattern
Dracula.exe --scan sample.exe "48 8B 05 ?? ?? ?? ?? 48 85 C0"

# Launch MCP Server for AI pair programming
Dracula.exe --mcp
```

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
├── CMakeLists.txt              # Production target-based build definition
├── README.md                   # Platform documentation
├── config/
│   └── config.ini              # Engine and sandbox configuration
├── docs/
│   └── DRACULA_GUIDE.md        # Comprehensive technical guide
├── include/
│   ├── cli/dracula_shell.h     # Interactive REPL & CLI parser
│   ├── common/findings.h       # Unified finding & evidence data structures
│   ├── common/types.h          # Core engine types
│   ├── core/
│   │   ├── analysis_orchestrator.h # Central analysis pipeline
│   │   ├── cfg_analyzer.h      # Control flow graph construction
│   │   ├── disassembler.h      # x86/x64 instruction decoding
│   │   ├── entropy_analyzer.h  # Shannon entropy & YARA scanner
│   │   ├── pattern_scanner.h   # Wildcard AOB scanner
│   │   ├── pe_inspector.h      # Safe bounds-checked PE32/PE32+ parser
│   │   ├── strings_analyzer.h  # ASCII/UTF-16LE classified strings
│   │   ├── threat_evaluator.h  # Multi-signal evidence threat scoring
│   │   ├── unicorn_analyzer.h  # Unicorn 2 CPU instruction tracer
│   │   └── win32_hle.h         # Win32 HLE, mock TEB/PEB, & anti-debug
│   ├── host/report_writer.h    # Multi-format report serializer
│   └── mcp/mcp_server.h        # Native JSON-RPC 2.0 MCP server
├── src/                        # Complete C++20 implementation
├── tests/
│   ├── test_dracula_suite.cpp  # 44/44 automated unit/integration test suite
│   └── test_emulate_buffer.cpp # Unicorn buffer regression test harness
└── tools/                      # Packaged dependencies & MCP helper
```

---

## 🛡️ License & Ethics

Dracula is designed strictly for authorized cybersecurity analysis, malware defense research, software reverse-engineering, and vulnerability assessment.
