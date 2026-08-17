# 🧛 DRACULA BINARY INTELLIGENCE & REVERSE-ENGINEERING PLATFORM
## Technical Architecture & Developer Guide (v2.0.0)

---

## 1. Architectural Overview

**Dracula** is an all-in-one static analysis, CPU emulation, memory inspection, and dynamic sandbox orchestration platform for Windows PE binaries (PE32/PE32+).

```
                            +-------------------------------------------+
                            |                Dracula.exe                |
                            |   (Interactive CLI, REPL, JSON, & MCP)    |
                            +---------------------+---------------------+
                                                  |
                     +----------------------------+----------------------------+
                     |                                                         |
        +------------v-------------+                             +-------------v------------+
        | Static & Emulation Core  |                             |  Dynamic Hardware VM Core |
        +------------+-------------+                             +-------------+------------+
                     |                                                         |
   +-----------------+-----------------+                         +-------------+------------+
   | - PeInspector (Bounds Checked)   |                         | - QemuManager (-snapshot)|
   | - EntropyAnalyzer (Shannon)      |                         | - LiveTcpServer (JSON)   |
   | - StringsAnalyzer (Classified)   |                         | - GuestAgent.exe (Ring 3)|
   | - Disassembler (x86/x64)         |                         +-------------+------------+
   | - CfgAnalyzer (Basic Blocks)     |                                       |
   | - PatternScanner (AOB Wildcard)  |                                       |
   | - UnicornAnalyzer (Unicorn 2)    |                                       |
   | - Win32Hle (Mock TEB/PEB & APIs) |                                       |
   +-----------------+-----------------+                                       |
                     |                                                         |
                     +----------------------------+----------------------------+
                                                  |
                                    +-------------v------------+
                                    |     ThreatEvaluator      |
                                    |  - Multi-Signal Scoring  |
                                    |  - MITRE ATT&CK Matrix   |
                                    +-------------+------------+
                                                  |
                                    +-------------v------------+
                                    |  ReportWriter / Exports  |
                                    |  - JSON (Structured)     |
                                    |  - Markdown (Docs)       |
                                    |  - ANSI Color Terminal   |
                                    +--------------------------+
```

---

## 2. Core Subsystems

### 2.1 PE Inspector (`PeInspector`)
- **Memory Safety**: Uses strict pointer bounds arithmetic (`RvaToFileOffset`, `SafeRead`, `DataDirectory` bounds check).
- **Features**:
  - Validates DOS (`MZ`) and NT (`PE\0\0`) headers.
  - Detects architecture (`x86` vs `x64` / `AMD64`).
  - Audits security mitigations:
    - **ASLR**: `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`
    - **High-Entropy ASLR**: `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`
    - **DEP / NX**: `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`
    - **Control Flow Guard (CFG)**: `IMAGE_DLLCHARACTERISTICS_GUARD_CF`
    - **SEH**: `IMAGE_DLLCHARACTERISTICS_NO_SEH`
    - **Authenticode**: Safe extraction of Certificate Table (`IMAGE_DIRECTORY_ENTRY_SECURITY`)
    - **RWX Sections**: Flags any section marked simultaneously with `IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE`.
  - Resolves Import Address Table (IAT), Export Address Table (EAT) with forwarders, and TLS Callbacks.

### 2.2 Shannon Entropy & Packer Detection (`EntropyAnalyzer`)
- Computes Shannon entropy:
  $$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- Flags sections with entropy $\ge 7.20$ as packed or encrypted.
- Signature matches known packers (`UPX`, `ASPack`, `Themida`, `VMProtect`, `MPRESS`).
- Direct integration with YARA 64 (`tools/yara64.exe`).

### 2.3 Strings Extractor & Categorizer (`StringsAnalyzer`)
- Extracts ASCII (1-byte) and UTF-16LE (2-byte) strings.
- Regex pattern matching with heuristic categorizers:
  - `URL`: `http://`, `https://`, `ftp://`
  - `IPv4`: `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`
  - `FilePath`: `[a-zA-Z]:\\[^<>:"/\\|?*\n\r]+`
  - `RegistryKey`: `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKLM`, `HKCU`, `Software\...`
  - `CommandFragment`: `cmd.exe`, `powershell`, `-enc`, `bypass`, `bitsadmin`, `certutil`
  - `DllName`: `*.dll`, `*.ocx`, `*.sys`
  - `SuspiciousApi`: `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, etc.

### 2.4 Disassembler & Control Flow Graph Engine (`Disassembler` & `CfgAnalyzer`)
- Full x86/x64 instruction decoding without external heavyweight disassembler dependencies.
- Handles prefixes (0x66, 0x67, 0xF0, 0xF2, 0xF3), REX prefixes (0x40 - 0x4F), ModR/M, SIB, RIP-relative addressing, and immediate values.
- Branch classification:
  - Unconditional jumps (`JMP`, `JMP [rel32]`)
  - Conditional branches (`JZ`, `JNZ`, `JA`, `JB`, `JG`, `JL`, `JECXZ`, `LOOP`, etc.)
  - Function calls (`CALL`, `CALL [rel32]`)
  - Function returns (`RET`, `RET imm16`)
- `CfgAnalyzer` performs recursive traversal across branch paths:
  - Splits binary into isolated `BasicBlock` nodes.
  - Tracks true/false edges and loop termination sets.
  - Renders ASCII branch flow diagrams for terminal viewing.

### 2.5 Pattern Scanner (`PatternScanner`)
- Fast, wildcard-capable Array-of-Bytes (AOB) scanner.
- Accepts standard hex pattern strings with `??` or `?` wildcards:
  ```
  "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??"
  ```
- Scans memory buffers, section arrays, or binary files on disk.

### 2.6 Win32 High-Level Emulation (HLE) & Mock TEB/PEB (`Win32Hle`)
- Maps mock Thread Environment Block (TEB) at `0x7FFE0000` (pointing `gs:[0x60]` to PEB).
- Maps mock Process Environment Block (PEB) at `0x7FFE1000` (`BeingDebugged`, `ImageBaseAddress`, `ProcessParameters`).
- Maps synthetic HLE thunks starting at `0x7FFF80000000`.
- Intercepts imported API calls in Unicorn and executes native C++ handlers:
  - **Memory**: `VirtualAlloc` (dynamic Unicorn memory mapping + RWX tracking), `VirtualFree`, `VirtualProtect`
  - **Anti-Debug**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` with policy toggles:
    - `Bypass`: Returns `FALSE` (0) to evade evasion checks.
    - `Realistic`: Returns `TRUE` (1) to emulate active debugger attached.
    - `Neutral`: Returns 0 without modifying PEB.
  - **Process / Thread**: `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThreadId`, `ExitProcess`, `TerminateProcess`
  - **Modules**: `GetModuleHandleA/W`, `LoadLibraryA/W`, `GetProcAddress` (dynamically returns new synthetic thunks!)
  - **Timers**: `Sleep` (fast-forward clock), `GetTickCount`, `QueryPerformanceCounter`
  - **CRT**: `printf`, `fprintf`, `vfprintf`, `puts`, `abort`, `__iob_func`, `__acrt_iob_func`

### 2.7 Multi-Signal Threat Evaluator (`ThreatEvaluator`)
- Aggregates static, entropy, emulation, and sandbox signals.
- Computes normalized 0-100 threat score:
  - `0 - 24`: **Clean / Benign**
  - `25 - 44`: **Low Risk**
  - `45 - 74`: **Suspicious**
  - `75 - 100`: **Critical Threat**
- Generates MITRE ATT&CK technique tags (`T1055`, `T1497`, `T1027`, `T1059`, `T1071`, `T1547`, `T1105`).

---

## 3. Interactive Shell & CLI Reference

Launch interactive mode:
```powershell
.\build\Dracula.exe
```

Prompt:
```
⚰️ dracula ❯ 
```

### Slash Command Table

| Command | Description | Example |
|---|---|---|
| `/analyze <file>` | Run complete static, entropy, and emulation pipeline | `/analyze sample.exe` |
| `/emulate <file>` | Run CPU emulation with Win32 HLE and view registers | `/emulate sample.exe` |
| `/disasm <file> [rva] [count]` | Disassemble machine code at entry point or target RVA | `/disasm sample.exe 0x1000 30` |
| `/cfg <file> [rva]` | Visualize function Control Flow Graph (CFG) | `/cfg sample.exe 0x1000` |
| `/headers <file>` | Display DOS/NT headers and section permissions table | `/headers sample.exe` |
| `/security <file>` | Audit ASLR, DEP, CFG, SEH, and Authenticode | `/security sample.exe` |
| `/imports <file>` | List imported DLLs and flag sensitive APIs | `/imports sample.exe` |
| `/exports <file>` | List exported symbols and function RVAs | `/exports sample.exe` |
| `/strings <file> [len]` | Extract and classify ASCII and Unicode strings | `/strings sample.exe 5` |
| `/entropy <file>` | Calculate section-by-section Shannon entropy | `/entropy sample.exe` |
| `/scan <file> <pattern>` | Scan for wildcard hex patterns | `/scan sample.exe "48 8B ?? ??"` |
| `/sandbox <file>` | Launch QEMU dynamic VM isolation | `/sandbox sample.exe` |
| `/findings` | Display structured findings for active session | `/findings` |
| `/report [json\|md\|txt] [out]` | Export session report to disk | `/report json out.json` |
| `/session` | View current active sample metadata | `/session` |
| `/mcp` | Launch Model Context Protocol (MCP) server | `/mcp` |
| `/help` | Print interactive command reference | `/help` |
| `/exit` | Terminate Dracula session | `/exit` |

### CLI Non-Interactive Flags

```powershell
Dracula.exe --analyze <path/to/binary.exe>
Dracula.exe --headers <path/to/binary.exe>
Dracula.exe --security <path/to/binary.exe>
Dracula.exe --disasm <path/to/binary.exe> [--rva 0x1000]
Dracula.exe --cfg <path/to/binary.exe> [--rva 0x1000]
Dracula.exe --scan <path/to/binary.exe> "48 8B 05 ?? ?? ?? ??"
Dracula.exe --mcp
Dracula.exe --version
Dracula.exe --help
```

---

## 4. Model Context Protocol (MCP) Integration

Dracula natively exposes a high-performance Model Context Protocol (MCP) JSON-RPC 2.0 stdio server.

### Connecting with Claude Desktop / Claude Code / Antigravity / Cursor

Add Dracula to your MCP configuration file (`mcp_config.json` or `claude_desktop_config.json`):

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

Or using the Python launcher:
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

### Exposed MCP Tools:
- `analyze_file`: Full static + entropy + emulation pipeline returning unified JSON report.
- `inspect_pe_headers`: Headers, entry point, section tables.
- `audit_security_mitigations`: ASLR, DEP, CFG, SEH, Authenticode, RWX.
- `disassemble_code`: x86/x64 instruction disassembly.
- `extract_strings`: Classified ASCII & UTF-16LE strings.
- `calculate_entropy`: Shannon entropy and packing verdict.
- `scan_hex_pattern`: AOB wildcard search.

---

## 5. Building & Verification

### Prerequisites
- CMake 3.20+
- MinGW-w64 (GCC 11+ with C++20 support) or MSVC 2022+

### Build Commands
```powershell
cmake -B build -G "MinGW Makefiles"
cmake --build build -j 4
```

### Run Comprehensive Test Suite
```powershell
ctest --test-dir build --output-on-failure
```

All 44 automated tests and emulation harnesses pass with 100% verification.
