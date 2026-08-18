# Dracula Third-Party Dependency Qualification Manifest

This document records the qualification, upstream provenance, pinned releases, licenses, architecture status, deterministic POC results, and architectural decisions for all 18 evaluated third-party dependencies for Dracula v1.2.1 Universal Target Runtime (UTR).

---

## Qualification Matrix Summary

| Dependency | Upstream / Pinned Version | License | Dracula Role | Arch Support | Build / Integration Method | Deterministic POC Result | Qualification Status | Decision & Rationale |
|---|---|---|---|---|---|---|---|---|
| **Capstone** | 5.0.1 (`capstone-engine/capstone`) | BSD-3-Clause | Native disassembly & instruction decoding | x86, x64, ARM64 | Static C CMake submodule | `test_emulate_buffer.cpp` (PASS) | **ACCEPTED (Core)** | Preserved from v1.1.2. Proven, fast, thread-safe instruction decoder. |
| **Unicorn** | 2.0.1 (`unicorn-engine/unicorn`) | GPL-2.0 / LGPL-2.1 | CPU emulation & Win32 HLE | x86, x64 | Static C archive (`libunicorn.a`) | `test_emulate_buffer.cpp` (PASS) | **ACCEPTED (Core)** | Preserved from v1.1.2. Verified CPU instruction emulator and sandbox. |
| **SQLite** | 3.46.1 Amalgamation (`sqlite.org`) | Public Domain / MIT Equivalent | Session database & evidence/function index | x86, x64, ARM64 | Vendored C amalgamation (`sqlite3.c`) | `poc_qualification.cpp` (PASS) | **ACCEPTED (Core)** | Embeds directly into `DraculaCore` with zero external runtime dependencies. Tested byte-exact round-trip. |
| **Zstandard (zstd)** | 1.5.6 (`facebook/zstd`) | BSD-3-Clause | Memory snapshot compression & region deltas | x86, x64, ARM64 | Vendored C source library (`third_party/zstd`) | `poc_qualification.cpp` (PASS) | **ACCEPTED (Core)** | Fast real-time compression with bounded memory limits. Verified lossless decompression round-trip. |
| **DbgHelp** | Windows OS Native (`dbghelp.dll`) | Microsoft OS Native | Process memory read & SymFromAddr symbol resolution | x86, x64, ARM64 | Dynamic DLL loader (`dbgeng_backend.cpp`) | `poc_qualification.cpp` (PASS) | **ACCEPTED (Native Adapter)** | Non-intrusive symbol resolution and process address-space inspection. |
| **DbgEng** | Windows SDK (`dbgeng.dll`) | Microsoft SDK | User/Kernel debugger engine interfaces | x86, x64 | COM discovery behind adapter | Verified dynamic link fallback (PASS) | **OPTIONAL / SDK ADAPTER** | Preserved as optional adapter; DbgHelp provides primary non-invasive symbol and memory inspection. |
| **DIA SDK** | Windows SDK (`msdia140.dll`) | Microsoft SDK | PDB symbol & type hierarchy resolution | x86, x64 | COM activation + export table fallback | Verified dynamic link fallback (PASS) | **OPTIONAL / SDK ADAPTER** | Enriches Function Intelligence when PDBs exist without breaking analysis when absent. |
| **Windows ETW + TDH** | Windows Native APIs (`advapi32.dll`) | Microsoft OS API | Non-invasive external observation of events | x86, x64, ARM64 | Win32 API calls (`IExternalObserver`) | `poc_qualification.cpp` (PASS) | **ACCEPTED (Native Adapter)** | Monitors process, thread, and module load events externally without DLL injection. |
| **System.Reflection.Metadata** | .NET 10 Built-in | MIT License | Static managed metadata, types, methods, IL, P/Invokes | x86, x64, ARM64 | Out-of-process `Dracula.ManagedHost.exe` | `test_managed_backend.cpp` (PASS) | **ACCEPTED (Core Managed)** | Fast, zero-allocation managed PE metadata parsing for .NET assemblies. |
| **Microsoft ClrMD** | NuGet 3.1.x / .NET 10 | MIT License | Live managed runtime inspection (threads, heap, JIT) | x86, x64 | Out-of-process `Dracula.ManagedHost.exe` | `test_managed_backend.cpp` (PASS) | **ACCEPTED (Live Managed)** | Isolated C# host executable communicating via bounded JSON-RPC over stdio. Malformed assemblies cannot crash `Dracula.exe`. |
| **PE-sieve** | v0.3.7.1 (`hasherezade/pe-sieve`) | BSD-2-Clause | In-memory PE detection & hook/patch scanning | x86, x64 | Tool binary (`tools/pe-sieve64.exe`) + JSON adapter | `poc_qualification.cpp` (PASS) | **ACCEPTED (Tool Adapter)** | Qualified for memory replacement detection, process hollowing identification, and dump validation. |
| **libPEConv** | v0.3.x (`hasherezade/libpeconv`) | BSD-2-Clause | Memory PE normalization & dump reconstruction | x86, x64 | Tool adapter | Verified CLI adapter (PASS) | **OPTIONAL / DEFERRED** | Normalizes memory-mapped PE images back into disk-aligned PE structures. |
| **YARA** | v4.5.1 (`VirusTotal/yara`) | BSD-3-Clause | Rule-based signature evidence engine | x86, x64 | Tool binary (`tools/yara64.exe`) + rules | `poc_qualification.cpp` (PASS) | **ACCEPTED (Primary Engine)** | Selected as primary rule engine. Matches are attributed to Evidence Graph with source confidence. |
| **YARA-X** | v0.5.0 (`VirusTotal/yara-x`) | BSD-3-Clause | Next-generation Rust-based rule engine | x64 (Evaluated) | Evaluated Rust C-API | Verified schema compatibility (PASS) | **OPTIONAL / DEFERRED** | Modern rewrite; classic YARA 4 selected as active engine to avoid Rust runtime linking overhead on MinGW. |
| **Microsoft Detours** | 4.0.1 (`microsoft/Detours`) | MIT License | Targeted API inline hook fallback | x86, x64, ARM64 | Source evaluation | Evaluated against minimal agent (PASS) | **OPTIONAL / DEFERRED** | Lightweight inline hooking primitive; custom minimal agent satisfies in-process telemetry requirements. |
| **Frida Gum** | 16.x (`frida/frida-gum`) | LGPL-2.1 / wxWindows | Dynamic in-process instrumentation backend | x86, x64 | Dynamic adapter | Evaluated against minimal agent (PASS) | **OPTIONAL / DEFERRED** | Heavyweight runtime; Dracula Agent custom telemetry engine selected as primary to avoid 20MB+ footprint. |
| **DynamoRIO** | 10.x (`DynamoRIO/dynamorio`) | BSD-3-Clause | Deep dynamic binary instrumentation & block trace | x86, x64 | Standalone tool | Evaluated architecture (PASS) | **REJECTED (High Overhead)** | Heavy instrumentation overhead; Unicorn 2 CPU emulation and QEMU provide superior deterministic sandboxing. |
| **LIEF** | 0.14.x (`lief-project/LIEF`) | Apache-2.0 | Multi-format executable parsing abstraction | x86, x64 | C++ library | Evaluated against PeInspector (PASS) | **OPTIONAL / DEFERRED** | Dracula's zero-copy `PeInspector` is faster, bounds-checked, and self-contained without external dependencies. |

---

## Detailed Component Evaluations

### 1. SQLite (3.46.1 Amalgamation)
- **License**: Public Domain / Blessing
- **Provenance**: `sqlite.org/2024/sqlite-amalgamation-3460100.zip`
- **Role**: Structured persistence for sessions, evidence graph nodes, and function intelligence index in `%LOCALAPPDATA%\Dracula\`.

### 2. Zstandard (v1.5.6)
- **License**: BSD-3-Clause
- **Provenance**: `github.com/facebook/zstd/releases/tag/v1.5.6`
- **Role**: Memory snapshot compression and region delta diffing with throughput exceeding 1 GB/s.

### 3. DbgHelp vs DbgEng vs DIA SDK
- **DbgHelp**: Native OS DLL used for symbol resolution (`SymFromAddr`) and read-only process memory inspection (`ReadProcessMemory`).
- **DbgEng**: Microsoft COM debugging engine for active debugger control.
- **DIA SDK**: Microsoft PDB debug interface access for symbol and type hierarchy parsing.

### 4. Dracula Agent
- **Engine**: Custom Minimal Win32 Telemetry Instrumentation (`DraculaAgent64.dll`).
- **Capabilities**: In-process module enumeration, memory protection transition recording, named pipe IPC, bounded message queuing, clean attach/detach.
