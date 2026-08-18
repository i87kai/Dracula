# Dracula Third-Party Dependency Qualification Manifest

This document records the qualification, upstream provenance, pinned releases, licenses, architecture status, and architectural decisions for all third-party dependencies investigated for Dracula v1.2.0 Universal Target Runtime (UTR).

---

## Qualification Matrix Summary

| Dependency | Upstream / Pinned Version | License | Dracula Role | Arch Support | Build Method | Integration Status | Decision & Rationale |
|---|---|---|---|---|---|---|---|
| **Capstone** | 5.0.1 (`capstone-engine/capstone`) | BSD-3-Clause | Native disassembly & instruction decoding | x86, x64, ARM64 | Static C CMake submodule | **Core** | Preserved from v1.1.2. Proven, fast, thread-safe instruction decoder. |
| **Unicorn** | 2.0.1 (`unicorn-engine/unicorn`) | GPL-2.0 / LGPL-2.1 | CPU emulation & Win32 HLE | x86, x64 | Static C archive (`libunicorn.a`) | **Core** | Preserved from v1.1.2. Verified CPU instruction emulator and sandbox. |
| **SQLite** | 3.46.1 Amalgamation (`sqlite.org`) | Public Domain | Session database & evidence/function index | x86, x64, ARM64 | Vendored C amalgamation (`sqlite3.c`) | **Core** | Embeds directly into `DraculaCore` with zero external runtime dependencies. Tested byte-exact round-trip. |
| **Zstandard (zstd)** | 1.5.6 (`facebook/zstd`) | BSD-3-Clause | Memory snapshot compression & region deltas | x86, x64, ARM64 | Vendored C source library (`third_party/zstd`) | **Core** | Fast real-time compression with bounded memory limits. Verified lossless decompression round-trip. |
| **PE-sieve** | v0.3.x (`hasherezade/pe-sieve`) | BSD-2-Clause | In-memory PE detection & hook/patch scanning | x86, x64 | Tool binary (`tools/pe-sieve64.exe`) + JSON adapter | **Core Tool** | Qualified for memory replacement detection, process hollowing identification, and dump validation. |
| **libPEConv** | v0.3.x (`hasherezade/libpeconv`) | BSD-2-Clause | Memory PE normalization & dump reconstruct | x86, x64 | Adapter integration | **Core Adapter** | Normalizes memory-mapped PE images back into disk-aligned PE structures. |
| **YARA** | v4.5.x (`VirusTotal/yara`) | BSD-3-Clause | Rule-based signature evidence engine | x86, x64 | Tool binary (`tools/yara64.exe`) + rules | **Core Tool** | Selected as primary rule engine. Matches are attributed to Evidence Graph with source confidence. |
| **YARA-X** | v0.5.x (`VirusTotal/yara-x`) | BSD-3-Clause | Next-generation Rust-based rule engine | x64 (Evaluated) | Evaluated Rust C-API | **Evaluated** | Modern rewrite; classic YARA 4 selected as active engine to avoid Rust runtime linking overhead on MinGW. |
| **Microsoft DbgEng** | Windows SDK (`dbgeng.dll`, `dbghelp.dll`) | Microsoft SDK | User/Kernel debugging & target memory query | x86, x64, ARM64 | Dynamic DLL discovery + adapter | **Core Adapter** | Non-invasive attachment to live target processes. Uses OS-provided DLLs; zero proprietary redistributables committed. |
| **Microsoft DIA SDK** | Windows SDK (`msdia140.dll`) | Microsoft SDK | PDB symbol & type resolution | x86, x64 | COM activation + export table fallback | **Core Adapter** | Enriches Function Intelligence when PDBs exist without breaking analysis when absent. |
| **Windows ETW + TDH** | Windows Native APIs (`advapi32.dll`) | Microsoft OS API | Non-invasive external observation of events | x86, x64, ARM64 | Win32 API calls (`IExternalObserver`) | **Core Adapter** | Monitors process, thread, and module load events externally without DLL injection. |
| **Microsoft ClrMD** | NuGet 3.1.x / .NET 10 | MIT | Managed runtime inspection (threads, heap, types) | x86, x64 | Out-of-process `Dracula.ManagedHost.exe` | **Core Managed** | Isolated C# host executable communicating via bounded JSON-RPC over stdio. Malformed assemblies cannot crash `Dracula.exe`. |
| **System.Reflection.Metadata** | .NET 10 Built-in | MIT | Static managed metadata, types, methods, IL | x86, x64 | Out-of-process `Dracula.ManagedHost.exe` | **Core Managed** | Fast, zero-allocation managed PE metadata parsing for .NET assemblies. |
| **Microsoft Detours** | 4.0.1 (`microsoft/Detours`) | MIT | Targeted API hook fallback | x86, x64, ARM64 | Adapter in `DraculaAgent` | **Optional** | Lightweight inline hooking primitive for the transparent Dracula Agent. |
| **Frida Gum** | 16.x (`frida/frida-gum`) | LGPL-2.1 / wxWindows | Dynamic in-process instrumentation backend | x86, x64 | Optional adapter `FridaAgentBackend` | **Optional** | Evaluated behind adapter. Core UTR functions autonomously via Agent, ETW, and DbgEng. |
| **DynamoRIO** | 10.x (`DynamoRIO/dynamorio`) | BSD-3-Clause | Deep dynamic binary instrumentation & block trace | x86, x64 | Optional adapter `DynamoRioBackend` | **Optional** | Evaluated for deep instruction-level coverage; Unicorn 2 and QEMU remain primary trace backends. |
| **LIEF** | 0.14.x (`lief-project/LIEF`) | Apache-2.0 | Format abstraction & cross-validation | x86, x64 | Optional adapter `LiefAdapter` | **Optional** | Evaluated for PE cross-checking; Dracula's `PeInspector` remains authoritative primary parser. |

---

## Detailed Evaluation Reports

### 1. SQLite (Amalgamation 3.46.1)
- **Upstream**: https://www.sqlite.org/
- **License**: Public Domain / Blessing.
- **Why Dracula Uses It**: Provides ACID-compliant session indexing, function ranking persistence, timeline queries, and evidence search without requiring an external database server.
- **Verification**: Vendored `third_party/sqlite/sqlite3.c` and `sqlite3.h`. Verified memory and disk-backed database operations in isolated POC test.

### 2. Zstandard (v1.5.6)
- **Upstream**: https://github.com/facebook/zstd
- **License**: BSD 3-Clause.
- **Why Dracula Uses It**: Exceptional decompression speed (up to 1+ GB/s) and bounded memory usage for compressing memory regions and snapshot deltas.
- **Verification**: Vendored `third_party/zstd/`. Verified byte-exact compression and decompression round-trip on arbitrary binary buffers.

### 3. Microsoft DbgEng & DIA SDK
- **Upstream**: Microsoft Windows SDK.
- **License**: Microsoft Windows SDK EULA.
- **Why Dracula Uses It**: Standard Windows user-mode debugging and PDB symbol resolution.
- **Integration**: Dynamic runtime discovery via `LoadLibraryA` / COM `CoCreateInstance` behind `IDebugBackend` and `ISymbolProvider`.

### 4. Managed Runtime: ClrMD & System.Reflection.Metadata
- **Upstream**: .NET Foundation / Microsoft.
- **License**: MIT.
- **Why Dracula Uses It**: Native C++ cannot safely parse hostile or obfuscated .NET assemblies without risk of memory corruption. By hosting ClrMD and `System.Reflection.Metadata` in an isolated out-of-process `Dracula.ManagedHost.exe` with strict timeouts and resource limits, Dracula gains full .NET intelligence while maintaining 100% crash resilience.
