# Dracula Architecture & Design Principles

Dracula is designed around three foundational principles that distinguish it from traditional disassemblers and sandboxes:

```
┌────────────────────────────────────────────────────────┐
│                        DRACULA                         │
│  "ONE PROJECT, ONE TARGET CONTEXT, ONE EVIDENCE MODEL" │
└────────────────────────────────────────────────────────┘
```

---

## 1. The Three Architectural Pillars

### Pillar 1: ONE PROJECT (Durable Workspaces)
Traditional debuggers and disassemblers maintain ephemeral in-memory state that evaporates upon process termination. Dracula treats every target as a durable project on disk (`<InstallRoot>\projects\<name>\`):
* The sample binary is copied immutably into the project.
* Static headers, section dumps, and hashes are computed once and stored.
* Memory snapshots, disassembly listings, and CFG structures are persisted.
* Dynamic event timelines and findings are committed to project SQLite databases.

### Pillar 2: ONE TARGET CONTEXT (Universal Target Runtime)
Whether an analyst is inspecting an on-disk `.exe`, a live running PID (`/process attach`), a `.NET` assembly (`/dotnet`), a loaded dynamic link library (`/dll`), or a kernel driver (`/driver`), the target model remains unified:
* Commands resolve their subject from the active target context automatically.
* Attached live processes mirror their backing disk image for seamless static inspection.

### Pillar 3: ONE EVIDENCE MODEL (Provenance Verification)
Every assertion made by Dracula carries rigorous verification metadata:
* `[CALCULATED]`: Mathematically derived from static image data (e.g. Shannon entropy, hash digests).
* `[RESOLVED]`: Reconstructed through static symbol resolution or heuristic decompilation (e.g. CFG branch influence, imported function RVAs).
* `[LIVE-READ VERIFIED]`: Directly inspected from live virtual memory, kernel ETW telemetry, or QEMU hypervisor readback.

---

## 2. Component Layering

```
┌──────────────────────────────────────────────────────────────────────────┐
│                             PRESENTATION                                 │
│      Terminal UI (REPL)      │      MCP stdio Server      │  (Future)    │
│  InteractiveScreen, Palette  │      JSON-RPC 2.0 Engine   │  Local Web   │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼──────────────────────────────────────┐
│                        APPLICATION SERVICE LAYER                         │
│   ProjectService   TargetService   MemoryService   AnalysisServices     │
│   SandboxService   UpdateService   Settings        HtmlReportWriter      │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼──────────────────────────────────────┐
│                    UNIVERSAL TARGET RUNTIME (UTR)                        │
│   FileTarget   ProcessTarget   ManagedTarget   DriverTarget   DllHarness │
│   EvidenceGraph   MemoryIntelligence   FunctionIntelligence              │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼──────────────────────────────────────┐
│                      CORE ENGINES & HARDWARE HYPERVISOR                  │
│   Capstone 5.0.1 (Disassembly)      │   Unicorn 2 (CPU Emulation)        │
│   DbgEng / DbgHelp (Native Debug)   │   QEMU x86_64 Hypervisor           │
│   SQLite3 (Artifact Persistence)    │   Zstandard (Chunked Compression)  │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Strict Boundary: Presentation vs Services

Dracula enforces a strict architectural boundary: **Engine and service layers return pure data DTOs and `CommandResult` structs without terminal escape codes, ANSI colors, or UI formatting.**

This decoupling ensures that:
1. The interactive terminal can format outputs with dynamic ANSI colors and responsive widths.
2. The MCP server can serialize pure JSON payloads for LLM assistants without ANSI corruption.
3. Future presentation adapters (such as the planned Local Web GUI) can consume the exact same service interfaces without modifying a single line of reverse-engineering logic.
