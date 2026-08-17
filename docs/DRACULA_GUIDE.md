# 🧛 DRACULA BINARY INTELLIGENCE & REVERSE-ENGINEERING PLATFORM
## Technical Architecture & Developer Guide (v1.1.0)

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
- **Evasion evidence is weighted by context.** On its own, anti-evasion evidence is
  halved and hard-capped at 15 points, so no amount of virtualization detection can
  carry a verdict by itself. Alongside independent malicious evidence it counts in
  full (capped at 25), because that is when evading analysis is meaningful.

---

## 2.8 Anti-Evasion Intelligence Engine (`AntiEvasionEngine`)

The engine answers a chain of questions, and keeps the answers separable so a
report never blurs what was *seen* into what was *guessed*:

```
What anti-analysis technique exists?      -> static detection
Where is it?                              -> RVA, function, basic block
How was it detected?                      -> evidence kind, per item
What is being inspected?                  -> environment property
Did it influence control flow?            -> provenance
Did behaviour change elsewhere?           -> differential execution
How confident are we?                     -> corroboration, not enthusiasm
```

### 2.8.1 Static Anti-Evasion Detection

Three independent sources, deliberately weighted very differently:

| Source | What it finds | Confidence ceiling |
|---|---|---|
| **Capstone linear sweep** of every executable section | `CPUID`, `RDTSC`, `RDTSCP`, `SIDT`, `SGDT`, `SLDT`, `STR`, `SMSW`, hypervisor backdoor port I/O | High, but only when the result reaches a compare **and** a conditional branch |
| **Imports** matched against a rule table | Timing, topology, memory, disk, firmware, device, registry, process, user-activity and debugger APIs | Medium for the handful rarely called except to fingerprint; Low otherwise |
| **Strings** matched against the artifact rule table | Vendor names, guest processes, drivers, services, device ids, registry keys, MAC prefixes, analysis tooling | Low — a bare string is close to no evidence at all |

For `CPUID` the engine recovers the **input leaf** by scanning backwards for the
constant loaded into `EAX`, then classifies accordingly: leaf 1 is a hypervisor-
presence check, `0x40000000` is a hypervisor vendor check, leaf `0xB`/`0x1F`/`4`
is topology. It never claims more precision than the recovered dataflow supports.

The forward scan continues past `call` instructions, because
`call IsDebuggerPresent; test al, al; je` is one of the most common gate shapes
there is and stopping at the call would miss every one of them. It stops at
`ret`, because the scan is intraprocedural.

### 2.8.2 Environment Profiles (`EnvironmentProfile`)

One place decides everything a sample can observe about its host. Nothing else
in the tree is allowed to invent an environment value.

| Profile | Hypervisor bit | Topology / RAM | Clock | Device & firmware |
|---|---|---|---|---|
| **Baseline** | set | 2 CPUs / 4 GB | frozen; `Sleep` is a no-op | QEMU disk, QEMU firmware, `52:54:00` |
| **Realistic** | **set** | 8 CPUs / 32 GB | advances; sleeps elapse | unchanged — evidence is *not* suppressed |
| **AnalysisFriendly** | clear | 8 CPUs / 32 GB | advances; sleeps elapse | Samsung SSD, AMI firmware, `3C:7C:3F` |

`Baseline` reproduces Dracula's historical behaviour and is honest about being
an analysis environment. `Realistic` makes the machine *ordinary*, not *lying*.
Only `AnalysisFriendly` normalizes indicators, and every one of them lands in
the audit trail.

### 2.8.3 Timing Model (`VirtualTimeState`)

Sophisticated samples do not read one clock; they read several and compare them.
An environment that advances `GetTickCount` by 5000 ms while `RDTSC` advances by
two cycles has announced exactly what it is.

So there is exactly **one** authoritative quantity — a logical nanosecond
counter — and every exposed clock is derived from it:

```
logical nanoseconds
├── RDTSC / RDTSCP              nanos * tscHz / 1e9 + tscBase
├── QueryPerformanceCounter     nanos * qpcHz / 1e9
├── GetTickCount / 64           nanos / 1e6 + tickBase
└── uptime                      nanos / 1e6 + bootUptime
```

The clocks *cannot* disagree; there is no second counter that could drift.
Logical time advances from two things only: instructions retiring, and explicit
advances such as an accelerated `Sleep`. Explicit advances are recorded.

### 2.8.4 CPUID Model

`CPUID` is answered from the active profile through Unicorn's instruction hook
rather than by whatever the emulator's own CPU model happens to report, which
makes runs reproducible and every answer attributable to a profile.

| Leaf | Answered with |
|---|---|
| `0` | max basic leaf, vendor string |
| `1` | family/model/stepping, logical processor count in `EBX[23:16]`, hypervisor bit in `ECX[31]` |
| `4`, `0xB` | topology / cache parameters |
| `0x40000000` | hypervisor vendor signature — or nothing at all, when the profile does not expose it |
| `0x80000002-4` | brand string |

`RDTSC` and `RDTSCP` have no Unicorn instruction hook, so their encodings are
recognised in the code hook, the registers are filled from the virtual clock,
and the program counter is stepped past the instruction. Descriptor-table reads
(`SIDT`/`SGDT`/`SLDT`/`STR`/`SMSW`) are **recorded as evidence and left to
execute natively** — Dracula models what they reveal, it does not fabricate
descriptor tables it cannot honestly produce.

### 2.8.5 Branch Influence Attribution (`BranchInfluenceTracker`)

The single most important distinction in the engine:

```
environment info merely collected   vs   environment info controls execution
```

A bounded, register-granular provenance tracker follows a value from the
instruction or API that produced it, through data movement and a small stack-spill
and output-buffer map, into the compare that sets the flags and the conditional
branch that reads them.

It is **not** a full dynamic taint engine, and does not pretend to be. Anything
it cannot follow — arbitrary memory, SIMD, indirect control flow — simply drops
the mark. It under-reports rather than guessing, because an over-eager
attribution would inflate confidence, which is the one thing this engine must
never do. A write from an untainted source *clears* the mark.

Because many environment APIs answer by filling a caller-supplied structure
rather than returning a value, handlers declare the output buffer they wrote, and
a later load out of that region carries the provenance into the destination
register. That is how a `GetSystemInfo` processor count reaches its branch.

### 2.8.6 Differential Execution

```
Run A — Baseline           Run B — Realistic         Run C — AnalysisFriendly
        └──────────────────────────┴─────────────────────────┘
                                   ▼
                            ExecutionDelta
        basic blocks · functions · branch directions · HLE calls
        instruction count · termination reason · behaviour fingerprint
```

Coverage is recorded as **sets and counters**, never as a list of every executed
address, so a multi-million-instruction run costs a bounded amount of memory.
Each run also produces a deterministic `BehaviorFingerprint` (FNV-1a over
coverage, API sequence and termination) that is stable enough for regression
tests.

`BranchDivergence` records name the exact RVA that went the other way, what each
path led to, and — when provenance attributed it — which environment property
decided it.

### 2.8.7 Environment Consistency Graph

A naive sandbox hides one VM marker while exposing ten contradictory ones, which
makes it *more* identifiable, not less: real hardware never contradicts itself.

Environment facts are modelled as **claims** made by a particular observable
channel (`CPUID`, OS API, firmware table, device metadata, timing model). Two
channels disagreeing about the same property is a contradiction, reported as
`PROFILE_COHERENCE_WARNING`. Detected contradictions include:

- hypervisor bit cleared while leaf `0x40000000` still answers *(critical)*
- CPUID topology disagreeing with the OS processor count
- a physical-looking profile still exposing QEMU firmware, disk or MAC
- a frozen clock on a profile that presents as real hardware
- a zero-frequency timing source
- an "ordinary desktop" that models no user input activity at all

**Fingerprintability (0-100)** counts visible virtualization markers, then adds
a heavier penalty for each contradiction. Every shipped profile validates clean.

### 2.8.8 Environment Sensitivity Score

Separate from the malware threat score, and measuring a different thing:

> How strongly did behaviour change when analysis-environment variables changed?

| Input | Contribution |
|---|---|
| Static techniques (gated, high confidence) | 6 each, **capped at 25 in total** |
| Static techniques (medium confidence) | 2 each, within the same cap |
| Branch that changed direction, attributed | 20 each |
| Branch that changed direction, unattributed | 12 each |
| Basic blocks reached in only one run | 2 each, capped at 20 |
| Functions reached in only one run | 4 each, capped at 20 |
| Different termination reason | 15 |
| APIs called in only one run | 3 each, capped at 12 |

Clamped to 0-100. Bands: `0` None · `1-19` Minimal · `20-44` Weak ·
`45-74` Clear · `75-100` Strong.

Static detection is capped at 25 on purpose: **finding a check is not the same
as watching it fire.** A high score does not mean malicious.

### 2.8.9 Supported Detections

| Technique | Statically detectable | Unicorn modelled | QEMU observable | Differentially verifiable |
|---|---|---|---|---|
| CPUID hypervisor bit | ✅ | ✅ | ✅ | ✅ |
| CPUID hypervisor vendor leaf | ✅ | ✅ | ✅ | ✅ |
| CPUID topology / vendor / brand | ✅ | ✅ | ✅ | ✅ |
| RDTSC / RDTSCP timing deltas | ✅ | ✅ | ✅ | ✅ |
| Tick count / QPC timing gates | ✅ | ✅ | ✅ | ✅ |
| Sleep-elapsed gates | ✅ | ✅ | ✅ | ✅ |
| Processor count / memory / disk size | ✅ | ✅ | ✅ | ✅ |
| Screen dimensions, input activity | ✅ | ✅ | ✅ | ✅ |
| Firmware / SMBIOS strings | ✅ | ✅ (modelled) | ✅ | ✅ |
| Registry virtualization keys | ✅ | ✅ (modelled) | ✅ | ✅ |
| `IsDebuggerPresent`, PEB `BeingDebugged` | ✅ | ✅ | ✅ | policy-driven |
| MAC OUI, device & driver names | ✅ | partial (modelled values) | ✅ | partial |
| Process / service enumeration | ✅ (imports, strings) | ❌ not modelled | ✅ | ❌ |
| `SIDT`/`SGDT`/`SLDT`/`STR`/`SMSW` | ✅ | observed only, not fabricated | ✅ | ❌ |
| Exception-based anti-debug | ✅ | ❌ not modelled | ✅ | ❌ |
| Hardware breakpoint (DR register) checks | ✅ (imports) | ❌ not modelled | ✅ | ❌ |

### 2.8.10 Limitations

Stated plainly, because a tool that overstates its reach is worse than one that
does less:

- **No virtual environment can be made indistinguishable from physical
  hardware.** Dracula reports what its environments expose; it does not hide them.
- Static branch correlation is **intraprocedural**. Cross-function gates are
  caught by dynamic provenance, not by the static scan.
- Provenance is register-granular with a bounded spill and output-buffer map. It
  drops what it cannot follow.
- Windows exception semantics are not modelled in Unicorn; exception-based
  anti-debug is reported as *detected statically* and never as *modelled*.
- Process, service and driver enumeration is modelled as profile data, not as a
  working Toolhelp/Service Control Manager implementation.
- Differential execution is bounded: a fixed profile count, instruction budget
  and time budget per run, with **no adaptive rerun loop**.

---

## 2.9 Sandbox Telemetry Networking

### 2.9.1 Roles

Keeping the two roles straight is what makes the port question simple:

```
        HOST                                   GUEST
   ┌──────────────┐                      ┌──────────────┐
   │ LiveTcpServer│  ◄──── connects ──── │  GuestAgent  │
   │   LISTENS    │      outbound to     │    DIALS     │
   │  0.0.0.0:P   │       10.0.2.2:P     │     OUT      │
   └──────────────┘                      └──────────────┘
```

`10.0.2.2` is the gateway alias QEMU's SLIRP user-mode networking gives every
guest for reaching the host. Because traffic only ever flows outbound, **no
inbound port forwarding is required**, and `hostfwd` is deliberately absent from
the QEMU command line.

> This was the bug. Dracula bound host port 8899 for its listener and then asked
> QEMU to forward the same host port inbound. QEMU could not bind a port Dracula
> already held, so it printed `Could not set up host forwarding rule` and exited
> about a second after launch. The guest never booted. The forwarding rule was
> never needed for anything.

### 2.9.2 Port allocation

Allocation is **bind-and-hold**: the port is claimed by a real `bind()` and the
live socket is handed to the listener, so there is no check-then-bind window for
another process to slip through, and the caller learns the port that was
*actually* bound rather than the one requested.

| Strategy | Behaviour |
|---|---|
| `fixed` | Use exactly `host_listen_port`, or fail with the reason |
| `preferred-then-range` | *(default)* Try `host_listen_port`, then scan the range, then fall back to an OS-assigned port |
| `ephemeral` | Let the OS assign any free port |

The default prefers the configured port so a guest image provisioned with a
fixed port keeps working, and Dracula only moves when that port is genuinely
taken.

The listening socket uses **`SO_EXCLUSIVEADDRUSE`, not `SO_REUSEADDR`**. On
Windows `SO_REUSEADDR` lets a second socket bind an address another socket is
already using, which is exactly the collision this code exists to detect;
exclusive use turns a conflict into an honest, reportable failure.

### 2.9.3 Startup order

The ordering is load bearing, because QEMU snapshots the shared folder into a
read-only FAT drive at launch:

```
1. bind the listener        -> only now is the real port known
2. stage the sample AND
   write dracula_session.ini -> the guest can only see what exists at launch
3. launch QEMU               -> nothing here binds a host port
4. wait                      -> connect budget, then execution budget
5. terminate QEMU            -> in-memory snapshot delta discarded
```

`dracula_session.ini` carries the host address and the port that was actually
bound. GuestAgent prefers an explicit `--host-port` argument and falls back to
this file, so both new and already-provisioned guests work.

### 2.9.4 Timeouts

Two independent budgets, because booting and running are different things:

* **connect budget** (`guest_connect_timeout_seconds`, default 240s) covers
  guest boot and auto-login, measured from launch.
* **execution budget** (`execution_timeout_seconds`) covers the sample itself and
  only starts once the agent is on the line.

Sharing one budget meant a 60 second execution limit silently capping a four
minute boot.

### 2.9.5 Wire format

Packet framing is a `PacketHeader` (magic, payload length, event type,
timestamp) followed by the payload. The host accepts **two payload encodings**:

* **binary** — length-prefixed fields, with `pid` and process name as optional
  trailing fields so an older agent that omits them still decodes;
* **legacy text** — `type|timestamp|category|message|details`, which agents
  deployed into existing guest images still emit.

The framing is identical in both, so a legacy agent's events arrive perfectly
framed and would otherwise decode to nothing at all — which looks exactly like a
silent guest. Legacy sequential event-type numbers are mapped onto the current
enum as part of that path.

### 2.9.6 Diagnostics

The session reports bytes on the wire, events decoded and framing
resynchronisations separately, because "the agent sent nothing" and "the agent
sent something the host could not decode" are very different faults that
otherwise look identical.

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
| `/antievasion [file] [--compare]` | Detect and analyze anti-VM / anti-sandbox behavior. Aliases: `/antivm`, `/evasion`, `/ae` | `/antievasion --compare` |
| `/findings` | Display structured findings for active session | `/findings` |
| `/report [json\|md\|txt] [out]` | Export session report to disk | `/report json out.json` |
| `/session` | View current active sample metadata | `/session` |
| `/mcp` | Launch Model Context Protocol (MCP) server | `/mcp` |
| `/help` | Print interactive command reference | `/help` |
| `/exit` | Terminate Dracula session | `/exit` |

### CLI Non-Interactive Flags

```powershell
Dracula.exe --analyze <path/to/binary.exe>
Dracula.exe --anti-evasion <path/to/binary.exe>
Dracula.exe --anti-evasion <path/to/binary.exe> --compare
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
- `analyze_file`: Full static + entropy + emulation pipeline returning unified JSON report. Includes a cheap static anti-evasion summary; differential execution is deliberately **not** run here because it is expensive and must be asked for.
- `analyze_anti_evasion`: Focused anti-evasion analysis. Pass `compare: true` to run the sample under multiple controlled environment profiles and prove whether behaviour actually changes. Returns structured techniques, differential runs, branch divergences and the normalization audit trail.
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
