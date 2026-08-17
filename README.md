# 🛡️ Dynamic Sandbox Tracer & Threat Intelligence Suite

A state-of-the-art, high-performance **C++20 & C Automated Sandbox Orchestrator**, **Dynamic Execution Tracer**, **Native CPU Instruction Emulator (Unicorn Engine 2)**, and **Malware Unpacking & Threat Assessment Engine**.

Designed to analyze, trace, and reverse-engineer untrusted Windows PE binaries inside fully isolated, hardware-accelerated environments with **zero persistent disk impact**.

---

## 📑 Table of Contents

- [Key Highlights](#-key-highlights)
- [Architecture Overview](#-architecture-overview)
- [System Components](#-system-components)
  - [1. QEMU Native Hardware Sandbox](#1-qemu-native-hardware-sandbox)
  - [2. In-Guest Telemetry Agent](#2-in-guest-telemetry-agent)
  - [3. Unicorn Engine 2 CPU Emulator](#3-unicorn-engine-2-cpu-emulator)
  - [4. Anti-Evasion & Unpacking Detection](#4-anti-evasion--unpacking-detection)
  - [5. Threat Scoring & MITRE ATT&CK Matrix](#5-threat-scoring--mitre-attck-matrix)
  - [6. Modular Dear ImGui Glassmorphic UI](#6-modular-dear-imgui-glassmorphic-ui)
- [Project Directory Layout](#-project-directory-layout)
- [Prerequisites & Toolchain](#-prerequisites--toolchain)
- [Build Instructions](#-build-instructions)
- [Quick Start Guide](#-quick-start-guide)
  - [Phase 1: Initial VM Setup](#phase-1-initial-vm-setup-one-time)
  - [Phase 2: Running Automated Dynamic Analysis](#phase-2-running-automated-dynamic-analysis)
  - [Phase 3: Running Unicorn CPU Emulation](#phase-3-running-unicorn-cpu-emulation)
  - [Phase 4: Live Process Memory Attachment & Emulation](#phase-4-live-process-memory-attachment--emulation)
- [Sample Analysis Report](#-sample-analysis-report)
- [Configuration & Customization](#-configuration--customization)
- [Security Disclaimer](#-security-disclaimer)

---

## 🌟 Key Highlights

* 🚀 **Zero-Touch Dynamic Isolation:** Executes binaries inside an isolated Windows 10 VM managed directly via QEMU with in-memory non-destructive delta (`-snapshot`). All filesystem, registry, and system changes vanish in **0 seconds** upon completion.
* ⚡ **Hardware Acceleration:** Native Windows Hypervisor Platform (**WHPX**) and TCG support for near-native execution speed.
* 📡 **Real-Time Live Telemetry Pipeline:** High-speed Winsock2 TCP streaming server transmits process spawns, network socket events, dropped files, and captured `stdout`/`stderr` from Guest to Host in real time.
* 🔍 **Native CPU Instruction Tracing:** Integrated **Unicorn Engine 2** parses PE headers, maps virtual memory, constructs shadow stacks, and single-steps x86_64 assembly with register logging (`RAX`, `RBX`, `RCX`, `RDX`, `RSP`, `RBP`, etc.) and memory write hooks.
* 🧩 **Unpacking & Anti-Analysis Detection:**
  * **Shannon Entropy Analysis:** Section-by-section mathematical entropy calculation ($H = -\sum p_i \log_2 p_i$) to spot encrypted/packed code.
  * **YARA 64 Integration:** Signature matching for popular packers (UPX, Themida, VMProtect, ASPack, PECompact, MPRESS, Enigma).
  * **Memory Forensics & Code Injection Hunting:** Pre-packaged with **PE-sieve 64** and **HollowsHunter 64** to automatically dump injected shellcode and unpacked payloads.
* 🎯 **Automated MITRE ATT&CK Mapping:** Classifies suspicious behavior into MITRE tactics and techniques with an automated threat score from 0 to 100.
* 🎨 **Modular Glassmorphism GUI:** DirectX 11 + Dear ImGui desktop dashboard with customizable fonts, graphs, and real-time telemetry feeds (decoupled via CMake option).

---

## 🏛️ Architecture Overview

```
                          ┌─────────────────────────────────────────────────────────┐
                          │                     HOST SYSTEM                         │
                          │                                                         │
                          │   ┌─────────────────────────────────────────────────┐   │
                          │   │               HostController.exe                │   │
                          │   │   • Target Staging                              │   │
                          │   │   • Live TCP Event Receiver (Port 8899)         │   │
                          │   │   • Threat Scorer & MITRE Matrix Generator      │   │
                          │   │   • Report Writer (sandbox_report.txt)          │   │
                          │   └───────────────┬─────────────────────────▲───────┘   │
                          │                   │                         │           │
                          │                   │ Starts Headless VM      │ TCP Stream│
                          │                   ▼                         │           │
                          │   ┌───────────────────────────────┐         │           │
                          │   │       QEMU Hypervisor         │         │           │
                          │   │   -M q35,accel=whpx           │         │           │
                          │   │   -snapshot (In-Memory Delta) │         │           │
                          │   │   -drive win10.vdi            │         │           │
                          │   └───────────────┬───────────────┘         │           │
                          └───────────────────┼─────────────────────────┼───────────┘
                                              │                         │
                                      VirtIO  │ Port Forward            │ 10.0.2.2:8899
                                              ▼                         │
                          ┌─────────────────────────────────────────────┴───────────┐
                          │                GUEST OS (WINDOWS 10 VM)                 │
                          │                                                         │
                          │   ┌─────────────────────────────────────────────────┐   │
                          │   │         auto_exec.bat / Startup Hook            │   │
                          │   │   • Auto-detects staged E:\target_sample.exe    │   │
                          │   └───────────────────────┬─────────────────────────┘   │
                          │                           │                             │
                          │                           ▼                             │
                          │   ┌─────────────────────────────────────────────────┐   │
                          │   │                GuestAgent.exe                   │   │
                          │   │   • Process Spawner (Pipe I/O Redirection)      │   │
                          │   │   • SystemTracer (Toolhelp32 Child Proc Tree)   │   │
                          │   │   • Network Watcher (GetExtendedTcpTable)       │   │
                          │   │   • File Monitor (ReadDirectoryChangesW)        │   │
                          │   │   • Memory Dumpers (PE-sieve, HollowsHunter)    │   │
                          │   └───────────────────────┬─────────────────────────┘   │
                          │                           │                             │
                          │                           ▼ Launches & Monitors         │
                          │               [ Target Executable (.exe) ]              │
                          └─────────────────────────────────────────────────────────┘
```

---

## ⚙️ System Components

### 1. QEMU Native Hardware Sandbox
* **Location:** `src/host/qemu_manager.cpp` | `include/host/qemu_manager.h`
* **Description:** Manages the lifecycle of headless/GUI QEMU virtual machine instances.
* **Key Features:**
  * Uses **Q35 chipset** with **EDK2 x86_64 UEFI firmware** and NVRAM support (`uefi_vars.fd`).
  * Enforces `-snapshot` mode so all guest writes are redirected to volatile RAM.
  * Mounts target staging storage via virtual FAT driver (`fat:ro:guest_share`).
  * Transparently terminates the VM and drops memory state when the analysis finishes.

### 2. In-Guest Telemetry Agent
* **Location:** `src/guest/main.cpp` | `src/guest/`
* **Description:** A statically linked Win32 background agent executing inside the guest environment.
* **Key Features:**
  * **Process Spawner:** Spawns the target process with redirected anonymous pipes to sniff console output (`stdout`/`stderr`).
  * **Process Tree Monitor:** Periodic snapshots via `CreateToolhelp32Snapshot` tracking spawned child processes and command-line arguments.
  * **Network Sniffer:** Polls active TCP sockets using `GetExtendedTcpTable` to detect outbound C2 connections.
  * **Filesystem Auditor:** Monitors filesystem modifications via `ReadDirectoryChangesW`.

### 3. Unicorn Engine 2 CPU Emulator
* **Location:** `src/core/unicorn_analyzer.cpp` | `include/core/unicorn_analyzer.h`
* **Description:** Static and instruction-level emulation module.
* **Key Features:**
  * Full PE32/PE32+ header parser (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS64`, `IMAGE_SECTION_HEADER`).
  * Maps executable sections into Unicorn virtual address space with accurate protection flags.
  * Allocates a 1 MB shadow stack (`RSP = 0x7FFF001FF000`).
  * Single-steps CPU execution, logging disassembly and full 64-bit general-purpose registers.
  * Memory hook (`UC_HOOK_MEM_WRITE`) tracks runtime memory modification.

### 4. Anti-Evasion & Unpacking Detection
* **Location:** `src/core/entropy_analyzer.cpp` | `rules/packers.yar`
* **Description:** Detects packers, crypters, and obfuscated payloads.
* **Key Features:**
  * Computes whole-file and per-section **Shannon Entropy** to identify compressed/encrypted sections.
  * Detects anomalous section permissions (e.g., `RWX` sections used in unpacking stubs).
  * Executes automated **YARA 64** rule scans against known packer signatures (UPX, Themida, VMProtect, ASPack, PECompact, MPRESS, Enigma).
  * Deploys **PE-sieve** and **HollowsHunter** within the guest to detect process hollowing and memory patches.

### 5. Threat Scoring & MITRE ATT&CK Matrix
* **Location:** `src/core/threat_evaluator.cpp`
* **Description:** Evaluates telemetry and static metrics to produce a threat score (0–100), security verdict, and MITRE mapping.
* **Mapped Tactics & Techniques:**
  * `T1027.002` - Software Packing (Defense Evasion)
  * `T1071.001` - Web Protocols / Outbound C2 Socket (Command and Control)
  * `T1059.003` - Windows Command Shell Execution (Execution)
  * `T1070` - Indicator Removal / Payload Staging in Temp Directory (Defense Evasion)
  * `T1547.001` - Registry Run Keys / Startup Folder Persistence (Persistence)

### 6. Modular Dear ImGui Glassmorphic UI
* **Location:** `src/gui/` | `include/gui/`
* **Description:** Hardware-accelerated (DirectX 11) Glassmorphism dashboard with dark mode styling, custom font loaders (`JetBrains Mono`, `Roboto`), live event tables, and register inspectors. Can be enabled via `-DBUILD_GUI=ON`.

### 7. Read-Only Live Process Inspector & Memory Buffer Emulator
* **Location:** `src/host/process_inspector.cpp` | `include/host/process_inspector.h`
* **Description:** Attaches to running host processes in strictly read-only mode (`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`).
* **Key Features:**
  * Enumerates running processes by name or PID using `CreateToolhelp32Snapshot`.
  * Resolves main module base address and image size via `EnumProcessModules` and `GetModuleInformation`.
  * Reads target virtual memory safely via `ReadProcessMemory`.
  * Passes memory buffers directly to `UnicornAnalyzer::EmulateBuffer` at their exact virtual address, preserving RIP-relative addressing and returning full `FunctionEmulationResult` diagnostics.
  * Guarantees non-invasive inspection with zero write permissions or thread creation in the target process.

---

## 📁 Project Directory Layout

```
jew/
├── .gitignore                      # Git ignore rules for build artifacts & temp files
├── CMakeLists.txt                  # Modular CMake configuration with target toggles
├── README.md                       # Comprehensive architecture & usage documentation
├── config/
│   └── config.ini                  # Unified configuration (QEMU, Network, Tracing, Tools)
├── rules/
│   └── packers.yar                 # YARA rules for packers & protectors detection
├── tools/                          # External host analysis binaries
│   ├── pe-sieve64.exe              # Process hollowing & memory dump utility
│   └── yara64.exe                  # Standalone YARA 64 scanner
├── samples/                        # Malware test samples & simulation harnesses
│   ├── test_sample.cpp             # Clean math & loop test binary
│   └── advanced_sample.cpp         # Dropped files, child process & C2 probe simulation
├── guest_share/                    # Clean VM shared staging folder
│   ├── auto_exec.bat               # In-guest boot auto-execution script
│   ├── setup_lab.bat               # Guest environment configuration script
│   ├── remove_password_and_autologin.bat # AutoLogon configuration script
│   └── tools/                      # In-guest Sysinternals & analysis tools
├── include/
│   ├── common/
│   │   ├── config.h                # Unified ConfigManager & INI parser
│   │   ├── protocol.h              # Length-prefixed binary-safe network protocol
│   │   └── types.h                 # Core structs (TraceEvent, AnalysisReport, etc.)
│   ├── core/
│   │   ├── analyzer_interface.h    # IAnalyzer abstract base class
│   │   ├── dynamic_vm_analyzer.h   # QEMU dynamic orchestration engine
│   │   ├── unicorn_analyzer.h      # Unicorn Engine 2 CPU emulator
│   │   ├── entropy_analyzer.h      # Shannon entropy & PE section auditor (32/64-bit)
│   │   ├── threat_evaluator.h      # Behavioral threat scoring & MITRE matrix
│   │   └── c_api.h                 # C FFI bindings (for Rust / Tauri integration)
│   ├── host/
│   │   ├── qemu_manager.h          # QEMU process controller with -snapshot
│   │   ├── live_tcp_server.h       # Non-blocking Winsock2 TCP telemetry receiver
│   │   ├── console_ui.h            # ANSI color console formatter
│   │   └── report_writer.h         # Advanced report generator
│   ├── guest/
│   │   ├── process_spawner.h       # Thread-safe child process spawner with pipes
│   │   ├── system_tracer.h         # Thread-safe process tree, file & network watcher
│   │   └── tcp_emitter.h           # In-guest TCP client emitter
│   ├── gui/
│   │   ├── glass_theme.h           # Glassmorphism dark-theme styling
│   │   └── gui_app.h               # Dear ImGui desktop dashboard
│   └── tools/                      # Dedicated memory inspector & reverse engineering headers
│       ├── game_offsets.h          # Single Source of Truth for offsets & signatures
│       ├── process_inspector.h     # Read-only memory & PE export inspector
│       └── injectable_api.h        # Injection Named Pipe protocol
├── src/
│   ├── common/
│   │   └── config.cpp              # INI configuration implementation
│   ├── core/                       # Core analysis engine implementations
│   ├── host/                       # Host controller and server implementations
│   ├── guest/                      # In-guest telemetry agent implementations
│   ├── gui/                        # ImGui DirectX 11 GUI implementations
│   └── tools/                      # Dedicated tools implementations
│       ├── external_offset_verifier.cpp
│       ├── external_overlay.cpp
│       └── injectable/
│           ├── injectable_dll.cpp
│           └── injectable_resource.rc
└── tests/
    └── test_emulate_buffer.cpp     # Standalone Unicorn CPU emulation unit tests
```

---

## 🔧 Prerequisites & Toolchain

* **Operating System:** Windows 10 / 11 (x86_64)
* **Compiler:** MinGW-W64 GCC 13.0+ / Clang with C++20 support
* **Build System:** CMake 3.20+ & MinGW Makefiles (`mingw32-make`)
* **Virtualization:** QEMU for Windows (`qemu-system-x86_64.exe` with WHPX feature enabled)
* **Disk Image:** A Windows 10 VDI/QCOW2 disk image (e.g., `D:\VirtualMachines\win10.vdi`)

---

## 🔨 Build Instructions

### 1. Build the CLI Orchestrator & Guest Agent (Fastest):
```powershell
# Configure CMake with MinGW Makefiles
cmake -B build -G "MinGW Makefiles" -DBUILD_GUI=OFF

# Compile all targets
cmake --build build
```

### 2. Build with Graphical User Interface (Dear ImGui + DirectX 11):
```powershell
cmake -B build -G "MinGW Makefiles" -DBUILD_GUI=ON
cmake --build build
```

---

## 🚀 Quick Start Guide

### Phase 1: Initial VM Setup (One-Time)

1. Convert or place your Windows 10 disk at `D:\VirtualMachines\win10.vdi`.
2. Launch the VM setup script:
   ```powershell
   .\launch_qemu_setup.bat
   ```
3. Inside the Windows 10 guest:
   * Open `This PC` and navigate to the mounted drive (`E:\` or `D:\`).
   * Right-click `setup_lab.bat` and choose **Run as Administrator**.
   * *(This installs tools to `C:\Sandbox`, sets up auto-login, removes passwords, and registers auto-execution on boot)*.
4. Shut down the VM (`Machine -> Quit`).

---

### Phase 2: Running Automated Dynamic Analysis

Run `HostController.exe` and pass the path of the binary you wish to inspect:

```powershell
.\build\HostController.exe advanced_sample.exe
```

1. Enter `1` to select **QEMU Native Hardware Sandbox**.
2. The orchestrator will:
   * Stage the binary into the guest shared drive.
   * Launch QEMU in the background with `-snapshot` and hardware acceleration.
   * Receive and print real-time live telemetry badges on your terminal.
   * Auto-terminate the VM on process exit, purging all guest modifications.
   * Write the comprehensive report to `sandbox_report.txt`.

---

### Phase 3: Running Unicorn CPU Emulation

To analyze execution at the CPU instruction and assembly level without launching a VM:

```powershell
.\build\HostController.exe test_sample.exe
```

1. Enter `2` to select **Unicorn CPU Emulation Engine**.
2. The engine parses the PE, maps sections, executes up to 1,000 instructions, logs every assembly instruction with live register states, and audits memory writes.

---

### Phase 4: Live Process Memory Attachment & Emulation

To attach to a running host process and emulate arbitrary memory regions offline in Unicorn:

```powershell
.\build\HostController.exe
```

1. Enter `3` to select **Attach to Running Process & Resolve Offsets (Read-Only, Live Memory)**.
2. Enter target process name (e.g., `explorer.exe`) or PID.
3. If multiple instances exist, select from the disambiguated list.
4. Specify hexadecimal or decimal function offset / virtual address and byte length.
5. The inspector reads memory bytes via `ReadProcessMemory` and executes them inside Unicorn at their real virtual base address with full RIP-relative correctness and diagnostics.

---

## 📊 Sample Analysis Report

Below is an excerpt from a generated `sandbox_report.txt`:

```text
================================================================================
                      SANDBOX ADVANCED ANALYSIS & THREAT REPORT                
================================================================================
Target Executable : advanced_sample.exe
Analysis Engine   : Dynamic QEMU Hardware Sandbox (Automated Snapshot Isolation)
Start Time        : 2026-08-16 19:57:58
End Time          : 2026-08-16 19:58:42
Exit Code         : 0
--------------------------------------------------------------------------------
SECURITY VERDICT & THREAT SCORING:
 [!] Final Threat Verdict : HIGH RISK - MALICIOUS
 [!] Threat Score         : 85 / 100
 [!] Packing / Crypter    : None (Native Binary) (Entropy: 5.59 / 8.00)
--------------------------------------------------------------------------------
ACTIVITY SUMMARY STATISTICS:
 - Processes Spawned   : 1
 - Files Modified      : 1
 - Network Connections : 1
 - Registry Changes    : 0
 - Total Events Logged : 19
================================================================================

PE SECTION ENTROPY & PACKER AUDIT:
--------------------------------------------------------------------------------
Section   VirtSize      RawSize       Entropy     Flags       Status
--------------------------------------------------------------------------------
.text     11392         11776         5.59        RX          NORMAL
.data     224           512           0.83        RW          NORMAL
.rdata    2384          2560          4.50        R           NORMAL
.idata    3932          4096          4.47        R           NORMAL
================================================================================

MITRE ATT&CK THREAT MATRIX MAPPING:
--------------------------------------------------------------------------------
 [T1071.001] Web Protocols / C2 Connection | Tactic: Command and Control | Outbound socket connect (8.8.8.8:53)
 [T1059.003] Windows Command Shell         | Tactic: Execution           | cmd.exe /c whoami
 [T1070    ] Indicator Removal / Staging   | Tactic: Defense Evasion     | Dropped payload in Temp directory
================================================================================

CHRONOLOGICAL RUNTIME EVENT LOG:
--------------------------------------------------------------------------------
[19:57:58] [QemuHost    ] Starting dynamic analysis session for: advanced_sample.exe
[19:57:58] [Network     ] Starting TCP Live Stream Receiver on port 8899
[19:57:58] [Sandbox     ] Staged target binary into guest_share/target_sample.exe
[19:57:58] [QEMU        ] Launching isolated QEMU sandbox with in-memory -snapshot protection...
[02:58:40] [GuestAgent  ] Guest Agent started execution of: E:\target_sample.exe
[02:58:40] [Process     ] Target Process Spawned (PID: 6416)
[02:58:40] [Stdout      ] [*] Advanced Sample Binary Started.
[02:58:40] [Stdout      ] [+] Created dropped file: C:\Users\User\AppData\Local\Temp\sandbox_dropped_payload.txt
[02:58:40] [Stdout      ] [+] Spawning Child Process (cmd.exe /c whoami)...
[02:58:41] [Network     ] Outbound TCP Connection to 8.8.8.8:53 (PID: 6416)
[02:58:42] [Process     ] Target Process Exited with Code: 0
[19:58:42] [QEMU        ] Stopping QEMU and discarding all sandbox disk modifications...
[19:58:42] [QemuHost    ] Sandbox session completed. System reverted to clean state in 0 seconds.
================================================================================
```

---

## ⚙️ Configuration & Customization

### Configuring Trace Options:
Modify `include/common/types.h`:
```cpp
struct TraceOptions {
    bool monitorConsoleOutput = true;      // Capture stdout / stderr
    bool monitorProcesses     = true;      // Track child processes
    bool monitorFiles         = true;      // Track filesystem activity
    bool monitorRegistry      = true;      // Track registry persistence
    bool monitorNetwork       = true;      // Track outbound TCP sockets
    uint32_t executionTimeoutSeconds = 60; // Max execution timeout
};
```

### Adding Custom YARA Signatures:
Add rules directly into `rules/packers.yar`:
```yara
rule Custom_Malware_Signature {
    strings:
        $sig = "SUSPICIOUS_MUTEX_NAME"
    condition:
        uint16(0) == 0x5A4D and any of them
}
```

---

## ⚠️ Security Disclaimer

This software is built for **educational, security research, and defensive threat analysis purposes only**. When analyzing live malware, always ensure execution takes place inside dedicated virtualized environments with network adapters configured according to your laboratory safety policies.
