# 🧛 DRACULA — Unified Binary Intelligence Platform

[![CI](https://github.com/i87kxxz/Dracula/actions/workflows/ci.yml/badge.svg)](https://github.com/i87kxxz/Dracula/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/i87kxxz/Dracula?style=flat-square&color=ff79c6)](https://github.com/i87kxxz/Dracula/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat-square)](https://www.gnu.org/licenses/gpl-3.0)
[![Target: Windows x64](https://img.shields.io/badge/Platform-Windows%20x64-8be9fd.svg?style=flat-square)]()
[![MCP Server](https://img.shields.io/badge/MCP-JSON--RPC%202.0-50fa7b.svg?style=flat-square)]()

> **"ONE PROJECT. ONE TARGET CONTEXT. ONE EVIDENCE MODEL."**

**Dracula** is a high-performance, modular reverse engineering and binary analysis platform for Windows x64. It unifies static file parsing, CPU emulation, live process debugging, memory forensics, kernel driver inspection, managed .NET runtime analysis, and disposable QEMU VM sandboxing into a single, project-backed architecture.

---

## ⚡ Key Highlights

* 📁 **Durable Project Workspaces**: Every sample creates a durable workspace (`<Root>\projects\<name>`) preserving unpacked memory dumps, static hashes, call graphs, disassembly, HTML reports, and timeline events across shell sessions.
* 🎯 **Universal Target Runtime (UTR)**: Seamlessly switch between PE files on disk, live processes (`/process attach`), .NET managed assemblies (`/dotnet`), DLL exports, and kernel drivers with consistent inspection commands.
* 🛡️ **Defensive Evidence Model**: Every discovery carries explicit verification tags (`CALCULATED`, `RESOLVED`, `LIVE-READ VERIFIED`) with full cryptographic provenance.
* 🧠 **Native Model Context Protocol (MCP)**: Built-in stdio MCP server (`drac --mcp`) enabling direct pair-programming and automated threat analysis from Claude, Antigravity, and Cursor.
* 📦 **Disposable Sandbox & `.draculaimg`**: Streaming, chunked Zstandard VM package format with immutable base images and copy-on-write QEMU overlays for automated live dynamic analysis.
* 🖥️ **Terminal User Interface**: Responsive, interactive terminal REPL with command palettes, scrollable output viewports, mouse text selection, and syntax highlighting.

---

## 📥 Quick Installation

### Option 1: One-Line PowerShell Bootstrap (Recommended)
Open PowerShell (no Administrator privileges required) and run:

```powershell
irm https://raw.githubusercontent.com/i87kxxz/Dracula/main/scripts/bootstrap.ps1 | iex
```

### Option 2: Manual Zip Release
1. Download `Dracula-v1.3.1-windows-x64.zip` and `.sha256` from [GitHub Releases](https://github.com/i87kxxz/Dracula/releases/latest).
2. Verify checksum and extract:
   ```powershell
   Expand-Archive -LiteralPath .\Dracula-v1.3.1-windows-x64.zip -DestinationPath C:\Dracula
   powershell -ExecutionPolicy Bypass -File C:\Dracula\scripts\install.ps1
   ```
3. Run `drac` from any terminal.

---

## 🚀 Quick Start Guide

### Launching Dracula
Simply type `drac` in your terminal:
```powershell
drac
```

### Analyzing a File
```dracula
drac> /analyze samples\malware_sample.exe
drac> /headers
drac> /security
drac> /imports
drac> /findings
drac> /report html
```

### Attaching to a Live Process
```dracula
drac> /process attach 4812
drac> /memory map
drac> /memory snapshot "Before Payload Injected"
drac> /disasm 0x00007FF6A1B01000 32
```

### Inspecting a .NET Assembly
```dracula
drac> /dotnet types
drac> /dotnet methods
drac> /dotnet pinvoke
```

---

## 🧭 Command Overview

| Category | Primary Commands | Description |
|---|---|---|
| **Analysis** | `/analyze`, `/static`, `/entropy`, `/antievasion`, `/scan` | Full pipeline static analysis, Shannon entropy, packer detection, pattern scanning. |
| **Inspection** | `/disasm`, `/headers`, `/security`, `/imports`, `/exports`, `/strings`, `/functions`, `/cfg`, `/xrefs` | Capstone disassembly, PE header auditing, control-flow graph construction, string classification. |
| **Universal Target** | `/target`, `/process`, `/memory`, `/dotnet`, `/dll`, `/driver` | Live process debugging, memory snapshotting and differential analysis, .NET metadata inspection. |
| **Emulation** | `/emulate` | Lightweight Unicorn 2 CPU emulation with Win32 HLE API hooks. |
| **Sandbox** | `/sandbox` | Isolated QEMU hypervisor management, base image restore, overlay sweeping. |
| **Session** | `/project`, `/session`, `/findings`, `/report`, `/artifacts` | Project management, self-contained standalone HTML report generation. |
| **System** | `/settings`, `/update`, `/about`, `/mcp`, `/version`, `/help`, `/clear`, `/exit` | User preferences, in-place software updater, MCP server, interactive help. |

---

## 🤖 AI Assistant Integration (MCP Server)

Dracula includes a native **Model Context Protocol (MCP)** server over stdio. Connect Dracula directly to your AI IDE (Claude Desktop, Antigravity, Cursor) by adding it to your `mcpServers` configuration:

```json
{
  "mcpServers": {
    "dracula": {
      "command": "drac.exe",
      "args": ["--mcp"]
    }
  }
}
```

---

## 📚 Complete Documentation

* [Getting Started Guide](docs/getting-started.md)
* [Installation & Deployment](docs/installation.md)
* [Architecture & Design Principles](docs/architecture.md)
* [Durable Projects & Evidence Graph](docs/projects.md)
* [Interactive CLI & Commands](docs/cli.md)
* [Disposable VM Sandbox](docs/sandbox.md)
* [.draculaimg Container Format](docs/draculaimg.md)
* [Model Context Protocol (MCP)](docs/mcp.md)
* [Building from Source](docs/building.md)
* [Troubleshooting & Diagnostics](docs/troubleshooting.md)
* [Project Roadmap](docs/roadmap.md)

---

## 📜 License & Acknowledgments

Dracula is licensed under the **GNU General Public License v3.0 (GPL-3.0-only)**. See [`LICENSE`](LICENSE) for complete terms.

Third-party notices and open-source licenses are detailed in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
