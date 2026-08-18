# Dracula Project Roadmap

This document outlines the strategic roadmap and future milestones for the Dracula platform.

---

## 🎯 v1.3.x — Open Source Release & Ecosystem Foundation (Current)
* [x] Authoritative single version source (`v1.3.1`).
* [x] Auto-update subsystem with WinINet GitHub API integration and SHA-256 verification.
* [x] Standardized installer (`scripts/install.ps1`) and web bootstrap (`scripts/bootstrap.ps1`).
* [x] Zero hardcoded personal paths across repository.
* [x] Comprehensive documentation suite and GPL v3.0 license.
* [x] Continuous Integration (CI) and automated release packaging workflows.

---

## 🚀 Future Milestones

### Milestone 1: Local Web GUI Architecture (Planned)
* **Design Goal**: A lightweight, standalone web interface running locally on `127.0.0.1`.
* **Zero Engine Rewrite**: The web interface will consume the existing `App::*` and `UTR::*` service layer via clean JSON-RPC / WebSocket endpoints.
* **Features**: Interactive CFG graph explorer, memory diff visualizer, real-time sandbox execution timeline, and YARA signature editor.

### Milestone 2: Advanced Brain Intelligence Models
* Utilization of `<InstallRoot>\brain\` workspace for offline machine-learning based function classification and malware lineage similarity clustering.

### Milestone 3: Cross-Platform Target Expansion
* Extended support for ELF x86_64, Mach-O binaries, and cross-platform remote QEMU targets.
