# Installation & Deployment Guide

This guide covers installing, updating, repairing, and uninstalling Dracula.

---

## System Requirements

* **Operating System**: Windows 10 / 11 (64-bit) or Windows Server 2019+
* **Processor**: x86_64 CPU with hardware virtualization support (Intel VT-x / AMD-V recommended for QEMU sandbox)
* **RAM**: 4 GB minimum (8 GB+ recommended for VM sandboxing)
* **Disk Space**: ~50 MB for core binaries; ~20 GB if hosting `.draculaimg` local analysis VM bases.

---

## 1. Web Bootstrap Installation (Recommended)

Run the following command in PowerShell:

```powershell
irm https://raw.githubusercontent.com/i87kxxz/Dracula/main/scripts/bootstrap.ps1 | iex
```

The bootstrap installer:
1. Downloads the latest verified release archive from GitHub.
2. Validates the SHA-256 cryptographic signature.
3. Interactive drive selection displaying real available disk space.
4. Initializes the workspace directory structure.
5. Adds `<InstallRoot>\bin` to your user `PATH` environment variable without requiring Administrator privileges.

---

## 2. Offline / Manual Installation

1. Download `Dracula-v1.3.1-windows-x64.zip` and `Dracula-v1.3.1-windows-x64.zip.sha256`.
2. Extract the archive:
   ```powershell
   Expand-Archive .\Dracula-v1.3.1-windows-x64.zip -DestinationPath C:\Dracula
   ```
3. Run the installer script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\Dracula\scripts\install.ps1 -InstallRoot C:\Dracula
   ```

---

## 3. Updating Dracula

### From within Dracula REPL:
```dracula
drac> /update check
drac> /update install
```

### Via PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\update.ps1
```

---

## 4. Uninstalling Dracula

To remove Dracula binaries and environment variables while preserving your user project workspaces:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1
```

To purge all projects and logs as well:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall.ps1 -PurgeProjects
```
