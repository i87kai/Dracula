# Troubleshooting & Diagnostics

Common issues, diagnostics, and remediation steps when running Dracula.

---

## 1. Terminal Display & Unicode Artifacts

### Issue: Terminal displays broken characters or misaligned boxes
* **Cause**: The terminal host does not support UTF-8 Braille glyphs (U+2800–U+28FF) or ANSI truecolor escape sequences.
* **Remediation**:
  - Use **Windows Terminal** or **VS Code Integrated Terminal**.
  - Launch with `--no-unicode` to force ASCII box drawings:
    ```powershell
    drac --no-unicode
    ```
  - Launch with `--no-color` to disable ANSI colors:
    ```powershell
    drac --no-color
    ```

---

## 2. Command Palette / Execution Errors

### Issue: "file does not exist: --pid 1234"
* **Remediation**: Use `/process attach <pid>` instead of `/target --pid <pid>`.

### Issue: Permission Denied during `/process attach`
* **Cause**: Target process is running at higher integrity level (Administrator / SYSTEM) or protected by Antivirus/EDR.
* **Remediation**: Run PowerShell / Terminal as Administrator before attaching.

---

## 3. QEMU Sandbox Failures

### Issue: "QEMU binary not found"
* **Cause**: `qemu-system-x86_64.exe` is not installed or not in PATH.
* **Remediation**: Install QEMU for Windows and add its directory to your system PATH, or place it inside `<InstallRoot>\tools\qemu\`.

### Issue: Stale or locked overlay files
* **Remediation**: Run `/sandbox overlays clean` or `/sandbox reset`.
