# Getting Started with Dracula

This guide walks you through your first analysis session with Dracula.

---

## 1. Launching the Interactive Shell

After installation, launch Dracula from your terminal:

```powershell
drac
```

On first launch without arguments, Dracula displays the startup picker allowing you to:
1. Open a target executable for analysis
2. Attach to a running process by PID
3. Continue a saved project workspace
4. Enter the direct interactive shell

---

## 2. Basic Static Analysis Workflow

To analyze an executable file:

```dracula
drac> /analyze samples\sample.exe
```

Dracula creates a durable project under `<InstallRoot>\projects\sample\`, computes cryptographic hashes (SHA-256), analyzes PE headers, evaluates mitigations, extracts strings, and computes threat scores.

Inspect specific components:
* PE Headers & Sections: `/headers`
* Security Mitigations: `/security`
* Import Table & Suspicious APIs: `/imports`
* Exported Functions: `/exports`
* Disassemble Entrypoint: `/disasm`
* Extracted Strings: `/strings`

---

## 3. Disassembly & Control Flow

To disassemble code at an explicit Virtual Address (VA) or Relative Virtual Address (RVA):

```dracula
drac> /disasm 0x00401000 20
drac> /cfg 0x00401000
drac> /functions
```

---

## 4. Emulation & Dynamic Execution

To emulate a specific function using Unicorn 2 with Win32 High-Level Emulation (HLE) hooks:

```dracula
drac> /emulate 0x00401000
```

---

## 5. Exporting Reports

Export your analysis findings to HTML, Markdown, or JSON:

```dracula
drac> /report html
drac> /report md summary.md
drac> /report json analysis.json
```
