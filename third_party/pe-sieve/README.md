# PE-sieve & libPEConv

## Overview
- **Component**: PE-sieve (v0.3.x) & libPEConv by hasherezade
- **Role in Dracula**: Scans target process memory for replaced modules (process hollowing, Doppelganging), unhooked DLLs, injected PE artifacts, inline hooks, and shellcode patches. Assists in dumping and reconstructing portable PE headers from mapped memory.
- **License**: BSD 2-Clause License.
- **Integration**: Integrated via `tools/pe-sieve64.exe` subprocess launcher and structured JSON report parsing into Dracula's Memory Intelligence subsystem (`PeSieveAdapter`).
- **Architecture Support**: x86, x64.
- **Adapter**: `Dracula::PeSieveAdapter`.
