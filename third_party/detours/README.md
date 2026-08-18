# Microsoft Detours

## Overview
- **Component**: Microsoft Detours 4.0.1
- **Role in Dracula**: Targeted Windows API interception / inline hooking backend for the optional transparent in-process Dracula Agent (`DraculaAgent64.dll`).
- **License**: MIT License.
- **Integration**: Abstracted behind `IInstrumentationBackend`.
- **Architecture Support**: x86, x64, ARM64.
- **Evaluation**: Detours provides a minimal, ultra-fast, dependency-free Win32 API hooking primitive for logging `VirtualAlloc`, `VirtualProtect`, and process events inside authorized user targets.
