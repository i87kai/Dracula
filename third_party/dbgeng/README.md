# Microsoft Windows Debugger Engine (DbgEng)

## Overview
- **Component**: Microsoft DbgEng / DbgHelp SDK APIs
- **Role in Dracula**: Live user-mode process debugging, kernel debugging target adapter, target attachment, thread enumeration, memory inspection, and software/hardware breakpoint coordination.
- **License**: Microsoft Windows SDK EULA (Redistribution subject to Microsoft SDK terms).
- **Integration**: Dynamic runtime discovery via `LoadLibraryA("dbgeng.dll")` and `LoadLibraryA("dbghelp.dll")`. No proprietary SDK redistributables are committed to Git.
- **Architecture Support**: x86, x64, ARM64.
- **Adapter**: `Dracula::DbgEngBackend` implementing `IDebugBackend`.
