# Windows Event Tracing (ETW) & Trace Data Helper (TDH)

## Overview
- **Component**: Windows Event Tracing for Windows (`advapi32.dll`, `tdh.dll`)
- **Role in Dracula**: Non-invasive external observation fallback for monitoring process creation/exit, thread lifecycle, image/module load events, network connections, and system API events without in-process DLL injection.
- **License**: Native Windows Operating System API.
- **Integration**: Standard Win32 API calls (`StartTraceW`, `ControlTraceW`, `EnableTraceEx2`, `OpenTraceW`, `ProcessTrace`, `TdhGetEventInformation`).
- **Architecture Support**: x86, x64, ARM64.
- **Adapter**: `Dracula::EtwObserver` implementing `IExternalObserver`.
