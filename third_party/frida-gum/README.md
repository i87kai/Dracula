# Frida Gum Instrumentation Backend

## Overview
- **Component**: Frida Gum (v16.x)
- **Role in Dracula**: Optional advanced in-process dynamic instrumentation backend for module enumeration, function interception, execution tracing, and backtrace unwinding.
- **License**: LGPL-2.1 / wxWindows Library Exception.
- **Status**: Evaluated behind optional adapter `FridaAgentBackend`. Core Dracula operates without requiring Frida runtime binaries by relying on native External Observer (ETW), DbgEng, and the lightweight Dracula Agent.
