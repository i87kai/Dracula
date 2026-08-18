# Microsoft Debug Interface Access (DIA) SDK

## Overview
- **Component**: Microsoft DIA SDK (`msdia140.dll` / COM interfaces `IDiaDataSource`, `IDiaSession`)
- **Role in Dracula**: Resolves symbols, PDB files, user-defined types (UDT), function names, source line numbers, and RVA mappings.
- **License**: Microsoft Visual Studio / Windows SDK EULA.
- **Integration**: Dynamic COM activation (`CLSID_DiaSource`) and fallback to export table parsing when DIA/PDB is unavailable.
- **Architecture Support**: x86, x64, ARM64.
- **Adapter**: `Dracula::DiaSymbolProvider` implementing `ISymbolProvider`.
