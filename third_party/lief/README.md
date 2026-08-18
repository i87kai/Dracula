# LIEF (Library to Instrument Executable Formats)

## Overview
- **Component**: LIEF (v0.14.x / v0.15.x)
- **Role in Dracula**: Supplementary format parser for cross-validating PE metadata and enabling future ELF/Mach-O expansion.
- **License**: Apache License 2.0.
- **Status**: Evaluated behind `LiefAdapter`. Dracula's built-in PE parser (`PeInspector`) remains the primary, fast, and authoritative PE inspection engine. LIEF is preserved as an optional cross-validation adapter.
