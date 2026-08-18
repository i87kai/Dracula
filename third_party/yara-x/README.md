# YARA vs YARA-X Qualification & Integration

## Overview
- **Primary Selected Engine**: YARA v4.5.x (`tools/yara64.exe` with `rules/packers.yar`)
- **Evaluated Alternative**: YARA-X (Rust-based rewrite)
- **Evaluation Decision**:
  - YARA v4.5.x is selected as the primary active rule execution engine due to deterministic C/Win32 binary packaging and direct compatibility with existing community rule sets without Rust runtime ABI overhead.
  - YARA-X was evaluated: its rule compilation and scan engine offer modern Rust ergonomics, but its C-API binding on Windows MinGW adds substantial binary size and build complexity. YARA 4 is preserved and qualified.
- **License**: BSD 3-Clause License.
- **Integration**: `Dracula::YaraAdapter` executes rule matching and normalizes findings into the Evidence Graph with confidence and source attribution.
- **Rule Attribution**: YARA matches are treated strictly as evidence/indicators, never as an automatic proof of malware.
