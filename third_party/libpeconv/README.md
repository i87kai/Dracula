# libPEConv

## Overview
- **Component**: libPEConv by hasherezade
- **Role in Dracula**: Normalizes memory-mapped PE images back into disk-aligned PE binaries, reconstructs raw section headers, relocations, and fixes import tables in memory dumps.
- **License**: BSD 2-Clause License.
- **Integration**: Works alongside PE-sieve and Dracula's dump engine to validate reconstructed executable dumps before writing to `artifacts/session_<id>/dumps/`.
- **Architecture Support**: x86, x64.
- **Adapter**: `Dracula::PeReconstructor`.
