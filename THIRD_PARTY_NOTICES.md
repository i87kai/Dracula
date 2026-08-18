# Third-Party Software Notices

Dracula is licensed under GPL-3.0-only. This file records the third-party code
and platform components used by the current source tree and Windows release.
License texts retained in the repository are under `third_party/LICENSES/` or
in the corresponding pinned source tree.

| Component | Upstream | Purpose | License | Integration |
| --- | --- | --- | --- | --- |
| Capstone 5.0.1 | <https://github.com/capstone-engine/capstone> | x86/x64 disassembly | BSD-3-Clause | Pinned Git submodule; compiled and statically linked |
| Unicorn 2.1.4 | <https://github.com/unicorn-engine/unicorn> | CPU emulation used by the HLE backend | GPL-2.0 / LGPL-2.1 dual license | Pinned Git submodule; compiled for x86 and statically linked under the LGPL option |
| SQLite 3.46.1 | <https://www.sqlite.org/> | Session/project indexes and structured persistence | Public domain | Vendored amalgamation; compiled and statically linked |
| Zstandard 1.5.6 | <https://github.com/facebook/zstd> | `.draculaimg` streaming compression | BSD-3-Clause | Vendored selected source files; compiled and statically linked |
| .NET runtime libraries | <https://github.com/dotnet/runtime> | `System.Reflection.Metadata`-based managed-code inspection | MIT | Dracula ManagedHost is framework-dependent; the .NET runtime is not bundled |
| Windows APIs and SDK import libraries | <https://learn.microsoft.com/windows/> | Process, memory, ETW, symbols, networking, cryptography, and optional DbgEng integration | Microsoft platform terms | Linked through Windows import libraries or loaded from the user's Windows installation; system binaries are not redistributed |

The complete BSD license notices for Capstone and Zstandard are included with
their source trees. Unicorn's upstream source contains its GPL-2.0 and
LGPL-2.1 license texts. Dracula uses Unicorn under its LGPL-2.1 licensing
option; Dracula's own combined release remains GPL-3.0-only.

## Optional and development-only integrations

- QEMU is an external user-installed program. Dracula orchestrates it but does
  not redistribute QEMU binaries, firmware, or operating-system images.
- DbgEng is optional and loaded only when the required Microsoft debugging
  components exist on the system. Those components are not included.
- Files under `guest_share/tools/` are development/guest-tool staging data and
  are not included in the Dracula release archive. In particular, Dracula does
  not redistribute x64dbg executables in its release.
- `rules/packers.yar` uses YARA-compatible rule syntax. Dracula does not vendor
  or link the YARA engine in the current build.
- PE-sieve, Frida, Triton, and similar tools may be evaluated or represented by
  optional adapters and license-reference files, but their binaries and source
  are not incorporated into the current Dracula executable or release archive.

## Operating-system media

Dracula does not ship Windows, Windows VM media, `.vdi`, `.qcow2`,
`.draculaimg`, memory dumps, or user projects. Users are responsible for
providing appropriately licensed local VM media and external tools.

If packaging changes introduce another redistributed component, update this
notice and include its required license material before release.
