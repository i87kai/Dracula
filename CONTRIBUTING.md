# Contributing to Dracula

Dracula is a Windows C++20 reverse-engineering workspace. Contributions are
welcome when they preserve the project model, evidence semantics, and the
separation between analysis code and presentation code.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities
through the private process in [SECURITY.md](SECURITY.md), not a public issue.

## Prerequisites

- Windows 10 or 11 x64
- Git with submodule support
- CMake 3.20 or newer
- MinGW-w64 GCC or another supported C++20 toolchain
- PowerShell 5.1 or newer
- .NET 10 SDK for the managed-code host

See [Building from Source](docs/building.md) for the maintained commands and
toolchain notes.

## Build and test

```powershell
git clone --recurse-submodules https://github.com/i87kai/Dracula.git
cd Dracula
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
```

Run the full suite before submitting a pull request. A fix should include a
focused regression test when the behavior can be exercised safely and
deterministically. Tests must use synthetic fixtures and isolated temporary
workspaces; never commit real samples, dumps, VM images, credentials, or user
projects.

## Architecture boundaries

The intended dependency direction is:

```text
Core analysis and UTR
        |
Application Services and structured DTOs
        |
CLI / MCP / future frontends
```

- Analysis logic belongs in the core or an appropriate backend.
- `src/app/` coordinates core behavior and returns structured data.
- `src/cli/` owns terminal input, formatting, and presentation only.
- Frontends must not reimplement parsers, target resolution, persistence, or
  evidence logic.
- Project-owned paths must resolve through `ProjectContext`, `ProjectManager`,
  or the common path utilities. Do not add personal or build-tree paths.

## Commands

`CommandRegistry` is the source of truth for command names, subcommands,
descriptions, capability requirements, and dispatch. When adding or changing a
command:

1. Add the operation to the relevant application service if it is not purely
   presentational.
2. Register the command and every dispatchable subcommand.
3. Keep palette, help, completion, and handler behavior registry-driven.
4. Add registry/dispatch tests.
5. Update [docs/cli.md](docs/cli.md) and any affected workflow document.

Do not document an alias or syntax that is not registered.

## Projects and persistence

A project is durable user data. Changes to `project.json`, artifact locations,
snapshot formats, indexes, or cleanup rules need compatibility tests. Cleanup,
repair, update, and default uninstall operations must not remove projects,
configuration, VM bases, or retained evidence.

Use atomic writes and explicit migration where persistent formats change.

## Analysis backends

New backends should implement the existing target/application-service
boundaries and report factual readiness. Installed, available, connected,
partial, and unsupported are different states. Optional dependencies must
degrade clearly when unavailable and must not be represented as active merely
because a file exists.

## Evidence terminology

Use the terms already implemented by the relevant subsystem. Address
correlation currently distinguishes `STATIC`, `RESOLVED`, and
`LIVE-READ VERIFIED`. Evidence graph relationships distinguish `Observed`,
`Inferred`, `Suspected`, and `Unknown`.

Do not introduce broad claims such as "cryptographic provenance" unless the
code and tests implement that exact security property.

## Dependencies

Before adding a dependency, document:

- its purpose and why existing facilities are insufficient;
- upstream project and pinned version;
- license and GPL-3.0-only compatibility;
- whether it is built from source, linked, dynamically discovered, or only an
  optional external tool;
- changes required in `.gitmodules`, CMake, packaging, CI, and
  `THIRD_PARTY_NOTICES.md`.

Do not commit redistributables, SDK components, or third-party binaries without
verified redistribution rights.

## Documentation and pull requests

Keep README concise and put detailed procedures in `docs/`. Public examples
must be safe, reproducible, free of private paths, and valid against the current
registry. Public presentation uses PNG screenshots and text diagrams, not SVG
artwork or badge images.

Use a focused branch and descriptive commits. In the pull request, explain the
user-visible behavior, architecture impact, tests performed, and any known
limitations.
