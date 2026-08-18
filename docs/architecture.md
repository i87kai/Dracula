# Architecture

Dracula separates analysis logic, project-aware operations, and presentation.

```text
┌──────────────────────────────────────────────┐
│                 Dracula Core                 │
│ PE · UTR · Memory · Functions · Evidence     │
│ Unicorn · QEMU · Runtime backends             │
└──────────────────────┬───────────────────────┘
                       │ structured results
┌──────────────────────▼───────────────────────┐
│             Application Services             │
│ Project · Target · Static · Process · Memory │
│ DLL · Runtime · Sandbox · Update             │
└──────────────────────┬───────────────────────┘
                       │
                 ┌─────┴─────┐
                 ▼           ▼
                CLI         MCP
                 │
                 └── future local web frontend
```

## Core and UTR

The Universal Target Runtime exposes target identity and capabilities for
native files, DLLs, running processes, managed assemblies, services, drivers,
and VM-backed targets. Capability checks happen before an operation runs, so a
static assembly does not pretend to provide process memory and a file target
does not pretend to provide threads.

Core components perform PE parsing, disassembly, CFG and XRef work, function
indexing, memory transforms, emulation, and evidence graph operations. They do
not format terminal output.

## Application services

Application services resolve every request through the active project and
return DTOs such as `CommandResult`, artifacts, evidence references, storage
reports, module correlation, and runtime status. This is the boundary shared by
the CLI and MCP server.

`ProjectContext` binds durable target identity to static and runtime artifacts.
A running process keeps its PID and backing executable in different fields;
the PID is never interpreted as a path.

## Frontends

The CLI owns terminal layout, command discovery, and rendering. The
`CommandRegistry` is authoritative for command names, aliases, usage,
subcommands, requirements, completion, and dispatch.

MCP is a headless stdio frontend over project-aware operations. A future local
web frontend is planned to consume the same service boundary. It is not present
in this release.

## Evidence terminology

Dracula uses related but distinct labels.

Address and DLL correlation:

- `STATIC`: obtained from an on-disk image without a live module base.
- `RESOLVED`: an RVA was correlated with a real loaded module base.
- `LIVE-READ VERIFIED`: the corresponding live address was read successfully.

Evidence graph truth levels:

- `Observed`: directly measured or recorded by a backend.
- `Inferred`: a logical conclusion from observations.
- `Suspected`: a hypothesis requiring more correlation.
- `Unknown`: insufficient visibility.

Evidence nodes also record engine/backend, session, module, address/RVA,
timestamp, and an artifact reference where available. These fields support
traceability; the project does not claim universal cryptographic provenance.

## Persistence and reports

Project metadata is committed through a temporary file and `.bak` fallback.
Large module, function, memory, and runtime tables are stored as local,
self-contained HTML artifacts. Reports do not fetch scripts, fonts, or data
from a CDN.

## Execution boundaries

- Unicorn is bounded CPU emulation with selected Win32 HLE.
- Host process inspection is read-oriented and capability gated.
- Driver runtime analysis is isolated to QEMU.
- QEMU bases are restored and treated as immutable; guest writes go to
  overlays.
- GuestAgent telemetry is associated with a per-session nonce.

## Future presentation layer

```text
        Dracula Core
             │
    Application Services
       /             \
      /               \
    CLI          Local Web GUI
    now              planned
```

The planned web frontend is intended for CFGs, call graphs, large tables,
memory maps, runtime timelines, project browsing, evidence relationships,
QEMU state, and artifacts. It will not move analysis logic into the browser.
