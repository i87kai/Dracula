# Roadmap

The roadmap separates shipped behavior from planned and experimental work.
Items here are direction, not a release commitment.

## Implemented

- Durable project workspaces and project-owned target copies
- Project-aware CLI and MCP frontends over application services
- PE analysis, Capstone disassembly, CFGs, XRefs, and function intelligence
- Authorized live-process modules, threads, memory maps, reads, and snapshots
- Static/live DLL address correlation
- Runtime event and evidence graph persistence
- Unicorn x86/x64 emulation with selected Win32 HLE
- Driver static analysis and managed assembly metadata inspection
- QEMU orchestration, GuestAgent telemetry, immutable bases, and overlays
- Streaming `.draculaimg` package, verify, and restore operations
- Verified release bootstrap and transactional updater path

## Planned

### Provider-neutral Dracula Skills

Skills will document operational knowledge: how workflows fit together, when
to choose a service, how to interpret evidence levels, decision procedures, and
analysis playbooks. Repository sources will live under `skills/`; packaged
skills are intended for `<install>\brain\skills\`.

Skills should reduce trial and error and wasted model context. They supplement
model knowledge; they do not increase a model's fundamental intelligence. No
Skills runtime is implemented today.

### Local web frontend

```text
        Dracula Core
             │
    Application Services
       /             \
      /               \
    CLI          Local Web GUI
    now              planned
```

The local frontend is intended for CFGs, call graphs, large function tables,
memory maps, runtime timelines, project browsing, evidence relationships,
QEMU state, and artifacts. It will reuse application services. No Node,
Electron, React, Vue, or other web dependency is part of the current tree.

### Deeper target integration

- More complete debugger execution control beyond current Win32/DbgHelp reads
- Project-first service target creation
- Additional managed runtime visibility
- Additional authorized target and backend adapters

## Experimental or environment-dependent

- In-process x64 agent telemetry
- Optional DbgEng-related integration beyond the DbgHelp-backed read path
- Full live QEMU guest acceptance, which depends on the user's local QEMU and
  licensed Windows environment
- Anti-evasion differential profiles, whose results require analyst
  interpretation and are not proof of malicious intent
