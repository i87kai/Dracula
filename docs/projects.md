# Projects and Persistence

A Dracula project is the durable context for one target. It owns the target
identity, a project copy of file-backed content, snapshots, runtime evidence,
reports, and generated artifacts.

## Layout

```text
projects/
  sample_<id>/
    project.json
    project.json.bak
    original/
    static/
    functions/
    modules/
    memory/
      maps/
      snapshots/
      dumps/
    runtime/
    sandbox/
    reports/
    artifacts/
    logs/
    overlays/
    cache/
```

`project.json` stores the schema version, project ID, timestamps, Dracula
version, target identity, snapshot counter, snapshots, and artifact records.
Paths to project-owned files are stored in portable relative form.

## File targets

Opening a file hashes it and copies it into `original/`. Existing-project
detection uses content identity, not only the filename. Static analysis prefers
the project copy, so later work does not depend on the original location.

The user's original is read but not modified or deleted by project cleanup or
project deletion.

## Process targets

Attaching to a process records:

- numeric PID;
- resolved backing executable;
- a project copy of that executable where readable;
- target architecture and capabilities; and
- live module, memory, snapshot, and event artifacts as they are requested.

Static commands use the backing image. Live commands use the PID and active
process handle. This keeps static analysis usable after the process exits.

## Common commands

```text
/project list
/project info
/project open <id-or-name>
/project new <file>
/project storage
/project cleanup
/project close
/project delete <id-or-name>
```

`/session` is a compatibility view over the same durable project store, not a
second persistence system.

## Cleanup and deletion

Cleanup removes only categories marked disposable: VM overlays, project cache,
and intermediate memory dumps. It retains the original sample copy, metadata,
static artifacts, functions, modules, memory maps, retained snapshots, runtime
events, reports, artifacts, and logs.

Project deletion is confirmed and constrained to the configured projects root.
It does not delete the user's original source file.

## Crash recovery

Metadata is written to a temporary file and committed with a backup. If the
primary `project.json` is corrupt or interrupted, Dracula attempts recovery from
`project.json.bak` and reports the recovery.
