# Durable Projects & Evidence Graph

Dracula organizes analysis work into durable, persistent project directories.

---

## 1. Workspace Directory Layout

Every Dracula installation has a root layout structured as follows:

```
<InstallRoot>/
├── bin/                 # drac.exe and runtime agent DLLs
├── config/              # settings.json and application configuration
├── rules/               # YARA and anti-evasion detection signatures
├── tools/               # External helpers and symbol tools
├── runtime/             # ETW sessions and runtime logs
├── vm/                  # QEMU virtual machine assets
│   ├── base/            # Immutable .draculaimg containers
│   ├── overlays/        # Disposable per-run qcow2 overlays
│   └── cache/           # Snapshot caches
├── brain/               # Reserved for high-level intelligence models
├── cache/               # Intermediate decompression cache
├── logs/                # Global operational logs
└── projects/            # Durable analysis project workspaces
    └── <ProjectName>/
        ├── project.json       # Project metadata, schema version, target info
        ├── target.bin         # Immutable copy of the target executable
        ├── project.db         # SQLite database storing findings & graph nodes
        ├── snapshots/         # Memory snapshots & diff structures
        ├── reports/           # Standalone self-contained HTML reports
        └── artifacts/         # Structured disassembly and memory dumps
```

---

## 2. Project Lifecycle & Commands

* **Create / Open Target**: `/analyze <path>` or `/target <path>`
* **List Projects**: `/project list`
* **View Project Storage**: `/project storage`
* **Clean Disposable Data**: `/project cleanup` (removes temporary dumps and intermediate overlays while preserving target, reports, and metadata)
* **Delete Project**: `/project delete <name>` (requires confirmation or `--force`)

---

## 3. Evidence Graph

Dracula constructs a persistent directed evidence graph linking artifacts together:
* **Node Types**: `SAMPLE`, `SECTION`, `IMPORT`, `EXPORT`, `STRING`, `FUNCTION`, `BLOCK`, `MEMORY_REGION`, `EVASION_TECHNIQUE`, `FINDING`.
* **Edge Types**: `CONTAINS`, `CALLS`, `REFERENCES`, `EXECUTES_IN`, `INFLUENCED_BY`, `DETECTS`.
* **Provenance Tags**: Explicitly tracks confidence and verification tier for every finding.
