# QEMU Sandbox

Dracula can run authorized targets inside a locally configured QEMU Windows
environment. This is an isolation boundary, not a guarantee that a guest is
undetectable or immune to escape vulnerabilities.

## Storage model

```text
user-provided Windows environment
               │
               ▼
      windows10.draculaimg
        verified package
               │ restore
               ▼
       immutable raw base
               │ backing file
       ┌───────┴────────┐
       ▼                ▼
 run overlay A      run overlay B
```

The base is restored from the package and used as a backing file. Guest writes
go to a run-specific qcow2 overlay. Overlay metadata records the owning QEMU
PID; cleanup refuses to remove an overlay owned by a live process.

## Requirements

- `qemu-system-x86_64.exe`
- `qemu-img.exe` beside the configured QEMU executable
- a user-provided, appropriately licensed Windows analysis environment
- GuestAgent provisioned in that environment
- sufficient local disk space for the package, restored base, and overlays

Dracula does not provide Windows or a VM image.

## Commands

```text
/sandbox status
/sandbox image info
/sandbox image import C:\VMs\windows10.vdi
/sandbox image verify
/sandbox image restore
/sandbox overlays
/sandbox overlays clean
/sandbox reset
```

Run `/help sandbox` for the exact registered syntax in the current build.

## GuestAgent

GuestAgent launches inside the guest and connects back to Dracula's allocated
host listener. A session nonce associates the connection with the intended run.
Telemetry is decoded into runtime events and evidence under the active project.

GuestAgent is x64. It is not a kernel monitor and does not make the QEMU guest
transparent to anti-VM checks.

## Reset and cleanup

Reset stops an active sandbox session, sweeps stale overlays, verifies the
`.draculaimg` package, and restores the base when it is missing or does not
match the packaged content. A live-owner check protects active overlays.

Do not store unrelated data in the managed overlay directory.

## Network behavior

QEMU networking depends on the local configuration. Analyze untrusted targets
only with a network policy suitable for the investigation. Do not assume the
default guest network is equivalent to a dedicated malware-analysis network.
