# QEMU Sandbox & Disposable Overlays

Dracula integrates an isolated QEMU hypervisor to execute unknown or potentially malicious binaries safely.

---

## 1. Safety Architecture: Immutable Base & Copy-On-Write Overlays

Dracula strictly separates the read-only guest operating system from guest execution modifications:

```
┌─────────────────────────────────────────────────────────────┐
│                    IMMUTABLE BASE IMAGE                     │
│               <InstallRoot>\vm\base\win10.raw               │
│                  (Opened Read-Only by QEMU)                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            │   Copy-On-Write (qcow2) Overlays    │
            ▼                                     ▼
┌───────────────────────────┐       ┌───────────────────────────┐
│     Overlay Run #101      │       │     Overlay Run #102      │
│  All guest writes land    │       │  Disposable, swept upon   │
│  exclusively in this file │       │  session completion       │
└───────────────────────────┘       └───────────────────────────┘
```

* **Zero Base Mutation**: The base image is never opened in write mode.
* **Disposable Overlays**: Every dynamic execution runs in a fresh `qcow2` overlay tagged with the owning QEMU PID.
* **Automatic Cleanup**: Stale overlays are swept automatically (`/sandbox overlays clean`). Active overlays owned by running QEMU processes are protected from deletion.

---

## 2. Guest Agent & Live Telemetry

* **GuestAgent.exe**: Lightweight in-guest monitor running inside the Windows VM.
* **TCP Handoff**: Connects back to Dracula host on a randomized loopback port.
* **System Event Stream**: Reports process spawn, thread creation, DLL load, registry write, and socket activity.

---

## 3. Sandbox Management Commands

* `/sandbox status`: Check hypervisor binary availability, base image status, and network port allocation.
* `/sandbox overlays`: List all present overlays with sizes and ownership state.
* `/sandbox overlays clean`: Sweep orphaned and stale run overlays.
* `/sandbox reset`: Stop active sessions, sweep overlays, verify base checksum, and restore state.
