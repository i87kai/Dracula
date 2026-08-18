# The `.draculaimg` Format

`.draculaimg` is Dracula's open-source container format for packaging a user's
local VM disk into a verifiable, restorable analysis base.

Dracula does not ship a `.draculaimg`, Windows image, product key, or Windows
installation media.

## Format version 1

```text
┌──────────────────────────────────────────────┐
│ fixed 512-byte header                        │
│ magic · version · source metadata · SHA-256  │
├──────────────────────────────────────────────┤
│ chunk record · Zstandard or raw payload      │
├──────────────────────────────────────────────┤
│ chunk record · Zstandard or raw payload      │
├──────────────────────────────────────────────┤
│ ...                                          │
└──────────────────────────────────────────────┘
```

The eight-byte magic is `DRACIMG\0`. The default chunk size is 16 MiB. Each
record stores a `DCHK` marker, compressed and uncompressed sizes, flags, and a
CRC-32 of the uncompressed chunk. A chunk is stored raw if compression would
make it larger.

The header stores the original size, chunk size/count, source format and name,
creation metadata, Dracula version, and SHA-256 of the original disk content.

## Operations

Package a locally supplied image:

```text
/sandbox image import C:\VMs\windows10.vdi
```

Inspect and verify:

```text
/sandbox image info
/sandbox image verify
```

Restore the operational base:

```text
/sandbox image restore
```

Packaging and restore are streaming operations. Partial output is removed on
failure or cancellation. Verification checks structure and per-chunk CRC-32;
deep verification also decompresses all chunks and recomputes the original
SHA-256.

## Supported source descriptions

The package records the source filename and extension such as VDI, qcow2, or
raw. The payload is disk content, not a license-transfer mechanism. Users are
responsible for the source environment and its licensing.

## QEMU use

The verified package restores an operational base under `vm\base`. QEMU uses
that base through temporary qcow2 overlays. See [QEMU Sandbox](sandbox.md).
