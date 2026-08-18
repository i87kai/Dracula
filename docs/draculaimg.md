# The .draculaimg Container Format

The `.draculaimg` format is Dracula's proprietary, high-performance compressed container format designed for distributing and restoring local virtual machine base images.

---

## 1. Specification Overview

* **Container Extension**: `.draculaimg`
* **Compression Algorithm**: Zstandard (zstd) with configurable chunk size (default: 4 MB chunks).
* **Integrity Model**:
  - Global SHA-256 header checksum verifying the uncompressed source image.
  - Per-chunk CRC-32 checksums enabling incremental corruption detection without decompressing the entire multi-gigabyte container.
* **Streaming Design**: Streamed reads and writes via native streaming buffers, enabling import/export of 20+ GB virtual disks with constant low memory usage (< 64 MB RAM).

---

## 2. Container Binary Header Layout

```
Offset  Size     Field Description
────────────────────────────────────────────────────────────────────────
0x00    4 bytes  Magic Identifier ("DRAC" / 0x43415244)
0x04    2 bytes  Format Version (e.g. 1)
0x06    2 bytes  Header Size
0x08    8 bytes  Original Uncompressed Size (bytes)
0x10    8 bytes  Compressed Payload Size (bytes)
0x18    4 bytes  Chunk Count
0x1C    4 bytes  Chunk Size (e.g. 4194304 bytes)
0x20    32 bytes SHA-256 Digest of Uncompressed Image
0x40    ...      Chunk Index Table (Offset, CompressedSize, CRC-32)
────────────────────────────────────────────────────────────────────────
```

---

## 3. CLI Commands

* **Import VM Image**:
  ```dracula
  drac> /sandbox image import C:\VMs\win10.vdi
  ```
  Converts and packages the source disk into `<InstallRoot>\vm\base\win10.draculaimg` with progress reporting.

* **Verify VM Package**:
  ```dracula
  drac> /sandbox image verify
  ```
  Validates per-chunk CRC-32 checksums and reports any localized disk corruption.

* **Restore Base Image**:
  ```dracula
  drac> /sandbox image restore
  ```
  Extracts and decompresses the raw base image to `<InstallRoot>\vm\base\win10.raw`.
