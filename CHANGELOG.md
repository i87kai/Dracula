# Changelog

This file records public release changes. The historical plain-text changelog
remains available in [`CHANGELOG.txt`](CHANGELOG.txt).

## 1.3.2 - 2026-08-18

### Changed

- Rewrote the public README and detailed documentation around the durable
  project workflow, local-first operation, installation, architecture,
  `.draculaimg`, QEMU, MCP, limitations, and contribution boundaries.
- Made Capstone and Unicorn reproducible pinned submodules and built Unicorn
  from source instead of relying on an untracked developer library.
- Added the .NET 10 ManagedHost to normal builds, tests, installation, and
  release packages.
- Reduced the Windows package to one canonical `bin/drac.exe` and audited its
  public contents.
- Removed developer source paths from native and managed release binaries.

### Fixed

- Made release checksums mandatory for bootstrap and update downloads.
- Moved program replacement into a post-exit transactional updater with staged
  validation, backup, rollback, post-commit version verification, and durable
  data preservation.
- Made installer repair restore packaged program components without replacing
  projects, configuration, or VM data.
- Corrected dependency notices and removed unsupported claims from public
  documentation.

### Verified

- Clean source configure/build/test/package flow on Windows x64.
- Isolated install, repair, default uninstall preservation, explicit purge,
  checksum rejection, successful update, and updater-owned rollback paths.

## 1.3.1 - 2026-08-18

- Added initial open-source repository materials, installer/bootstrap/update
  commands, release packaging, version/about output, and shared terminal art.

## 1.3.0 - 2026-08-18

- Introduced the durable project-centric workspace, application-service layer,
  registry-driven commands, structured artifacts, `.draculaimg`, immutable VM
  overlays, project-aware MCP tools, and truthful runtime readiness states.
