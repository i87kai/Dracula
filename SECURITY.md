# Security Policy

## Supported versions

Security fixes are provided for the current `1.3.x` release line. Older release
lines may no longer receive fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected Dracula vulnerability. Use the
repository's [private vulnerability reporting
page](https://github.com/i87kai/Dracula/security/advisories/new) when it is
available. If private reporting is unavailable, open a public issue containing
only a request for a private contact channel and no sensitive technical detail.

Include the affected version, platform, impact, reproduction steps, and the
smallest safe proof of concept you can provide privately.

Do not attach any of the following to public issues or discussions:

- confidential or proprietary binaries;
- malware samples;
- process or memory dumps;
- VM images or `.draculaimg` packages;
- project workspaces or runtime captures containing private data;
- credentials, API keys, tokens, or personal information.

Analysis targets and captures can contain secrets even when Dracula itself did
not create them. Review and minimize every artifact before sharing it.

## Scope

Relevant reports include vulnerabilities in Dracula, its installer/updater,
project parsing, report generation, GuestAgent protocol, process/runtime
inspection, and QEMU orchestration. Security weaknesses in third-party tools or
the user's guest operating system should normally be reported to their upstream
maintainers, unless Dracula's integration creates the vulnerability.

We will acknowledge valid reports and coordinate remediation and disclosure.
Please do not publish details before a fix or an agreed disclosure date.
