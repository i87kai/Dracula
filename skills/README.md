# Dracula AI Skills Directory

This directory is reserved for provider-neutral, interoperable AI assistant skills and tool profiles.

## Architecture & Principles
Dracula integrates with Large Language Models and AI Pair Programmers through two native mechanisms:
1. **Model Context Protocol (MCP)**: Native JSON-RPC 2.0 stdio server (`drac --mcp`).
2. **Provider-Neutral Skills**: Standard Markdown instructions and tool definitions compatible with Antigravity, Claude Code, Cursor, Windsurf, and custom agentic frameworks.

## Standard Layout
```
skills/
├── README.md                 # This specification
├── dracula-investigator/     # Deep binary triage & threat assessment skill
└── dracula-memory-forensics/ # Dynamic memory layout & unpacker skill
```

## Guidelines for Creating Dracula Skills
* Skills must rely on standard Dracula CLI commands (`/analyze`, `/memory`, `/emulate`, `/findings`, `/report`) or MCP tool equivalents.
* Skills must maintain target provenance and reference evidence tags (`CALCULATED`, `RESOLVED`, `LIVE-READ VERIFIED`).
