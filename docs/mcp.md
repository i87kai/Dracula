# MCP Integration

Dracula exposes project-aware analysis operations as a stdio Model Context
Protocol server. MCP is optional; the CLI and analysis engine do not require an
AI client.

## Start the server

```powershell
drac --mcp
```

In MCP mode, stdout is reserved for newline-delimited JSON-RPC messages. The
terminal UI and ANSI formatting are disabled.

## Client configuration

Use the installed command:

```json
{
  "mcpServers": {
    "dracula": {
      "command": "drac",
      "args": ["--mcp"]
    }
  }
}
```

If the client does not inherit the user PATH, use the absolute path to
`<install>\bin\drac.exe`.

## Project-aware model

The MCP frontend resolves targets through the same project and application
services as the CLI. Tools cover target/project opening, static analysis,
headers, imports/exports, strings, disassembly, memory maps and comparisons,
functions, runtime status/events, artifacts, managed inspection, findings, and
sandbox operations where the active target supports them.

Request the live tool schema with MCP `tools/list`; that result is
authoritative for the installed version.

## Data boundary

Dracula does not choose or contact an AI provider. It writes JSON-RPC to the
configured client's stdio connection. Whether a client processes data locally
or sends it to a remote provider depends on that client and provider.

Review the client configuration before exposing proprietary targets, memory,
or reports. A target is not uploaded merely because MCP mode is available.

## Interpretation

An AI receives structured access to the same `ProjectContext` and evidence
model, reducing the need to paste disconnected addresses, logs, screenshots,
and dumps. MCP does not make every model equally capable and does not replace
Dracula's parsing, memory, emulation, or evidence engines.

Provider-neutral Dracula Skills are planned separately. No Skills runtime is
implemented in this release.
