# Model Context Protocol (MCP) Integration

Dracula provides a native, high-performance stdio server implementing the **Model Context Protocol (MCP)** standard (Protocol Version `2024-11-05`).

---

## 1. Overview

By integrating Dracula as an MCP server, AI assistants (Claude Desktop, Google Antigravity, Cursor, Windsurf) can directly inspect binary targets, disassemble functions, evaluate security mitigations, read memory maps, and query the evidence graph autonomously.

### Clean Stdio Guarantee
When invoked with `--mcp`, Dracula enters a dedicated headless stdio mode:
* Zero terminal ANSI sequences or color codes on `stdout`.
* Pure JSON-RPC 2.0 frames delimited by newlines.
* Log messages redirected exclusively to internal files.

---

## 2. Configuration Examples

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "dracula": {
      "command": "C:\\Dracula\\bin\\drac.exe",
      "args": ["--mcp"]
    }
  }
}
```

### Cursor / Custom Stdio Configuration
```json
{
  "mcpServers": {
    "dracula": {
      "command": "drac.exe",
      "args": ["--mcp"]
    }
  }
}
```

---

## 3. Available MCP Tools

| Tool Name | Parameters | Description |
|---|---|---|
| `target_open` | `path` (string) OR `pid` (number) | Open a static file or attach to a live process. |
| `static_analyze` | None | Run full static pipeline on the active target. |
| `disassemble` | `address` (string), `count` (number) | Disassemble instructions at specified address. |
| `headers_inspect` | None | Inspect PE headers and data directories. |
| `security_audit` | None | Audit ASLR, DEP, CFG, SEH, and Authenticode mitigations. |
| `imports_list` | None | List imported DLLs and sensitive API calls. |
| `exports_list` | None | List exported functions and RVAs. |
| `strings_extract` | `min_length` (number) | Extract and classify strings. |
| `memory_map` | None | Query virtual memory layout and protection flags. |
| `findings_get` | None | Retrieve structured findings and threat score. |
| `project_list` | None | List durable project workspaces. |
| `project_open` | `id` (string) | Switch active project workspace. |
