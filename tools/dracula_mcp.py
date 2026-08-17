#!/usr/bin/env python3
"""
Dracula MCP Bridge (Model Context Protocol)
Connects LLMs (Claude, Antigravity, Cursor, OpenAI) to the native Dracula.exe intelligence suite.
"""

import sys
import os
import subprocess
import json

def find_dracula_binary():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_dir, "build", "Dracula.exe"),
        os.path.join(base_dir, "Dracula.exe"),
        os.path.join(base_dir, "build", "Dracula"),
        "Dracula.exe",
        "Dracula"
    ]
    for c in candidates:
        if os.path.exists(c) and os.path.isfile(c):
            return c
    return "Dracula.exe"

def main():
    binary = find_dracula_binary()
    cmd = [binary, "--mcp"]
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        proc.wait()
    except Exception as e:
        sys.stderr.write(f"[-] Error launching Dracula MCP server: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
