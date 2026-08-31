#!/usr/bin/env python3
"""Adversarial stress test for params and arguments edge cases in MCP server."""
import io
import json
from rvs_agent_harness import RvsHarness

harness = RvsHarness()

adversarial_mcp_requests = [
    # 1. params is null
    {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": None},
    # 2. params is string
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": "invalid_params"},
    # 3. params is list
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": [1, 2, 3]},
    # 4. params is integer
    {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": 42},
    # 5. arguments inside params is null
    {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "rvs_info", "arguments": None}},
    # 6. arguments inside params is string
    {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "rvs_info", "arguments": "foo"}},
]

for req in adversarial_mcp_requests:
    stdin_stream = io.StringIO(json.dumps(req) + "\n")
    stdout_stream = io.StringIO()
    print(f"Testing req: {req}")
    try:
        harness.serve_mcp(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
        stdout_stream.seek(0)
        out = stdout_stream.read().strip()
        print(f"-> Response: {out}")
    except Exception as e:
        print(f"-> CRASHED with exception: {type(e).__name__}: {e}")
