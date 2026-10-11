#!/usr/bin/env python3
"""
tests/test_adversarial_mcp_crash.py - Adversarial MCP JSON-RPC Crash & Fuzzing Resilience Suite.

Validates zero unhandled exceptions, crash resilience, and strict JSON-RPC 2.0 conformance
under intense fuzzing, malformed payloads, stream floods, and adversarial tool inputs.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    CANONICAL_TOOLS,
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    RvsAgentHarness,
    RvsHarness,
    find_rvs_binary,
    get_tool_schemas,
    transform_response,
)


class TestAdversarialMcpCrash(unittest.TestCase):
    """Adversarial stress and crash resilience test suite for MCP server and harness."""

    @classmethod
    def setUpClass(cls):
        cls.crackme_path = WORKSPACE_DIR / "crackme_case"
        if not cls.crackme_path.exists():
            fixture_src = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
            if fixture_src.exists():
                shutil.copy(fixture_src, cls.crackme_path)
                os.chmod(cls.crackme_path, 0o755)

        cls.rvs_bin = find_rvs_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)
        cls.harness_script = WORKSPACE_DIR / "rvs_agent_harness.py"

    def run_in_memory_mcp(self, raw_input: str) -> List[Dict[str, Any]]:
        stdin_stream = io.StringIO(raw_input)
        stdout_stream = io.StringIO()
        self.harness.serve_mcp(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
        stdout_stream.seek(0)
        responses = []
        for line in stdout_stream:
            line_s = line.strip()
            if line_s:
                responses.append(json.loads(line_s))
        return responses

    def run_subprocess_mcp(self, raw_input: str, timeout: float = 10.0) -> (List[Dict[str, Any]], str, int):
        proc = subprocess.Popen(
            [sys.executable, str(self.harness_script), "--mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=raw_input, timeout=timeout)
        responses = []
        for line in stdout.splitlines():
            line_s = line.strip()
            if line_s:
                try:
                    responses.append(json.loads(line_s))
                except Exception as exc:
                    self.fail(f"Malformed JSON emitted to stdout: {line_s!r} error: {exc}")
        return responses, stderr, proc.returncode

    # -------------------------------------------------------------------------
    # 1. Raw Stream & Lexical Fuzzing
    # -------------------------------------------------------------------------

    def test_01_raw_text_and_malformed_syntax_fuzzing(self):
        """Fuzz with garbage strings, unclosed brackets, null bytes, and control chars."""
        garbage_inputs = [
            "",
            "   \n\t  \r\n",
            "{",
            "}",
            "{[",
            '{"unclosed string',
            '{"a": 1, "b": }',
            '{"key": undefined}',
            "NaN",
            "Infinity",
            "-Infinity",
            "<xml>not json</xml>",
            "SELECT * FROM users;",
            "\x00\x01\x02\x03",
            '{"jsonrpc": "2.0", "method": "ping", "id": 1\x00}',
            "💥🔥✨🎉",
            '{"emoji": "💥", "id": 99, "jsonrpc": "2.0"}',
            "\\" * 50,
            '{"nested": ' + ('{"a": ' * 20) + '1' + ('}' * 20) + '}',
        ]
        for item in garbage_inputs:
            resps = self.run_in_memory_mcp(item + "\n")
            # If empty or blank lines, 0 responses
            if not item.strip():
                self.assertEqual(len(resps), 0)
                continue
            # Any invalid request with or without id must yield a valid JSON-RPC envelope
            self.assertGreaterEqual(len(resps), 1)
            for r in resps:
                self.assertEqual(r.get("jsonrpc"), "2.0")
                if "error" in r:
                    self.assertIn(r["error"].get("code"), [-32700, -32600, -32601, -32602, -32603])

    def test_02_oversized_payload_fuzzing(self):
        """Fuzz with a massive 1MB single-line JSON string without memory explosion or crash."""
        huge_str = "A" * (1024 * 1024)
        req = json.dumps({"jsonrpc": "2.0", "id": "huge_req", "method": "unknown_huge", "params": {"blob": huge_str}})
        resps = self.run_in_memory_mcp(req + "\n")
        self.assertEqual(len(resps), 1)
        r = resps[0]
        self.assertEqual(r.get("jsonrpc"), "2.0")
        self.assertEqual(r.get("id"), "huge_req")
        self.assertIn("error", r)
        self.assertEqual(r["error"].get("code"), -32601)

    # -------------------------------------------------------------------------
    # 2. JSON-RPC Protocol Structural Fuzzing
    # -------------------------------------------------------------------------

    def test_03_invalid_jsonrpc_root_types(self):
        """Root JSON elements that are not JSON objects must return -32600."""
        non_object_roots = [
            12345,
            -999.5,
            True,
            False,
            None,
            "just a plain string",
            [1, 2, 3],
            [{"jsonrpc": "2.0", "id": 1, "method": "ping"}],  # batch not enabled as single object
        ]
        for root_val in non_object_roots:
            payload = json.dumps(root_val) + "\n"
            resps = self.run_in_memory_mcp(payload)
            self.assertEqual(len(resps), 1, f"Failed for root value: {root_val!r}")
            r = resps[0]
            self.assertEqual(r.get("jsonrpc"), "2.0")
            self.assertIn("error", r)
            self.assertEqual(r["error"].get("code"), -32600)

    def test_04_jsonrpc_version_field_fuzzing(self):
        """Invalid or missing jsonrpc version fields must return -32600."""
        bad_versions = [
            None,
            "",
            "1.0",
            "2.1",
            "3.0",
            2.0,
            2,
            True,
            False,
            [],
            {},
        ]
        for idx, bv in enumerate(bad_versions, 1000):
            req = {"id": idx, "method": "ping"}
            if bv is not None:
                req["jsonrpc"] = bv
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1, f"Failed for bad version: {bv!r}")
            r = resps[0]
            self.assertEqual(r.get("jsonrpc"), "2.0")
            self.assertEqual(r.get("id"), idx)
            self.assertIn("error", r)
            self.assertEqual(r["error"].get("code"), -32600)

    def test_05_id_field_type_diversity(self):
        """JSON-RPC allows numbers, strings, and null for id."""
        id_cases = [
            0,
            1,
            -100,
            9999999999999999,
            "req-001",
            "uuid-4b55-adb3",
            "",
            None,
        ]
        for item in id_cases:
            req = {"jsonrpc": "2.0", "id": item, "method": "ping"}
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1)
            r = resps[0]
            self.assertEqual(r.get("jsonrpc"), "2.0")
            self.assertEqual(r.get("id"), item)
            self.assertEqual(r.get("result"), {})

    def test_06_method_field_fuzzing(self):
        """Malformed method types and non-existent methods must be safely rejected."""
        # Non-string methods -> -32600
        non_string_methods = [123, 3.14, True, False, [], {}, None]
        for m in non_string_methods:
            req = {"jsonrpc": "2.0", "id": 501, "method": m}
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1)
            self.assertEqual(resps[0]["error"]["code"], -32600)

        # Non-existent string methods -> -32601
        bogus_methods = [
            "",
            "ping_pong",
            "tools",
            "tools/get",
            "tools/call/execute",
            "../../secret_method",
            "__init__",
            "eval",
        ]
        for bm in bogus_methods:
            req = {"jsonrpc": "2.0", "id": 502, "method": bm}
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1)
            self.assertEqual(resps[0]["error"]["code"], -32601)

    def test_07_params_field_fuzzing(self):
        """Invalid types for params must return -32602."""
        invalid_params_types = ["string_params", 12345, [1, 2, 3], True]
        for bad_p in invalid_params_types:
            for method in ["initialize", "ping", "tools/list", "tools/call"]:
                req = {"jsonrpc": "2.0", "id": 601, "method": method, "params": bad_p}
                resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
                self.assertEqual(len(resps), 1)
                self.assertEqual(resps[0]["error"]["code"], -32602)

    # -------------------------------------------------------------------------
    # 3. Adversarial Tools Call Fuzzing
    # -------------------------------------------------------------------------

    def test_08_adversarial_tool_names(self):
        """Adversarial tool names return -32602 or structured error envelopes."""
        # Empty or non-string tool names return -32602
        invalid_names = [None, "", 123, [], {}]
        for inv_name in invalid_names:
            req = {
                "jsonrpc": "2.0",
                "id": 701,
                "method": "tools/call",
                "params": {"name": inv_name, "arguments": {}},
            }
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1)
            self.assertEqual(resps[0]["error"]["code"], -32602)

        # Unrecognized tool string names return structured isError envelope
        unknown_tools = [
            "rvs_nonexistent_tool_123",
            "../etc/passwd",
            "rm -rf /",
            "bash",
            "python",
            "__import__",
            "rvs_pwn",
        ]
        for unk in unknown_tools:
            req = {
                "jsonrpc": "2.0",
                "id": 702,
                "method": "tools/call",
                "params": {"name": unk, "arguments": {}},
            }
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1)
            self.assertTrue(resps[0]["result"]["isError"])
            content = json.loads(resps[0]["result"]["content"][0]["text"])
            self.assertFalse(content["success"])
            self.assertIn("error", content)

    def test_09_all_canonical_tools_missing_arguments_safety(self):
        """Every canonical tool when called with empty or None arguments returns without crashing."""
        for tool_entry in CANONICAL_TOOLS:
            tool_name = tool_entry["name"] if isinstance(tool_entry, dict) else str(tool_entry)
            for args in [{}, None, {"extra_bogus_arg": 123}]:
                req = {
                    "jsonrpc": "2.0",
                    "id": f"tool_test_{tool_name}",
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": args},
                }
                resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
                self.assertEqual(len(resps), 1, f"Failed for {tool_name} with args {args}")
                r = resps[0]
                self.assertEqual(r.get("id"), f"tool_test_{tool_name}")
                self.assertIn("result", r)
                content = json.loads(r["result"]["content"][0]["text"])
                self.assertIn("success", content)

    def test_10_adversarial_file_targets(self):
        """Tools invoked against invalid, unreadable, or special filesystem paths recover cleanly."""
        adversarial_targets = [
            "/nonexistent/directory/path/never_existed_9999.bin",
            "/dev/null",
            "/dev/zero",
            tempfile.gettempdir(),  # directory instead of file
        ]
        tools_to_test = ["rvs_info", "rvs_strings", "rvs_symbols", "rvs_agent_triage"]
        for target in adversarial_targets:
            for tool_name in tools_to_test:
                req = {
                    "jsonrpc": "2.0",
                    "id": 801,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {"file": target}},
                }
                resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
                self.assertEqual(len(resps), 1)
                r = resps[0]
                content = json.loads(r["result"]["content"][0]["text"])
                self.assertIn("success", content)
                if not content["success"]:
                    self.assertTrue(r["result"]["isError"])

    def test_11_patch_tools_adversarial_inputs(self):
        """Patch tools with invalid hex bytes, invalid addresses, and corrupt plans."""
        adversarial_patches = [
            ("rvs_patch_instruction", {"file": str(self.crackme_path), "addr": "invalid_hex", "instruction": "nop"}),
            ("rvs_patch_string", {"file": str(self.crackme_path), "offset": "invalid_offset", "new_string": "test"}),
            ("rvs_patch_bytes", {"file": str(self.crackme_path), "addr": "0x1000", "hex_bytes": "NOT_HEX_CHARS"}),
            ("rvs_patch_bytes", {"file": str(self.crackme_path), "addr": "0x1000", "hex_bytes": "123"}),  # odd length
            ("rvs_agent_patch_plan", {"file": str(self.crackme_path), "plan": "not a list of patches"}),
        ]
        for tool_name, args in adversarial_patches:
            req = {
                "jsonrpc": "2.0",
                "id": 901,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            }
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1)
            r = resps[0]
            self.assertTrue(r["result"]["isError"])
            content = json.loads(r["result"]["content"][0]["text"])
            self.assertFalse(content["success"])
            self.assertIn("error", content)

    # -------------------------------------------------------------------------
    # 4. Subprocess Pipe Stream Fuzzing & Resilience
    # -------------------------------------------------------------------------

    def test_12_subprocess_rapid_burst_fuzzing(self):
        """Send a rapid burst of 50 mixed valid and invalid JSON-RPC requests to subprocess."""
        requests = []
        for i in range(50):
            if i % 5 == 0:
                # Valid ping
                requests.append(json.dumps({"jsonrpc": "2.0", "id": i, "method": "ping"}))
            elif i % 5 == 1:
                # Malformed JSON
                requests.append(f'{{broken json {i}')
            elif i % 5 == 2:
                # Missing jsonrpc field
                requests.append(json.dumps({"id": i, "method": "ping"}))
            elif i % 5 == 3:
                # Unknown method
                requests.append(json.dumps({"jsonrpc": "2.0", "id": i, "method": f"bogus_{i}"}))
            else:
                # Tool call on crackme_case
                requests.append(json.dumps({
                    "jsonrpc": "2.0",
                    "id": i,
                    "method": "tools/call",
                    "params": {"name": "rvs_info", "arguments": {"file": str(self.crackme_path), "compact": True}},
                }))

        raw_stream = "\n".join(requests) + "\n"
        resps, stderr, retcode = self.run_subprocess_mcp(raw_stream, timeout=15.0)

        self.assertEqual(retcode, 0, f"Subprocess exited with non-zero code {retcode}. Stderr: {stderr}")
        self.assertEqual(len(resps), 50, f"Expected 50 responses for 50 requests, got {len(resps)}")
        # Verify stderr contains zero unhandled Python exceptions
        self.assertNotIn("Traceback (most recent call last)", stderr)

    def test_13_subprocess_abrupt_eof_and_empty_stream(self):
        """Sending empty stream or immediate EOF must cleanly terminate server with code 0."""
        resps, stderr, retcode = self.run_subprocess_mcp("", timeout=5.0)
        self.assertEqual(retcode, 0)
        self.assertEqual(len(resps), 0)
        self.assertNotIn("Traceback", stderr)

    def test_14_direct_transform_response_adversarial_types(self):
        """transform_response handles unexpected data types and boundary budgets safely."""
        adversarial_envelopes = [
            {"success": True, "command": "info", "data": None},
            {"success": True, "command": "info", "data": 12345},
            {"success": True, "command": "info", "data": ["item1", "item2", 999]},
            {"success": True, "command": "disasm", "data": "plain string not dict"},
            {"success": False, "command": "error", "error": {"code": "ERR", "message": "msg"}},
        ]
        for env in adversarial_envelopes:
            for b in [None, 0, -100, 50, 1000000]:
                res = transform_response(env, budget=b)
                self.assertIsInstance(res, dict)
                if env.get("success"):
                    self.assertIn("data", res)
                else:
                    self.assertIn("error", res)
                self.assertIn("token_estimate", res)
                self.assertGreaterEqual(res["token_estimate"], 0)


if __name__ == "__main__":
    unittest.main()
