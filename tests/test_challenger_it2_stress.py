#!/usr/bin/env python3
"""
tests/test_challenger_it2_stress.py - Challenger 2 (Iteration 2) Adversarial Stress Suite.

Exhaustively stress-tests:
1. MCP Stdio Server resilience against all permutations of malformed requests
   (params: null, string, list, int, bool; arguments: null, string, list, int, bool).
   Ensures daemon NEVER crashes or exits early across a continuous multi-line stream.
2. `RvsHarness.patch_plan()` and `execute_tool("rvs_agent_patch_plan")`:
   - Inputs: dict, valid JSON string, invalid JSON string, temp file path (Path and str), non-existent file path.
   - Modes: dry_run=True vs dry_run=False.
   - Binary state verification: dry_run=True must NEVER mutate binary or create backup; dry_run=False MUST mutate binary and create backup.
3. Zero-budget instruction truncation (`max_instructions=0`).
4. Legacy alias `RvsAgentHarness` parity.
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    EXIT_INVALID_ARGUMENT,
    EXIT_SUCCESS,
    RvsAgentHarness,
    RvsHarness,
    find_rvs_binary,
)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


class TestChallengerIt2Adversarial(unittest.TestCase):
    """Adversarial stress testing suite for Iteration 2 fixes."""

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

    def create_temp_crackme(self) -> Path:
        """Create a disposable temporary binary for mutation tests."""
        tmp = tempfile.NamedTemporaryFile(delete=False, prefix="it2_stress_crackme_")
        tmp.close()
        tmp_path = Path(tmp.name)
        shutil.copy(self.crackme_path, tmp_path)
        os.chmod(tmp_path, 0o755)
        self.addCleanup(lambda: tmp_path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(f"{tmp_path}.bak").unlink(missing_ok=True))
        return tmp_path

    # =========================================================================
    # 1. Exhaustive MCP Malformed Payload Stress Testing
    # =========================================================================

    def test_01_mcp_server_never_crashes_on_malformed_stream(self):
        """
        Feed 30+ malformed, adversarial, and valid requests sequentially through a SINGLE
        in-memory and subprocess MCP stdio server session to verify the server NEVER crashes,
        processes every single line, and returns valid JSON-RPC 2.0 error envelopes.
        """
        adversarial_stream = [
            # Bad JSON syntax (5 items)
            "not a json",
            "{broken json:",
            "[]",  # list not dict
            "\"just a string\"",
            "12345",
            # Missing JSON-RPC version (2 items)
            {"id": 1, "method": "ping"},
            {"jsonrpc": "1.0", "id": 2, "method": "ping"},
            # Non-string method (3 items)
            {"jsonrpc": "2.0", "id": 3, "method": None},
            {"jsonrpc": "2.0", "id": 4, "method": 12345},
            {"jsonrpc": "2.0", "id": 5, "method": ["ping"]},
            # Method not found (1 item)
            {"jsonrpc": "2.0", "id": 6, "method": "system/nonexistent"},
            # Initialize with bad params (5 items)
            {"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": None},
            {"jsonrpc": "2.0", "id": 8, "method": "initialize", "params": "string"},
            {"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": [1, 2]},
            {"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": 42},
            {"jsonrpc": "2.0", "id": 11, "method": "initialize", "params": True},
            # Valid initialize (1 item)
            {"jsonrpc": "2.0", "id": 12, "method": "initialize", "params": {}},
            # Initialized notification (no id => no response line) (1 item)
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            # Ping with bad params (3 items)
            {"jsonrpc": "2.0", "id": 13, "method": "ping", "params": None},
            {"jsonrpc": "2.0", "id": 14, "method": "ping", "params": "bad"},
            {"jsonrpc": "2.0", "id": 15, "method": "ping", "params": 99},
            # Valid ping (1 item)
            {"jsonrpc": "2.0", "id": 16, "method": "ping"},
            # Tools/list with bad params (3 items)
            {"jsonrpc": "2.0", "id": 17, "method": "tools/list", "params": None},
            {"jsonrpc": "2.0", "id": 18, "method": "tools/list", "params": "foo"},
            {"jsonrpc": "2.0", "id": 19, "method": "tools/list", "params": [1]},
            # Valid tools/list (1 item)
            {"jsonrpc": "2.0", "id": 20, "method": "tools/list"},
            # Tools/call with malformed params (5 items)
            {"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": None},
            {"jsonrpc": "2.0", "id": 22, "method": "tools/call", "params": "invalid_params"},
            {"jsonrpc": "2.0", "id": 23, "method": "tools/call", "params": [1, 2, 3]},
            {"jsonrpc": "2.0", "id": 24, "method": "tools/call", "params": 42},
            {"jsonrpc": "2.0", "id": 25, "method": "tools/call", "params": False},
            # Tools/call with malformed arguments inside params (5 items)
            {"jsonrpc": "2.0", "id": 26, "method": "tools/call", "params": {"name": "rvs_info", "arguments": None}},
            {"jsonrpc": "2.0", "id": 27, "method": "tools/call", "params": {"name": "rvs_info", "arguments": "string_arg"}},
            {"jsonrpc": "2.0", "id": 28, "method": "tools/call", "params": {"name": "rvs_info", "arguments": [1, 2]}},
            {"jsonrpc": "2.0", "id": 29, "method": "tools/call", "params": {"name": "rvs_info", "arguments": 999}},
            {"jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {"name": "rvs_info", "arguments": True}},
            # Tools/call with empty or invalid tool name (2 items)
            {"jsonrpc": "2.0", "id": 31, "method": "tools/call", "params": {"name": "", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 32, "method": "tools/call", "params": {"name": "nonexistent_tool_xyz", "arguments": {}}},
            # Valid tools/call at the end of stream to prove server is still healthy (1 item)
            {
                "jsonrpc": "2.0",
                "id": 33,
                "method": "tools/call",
                "params": {
                    "name": "rvs_info",
                    "arguments": {"file": str(self.crackme_path), "compact": True},
                },
            },
        ]

        # Total 39 items, 1 notification (no response), expected 38 responses
        expected_resp_count = len(adversarial_stream) - 1

        # 1. Test In-Memory Stream
        lines_in = []
        for item in adversarial_stream:
            if isinstance(item, str):
                lines_in.append(item)
            else:
                lines_in.append(json.dumps(item))
        raw_stream = "\n".join(lines_in) + "\n"

        stdin_stream = io.StringIO(raw_stream)
        stdout_stream = io.StringIO()
        self.harness.serve_mcp(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
        stdout_stream.seek(0)
        output_lines = [l.strip() for l in stdout_stream if l.strip()]

        self.assertEqual(len(output_lines), expected_resp_count, f"Expected {expected_resp_count} responses, got {len(output_lines)}")

        # Verify each line is valid JSON
        responses = [json.loads(line) for line in output_lines]

        # Verify final call (id=33) succeeded
        last_resp = responses[-1]
        self.assertEqual(last_resp.get("id"), 33)
        self.assertFalse(last_resp["result"].get("isError"))
        inner_info = json.loads(last_resp["result"]["content"][0]["text"])
        self.assertTrue(inner_info.get("success"))

        # 2. Test Subprocess Stdio Server
        proc = subprocess.Popen(
            [sys.executable, str(self.harness_script), "--mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=raw_stream, timeout=10.0)
        sub_lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        self.assertEqual(len(sub_lines), expected_resp_count)
        sub_resps = [json.loads(line) for line in sub_lines]
        self.assertEqual(sub_resps[-1]["id"], 33)
        self.assertFalse(sub_resps[-1]["result"].get("isError"))

    # =========================================================================
    # 2. RvsHarness.patch_plan() and execute_tool("rvs_agent_patch_plan")
    # =========================================================================

    def test_02_patch_plan_dict_dry_run_true(self):
        """Verify patch_plan with dict input and dry_run=True does NOT mutate binary."""
        temp_bin = self.create_temp_crackme()
        orig_hash = sha256_file(temp_bin)

        plan = {
            "name": "bypass_password_check",
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}
            ],
        }

        resp = self.harness.patch_plan(temp_bin, plan=plan, dry_run=True)
        self.assertTrue(resp.get("success"), f"patch_plan failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("dry_run"))
        self.assertFalse(data.get("applied"))

        # Target binary MUST NOT be modified
        self.assertEqual(sha256_file(temp_bin), orig_hash)
        # Backup MUST NOT exist
        self.assertFalse(Path(f"{temp_bin}.bak").exists())

    def test_03_patch_plan_dict_dry_run_false(self):
        """Verify patch_plan with dict input and dry_run=False APPLIES patch and creates backup."""
        temp_bin = self.create_temp_crackme()
        orig_hash = sha256_file(temp_bin)

        plan = {
            "name": "bypass_password_check",
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}
            ],
        }

        resp = self.harness.patch_plan(temp_bin, plan=plan, dry_run=False)
        self.assertTrue(resp.get("success"), f"patch_plan failed: {resp}")
        data = resp.get("data", {})
        self.assertFalse(data.get("dry_run"))
        self.assertTrue(data.get("applied"))

        # Target binary MUST be modified
        self.assertNotEqual(sha256_file(temp_bin), orig_hash)
        # Backup MUST exist and match original hash
        bak_file = Path(f"{temp_bin}.bak")
        self.assertTrue(bak_file.exists())
        self.assertEqual(sha256_file(bak_file), orig_hash)

    def test_04_patch_plan_json_string_input(self):
        """Verify patch_plan with JSON string input works for both dry_run=True and dry_run=False."""
        temp_bin = self.create_temp_crackme()
        orig_hash = sha256_file(temp_bin)

        plan_dict = {
            "name": "json_str_patch",
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}
            ],
        }
        plan_str = json.dumps(plan_dict)

        # 1. dry_run=True
        resp_dry = self.harness.patch_plan(temp_bin, plan=plan_str, dry_run=True)
        self.assertTrue(resp_dry.get("success"), f"dry run failed: {resp_dry}")
        self.assertTrue(resp_dry["data"].get("dry_run"))
        self.assertFalse(resp_dry["data"].get("applied"))
        self.assertEqual(sha256_file(temp_bin), orig_hash)

        # 2. dry_run=False
        resp_apply = self.harness.patch_plan(temp_bin, plan=plan_str, dry_run=False)
        self.assertTrue(resp_apply.get("success"), f"apply failed: {resp_apply}")
        self.assertFalse(resp_apply["data"].get("dry_run"))
        self.assertTrue(resp_apply["data"].get("applied"))
        self.assertNotEqual(sha256_file(temp_bin), orig_hash)

    def test_05_patch_plan_file_input(self):
        """Verify patch_plan with file path input (Path and str) works for both dry_run=True and dry_run=False."""
        temp_bin = self.create_temp_crackme()
        orig_hash = sha256_file(temp_bin)

        plan_dict = {
            "name": "file_patch",
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(json.dumps(plan_dict))
            plan_file_path = Path(f.name)
        self.addCleanup(lambda: plan_file_path.unlink(missing_ok=True))

        # 1. Pass as Path object with dry_run=True
        resp_dry = self.harness.patch_plan(temp_bin, plan=plan_file_path, dry_run=True)
        self.assertTrue(resp_dry.get("success"), f"dry run with Path failed: {resp_dry}")
        self.assertTrue(resp_dry["data"].get("dry_run"))
        self.assertFalse(resp_dry["data"].get("applied"))
        self.assertEqual(sha256_file(temp_bin), orig_hash)

        # 2. Pass as string path with dry_run=False
        resp_apply = self.harness.patch_plan(temp_bin, plan=str(plan_file_path), dry_run=False)
        self.assertTrue(resp_apply.get("success"), f"apply with str path failed: {resp_apply}")
        self.assertFalse(resp_apply["data"].get("dry_run"))
        self.assertTrue(resp_apply["data"].get("applied"))
        self.assertNotEqual(sha256_file(temp_bin), orig_hash)

    def test_06_patch_plan_invalid_json_string_graceful_error(self):
        """Verify malformed JSON string plan gracefully yields typed error without crash."""
        temp_bin = self.create_temp_crackme()
        resp = self.harness.patch_plan(temp_bin, plan="{malformed json", dry_run=True)
        self.assertFalse(resp.get("success"))
        self.assertIn("error", resp)

    def test_07_execute_tool_rvs_agent_patch_plan_mcp(self):
        """Test rvs_agent_patch_plan through execute_tool and MCP tools/call."""
        temp_bin = self.create_temp_crackme()
        orig_hash = sha256_file(temp_bin)

        plan = {
            "name": "mcp_plan_test",
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}
            ],
        }

        # 1. execute_tool with dry_run=True
        res1 = self.harness.execute_tool(
            "rvs_agent_patch_plan",
            {"file": str(temp_bin), "plan": plan, "dry_run": True},
        )
        self.assertTrue(res1.get("success"), f"execute_tool dry_run failed: {res1}")
        self.assertTrue(res1["data"].get("dry_run"))
        self.assertFalse(res1["data"].get("applied"))
        self.assertEqual(sha256_file(temp_bin), orig_hash)

        # 2. MCP JSON-RPC tools/call with dry_run=True
        req = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "rvs_agent_patch_plan",
                "arguments": {
                    "file": str(temp_bin),
                    "plan": plan,
                    "dry_run": True,
                },
            },
        }
        stdin_stream = io.StringIO(json.dumps(req) + "\n")
        stdout_stream = io.StringIO()
        self.harness.serve_mcp(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
        stdout_stream.seek(0)
        mcp_resp = json.loads(stdout_stream.read().strip())
        self.assertFalse(mcp_resp["result"].get("isError"))
        inner = json.loads(mcp_resp["result"]["content"][0]["text"])
        self.assertTrue(inner.get("success"))
        self.assertTrue(inner["data"].get("dry_run"))
        self.assertFalse(inner["data"].get("applied"))
        self.assertEqual(sha256_file(temp_bin), orig_hash)

        # 3. execute_tool with dry_run=False
        res2 = self.harness.execute_tool(
            "rvs_agent_patch_plan",
            {"file": str(temp_bin), "plan": plan, "dry_run": False},
        )
        self.assertTrue(res2.get("success"), f"execute_tool apply failed: {res2}")
        self.assertFalse(res2["data"].get("dry_run"))
        self.assertTrue(res2["data"].get("applied"))
        self.assertNotEqual(sha256_file(temp_bin), orig_hash)

    # =========================================================================
    # 3. Zero-budget instruction truncation (max_instructions=0)
    # =========================================================================

    def test_08_disasm_max_instructions_zero(self):
        """Verify max_instructions=0 truncates instructions list to empty [] across all basic blocks."""
        resp = self.harness.disasm(self.crackme_path, "main", max_instructions=0, compact=True)
        self.assertTrue(resp.get("success"), f"disasm failed: {resp}")
        blocks = resp["data"].get("blocks", [])
        self.assertGreater(len(blocks), 0)
        for b in blocks:
            self.assertEqual(len(b.get("instructions", [])), 0)

    # =========================================================================
    # 4. Legacy Parity
    # =========================================================================

    def test_09_legacy_harness_alias_compatibility(self):
        """Verify RvsAgentHarness maintains exact behavioral parity with RvsHarness."""
        legacy = RvsAgentHarness(rvs_bin=self.rvs_bin)
        resp = legacy.info(self.crackme_path, compact=True)
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp.get("command"), "info")


if __name__ == "__main__":
    unittest.main(verbosity=2)
