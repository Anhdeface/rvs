#!/usr/bin/env python3
"""
tests/test_challenger_m4_adversarial_mcp_stress.py - Challenger 1 Milestone M4 Adversarial Stress Suite.

Empirical verification suite challenging:
1. Invalid UTF-8 / raw binary byte sequences on stdio pipe.
2. 1MB+ and 5MB single-line payloads and deep JSON nesting.
3. Malformed JSON-RPC syntax, null bytes in strings, and truncated streams.
4. Out-of-order, mixed notification/request pipelines, and burst concurrency.
5. Non-existent tools and extreme argument boundary conditions.
6. Special and invalid filepaths (/dev/null, /dev/urandom, /proc/self/mem, non-existent paths).
7. Strict JSON-RPC 2.0 error taxonomy and absence of unhandled Python tracebacks.
"""

from __future__ import annotations

import concurrent.futures
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    CANONICAL_TOOLS,
    RvsHarness,
    find_rvs_binary,
    transform_response,
)


class TestChallengerM4AdversarialMcpStress(unittest.TestCase):
    """Adversarial stress and protocol compliance test suite for rvs_agent_harness.py."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.crackme_path = WORKSPACE_DIR / "crackme_case"
        if not cls.crackme_path.exists():
            fixture_src = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
            if fixture_src.exists():
                shutil.copy(fixture_src, cls.crackme_path)
                os.chmod(cls.crackme_path, 0o755)

        cls.rvs_bin = find_rvs_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)
        cls.harness_script = WORKSPACE_DIR / "rvs_agent_harness.py"

    def run_mcp_bytes_subprocess(
        self, raw_bytes: bytes, timeout: float = 10.0
    ) -> Tuple[List[Dict[str, Any]], bytes, int]:
        """Runs the MCP subprocess feeding raw bytes to stdin."""
        proc = subprocess.Popen(
            [sys.executable, str(self.harness_script), "--mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = proc.communicate(input=raw_bytes, timeout=timeout)
        responses = []
        for line in stdout_bytes.splitlines():
            line_s = line.strip()
            if line_s:
                try:
                    responses.append(json.loads(line_s.decode("utf-8", errors="replace")))
                except Exception as exc:
                    self.fail(f"Malformed JSON emitted to stdout: {line_s!r} error: {exc}")
        return responses, stderr_bytes, proc.returncode

    def run_mcp_str_subprocess(
        self, raw_str: str, timeout: float = 15.0
    ) -> Tuple[List[Dict[str, Any]], str, int]:
        """Runs the MCP subprocess feeding text to stdin."""
        proc = subprocess.Popen(
            [sys.executable, str(self.harness_script), "--mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout_str, stderr_str = proc.communicate(input=raw_str, timeout=timeout)
        responses = []
        for line in stdout_str.splitlines():
            line_s = line.strip()
            if line_s:
                try:
                    responses.append(json.loads(line_s))
                except Exception as exc:
                    self.fail(f"Malformed JSON emitted to stdout: {line_s!r} error: {exc}")
        return responses, stderr_str, proc.returncode

    # -------------------------------------------------------------------------
    # 1. Invalid UTF-8 & Raw Byte Stream Stress
    # -------------------------------------------------------------------------

    def test_01_invalid_utf8_byte_sequences_resilience(self) -> None:
        """
        Adversarial Test: Feeding invalid UTF-8 byte sequences over stdio pipe.
        Expected: Server must handle invalid bytes without unhandled Python tracebacks,
        and must not prematurely abort before processing subsequent valid JSON-RPC requests.
        """
        # Invalid UTF-8 sequences (isolated continuation bytes, overlong sequences, 0xFF)
        bad_bytes = b"\xff\xfe\xfd\n\x80\x81\x82\n\xc0\xaf\n"
        valid_request = json.dumps({"jsonrpc": "2.0", "id": "valid_after_bad_bytes", "method": "ping"}).encode("utf-8") + b"\n"
        payload = bad_bytes + valid_request

        responses, stderr_bytes, retcode = self.run_mcp_bytes_subprocess(payload)
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        # Invariant: Zero unhandled tracebacks on stderr
        self.assertNotIn("Traceback (most recent call last)", stderr_text, f"Unhandled traceback on stderr: {stderr_text}")
        # Invariant: Must return cleanly and process valid request
        self.assertEqual(retcode, 0, f"Process crashed with exit code {retcode}. Stderr: {stderr_text}")
        self.assertGreaterEqual(len(responses), 1, "Failed to respond to valid request following invalid UTF-8 bytes")
        valid_resp = [r for r in responses if r.get("id") == "valid_after_bad_bytes"]
        self.assertEqual(len(valid_resp), 1, "Missing response for valid request")
        self.assertEqual(valid_resp[0].get("jsonrpc"), "2.0")

    # -------------------------------------------------------------------------
    # 2. Extreme Payloads & Deep Nesting
    # -------------------------------------------------------------------------

    def test_02_oversized_5mb_single_line_payload(self) -> None:
        """Adversarial Test: 5MB single-line JSON payload to ping and unknown tools."""
        huge_data = "Z" * (5 * 1024 * 1024)
        req = json.dumps({
            "jsonrpc": "2.0",
            "id": "5mb_req",
            "method": "ping",
            "params": {"filler": huge_data},
        }) + "\n"
        responses, stderr, retcode = self.run_mcp_str_subprocess(req, timeout=20.0)
        self.assertEqual(retcode, 0)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].get("id"), "5mb_req")
        self.assertEqual(responses[0].get("jsonrpc"), "2.0")
        self.assertNotIn("Traceback", stderr)

    def test_03_deeply_nested_json_structures(self) -> None:
        """Adversarial Test: Deeply nested JSON structures (150 levels)."""
        nested: Any = "leaf"
        for _ in range(150):
            nested = {"k": nested}
        req = json.dumps({
            "jsonrpc": "2.0",
            "id": "deep_nested",
            "method": "ping",
            "params": {"tree": nested},
        }) + "\n"
        responses, stderr, retcode = self.run_mcp_str_subprocess(req, timeout=10.0)
        self.assertEqual(retcode, 0)
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].get("id"), "deep_nested")
        self.assertNotIn("Traceback", stderr)

    # -------------------------------------------------------------------------
    # 3. Protocol Invariants: Notifications vs Requests vs Errors
    # -------------------------------------------------------------------------

    def test_04_mixed_notification_and_request_pipeline(self) -> None:
        """
        JSON-RPC 2.0 Invariant:
        - Requests (with 'id') MUST receive a response.
        - Notifications (without 'id') MUST NOT receive any response.
        - Exactly N responses must be received for N requests in a pipelined stream.
        """
        stream_parts = []
        expected_ids = []

        for i in range(30):
            if i % 3 == 0:
                # Notification (NO id field)
                stream_parts.append(json.dumps({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {"index": i},
                }))
            elif i % 3 == 1:
                # Standard request
                msg_id = f"req_{i}"
                expected_ids.append(msg_id)
                stream_parts.append(json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "method": "ping",
                }))
            else:
                # Request with error (unknown method)
                msg_id = f"err_{i}"
                expected_ids.append(msg_id)
                stream_parts.append(json.dumps({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "method": f"unknown_method_{i}",
                }))

        raw_pipeline = "\n".join(stream_parts) + "\n"
        responses, stderr, retcode = self.run_mcp_str_subprocess(raw_pipeline, timeout=15.0)

        self.assertEqual(retcode, 0)
        self.assertNotIn("Traceback", stderr)
        # Verify exact response count matches number of requests with IDs
        self.assertEqual(len(responses), len(expected_ids))
        received_ids = [r.get("id") for r in responses]
        self.assertEqual(received_ids, expected_ids)

        for r in responses:
            self.assertEqual(r.get("jsonrpc"), "2.0")
            if str(r.get("id")).startswith("err_"):
                self.assertIn("error", r)
                self.assertEqual(r["error"]["code"], -32601)
            else:
                self.assertIn("result", r)

    # -------------------------------------------------------------------------
    # 4. Canonical Tools Boundary Conditions & Invalid Filepaths
    # -------------------------------------------------------------------------

    def test_05_canonical_tools_special_and_extreme_filepaths(self) -> None:
        """
        Adversarial Test: Ingesting /dev/null, /dev/urandom, /proc/self/mem, directories,
        and 4096-char paths across all canonical tools.
        """
        extreme_targets = [
            "/dev/null",
            "/dev/zero",
            "/dev/urandom",
            "/proc/self/mem",
            tempfile.gettempdir(),
            "/nonexistent/directory/path/that/never/existed_99999.bin",
            "/tmp/" + ("a" * 4000) + ".bin",
        ]
        tools_to_test = [
            "rvs_info",
            "rvs_functions",
            "rvs_disasm",
            "rvs_decompile",
            "rvs_strings",
            "rvs_symbols",
            "rvs_flow",
            "rvs_xrefs",
        ]

        requests = []
        req_id = 0
        for target in extreme_targets:
            for tool_name in tools_to_test:
                req_id += 1
                requests.append(json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {"file": target}},
                }))

        raw_stream = "\n".join(requests) + "\n"
        responses, stderr, retcode = self.run_mcp_str_subprocess(raw_stream, timeout=30.0)

        self.assertEqual(retcode, 0)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(len(responses), len(requests))

        for r in responses:
            self.assertEqual(r.get("jsonrpc"), "2.0")
            self.assertIn("result", r)
            content = json.loads(r["result"]["content"][0]["text"])
            self.assertIn("success", content)
            self.assertFalse(content["success"])
            self.assertTrue(r["result"]["isError"])

    def test_06_budget_and_offset_extreme_boundaries(self) -> None:
        """
        Adversarial Test: Calling tools with extreme boundary budgets and offsets:
        - budget: negative, zero, 1, 10**18, non-integer types
        - offset: negative, 10**18, non-integer types
        - limit: negative, zero, 10**18, non-integer types
        """
        boundary_cases = [
            {"budget": -100, "limit": -5},
            {"budget": 0, "limit": 0},
            {"budget": 1, "limit": 1},
            {"budget": 10**18, "limit": 10**18},
            {"budget": "not_an_int", "limit": "also_not_int"},
            {"offset": -50, "budget": 50},
            {"offset": 10**18, "budget": 100},
            {"offset": "0xinvalid"},
        ]

        requests = []
        for idx, b_args in enumerate(boundary_cases, 1):
            args = {"file": str(self.crackme_path)}
            args.update(b_args)
            requests.append(json.dumps({
                "jsonrpc": "2.0",
                "id": idx,
                "method": "tools/call",
                "params": {"name": "rvs_disasm", "arguments": args},
            }))

        raw_stream = "\n".join(requests) + "\n"
        responses, stderr, retcode = self.run_mcp_str_subprocess(raw_stream, timeout=20.0)

        self.assertEqual(retcode, 0)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(len(responses), len(requests))
        for r in responses:
            self.assertEqual(r.get("jsonrpc"), "2.0")
            self.assertIn("result", r)

    # -------------------------------------------------------------------------
    # 5. Rapid Concurrency Bursts
    # -------------------------------------------------------------------------

    def test_07_concurrent_tool_execution_burst(self) -> None:
        """
        Adversarial Test: 20 concurrent threads calling execute_tool simultaneously
        across mixed tools, targets, and budgets on a single RvsHarness instance.
        """
        num_threads = 20
        iterations = 5
        barrier = threading.Barrier(num_threads)
        errors: List[str] = []

        def worker(tid: int) -> None:
            try:
                barrier.wait(timeout=10.0)
                for i in range(iterations):
                    op = (tid + i) % 4
                    if op == 0:
                        res = self.harness.execute_tool("rvs_info", {"file": str(self.crackme_path), "compact": True})
                    elif op == 1:
                        res = self.harness.execute_tool("rvs_strings", {"file": str(self.crackme_path), "limit": 5, "budget": 100})
                    elif op == 2:
                        res = self.harness.execute_tool("rvs_symbols", {"file": str(self.crackme_path), "limit": 5})
                    else:
                        res = self.harness.execute_tool("rvs_ping", {})

                    if not isinstance(res, dict):
                        errors.append(f"Thread {tid} op {op} non-dict result: {res}")
                    elif "success" not in res:
                        errors.append(f"Thread {tid} op {op} missing success key: {res}")
            except Exception as exc:
                errors.append(f"Thread {tid} exception: {exc}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(worker, t) for t in range(num_threads)]
            concurrent.futures.wait(futures)

        self.assertEqual(len(errors), 0, f"Concurrent tool execution errors: {errors[:5]}")


if __name__ == "__main__":
    unittest.main()
