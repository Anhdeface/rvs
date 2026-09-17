#!/usr/bin/env python3
"""
tests/test_challenger_preview_r1_1.py - Empirical Challenger Stress Test Suite for rvs.

Adversarial Stress Testing of:
1. Frida spawn and attach targets:
   - Bare 'frida://' and 'frida:///' immediate return (< 1.0s) without hang/timeout.
   - Positive PID strings like '+1234' parsed cleanly as PID 1234 without overflow errors.
   - Contrast with actual numeric overflow strings returning INVALID_ARGUMENT (exit code 1).
   - Process arguments with spaces preserved and quoted in 'frida://spawn/...' URIs.
2. rvs_agent_harness.py:
   - Flag ordering in rvs_frida_spawn: verify --device and --timeout are positioned before --args
     so clap does not greedily consume them into debuggee arguments.
   - Timeout synchronization: watchdog timeout = frida_timeout + 5.0.
   - Parameter aliasing across all Frida tools:
     * 'target' instead of 'path' in spawn
     * 'pid' instead of 'target' in attach, modules, symbols, hooks
     * 'function' / 'symbol' instead of 'addr' in hooks and trace-regs
     * 'fmt' instead of 'format' in hook
     * 'regs' as list/tuple vs comma-separated string in trace-regs
     * 'value' / 'return_value' / 'ret' instead of 'retval' in hook-return
     * 'address' instead of 'addr', 'length' / 'size' instead of 'len' in mem-read
     * 'address' instead of 'addr', 'bytes' / 'hex_bytes' / 'hex' instead of 'data' in mem-write
     * 'lib' / 'library' instead of 'module' in symbols
     * 'params' / 'rpc_args' as dict/list in rpc
   - Missing required parameters returning standard ApiResponseDict envelopes with exit code 1.
"""

import json
import os
import shlex
import subprocess
import time
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"
import sys
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

from rvs_agent_harness import RvsHarness, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR


class TestEmpiricalChallengerPreviewR1_1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RVS_BIN.exists():
            res = subprocess.run(["cargo", "build"], cwd=WORKSPACE_DIR, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"cargo build failed: {res.stderr}")
        assert RVS_BIN.exists(), f"Binary not found at {RVS_BIN}"
        cls.harness = RvsHarness(rvs_bin=str(RVS_BIN))

    def run_rvs(self, args, timeout=10.0):
        cmd = [str(RVS_BIN)] + args
        start = time.perf_counter()
        res = subprocess.run(cmd, cwd=WORKSPACE_DIR, capture_output=True, text=True, timeout=timeout)
        elapsed = time.perf_counter() - start
        envelope = None
        if res.stdout.strip():
            try:
                envelope = json.loads(res.stdout)
            except json.JSONDecodeError as e:
                self.fail(f"Output is not valid JSON: {res.stdout}\nError: {e}")
        return res.returncode, envelope, res.stdout, res.stderr, elapsed

    # =========================================================================
    # Part 1: Frida Spawn & Attach Targets Stress Testing
    # =========================================================================

    def test_bare_frida_uri_immediate_return(self):
        """Bare 'frida://' must return immediately (< 1.0s) without hanging radare2."""
        ret, envelope, out, err, elapsed = self.run_rvs(["frida", "attach", "frida://"], timeout=5.0)
        self.assertLess(elapsed, 1.0, f"Bare frida:// took too long ({elapsed:.3f}s), expected immediate return")
        self.assertEqual(ret, 6, f"Expected exit code 6 (R2_FRIDA_NOT_INSTALLED), got {ret}")
        self.assertIsNotNone(envelope)
        self.assertFalse(envelope["success"])
        self.assertEqual(envelope["error"]["code"], "R2_FRIDA_NOT_INSTALLED")
        self.assertIn("must specify a target", envelope["error"]["message"])

    def test_bare_frida_trailing_slashes_immediate_return(self):
        """Bare 'frida:///' and 'frida://///' must return immediately (< 1.0s)."""
        for uri in ["frida:///", "frida:////", "frida://///"]:
            ret, envelope, out, err, elapsed = self.run_rvs(["frida", "attach", uri], timeout=5.0)
            self.assertLess(elapsed, 1.0, f"Bare URI {uri} took {elapsed:.3f}s, expected immediate return")
            self.assertEqual(ret, 6, f"Expected exit code 6 for {uri}, got {ret}")
            self.assertIsNotNone(envelope)
            self.assertFalse(envelope["success"])
            self.assertEqual(envelope["error"]["code"], "R2_FRIDA_NOT_INSTALLED")
            self.assertIn("must specify a target", envelope["error"]["message"])

    def test_positive_pid_parsing_no_overflow(self):
        """Positive PID strings like '+1234' must NOT trigger integer overflow error."""
        for pid_str in ["+1234", "+1", "+65535", "+99999"]:
            ret, envelope, out, err, elapsed = self.run_rvs(["frida", "attach", pid_str], timeout=5.0)
            # If parsed cleanly as PID, it proceeds to attach (which exits 6 since target PID doesn't exist)
            # It must NOT exit with code 1 (INVALID_ARGUMENT / overflow error).
            self.assertNotEqual(ret, 1, f"Positive PID {pid_str} erroneously failed with INVALID_ARGUMENT (exit code 1)")
            self.assertEqual(ret, 6, f"Expected exit code 6 (R2_FRIDA_NOT_INSTALLED / connection failure), got {ret}")
            self.assertIsNotNone(envelope)
            self.assertNotEqual(envelope["error"]["code"], "INVALID_ARGUMENT")
            self.assertNotIn("exceeds maximum allowable PID value", envelope["error"]["message"])

    def test_actual_overflow_pid_rejected(self):
        """Massive numeric strings exceeding u32::MAX must return INVALID_ARGUMENT (exit code 1)."""
        overflow_pid = "9999999999999999999999999999999999999999"
        ret, envelope, out, err, elapsed = self.run_rvs(["frida", "attach", overflow_pid], timeout=5.0)
        self.assertEqual(ret, 1, f"Expected exit code 1 for overflow PID, got {ret}")
        self.assertIsNotNone(envelope)
        self.assertFalse(envelope["success"])
        self.assertEqual(envelope["error"]["code"], "INVALID_ARGUMENT")
        self.assertIn("exceeds maximum allowable PID value", envelope["error"]["message"])

    def test_process_arguments_with_spaces_preserved(self):
        """Process arguments containing spaces must be quoted in the frida://spawn/... URI."""
        ret, envelope, out, err, elapsed = self.run_rvs(
            ["frida", "spawn", "/bin/ls", "--args", "--message", "hello world", "--flag", "spaced value with quotes \"inner\""],
            timeout=10.0,
        )
        self.assertEqual(ret, 0, f"Expected exit code 0 for frida spawn, got {ret}. Error: {err}")
        self.assertIsNotNone(envelope)
        self.assertTrue(envelope["success"])
        target_uri = envelope["data"]["target_uri"]
        # Verify that 'hello world' is quoted
        self.assertIn('"hello world"', target_uri, f"Expected '\"hello world\"' in target_uri, got: {target_uri}")
        # Verify that spaced value with inner quotes is properly escaped
        self.assertIn('"spaced value with quotes \\"inner\\""', target_uri, f"Quoting/escaping failed in target_uri: {target_uri}")

    # =========================================================================
    # Part 2: rvs_agent_harness.py Flag Ordering & Isolation
    # =========================================================================

    def test_harness_frida_spawn_flag_ordering(self):
        """Verify harness places --device and --timeout before --args to prevent clap greedy capture."""
        recorded_cmds = []

        def mock_run(cmd, *args, **kwargs):
            recorded_cmds.append((cmd, kwargs))
            return {"status": "ok", "data": {}}

        h = RvsHarness()
        h.run = mock_run

        # Invoke via frida_spawn
        h.frida_spawn(
            path="/bin/ls",
            args=["--custom-flag", "value", "--extra"],
            device="usb",
            frida_timeout=20,
        )
        self.assertEqual(len(recorded_cmds), 1)
        cmd, kwargs = recorded_cmds[0]
        self.assertIn("--device", cmd)
        self.assertIn("--timeout", cmd)
        self.assertIn("--args", cmd)

        device_idx = cmd.index("--device")
        timeout_idx = cmd.index("--timeout")
        args_idx = cmd.index("--args")

        self.assertLess(device_idx, args_idx, "--device must appear BEFORE --args")
        self.assertLess(timeout_idx, args_idx, "--timeout must appear BEFORE --args")
        self.assertEqual(kwargs.get("timeout"), 25.0, "Subprocess watchdog timeout must be synchronized to frida_timeout + 5s")

    def test_cli_clap_does_not_swallow_timeout_when_before_args(self):
        """Empirically test CLI binary: placing --timeout before --args preserves target_uri."""
        ret, envelope, out, err, elapsed = self.run_rvs(
            ["frida", "spawn", "/bin/ls", "--timeout", "15", "--args", "--flag", "val"],
            timeout=10.0,
        )
        self.assertEqual(ret, 0, f"Expected exit code 0, got {ret}")
        self.assertIsNotNone(envelope)
        target_uri = envelope["data"]["target_uri"]
        # --timeout 15 must NOT appear in the debuggee arguments
        self.assertNotIn("--timeout", target_uri, f"target_uri swallowed --timeout: {target_uri}")
        self.assertIn("--flag val", target_uri)

    # =========================================================================
    # Part 3: Parameter Aliasing Stress Testing in execute_tool
    # =========================================================================

    def test_parameter_aliasing_spawn(self):
        """'target' or 'file' instead of 'path' in rvs_frida_spawn."""
        recorded = []
        def mock_run(cmd, *args, **kwargs):
            recorded.append(cmd)
            return {"status": "ok", "data": {}}

        h = RvsHarness()
        h.run = mock_run

        # Case A: 'target' instead of 'path'
        h.execute_tool("rvs_frida_spawn", {"target": "/bin/ls", "args": ["-la"]})
        self.assertIn("/bin/ls", recorded[-1])
        self.assertIn("--args", recorded[-1])

        # Case B: 'file' instead of 'path'
        h.execute_tool("rvs_frida_spawn", {"file": "/bin/echo", "args": ["hi"]})
        self.assertIn("/bin/echo", recorded[-1])

        # Case C: 'args' passed as string instead of list (e.g. from LLM prompt)
        h.execute_tool("rvs_frida_spawn", {"path": "/bin/echo", "args": "--message 'hello world' --verbose"})
        self.assertIn("--message", recorded[-1])
        self.assertIn("hello world", recorded[-1])
        self.assertIn("--verbose", recorded[-1])

        # Case D: timeout passed as string
        h.execute_tool("rvs_frida_spawn", {"path": "/bin/echo", "timeout": "30"})
        self.assertIn("--timeout", recorded[-1])
        self.assertIn("30", recorded[-1])

    def test_parameter_aliasing_attach(self):
        """'pid', 'path', or 'file' instead of 'target' in rvs_frida_attach."""
        recorded = []
        def mock_run(cmd, *args, **kwargs):
            recorded.append(cmd)
            return {"status": "ok", "data": {}}

        h = RvsHarness()
        h.run = mock_run

        # 'pid' instead of 'target'
        h.execute_tool("rvs_frida_attach", {"pid": 5678})
        self.assertEqual(recorded[-1], ["frida", "attach", "5678"])

        # 'path' instead of 'target'
        h.execute_tool("rvs_frida_attach", {"path": "target_process"})
        self.assertEqual(recorded[-1], ["frida", "attach", "target_process"])

        # 'file' instead of 'target'
        h.execute_tool("rvs_frida_attach", {"file": "5678"})
        self.assertEqual(recorded[-1], ["frida", "attach", "5678"])

        # Ambient 'file' alongside 'target'
        h.execute_tool("rvs_frida_attach", {"target": "5678", "file": "/ambient/file"})
        self.assertEqual(recorded[-1], ["frida", "attach", "5678"])

    def test_parameter_aliasing_hook(self):
        """'function', 'symbol', 'target_addr' instead of 'addr', and 'fmt' instead of 'format'."""
        recorded = []
        def mock_run(cmd, *args, **kwargs):
            recorded.append(cmd)
            return {"status": "ok", "data": {}}

        h = RvsHarness()
        h.run = mock_run

        # 'function' and 'fmt'
        h.execute_tool("rvs_frida_hook", {"target": "1234", "function": "sym.login", "fmt": "zi"})
        self.assertEqual(recorded[-1], ["frida", "hook", "--target", "1234", "--addr", "sym.login", "--format", "zi"])

        # 'symbol'
        h.execute_tool("rvs_frida_hook", {"pid": 1234, "symbol": "sym.check"})
        self.assertIn("--addr", recorded[-1])
        self.assertIn("sym.check", recorded[-1])

    def test_parameter_aliasing_trace_regs(self):
        """'regs' as array vs string, and 'registers' alias."""
        recorded = []
        def mock_run(cmd, *args, **kwargs):
            recorded.append(cmd)
            return {"status": "ok", "data": {}}

        h = RvsHarness()
        h.run = mock_run

        # 'regs' as list
        h.execute_tool("rvs_frida_trace_regs", {"target": "1234", "addr": "0x401000", "regs": ["rax", "rdi", "rsi"]})
        self.assertIn("--regs", recorded[-1])
        self.assertIn("rax,rdi,rsi", recorded[-1])

        # 'registers' as string
        h.execute_tool("rvs_frida_trace_regs", {"pid": 1234, "function": "main", "registers": "eax,ebx"})
        self.assertIn("--regs", recorded[-1])
        self.assertIn("eax,ebx", recorded[-1])

    def test_parameter_aliasing_hook_return(self):
        """'value', 'return_value', 'ret' instead of 'retval'."""
        recorded = []
        def mock_run(cmd, *args, **kwargs):
            recorded.append(cmd)
            return {"status": "ok", "data": {}}

        h = RvsHarness()
        h.run = mock_run

        for val_key in ["value", "return_value", "ret", "retval"]:
            h.execute_tool("rvs_frida_hook_return", {"target": "1234", "addr": "0x401000", val_key: 0})
            self.assertEqual(recorded[-1], ["frida", "hook-return", "--target", "1234", "--addr", "0x401000", "--retval", "0"])

    def test_parameter_aliasing_memory_and_rpc(self):
        """mem_read, mem_write, symbols, rpc aliases."""
        recorded = []
        def mock_run(cmd, *args, **kwargs):
            recorded.append(cmd)
            return {"status": "ok", "data": {}}

        h = RvsHarness()
        h.run = mock_run

        # mem_read address & length
        h.execute_tool("rvs_frida_mem_read", {"pid": 1234, "address": "0x5000", "length": 128})
        self.assertEqual(recorded[-1], ["frida", "mem-read", "--target", "1234", "--addr", "0x5000", "--len", "128"])

        # mem_write address & hex_bytes
        h.execute_tool("rvs_frida_mem_write", {"pid": 1234, "address": "0x5000", "hex_bytes": "cc90"})
        self.assertEqual(recorded[-1], ["frida", "mem-write", "--target", "1234", "--addr", "0x5000", "--data", "cc90"])

        # symbols lib
        h.execute_tool("rvs_frida_symbols", {"pid": 1234, "lib": "libcrypto.so"})
        self.assertIn("--module", recorded[-1])
        self.assertIn("libcrypto.so", recorded[-1])

        # rpc params as list
        h.execute_tool("rvs_frida_rpc", {"pid": 1234, "name": "do_work", "params": [1, 2, "three"]})
        self.assertEqual(recorded[-1], ["frida", "rpc", "--target", "1234", "--method", "do_work", "--args", '[1, 2, "three"]'])

    def test_missing_required_parameters_error_envelopes(self):
        """Omitting required parameters across tools must return ApiResponseDict with exit_code 1."""
        h = RvsHarness()

        tool_cases = [
            ("rvs_frida_spawn", {}),
            ("rvs_frida_attach", {}),
            ("rvs_frida_hook", {"target": "1234"}),
            ("rvs_frida_hook", {"addr": "0x1000"}),
            ("rvs_frida_trace_regs", {"target": "1234", "addr": "0x1000"}),
            ("rvs_frida_hook_return", {"target": "1234", "addr": "0x1000"}),
            ("rvs_frida_mem_read", {"target": "1234"}),
            ("rvs_frida_mem_write", {"target": "1234", "addr": "0x1000"}),
            ("rvs_frida_rpc", {"target": "1234"}),
        ]

        for tool_name, args in tool_cases:
            res = h.execute_tool(tool_name, args)
            self.assertFalse(res["success"], f"Tool {tool_name} should have failed on args {args}")
            self.assertIsNotNone(res["error"])
            self.assertEqual(res["error"]["code"], "INVALID_ARGUMENT")
            self.assertEqual(res["error"]["exit_code"], EXIT_INVALID_ARGUMENT)
            self.assertIn("Missing required", res["error"]["message"])


if __name__ == "__main__":
    unittest.main()
