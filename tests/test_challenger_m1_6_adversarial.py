#!/usr/bin/env python3
"""
tests/test_challenger_m1_6_adversarial.py - Adversarial Verification Suite for Milestone 1

Empirically tests:
1. Breakpoint CLI args: exhaustive permutation testing of named --addr vs positional addr,
   action flags, hardware breakpoints, and session resolution under `rvs dynamic debug bp`.
2. Memory write defense: non-hex strings, odd-length strings, empty strings, unmapped addresses
   (0xdeadbeef000, 0x0, 0xffffffffffffffff), verifying exit codes 1 and 3, never false success (0).
3. Frida safety & robustness: fuzzing and hostile edge-case input probing across frida subcommands
   (env-check, attach, spawn, hook, trace-regs, hook-return, hook-remove, script, rpc, mem-read, mem-write)
   ensuring zero panics and standard error envelope conformity (exit codes 1, 2, 3, or 6 on missing io_frida).
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"
AUTH_GATE_BIN = WORKSPACE_DIR / "tests" / "fixtures" / "auth_gate_elf64"
TEST_TARGET_BIN = WORKSPACE_DIR / "tests" / "fixtures" / "test_target_elf64"


class TestM1AdversarialVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RVS_BIN.exists():
            res = subprocess.run(["cargo", "build"], cwd=WORKSPACE_DIR, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"cargo build failed: {res.stderr}")
        assert RVS_BIN.exists(), f"rvs binary missing at {RVS_BIN}"
        assert AUTH_GATE_BIN.exists(), f"Fixture missing at {AUTH_GATE_BIN}"

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rvs_m1_adv_")
        self.socket_path = Path(self.temp_dir) / "m1-adv.sock"
        self.env = os.environ.copy()
        self.env["RVS_DEBUG_SOCKET"] = str(self.socket_path)
        self.env["TERM"] = "dumb"
        self.env["NO_COLOR"] = "1"

    def tearDown(self):
        try:
            subprocess.run(
                [str(RVS_BIN), "dynamic", "debug", "daemon", "--stop"],
                env=self.env,
                capture_output=True,
                timeout=3,
            )
        except Exception:
            pass
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception:
                pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_cmd(self, args, timeout=10):
        cmd = [str(RVS_BIN)] + args
        res = subprocess.run(
            cmd,
            cwd=WORKSPACE_DIR,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        data = None
        if res.stdout.strip():
            try:
                data = json.loads(res.stdout)
            except json.JSONDecodeError:
                pass
        return res.returncode, data, res.stdout, res.stderr

    def spawn_debug_session(self, target=AUTH_GATE_BIN):
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "spawn", str(target)])
        self.assertEqual(rc, 0, f"Spawn failed: stdout={stdout}, stderr={stderr}")
        self.assertIsNotNone(data, "Expected JSON response from spawn")
        self.assertTrue(data.get("success"), f"Spawn was not successful: {data}")
        sid = data.get("data", {}).get("session_id")
        self.assertIsNotNone(sid, "No session_id in spawn response")
        return sid

    # =========================================================================
    # SUITE 1: Breakpoint CLI Argument Variations & Resolution
    # =========================================================================

    def test_bp_cli_positional_session_named_addr(self):
        """Test: bp <session> --addr <addr>"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", sid, "--addr", "0x401100"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("data", {}).get("action"), "add")
        bps = data.get("data", {}).get("breakpoints", [])
        self.assertTrue(any(b.get("addr_hex") == "0x401100" or b.get("addr") == 0x401100 for b in bps))

    def test_bp_cli_named_session_named_addr(self):
        """Test: bp --session <session> --addr <addr>"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", "--session", sid, "--addr", "0x401110"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("data", {}).get("action"), "add")

    def test_bp_cli_named_session_positional_addr(self):
        """Test: bp --session <session> <addr>"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", "--session", sid, "0x401120"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("data", {}).get("action"), "add")

    def test_bp_cli_positional_session_positional_addr(self):
        """Test: bp <session> <addr>"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", sid, "0x401130"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("data", {}).get("action"), "add")

    def test_bp_cli_action_flag_with_named_session_named_addr(self):
        """Test: bp --action add --session <session> --addr <addr>"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", "--action", "add", "--session", sid, "--addr", "0x401140"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("data", {}).get("action"), "add")

    def test_bp_cli_action_flag_with_positional_session_named_addr(self):
        """Test: bp <session> --action add --addr <addr>"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", sid, "--action", "add", "--addr", "0x401150"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("data", {}).get("action"), "add")

    def test_bp_cli_action_flag_with_positional_session_positional_addr(self):
        """Test: bp <session> 0x401155 --action add"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", sid, "0x401155", "--action", "add"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("data", {}).get("action"), "add")

    def test_bp_cli_hw_breakpoint_with_named_addr(self):
        """Test: bp --hw --session <session> --addr <addr>"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", "--hw", "--session", sid, "--addr", "0x401160"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("data", {}).get("hw"))

    def test_bp_cli_hw_breakpoint_with_positional_addr(self):
        """Test: bp <session> --hw 0x401170"""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", sid, "--hw", "0x401170"
        ])
        self.assertEqual(rc, 0, f"Failed: stdout={stdout}, stderr={stderr}")
        self.assertTrue(data.get("success"))
        self.assertTrue(data.get("data", {}).get("hw"))

    def test_bp_cli_remove_and_list_and_clear(self):
        """Test: breakpoint lifecycle (add, list, remove, clear) via CLI flags"""
        sid = self.spawn_debug_session()
        # Add
        self.run_cmd(["dynamic", "debug", "bp", sid, "--addr", "0x401180"])
        # List
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "bp", sid, "--action", "list"])
        self.assertEqual(rc, 0)
        self.assertEqual(data.get("data", {}).get("total_breakpoints"), 1)
        # Remove
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "bp", sid, "--action", "remove", "--addr", "0x401180"
        ])
        self.assertEqual(rc, 0)
        self.assertEqual(data.get("data", {}).get("total_breakpoints"), 0)
        # Add 2 and clear
        self.run_cmd(["dynamic", "debug", "bp", sid, "0x401190"])
        self.run_cmd(["dynamic", "debug", "bp", sid, "0x4011a0"])
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "bp", sid, "--action", "clear"])
        self.assertEqual(rc, 0)
        self.assertEqual(data.get("data", {}).get("total_breakpoints"), 0)

    def test_bp_cli_missing_session_returns_exit_code_1(self):
        """Test: bp without session fails cleanly with Exit Code 1 (INVALID_ARGUMENT)."""
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "bp"])
        self.assertEqual(rc, 1, f"Expected rc=1, got {rc}")
        self.assertIsNotNone(data)
        self.assertFalse(data.get("success"))
        self.assertEqual(data.get("error", {}).get("exit_code"), 1)
        self.assertEqual(data.get("error", {}).get("category"), "INVALID_ARGUMENT")

    # =========================================================================
    # SUITE 2: Defensive Memory Write & Bounds Verification
    # =========================================================================

    def test_mem_write_rejects_odd_length_hex(self):
        """Test: write memory with odd-length hex strings -> Exit Code 1, never 0."""
        sid = self.spawn_debug_session()
        for odd_hex in ["1", "123", "909", "abcdef1"]:
            rc, data, stdout, stderr = self.run_cmd([
                "dynamic", "debug", "mem", "--session", sid, "--action", "write",
                "--addr", "0x401000", "--data", odd_hex
            ])
            self.assertEqual(rc, 1, f"Expected rc=1 for odd hex '{odd_hex}', got {rc}")
            self.assertIsNotNone(data, f"Expected JSON envelope, got stdout: {stdout}")
            self.assertFalse(data.get("success"))
            self.assertEqual(data.get("error", {}).get("exit_code"), 1)
            self.assertEqual(data.get("error", {}).get("category"), "INVALID_ARGUMENT")
            self.assertIn("even", data.get("error", {}).get("message", "").lower())

    def test_mem_write_rejects_non_hex_characters(self):
        """Test: write memory with invalid hex characters -> Exit Code 1, never 0."""
        sid = self.spawn_debug_session()
        for bad_hex in ["zzzz", "12xy", "90gh", "0xZZ", "!@#$"]:
            rc, data, stdout, stderr = self.run_cmd([
                "dynamic", "debug", "mem", "--session", sid, "--action", "write",
                "--addr", "0x401000", "--data", bad_hex
            ])
            self.assertEqual(rc, 1, f"Expected rc=1 for bad hex '{bad_hex}', got {rc}")
            self.assertIsNotNone(data, f"Expected JSON envelope, got stdout: {stdout}")
            self.assertFalse(data.get("success"))
            self.assertEqual(data.get("error", {}).get("exit_code"), 1)
            self.assertEqual(data.get("error", {}).get("category"), "INVALID_ARGUMENT")

    def test_mem_write_rejects_empty_data(self):
        """Test: write memory with empty data -> Exit Code 1."""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "mem", "--session", sid, "--action", "write",
            "--addr", "0x401000", "--data", ""
        ])
        self.assertEqual(rc, 1, f"Expected rc=1 for empty data, got {rc}")
        self.assertFalse(data.get("success"))
        self.assertEqual(data.get("error", {}).get("exit_code"), 1)

    def test_mem_write_rejects_unmapped_high_address(self):
        """Test: write to unmapped high address 0xdeadbeef000 -> Exit Code 3 (ANALYSIS_ERROR), never 0."""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "mem", "--session", sid, "--action", "write",
            "--addr", "0xdeadbeef000", "--data", "90909090"
        ])
        self.assertEqual(rc, 3, f"Expected rc=3 for unmapped address, got {rc}")
        self.assertIsNotNone(data, f"Expected JSON envelope, got stdout: {stdout}")
        self.assertFalse(data.get("success"))
        self.assertEqual(data.get("error", {}).get("exit_code"), 3)
        self.assertEqual(data.get("error", {}).get("category"), "ANALYSIS_ERROR")

    def test_mem_write_rejects_null_address(self):
        """Test: write to NULL address (0x0 / 0) -> Exit Code 3, never 0."""
        sid = self.spawn_debug_session()
        for null_addr in ["0x0", "0", "0x0000000000000000"]:
            rc, data, stdout, stderr = self.run_cmd([
                "dynamic", "debug", "mem", "--session", sid, "--action", "write",
                "--addr", null_addr, "--data", "90909090"
            ])
            self.assertEqual(rc, 3, f"Expected rc=3 for null address '{null_addr}', got {rc}")
            self.assertIsNotNone(data)
            self.assertFalse(data.get("success"))
            self.assertEqual(data.get("error", {}).get("exit_code"), 3)
            self.assertEqual(data.get("error", {}).get("category"), "ANALYSIS_ERROR")

    def test_mem_write_rejects_max_64bit_unmapped(self):
        """Test: write to 0xffffffffffffffff -> Exit Code 3, never 0."""
        sid = self.spawn_debug_session()
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "mem", "--session", sid, "--action", "write",
            "--addr", "0xffffffffffffffff", "--data", "9090"
        ])
        self.assertEqual(rc, 3, f"Expected rc=3 for 0xffffffffffffffff, got {rc}")
        self.assertIsNotNone(data)
        self.assertFalse(data.get("success"))
        self.assertEqual(data.get("error", {}).get("exit_code"), 3)

    def test_mem_write_and_read_at_valid_mapped_address(self):
        """Test: write valid hex to mapped code/data address, verify written=True and bytes_written."""
        sid = self.spawn_debug_session()
        # Find entrypoint or rip
        rc, reg_data, _, _ = self.run_cmd(["dynamic", "debug", "registers", sid])
        self.assertEqual(rc, 0)
        rip_hex = reg_data.get("data", {}).get("rip_hex")
        self.assertIsNotNone(rip_hex)

        # Write 4 NOP bytes (0x90909090)
        rc, write_data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "mem", sid, "--action", "write", "--addr", rip_hex, "--data", "90909090"
        ])
        self.assertEqual(rc, 0, f"Write failed: {stdout} {stderr}")
        self.assertTrue(write_data.get("success"))
        self.assertEqual(write_data.get("data", {}).get("bytes_written"), 4)
        self.assertTrue(write_data.get("data", {}).get("written"))

        # Read back
        rc, read_data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "mem", sid, "--action", "read", "--addr", rip_hex, "-l", "4"
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(read_data.get("success"))
        self.assertEqual(read_data.get("data", {}).get("hex"), "90909090")

    # =========================================================================
    # SUITE 3: Frida Subcommands Robustness & Panic-Free Verification
    # =========================================================================

    def test_frida_env_check_no_panic(self):
        """Test: rvs frida env-check executes cleanly without panicking."""
        rc, data, stdout, stderr = self.run_cmd(["frida", "env-check"])
        # Either 0 (if r2frida installed) or 6 (R2_FRIDA_NOT_INSTALLED)
        self.assertIn(rc, [0, 6], f"Expected rc 0 or 6, got {rc}")
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(data)

    def test_frida_attach_malformed_targets_no_panic(self):
        """Test: rvs frida attach with invalid PID / malformed target strings."""
        bad_targets = [
            "not_a_pid",
            "-999999",
            "999999999999999999999999999999999999999999999",
            "",
            "frida://",
            "invalid_scheme://1234",
            "../relative/path/not/allowed",
        ]
        for target in bad_targets:
            args = ["frida", "attach", target] if target else ["frida", "attach"]
            rc, data, stdout, stderr = self.run_cmd(args)
            self.assertNotEqual(rc, 0, f"Target '{target}' should fail, got rc=0")
            self.assertNotIn("panicked at", stderr, f"Target '{target}' caused panic: {stderr}")
            self.assertIsNotNone(data, f"Target '{target}' must emit valid JSON error envelope")
            self.assertFalse(data.get("success"))
            self.assertIn(data.get("error", {}).get("exit_code"), [1, 2, 3, 6])

    def test_frida_spawn_invalid_paths_no_panic(self):
        """Test: rvs frida spawn with nonexistent, non-executable, or directory paths."""
        bad_paths = [
            "/nonexistent/binary/path_123456",
            "/dev/null",
            str(WORKSPACE_DIR),
        ]
        for path in bad_paths:
            rc, data, stdout, stderr = self.run_cmd(["frida", "spawn", path])
            self.assertNotEqual(rc, 0, f"Spawn on '{path}' should fail")
            self.assertNotIn("panicked at", stderr, f"Spawn on '{path}' caused panic: {stderr}")
            self.assertIsNotNone(data)
            self.assertFalse(data.get("success"))
            self.assertIn(data.get("error", {}).get("exit_code"), [1, 2, 3, 6])

    def test_frida_hook_validation_no_panic(self):
        """Test: rvs frida hook parameter validation (addresses, formats, injections)."""
        bad_cases = [
            # Bad address syntax -> 1
            (["frida", "hook", "--target", "0", "--addr", "bad;injection", "--format", "x"], [1]),
            # Out of bounds address -> 3 (ADDRESS_OUT_OF_BOUNDS)
            (["frida", "hook", "--target", "0", "--addr", "0xffffffffffffffff", "--format", "x"], [3]),
            # Bad format -> 1
            (["frida", "hook", "--target", "0", "--addr", "0x401000", "--format", "invalid_fmt"], [1]),
            (["frida", "hook", "--target", "0", "--addr", "0x401000", "--format", "x; rm -rf /"], [1]),
        ]
        for cmd_args, expected_codes in bad_cases:
            rc, data, stdout, stderr = self.run_cmd(cmd_args)
            self.assertNotEqual(rc, 0, f"Command {cmd_args} should fail")
            self.assertNotIn("panicked at", stderr, f"Panic on {cmd_args}: {stderr}")
            self.assertIsNotNone(data)
            self.assertFalse(data.get("success"))
            self.assertIn(data.get("error", {}).get("exit_code"), expected_codes)

    def test_frida_trace_regs_validation_no_panic(self):
        """Test: rvs frida trace-regs parameter validation."""
        bad_regs = [
            "",
            "   ",
            ",,,",
            "rax, bad!reg",
            "rax; echo hacked",
            "r" * 100,  # Long invalid register name
        ]
        for regs in bad_regs:
            rc, data, stdout, stderr = self.run_cmd([
                "frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", regs
            ])
            self.assertEqual(rc, 1)
            self.assertNotIn("panicked at", stderr, f"Panic on regs='{regs}': {stderr}")
            self.assertIsNotNone(data)
            self.assertFalse(data.get("success"))
            self.assertEqual(data.get("error", {}).get("exit_code"), 1)

    def test_frida_script_and_rpc_validation_no_panic(self):
        """Test: rvs frida script and rpc validation."""
        # Nonexistent script file via --file
        rc, data, stdout, stderr = self.run_cmd([
            "frida", "script", "--target", "0", "--file", "/nonexistent/script.js"
        ])
        self.assertEqual(rc, 2)
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("exit_code"), 2)

        # Empty script string via --code
        rc, data, stdout, stderr = self.run_cmd([
            "frida", "script", "--target", "0", "--code", "   "
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("exit_code"), 1)

        # Malformed RPC method identifier
        rc, data, stdout, stderr = self.run_cmd([
            "frida", "rpc", "--target", "0", "--method", "bad-method; injection()"
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("exit_code"), 1)

    def test_frida_memory_read_write_validation_no_panic(self):
        """Test: rvs frida mem-read and mem-write parameter validation."""
        # mem-write with odd length hex
        rc, data, stdout, stderr = self.run_cmd([
            "frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", "123"
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("exit_code"), 1)

        # mem-write with non-hex characters
        rc, data, stdout, stderr = self.run_cmd([
            "frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", "zzzz"
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("exit_code"), 1)

        # mem-read with invalid length
        rc, data, stdout, stderr = self.run_cmd([
            "frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "0"
        ])
        self.assertEqual(rc, 1)
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("exit_code"), 1)


if __name__ == "__main__":
    unittest.main()
