#!/usr/bin/env python3
"""
tests/test_challenger_m2_it1_adversarial.py

Adversarial stress-testing and empirical validation harness for Milestone 2 (`rvs frida` subcommands).
Author: challenger_m2_it1_1

Probes:
1. Negative PIDs:
   - `rvs frida attach -1`, `rvs frida attach -9999`, `rvs frida attach -- -1`, `rvs frida attach "-0"`
   - Negative PIDs on all target-consuming frida subcommands (--target=-1)
2. Boundary addresses:
   - Out of bounds: 0xffffffffffffffff, 0x800000000000 (exit code 3 / ADDRESS_OUT_OF_BOUNDS)
   - Valid boundary: 0x0, 0x1000, 0x7fffffffffff (handled cleanly without crash)
   - Empty addresses: "" (exit code 1 / INVALID_ARGUMENT)
   - Malformed hex: 0xZZZZ (exit code 1 / INVALID_ARGUMENT)
3. Invalid hook format strings:
   - INVALID_FMT, ???, x!z (exit code 1 / INVALID_ARGUMENT)
   - Format validation runs prior to driver/env check
   - Empty format string behavior observation
4. Negative pagination:
   - --limit -1, --limit -9999, --limit i64::MIN (exit code 1 / INVALID_ARGUMENT)
   - --offset -1, --offset -9999, --offset i64::MIN (exit code 1 / INVALID_ARGUMENT)
   - Non-numeric pagination values: --limit abc (exit code 1 / INVALID_ARGUMENT)
5. Non-hex memory write payloads:
   - --data ZZZZ (exit code 1 / INVALID_ARGUMENT)
   - --data 123 (odd-length hex string) (exit code 1 / INVALID_ARGUMENT)
   - --data "" (empty hex string) (exit code 1 / INVALID_ARGUMENT)
   - --data 0xZZZZ, --data 0x123 (exit code 1 / INVALID_ARGUMENT)
   - --data "90 90" (embedded whitespace) (exit code 1 / INVALID_ARGUMENT)
6. Malformed URIs:
   - gdb://1234, http://localhost, unknown://, tcp://127.0.0.1:1234 (exit code 1 / INVALID_ARGUMENT)
   - frida:// (valid scheme prefix, graceful degradation)
7. Missing binaries & scripts:
   - rvs frida spawn /nonexistent/binary/path/xyz (exit code 2 / FILE_NOT_FOUND)
   - rvs frida script --target 0 --file /nonexistent/script.js (exit code 2 / FILE_NOT_FOUND)
   - rvs frida script --target 0 (neither code nor file) (exit code 1 / INVALID_ARGUMENT)
   - rvs frida script --target 0 --code "" (empty code string) (exit code 1 / INVALID_ARGUMENT)
8. Edge cases across other subcommands:
   - trace-regs with empty regs string (exit code 1 / INVALID_ARGUMENT)
   - hook-return with empty retval string (exit code 1 / INVALID_ARGUMENT)
   - hook-remove with empty id string (exit code 1 / INVALID_ARGUMENT)
   - rpc with empty method string (exit code 1 / INVALID_ARGUMENT)
   - mem-read with len 0 or len > 1MB (exit code 1 / INVALID_ARGUMENT)
   - Missing required options across all 15 subcommands (exit code 1 / INVALID_ARGUMENT)
9. ANSI-free output verification and JSON envelope schema conformance across all runs.
"""

import json
import re
import subprocess
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "release" / "rvs"
if not RVS_BIN.exists():
    RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"

ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

EXIT_SUCCESS = 0
EXIT_INVALID_ARGUMENT = 1
EXIT_FILE_ERROR = 2
EXIT_ANALYSIS_ERROR = 3
EXIT_PATCH_ERROR = 4
EXIT_TIMEOUT_ERROR = 5
EXIT_INTERNAL_ERROR = 6


def run_rvs(args, timeout=15):
    cmd = [str(RVS_BIN)] + args
    res = subprocess.run(
        cmd,
        cwd=WORKSPACE_DIR,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    # Check ANSI pollution
    stdout_ansi = bool(ANSI_REGEX.search(res.stdout))
    stderr_ansi = bool(ANSI_REGEX.search(res.stderr))

    # Parse JSON if possible
    parsed = None
    try:
        parsed = json.loads(res.stdout)
    except Exception:
        pass

    return {
        "returncode": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "parsed": parsed,
        "stdout_ansi": stdout_ansi,
        "stderr_ansi": stderr_ansi,
    }


class TestChallengerM2Adversarial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RVS_BIN.exists():
            subprocess.run(["cargo", "build", "--release"], cwd=WORKSPACE_DIR, check=True)
        assert RVS_BIN.exists(), f"rvs binary not found at {RVS_BIN}"

    def assert_valid_envelope(self, result, expected_rc=None, expected_category=None):
        """Asserts response is valid JSON envelope with expected exit code and zero ANSI."""
        self.assertFalse(result["stdout_ansi"], f"ANSI detected in stdout: {result['stdout']}")
        self.assertFalse(result["stderr_ansi"], f"ANSI detected in stderr: {result['stderr']}")
        self.assertIsNotNone(result["parsed"], f"Failed to parse JSON output: {result['stdout']}")

        envelope = result["parsed"]
        self.assertIn("success", envelope)
        self.assertIn("command", envelope)
        self.assertIn("target", envelope)
        self.assertIn("timestamp", envelope)

        if expected_rc is not None:
            self.assertEqual(
                result["returncode"],
                expected_rc,
                f"Expected exit code {expected_rc}, got {result['returncode']}. Output: {result['stdout']}",
            )

        if not envelope["success"]:
            self.assertIn("error", envelope)
            err = envelope["error"]
            self.assertIn("code", err)
            self.assertIn("message", err)
            self.assertIn("category", err)
            self.assertIn("exit_code", err)
            self.assertIn("suggestion", err)
            if expected_category:
                self.assertEqual(err["category"], expected_category)
            if expected_rc is not None:
                self.assertEqual(err["exit_code"], expected_rc)

    # =========================================================================
    # Group 1: Negative PIDs
    # =========================================================================

    def test_attach_negative_pid_minus_one(self):
        """Negative PID -1 on attach returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "attach", "-1"])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("cannot be negative", res["parsed"]["error"]["message"])

    def test_attach_negative_pid_minus_9999(self):
        """Negative PID -9999 on attach returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "attach", "-9999"])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("cannot be negative", res["parsed"]["error"]["message"])

    def test_attach_negative_pid_double_hyphen(self):
        """Negative PID with -- separator returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "attach", "--", "-1"])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("cannot be negative", res["parsed"]["error"]["message"])

    def test_attach_negative_zero(self):
        """Negative PID -0 returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "attach", "-0"])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("cannot be negative", res["parsed"]["error"]["message"])

    def test_negative_pid_across_frida_subcommands(self):
        """Negative target PID across all subcommands returns exit 1 (INVALID_ARGUMENT)."""
        subcommands = [
            ["frida", "modules", "--target=-1"],
            ["frida", "symbols", "--target=-1"],
            ["frida", "classes", "--target=-1"],
            ["frida", "hook", "--target=-1", "-A", "0x1000"],
            ["frida", "trace-regs", "--target=-1", "-A", "0x1000", "-r", "rax"],
            ["frida", "hook-return", "--target=-1", "-A", "0x1000", "--retval", "0x1"],
            ["frida", "hooks-list", "--target=-1"],
            ["frida", "hook-remove", "--target=-1", "--id", "0"],
            ["frida", "script", "--target=-1", "--code", "console.log(1)"],
            ["frida", "rpc", "--target=-1", "-m", "test"],
            ["frida", "mem-read", "--target=-1", "-A", "0x1000"],
            ["frida", "mem-write", "--target=-1", "-A", "0x1000", "-d", "9090"],
        ]
        for cmd in subcommands:
            with self.subTest(cmd=" ".join(cmd)):
                res = run_rvs(cmd)
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")

    # =========================================================================
    # Group 2: Boundary Addresses
    # =========================================================================

    def test_address_out_of_bounds_ffffffffffffffff(self):
        """Address 0xffffffffffffffff returns exit 3 (ANALYSIS_ERROR / ADDRESS_OUT_OF_BOUNDS)."""
        commands = [
            ["frida", "hook", "-t", "1234", "-A", "0xffffffffffffffff"],
            ["frida", "trace-regs", "-t", "1234", "-A", "0xffffffffffffffff", "-r", "rax"],
            ["frida", "hook-return", "-t", "1234", "-A", "0xffffffffffffffff", "--retval", "0x1"],
            ["frida", "mem-read", "-t", "1234", "-A", "0xffffffffffffffff"],
            ["frida", "mem-write", "-t", "1234", "-A", "0xffffffffffffffff", "-d", "9090"],
        ]
        for cmd in commands:
            with self.subTest(cmd=" ".join(cmd)):
                res = run_rvs(cmd)
                self.assert_valid_envelope(res, EXIT_ANALYSIS_ERROR, "ANALYSIS_ERROR")
                self.assertEqual(res["parsed"]["error"]["code"], "ADDRESS_OUT_OF_BOUNDS")

    def test_address_out_of_bounds_exceeding_48bit_limit(self):
        """Address 0x800000000000 exceeds 48-bit userland boundary -> exit 3."""
        res = run_rvs(["frida", "hook", "-t", "1234", "-A", "0x800000000000"])
        self.assert_valid_envelope(res, EXIT_ANALYSIS_ERROR, "ANALYSIS_ERROR")
        self.assertEqual(res["parsed"]["error"]["code"], "ADDRESS_OUT_OF_BOUNDS")

    def test_address_valid_boundaries_no_crash(self):
        """Addresses 0x0, 0x1000, 0x7fffffffffff pass address validation and degrade gracefully (exit 6)."""
        for addr in ["0x0", "0x1000", "0x7fffffffffff"]:
            with self.subTest(addr=addr):
                res = run_rvs(["frida", "hook", "-t", "1234", "-A", addr])
                # In absence of io_frida, returns exit 6 (INTERNAL_ERROR); if present, installs hook.
                self.assertIn(res["returncode"], [EXIT_SUCCESS, EXIT_INTERNAL_ERROR])
                self.assert_valid_envelope(res, res["returncode"])

    def test_empty_address_rejected_with_invalid_argument(self):
        """Empty address string returns exit 1 (INVALID_ARGUMENT)."""
        commands = [
            ["frida", "hook", "-t", "1234", "-A", ""],
            ["frida", "trace-regs", "-t", "1234", "-A", "", "-r", "rax"],
            ["frida", "hook-return", "-t", "1234", "-A", "", "--retval", "0x1"],
            ["frida", "mem-read", "-t", "1234", "-A", ""],
            ["frida", "mem-write", "-t", "1234", "-A", "", "-d", "9090"],
        ]
        for cmd in commands:
            with self.subTest(cmd=" ".join(cmd)):
                res = run_rvs(cmd)
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
                self.assertIn("Address cannot be empty", res["parsed"]["error"]["message"])

    def test_malformed_hex_address(self):
        """Malformed hex address '0xZZZZ' returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "hook", "-t", "1234", "-A", "0xZZZZ"])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")

    # =========================================================================
    # Group 3: Invalid Hook Format Strings
    # =========================================================================

    def test_hook_invalid_format_strings(self):
        """Invalid format strings (INVALID_FMT, ???, x!z) return exit 1 (INVALID_ARGUMENT)."""
        for bad_fmt in ["INVALID_FMT", "???", "x!z", "i@x", "x#"]:
            with self.subTest(fmt=bad_fmt):
                res = run_rvs(["frida", "hook", "-t", "1234", "-A", "0x1000", "--format", bad_fmt])
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
                self.assertIn("Invalid format specifier character", res["parsed"]["error"]["message"])

    def test_hook_valid_format_characters_no_syntax_error(self):
        """Valid format characters (+, ^, i, x, z, w, a, h, O, p, s, c, v, 0-9) pass validation."""
        valid_fmt = "^+ixzwahOpscv012"
        res = run_rvs(["frida", "hook", "-t", "1234", "-A", "0x1000", "--format", valid_fmt])
        # Passes format check, reaches driver check -> exit 6 (or 0 if installed)
        self.assertIn(res["returncode"], [EXIT_SUCCESS, EXIT_INTERNAL_ERROR])
        self.assert_valid_envelope(res, res["returncode"])

    def test_hook_empty_format_string_behavior(self):
        """Empty format string --format '' produces valid JSON without crash."""
        res = run_rvs(["frida", "hook", "-t", "1234", "-A", "0x1000", "--format", ""])
        self.assertIn(res["returncode"], [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR, EXIT_SUCCESS])
        self.assert_valid_envelope(res, res["returncode"])

    # =========================================================================
    # Group 4: Negative Pagination
    # =========================================================================

    def test_symbols_negative_limit(self):
        """Negative limit values return exit 1 (INVALID_ARGUMENT)."""
        for lim in ["-1", "-9999", "-9223372036854775808"]:
            with self.subTest(limit=lim):
                res = run_rvs(["frida", "symbols", "-t", "1234", "--limit", lim])
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
                self.assertIn("--limit must be non-negative", res["parsed"]["error"]["message"])

    def test_symbols_negative_offset(self):
        """Negative offset values return exit 1 (INVALID_ARGUMENT)."""
        for off in ["-1", "-9999", "-9223372036854775808"]:
            with self.subTest(offset=off):
                res = run_rvs(["frida", "symbols", "-t", "1234", "--offset", off])
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
                self.assertIn("--offset must be non-negative", res["parsed"]["error"]["message"])

    def test_symbols_non_numeric_pagination(self):
        """Non-numeric limit or offset returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "symbols", "-t", "1234", "--limit", "abc"])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")

    # =========================================================================
    # Group 5: Non-Hex Memory Write Payloads
    # =========================================================================

    def test_mem_write_non_hex_payloads(self):
        """Invalid hex strings (ZZZZ, 0xZZZZ, 90g0, odd length 123) return exit 1."""
        bad_payloads = ["ZZZZ", "123", "", "0xZZZZ", "0x123", "90 90", "90g0", "abc"]
        for payload in bad_payloads:
            with self.subTest(data=payload):
                res = run_rvs(["frida", "mem-write", "-t", "1234", "-A", "0x1000", "--data", payload])
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
                self.assertIn("Invalid hex data string", res["parsed"]["error"]["message"])

    # =========================================================================
    # Group 6: Malformed URIs
    # =========================================================================

    def test_attach_malformed_uris(self):
        """Unsupported URI schemes return exit 1 (INVALID_ARGUMENT)."""
        schemes = [
            "gdb://1234",
            "http://localhost",
            "unknown://target",
            "tcp://127.0.0.1:1234",
            "ssh://user@host",
            "file:///tmp/proc",
        ]
        for uri in schemes:
            with self.subTest(uri=uri):
                res = run_rvs(["frida", "attach", uri])
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
                self.assertIn("Invalid URI scheme", res["parsed"]["error"]["message"])

    def test_attach_valid_frida_scheme_prefix(self):
        """Valid frida:// URIs pass scheme check and degrade gracefully (exit 6)."""
        for uri in ["frida://1234", "frida://attach/local//test", "frida://"]:
            with self.subTest(uri=uri):
                res = run_rvs(["frida", "attach", uri])
                self.assertIn(res["returncode"], [EXIT_SUCCESS, EXIT_INTERNAL_ERROR])
                self.assert_valid_envelope(res, res["returncode"])

    # =========================================================================
    # Group 7: Missing Binaries & Scripts
    # =========================================================================

    def test_spawn_missing_binary(self):
        """Spawning a nonexistent binary returns exit 2 (FILE_NOT_FOUND)."""
        res = run_rvs(["frida", "spawn", "/nonexistent/binary/path/xyz_9999"])
        self.assert_valid_envelope(res, EXIT_FILE_ERROR, "FILE_ERROR")
        self.assertEqual(res["parsed"]["error"]["code"], "FILE_NOT_FOUND")

    def test_script_missing_file(self):
        """Executing a nonexistent script file returns exit 2 (FILE_NOT_FOUND)."""
        res = run_rvs(["frida", "script", "-t", "1234", "--file", "/nonexistent/script.js"])
        self.assert_valid_envelope(res, EXIT_FILE_ERROR, "FILE_ERROR")
        self.assertEqual(res["parsed"]["error"]["code"], "FILE_NOT_FOUND")

    def test_script_missing_both_code_and_file(self):
        """Script execution without --code or --file returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "script", "-t", "1234"])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("Either --code or --file must be specified", res["parsed"]["error"]["message"])

    def test_script_empty_code_string(self):
        """Script execution with empty --code '' returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "script", "-t", "1234", "--code", ""])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("Script code cannot be empty", res["parsed"]["error"]["message"])

    # =========================================================================
    # Group 8: Additional Edge Cases Across All Subcommands
    # =========================================================================

    def test_trace_regs_empty_regs(self):
        """Trace-regs with empty registers list returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "trace-regs", "-t", "1234", "-A", "0x1000", "-r", ""])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("Registers list cannot be empty", res["parsed"]["error"]["message"])

    def test_hook_return_empty_retval(self):
        """Hook-return with empty return value returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "hook-return", "-t", "1234", "-A", "0x1000", "--retval", ""])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("Return value cannot be empty", res["parsed"]["error"]["message"])

    def test_hook_remove_empty_id(self):
        """Hook-remove with empty id returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "hook-remove", "-t", "1234", "--id", ""])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("Hook ID cannot be empty", res["parsed"]["error"]["message"])

    def test_rpc_empty_method(self):
        """Rpc with empty method name returns exit 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "rpc", "-t", "1234", "-m", ""])
        self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")
        self.assertIn("RPC method name cannot be empty", res["parsed"]["error"]["message"])

    def test_mem_read_len_zero_and_overflow(self):
        """Mem-read with len=0 or len > 1MB returns exit 1 (INVALID_ARGUMENT)."""
        for l in ["0", "999999999"]:
            with self.subTest(length=l):
                res = run_rvs(["frida", "mem-read", "-t", "1234", "-A", "0x1000", "-l", l])
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")

    def test_missing_required_arguments_exit_code_one(self):
        """Omission of mandatory flags returns exit 1 with structured JSON envelope."""
        subcommands = [
            ["frida", "attach"],
            ["frida", "spawn"],
            ["frida", "modules"],
            ["frida", "symbols"],
            ["frida", "classes"],
            ["frida", "hook"],
            ["frida", "trace-regs"],
            ["frida", "hook-return"],
            ["frida", "hooks-list"],
            ["frida", "hook-remove"],
            ["frida", "rpc"],
            ["frida", "mem-read"],
            ["frida", "mem-write"],
        ]
        for cmd in subcommands:
            with self.subTest(cmd=" ".join(cmd)):
                res = run_rvs(cmd)
                self.assert_valid_envelope(res, EXIT_INVALID_ARGUMENT, "INVALID_ARGUMENT")

    def test_env_check_graceful_degradation(self):
        """Env-check returns exit 6 (R2_FRIDA_NOT_INSTALLED) when io_frida is absent or exit 0."""
        res = run_rvs(["frida", "env-check"])
        self.assertIn(res["returncode"], [EXIT_SUCCESS, EXIT_INTERNAL_ERROR])
        self.assert_valid_envelope(res, res["returncode"])


if __name__ == "__main__":
    unittest.main()
