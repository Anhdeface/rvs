#!/usr/bin/env python3
"""
tests/test_challenger_m2_it2_adversarial.py

Adversarial stress-testing harness for Milestone 2 Iteration 2 (rvs frida CLI):
1. --regs boundary cases: "", ",,,", " , , ", invalid register names, non-ascii, extremely long lists.
2. Script mutual exclusion: --code "1+1" --file /tmp/test.js, empty --code "", missing --file.
3. Attach and spawn with invalid PIDs, negative PIDs, non-existent binaries, non-executable files, invalid formats.
4. Mem-read and mem-write with out-of-bounds addresses, odd-length hex strings, non-hex strings, zero length, overflow lengths.
5. Exit code taxonomy and structured JSON error envelope verification (no panics, no unwrap crashes, no hangs).
"""

import json
import os
import re
import stat
import subprocess
import tempfile
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


def run_rvs(args, timeout=10):
    cmd = [str(RVS_BIN)] + args
    try:
        res = subprocess.run(
            cmd,
            cwd=WORKSPACE_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "TIMEOUT EXPIRED",
            "parsed": None,
            "stdout_ansi": False,
            "stderr_ansi": False,
            "timed_out": True,
        }

    stdout_ansi = bool(ANSI_REGEX.search(res.stdout))
    stderr_ansi = bool(ANSI_REGEX.search(res.stderr))

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
        "timed_out": False,
    }


class TestChallengerM2It2Adversarial(unittest.TestCase):

    def assert_no_panic_or_hang(self, res, label=""):
        self.assertFalse(res.get("timed_out"), f"Command hung/timed out: {label}")
        self.assertNotIn("panicked at", res["stderr"], f"Panic detected in stderr: {label}")
        self.assertNotIn("panicked at", res["stdout"], f"Panic detected in stdout: {label}")
        self.assertNotEqual(res["returncode"], 101, f"Rust panic exit code 101: {label}")
        self.assertFalse(res["stdout_ansi"], f"ANSI escape in stdout: {label}")

    def assert_json_error_envelope(self, res, expected_rc=None, expected_cat=None, label=""):
        self.assert_no_panic_or_hang(res, label)
        parsed = res["parsed"]
        self.assertIsNotNone(parsed, f"Expected valid JSON output in stdout, got:\n{res['stdout']}\nStderr:\n{res['stderr']}\nLabel: {label}")
        self.assertFalse(parsed.get("success"), f"Expected success=false: {label}")
        err = parsed.get("error", {})
        self.assertIn("code", err, f"Error object missing 'code': {label}")
        self.assertIn("message", err, f"Error object missing 'message': {label}")
        self.assertIn("suggestion", err, f"Error object missing 'suggestion': {label}")

        actual_rc = res["returncode"]
        if expected_rc is not None:
            self.assertEqual(
                actual_rc,
                expected_rc,
                f"Exit code mismatch for {label}: expected {expected_rc}, got {actual_rc} (error code: {err.get('code')}, message: {err.get('message')})"
            )
        if expected_cat is not None:
            self.assertEqual(
                err.get("category"),
                expected_cat,
                f"Category mismatch for {label}: expected {expected_cat}, got {err.get('category')}"
            )

    # =========================================================================
    # 1. --regs Boundary Cases
    # =========================================================================

    def test_regs_empty_string(self):
        """--regs '' must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", ""])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="empty regs")

    def test_regs_only_commas(self):
        """--regs ',,,' must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", ",,,"])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="commas only regs")

    def test_regs_spaces_and_commas(self):
        """--regs ' , , ' must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", " , , "])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="spaces and commas regs")

    def test_regs_tab_and_newline_commas(self):
        """--regs '\\t,\\n,  ' must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", "\t,\n,  "])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="whitespace commas regs")

    def test_regs_invalid_register_names(self):
        """Probes invalid register names like 'invalid@reg!name', 'foo bar', '123'."""
        for bad_reg in ["invalid@reg!name", "foo bar", "rax;rm", "rax$rbx", ";id", "123"]:
            res = run_rvs(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", bad_reg])
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"bad reg {bad_reg}")

    def test_regs_non_ascii(self):
        """Probes non-ascii register names like '🦀,✨' or homoglyph 'rаx'."""
        for non_ascii in ["🦀,✨", "rаx", "\x01\x02"]:
            res = run_rvs(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", non_ascii])
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"non-ascii reg {non_ascii}")

    def test_regs_extremely_long_list(self):
        """Probes extremely long list (10,000 registers) returning exit code 1."""
        long_regs = ",".join([f"r{i}" for i in range(10000)])
        res = run_rvs(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", long_regs], timeout=15)
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="10k regs")

    # =========================================================================
    # 2. Script Mutual Exclusion & Input Validation
    # =========================================================================

    def test_script_mutual_exclusion_both_code_and_file(self):
        """Both --code and --file must be rejected with exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "script", "--target", "0", "--code", "1+1", "--file", "/tmp/test.js"])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="script code+file conflict")

    def test_script_empty_code(self):
        """--code '' must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "script", "--target", "0", "--code", ""])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="script empty code")

    def test_script_whitespace_code(self):
        """--code '   ' must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "script", "--target", "0", "--code", "   "])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="script whitespace code")

    def test_script_missing_code_and_file(self):
        """Neither --code nor --file must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "script", "--target", "0"])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="script missing code and file")

    def test_script_nonexistent_file(self):
        """--file to a non-existent path must return exit code 2 (FILE_ERROR / FILE_NOT_FOUND)."""
        res = run_rvs(["frida", "script", "--target", "0", "--file", "/nonexistent/path/for/test_rvs_script_12345.js"])
        self.assert_json_error_envelope(res, expected_rc=EXIT_FILE_ERROR, expected_cat="FILE_ERROR", label="script nonexistent file")

    # =========================================================================
    # 3. Attach and Spawn Edge Cases
    # =========================================================================

    def test_attach_negative_pids(self):
        """Negative PIDs (-1, -9999, -0, -2147483648) must return exit code 1 (INVALID_ARGUMENT)."""
        for neg in ["-1", "-9999", "-0", "-2147483648", "-9223372036854775808"]:
            res = run_rvs(["frida", "attach", "--", neg])
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"attach negative PID {neg}")

    def test_attach_empty_or_whitespace_target(self):
        """Empty or whitespace target must return exit code 1 (INVALID_ARGUMENT)."""
        for empty_val in ["", "   ", "\t"]:
            res = run_rvs(["frida", "attach", empty_val])
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"attach empty '{empty_val}'")

    def test_attach_invalid_scheme_formats(self):
        """Invalid schemes (http://, gdb://, unknown://) must return exit code 1 (INVALID_ARGUMENT)."""
        for bad_uri in ["http://localhost", "gdb://1234", "unknown://foo", "tcp://127.0.0.1:27042"]:
            res = run_rvs(["frida", "attach", bad_uri])
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"attach bad URI {bad_uri}")

    def test_attach_huge_overflow_number(self):
        """Extreme numeric strings > u32 / u64 must return exit code 1 (INVALID_ARGUMENT)."""
        huge_str = "9" * 60
        res = run_rvs(["frida", "attach", huge_str])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="attach huge number")

    def test_spawn_nonexistent_binary(self):
        """Spawning nonexistent binary path must return exit code 2 (FILE_ERROR / FILE_NOT_FOUND)."""
        res = run_rvs(["frida", "spawn", "/nonexistent/binary/path/xyz_rvs_test_12345"])
        self.assert_json_error_envelope(res, expected_rc=EXIT_FILE_ERROR, expected_cat="FILE_ERROR", label="spawn nonexistent binary")

    def test_spawn_empty_path(self):
        """Spawning with empty string path must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "spawn", ""])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="spawn empty path")

    def test_spawn_directory(self):
        """Spawning a directory path (e.g. /tmp or workspace dir) must return exit code 2 (FILE_ERROR)."""
        res = run_rvs(["frida", "spawn", "/tmp"])
        self.assert_json_error_envelope(res, expected_rc=EXIT_FILE_ERROR, expected_cat="FILE_ERROR", label="spawn directory /tmp")

    def test_spawn_zero_byte_file(self):
        """Spawning a 0-byte file must return exit code 2 (FILE_ERROR / ZERO_BYTE_FILE)."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf_path = tf.name
        try:
            res = run_rvs(["frida", "spawn", tf_path])
            self.assert_json_error_envelope(res, expected_rc=EXIT_FILE_ERROR, expected_cat="FILE_ERROR", label="spawn zero byte file")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_spawn_non_executable_file(self):
        """Spawning a non-executable file must return exit code 2 (FILE_ERROR / PERMISSION_DENIED)."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"#!/bin/sh\necho hello\n")
            tf_path = tf.name
        os.chmod(tf_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600, not executable
        try:
            res = run_rvs(["frida", "spawn", tf_path])
            self.assert_json_error_envelope(res, expected_rc=EXIT_FILE_ERROR, expected_cat="FILE_ERROR", label="spawn non-executable file")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    # =========================================================================
    # 4. mem-read and mem-write Boundary & Hex Validation
    # =========================================================================

    def test_mem_read_out_of_bounds_address(self):
        """Out of bounds address for mem-read must return exit code 3 (ANALYSIS_ERROR / ADDRESS_OUT_OF_BOUNDS)."""
        for oob in ["0xffffffffffffffff", "0x800000000000", "0x1000000000000"]:
            res = run_rvs(["frida", "mem-read", "--target", "0", "--addr", oob, "--len", "32"])
            self.assert_json_error_envelope(res, expected_rc=EXIT_ANALYSIS_ERROR, expected_cat="ANALYSIS_ERROR", label=f"mem-read oob {oob}")

    def test_mem_write_out_of_bounds_address(self):
        """Out of bounds address for mem-write must return exit code 3 (ANALYSIS_ERROR / ADDRESS_OUT_OF_BOUNDS)."""
        for oob in ["0xffffffffffffffff", "0x800000000000", "0x1000000000000"]:
            res = run_rvs(["frida", "mem-write", "--target", "0", "--addr", oob, "--data", "9090"])
            self.assert_json_error_envelope(res, expected_rc=EXIT_ANALYSIS_ERROR, expected_cat="ANALYSIS_ERROR", label=f"mem-write oob {oob}")

    def test_mem_write_odd_length_hex(self):
        """Odd length hex data string must return exit code 1 (INVALID_ARGUMENT)."""
        for odd_hex in ["1", "123", "0x123", "abcdef1", "0x1"]:
            res = run_rvs(["frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", odd_hex])
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"odd hex {odd_hex}")

    def test_mem_write_non_hex_strings(self):
        """Non-hex strings must return exit code 1 (INVALID_ARGUMENT)."""
        for bad_hex in ["ZZZZ", "0xZZZZ", "90 90", "hello_world", "12gh", "GHIJKL"]:
            res = run_rvs(["frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", bad_hex])
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"bad hex {bad_hex}")

    def test_mem_write_empty_data(self):
        """Empty data string for mem-write must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", ""])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="empty hex data")

    def test_mem_read_zero_length(self):
        """Zero length for mem-read must return exit code 1 (INVALID_ARGUMENT)."""
        res = run_rvs(["frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "0"])
        self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="mem-read zero len")

    def test_mem_read_overflow_lengths(self):
        """Length > 1MB, negative length, or usize overflow must return exit code 1 (INVALID_ARGUMENT)."""
        # > 1MB (1048576)
        res1 = run_rvs(["frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "1048577"])
        self.assert_json_error_envelope(res1, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="mem-read len > 1MB")

        # usize overflow
        res2 = run_rvs(["frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "18446744073709551616"])
        self.assert_json_error_envelope(res2, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="mem-read usize overflow")

        # negative length
        res3 = run_rvs(["frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "-1"])
        self.assert_json_error_envelope(res3, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label="mem-read negative len")

    # =========================================================================
    # 5. Resilience: No Panics, Hangs, or Unwraps across all Frida subcommands
    # =========================================================================

    def test_resilience_missing_required_flags_all_subcommands(self):
        """Invoking any frida subcommand without required arguments must return exit code 1 with JSON envelope, never panic."""
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
            ["frida", "script"],
            ["frida", "rpc"],
            ["frida", "mem-read"],
            ["frida", "mem-write"],
        ]
        for sub in subcommands:
            res = run_rvs(sub)
            self.assert_json_error_envelope(res, expected_rc=EXIT_INVALID_ARGUMENT, expected_cat="INVALID_ARGUMENT", label=f"missing args for {' '.join(sub)}")


if __name__ == "__main__":
    unittest.main()
