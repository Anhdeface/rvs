#!/usr/bin/env python3
"""
tests/test_challenger_m1_empirical.py - Adversarial Stress & Edge-Case Suite for Milestone 1.

Verifies:
1. Command injection attempts in resolve_address (; ?e injected, newlines, backticks, pipes, ampersands, shell vars)
2. Redirection operator edge case (> and <)
3. 0-byte binary files, directory paths, nonexistent files (Exit code 2, FILE_ERROR, JSON envelope)
4. Invalid arguments, missing flags, invalid modes, malformed patch plans (Exit code 1, INVALID_ARGUMENT)
5. Patch errors (Exit code 4, PATCH_ERROR)
6. CLI --timeout option (normal success, immediate timeout exit code 5, invalid/negative timeout exit code 1)
7. Production code hygiene (zero unwrap/expect/panic in production logic)
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"
TEST_TARGET = WORKSPACE_DIR / "tests" / "fixtures" / "test_target_elf64"


class TestMilestone1AdversarialChallenger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RVS_BIN.exists():
            build_res = subprocess.run(["cargo", "build"], cwd=WORKSPACE_DIR, capture_output=True, text=True)
            if build_res.returncode != 0:
                raise RuntimeError(f"cargo build failed: {build_res.stderr}")
        assert RVS_BIN.exists(), f"Binary not found at {RVS_BIN}"
        assert TEST_TARGET.exists(), f"Test target fixture not found at {TEST_TARGET}"

    def run_rvs(self, args, check_json=True):
        cmd = [str(RVS_BIN)] + args
        res = subprocess.run(cmd, cwd=WORKSPACE_DIR, capture_output=True, text=True)
        envelope = None
        if check_json and res.stdout.strip():
            try:
                envelope = json.loads(res.stdout)
            except json.JSONDecodeError as e:
                self.fail(f"Output is not valid JSON: {res.stdout}\nError: {e}")
        return res.returncode, envelope, res.stdout, res.stderr

    # =========================================================================
    # 1. Command Injection in resolve_address
    # =========================================================================

    def test_injection_semicolon_rejected(self):
        """Semicolon command separator must return exit code 1 with INVALID_ARGUMENT."""
        payload = "sym.main; ?e injected"
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
        self.assertEqual(ret, 1, f"Expected exit code 1, got {ret}")
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
        self.assertIn("Invalid characters", data["error"]["message"])

    def test_injection_semicolon_shell_command_no_side_effect(self):
        """Shell execution attempt via semicolon must fail with code 1 and have no side effects."""
        canary = Path("/tmp/challenger_m1_semi_canary")
        if canary.exists():
            canary.unlink()
        try:
            payload = f"0x401000; !touch {canary}"
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
            self.assertEqual(ret, 1)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertFalse(canary.exists(), "CRITICAL: Side-effect file created by semicolon injection!")
        finally:
            if canary.exists():
                canary.unlink()

    def test_injection_newlines_rejected(self):
        """Unix newlines (\\n) in target must return exit code 1 in analyze blocks."""
        payload = "sym.main\n?e injected"
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
        self.assertEqual(ret, 1)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_injection_carriage_return_rejected(self):
        """Carriage returns (\\r) and CRLF in target must return exit code 1 in analyze blocks."""
        payload = "sym.main\r?e injected"
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
        self.assertEqual(ret, 1)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)

        payload_crlf = "sym.main\r\n?e injected"
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload_crlf])
        self.assertEqual(ret, 1)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)

    def test_injection_backticks_rejected_no_side_effect(self):
        """Backtick execution attempts must fail with code 1 without executing subcommands."""
        canary = Path("/tmp/challenger_m1_backtick_canary")
        if canary.exists():
            canary.unlink()
        try:
            payload = f"`touch {canary}`"
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
            self.assertEqual(ret, 1)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
            self.assertFalse(canary.exists(), "CRITICAL: Backtick command executed side-effect file!")
        finally:
            if canary.exists():
                canary.unlink()

    def test_injection_pipes_and_ampersand_rejected(self):
        """Pipe (|) and ampersand (&) characters must return exit code 1."""
        for payload in ["main | cat", "| id", "main && id", "0x1000 &"]:
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
            self.assertEqual(ret, 1, f"Failed for payload: {payload}")
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_injection_shell_variables_rejected(self):
        """Shell variable prefix ($) must return exit code 1."""
        for payload in ["$USER", "$(id)", "${IFS}"]:
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
            self.assertEqual(ret, 1, f"Failed for payload: {payload}")
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)

    def test_empty_and_whitespace_target_rejected(self):
        """Empty or whitespace-only target must return exit code 1."""
        for target in ["", "   ", "\t"]:
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", target])
            self.assertEqual(ret, 1, f"Failed for target: repr({target})")
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertIn("cannot be empty", data["error"]["message"])

    def test_redirection_operator_behavior_observed(self):
        """
        Adversarial Observation: Redirection operator (>) in resolve_address.
        Empirically observes whether '>' bypasses the character filter and creates a file.
        """
        canary = Path("/tmp/challenger_m1_redir_canary")
        if canary.exists():
            canary.unlink()
        try:
            payload = f"0x401000 > {canary}"
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
            created = canary.exists()
            if created:
                content = canary.read_text()
                print(f"\n[VULNERABILITY CONFIRMED] Redirection '>' bypassed filter, created {canary} with content: {repr(content)}")
        finally:
            if canary.exists():
                canary.unlink()

    def test_agent_decompile_and_flow_error_masking_finding(self):
        """
        Adversarial Observation: In agent decompile and agent flow, resolve_address errors
        are masked into SymbolNotFound (code 3) instead of InvalidArgument (code 1).
        """
        payload = "sym.main; ?e injected"
        # analyze blocks preserves code 1
        ret_blocks, data_blocks, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
        self.assertEqual(ret_blocks, 1)
        self.assertEqual(data_blocks["error"]["category"], "INVALID_ARGUMENT")

        # agent decompile now correctly preserves exit code 1 and INVALID_ARGUMENT category
        ret_decomp, data_decomp, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "agent", "decompile", payload])
        self.assertEqual(ret_decomp, 1)
        self.assertEqual(data_decomp["error"]["category"], "INVALID_ARGUMENT")

    # =========================================================================
    # 2. File Error Taxonomy (0-byte, directory, nonexistent)
    # =========================================================================

    def test_zero_byte_file_exit_code_and_envelope(self):
        """0-byte file must consistently yield exit code 2 and ZERO_BYTE_FILE error envelope."""
        with tempfile.NamedTemporaryFile() as empty_f:
            empty_path = empty_f.name
            commands_to_test = [
                ["info"],
                ["strings"],
                ["symbols"],
                ["analyze", "functions"],
                ["agent", "triage"],
                ["patch", "instruction", "--addr", "0x1000", "--assembly", "nop"],
                ["patch", "string", "--addr", "0x1000", "--new", "test"],
                ["patch", "bytes", "--addr", "0x1000", "--hex", "90"],
            ]
            for cmd in commands_to_test:
                ret, data, out, err = self.run_rvs(["-f", empty_path] + cmd)
                self.assertEqual(ret, 2, f"Expected exit code 2 for {cmd}, got {ret}")
                self.assertIsNotNone(data)
                self.assertFalse(data["success"])
                self.assertEqual(data["error"]["exit_code"], 2)
                self.assertEqual(data["error"]["code"], "ZERO_BYTE_FILE")
                self.assertEqual(data["error"]["category"], "FILE_ERROR")
                self.assertIn("0 bytes", data["error"]["message"])
                self.assertTrue(len(data["error"]["suggestion"]) > 0)

    def test_directory_path_exit_code_and_envelope(self):
        """Passing a directory path must yield exit code 2 and FILE_NOT_FOUND error envelope."""
        ret, data, out, err = self.run_rvs(["-f", "/tmp", "info"])
        self.assertEqual(ret, 2)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 2)
        self.assertEqual(data["error"]["code"], "FILE_NOT_FOUND")
        self.assertEqual(data["error"]["category"], "FILE_ERROR")
        self.assertIn("directory", data["error"]["message"])

    def test_nonexistent_file_exit_code_and_envelope(self):
        """Nonexistent file must yield exit code 2 and FILE_NOT_FOUND error envelope."""
        nonexistent = "/tmp/surely_nonexistent_file_challenger_m1.bin"
        ret, data, out, err = self.run_rvs(["-f", nonexistent, "info"])
        self.assertEqual(ret, 2)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 2)
        self.assertEqual(data["error"]["code"], "FILE_NOT_FOUND")
        self.assertEqual(data["error"]["category"], "FILE_ERROR")

    # =========================================================================
    # 3. Invalid Arguments and Invalid Modes
    # =========================================================================

    def test_missing_required_file_flag(self):
        """Omitting -f/--file must yield exit code 1 with INVALID_ARGUMENT envelope."""
        ret, data, out, err = self.run_rvs(["info"])
        self.assertEqual(ret, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
        self.assertIn("Target binary file path is required", data["error"]["message"])

    def test_invalid_cli_flag(self):
        """Unknown CLI flag must yield exit code 1 with structured JSON envelope."""
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "--completely-bogus-flag", "info"])
        self.assertEqual(ret, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_invalid_subcommand_mode(self):
        """Unrecognized subcommand mode must yield exit code 1 with structured JSON envelope."""
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "nonexistent_mode"])
        self.assertEqual(ret, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_invalid_format_enum(self):
        """Invalid format value must yield exit code 1 with structured JSON envelope."""
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "--format", "bogus_fmt", "info"])
        self.assertEqual(ret, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_malformed_patch_plan_json(self):
        """Malformed JSON in agent patch-plan must yield exit code 1 with INVALID_ARGUMENT."""
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "agent", "patch-plan", "--plan", "{malformed: json"])
        self.assertEqual(ret, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_patch_plan_missing_fields(self):
        """Patch plan missing step fields must yield exit code 1 with INVALID_ARGUMENT."""
        incomplete_plan = json.dumps({
            "name": "test_plan",
            "dry_run": True,
            "steps": [
                {"type": "instruction", "addr": "0x401000"}  # missing 'assembly'
            ]
        })
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "agent", "patch-plan", "--plan", incomplete_plan])
        self.assertEqual(ret, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
        self.assertIn("missing required field 'assembly'", data["error"]["message"])

    def test_patch_bytes_invalid_hex(self):
        """Odd-length or non-hex string in patch bytes must return exit code 4 (PATCH_ERROR)."""
        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "patch", "bytes", "--addr", "0x401000", "--hex", "123"])
        self.assertEqual(ret, 4)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

        ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "patch", "bytes", "--addr", "0x401000", "--hex", "ZZ"])
        self.assertEqual(ret, 4)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

    # =========================================================================
    # 4. CLI with --timeout Option
    # =========================================================================

    def test_cli_timeout_success(self):
        """CLI with valid --timeout completes successfully with exit code 0."""
        ret, data, out, err = self.run_rvs(["--timeout", "10", "-f", str(TEST_TARGET), "info"])
        self.assertEqual(ret, 0)
        self.assertIsNotNone(data)
        self.assertTrue(data["success"])
        self.assertEqual(data["command"], "info")

    def test_cli_timeout_immediate_expiry(self):
        """CLI with --timeout 0 triggers immediate timeout with exit code 5 and TIMEOUT_ERROR."""
        ret, data, out, err = self.run_rvs(["--timeout", "0", "-f", str(TEST_TARGET), "info"])
        self.assertEqual(ret, 5)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 5)
        self.assertEqual(data["error"]["code"], "TIMEOUT_EXPIRED")
        self.assertEqual(data["error"]["category"], "TIMEOUT_ERROR")
        self.assertIn("timed out after 0s", data["error"]["message"])

    def test_cli_timeout_invalid_value(self):
        """CLI with non-numeric --timeout yields exit code 1 and INVALID_ARGUMENT envelope."""
        ret, data, out, err = self.run_rvs(["--timeout", "not_a_number", "-f", str(TEST_TARGET), "info"])
        self.assertEqual(ret, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    # =========================================================================
    # 5. Discrimination: Invalid Syntax vs Valid Syntax Missing Symbol
    # =========================================================================

    def test_symbol_not_found_vs_invalid_argument(self):
        """Valid syntax that does not exist returns code 3; injection attempts return code 1 in analyze blocks."""
        # Nonexistent valid symbol -> code 3
        ret3, data3, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "agent", "decompile", "nonexistent_symbol_12345"])
        self.assertEqual(ret3, 3)
        self.assertEqual(data3["error"]["exit_code"], 3)
        self.assertEqual(data3["error"]["category"], "ANALYSIS_ERROR")
        self.assertEqual(data3["error"]["code"], "SYMBOL_NOT_FOUND")

        # Injection payload in analyze blocks -> code 1
        ret1, data1, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", "nonexistent; injected"])
        self.assertEqual(ret1, 1)
        self.assertEqual(data1["error"]["exit_code"], 1)
        self.assertEqual(data1["error"]["category"], "INVALID_ARGUMENT")

    # =========================================================================
    # 6. Production Code Panic-Free Audit
    # =========================================================================

    def test_no_production_panics_or_unwraps(self):
        """Scan src/ for production .unwrap(), .expect(), panic!(), or unreachable!()."""
        production_violations = []
        for root, _, files in os.walk(WORKSPACE_DIR / "src"):
            for f in files:
                if f.endswith(".rs"):
                    fpath = Path(root) / f
                    with open(fpath, "r", encoding="utf-8") as fh:
                        in_test = False
                        for idx, line in enumerate(fh, 1):
                            stripped = line.strip()
                            if "#[cfg(test)]" in stripped or "mod test" in stripped:
                                in_test = True
                            if in_test:
                                continue
                            if stripped.startswith("//"):
                                continue
                            if re.search(r"\.(unwrap|expect)\(", stripped):
                                production_violations.append((str(fpath.relative_to(WORKSPACE_DIR)), idx, stripped))
                            if re.search(r"\b(panic!|unreachable!)\(", stripped):
                                production_violations.append((str(fpath.relative_to(WORKSPACE_DIR)), idx, stripped))

        self.assertEqual(
            len(production_violations),
            0,
            f"Found forbidden panics/unwraps in production code: {production_violations}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
