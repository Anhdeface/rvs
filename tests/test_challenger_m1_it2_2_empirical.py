#!/usr/bin/env python3
"""
Empirical Adversarial Verification Suite for Milestone 1 Iteration 2 Gate
Adversarial Challenger 2

Comprehensive empirical stress-testing:
1. Zero-byte files across all major subcommands (exit code 2, ZERO_BYTE_FILE, FILE_ERROR)
2. Timeout thresholds (--timeout 0 -> exit code 5; --timeout 10 -> exit code 0)
3. Zero steps / Negative steps across dynamic and agent commands
4. Empty patch plan steps (dry run & live execution) and malformed step structures
5. Multi-byte UTF-8 emoji strings across JSON parser, symbol resolver, and patch plans
6. Strict exit code taxonomy (1..6) and structured JSON error envelopes
7. Invariant: Zero unhandled panics across all invocations
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE / "target" / "debug" / "rvs"
TARGET_ELF = WORKSPACE / "tests" / "fixtures" / "test_target_elf64"


class Challenger2M1Iteration2TestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RVS_BIN.exists():
            subprocess.run(["cargo", "build"], cwd=str(WORKSPACE), check=True)
        assert RVS_BIN.exists(), f"rvs binary missing at {RVS_BIN}"
        assert TARGET_ELF.exists(), f"fixture missing at {TARGET_ELF}"

    def run_cmd(self, args, binary=TARGET_ELF):
        cmd = [str(RVS_BIN)]
        if binary is not None:
            cmd.extend(["-f", str(binary)])
        cmd.extend(args)
        proc = subprocess.run(cmd, cwd=str(WORKSPACE), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Invariant: No panics
        self.assertNotIn("panicked at", proc.stderr, f"PANIC DETECTED on command {cmd}:\n{proc.stderr}")
        self.assertNotIn("fatal runtime error", proc.stderr, f"FATAL ERROR on command {cmd}:\n{proc.stderr}")

        envelope = None
        if proc.stdout.strip():
            try:
                envelope = json.loads(proc.stdout)
            except json.JSONDecodeError as e:
                self.fail(f"Invalid JSON output on command {cmd}:\n{proc.stdout}\nError: {e}")

        return proc.returncode, envelope, proc.stdout, proc.stderr

    # =========================================================================
    # 1. Zero-Byte Files Stress Testing
    # =========================================================================

    def test_zero_byte_file_across_all_subcommands(self):
        """Verify that zero-byte files consistently return exit code 2 and ZERO_BYTE_FILE envelope."""
        with tempfile.NamedTemporaryFile() as empty_f:
            empty_path = Path(empty_f.name)
            subcommands = [
                ["info"],
                ["analyze", "functions"],
                ["analyze", "blocks", "main"],
                ["analyze", "graph", "main"],
                ["analyze", "prologue-epilogue"],
                ["analyze", "xrefs", "main"],
                ["strings"],
                ["symbols"],
                ["dynamic", "emulate", "main"],
                ["dynamic", "trace", "main"],
                ["dynamic", "step", "main"],
                ["agent", "triage"],
                ["agent", "decompile", "main"],
                ["agent", "flow", "main"],
                ["agent", "xrefs", "main"],
                ["agent", "patch-plan", "--plan", '{"name":"x","dry_run":true,"steps":[]}'],
                ["patch", "instruction", "--addr", "0x1000", "--assembly", "nop"],
                ["patch", "bytes", "--addr", "0x1000", "--hex", "90"],
                ["patch", "string", "--addr", "0x1000", "--new", "test"],
            ]

            for subcmd in subcommands:
                rc, data, stdout, stderr = self.run_cmd(subcmd, binary=empty_path)
                self.assertEqual(rc, 2, f"Expected exit code 2 for zero-byte file on {subcmd}, got {rc}")
                self.assertIsNotNone(data, f"Missing JSON envelope on {subcmd}")
                self.assertFalse(data["success"])
                self.assertEqual(data["error"]["code"], "ZERO_BYTE_FILE")
                self.assertEqual(data["error"]["category"], "FILE_ERROR")
                self.assertEqual(data["error"]["exit_code"], 2)
                self.assertTrue(len(data["error"]["message"]) > 0)
                self.assertTrue(len(data["error"]["suggestion"]) > 0)

    # =========================================================================
    # 2. Timeout Thresholds (--timeout 0 and --timeout 10)
    # =========================================================================

    def test_timeout_threshold_zero_returns_code_5(self):
        """Verify --timeout 0 triggers TIMEOUT_EXPIRED with exit code 5 and clean JSON envelope."""
        subcommands = [
            ["--timeout", "0", "info"],
            ["--timeout", "0", "analyze", "functions"],
            ["--timeout", "0", "agent", "triage"],
            ["--timeout", "0", "dynamic", "emulate", "main"],
        ]
        for subcmd in subcommands:
            rc, data, stdout, stderr = self.run_cmd(subcmd)
            self.assertEqual(rc, 5, f"Expected exit code 5 for --timeout 0 on {subcmd}, got {rc}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["code"], "TIMEOUT_EXPIRED")
            self.assertEqual(data["error"]["category"], "TIMEOUT_ERROR")
            self.assertEqual(data["error"]["exit_code"], 5)
            self.assertIn("timed out", data["error"]["message"])

    def test_timeout_threshold_ten_succeeds(self):
        """Verify --timeout 10 allows normal fast commands to succeed with exit code 0."""
        subcommands = [
            ["--timeout", "10", "info"],
            ["--timeout", "10", "analyze", "functions"],
            ["--timeout", "10", "strings"],
            ["--timeout", "10", "agent", "triage"],
        ]
        for subcmd in subcommands:
            rc, data, stdout, stderr = self.run_cmd(subcmd)
            self.assertEqual(rc, 0, f"Expected exit code 0 for --timeout 10 on {subcmd}, got {rc}")
            self.assertIsNotNone(data)
            self.assertTrue(data["success"])

    # =========================================================================
    # 3. Zero Steps and Negative Steps
    # =========================================================================

    def test_zero_steps_dynamic_commands(self):
        """Verify dynamic commands handle 0 steps gracefully without panic."""
        # 3.1 dynamic emulate with 0 steps
        rc, data, _, _ = self.run_cmd(["dynamic", "emulate", "main", "--steps", "0"])
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["steps_requested"], 0)
        self.assertEqual(data["data"]["steps_executed"], 0)
        self.assertEqual(len(data["data"]["register_diff"]), 0)

        # 3.2 dynamic trace with 0 steps (falls back to default 20)
        rc, data, _, _ = self.run_cmd(["dynamic", "trace", "main", "--steps", "0"])
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["total_steps"], 20)

        # 3.3 dynamic step with 0 count (falls back to default 1)
        rc, data, _, _ = self.run_cmd(["dynamic", "step", "main", "--count", "0"])
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["steps"], 1)

        # 3.4 agent emulate with 0 steps (falls back to default 100)
        rc, data, _, _ = self.run_cmd(["agent", "emulate", "main", "--steps", "0"])
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertTrue(data["data"]["steps_executed"] > 0)

    def test_negative_steps_cli_validation(self):
        """Verify negative steps and count parameters return exit code 1 with structured JSON envelope."""
        cases = [
            ["dynamic", "emulate", "main", "--steps=-1"],
            ["dynamic", "trace", "main", "--steps=-5"],
            ["dynamic", "step", "main", "--count=-1"],
            ["agent", "emulate", "main", "--steps=-10"],
            ["strings", "--min-len=-2"],
        ]
        for cmd in cases:
            rc, data, stdout, stderr = self.run_cmd(cmd)
            self.assertEqual(rc, 1, f"Expected exit code 1 for negative step {cmd}, got {rc}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["code"], "INVALID_ARGUMENT")
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
            self.assertEqual(data["error"]["exit_code"], 1)

    # =========================================================================
    # 4. Empty Patch Plan Steps and Malformed Step Structures
    # =========================================================================

    def test_patch_plan_empty_steps_dry_run(self):
        """Verify empty steps array in dry run succeeds with 0 steps executed."""
        plan = {"name": "Empty Dry Run", "dry_run": True, "steps": []}
        rc, data, _, _ = self.run_cmd(["agent", "patch-plan", "--plan", json.dumps(plan)])
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["total_steps"], 0)
        self.assertEqual(data["data"]["steps_executed"], 0)
        self.assertEqual(len(data["data"]["step_results"]), 0)
        self.assertFalse(data["data"]["applied"])
        self.assertTrue(data["data"]["dry_run"])

    def test_patch_plan_empty_steps_live_run(self):
        """Verify empty steps array in live run succeeds with 0 steps executed and creates backup."""
        with tempfile.NamedTemporaryFile() as tmp_target:
            shutil.copyfile(TARGET_ELF, tmp_target.name)
            plan = {"name": "Empty Live Run", "dry_run": False, "steps": []}
            rc, data, _, _ = self.run_cmd(["agent", "patch-plan", "--plan", json.dumps(plan)], binary=Path(tmp_target.name))
            self.assertEqual(rc, 0)
            self.assertTrue(data["success"])
            self.assertEqual(data["data"]["total_steps"], 0)
            self.assertEqual(data["data"]["steps_executed"], 0)
            self.assertEqual(len(data["data"]["step_results"]), 0)
            self.assertTrue(data["data"]["applied"])
            self.assertIsNotNone(data["data"].get("backup_path"))
            self.assertTrue(Path(data["data"]["backup_path"]).exists())
            # Clean up backup
            if Path(data["data"]["backup_path"]).exists():
                Path(data["data"]["backup_path"]).unlink()

    def test_patch_plan_malformed_steps(self):
        """Verify malformed step objects return exit code 1 and PATCH_PLAN_ERROR."""
        malformed_plans = [
            ({"name": "Empty step dict", "dry_run": True, "steps": [{}]}, "missing field `type`"),
            ({"name": "Missing addr", "dry_run": True, "steps": [{"type": "instruction"}]}, "missing field `addr`"),
            ({"name": "Empty addr", "dry_run": True, "steps": [{"type": "instruction", "addr": ""}]}, "missing required field 'addr'"),
            ({"name": "Whitespace addr", "dry_run": True, "steps": [{"type": "instruction", "addr": "   \t"}]}, "missing required field 'addr'"),
            ({"name": "Unknown type", "dry_run": True, "steps": [{"type": "bogus_op", "addr": "0x1000"}]}, "Unknown step type 'bogus_op'"),
            ({"name": "Missing asm", "dry_run": True, "steps": [{"type": "instruction", "addr": "0x1000"}]}, "missing required field 'assembly'"),
            ({"name": "Missing hex", "dry_run": True, "steps": [{"type": "bytes", "addr": "0x1000"}]}, "missing required field 'hex'"),
            ({"name": "Missing string", "dry_run": True, "steps": [{"type": "string", "addr": "0x1000"}]}, "missing required field 'new_string'"),
        ]
        for plan_obj, expected_fragment in malformed_plans:
            rc, data, _, _ = self.run_cmd(["agent", "patch-plan", "--plan", json.dumps(plan_obj)])
            self.assertEqual(rc, 1)
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertIn(expected_fragment, data["error"]["message"])

    # =========================================================================
    # 5. Multi-Byte UTF-8 and Emoji Strings Stress Testing
    # =========================================================================

    def test_emoji_symbols_and_targets_resilience(self):
        """Verify emoji queries do not panic and cleanly return exit code 3 (SYMBOL_NOT_FOUND)."""
        emoji_queries = ["sym.🚀", "🦀", "main_🔥", "0xZZZZ🦀", "🌍_test_func"]
        for sym in emoji_queries:
            for subcmd in [["agent", "decompile", sym], ["agent", "flow", sym], ["analyze", "blocks", sym]]:
                rc, data, stdout, stderr = self.run_cmd(subcmd)
                self.assertEqual(rc, 3, f"Expected exit code 3 for symbol '{sym}' on {subcmd}, got {rc}")
                self.assertIsNotNone(data)
                self.assertFalse(data["success"])
                self.assertEqual(data["error"]["code"], "SYMBOL_NOT_FOUND")
                self.assertEqual(data["error"]["category"], "ANALYSIS_ERROR")
                self.assertEqual(data["error"]["exit_code"], 3)
                self.assertIn(sym, data["error"]["message"])

    def test_emoji_in_patch_plan_metadata_and_payload(self):
        """Verify emojis in patch plan name and new_string are properly encoded and handled."""
        plan = {
            "name": "🚀 Emoji Patch Plan 🦀",
            "dry_run": True,
            "steps": [
                {
                    "type": "string",
                    "addr": "sym.main",
                    "new_string": "Hello 🦀 World 🌍"
                }
            ]
        }
        rc, data, _, _ = self.run_cmd(["agent", "patch-plan", "--plan", json.dumps(plan)])
        self.assertEqual(rc, 0)
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["plan_name"], "🚀 Emoji Patch Plan 🦀")
        step_res = data["data"]["step_results"][0]
        self.assertTrue(step_res["success"])
        # Verify UTF-8 hex encoding for 🦀 (f09fa680)
        self.assertIn("f09fa680", step_res["patched_bytes"])

    def test_emoji_in_register_presets_rejected(self):
        """Verify register preset syntax rejects emojis gracefully with exit code 1."""
        rc, data, _, _ = self.run_cmd(["dynamic", "emulate", "main", "--reg", "rax=🦀"])
        self.assertEqual(rc, 1)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "INVALID_ARGUMENT")
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
        self.assertEqual(data["error"]["exit_code"], 1)

    # =========================================================================
    # 6. Exit Codes Taxonomy 1..6 Verification
    # =========================================================================

    def test_exit_code_1_invalid_argument(self):
        """Verify various invalid argument conditions return exit code 1."""
        cases = [
            (["--completely-unknown-flag"], None),
            (["info"], None), # missing -f
            (["-f", str(TARGET_ELF), "analyze", "blocks", "sym.main > /tmp/test_pwn"], None),
            (["-f", str(TARGET_ELF), "analyze", "blocks", "sym.main; whoami"], None),
            (["-f", str(TARGET_ELF), "dynamic", "emulate", "main", "--reg", "invalid_reg_format"], None),
        ]
        for cmd, target in cases:
            rc, data, _, _ = self.run_cmd(cmd, binary=target)
            self.assertEqual(rc, 1, f"Expected code 1 for {cmd}, got {rc}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_exit_code_2_file_error(self):
        """Verify file not found, directory, and zero byte return exit code 2."""
        cases = [
            (["-f", "/nonexistent/binary/path/9999.bin", "info"], None),
            (["-f", "/tmp", "info"], None),
        ]
        for cmd, target in cases:
            rc, data, _, _ = self.run_cmd(cmd, binary=target)
            self.assertEqual(rc, 2, f"Expected code 2 for {cmd}, got {rc}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 2)
            self.assertEqual(data["error"]["category"], "FILE_ERROR")

    def test_exit_code_3_analysis_error(self):
        """Verify symbol not found returns exit code 3."""
        rc, data, _, _ = self.run_cmd(["agent", "decompile", "nonexistent_function_xyz_987"])
        self.assertEqual(rc, 3)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 3)
        self.assertEqual(data["error"]["category"], "ANALYSIS_ERROR")

    def test_exit_code_4_patch_error(self):
        """Verify invalid assembly and invalid hex return exit code 4."""
        # 4.1 Invalid assembly mnemonic
        rc, data, _, _ = self.run_cmd(["patch", "instruction", "--addr", "0x1000", "--assembly", "illegal_mnemonic_xyz eax, ebx"])
        self.assertEqual(rc, 4)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

        # 4.2 Odd-length hex
        rc, data, _, _ = self.run_cmd(["patch", "bytes", "--addr", "0x1000", "--hex", "abc"])
        self.assertEqual(rc, 4)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

        # 4.3 Non-hex character
        rc, data, _, _ = self.run_cmd(["patch", "bytes", "--addr", "0x1000", "--hex", "abzz"])
        self.assertEqual(rc, 4)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

    def test_exit_code_5_timeout(self):
        """Verify execution timeout returns exit code 5."""
        rc, data, _, _ = self.run_cmd(["--timeout", "0", "info"])
        self.assertEqual(rc, 5)
        self.assertIsNotNone(data)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["exit_code"], 5)
        self.assertEqual(data["error"]["category"], "TIMEOUT_ERROR")


if __name__ == "__main__":
    unittest.main()
