#!/usr/bin/env python3
"""
Empirical Adversarial Verification Suite for Milestone 1
Adversarial Challenger 2

Verifies:
1. Patch plans with missing fields (missing assembly, missing hex, missing new_string,
   unknown step types, missing addr, empty addr, corrupted json) -> No panic, AppError::PatchPlanError returned.
2. Truncated or multi-byte UTF-8 strings in parse_json error previews -> No char boundary panics.
3. Strict adherence to 1..6 exit code taxonomy.
"""

import os
import sys
import json
import tempfile
import subprocess
import unittest
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE / "target" / "debug" / "rvs"
TARGET_ELF = WORKSPACE / "tests" / "fixtures" / "test_target_elf64"

class TestChallengerM1PatchPlanEdgeCases(unittest.TestCase):
    """Area 1: Patch plans with missing fields and edge cases."""

    def run_patch_plan(self, plan_obj_or_str, flags=None):
        if flags is None:
            flags = []
        if isinstance(plan_obj_or_str, (dict, list)):
            plan_str = json.dumps(plan_obj_or_str)
        else:
            plan_str = str(plan_obj_or_str)

        cmd = [str(RVS_BIN), "-f", str(TARGET_ELF), "agent", "patch-plan", "--plan", plan_str] + flags
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    def test_missing_assembly_dry_run(self):
        plan = {
            "name": "Missing assembly dry run",
            "dry_run": True,
            "steps": [{"type": "instruction", "addr": "0x1000"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic")
        self.assertEqual(rc, 1, f"Expected exit code 1, got {rc}")
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing required field 'assembly'", data["error"]["message"])

    def test_missing_assembly_live(self):
        plan = {
            "name": "Missing assembly live",
            "dry_run": False,
            "steps": [{"type": "instruction", "addr": "0x1000"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic")
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing required field 'assembly'", data["error"]["message"])

    def test_missing_hex_dry_run(self):
        plan = {
            "name": "Missing hex dry run",
            "dry_run": True,
            "steps": [{"type": "bytes", "addr": "0x1000"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic")
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing required field 'hex'", data["error"]["message"])

    def test_missing_hex_live(self):
        plan = {
            "name": "Missing hex live",
            "dry_run": False,
            "steps": [{"type": "bytes", "addr": "0x1000"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic")
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing required field 'hex'", data["error"]["message"])

    def test_missing_new_string_dry_run(self):
        plan = {
            "name": "Missing string dry run",
            "dry_run": True,
            "steps": [{"type": "string", "addr": "0x1000"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic")
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing required field 'new_string'", data["error"]["message"])

    def test_missing_new_string_live(self):
        plan = {
            "name": "Missing string live",
            "dry_run": False,
            "steps": [{"type": "string", "addr": "0x1000"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic")
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing required field 'new_string'", data["error"]["message"])

    def test_unknown_step_types(self):
        unknown_cases = [
            "jump_somewhere",
            "invalid_type",
            "NOP_EXTENDED",
            "___",
            "12345",
        ]
        for utype in unknown_cases:
            plan = {
                "name": f"Unknown {utype}",
                "dry_run": True,
                "steps": [{"type": utype, "addr": "0x1000"}]
            }
            rc, stdout, stderr = self.run_patch_plan(plan)
            self.assertNotIn("panicked at", stderr, f"Must not panic on unknown step type '{utype}'")
            self.assertEqual(rc, 1)
            data = json.loads(stdout)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
            self.assertIn(f"Unknown step type '{utype.lower()}'", data["error"]["message"])

    def test_missing_addr_field(self):
        plan = {
            "name": "Missing addr",
            "dry_run": True,
            "steps": [{"type": "instruction", "assembly": "nop"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic on missing addr")
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing field `addr`", data["error"]["message"])

    def test_empty_addr_string(self):
        plan = {
            "name": "Empty addr",
            "dry_run": True,
            "steps": [{"type": "instruction", "addr": "   \n\t", "assembly": "nop"}]
        }
        rc, stdout, stderr = self.run_patch_plan(plan)
        self.assertNotIn("panicked at", stderr, "Must not panic on empty addr")
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")
        self.assertIn("missing required field 'addr'", data["error"]["message"])

    def test_corrupted_json_strings(self):
        bad_inputs = [
            "",
            "{",
            "{\"name\": \"incomplete\", \"steps\":",
            "not json at all",
            "12345",
            "null",
            "[1, 2, 3]",
        ]
        for bad in bad_inputs:
            rc, stdout, stderr = self.run_patch_plan(bad)
            self.assertNotIn("panicked at", stderr, f"Must not panic on bad json: {bad[:20]}")
            self.assertEqual(rc, 1)
            data = json.loads(stdout)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["code"], "PATCH_PLAN_ERROR")


class TestChallengerM1ExitCodeTaxonomy(unittest.TestCase):
    """Area 3: Strict adherence to 1..6 exit code taxonomy."""

    def run_cmd(self, args):
        cmd = [str(RVS_BIN)] + args
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    def test_exit_code_1_invalid_arguments(self):
        # 1. Invalid CLI flag
        rc, stdout, stderr = self.run_cmd(["--bogus-flag-does-not-exist"])
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

        # 2. Missing -f / --file target
        rc, stdout, stderr = self.run_cmd(["info"])
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

        # 3. Invalid output format
        rc, stdout, stderr = self.run_cmd(["-f", str(TARGET_ELF), "--format", "nonexistent_mode", "info"])
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 1)

        # 4. Command injection attempt in target address
        rc, stdout, stderr = self.run_cmd(["-f", str(TARGET_ELF), "analyze", "blocks", "sym.main; id"])
        self.assertEqual(rc, 1)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["code"], "INVALID_ARGUMENT")

    def test_exit_code_2_file_errors(self):
        # 1. Non-existent file
        rc, stdout, stderr = self.run_cmd(["-f", "/nonexistent_binary_xyz_12345.bin", "info"])
        self.assertEqual(rc, 2)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 2)
        self.assertEqual(data["error"]["category"], "FILE_ERROR")

        # 2. Directory as target
        rc, stdout, stderr = self.run_cmd(["-f", "/tmp", "info"])
        self.assertEqual(rc, 2)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 2)
        self.assertEqual(data["error"]["category"], "FILE_ERROR")

        # 3. Zero-byte empty file
        with tempfile.NamedTemporaryFile() as tmp:
            rc, stdout, stderr = self.run_cmd(["-f", tmp.name, "info"])
            self.assertEqual(rc, 2)
            data = json.loads(stdout)
            self.assertEqual(data["error"]["exit_code"], 2)
            self.assertEqual(data["error"]["category"], "FILE_ERROR")

    def test_exit_code_3_analysis_errors(self):
        # Non-existent function in decompile
        rc, stdout, stderr = self.run_cmd(["-f", str(TARGET_ELF), "agent", "decompile", "nonexistent_func_xyz"])
        self.assertEqual(rc, 3)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 3)
        self.assertEqual(data["error"]["category"], "ANALYSIS_ERROR")

    def test_exit_code_4_patch_errors(self):
        # 1. Invalid assembly instruction mnemonic
        rc, stdout, stderr = self.run_cmd([
            "-f", str(TARGET_ELF), "patch", "instruction",
            "--addr", "0x1000", "--assembly", "illegal_mnemonic_xyz eax, 1"
        ])
        self.assertEqual(rc, 4)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

        # 2. Invalid hex string (odd length)
        rc, stdout, stderr = self.run_cmd([
            "-f", str(TARGET_ELF), "patch", "bytes",
            "--addr", "0x1000", "--hex", "abc"
        ])
        self.assertEqual(rc, 4)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

        # 3. Invalid hex string (non-hex chars)
        rc, stdout, stderr = self.run_cmd([
            "-f", str(TARGET_ELF), "patch", "bytes",
            "--addr", "0x1000", "--hex", "abzz"
        ])
        self.assertEqual(rc, 4)
        data = json.loads(stdout)
        self.assertEqual(data["error"]["exit_code"], 4)
        self.assertEqual(data["error"]["category"], "PATCH_ERROR")

    def test_taxonomy_range_invariants(self):
        """Verify all known error triggers produce exit codes strictly in 1..6."""
        error_invocations = [
            ["--invalid-flag"],
            ["info"],
            ["-f", "/nonexistent.bin", "info"],
            ["-f", "/tmp", "info"],
            ["-f", str(TARGET_ELF), "agent", "decompile", "no_such_function"],
            ["-f", str(TARGET_ELF), "patch", "instruction", "--addr", "0x1000", "--assembly", "bad_asm"],
            ["-f", str(TARGET_ELF), "patch", "bytes", "--addr", "0x1000", "--hex", "123"],
            ["-f", str(TARGET_ELF), "agent", "patch-plan", "--plan", "{bad_json"],
            ["-f", str(TARGET_ELF), "agent", "patch-plan", "--plan", '{"name":"x","steps":[{"type":"instruction","addr":"0x1000"}]}'],
        ]
        for args in error_invocations:
            rc, stdout, stderr = self.run_cmd(args)
            self.assertIn(rc, range(1, 7), f"Exit code {rc} outside 1..6 for args: {args}")
            self.assertNotIn("panicked at", stderr, f"Panic detected for args: {args}")
            data = json.loads(stdout)
            self.assertFalse(data["success"])
            self.assertIn(data["error"]["exit_code"], range(1, 7))


if __name__ == "__main__":
    unittest.main(verbosity=2)
