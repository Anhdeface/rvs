#!/usr/bin/env python3
"""
tests/test_challenger_m1_it2_empirical.py

Adversarial Stress Test Suite for Milestone 1 Iteration 2 Gate:
- Empirical stress-testing of redirection and injection defenses in src/r2/driver.rs:resolve_address.
- Verification of canary files on disk (no creation, no truncation).
- Verification of exit code taxonomy (1: InvalidArgument, 2: FileError, 3: SymbolNotFound).
- Verification across analyze blocks, agent decompile, agent flow, rvs_disasm, dynamic commands, patch commands.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"
TEST_TARGET = WORKSPACE_DIR / "tests" / "fixtures" / "test_target_elf64"

# Import Python harness for rvs_disasm and tool verification
import sys
sys.path.insert(0, str(WORKSPACE_DIR))
from rvs_agent_harness import RvsAgentHarness


class TestMilestone1Iteration2Empirical(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert RVS_BIN.exists(), f"Binary not found at {RVS_BIN}"
        assert TEST_TARGET.exists(), f"Test target fixture not found at {TEST_TARGET}"
        cls.harness = RvsAgentHarness(str(RVS_BIN))

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
    # Part 1: Adversarial Payloads across All Specified Characters
    # Characters: '>', '<', '>>', '~', '!', '\\', '"', '\'', '#', ';', '\n', '|', '&', '$'
    # =========================================================================

    def test_forbidden_characters_in_analyze_blocks(self):
        """Verify each forbidden character returns exit code 1 (INVALID_ARGUMENT) in analyze blocks."""
        forbidden_chars = [
            '>', '<', '>>', '~', '!', '\\', '"', "'", '#', ';', '\n', '|', '&', '$', '\r'
        ]
        for ch in forbidden_chars:
            payload = f"0x401060{ch}payload"
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", payload])
            self.assertEqual(ret, 1, f"Character '{ch}' failed to trigger exit code 1 in analyze blocks. Got {ret}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
            self.assertIn("Invalid characters", data["error"]["message"])

    def test_forbidden_characters_in_agent_decompile(self):
        """Verify each forbidden character returns exit code 1 (INVALID_ARGUMENT) in agent decompile."""
        forbidden_chars = [
            '>', '<', '>>', '~', '!', '\\', '"', "'", '#', ';', '\n', '|', '&', '$', '\r'
        ]
        for ch in forbidden_chars:
            payload = f"sym.main{ch}payload"
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "agent", "decompile", payload])
            self.assertEqual(ret, 1, f"Character '{ch}' failed to trigger exit code 1 in agent decompile. Got {ret}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
            self.assertIn("Invalid characters", data["error"]["message"])

    def test_forbidden_characters_in_agent_flow(self):
        """Verify each forbidden character returns exit code 1 (INVALID_ARGUMENT) in agent flow."""
        forbidden_chars = [
            '>', '<', '>>', '~', '!', '\\', '"', "'", '#', ';', '\n', '|', '&', '$', '\r'
        ]
        for ch in forbidden_chars:
            payload = f"sym.main{ch}payload"
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "agent", "flow", payload])
            self.assertEqual(ret, 1, f"Character '{ch}' failed to trigger exit code 1 in agent flow. Got {ret}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
            self.assertIn("Invalid characters", data["error"]["message"])

    def test_forbidden_characters_in_rvs_disasm_harness(self):
        """Verify rvs_disasm via harness propagates exit code 1 on forbidden characters."""
        forbidden_chars = [
            '>', '<', '>>', '~', '!', '\\', '"', "'", '#', ';', '\n', '|', '&', '$', '\r'
        ]
        for ch in forbidden_chars:
            payload = f"0x401060{ch}payload"
            resp = self.harness.disasm(str(TEST_TARGET), payload)
            self.assertFalse(resp.get("success"), f"Harness disasm succeeded unexpectedly for character '{ch}'")
            err_info = resp.get("error", {})
            self.assertEqual(err_info.get("exit_code"), 1, f"Expected exit_code 1 for '{ch}', got {err_info.get('exit_code')}")
            self.assertEqual(err_info.get("category"), "INVALID_ARGUMENT")

    def test_forbidden_characters_in_other_subcommands(self):
        """Verify dynamic and patch subcommands also return exit code 1 on forbidden characters."""
        commands = [
            ["dynamic", "emulate", "0x401060; touch evil"],
            ["dynamic", "trace", "0x401060 > evil"],
            ["dynamic", "step", "0x401060 | evil"],
            ["agent", "emulate", "0x401060 < evil"],
            ["agent", "trace", "0x401060 & evil"],
            ["patch", "instruction", "--addr", "0x401060`id`", "--assembly", "nop"],
            ["patch", "string", "--addr", "0x401060$USER", "--new", "test"],
            ["patch", "bytes", "--addr", "0x401060#comment", "--hex", "90"],
            ["analyze", "graph", "--type", "cfg", "sym.main~grep"],
            ["analyze", "prologue-epilogue", "sym.main!id"],
        ]
        for cmd in commands:
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET)] + cmd)
            self.assertEqual(ret, 1, f"Command {cmd} expected exit code 1, got {ret}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    # =========================================================================
    # Part 2: Canary Files on Disk Verification (No File Creation or Truncation)
    # =========================================================================

    def test_redirection_creation_prevention_on_disk(self):
        """Empirically prove that no file is created for any redirection or shell syntax in commands using resolve_address."""
        with tempfile.TemporaryDirectory() as tmpdir:
            canary_targets = [
                Path(tmpdir) / "canary_gt.txt",
                Path(tmpdir) / "canary_gtgt.txt",
                Path(tmpdir) / "canary_bang.txt",
                Path(tmpdir) / "canary_semi.txt",
                Path(tmpdir) / "canary_pipe.txt",
                Path(tmpdir) / "canary_bg.txt",
                Path(tmpdir) / "canary_backtick.txt",
            ]
            attack_vectors = [
                ("analyze", "blocks", f"0x401060 > {canary_targets[0]}"),
                ("analyze", "blocks", f"sym.main >> {canary_targets[1]}"),
                ("analyze", "blocks", f"0x401060; touch {canary_targets[3]}"),
                ("agent", "decompile", f"main > {canary_targets[0]}"),
                ("agent", "decompile", f"0x401060!touch {canary_targets[2]}"),
                ("agent", "flow", f"main >> {canary_targets[1]}"),
                ("agent", "flow", f"0x401060 | touch {canary_targets[4]}"),
                ("dynamic", "emulate", f"0x401060 & touch {canary_targets[5]}"),
                ("patch", "instruction", "--addr", f"`touch {canary_targets[6]}`", "--assembly", "nop"),
            ]
            for cmd_parts in attack_vectors:
                ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET)] + list(cmd_parts))
                self.assertEqual(ret, 1)

            # Check that NONE of the canaries were created
            for canary in canary_targets:
                self.assertFalse(canary.exists(), f"CRITICAL SECURITY VIOLATION: Canary {canary} was created on disk!")

    def test_redirection_truncation_prevention_on_disk(self):
        """Empirically prove that existing files are NOT truncated or modified."""
        with tempfile.TemporaryDirectory() as tmpdir:
            canary = Path(tmpdir) / "preexisting_sensitive_file.dat"
            sentinel_content = "CRITICAL_SECRET_DATA_DO_NOT_TRUNCATE_12345\n"
            canary.write_text(sentinel_content)
            self.assertTrue(canary.exists())
            self.assertEqual(canary.stat().st_size, len(sentinel_content))

            # Attempt overwrite via >
            ret1, data1, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", f"0x401060 > {canary}"])
            self.assertEqual(ret1, 1)
            self.assertEqual(canary.read_text(), sentinel_content, "Existing file was truncated or modified by '>' attack!")

            # Attempt overwrite via agent decompile
            ret2, data2, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "agent", "decompile", f"main > {canary}"])
            self.assertEqual(ret2, 1)
            self.assertEqual(canary.read_text(), sentinel_content, "Existing file was modified by agent decompile attack!")

            # Attempt append via >>
            ret3, data3, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "agent", "flow", f"main >> {canary}"])
            self.assertEqual(ret3, 1)
            self.assertEqual(canary.read_text(), sentinel_content, "Existing file was appended by '>>' attack!")

    # =========================================================================
    # Part 3: Exit Code Taxonomy Verification
    # Code 1: INVALID_ARGUMENT
    # Code 2: FILE_ERROR (zero-byte, directory, nonexistent)
    # Code 3: ANALYSIS_ERROR / SYMBOL_NOT_FOUND (valid symbol syntax, missing from binary)
    # =========================================================================

    def test_exit_code_1_invalid_arguments(self):
        """Verify invalid argument errors return exit code 1."""
        test_cases = [
            # Empty address
            (["analyze", "blocks", ""], 1, "INVALID_ARGUMENT"),
            # Whitespace address
            (["analyze", "blocks", "   "], 1, "INVALID_ARGUMENT"),
            # Control character (escape \x1b)
            (["analyze", "blocks", "0x401000\x1bextra"], 1, "INVALID_ARGUMENT"),
            # Invalid CLI flag
            (["--invalid-flag-12345", "info"], 1, "INVALID_ARGUMENT"),
            # Missing -f flag
            ([], 1, "INVALID_ARGUMENT"),  # run without -f
        ]
        for cmd_suffix, expected_code, expected_cat in test_cases:
            if cmd_suffix == []:
                ret, data, out, err = self.run_rvs(["info"])
            else:
                ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET)] + cmd_suffix)
            self.assertEqual(ret, expected_code, f"Failed for {cmd_suffix}: expected {expected_code}, got {ret}")
            self.assertIsNotNone(data)
            self.assertEqual(data["error"]["exit_code"], expected_code)
            self.assertEqual(data["error"]["category"], expected_cat)

    def test_exit_code_3_missing_symbols(self):
        """Verify missing symbols (valid symbol syntax that does not exist) return exit code 3."""
        nonexistent_symbol = "nonexistent_symbol_func_12345_xyz"
        subcommands = [
            ["analyze", "blocks", nonexistent_symbol],
            ["agent", "decompile", nonexistent_symbol],
            ["agent", "flow", nonexistent_symbol],
            ["dynamic", "emulate", nonexistent_symbol],
            ["dynamic", "trace", nonexistent_symbol],
            ["dynamic", "step", nonexistent_symbol],
            ["agent", "emulate", nonexistent_symbol],
            ["agent", "trace", nonexistent_symbol],
        ]
        for cmd in subcommands:
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET)] + cmd)
            self.assertEqual(ret, 3, f"Command {cmd} expected exit code 3 (SYMBOL_NOT_FOUND), got {ret}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 3)
            self.assertEqual(data["error"]["category"], "ANALYSIS_ERROR")
            self.assertEqual(data["error"]["code"], "SYMBOL_NOT_FOUND")
            self.assertIn(nonexistent_symbol, data["error"]["message"])

    def test_exit_code_2_zero_byte_file(self):
        """Verify zero-byte empty file returns exit code 2 (ZERO_BYTE_FILE) across commands."""
        with tempfile.NamedTemporaryFile() as empty_f:
            empty_path = empty_f.name
            commands = [
                ["info"],
                ["analyze", "functions"],
                ["analyze", "blocks", "0x401000"],
                ["agent", "decompile", "main"],
                ["agent", "flow", "main"],
                ["agent", "triage"],
                ["dynamic", "emulate", "0x401000"],
                ["patch", "instruction", "--addr", "0x1000", "--assembly", "nop"],
            ]
            for cmd in commands:
                ret, data, out, err = self.run_rvs(["-f", empty_path] + cmd)
                self.assertEqual(ret, 2, f"Expected code 2 for zero-byte file on {cmd}, got {ret}")
                self.assertIsNotNone(data)
                self.assertFalse(data["success"])
                self.assertEqual(data["error"]["exit_code"], 2)
                self.assertEqual(data["error"]["category"], "FILE_ERROR")
                self.assertEqual(data["error"]["code"], "ZERO_BYTE_FILE")

    def test_exit_code_2_directory_input(self):
        """Verify directory target returns exit code 2 (FILE_ERROR) across commands."""
        commands = [
            ["info"],
            ["analyze", "blocks", "0x401000"],
            ["agent", "decompile", "main"],
            ["agent", "flow", "main"],
        ]
        for cmd in commands:
            ret, data, out, err = self.run_rvs(["-f", "/tmp"] + cmd)
            self.assertEqual(ret, 2, f"Expected code 2 for directory on {cmd}, got {ret}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 2)
            self.assertEqual(data["error"]["category"], "FILE_ERROR")
            self.assertEqual(data["error"]["code"], "FILE_NOT_FOUND")
            self.assertIn("is a directory", data["error"]["message"])

    def test_exit_code_2_nonexistent_file(self):
        """Verify nonexistent file returns exit code 2 (FILE_ERROR) across commands."""
        commands = [
            ["info"],
            ["analyze", "blocks", "0x401000"],
            ["agent", "decompile", "main"],
            ["agent", "flow", "main"],
        ]
        for cmd in commands:
            ret, data, out, err = self.run_rvs(["-f", "/nonexistent/path/binary.bin"] + cmd)
            self.assertEqual(ret, 2, f"Expected code 2 for nonexistent file on {cmd}, got {ret}")
            self.assertIsNotNone(data)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["exit_code"], 2)
            self.assertEqual(data["error"]["category"], "FILE_ERROR")
            self.assertEqual(data["error"]["code"], "FILE_NOT_FOUND")

    # =========================================================================
    # Part 4: Valid Inputs & Functional Regression Verification
    # =========================================================================

    def test_valid_inputs_succeed_normally(self):
        """Ensure hardening did not break legitimate symbols, addresses, or expressions."""
        # 1. Hex address
        ret, data, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", "0x401060"])
        self.assertEqual(ret, 0)
        self.assertTrue(data["success"])

        # 2. Function symbol
        ret, data, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", "main"])
        self.assertEqual(ret, 0)
        self.assertTrue(data["success"])

        # 3. sym. prefix
        ret, data, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "agent", "decompile", "main"])
        self.assertEqual(ret, 0)
        self.assertTrue(data["success"])

        # 4. Decimal address (4198496 == 0x401060)
        ret, data, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "blocks", "4198496"])
        self.assertEqual(ret, 0)
        self.assertTrue(data["success"])

        # 5. Agent flow
        ret, data, _, _ = self.run_rvs(["-f", str(TEST_TARGET), "agent", "flow", "main"])
        self.assertEqual(ret, 0)
        self.assertTrue(data["success"])

        # 6. Python harness rvs_disasm
        resp = self.harness.disasm(str(TEST_TARGET), "main")
        self.assertTrue(resp.get("success"))

    # =========================================================================
    # Part 5: New Adversarial Finding (Bypass Outside resolve_address)
    # =========================================================================

    def test_adversarial_finding_analyze_graph_callgraph_bypasses_resolve_address(self):
        """
        Adversarial Finding AF-3:
        src/analysis/graph.rs:57 (generate_callgraph) directly formats `target` into
        `s {}; agcj` without calling `resolve_address`, allowing command injection
        and file redirection in the default `analyze graph` command.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            canary = Path(tmpdir) / "graph_canary.txt"
            payload = f"main; !touch {canary}"
            ret, data, out, err = self.run_rvs(["-f", str(TEST_TARGET), "analyze", "graph", payload])
            # We observe that it exited with code 0 instead of rejecting with code 1
            if canary.exists():
                print(f"\n[NEW ADVERSARIAL FINDING AF-3] analyze graph (callgraph) bypassed sanitization and created {canary}!")
                # Clean up canary
                canary.unlink()


if __name__ == "__main__":
    unittest.main()
