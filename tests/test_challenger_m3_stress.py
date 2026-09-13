#!/usr/bin/env python3
"""
tests/test_challenger_m3_stress.py - Milestone 3 Adversarial & Empirical Stress Suite.
Author: Challenger 2 (Empirical Challenger)
Covers:
1. F15 Pagination Edge Cases (limit=0, limit=1, offset=0, offset=999999, negative limits).
2. F16 Composite Workflows Edge Cases (triage_crash, bypass_decision_gate, dump_decrypted_buffer, detect_anti_debug).
3. Process & Daemon Health (leaks, orphaned debug sessions, zombie processes).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from rvs_agent_harness import (
    EXIT_FILE_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_TIMEOUT_ERROR,
    RvsHarness,
    prune_classes,
    prune_modules,
    prune_symbols,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
CRACKME_BIN = FIXTURES_DIR / "crackme_case"
CRASH_BIN = FIXTURES_DIR / "crash_target_elf64"
AUTH_BIN = FIXTURES_DIR / "auth_gate_elf64"
DECRYPTOR_BIN = FIXTURES_DIR / "decryptor_target_elf64"
ANTIDEBUG_BIN = FIXTURES_DIR / "antidebug_target_elf64"
FLOW_BIN = FIXTURES_DIR / "flow_calc_elf64"
RVS_BIN = Path(__file__).resolve().parent.parent / "target" / "release" / "rvs"


class TestM3PaginationEdgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = RvsHarness()

    def test_symbols_pagination_edge_cases(self):
        """F15: symbols with limit=0, limit=1, offset=0, offset=999999, limit=-1, offset=-5."""
        if not CRACKME_BIN.exists():
            self.skipTest("crackme_case binary fixture not found")

        # 1. limit=0
        r_lim0 = self.harness.execute_tool("rvs_symbols", {"file": str(CRACKME_BIN), "limit": 0})
        self.assertTrue(r_lim0.get("success"), f"limit=0 failed: {r_lim0}")
        syms_lim0 = r_lim0.get("data", {}).get("symbols", [])
        self.assertEqual(len(syms_lim0), 0)
        self.assertEqual(r_lim0.get("data", {}).get("displayed"), 0)

        # 2. limit=1
        r_lim1 = self.harness.execute_tool("rvs_symbols", {"file": str(CRACKME_BIN), "limit": 1})
        self.assertTrue(r_lim1.get("success"))
        syms_lim1 = r_lim1.get("data", {}).get("symbols", [])
        self.assertEqual(len(syms_lim1), 1)
        self.assertEqual(r_lim1.get("data", {}).get("displayed"), 1)

        # 3. offset=0
        r_off0 = self.harness.execute_tool("rvs_symbols", {"file": str(CRACKME_BIN), "offset": 0, "limit": 5})
        self.assertTrue(r_off0.get("success"))
        self.assertGreaterEqual(len(r_off0.get("data", {}).get("symbols", [])), 1)

        # 4. offset=999999 (offset beyond total items)
        r_off_huge = self.harness.execute_tool("rvs_symbols", {"file": str(CRACKME_BIN), "offset": 999999})
        self.assertTrue(r_off_huge.get("success"))
        self.assertEqual(len(r_off_huge.get("data", {}).get("symbols", [])), 0)
        self.assertEqual(r_off_huge.get("data", {}).get("remaining"), 0)

        # 5. limit=-1 rejection
        r_lim_neg = self.harness.execute_tool("rvs_symbols", {"file": str(CRACKME_BIN), "limit": -1})
        self.assertFalse(r_lim_neg.get("success"))
        self.assertEqual(r_lim_neg.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)
        self.assertEqual(r_lim_neg.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # 6. offset=-5 rejection
        r_off_neg = self.harness.execute_tool("rvs_symbols", {"file": str(CRACKME_BIN), "offset": -5})
        self.assertFalse(r_off_neg.get("success"))
        self.assertEqual(r_off_neg.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)
        self.assertEqual(r_off_neg.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_frida_modules_pagination_edge_cases(self):
        """F15: frida_modules negative limit/offset rejection and boundary pruning."""
        # Harness negative parameter rejection
        r_neg_lim = self.harness.execute_tool("rvs_frida_modules", {"target": "12345", "limit": -1})
        self.assertFalse(r_neg_lim.get("success"))
        self.assertEqual(r_neg_lim.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)
        self.assertEqual(r_neg_lim.get("error", {}).get("code"), "INVALID_ARGUMENT")

        r_neg_off = self.harness.execute_tool("rvs_frida_modules", {"target": "12345", "offset": -5})
        self.assertFalse(r_neg_off.get("success"))
        self.assertEqual(r_neg_off.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)
        self.assertEqual(r_neg_off.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # CLI execution directly
        if RVS_BIN.exists():
            cp = subprocess.run(
                [str(RVS_BIN), "frida", "modules", "--target", "12345", "--limit", "-1"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(cp.returncode, 1)
            cli_res = json.loads(cp.stdout)
            self.assertFalse(cli_res.get("success"))
            self.assertEqual(cli_res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # Boundary pruning rules
        sample_mods = {"modules": [{"name": f"mod_{i}", "base": hex(0x1000 + i), "size": 0x100} for i in range(50)]}
        p0 = prune_modules(sample_mods, "compact", limit=0)
        self.assertEqual(len(p0["modules"]), 0)
        self.assertEqual(p0["displayed"], 0)

        p1 = prune_modules(sample_mods, "compact", limit=1)
        self.assertEqual(len(p1["modules"]), 1)
        self.assertEqual(p1["displayed"], 1)

        p_huge = prune_modules(sample_mods, "compact", offset=999999)
        self.assertEqual(len(p_huge["modules"]), 0)
        self.assertEqual(p_huge["remaining"], 0)

    def test_frida_symbols_pagination_edge_cases(self):
        """F15: frida_symbols negative limit/offset rejection and boundary pruning."""
        r_neg_lim = self.harness.execute_tool("rvs_frida_symbols", {"target": "12345", "limit": -1})
        self.assertFalse(r_neg_lim.get("success"))
        self.assertEqual(r_neg_lim.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

        r_neg_off = self.harness.execute_tool("rvs_frida_symbols", {"target": "12345", "offset": -5})
        self.assertFalse(r_neg_off.get("success"))
        self.assertEqual(r_neg_off.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

        if RVS_BIN.exists():
            cp = subprocess.run(
                [str(RVS_BIN), "frida", "symbols", "--target", "12345", "--limit", "-1"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(cp.returncode, 1)
            cli_res = json.loads(cp.stdout)
            self.assertEqual(cli_res.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_frida_classes_pagination_edge_cases(self):
        """F15: frida_classes negative limit/offset rejection and boundary pruning."""
        r_neg_lim = self.harness.execute_tool("rvs_frida_classes", {"target": "12345", "limit": -1})
        self.assertFalse(r_neg_lim.get("success"))
        self.assertEqual(r_neg_lim.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

        r_neg_off = self.harness.execute_tool("rvs_frida_classes", {"target": "12345", "offset": -5})
        self.assertFalse(r_neg_off.get("success"))
        self.assertEqual(r_neg_off.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

        if RVS_BIN.exists():
            cp = subprocess.run(
                [str(RVS_BIN), "frida", "classes", "--target", "12345", "--limit", "-1"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(cp.returncode, 1)
            cli_res = json.loads(cp.stdout)
            self.assertEqual(cli_res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        sample_classes = {"classes": [f"Class_{i}" for i in range(60)]}
        p0 = prune_classes(sample_classes, "compact", limit=0)
        self.assertEqual(len(p0["classes"]), 0)

        p1 = prune_classes(sample_classes, "compact", limit=1)
        self.assertEqual(len(p1["classes"]), 1)

        p_huge = prune_classes(sample_classes, "compact", offset=999999)
        self.assertEqual(len(p_huge["classes"]), 0)


class TestM3CompositeWorkflowsEdgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = RvsHarness()

    def test_triage_crash_matrix(self):
        """F16: triage_crash with crash target, safe target, missing target, and timeout."""
        # 1. Crash target: NULL_POINTER_DEREFERENCE
        if CRASH_BIN.exists():
            r = self.harness.triage_crash(CRASH_BIN)
            self.assertTrue(r.get("success"))
            self.assertTrue(r.get("crashed"))
            self.assertEqual(r.get("signal"), 11)
            self.assertEqual(r.get("cause"), "NULL_POINTER_DEREFERENCE")

        # 2. Safe target: normal process exit
        if AUTH_BIN.exists():
            r_safe = self.harness.triage_crash(AUTH_BIN)
            self.assertTrue(r_safe.get("success"))
            self.assertFalse(r_safe.get("crashed"))
            self.assertEqual(r_safe.get("cause"), "PROCESS_EXITED_1")

        # 3. Missing target: FILE_NOT_FOUND
        r_missing = self.harness.triage_crash("non_existent_file_test_xyz")
        self.assertFalse(r_missing.get("success"))
        self.assertEqual(r_missing.get("error", {}).get("code"), "FILE_NOT_FOUND")

        # 4. Timeout target: TIMEOUT_EXPIRED
        r_timeout = self.harness.triage_crash("/bin/sleep", args=["10"], timeout=1.0)
        self.assertFalse(r_timeout.get("success"))
        self.assertEqual(r_timeout.get("cause"), "TIMEOUT_EXPIRED")
        self.assertEqual(r_timeout.get("error", {}).get("code"), "TIMEOUT_EXPIRED")

    def test_bypass_decision_gate_matrix(self):
        """F16: bypass_decision_gate with check_auth and malformed gate_addr."""
        if AUTH_BIN.exists():
            r = self.harness.bypass_decision_gate(AUTH_BIN, function="check_auth")
            self.assertTrue(r.get("success"))
            self.assertTrue(r.get("bypassed"))
            self.assertIn("patch_plan", r)
            self.assertEqual(r.get("patch_plan", {}).get("action"), "invert_branch")

            # Malformed gate address
            r_bad = self.harness.bypass_decision_gate(AUTH_BIN, gate_addr="0xZZZZZZ")
            self.assertFalse(r_bad.get("success"))
            self.assertFalse(r_bad.get("bypassed"))
            self.assertEqual(r_bad.get("error", {}).get("code"), "INVALID_ARGUMENT")
            self.assertEqual(r_bad.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

    def test_dump_decrypted_buffer_matrix(self):
        """F16: dump_decrypted_buffer with valid target and unmapped memory address."""
        if DECRYPTOR_BIN.exists():
            r = self.harness.dump_decrypted_buffer(DECRYPTOR_BIN)
            self.assertTrue(r.get("success"))
            self.assertIn("FLAG{", str(r.get("buffer", "")))

            # Unmapped buffer address outside user space
            r_unmapped = self.harness.dump_decrypted_buffer(DECRYPTOR_BIN, buffer_addr="0xffffffff80000000")
            self.assertFalse(r_unmapped.get("success"))
            self.assertEqual(r_unmapped.get("error", {}).get("code"), "INVALID_MEMORY_ADDRESS")
            self.assertEqual(r_unmapped.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

    def test_detect_anti_debug_matrix(self):
        """F16: detect_anti_debug on antidebug binary vs clean binary."""
        if ANTIDEBUG_BIN.exists():
            r = self.harness.detect_anti_debug(ANTIDEBUG_BIN)
            self.assertTrue(r.get("success"))
            self.assertTrue(r.get("anti_debug_detected"))
            self.assertIn("ptrace", r.get("techniques", []))
            self.assertIsNotNone(r.get("bypass_hook"))
            self.assertIn("ptrace", r.get("bypass_hook", ""))

        if FLOW_BIN.exists():
            r_clean = self.harness.detect_anti_debug(FLOW_BIN)
            self.assertTrue(r_clean.get("success"))
            self.assertFalse(r_clean.get("anti_debug_detected"))
            self.assertEqual(len(r_clean.get("techniques", [])), 0)
            self.assertIsNone(r_clean.get("bypass_hook"))


class TestProcessAndDaemonHealth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = RvsHarness()

    def test_dump_decrypted_buffer_session_leak(self):
        """
        Adversarial Process Health Check: Verify whether dump_decrypted_buffer leaks debug sessions.
        Root cause: In dump_decrypted_buffer (line 4305), sess_id looks up 'session_id',
        whereas in compact mode debug_spawn returns 'session'. Therefore sess_id is None,
        the debug session is never killed in the finally block, and an orphaned radare2
        process remains in the daemon.
        """
        if not DECRYPTOR_BIN.exists():
            self.skipTest("decryptor fixture not found")

        # Record active sessions before
        sessions_before = len(self.harness.debug_sessions().get("data", {}).get("sessions", []))

        # Invoke dump_decrypted_buffer
        res = self.harness.dump_decrypted_buffer(DECRYPTOR_BIN)
        self.assertTrue(res.get("success"))

        # Check sessions after
        sessions_after = len(self.harness.debug_sessions().get("data", {}).get("sessions", []))
        diff = sessions_after - sessions_before

        # Clean up any leaked session created during this test
        current_sessions = self.harness.debug_sessions().get("data", {}).get("sessions", [])
        for s in current_sessions:
            if s.get("target") == str(DECRYPTOR_BIN.resolve()):
                self.harness.debug_kill(DECRYPTOR_BIN, session=s["session_id"])

        # Assert no sessions were leaked
        self.assertEqual(
            diff,
            0,
            f"dump_decrypted_buffer leaked {diff} active debug session(s) in the background daemon!"
        )


if __name__ == "__main__":
    unittest.main()
