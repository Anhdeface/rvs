#!/usr/bin/env python3
"""
Comprehensive Empirical Stress & Verification Suite for Milestone 4 Crackme Recipes.
Challenger 1 (M4 Crackme & Workflow Stress).

Verifies:
1. `crash_target_elf64` with `triage_crash`: signal 11, NULL deref, faulting addr 0x0, safe mode handling.
2. `decryptor_target_elf64` with `dump_decrypted_buffer`: FLAG{...}, non-empty hex, bytes, length variants.
3. `antidebug_target_elf64` with `detect_anti_debug`: ptrace, tracerpid, frida bypass generation, negative tests.
4. `auth_gate_elf64` with `bypass_decision_gate`: dynamic gate evaluation, branch inversion, patch plan.
5. Interactive debugger walkthrough (SKILL.md Recipe 1).
6. ESIL dynamic emulation (SKILL.md Recipe 2 Option B).
7. Daemon session lifecycle & 0 orphan process invariant.
"""

import os
import re
import signal
import subprocess
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

import rvs_agent_harness as h
from rvs_agent_harness import (
    RvsHarness,
    EXIT_SUCCESS,
    EXIT_INVALID_ARGUMENT,
    EXIT_FILE_ERROR,
    EXIT_ANALYSIS_ERROR,
    EXIT_TIMEOUT_ERROR,
)

FIXTURES_DIR = Path("/home/quanh/Documents/rvs/tests/fixtures")
CRASH_TARGET = FIXTURES_DIR / "crash_target_elf64"
DECRYPTOR_TARGET = FIXTURES_DIR / "decryptor_target_elf64"
ANTIDEBUG_TARGET = FIXTURES_DIR / "antidebug_target_elf64"
AUTH_GATE_TARGET = FIXTURES_DIR / "auth_gate_elf64"
FLOW_CALC_TARGET = FIXTURES_DIR / "flow_calc_elf64"


class TestMilestone4CrackmeStress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = RvsHarness()
        assert CRASH_TARGET.exists(), f"Missing fixture {CRASH_TARGET}"
        assert DECRYPTOR_TARGET.exists(), f"Missing fixture {DECRYPTOR_TARGET}"
        assert ANTIDEBUG_TARGET.exists(), f"Missing fixture {ANTIDEBUG_TARGET}"
        assert AUTH_GATE_TARGET.exists(), f"Missing fixture {AUTH_GATE_TARGET}"
        assert FLOW_CALC_TARGET.exists(), f"Missing fixture {FLOW_CALC_TARGET}"
        cls.clean_dangling_sessions()

    @classmethod
    def tearDownClass(cls):
        cls.clean_dangling_sessions()

    @classmethod
    def clean_dangling_sessions(cls):
        try:
            sess_res = cls.harness.debug_sessions()
            sessions = sess_res.get("data", {}).get("sessions", [])
            for s in sessions:
                sid = s.get("session_id")
                tgt = s.get("target", "")
                if sid:
                    cls.harness.debug_kill(tgt, session=sid)
        except Exception:
            pass

    def tearDown(self):
        # Guarantee session cleanup after each test
        self.clean_dangling_sessions()

    # =========================================================================
    # 1. crash_target_elf64 with triage_crash
    # =========================================================================

    def test_01_crash_target_null_deref_default(self):
        """Test crash_target_elf64 defaults to deterministic SIGSEGV (signal 11) NULL dereference."""
        res = self.harness.triage_crash(CRASH_TARGET)
        self.assertTrue(res.get("success"), f"triage_crash failed: {res}")
        self.assertTrue(res.get("crashed"), f"Expected crashed=True, got: {res}")
        self.assertEqual(res.get("signal"), 11, f"Expected SIGSEGV (11), got {res.get('signal')}")
        self.assertEqual(res.get("cause"), "NULL_POINTER_DEREFERENCE")
        self.assertEqual(res.get("fault_addr"), "0x0")
        self.assertTrue(res.get("rip", "").startswith("0x4011"), f"Unexpected rip: {res.get('rip')}")
        self.assertIn("mov", res.get("instruction", "").lower())
        self.assertIsInstance(res.get("register_diff"), list)
        self.assertGreater(len(res.get("register_diff")), 0)
        self.assertIsNone(res.get("error"))

    def test_02_crash_target_explicit_crash_arg(self):
        """Test crash_target_elf64 with explicit ['crash'] arg triggers SIGSEGV."""
        res = self.harness.triage_crash(CRASH_TARGET, args=["crash"])
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("crashed"))
        self.assertEqual(res.get("signal"), 11)
        self.assertEqual(res.get("cause"), "NULL_POINTER_DEREFERENCE")

    def test_03_crash_target_safe_arg_no_crash(self):
        """Test crash_target_elf64 with ['safe'] arg exits cleanly without crashing."""
        res = self.harness.triage_crash(CRASH_TARGET, args=["safe"])
        self.assertTrue(res.get("success"), f"Expected success=True: {res}")
        self.assertFalse(res.get("crashed"), f"Expected crashed=False: {res}")
        self.assertEqual(res.get("cause"), "NO_CRASH_DETECTED")
        self.assertEqual(res.get("exit_code"), 0)
        self.assertIsNone(res.get("error"))

    def test_04_crash_target_execute_tool_interface(self):
        """Test rvs_triage_crash through harness execute_tool dispatch."""
        res = self.harness.execute_tool("rvs_triage_crash", {"file": str(CRASH_TARGET)})
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("crashed"))
        self.assertEqual(res.get("signal"), 11)
        self.assertEqual(res.get("cause"), "NULL_POINTER_DEREFERENCE")

    def test_05_crash_target_missing_file_error(self):
        """Test triage_crash returns FILE_ERROR on non-existent file."""
        res = self.harness.triage_crash(FIXTURES_DIR / "non_existent_binary_xyz")
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("cause"), "FILE_NOT_FOUND")
        self.assertEqual(res.get("error", {}).get("exit_code"), EXIT_FILE_ERROR)

    def test_06_crash_target_invalid_format_error(self):
        """Test triage_crash returns INVALID_BINARY_FORMAT on non-ELF file."""
        text_file = FIXTURES_DIR / "crash_target.c"
        res = self.harness.triage_crash(text_file)
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("cause"), "INVALID_BINARY_FORMAT")
        self.assertEqual(res.get("error", {}).get("exit_code"), EXIT_ANALYSIS_ERROR)

    # =========================================================================
    # 2. decryptor_target_elf64 with dump_decrypted_buffer
    # =========================================================================

    def test_07_decryptor_target_dump_default(self):
        """Test decryptor_target_elf64 extracts decrypted buffer, non-empty hex, and bytes."""
        res = self.harness.dump_decrypted_buffer(DECRYPTOR_TARGET)
        self.assertTrue(res.get("success"), f"dump_decrypted_buffer failed: {res}")
        buf = res.get("buffer", "")
        self.assertTrue(buf.startswith("FLAG{"), f"Expected FLAG{{...}}, got: '{buf}'")
        self.assertEqual(buf, "FLAG{rvs_dynamic_decryptor_buffer_extracted_2026}")
        self.assertEqual(res.get("buffer_addr"), "0x404060")

        # Verify non-empty hex and bytes
        hex_str = res.get("hex", "")
        bytes_list = res.get("bytes", [])
        self.assertTrue(len(hex_str) > 0, f"Expected non-empty hex, got: '{hex_str}'")
        self.assertTrue(len(bytes_list) > 0, f"Expected non-empty bytes, got: {bytes_list}")

        # Verify mathematical consistency between hex, bytes, and string
        reconstructed_bytes = bytes.fromhex(hex_str)
        self.assertEqual(list(reconstructed_bytes), bytes_list)
        self.assertTrue(reconstructed_bytes.startswith(buf.encode("latin-1")))

    def test_08_decryptor_target_custom_buffer_len(self):
        """Test dump_decrypted_buffer with custom buffer_len sizes (16, 32, 64)."""
        for length in (16, 32, 64):
            res = self.harness.dump_decrypted_buffer(DECRYPTOR_TARGET, buffer_len=length)
            self.assertTrue(res.get("success"))
            self.assertEqual(res.get("buffer_len"), length)
            self.assertEqual(len(res.get("bytes", [])), length)
            self.assertEqual(len(res.get("hex", "")), length * 2)

    def test_09_decryptor_target_execute_tool_interface(self):
        """Test rvs_dump_decrypted_buffer through harness execute_tool dispatch."""
        res = self.harness.execute_tool("rvs_dump_decrypted_buffer", {"file": str(DECRYPTOR_TARGET)})
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("buffer"), "FLAG{rvs_dynamic_decryptor_buffer_extracted_2026}")
        self.assertEqual(res.get("buffer_addr"), "0x404060")
        self.assertTrue(len(res.get("hex", "")) > 0)
        self.assertTrue(len(res.get("bytes", [])) > 0)

    def test_10_decryptor_target_invalid_buffer_addr_rejection(self):
        """Test dump_decrypted_buffer rejects out-of-range kernel/unmapped addresses."""
        res = self.harness.dump_decrypted_buffer(DECRYPTOR_TARGET, buffer_addr="0xffffffffffffffff")
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_MEMORY_ADDRESS")
        self.assertEqual(res.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

        res2 = self.harness.dump_decrypted_buffer(DECRYPTOR_TARGET, buffer_addr="0x400")
        self.assertFalse(res2.get("success"))
        self.assertEqual(res2.get("error", {}).get("code"), "INVALID_MEMORY_ADDRESS")

    # =========================================================================
    # 3. antidebug_target_elf64 with detect_anti_debug
    # =========================================================================

    def test_11_antidebug_target_detection(self):
        """Test antidebug_target_elf64 detects ptrace and TracerPid anti-debugging techniques."""
        res = self.harness.detect_anti_debug(ANTIDEBUG_TARGET)
        self.assertTrue(res.get("success"), f"detect_anti_debug failed: {res}")
        self.assertTrue(res.get("anti_debug_detected"))
        techniques = res.get("techniques", [])
        self.assertIn("ptrace", techniques)
        self.assertIn("proc_status_tracerpid", techniques)
        self.assertEqual(res.get("risk_score"), 0.8)

        details = res.get("details", {})
        self.assertIn("imp.ptrace", details.get("ptrace_symbol", ""))
        self.assertIn("TracerPid", details.get("proc_status_string", ""))
        self.assertIn("DEBUGGER_DETECTED", details.get("debugger_detected_string", ""))

        hook = res.get("bypass_hook", "")
        self.assertIsNotNone(hook)
        self.assertIn("Interceptor.attach", hook)
        self.assertIn("PTRACE_TRACEME", hook)
        self.assertIn("/proc/self/status", hook)

    def test_12_antidebug_target_execute_tool_interface(self):
        """Test rvs_detect_anti_debug through harness execute_tool dispatch."""
        res = self.harness.execute_tool("rvs_detect_anti_debug", {"file": str(ANTIDEBUG_TARGET)})
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("anti_debug_detected"))
        self.assertIn("ptrace", res.get("techniques", []))

    def test_13_antidebug_negative_clean_binary(self):
        """Test detect_anti_debug on binary without anti-debugging returns clean status."""
        res = self.harness.detect_anti_debug(FLOW_CALC_TARGET)
        self.assertTrue(res.get("success"))
        self.assertFalse(res.get("anti_debug_detected"))
        self.assertEqual(res.get("techniques"), [])
        self.assertEqual(res.get("risk_score"), 0.0)
        self.assertIsNone(res.get("bypass_hook"))

    def test_14_antidebug_missing_file_error(self):
        """Test detect_anti_debug returns FILE_ERROR on missing file."""
        res = self.harness.detect_anti_debug(FIXTURES_DIR / "non_existent_binary_xyz")
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("exit_code"), EXIT_FILE_ERROR)

    # =========================================================================
    # 4. auth_gate_elf64 with bypass_decision_gate
    # =========================================================================

    def test_15_auth_gate_bypass_by_symbol(self):
        """Test auth_gate_elf64 bypass_decision_gate with 'sym.check_master_password'."""
        res = self.harness.bypass_decision_gate(AUTH_GATE_TARGET, gate_addr="sym.check_master_password")
        self.assertTrue(res.get("success"), f"bypass_decision_gate failed: {res}")
        self.assertTrue(res.get("bypassed"), f"Expected bypassed=True, got: {res}")
        self.assertEqual(res.get("gate_addr"), "0x40117a")
        self.assertIn("jne", res.get("branch_instruction", ""))
        self.assertIn("je", res.get("inverted_instruction", ""))

        plan = res.get("patch_plan", {})
        self.assertEqual(plan.get("action"), "invert_branch")
        self.assertEqual(plan.get("addr"), "0x40117a")
        self.assertIn("jne", plan.get("original", ""))
        self.assertIn("je", plan.get("replacement", ""))

    def test_16_auth_gate_bypass_by_short_name(self):
        """Test auth_gate_elf64 bypass_decision_gate with 'check_master_password' (no sym. prefix)."""
        res = self.harness.bypass_decision_gate(AUTH_GATE_TARGET, gate_addr="check_master_password")
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("bypassed"))
        self.assertEqual(res.get("gate_addr"), "0x40117a")

    def test_17_auth_gate_execute_tool_interface(self):
        """Test rvs_bypass_decision_gate through harness execute_tool dispatch."""
        res = self.harness.execute_tool(
            "rvs_bypass_decision_gate",
            {"file": str(AUTH_GATE_TARGET), "gate_addr": "sym.check_master_password"},
        )
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("bypassed"))
        self.assertEqual(res.get("gate_addr"), "0x40117a")

    def test_18_auth_gate_non_existent_symbol(self):
        """Test bypass_decision_gate returns SYMBOL_NOT_FOUND on non-existent function."""
        res = self.harness.bypass_decision_gate(AUTH_GATE_TARGET, gate_addr="non_existent_func_xyz")
        self.assertFalse(res.get("success"))
        self.assertFalse(res.get("bypassed"))
        self.assertEqual(res.get("error", {}).get("code"), "SYMBOL_NOT_FOUND")

    def test_19_auth_gate_malformed_gate_addr(self):
        """Test bypass_decision_gate returns INVALID_ARGUMENT on malformed hex address."""
        res = self.harness.bypass_decision_gate(AUTH_GATE_TARGET, gate_addr="0xZZZZINVALID")
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

    # =========================================================================
    # 5. Interactive Debugger Walkthrough (SKILL.md Recipe 1)
    # =========================================================================

    def test_20_interactive_recipe1_step_by_step_walkthrough(self):
        """
        Execute SKILL.md Recipe 1 step-by-step:
        1. spawn auth_gate with bad password and no_aslr=True
        2. add breakpoint at decision gate 0x40117a
        3. continue until breakpoint hit
        4. read register diff
        5. invert ZF (rflags) and set rax=1
        6. step 1 instruction
        7. kill session cleanly
        """
        # Step 1: Spawn
        spawn = self.harness.debug_spawn(AUTH_GATE_TARGET, args=["bad_password"], no_aslr=True)
        self.assertTrue(spawn.get("success"), f"spawn failed: {spawn}")
        sess_id = spawn.get("data", {}).get("session_id") or spawn.get("data", {}).get("session")
        self.assertIsNotNone(sess_id)

        try:
            # Step 2: Breakpoint at gate 0x40117a
            bp = self.harness.debug_breakpoint(AUTH_GATE_TARGET, session=sess_id, action="add", addr="0x40117a")
            self.assertTrue(bp.get("success"), f"breakpoint failed: {bp}")

            # Step 3: Continue until gate
            cont = self.harness.debug_continue(AUTH_GATE_TARGET, session=sess_id, until="0x40117a")
            self.assertTrue(cont.get("success"), f"continue failed: {cont}")
            cont_data = cont.get("data", {})
            reason = cont_data.get("reason") or cont_data.get("stop_reason")
            self.assertEqual(reason, "breakpoint")
            rip_hex = cont_data.get("rip_hex") or cont_data.get("rip")
            self.assertEqual(rip_hex, "0x40117a")

            # Step 4: Register diff
            diff = self.harness.debug_registers(AUTH_GATE_TARGET, session=sess_id, diff=True)
            self.assertTrue(diff.get("success"), f"registers diff failed: {diff}")

            # Step 5: Invert ZF in rflags or set RAX=1
            mod = self.harness.debug_registers(AUTH_GATE_TARGET, session=sess_id, reg_set=["rax=1", "rflags=0x246"])
            self.assertTrue(mod.get("success"), f"registers write failed: {mod}")

            # Step 6: Step 1 instruction
            step = self.harness.debug_step(AUTH_GATE_TARGET, session=sess_id, count=1)
            self.assertTrue(step.get("success"), f"step failed: {step}")

        finally:
            # Step 7: Clean up session
            kill = self.harness.debug_kill(AUTH_GATE_TARGET, session=sess_id)
            self.assertTrue(kill.get("success"), f"kill failed: {kill}")

    # =========================================================================
    # 6. Dynamic Emulation Walkthrough (SKILL.md Recipe 2 Option B)
    # =========================================================================

    def test_21_dynamic_emulate_decryptor_loop(self):
        """
        Execute SKILL.md Recipe 2 Option B:
        Emulate decrypt_buffer loop in decryptor_target_elf64 using ESIL.
        """
        emu = self.harness.dynamic_emulate(
            DECRYPTOR_TARGET,
            "sym.decrypt_buffer",
            steps=50,
            read_mem="0x404060",
            mem_len=32,
            compact=True,
        )
        self.assertTrue(emu.get("success"), f"dynamic_emulate failed: {emu}")
        data = emu.get("data", {})
        steps = data.get("steps") or data.get("steps_executed")
        self.assertEqual(steps, 50)
        self.assertEqual(data.get("stop"), "step_limit_completed")
        self.assertIn("diff", data)

    # =========================================================================
    # 7. Session Lifecycle & Clean Process Audit
    # =========================================================================

    def test_22_zero_active_debug_sessions_and_orphans(self):
        """Verify daemon reports exactly 0 active debug sessions and no orphan fixture processes."""
        sess_res = self.harness.debug_sessions()
        self.assertTrue(sess_res.get("success"))
        active = sess_res.get("data", {}).get("sessions", [])
        self.assertEqual(len(active), 0, f"Found {len(active)} active sessions: {active}")

        # Check process table via ps
        cmd = ["ps", "-eo", "pid,comm,args"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        fixture_names = ["auth_gate", "crash_target", "decryptor_target", "antidebug_target"]
        dangling = []
        for line in res.stdout.splitlines():
            if any(fx in line for fx in fixture_names) and "python" not in line and "grep" not in line and "bash" not in line:
                dangling.append(line.strip())

        self.assertEqual(dangling, [], f"Found orphan processes: {dangling}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
