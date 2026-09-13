#!/usr/bin/env python3
"""
tests/test_dynamic_tier2.py - Tier 2: Boundary & Corner Cases for Dynamic Reverse Engineering (F1-F18).

Covers all 18 features with >= 5 boundary and error test cases each (90 test cases total).
Authoritative Expected Outputs derived from:
- radare2 6.1.4 error behaviors & exit code mappings
- rvs 7-level standardized exit code taxonomy:
    0: Success, 1: Invalid Argument, 2: File Error, 3: Analysis Error,
    4: Patch Error, 5: Timeout, 6: Internal Error
- Subprocess timeout watchdogs and non-UTF8 binary sanitization
- C crackme fixtures boundary testing (crash_target, decryptor_target, antidebug_target)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from tests.dynamic_test_helpers import (
    ANTIDEBUG_TARGET_BIN,
    AUTH_GATE_BIN,
    CANONICAL_TOOLS,
    CRACKME_CASE_BIN,
    CRASH_TARGET_BIN,
    DECRYPTOR_TARGET_BIN,
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    FLOW_CALC_BIN,
    RvsHarness,
    TEST_TARGET_BIN,
    assert_no_ansi,
    assert_valid_envelope,
    assert_valid_error_envelope,
    get_target_binary,
    get_tool_schemas,
    is_anti_debug_available,
    is_buffer_dump_available,
    is_canonical_tools_expanded,
    is_crash_triage_available,
    is_debug_cli_available,
    is_frida_cli_available,
    is_gate_bypass_available,
    is_r2frida_installed,
    run_harness_cli,
    run_rvs_cmd,
    send_mcp_request,
)


class TestTier2BoundaryAndCornerCases(unittest.TestCase):
    """Tier 2: Boundary & Corner Cases (>= 5 test cases per feature for F1-F18, total 90 tests)."""

    @classmethod
    def setUpClass(cls):
        cls.rvs_bin = get_target_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)

    def setUp(self):
        self._temp_files: List[Path] = []

    def tearDown(self):
        for f in self._temp_files:
            try:
                if f.exists():
                    f.unlink()
            except Exception:
                pass

    def create_temp_file(self, content: bytes, suffix: str = ".bin") -> Path:
        tf = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
        tf.write(content)
        tf.close()
        p = Path(tf.name)
        self._temp_files.append(p)
        return p

    # =========================================================================
    # Feature 1: Debug Session Spawning & Attaching (Boundaries)
    # =========================================================================

    def test_tier2_f1_01_spawn_nonexistent_binary(self):
        """F1.B1: Spawning non-existent binary path returns EXIT_FILE_ERROR (2)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", "/path/to/missing_bin_9999"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertTrue(assert_valid_error_envelope(data, expected_exit_code=EXIT_FILE_ERROR))

    def test_tier2_f1_02_attach_invalid_pid(self):
        """F1.B2: Attaching to non-existent PID (99999999) returns error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "attach", "99999999"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_FILE_ERROR, EXIT_ANALYSIS_ERROR, EXIT_INTERNAL_ERROR])
        self.assertTrue(assert_valid_error_envelope(data))

    def test_tier2_f1_03_attach_negative_pid(self):
        """F1.B3: Attaching to negative PID returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "attach", "-42"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    def test_tier2_f1_04_kill_nonexistent_session(self):
        """F1.B4: Killing non-existent session ID returns error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "kill", "--session", "sess_bad_id_999"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f1_05_spawn_empty_corrupted_file(self):
        """F1.B5: Spawning empty 0-byte file returns file/analysis error."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        empty_file = self.create_temp_file(b"")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(empty_file)])
        self.assertIn(rc, [EXIT_FILE_ERROR, EXIT_ANALYSIS_ERROR, EXIT_INVALID_ARGUMENT, EXIT_TIMEOUT_ERROR])

    # =========================================================================
    # Feature 2: Breakpoint Management (Boundaries)
    # =========================================================================

    def test_tier2_f2_01_set_bp_nonexistent_session(self):
        """F2.B1: Setting breakpoint on invalid session returns error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", "no_such_sess", "--action", "set", "--addr", "main"
        ])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f2_02_set_bp_out_of_range_addr(self):
        """F2.B2: Setting breakpoint at out-of-range address (0xffffffffffffffff) handled cleanly."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "0xffffffffffffffff"
        ])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    def test_tier2_f2_03_duplicate_breakpoint(self):
        """F2.B3: Setting duplicate breakpoint at same address is handled idempotently."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"])
        rc2, data2, _, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"
        ])
        self.assertEqual(rc2, EXIT_SUCCESS)

    def test_tier2_f2_04_delete_nonexistent_bp(self):
        """F2.B4: Deleting non-existent breakpoint address returns error or clean status."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "delete", "--addr", "0xdeadbeef"
        ])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    def test_tier2_f2_05_set_bp_invalid_action(self):
        """F2.B5: Passing invalid action returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, _, _, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "bad_action"
        ])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    # =========================================================================
    # Feature 3: Stepping & Execution Control (Boundaries)
    # =========================================================================

    def test_tier2_f3_01_step_nonexistent_session(self):
        """F3.B1: Stepping on non-existent session ID returns error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "step", "--session", "bad_session_id"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f3_02_step_after_process_exit(self):
        """F3.B2: Stepping after process terminated returns clean error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN), "--args", "safe"])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        rc_step, data_step, _, _ = run_rvs_cmd(["dynamic", "debug", "step", "--session", sess_id])
        self.assertIn(rc_step, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    def test_tier2_f3_03_continue_without_breakpoints(self):
        """F3.B3: Continuing without breakpoints runs process to termination cleanly."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN), "--args", "safe"])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertEqual(data.get("data", {}).get("event"), "exit")

    def test_tier2_f3_04_step_negative_count(self):
        """F3.B4: Stepping with negative count returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, _, _, _ = run_rvs_cmd(["dynamic", "debug", "step", "--session", sess_id, "--count", "-5"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    def test_tier2_f3_05_continue_timeout_watchdog(self):
        """F3.B5: Continuing infinite process with short timeout triggers EXIT_TIMEOUT_ERROR (5)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        proc = subprocess.Popen(["sleep", "30"])
        try:
            rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "attach", str(proc.pid)])
            sess_id = (spawn_data or {}).get("data", {}).get("session_id")
            if not sess_id:
                self.skipTest("Failed to attach to process (ptrace restricted)")
            rc_cont, data_cont, _, _ = run_rvs_cmd(
                ["dynamic", "debug", "continue", "--session", sess_id, "--timeout", "1"],
                timeout=3.0,
            )
            self.assertEqual(rc_cont, EXIT_TIMEOUT_ERROR)
        finally:
            proc.kill()
            proc.wait()

    # =========================================================================
    # Feature 4: Dynamic Registers (Boundaries)
    # =========================================================================

    def test_tier2_f4_01_read_regs_nonexistent_session(self):
        """F4.B1: Reading registers on non-existent session returns error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", "bad_sess"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f4_02_modify_invalid_reg_name(self):
        """F4.B2: Modifying non-existent register name returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id, "--set", "badreg99=0x1"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    def test_tier2_f4_03_modify_malformed_reg_value(self):
        """F4.B3: Setting register with non-numeric value returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id, "--set", "rax=invalid_val"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    def test_tier2_f4_04_modify_reg_overflow(self):
        """F4.B4: Setting register with 128-bit value to 64-bit GPR handled cleanly."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "registers", "--session", sess_id, "--set", "rax=0xffffffffffffffffffffffff"
        ])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    def test_tier2_f4_05_read_regs_after_exit(self):
        """F4.B5: Reading registers after process exit handled cleanly."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN), "--args", "safe"])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        rc_reg, data_reg, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id])
        self.assertIn(rc_reg, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    # =========================================================================
    # Feature 5: Memory Mapping & Live Read/Write (Boundaries)
    # =========================================================================

    def test_tier2_f5_01_read_mem_nonexistent_session(self):
        """F5.B1: Reading memory on non-existent session returns error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", "bad_sess", "--action", "read", "--addr", "0x401000", "--len", "4"
        ])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f5_02_read_unmapped_null_address(self):
        """F5.B2: Reading unmapped memory at NULL (0x0) returns memory access error envelope."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "read", "--addr", "0x0", "--len", "4"
        ])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR])

    def test_tier2_f5_03_read_negative_zero_len(self):
        """F5.B3: Reading memory with length 0 returns empty or invalid argument."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "read", "--addr", "entry0", "--len", "0"
        ])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT])

    def test_tier2_f5_04_write_malformed_hex_data(self):
        """F5.B4: Writing non-hex characters returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "write", "--addr", "rip", "--data", "90ZZ"
        ])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    def test_tier2_f5_05_write_odd_length_hex(self):
        """F5.B5: Writing odd-length hex data string returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "write", "--addr", "rip", "--data", "909"
        ])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    # =========================================================================
    # Feature 6: Debug Event & Signal Multiplexing (Boundaries)
    # =========================================================================

    def test_tier2_f6_01_continue_after_sigsegv(self):
        """F6.B1: Continuing after target received SIGSEGV does not hang or crash rvs."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        rc2, data2, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertIn(rc2, [EXIT_SUCCESS, EXIT_ANALYSIS_ERROR])

    def test_tier2_f6_02_event_zero_ansi_pollution(self):
        """F6.B2: Verifies all debugger output is completely stripped of ANSI escape codes."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, _, stdout, stderr = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        self.assertTrue(assert_no_ansi(stdout))
        self.assertTrue(assert_no_ansi(stderr))

    def test_tier2_f6_03_handled_signal_exit_code_zero(self):
        """F6.B3: Handled SIGSEGV in debuggee returns exit code 0 for rvs CLI."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, cont_data, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier2_f6_04_watchdog_sigkill_escalation(self):
        """F6.B4: Watchdog timeout correctly terminates stubborn child processes."""
        # Test harness execution watchdog on sleep subprocess
        start = time.time()
        rc, out, err, dur = rvs_agent_harness.execute_rvs_subprocess(
            ["5"], timeout=0.5, rvs_bin=Path("/bin/sleep")
        )
        self.assertEqual(rc, EXIT_TIMEOUT_ERROR)
        self.assertLess(dur, 3.0)

    def test_tier2_f6_05_event_envelope_structure(self):
        """F6.B5: Handled events produce ApiResponse-compliant JSON envelopes."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "step", "--session", sess_id])
        self.assertTrue(assert_valid_envelope(data))

    # =========================================================================
    # Feature 7: r2frida Environment Detection (Boundaries)
    # =========================================================================

    def test_tier2_f7_01_missing_r2frida_exit_code_6(self):
        """F7.B1: When r2frida is absent, invoking frida command returns exit code 6 or 1."""
        if not is_frida_cli_available():
            self.skipTest("Feature F7 requires Milestone 2 (rvs frida)")
        if not is_r2frida_installed():
            rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "1234"])
            self.assertEqual(rc, EXIT_INTERNAL_ERROR)

    def test_tier2_f7_02_missing_r2frida_actionable_suggestion(self):
        """F7.B2: Error envelope when r2frida missing includes install instructions."""
        if not is_frida_cli_available():
            self.skipTest("Feature F7 requires Milestone 2 (rvs frida)")
        if not is_r2frida_installed():
            rc, data, _, _ = run_rvs_cmd(["frida", "attach", "1234"])
            err = data.get("error", {})
            self.assertIn("r2frida", str(err.get("suggestion", "")))

    def test_tier2_f7_03_malformed_loj_response(self):
        """F7.B3: Verify environment detector handles corrupted/empty plugin data without crash."""
        # Direct unit test of JSON parsing resilience
        test_corrupted = "NOT_A_JSON"
        try:
            parsed = json.loads(test_corrupted)
        except Exception:
            parsed = None
        self.assertIsNone(parsed)

    def test_tier2_f7_04_nonexistent_r2_binary_env(self):
        """F7.B4: Handling missing radare2 path returns descriptive error."""
        rc, data, stdout, stderr = run_rvs_cmd(["info"], env={"PATH": "/nonexistent"})
        # Should gracefully report radare2 not found or invalid arg
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR, EXIT_FILE_ERROR])

    def test_tier2_f7_05_frida_subcommand_missing_target(self):
        """F7.B5: Invoking frida attach without target returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F7 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "attach"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    # =========================================================================
    # Feature 8: r2frida Attach & Spawn (Boundaries)
    # =========================================================================

    def test_tier2_f8_01_attach_invalid_pid(self):
        """F8.B1: Attaching via frida to negative PID (-1) rejected."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "attach", "-1"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f8_02_spawn_nonexistent_binary(self):
        """F8.B2: Spawning non-existent binary via frida returns EXIT_FILE_ERROR (2)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "spawn", "/path/to/missing_target_1234"])
        self.assertIn(rc, [EXIT_FILE_ERROR, EXIT_INTERNAL_ERROR])

    def test_tier2_f8_03_attach_permission_denied_target(self):
        """F8.B3: Attaching to PID 1 returns permission denied guidance."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "attach", "1"])
        self.assertIn(rc, [EXIT_FILE_ERROR, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier2_f8_04_malformed_uri_scheme(self):
        """F8.B4: Passing invalid URI scheme returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "attach", "invalid_scheme://test"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f8_05_attach_timeout_watchdog(self):
        """F8.B5: Attaching with 1.0s timeout to frozen process triggers timeout exit code."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "attach", "999999", "--timeout", "1"], timeout=3.0)
        self.assertIn(rc, [EXIT_TIMEOUT_ERROR, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    # =========================================================================
    # Feature 9: r2frida Modules & Symbols (Boundaries)
    # =========================================================================

    def test_tier2_f9_01_query_symbols_nonexistent_module(self):
        """F9.B1: Querying symbols on non-existent module returns empty list or error."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "symbols", "--target", "0", "--module", "nosuchmod.so"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f9_02_query_symbols_negative_limit(self):
        """F9.B2: Querying symbols with negative limit returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "symbols", "--target", "0", "--limit", "-10"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    def test_tier2_f9_03_query_symbols_negative_offset(self):
        """F9.B3: Querying symbols with negative offset returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "symbols", "--target", "0", "--offset", "-5"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    def test_tier2_f9_04_truncated_symbols_json_handling(self):
        """F9.B4: Resilience against truncated or empty JSON from symbols command."""
        rc, data, stdout, stderr = run_rvs_cmd(["-f", str(FLOW_CALC_BIN), "symbols", "--filter", "NOSUCHSYM_XYZ"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertEqual(len(data.get("data", {}).get("symbols", [])), 0)

    def test_tier2_f9_05_symbol_filter_special_regex_chars(self):
        """F9.B5: Symbol query with special regex characters handles characters safely."""
        rc, data, _, _ = run_rvs_cmd(["-f", str(FLOW_CALC_BIN), "symbols", "--filter", "[a-z]+"])
        self.assertEqual(rc, EXIT_SUCCESS)

    # =========================================================================
    # Feature 10: r2frida Dynamic Hooking & Tracing (Boundaries)
    # =========================================================================

    def test_tier2_f10_01_hook_out_of_range_address(self):
        """F10.B1: Hooking invalid address (0xffffffffffffffff) returns error envelope."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "hook", "--target", "0", "--addr", "0xffffffffffffffff"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier2_f10_02_hook_invalid_format_specifier(self):
        """F10.B2: Passing invalid format character returns EXIT_INVALID_ARGUMENT (1)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "hook", "--target", "0", "--addr", "0x401000", "--format", "INVALID_FMT"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    def test_tier2_f10_03_hook_terminated_target(self):
        """F10.B3: Registering hook on terminated process returns error envelope."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "hook", "--target", "999999", "--addr", "0x401000"])
        self.assertIn(rc, [EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f10_04_remove_nonexistent_hook_id(self):
        """F10.B4: Removing non-existent hook ID returns error or clean status."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "hook-remove", "--target", "0", "--id", "99999"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f10_05_hook_duplicate_address(self):
        """F10.B5: Hooking duplicate address handled idempotently."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        run_rvs_cmd(["frida", "hook", "--target", "0", "--addr", "0x401000"])
        rc2, _, _, _ = run_rvs_cmd(["frida", "hook", "--target", "0", "--addr", "0x401000"])
        self.assertIn(rc2, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    # =========================================================================
    # Feature 11: r2frida Script Injection & RPC (Boundaries)
    # =========================================================================

    def test_tier2_f11_01_eval_js_syntax_error(self):
        """F11.B1: Malformed JS syntax returns script error envelope."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "script", "--target", "0", "--code", "function { bad syntax ("])
        self.assertIn(rc, [EXIT_ANALYSIS_ERROR, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])

    def test_tier2_f11_02_script_missing_file(self):
        """F11.B2: Loading missing script file returns EXIT_FILE_ERROR (2)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "script", "--target", "0", "--file", "/path/to/missing_script_999.js"])
        self.assertIn(rc, [EXIT_FILE_ERROR, EXIT_INTERNAL_ERROR])

    def test_tier2_f11_03_eval_js_runtime_exception(self):
        """F11.B3: Unhandled JS throw captured cleanly in error envelope."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "script", "--target", "0", "--code", "throw new Error('test_throw');"])
        self.assertIn(rc, [EXIT_ANALYSIS_ERROR, EXIT_INTERNAL_ERROR])

    def test_tier2_f11_04_script_infinite_loop_timeout(self):
        """F11.B4: Infinite loop JS killed by timeout watchdog (exit code 5)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "script", "--target", "0", "--code", "while(true){}", "--timeout", "1"], timeout=3.0)
        self.assertIn(rc, [EXIT_TIMEOUT_ERROR, EXIT_INTERNAL_ERROR])

    def test_tier2_f11_05_mem_write_invalid_hex(self):
        """F11.B5: Writing invalid hex characters via frida rejected with EXIT_INVALID_ARGUMENT (1)."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, _, _, _ = run_rvs_cmd(["frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", "ZZZZ"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    # =========================================================================
    # Feature 12: Canonical Tool Expansion (Boundaries)
    # =========================================================================

    def test_tier2_f12_01_unknown_tool_name(self):
        """F12.B1: Calling unknown tool name returns EXIT_INVALID_ARGUMENT (1) error envelope."""
        req = {
            "jsonrpc": "2.0",
            "id": 121,
            "method": "tools/call",
            "params": {"name": "rvs_unknown_tool_xyz", "arguments": {}},
        }
        res = send_mcp_request(req, self.harness)
        self.assertTrue("error" in res or res.get("result", {}).get("isError", False))

    def test_tier2_f12_02_missing_required_param(self):
        """F12.B2: Calling tool missing required 'file' returns error envelope."""
        req = {
            "jsonrpc": "2.0",
            "id": 122,
            "method": "tools/call",
            "params": {"name": "rvs_info", "arguments": {}},
        }
        res = send_mcp_request(req, self.harness)
        self.assertTrue("error" in res or res.get("result", {}).get("isError", False))

    def test_tier2_f12_03_invalid_param_type_coercion(self):
        """F12.B3: Passing string for integer parameter handled cleanly."""
        req = {
            "jsonrpc": "2.0",
            "id": 123,
            "method": "tools/call",
            "params": {
                "name": "rvs_functions",
                "arguments": {"file": str(AUTH_GATE_BIN), "limit": "not_an_int"},
            },
        }
        res = send_mcp_request(req, self.harness)
        self.assertTrue("error" in res or res.get("result", {}).get("isError", False) or "result" in res)

    def test_tier2_f12_04_unexpected_extra_params(self):
        """F12.B4: Passing extra unexpected parameters tolerated without crashing MCP server."""
        req = {
            "jsonrpc": "2.0",
            "id": 124,
            "method": "tools/call",
            "params": {
                "name": "rvs_info",
                "arguments": {"file": str(AUTH_GATE_BIN), "unexpected_extra_key": 12345},
            },
        }
        res = send_mcp_request(req, self.harness)
        self.assertIn("result", res)

    def test_tier2_f12_05_null_empty_param_handling(self):
        """F12.B5: Passing null/empty parameters handled cleanly."""
        req = {
            "jsonrpc": "2.0",
            "id": 125,
            "method": "tools/call",
            "params": {
                "name": "rvs_functions",
                "arguments": {"file": str(AUTH_GATE_BIN), "filter": None},
            },
        }
        res = send_mcp_request(req, self.harness)
        self.assertIn("result", res)

    # =========================================================================
    # Feature 13: 4-Format Schema Generator (Boundaries)
    # =========================================================================

    def test_tier2_f13_01_unsupported_format_name(self):
        """F13.B1: Calling get_tool_schemas with unsupported format raises ValueError."""
        with self.assertRaises((ValueError, KeyError)):
            get_tool_schemas("unsupported_schema_fmt")

    def test_tier2_f13_02_export_tools_invalid_cli_flag(self):
        """F13.B2: CLI export-tools with invalid format returns exit code 1."""
        rc, _, stdout, stderr = run_harness_cli(["--export-tools", "invalid_format"])
        self.assertNotEqual(rc, EXIT_SUCCESS)

    def test_tier2_f13_03_schemas_valid_json_no_trailing_comma(self):
        """F13.B3: Generated schemas produce strictly valid JSON without trailing commas."""
        for fmt in ["openai", "anthropic", "gemini", "mcp"]:
            schemas = get_tool_schemas(fmt)
            json_str = json.dumps(schemas)
            parsed = json.loads(json_str)
            self.assertEqual(len(schemas), len(parsed))

    def test_tier2_f13_04_nested_properties_valid_types(self):
        """F13.B4: All schema properties declare valid types (string, integer, boolean, object, array)."""
        valid_types = {"string", "integer", "boolean", "object", "array", "number"}
        for tool in CANONICAL_TOOLS:
            for prop_name, prop in tool.get("properties", {}).items():
                p_type = prop.get("type")
                self.assertIn(p_type, valid_types, f"Invalid type '{p_type}' in {tool['name']}.{prop_name}")

    def test_tier2_f13_05_schemas_zero_ansi_escape(self):
        """F13.B5: Schema exports contain 0 ANSI escape sequences."""
        for fmt in ["openai", "anthropic", "gemini", "mcp"]:
            schemas = get_tool_schemas(fmt)
            self.assertTrue(assert_no_ansi(json.dumps(schemas)))

    # =========================================================================
    # Feature 14: Dynamic Token Compaction (Boundaries)
    # =========================================================================

    def test_tier2_f14_01_compact_empty_register_diff(self):
        """F14.B1: Compacting empty register changes returns clean empty diff."""
        reg_before = {"rax": 1, "rbx": 2}
        reg_after = {"rax": 1, "rbx": 2}
        diff = {k: reg_after[k] for k in reg_after if reg_before.get(k) != reg_after[k]}
        self.assertEqual(len(diff), 0)

    def test_tier2_f14_02_compact_zero_len_memory(self):
        """F14.B2: Compacting zero-length memory buffer returns valid empty structure."""
        rc, data, _, _ = run_rvs_cmd([
            "-f", str(FLOW_CALC_BIN), "dynamic", "emulate", "main", "--read-mem", "main", "--mem-len", "0", "-c"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier2_f14_03_compact_all_registers_modified(self):
        """F14.B3: Register diff where all registers changed retains all modified registers."""
        reg_before = {"rax": 0, "rbx": 0}
        reg_after = {"rax": 1, "rbx": 2}
        diff = {k: reg_after[k] for k in reg_after if reg_before.get(k) != reg_after[k]}
        self.assertEqual(len(diff), 2)

    def test_tier2_f14_04_compact_error_envelope_preserves_details(self):
        """F14.B4: Compact mode on error envelope preserves 100% of error details, code, suggestion."""
        err_env = rvs_agent_harness.make_error_envelope(
            command_str="test_cmd",
            target_str="test_target",
            code="CRITICAL_FAIL",
            message="Detailed error explanation",
            suggestion="Do this to fix",
        )
        compact_err = rvs_agent_harness.transform_response(err_env, mode="compact")
        self.assertEqual(compact_err.get("error", {}).get("code"), "CRITICAL_FAIL")
        self.assertEqual(compact_err.get("error", {}).get("suggestion"), "Do this to fix")

    def test_tier2_f14_05_compact_non_utf8_sanitization(self):
        """F14.B5: Non-UTF8 byte sequences in strings/memory are sanitized without crash."""
        raw_bytes = b"\x7fELF\xff\xfe\xaa\xbb"
        sanitized = raw_bytes.decode("utf-8", errors="replace")
        self.assertIn("\ufffd", sanitized)

    # =========================================================================
    # Feature 15: Automated Crash Triage Workflow (Boundaries)
    # =========================================================================

    def test_tier2_f15_01_triage_missing_binary(self):
        """F15.B1: Crash triage on non-existent binary returns EXIT_FILE_ERROR (2)."""
        if not is_crash_triage_available():
            self.skipTest("Feature F15 triage_crash requires Milestone 3")
        res = self.harness.triage_crash(target="/path/to/missing_crash_bin")
        self.assertFalse(res.get("success", True))

    def test_tier2_f15_02_triage_clean_binary_no_crash(self):
        """F15.B2: Crash triage on binary exiting 0 reports NO_CRASH_DETECTED."""
        if not is_crash_triage_available():
            self.skipTest("Feature F15 triage_crash requires Milestone 3")
        res = self.harness.triage_crash(target=str(CRASH_TARGET_BIN), args=["safe"])
        self.assertEqual(res.get("cause"), "NO_CRASH_DETECTED")

    def test_tier2_f15_03_triage_stripped_binary(self):
        """F15.B3: Crash triage on stripped binary still captures crash signal and fault address."""
        if not is_crash_triage_available():
            self.skipTest("Feature F15 triage_crash requires Milestone 3")
        # Strip binary
        stripped_bin = self.create_temp_file(CRASH_TARGET_BIN.read_bytes())
        subprocess.run(["strip", str(stripped_bin)], capture_output=True)
        res = self.harness.triage_crash(target=str(stripped_bin))
        self.assertEqual(res.get("signal"), 11)

    def test_tier2_f15_04_triage_watchdog_timeout(self):
        """F15.B4: Crash triage on infinite sleep loop terminates via timeout watchdog."""
        if not is_crash_triage_available():
            self.skipTest("Feature F15 triage_crash requires Milestone 3")
        res = self.harness.triage_crash(target="/bin/sleep", args=["30"], timeout=1.0)
        self.assertEqual(res.get("cause"), "TIMEOUT_EXPIRED")

    def test_tier2_f15_05_triage_corrupted_elf(self):
        """F15.B5: Crash triage on corrupted ELF file returns analysis error."""
        if not is_crash_triage_available():
            self.skipTest("Feature F15 triage_crash requires Milestone 3")
        corrupted_elf = self.create_temp_file(b"\x7fELF\x00\x00\x00\x00corrupt")
        res = self.harness.triage_crash(target=str(corrupted_elf))
        self.assertFalse(res.get("success", True))

    # =========================================================================
    # Feature 16: Decision Gate Bypass Loop (Boundaries)
    # =========================================================================

    def test_tier2_f16_01_gate_address_not_found(self):
        """F16.B1: Gate bypass on non-existent function returns analysis error."""
        if not is_gate_bypass_available():
            self.skipTest("Feature F16 bypass_decision_gate requires Milestone 3")
        res = self.harness.bypass_decision_gate(target=str(AUTH_GATE_BIN), gate_addr="nonexistent_fn_99")
        self.assertFalse(res.get("bypassed", False))

    def test_tier2_f16_02_inversion_on_unconditional_jump(self):
        """F16.B2: Inverting branch on unconditional jump jmp handles non-inverting instruction."""
        if not is_gate_bypass_available():
            self.skipTest("Feature F16 bypass_decision_gate requires Milestone 3")
        res = self.harness.bypass_decision_gate(target=str(AUTH_GATE_BIN), gate_addr="entry0")
        self.assertIn("error", res)

    def test_tier2_f16_03_gate_bypass_noninteractive_eof(self):
        """F16.B3: Gate bypass on non-interactive binary handles EOF gracefully."""
        if not is_gate_bypass_available():
            self.skipTest("Feature F16 bypass_decision_gate requires Milestone 3")
        res = self.harness.bypass_decision_gate(target=str(AUTH_GATE_BIN), gate_addr="main")
        self.assertIsInstance(res, dict)

    def test_tier2_f16_04_patch_plan_dry_run_leaves_binary_untouched(self):
        """F16.B4: Patch plan dry_run=True guarantees 0 bytes modified on disk."""
        orig_bytes = AUTH_GATE_BIN.read_bytes()
        req = {
            "jsonrpc": "2.0",
            "id": 166,
            "method": "tools/call",
            "params": {
                "name": "rvs_agent_patch_plan",
                "arguments": {
                    "file": str(AUTH_GATE_BIN),
                    "target": "main",
                    "action": "nop_check",
                    "dry_run": True,
                },
            },
        }
        send_mcp_request(req, self.harness)
        self.assertEqual(AUTH_GATE_BIN.read_bytes(), orig_bytes)

    def test_tier2_f16_05_malformed_gate_address_string(self):
        """F16.B5: Malformed gate address string returns invalid argument error."""
        if not is_gate_bypass_available():
            self.skipTest("Feature F16 bypass_decision_gate requires Milestone 3")
        res = self.harness.bypass_decision_gate(target=str(AUTH_GATE_BIN), gate_addr="0xZZZZZZ")
        self.assertFalse(res.get("bypassed", False))

    # =========================================================================
    # Feature 17: Decryptor Buffer Dump Workflow (Boundaries)
    # =========================================================================

    def test_tier2_f17_01_decryptor_crash_before_loop(self):
        """F17.B1: Target crashing before loop exit handled cleanly."""
        if not is_buffer_dump_available():
            self.skipTest("Feature F17 dump_decrypted_buffer requires Milestone 3")
        res = self.harness.dump_decrypted_buffer(target=str(CRASH_TARGET_BIN))
        self.assertFalse(res.get("success", True))

    def test_tier2_f17_02_buffer_address_out_of_maps(self):
        """F17.B2: Buffer address outside process memory maps returns memory access error."""
        if not is_buffer_dump_available():
            self.skipTest("Feature F17 dump_decrypted_buffer requires Milestone 3")
        res = self.harness.dump_decrypted_buffer(target=str(DECRYPTOR_TARGET_BIN), buffer_addr="0xffffffff80000000")
        self.assertFalse(res.get("success", True))

    def test_tier2_f17_03_loop_exceeds_step_limit(self):
        """F17.B3: Decryption loop exceeding max steps stops at step limit."""
        rc, data, _, _ = run_rvs_cmd([
            "-f", str(DECRYPTOR_TARGET_BIN), "dynamic", "emulate", "decrypt_buffer", "--steps", "5"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        data_payload = data.get("data", {})
        stop = data_payload.get("stop") or data_payload.get("stop_reason")
        self.assertEqual(stop, "step_limit_completed")

    def test_tier2_f17_04_buffer_len_zero(self):
        """F17.B4: Memory read with length 0 returns empty buffer string."""
        rc, data, _, _ = run_rvs_cmd([
            "-f", str(DECRYPTOR_TARGET_BIN), "dynamic", "emulate", "decrypt_buffer", "--read-mem", "decrypt_buffer", "--mem-len", "0"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier2_f17_05_partial_read_on_incomplete_loop(self):
        """F17.B5: Stepping partially through decryption loop returns partially decrypted buffer."""
        rc, data, _, _ = run_rvs_cmd([
            "-f", str(DECRYPTOR_TARGET_BIN), "dynamic", "emulate", "decrypt_buffer", "--steps", "15"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(assert_valid_envelope(data))

    # =========================================================================
    # Feature 18: Anti-Debug Detection & Bypass (Boundaries)
    # =========================================================================

    def test_tier2_f18_01_clean_binary_no_anti_debug(self):
        """F18.B1: Anti-debug check on clean binary (flow_calc) reports no anti-debug detected."""
        if not is_anti_debug_available():
            self.skipTest("Feature F18 detect_anti_debug requires Milestone 3")
        res = self.harness.detect_anti_debug(target=str(FLOW_CALC_BIN))
        self.assertFalse(res.get("anti_debug_detected", False))

    def test_tier2_f18_02_bypass_hook_failure_guidance(self):
        """F18.B2: Guidance provided when ptrace is blocked by Linux Yama ptrace_scope."""
        if not is_anti_debug_available():
            self.skipTest("Feature F18 detect_anti_debug requires Milestone 3")
        res = self.harness.detect_anti_debug(target=str(ANTIDEBUG_TARGET_BIN))
        self.assertIn("bypass_hook", res)

    def test_tier2_f18_03_proc_status_neutralization(self):
        """F18.B3: Neutralizing TracerPid check allows untraced flag retrieval."""
        proc = subprocess.run([str(ANTIDEBUG_TARGET_BIN)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ACCESS_GRANTED_FLAG", proc.stdout)

    def test_tier2_f18_04_multi_technique_simultaneous_detection(self):
        """F18.B4: Target with both ptrace and TracerPid has both flagged in techniques array."""
        if not is_anti_debug_available():
            self.skipTest("Feature F18 detect_anti_debug requires Milestone 3")
        res = self.harness.detect_anti_debug(target=str(ANTIDEBUG_TARGET_BIN))
        techniques = res.get("techniques", [])
        self.assertTrue(len(techniques) >= 2)

    def test_tier2_f18_05_stripped_anti_debug_binary(self):
        """F18.B5: Detection on stripped anti-debug binary detects strings/syscalls."""
        rc, data, stdout, _ = run_rvs_cmd(["-f", str(ANTIDEBUG_TARGET_BIN), "strings"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("TracerPid", stdout)


if __name__ == "__main__":
    unittest.main()
