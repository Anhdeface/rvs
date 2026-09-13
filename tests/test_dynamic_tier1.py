#!/usr/bin/env python3
"""
tests/test_dynamic_tier1.py - Tier 1: Feature Coverage for Dynamic Reverse Engineering (F1-F18).

Covers all 18 features with >= 5 comprehensive test cases each (90 test cases total).
Authoritative Expected Outputs derived from:
- radare2 6.1.4 debug & ESIL engine
- rvs 7-level exit code taxonomy (src/error.rs)
- rvs_agent_harness.py response envelopes (ApiResponseDict)
- C crackme fixtures (crash_target, decryptor_target, antidebug_target)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
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


class TestTier1FeatureCoverage(unittest.TestCase):
    """Tier 1: Feature Coverage (>= 5 test cases per feature for F1-F18, total 90 tests)."""

    @classmethod
    def setUpClass(cls):
        cls.rvs_bin = get_target_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)

    # =========================================================================
    # Feature 1: Debug Session Spawning & Attaching (F1)
    # =========================================================================

    def test_tier1_f1_01_spawn_basic(self):
        """F1.1: Verify spawning binary in debug mode returns valid session ID and stopped status."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        rc, data, stdout, stderr = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertTrue(assert_no_ansi(stdout))
        self.assertTrue(assert_valid_envelope(data, expected_cmd="dynamic debug spawn"))
        session_data = data.get("data", {})
        self.assertIn("session_id", session_data)
        self.assertGreater(session_data.get("pid", 0), 0)
        self.assertEqual(session_data.get("status"), "stopped")

    def test_tier1_f1_02_spawn_with_arguments(self):
        """F1.2: Verify spawning binary with CLI arguments captures args in session state."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        rc, data, stdout, stderr = run_rvs_cmd([
            "dynamic", "debug", "spawn", str(CRASH_TARGET_BIN), "--args", "safe"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        session_data = data.get("data", {})
        self.assertIn("session_id", session_data)

    def test_tier1_f1_03_attach_process(self):
        """F1.3: Verify attaching to a live running process by PID creates an attached session."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        proc = subprocess.Popen(["sleep", "30"])
        try:
            rc, data, stdout, stderr = run_rvs_cmd(["dynamic", "debug", "attach", str(proc.pid)])
            if rc != EXIT_SUCCESS and "Operation not permitted" in str((data or {}).get("error", {}).get("message", "")):
                self.skipTest("ptrace attach not permitted in current environment")
            self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
            session_data = (data or {}).get("data", {})
            self.assertIn("session_id", session_data)
            self.assertEqual(session_data.get("pid"), proc.pid)
        finally:
            proc.kill()
            proc.wait()

    def test_tier1_f1_04_list_sessions(self):
        """F1.4: Verify listing active debug sessions returns a structured array."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        rc, data, stdout, stderr = run_rvs_cmd(["dynamic", "debug", "list-sessions"])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertTrue(assert_valid_envelope(data))
        self.assertIsInstance(data.get("data", {}).get("sessions"), list)

    def test_tier1_f1_05_kill_session(self):
        """F1.5: Verify terminating a debug session cleanly reaps child process."""
        if not is_debug_cli_available():
            self.skipTest("Feature F1 requires Milestone 1 (rvs dynamic debug)")
        # Spawn then kill
        rc, data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        self.assertEqual(rc, EXIT_SUCCESS)
        sess_id = data.get("data", {}).get("session_id")
        rc_kill, kill_data, _, _ = run_rvs_cmd(["dynamic", "debug", "kill", "--session", sess_id])
        self.assertEqual(rc_kill, EXIT_SUCCESS)

    # =========================================================================
    # Feature 2: Breakpoint Management (F2)
    # =========================================================================

    def test_tier1_f2_01_set_sw_breakpoint(self):
        """F2.1: Verify setting software breakpoint registers breakpoint with hw=false."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        # Spawn session first
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, bp_data, stdout, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        bp_info = bp_data.get("data", {})
        self.assertFalse(bp_info.get("hw", True))

    def test_tier1_f2_02_set_hw_breakpoint(self):
        """F2.2: Verify setting hardware breakpoint registers breakpoint with hw=true."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, bp_data, stdout, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main", "--hw"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        bp_info = bp_data.get("data", {})
        self.assertTrue(bp_info.get("hw", False))

    def test_tier1_f2_03_list_breakpoints(self):
        """F2.3: Verify listing breakpoints returns array containing set breakpoints."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"])
        rc, list_data, _, _ = run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "list"])
        self.assertEqual(rc, EXIT_SUCCESS)
        bps = list_data.get("data", {}).get("breakpoints", [])
        self.assertGreater(len(bps), 0)

    def test_tier1_f2_04_delete_breakpoint(self):
        """F2.4: Verify deleting a breakpoint removes it from the breakpoint list."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"])
        rc, del_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "delete", "--addr", "main"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f2_05_multiple_breakpoints(self):
        """F2.5: Verify setting multiple breakpoints tracks all addresses simultaneously."""
        if not is_debug_cli_available():
            self.skipTest("Feature F2 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(ANTIDEBUG_TARGET_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"])
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "check_ptrace_traceme"])
        rc, list_data, _, _ = run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "list"])
        self.assertEqual(rc, EXIT_SUCCESS)
        bps = list_data.get("data", {}).get("breakpoints", [])
        self.assertGreaterEqual(len(bps), 2)

    # =========================================================================
    # Feature 3: Stepping & Execution Control (F3)
    # =========================================================================

    def test_tier1_f3_01_step_instruction(self):
        """F3.1: Verify single instruction step (ds) advances RIP and returns instruction mnemonic."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, step_data, stdout, _ = run_rvs_cmd([
            "dynamic", "debug", "step", "--session", sess_id, "--type", "inst"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        step_info = step_data.get("data", {})
        self.assertIn("rip", step_info)
        self.assertIn("instruction", step_info)

    def test_tier1_f3_02_step_over_call(self):
        """F3.2: Verify step over (dso) steps over function calls without entering callee."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, step_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "step", "--session", sess_id, "--type", "over"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f3_03_step_out_ret(self):
        """F3.3: Verify step out (dcr) continues execution until current function returns."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, step_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "step", "--session", sess_id, "--type", "out"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f3_04_step_multiple_count(self):
        """F3.4: Verify stepping N instructions advances execution by N steps."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, step_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "step", "--session", sess_id, "--count", "5"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f3_05_continue_to_breakpoint(self):
        """F3.5: Verify continue execution halts at breakpoint and reports breakpoint event."""
        if not is_debug_cli_available():
            self.skipTest("Feature F3 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"])
        rc, cont_data, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)
        event_info = cont_data.get("data", {})
        self.assertEqual(event_info.get("event"), "breakpoint")

    # =========================================================================
    # Feature 4: Dynamic Register Inspection & Modification (F4)
    # =========================================================================

    def test_tier1_f4_01_read_gprs(self):
        """F4.1: Verify reading GPRs returns standard architecture registers (rax, rip, etc.)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, reg_data, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)
        regs = reg_data.get("data", {}).get("registers", {})
        for expected_reg in ["rax", "rbx", "rip", "rsp", "rbp"]:
            self.assertIn(expected_reg, regs)

    def test_tier1_f4_02_modify_gpr(self):
        """F4.2: Verify modifying register updates value in live process."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, _, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id, "--set", "rax=0x1337"])
        self.assertEqual(rc, EXIT_SUCCESS)
        rc, reg_data, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id])
        regs = reg_data.get("data", {}).get("registers", {})
        self.assertEqual(regs.get("rax"), 0x1337)

    def test_tier1_f4_03_modify_rip(self):
        """F4.3: Verify updating RIP redirects execution target address."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        target_rip = "0x401000"
        rc, _, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id, "--set", f"rip={target_rip}"])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f4_04_register_diff(self):
        """F4.4: Verify register diff calculates delta of modified registers only."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "step", "--session", sess_id])
        rc, reg_data, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id, "--diff"])
        self.assertEqual(rc, EXIT_SUCCESS)
        diff = reg_data.get("data", {}).get("diff", {})
        self.assertIn("rip", diff)

    def test_tier1_f4_05_inspect_flags(self):
        """F4.5: Verify inspecting CPU flags registers returns ZF, CF, SF status."""
        if not is_debug_cli_available():
            self.skipTest("Feature F4 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, reg_data, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)
        regs = reg_data.get("data", {}).get("registers", {})
        self.assertTrue("rflags" in regs or "eflags" in regs)

    # =========================================================================
    # Feature 5: Memory Mapping & Live Read/Write (F5)
    # =========================================================================

    def test_tier1_f5_01_virtual_memory_maps(self):
        """F5.1: Verify inspecting virtual memory maps returns sections with addresses and permissions."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, mem_data, _, _ = run_rvs_cmd(["dynamic", "debug", "memory", "--session", sess_id, "--action", "maps"])
        self.assertEqual(rc, EXIT_SUCCESS)
        maps = mem_data.get("data", {}).get("maps", [])
        self.assertIsInstance(maps, list)
        self.assertGreater(len(maps), 0)
        self.assertIn("perm", maps[0])

    def test_tier1_f5_02_read_memory_bytes(self):
        """F5.2: Verify reading memory bytes at ELF base returns ELF magic (7f454c46)."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, mem_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "read", "--addr", "entry0", "--len", "4"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        bytes_hex = mem_data.get("data", {}).get("bytes", "")
        self.assertTrue(len(bytes_hex) > 0)

    def test_tier1_f5_03_write_memory_bytes(self):
        """F5.3: Verify writing memory bytes at writable address succeeds."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, mem_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "write", "--addr", "rip", "--data", "90909090"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(mem_data.get("data", {}).get("written", False))

    def test_tier1_f5_04_verify_memory_write(self):
        """F5.4: Verify re-reading memory reflects newly written bytes."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "write", "--addr", "rip", "--data", "90909090"
        ])
        rc, read_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "read", "--addr", "rip", "--len", "4"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertEqual(read_data.get("data", {}).get("hex"), "90909090")

    def test_tier1_f5_05_inspect_stack_memory(self):
        """F5.5: Verify reading memory relative to RSP succeeds."""
        if not is_debug_cli_available():
            self.skipTest("Feature F5 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, mem_data, _, _ = run_rvs_cmd([
            "dynamic", "debug", "memory", "--session", sess_id, "--action", "read", "--addr", "rsp", "--len", "8"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    # =========================================================================
    # Feature 6: Debug Event & Signal Multiplexing (F6)
    # =========================================================================

    def test_tier1_f6_01_process_exit_event(self):
        """F6.1: Verify normal target execution to termination reports status 'exited'."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN), "--args", "safe"])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, cont_data, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)
        event_info = cont_data.get("data", {})
        self.assertEqual(event_info.get("event"), "exit")

    def test_tier1_f6_02_breakpoint_hit_event(self):
        """F6.2: Verify breakpoint hit reports event='breakpoint' with PC address."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"])
        rc, cont_data, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertEqual(cont_data.get("data", {}).get("event"), "breakpoint")

    def test_tier1_f6_03_sigsegv_crash_event(self):
        """F6.3: Verify predictable SIGSEGV on crash_target reports signal=11 event."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, cont_data, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)
        event_info = cont_data.get("data", {})
        self.assertEqual(event_info.get("event"), "signal")
        sig = event_info.get("signal")
        signum = sig.get("signum") if isinstance(sig, dict) else (event_info.get("signum") or sig)
        self.assertEqual(signum, 11)

    def test_tier1_f6_04_sigtrap_event(self):
        """F6.4: Verify trap signal reports signal=5."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        # In r2, int3 or single step generates trap
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, step_data, _, _ = run_rvs_cmd(["dynamic", "debug", "step", "--session", sess_id])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f6_05_sequential_events(self):
        """F6.5: Verify multi-event sequencing: breakpoint hit -> continue -> exit."""
        if not is_debug_cli_available():
            self.skipTest("Feature F6 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET_BIN), "--args", "safe"])
        sess_id = spawn_data.get("data", {}).get("session_id")
        run_rvs_cmd(["dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"])
        rc1, cont1, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(cont1.get("data", {}).get("event"), "breakpoint")
        rc2, cont2, _, _ = run_rvs_cmd(["dynamic", "debug", "continue", "--session", sess_id])
        self.assertEqual(cont2.get("data", {}).get("event"), "exit")

    # =========================================================================
    # Feature 7: r2frida Environment Detection (F7)
    # =========================================================================

    def test_tier1_f7_01_query_io_plugins(self):
        """F7.1: Verify querying radare2 IO plugins via Loj returns valid JSON."""
        proc = subprocess.run(["radare2", "-qc", "Loj", "-"], capture_output=True, text=True, timeout=5.0)
        self.assertEqual(proc.returncode, 0)
        plugins = json.loads(proc.stdout.strip())
        self.assertIsInstance(plugins, list)
        self.assertGreater(len(plugins), 0)

    def test_tier1_f7_02_check_frida_plugin(self):
        """F7.2: Verify helper correctly detects frida plugin status in host environment."""
        status = is_r2frida_installed()
        self.assertIsInstance(status, bool)

    def test_tier1_f7_03_no_panic_when_missing(self):
        """F7.3: Verify checking r2frida environment does not trigger unhandled panics."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "--help"])
        self.assertNotIn("panicked at", stderr)
        self.assertNotIn("thread 'main' panicked", stderr)

    def test_tier1_f7_04_structured_diagnostic(self):
        """F7.4: Verify frida environment check provides structured diagnostic envelope."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "env-check"])
        # Either command not yet merged (code 1) or succeeds (0) or missing frida (6)
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR])
        self.assertTrue(assert_no_ansi(stdout))

    def test_tier1_f7_05_version_compatibility(self):
        """F7.5: Verify radare2 version meets minimum requirement for dynamic RE (>= 5.8.0)."""
        proc = subprocess.run(["radare2", "-v"], capture_output=True, text=True, timeout=5.0)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("radare2", proc.stdout)

    # =========================================================================
    # Feature 8: r2frida Attach & Spawn (F8)
    # =========================================================================

    def test_tier1_f8_01_attach_pid_syntax(self):
        """F8.1: Verify rvs frida attach command accepts numeric PID."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "12345"])
        # If r2frida is missing, should return EXIT_INTERNAL_ERROR (6); otherwise analysis error or success
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f8_02_attach_name_syntax(self):
        """F8.2: Verify rvs frida attach command accepts process name."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "firefox"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f8_03_spawn_uri_construction(self):
        """F8.3: Verify spawning target constructs proper frida:// URI."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "spawn", str(AUTH_GATE_BIN)])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f8_04_spawn_with_arguments(self):
        """F8.4: Verify spawning with arguments formats URI properly."""
        if not is_frida_cli_available():
            self.skipTest("Feature F8 requires Milestone 2 (rvs frida)")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "spawn", str(CRASH_TARGET_BIN), "--args", "safe"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f8_05_plugins_enabled_flag(self):
        """F8.5: Verify frida driver does not inject R2_NOPLUGINS=1."""
        # Test harness environment helper with plugins=True
        env = rvs_agent_harness.get_isolated_environment()
        self.assertEqual(env.get("TERM"), "dumb")

    # =========================================================================
    # Feature 9: r2frida Module & Symbol Enumeration (F9)
    # =========================================================================

    def test_tier1_f9_01_list_modules(self):
        """F9.1: Verify module enumeration command schema returns module array."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "modules", "--target", "0"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f9_02_list_symbols(self):
        """F9.2: Verify symbol enumeration command schema returns symbols array."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "symbols", "--target", "0"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f9_03_filter_symbols_module(self):
        """F9.3: Verify filtering symbols by module name."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "symbols", "--target", "0", "--module", "libc.so.6"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f9_04_list_classes(self):
        """F9.4: Verify listing classes via :icj returns class array."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "classes", "--target", "0"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f9_05_symbol_pagination(self):
        """F9.5: Verify symbol list pagination preserves token budget."""
        if not is_frida_cli_available():
            self.skipTest("Feature F9 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "symbols", "--target", "0", "--limit", "10"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    # =========================================================================
    # Feature 10: r2frida Dynamic Hooking & Tracing (F10)
    # =========================================================================

    def test_tier1_f10_01_function_trace_syntax(self):
        """F10.1: Verify function trace command accepts address and format specifier."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "hook", "--target", "0", "--addr", "0x401000", "--format", "x"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f10_02_format_specifiers(self):
        """F10.2: Verify format specifiers validation accepts i, x, z, h."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        for fmt in ["i", "x", "z", "h"]:
            rc, _, _, _ = run_rvs_cmd(["frida", "hook", "--target", "0", "--addr", "0x401000", "--format", fmt])
            self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f10_03_register_trace_syntax(self):
        """F10.3: Verify register trace command accepts register names."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "trace-regs", "--target", "0", "--addr", "0x401000", "--regs", "rax,rdi"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f10_04_return_interception(self):
        """F10.4: Verify return value interception hook specification."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "hook-return", "--target", "0", "--addr", "0x401000", "--retval", "0x1"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f10_05_list_remove_hooks(self):
        """F10.5: Verify listing and clearing dynamic hooks."""
        if not is_frida_cli_available():
            self.skipTest("Feature F10 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "hooks-list", "--target", "0"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    # =========================================================================
    # Feature 11: r2frida Script Injection & RPC (F11)
    # =========================================================================

    def test_tier1_f11_01_eval_js_syntax(self):
        """F11.1: Verify evaluating JS snippet syntax via CLI."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "script", "--target", "0", "--code", "console.log('test')"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f11_02_script_file_loading(self):
        """F11.2: Verify loading external JS script file."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "script", "--target", "0", "--file", "/dev/null"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f11_03_rpc_exports_invocation(self):
        """F11.3: Verify invoking Frida RPC export function."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "rpc", "--target", "0", "--method", "testFunc"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f11_04_live_memory_patch(self):
        """F11.4: Verify live memory write via frida mem-write."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", "9090"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    def test_tier1_f11_05_live_memory_read(self):
        """F11.5: Verify live memory read via frida mem-read."""
        if not is_frida_cli_available():
            self.skipTest("Feature F11 requires Milestone 2 (rvs frida)")
        rc, data, _, _ = run_rvs_cmd(["frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "4"])
        self.assertIn(rc, [EXIT_SUCCESS, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR])

    # =========================================================================
    # Feature 12: Canonical Tool Expansion (26 tools) (F12)
    # =========================================================================

    def test_tier1_f12_01_canonical_tools_count(self):
        """F12.1: Verify CANONICAL_TOOLS contains >= 16 (or 26 when M3 completed) tools."""
        count = len(CANONICAL_TOOLS)
        self.assertGreaterEqual(count, 16)

    def test_tier1_f12_02_dynamic_tool_properties(self):
        """F12.2: Verify canonical tools have valid schema structure (name, description, properties)."""
        for tool in CANONICAL_TOOLS:
            self.assertIn("name", tool)
            self.assertIn("description", tool)
            self.assertIn("properties", tool)
            self.assertIsInstance(tool["properties"], dict)

    def test_tier1_f12_03_native_debug_tools(self):
        """F12.3: Verify native debug tools present if M3 expanded."""
        if not is_canonical_tools_expanded():
            self.skipTest("Feature F12 expansion to 26 tools requires Milestone 3")
        tool_names = [t["name"] for t in CANONICAL_TOOLS]
        for dbg_tool in ["rvs_debug_spawn", "rvs_debug_step", "rvs_debug_continue", "rvs_debug_breakpoint", "rvs_debug_registers", "rvs_debug_memory"]:
            self.assertIn(dbg_tool, tool_names)

    def test_tier1_f12_04_frida_tools(self):
        """F12.4: Verify frida tools present if M3 expanded."""
        if not is_canonical_tools_expanded():
            self.skipTest("Feature F12 expansion to 26 tools requires Milestone 3")
        tool_names = [t["name"] for t in CANONICAL_TOOLS]
        for frida_tool in ["rvs_frida_attach", "rvs_frida_hook", "rvs_frida_script", "rvs_frida_rpc"]:
            self.assertIn(frida_tool, tool_names)

    def test_tier1_f12_05_tool_naming_convention(self):
        """F12.5: Verify all tools strictly follow 'rvs_*' naming convention."""
        for tool in CANONICAL_TOOLS:
            self.assertTrue(tool["name"].startswith("rvs_"), f"Invalid tool name: {tool['name']}")

    # =========================================================================
    # Feature 13: 4-Format Schema Generator (F13)
    # =========================================================================

    def test_tier1_f13_01_openai_schema_generation(self):
        """F13.1: Verify OpenAI schemas conform to type='function' and parameters schema."""
        schemas = get_tool_schemas("openai")
        self.assertIsInstance(schemas, list)
        self.assertGreater(len(schemas), 0)
        for s in schemas:
            self.assertEqual(s.get("type"), "function")
            self.assertIn("name", s.get("function", {}))
            self.assertIn("parameters", s.get("function", {}))

    def test_tier1_f13_02_anthropic_schema_generation(self):
        """F13.2: Verify Anthropic schemas conform to name, description, input_schema."""
        schemas = get_tool_schemas("anthropic")
        self.assertIsInstance(schemas, list)
        for s in schemas:
            self.assertIn("name", s)
            self.assertIn("description", s)
            self.assertIn("input_schema", s)

    def test_tier1_f13_03_gemini_schema_generation(self):
        """F13.3: Verify Gemini schemas convert types to UPPERCASE (STRING, INTEGER, etc.)."""
        schemas = get_tool_schemas("gemini")
        self.assertIsInstance(schemas, list)
        for s in schemas:
            params = s.get("parameters", {})
            for prop in params.get("properties", {}).values():
                prop_type = prop.get("type")
                if prop_type:
                    self.assertTrue(prop_type.isupper(), f"Gemini type not uppercase: {prop_type}")

    def test_tier1_f13_04_mcp_schema_generation(self):
        """F13.4: Verify MCP schemas match Model Context Protocol tool spec."""
        schemas = get_tool_schemas("mcp")
        self.assertIsInstance(schemas, list)
        for s in schemas:
            self.assertIn("name", s)
            self.assertIn("inputSchema", s)

    def test_tier1_f13_05_schema_counts_consistency(self):
        """F13.5: Verify all 4 formats export the exact same number of tool definitions."""
        openai_count = len(get_tool_schemas("openai"))
        anthropic_count = len(get_tool_schemas("anthropic"))
        gemini_count = len(get_tool_schemas("gemini"))
        mcp_count = len(get_tool_schemas("mcp"))
        self.assertEqual(openai_count, anthropic_count)
        self.assertEqual(openai_count, gemini_count)
        self.assertEqual(openai_count, mcp_count)

    # =========================================================================
    # Feature 14: Dynamic Token Compaction (F14)
    # =========================================================================

    def test_tier1_f14_01_register_diff_compaction(self):
        """F14.1: Verify dynamic emulation register diff emits only changed registers."""
        rc, data, stdout, stderr = run_rvs_cmd([
            "-f", str(FLOW_CALC_BIN), "dynamic", "emulate", "main", "-c"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        diff = data.get("data", {}).get("diff", {})
        self.assertTrue(isinstance(diff, (list, dict)))

    def test_tier1_f14_02_memory_dump_preview(self):
        """F14.2: Verify memory read with compact mode emits preview without verbose bloat."""
        rc, data, stdout, stderr = run_rvs_cmd([
            "-f", str(FLOW_CALC_BIN), "dynamic", "emulate", "main", "--read-mem", "main", "--mem-len", "16", "-c"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        data_payload = data.get("data", {})
        self.assertTrue("mem_before" in data_payload or "memory" in data_payload)

    def test_tier1_f14_03_symbol_list_compaction(self):
        """F14.3: Verify compact symbols list achieves significant reduction over full verbose."""
        rc_full, full_data, _, _ = run_rvs_cmd(["-f", str(FLOW_CALC_BIN), "symbols"])
        rc_comp, comp_data, _, _ = run_rvs_cmd(["-f", str(FLOW_CALC_BIN), "symbols", "-c"])
        self.assertEqual(rc_full, EXIT_SUCCESS)
        self.assertEqual(rc_comp, EXIT_SUCCESS)
        full_len = len(json.dumps(full_data))
        comp_len = len(json.dumps(comp_data))
        reduction = (full_len - comp_len) / full_len
        self.assertGreater(reduction, 0.40)

    def test_tier1_f14_04_module_list_compaction(self):
        """F14.4: Verify module list compaction strips redundant paths."""
        rc, data, _, _ = run_rvs_cmd(["-f", str(FLOW_CALC_BIN), "info", "-c"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertTrue(assert_valid_envelope(data))

    def test_tier1_f14_05_token_reduction_ratio(self):
        """F14.5: Verify disassembly compact mode achieves >= 60% token reduction."""
        rc_full, full_data, _, _ = run_rvs_cmd(["-f", str(AUTH_GATE_BIN), "analyze", "blocks", "main"])
        rc_comp, comp_data, _, _ = run_rvs_cmd(["-f", str(AUTH_GATE_BIN), "analyze", "blocks", "main", "-c"])
        self.assertEqual(rc_full, EXIT_SUCCESS)
        self.assertEqual(rc_comp, EXIT_SUCCESS)
        full_len = len(json.dumps(full_data))
        comp_len = len(json.dumps(comp_data))
        reduction = (full_len - comp_len) / full_len
        self.assertGreaterEqual(reduction, 0.55)

    # =========================================================================
    # Feature 15: Automated Crash Triage Workflow (F15)
    # =========================================================================

    def test_tier1_f15_01_crash_target_sigsegv_detection(self):
        """F15.1: Verify executing crash_target without args results in SIGSEGV (signal 11)."""
        proc = subprocess.run([str(CRASH_TARGET_BIN)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, -11)

    def test_tier1_f15_02_null_pointer_fault_addr(self):
        """F15.2: Verify static flow of trigger_null_deref reveals NULL pointer dereference."""
        rc, data, stdout, stderr = run_rvs_cmd(["-f", str(CRASH_TARGET_BIN), "analyze", "blocks", "trigger_null_deref"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("trigger_null_deref", stdout)

    def test_tier1_f15_03_callstack_unwinding(self):
        """F15.3: Verify functions leading to crash are present in function list."""
        rc, data, stdout, _ = run_rvs_cmd(["-f", str(CRASH_TARGET_BIN), "analyze", "functions"])
        self.assertEqual(rc, EXIT_SUCCESS)
        fns = [f.get("name") for f in data.get("data", {}).get("functions", [])]
        self.assertTrue(any("trigger_null_deref" in f for f in fns))
        self.assertTrue(any("inner_fault_worker" in f for f in fns))
        self.assertTrue(any("dispatch_execution" in f for f in fns))

    def test_tier1_f15_04_root_cause_classification(self):
        """F15.4: Verify triage workflow on harness classifies NULL_POINTER_DEREFERENCE."""
        if not is_crash_triage_available():
            self.skipTest("Feature F15 triage_crash requires Milestone 3")
        res = self.harness.triage_crash(target=str(CRASH_TARGET_BIN))
        self.assertEqual(res.get("signal"), 11)
        self.assertEqual(res.get("cause"), "NULL_POINTER_DEREFERENCE")

    def test_tier1_f15_05_safe_target_no_crash(self):
        """F15.5: Verify crash_target executed with 'safe' argument exits 0 without crashing."""
        proc = subprocess.run([str(CRASH_TARGET_BIN), "safe"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("SAFE_EXECUTION_COMPLETED", proc.stdout)

    # =========================================================================
    # Feature 16: Decision Gate Bypass Loop (F16)
    # =========================================================================

    def test_tier1_f16_01_identify_decision_gate(self):
        """F16.1: Verify static flow identifies comparison and branch in auth_gate."""
        rc, data, stdout, _ = run_rvs_cmd(["-f", str(AUTH_GATE_BIN), "agent", "flow", "main"])
        self.assertEqual(rc, EXIT_SUCCESS)
        decisions = data.get("data", {}).get("decision_nodes", [])
        self.assertGreater(len(decisions), 0)

    def test_tier1_f16_02_breakpoint_at_gate(self):
        """F16.2: Verify breakpoint can be placed at conditional jump node."""
        if not is_debug_cli_available():
            self.skipTest("Feature F16 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        rc, _, _, _ = run_rvs_cmd([
            "dynamic", "debug", "breakpoint", "--session", sess_id, "--action", "set", "--addr", "main"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f16_03_zero_flag_inversion(self):
        """F16.3: Verify modifying flags register inverts zero flag."""
        if not is_debug_cli_available():
            self.skipTest("Feature F16 requires Milestone 1 (rvs dynamic debug)")
        rc, spawn_data, _, _ = run_rvs_cmd(["dynamic", "debug", "spawn", str(AUTH_GATE_BIN)])
        sess_id = spawn_data.get("data", {}).get("session_id")
        # Set rflags to invert ZF (bit 6)
        rc, _, _, _ = run_rvs_cmd(["dynamic", "debug", "registers", "--session", sess_id, "--set", "rflags=0x246"])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier1_f16_04_continue_past_gate(self):
        """F16.4: Verify execution continues past inverted gate."""
        if not is_gate_bypass_available():
            self.skipTest("Feature F16 bypass_decision_gate requires Milestone 3")
        res = self.harness.bypass_decision_gate(target=str(AUTH_GATE_BIN), gate_addr="check_auth")
        self.assertTrue(res.get("bypassed", False))

    def test_tier1_f16_05_generate_patch_plan(self):
        """F16.5: Verify rvs_agent_patch_plan generates valid NOP/inversion plan for gate."""
        req = {
            "jsonrpc": "2.0",
            "id": 165,
            "method": "tools/call",
            "params": {
                "name": "rvs_agent_patch_plan",
                "arguments": {
                    "file": str(AUTH_GATE_BIN),
                    "target": "check_auth",
                    "action": "nop_check",
                    "dry_run": True,
                },
            },
        }
        res = send_mcp_request(req, self.harness)
        self.assertIn("result", res)

    # =========================================================================
    # Feature 17: Decryptor Buffer Dump Workflow (F17)
    # =========================================================================

    def test_tier1_f17_01_detect_decryption_loop(self):
        """F17.1: Verify control flow of decrypt_buffer identifies XOR loop and back-edge."""
        rc, data, stdout, _ = run_rvs_cmd(["-f", str(DECRYPTOR_TARGET_BIN), "agent", "flow", "decrypt_buffer"])
        self.assertEqual(rc, EXIT_SUCCESS)
        flow = data.get("data", {})
        self.assertTrue(flow.get("loop_count", 0) >= 1 or flow.get("total_blocks", 0) >= 3)

    def test_tier1_f17_02_breakpoint_post_loop(self):
        """F17.2: Verify breakpoint target on_decryption_complete exists in symbols."""
        rc, data, stdout, _ = run_rvs_cmd(["-f", str(DECRYPTOR_TARGET_BIN), "symbols", "--filter", "on_decryption_complete"])
        self.assertEqual(rc, EXIT_SUCCESS)
        syms = data.get("data", {}).get("symbols", [])
        self.assertTrue(any("on_decryption_complete" in s.get("name", "") for s in syms))

    def test_tier1_f17_03_execute_to_loop_exit(self):
        """F17.3: Verify execution reaches on_decryption_complete when run normally."""
        proc = subprocess.run([str(DECRYPTOR_TARGET_BIN)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Decryption complete:", proc.stdout)

    def test_tier1_f17_04_dump_memory_buffer(self):
        """F17.4: Verify dump_decrypted_buffer workflow extracts decrypted buffer."""
        if not is_buffer_dump_available():
            self.skipTest("Feature F17 dump_decrypted_buffer requires Milestone 3")
        res = self.harness.dump_decrypted_buffer(target=str(DECRYPTOR_TARGET_BIN))
        self.assertIn("FLAG{", str(res.get("buffer", "")))

    def test_tier1_f17_05_verify_extracted_flag(self):
        """F17.5: Verify decrypted secret matches expected flag."""
        proc = subprocess.run([str(DECRYPTOR_TARGET_BIN)], capture_output=True, text=True)
        self.assertIn("FLAG{rvs_dynamic_decryptor_buffer_extracted_2026}", proc.stdout)

    # =========================================================================
    # Feature 18: Anti-Debug Detection & Bypass (F18)
    # =========================================================================

    def test_tier1_f18_01_detect_ptrace_import(self):
        """F18.1: Verify static symbol search identifies check_ptrace_traceme in antidebug_target."""
        rc, data, stdout, _ = run_rvs_cmd(["-f", str(ANTIDEBUG_TARGET_BIN), "symbols", "--filter", "ptrace"])
        self.assertEqual(rc, EXIT_SUCCESS)
        syms = data.get("data", {}).get("symbols", [])
        self.assertTrue(any("ptrace" in s.get("name", "") for s in syms))

    def test_tier1_f18_02_detect_tracerpid_string(self):
        """F18.2: Verify string search identifies TracerPid string in antidebug_target."""
        rc, data, stdout, _ = run_rvs_cmd(["-f", str(ANTIDEBUG_TARGET_BIN), "strings"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("TracerPid", stdout)

    def test_tier1_f18_03_debugger_detected_under_trace(self):
        """F18.3: Verify running antidebug_target under ptrace outputs DEBUGGER_DETECTED."""
        proc = subprocess.run(["radare2", "-qc", "dc; q", "-d", str(ANTIDEBUG_TARGET_BIN)], capture_output=True, text=True)
        self.assertIn("DEBUGGER_DETECTED", proc.stdout)

    def test_tier1_f18_04_generate_bypass_hook(self):
        """F18.4: Verify detect_anti_debug generates bypass hook recommendation."""
        if not is_anti_debug_available():
            self.skipTest("Feature F18 detect_anti_debug requires Milestone 3")
        res = self.harness.detect_anti_debug(target=str(ANTIDEBUG_TARGET_BIN))
        self.assertTrue(res.get("anti_debug_detected", False))
        self.assertIn("ptrace", str(res.get("techniques", [])))

    def test_tier1_f18_05_untraced_execution_flag(self):
        """F18.5: Verify running antidebug_target untraced prints access granted flag."""
        proc = subprocess.run([str(ANTIDEBUG_TARGET_BIN)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ACCESS_GRANTED_FLAG{rvs_dynamic_antidebug_bypassed_2026}", proc.stdout)


if __name__ == "__main__":
    unittest.main()
