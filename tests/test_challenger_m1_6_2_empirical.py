#!/usr/bin/env python3
"""
tests/test_challenger_m1_6_2_empirical.py - Empirical Adversarial Verification Suite for Milestone 1.

Comprehensive challenger tests covering:
1. Dynamic register diffing: verify `registers --diff` captures modified registers across steps, halts, and mutations.
2. Signal and exit handling: test debuggee exit events and crash events (e.g. `crash_target_elf64`, `crash_target_elf32`) ensuring structured envelopes and correct exit codes.
3. ESIL dynamic tracing on multi-arch targets (ELF64, ELF32, ARM32) ensuring program counter resolution works without hardcoded `rip`.
4. Defensive CLI and error envelopes.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "release" / "rvs"
if not RVS_BIN.exists():
    RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"

FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"
TEST_TARGET_64 = FIXTURES_DIR / "test_target_elf64"
TEST_TARGET_32 = FIXTURES_DIR / "test_target_elf32"
CRASH_TARGET_64 = FIXTURES_DIR / "crash_target_elf64"
CRASH_TARGET_32 = FIXTURES_DIR / "crash_target_elf32"
AUTH_GATE_64 = FIXTURES_DIR / "auth_gate_elf64"
AUTH_GATE_PIE = FIXTURES_DIR / "auth_gate_elf64_pie"


class BaseChallengerTestCase(unittest.TestCase):
    """Base setup for isolating Unix Domain Socket per test case."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rvs_m1_6_2_")
        self.socket_path = Path(self.temp_dir) / "rvs-test.sock"
        self.env = os.environ.copy()
        self.env["RVS_DEBUG_SOCKET"] = str(self.socket_path)
        self.env["TERM"] = "dumb"
        self.env["NO_COLOR"] = "1"
        self.active_sessions = []

    def tearDown(self):
        for sid in self.active_sessions:
            try:
                self.run_cmd(["dynamic", "debug", "kill", sid], timeout=3)
            except Exception:
                pass
        try:
            self.run_cmd(["dynamic", "debug", "daemon", "--stop"], timeout=3)
        except Exception:
            pass
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception:
                pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_cmd(self, args, timeout=15):
        cmd = [str(RVS_BIN)] + args
        res = subprocess.run(
            cmd,
            cwd=WORKSPACE_DIR,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        parsed = None
        if res.stdout.strip():
            try:
                parsed = json.loads(res.stdout)
            except json.JSONDecodeError:
                pass
        return res.returncode, parsed, res.stdout, res.stderr

    def spawn_session(self, binary_path, extra_args=None):
        cmd = ["dynamic", "debug", "spawn", str(binary_path)]
        if extra_args:
            cmd.extend(extra_args)
        rc, data, stdout, stderr = self.run_cmd(cmd)
        self.assertEqual(rc, 0, f"Spawn failed for {binary_path}: {stdout} {stderr}")
        self.assertIsNotNone(data, f"No JSON parsed from stdout: {stdout}")
        self.assertTrue(data.get("success"), f"Spawn unsuccessful: {data}")
        sid = data["data"]["session_id"]
        self.active_sessions.append(sid)
        return sid, data["data"]


class TestRegisterDiffingAdversarial(BaseChallengerTestCase):
    """Area 1: Dynamic register diffing across steps, halts, and mutations."""

    def test_fresh_spawn_registers_diff_empty(self):
        """Verify registers --diff on a newly spawned session reports an empty diff."""
        sid, info = self.spawn_session(TEST_TARGET_64)
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "registers", sid, "--diff"])
        self.assertEqual(rc, 0)
        self.assertTrue(data.get("success"))
        self.assertEqual(data["data"]["modified"], [])
        self.assertEqual(data["data"]["diff"], {})

    def test_single_step_registers_diff(self):
        """Verify single step updates previous_registers so registers --diff reflects changed registers."""
        sid, info = self.spawn_session(TEST_TARGET_64)
        initial_rip = info["rip"]

        # Step 1 instruction
        rc, step_data, _, _ = self.run_cmd(["dynamic", "debug", "step", sid, "-n", "1"])
        self.assertEqual(rc, 0)
        new_rip = step_data["data"]["rip"]
        self.assertNotEqual(initial_rip, new_rip)

        # Verify step response register_diff contains RIP
        step_diffs = {d["reg"]: d for d in step_data["data"]["register_diff"]}
        self.assertIn("rip", step_diffs)
        self.assertEqual(step_diffs["rip"]["before"], initial_rip)
        self.assertEqual(step_diffs["rip"]["after"], new_rip)

        # Verify registers --diff captures the same RIP change
        rc, reg_data, _, _ = self.run_cmd(["dynamic", "debug", "registers", sid, "--diff"])
        self.assertEqual(rc, 0)
        diff_map = reg_data["data"]["diff"]
        self.assertIn("rip", diff_map)
        self.assertEqual(diff_map["rip"]["before"], initial_rip)
        self.assertEqual(diff_map["rip"]["after"], new_rip)

    def test_multi_step_registers_diff(self):
        """Verify multi-step (count=5) accumulates register changes across all 5 steps."""
        sid, info = self.spawn_session(TEST_TARGET_64)
        start_rip = info["rip"]

        rc, step_data, _, _ = self.run_cmd(["dynamic", "debug", "step", sid, "-n", "5"])
        self.assertEqual(rc, 0)
        final_rip = step_data["data"]["rip"]
        self.assertNotEqual(start_rip, final_rip)

        rc, reg_data, _, _ = self.run_cmd(["dynamic", "debug", "registers", sid, "--diff"])
        self.assertEqual(rc, 0)
        diff_map = reg_data["data"]["diff"]
        self.assertIn("rip", diff_map)
        self.assertEqual(diff_map["rip"]["before"], start_rip)
        self.assertEqual(diff_map["rip"]["after"], final_rip)

    def test_manual_register_mutation_diff(self):
        """Verify manual register modification via --set updates modified diff correctly."""
        sid, info = self.spawn_session(TEST_TARGET_64)

        target_val = 0xdeadbeef1337cafe
        rc, set_data, _, _ = self.run_cmd([
            "dynamic", "debug", "registers", sid,
            "--set", f"rax={hex(target_val)}"
        ])
        self.assertEqual(rc, 0)
        modified = {d["reg"]: d for d in set_data["data"]["modified"]}
        self.assertIn("rax", modified)
        self.assertEqual(modified["rax"]["after"], target_val)

        # Subsequent registers read without --set should confirm RAX persisted
        rc, get_data, _, _ = self.run_cmd(["dynamic", "debug", "registers", sid])
        self.assertEqual(rc, 0)
        self.assertEqual(get_data["data"]["registers"]["rax"], target_val)

    def test_breakpoint_continue_diff(self):
        """Verify continuing from entrypoint to a breakpoint computes register diff."""
        sid, info = self.spawn_session(TEST_TARGET_64)
        entry_rip = info["rip"]

        # Set breakpoint at main
        rc, bp_data, _, _ = self.run_cmd([
            "dynamic", "debug", "breakpoint", sid,
            "--action", "add", "main"
        ])
        self.assertEqual(rc, 0)

        # Continue to main
        rc, cont_data, _, _ = self.run_cmd(["dynamic", "debug", "continue", sid])
        self.assertEqual(rc, 0)
        self.assertEqual(cont_data["data"]["status"], "stopped")
        self.assertEqual(cont_data["data"]["stop_reason"], "breakpoint")
        self.assertEqual(cont_data["data"]["event"], "breakpoint")
        main_rip = cont_data["data"]["rip"]
        self.assertNotEqual(entry_rip, main_rip)

        # Verify register_diff in continue response
        cont_diff = {d["reg"]: d for d in cont_data["data"]["register_diff"]}
        self.assertIn("rip", cont_diff)
        self.assertEqual(cont_diff["rip"]["before"], entry_rip)
        self.assertEqual(cont_diff["rip"]["after"], main_rip)

        # Verify registers --diff matches
        rc, reg_data, _, _ = self.run_cmd(["dynamic", "debug", "registers", sid, "--diff"])
        self.assertEqual(rc, 0)
        diff_map = reg_data["data"]["diff"]
        self.assertIn("rip", diff_map)
        self.assertEqual(diff_map["rip"]["before"], entry_rip)
        self.assertEqual(diff_map["rip"]["after"], main_rip)

    def test_register_diff_32bit_target(self):
        """Verify register diffing works on 32-bit ELF targets tracking 'eip'."""
        if not TEST_TARGET_32.exists():
            self.skipTest("32-bit fixture not present")
        sid, info = self.spawn_session(TEST_TARGET_32)
        self.assertEqual(info["arch"], "x86")
        self.assertEqual(info["bits"], 32)
        initial_eip = info["rip"]

        rc, step_data, _, _ = self.run_cmd(["dynamic", "debug", "step", sid, "-n", "1"])
        self.assertEqual(rc, 0)
        step_diffs = {d["reg"]: d for d in step_data["data"]["register_diff"]}
        self.assertIn("eip", step_diffs)
        self.assertEqual(step_diffs["eip"]["before"], initial_eip)

        rc, reg_data, _, _ = self.run_cmd(["dynamic", "debug", "registers", sid, "--diff"])
        self.assertEqual(rc, 0)
        diff_map = reg_data["data"]["diff"]
        self.assertIn("eip", diff_map)


class TestSignalAndExitHandlingAdversarial(BaseChallengerTestCase):
    """Area 2: Signal and exit handling across crashes, clean exits, and exit codes."""

    def test_crash_target_sigsegv_positional_session(self):
        """Positional session continue on crash target yields structured SIGSEGV envelope."""
        sid, info = self.spawn_session(CRASH_TARGET_64)
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "continue", sid])
        self.assertEqual(rc, 0, f"Expected clean CLI exit code 0 on crash capture, got {rc}")
        self.assertTrue(data.get("success"))

        cdata = data["data"]
        self.assertEqual(cdata["status"], "signaled")
        self.assertEqual(cdata["stop_reason"], "signal")
        self.assertEqual(cdata["event"], "signal")

        sig = cdata["signal"]
        self.assertIsInstance(sig, dict)
        self.assertEqual(sig["signum"], 11)
        self.assertEqual(sig["name"], "SIGSEGV")
        self.assertIn("fault_addr", sig)
        self.assertEqual(sig["code"], 1)

        # Verify RIP points to faulting instruction and instruction is captured
        self.assertIn("mov", cdata["instruction"])
        self.assertIn("0xdeadbeef", cdata["instruction"])
        self.assertIsNotNone(cdata["rip"])
        self.assertIsNotNone(cdata["rip_hex"])

    def test_crash_target_sigsegv_flag_session(self):
        """Flag --session continue on crash target yields backward-compatible integer signal 11."""
        sid, info = self.spawn_session(CRASH_TARGET_64)
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "continue", "--session", sid])
        self.assertEqual(rc, 0)
        self.assertTrue(data.get("success"))

        cdata = data["data"]
        self.assertEqual(cdata["status"], "signaled")
        self.assertEqual(cdata["signum"], 11)
        self.assertEqual(cdata["signal"]["signum"], 11)
        self.assertEqual(cdata["signal"]["name"], "SIGSEGV")

    def test_crash_target_safe_clean_exit_0(self):
        """Crash target with argument 'safe' exits cleanly with exit_code == 0."""
        sid, info = self.spawn_session(CRASH_TARGET_64, extra_args=["--args", "safe"])
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "continue", sid])
        self.assertEqual(rc, 0)
        self.assertTrue(data.get("success"))

        cdata = data["data"]
        self.assertEqual(cdata["status"], "exited")
        self.assertEqual(cdata["stop_reason"], "exit")
        self.assertEqual(cdata["event"], "exit")
        self.assertEqual(cdata["exit_code"], 0)
        self.assertEqual(cdata["register_diff"], [])

    def test_non_zero_exit_code_capture(self):
        """auth_gate_elf64 without arguments terminates with exit code 1."""
        sid, info = self.spawn_session(AUTH_GATE_64)
        rc, data, stdout, stderr = self.run_cmd(["dynamic", "debug", "continue", sid])
        self.assertEqual(rc, 0)
        self.assertTrue(data.get("success"))

        cdata = data["data"]
        self.assertEqual(cdata["status"], "exited")
        self.assertEqual(cdata["stop_reason"], "exit")
        self.assertEqual(cdata["event"], "exit")
        self.assertEqual(cdata["exit_code"], 1)

    def test_stepping_into_crash(self):
        """Single-stepping into a faulting dereference triggers signal state transition."""
        sid, info = self.spawn_session(CRASH_TARGET_64)

        # Break directly at the NULL dereference instruction (0x4011aa)
        rc, bp_data, _, _ = self.run_cmd([
            "dynamic", "debug", "breakpoint", sid,
            "--action", "add", "0x4011aa"
        ])
        self.assertEqual(rc, 0)
        self.assertEqual(bp_data["data"]["modified"]["addr_hex"], "0x4011aa")

        # Continue to breakpoint
        rc, cont_data, _, _ = self.run_cmd(["dynamic", "debug", "continue", sid])
        self.assertEqual(rc, 0)
        self.assertEqual(cont_data["data"]["event"], "breakpoint")
        self.assertEqual(cont_data["data"]["rip_hex"], "0x4011aa")

        # Step 1 instruction directly into the fault
        rc, step_data, _, _ = self.run_cmd(["dynamic", "debug", "step", sid, "-n", "1"])
        self.assertEqual(rc, 0)
        self.assertEqual(step_data["data"]["status"], "signaled")
        self.assertIn("mov", step_data["data"]["instruction"])

    def test_crash_target_32bit_handling(self):
        """Signal handling for 32-bit crash_target_elf32 captures SIGSEGV cleanly."""
        if not CRASH_TARGET_32.exists():
            self.skipTest("32-bit crash target fixture not present")
        sid, info = self.spawn_session(CRASH_TARGET_32)
        rc, data, _, _ = self.run_cmd(["dynamic", "debug", "continue", sid])
        self.assertEqual(rc, 0)
        cdata = data["data"]
        self.assertEqual(cdata["status"], "signaled")
        self.assertEqual(cdata["event"], "signal")
        self.assertEqual(cdata["signal"]["signum"], 11)
        self.assertIn("mov", cdata["instruction"])
        self.assertIn("eax", cdata["instruction"])

    def test_safe_exit_32bit(self):
        """32-bit target with 'safe' argument exits cleanly with code 0."""
        if not CRASH_TARGET_32.exists():
            self.skipTest("32-bit crash target fixture not present")
        sid, info = self.spawn_session(CRASH_TARGET_32, extra_args=["--args", "safe"])
        rc, data, _, _ = self.run_cmd(["dynamic", "debug", "continue", sid])
        self.assertEqual(rc, 0)
        self.assertEqual(data["data"]["status"], "exited")
        self.assertEqual(data["data"]["exit_code"], 0)


class TestEsilDynamicTracingMultiArch(BaseChallengerTestCase):
    """Area 3: ESIL dynamic tracing on multi-arch targets ensuring dynamic PC resolution."""

    def test_esil_trace_elf64(self):
        """ESIL dynamic trace on ELF64 resolves 'rip' and steps instructions correctly."""
        rc, data, stdout, stderr = self.run_cmd([
            "-f", str(TEST_TARGET_64),
            "dynamic", "trace", "main",
            "--steps", "5"
        ])
        self.assertEqual(rc, 0, f"dynamic trace failed: {stdout} {stderr}")
        self.assertTrue(data.get("success"))
        tdata = data["data"]
        self.assertEqual(tdata["total_steps"], 5)
        self.assertEqual(len(tdata["trace"]), 5)

        # Step 1 should have reg_changes with rip
        step1 = tdata["trace"][1]
        changed_regs = {c["reg"] for c in step1["reg_changes"]}
        self.assertIn("rip", changed_regs)

    def test_esil_trace_elf32(self):
        """ESIL dynamic trace on ELF32 resolves 'eip' without hardcoded 'rip'."""
        if not TEST_TARGET_32.exists():
            self.skipTest("32-bit fixture not present")
        rc, data, stdout, stderr = self.run_cmd([
            "-f", str(TEST_TARGET_32),
            "dynamic", "trace", "main",
            "--steps", "5"
        ])
        self.assertEqual(rc, 0, f"dynamic trace on 32-bit failed: {stdout} {stderr}")
        self.assertTrue(data.get("success"))
        tdata = data["data"]
        self.assertEqual(tdata["total_steps"], 5)

        # Step 1 should have reg_changes with eip (NOT rip)
        step1 = tdata["trace"][1]
        changed_regs = {c["reg"] for c in step1["reg_changes"]}
        self.assertIn("eip", changed_regs)
        self.assertNotIn("rip", changed_regs)

    def test_esil_step_elf32(self):
        """ESIL dynamic step on ELF32 steps forward and records 'eip' change."""
        if not TEST_TARGET_32.exists():
            self.skipTest("32-bit fixture not present")
        rc, data, stdout, stderr = self.run_cmd([
            "-f", str(TEST_TARGET_32),
            "dynamic", "step", "main",
            "--count", "2"
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(data.get("success"))
        sdata = data["data"]
        self.assertEqual(sdata["steps"], 2)
        changed_regs = {c["reg"] for c in sdata["reg_changes"]}
        self.assertIn("eip", changed_regs)
        self.assertIn("eip", sdata["final_registers"])
        self.assertNotIn("rip", sdata["final_registers"])

    def test_esil_trace_arm_synthetic(self):
        """ESIL dynamic trace on ARM32 machine code resolves 'pc' dynamically."""
        # Generate small ARM32 snippet: mov r0, 42; add r0, r0, 1; mov r1, 10
        raw_hex = subprocess.check_output(
            ["rasm2", "-a", "arm", "-b", "32", "mov r0, 42; add r0, r0, 1; mov r1, 10; bx lr"]
        ).decode().strip()
        arm_bin_path = Path(self.temp_dir) / "sample_arm.bin"
        arm_bin_path.write_bytes(bytes.fromhex(raw_hex))

        rc, data, stdout, stderr = self.run_cmd([
            "-f", str(arm_bin_path),
            "-a", "arm",
            "-b", "32",
            "dynamic", "trace", "0x0",
            "--steps", "3"
        ])
        self.assertEqual(rc, 0, f"dynamic trace on ARM failed: {stdout} {stderr}")
        self.assertTrue(data.get("success"))
        tdata = data["data"]
        self.assertEqual(tdata["total_steps"], 3)

        # Step 1 should record pc and r0 changes
        step1 = tdata["trace"][1]
        changed_regs = {c["reg"] for c in step1["reg_changes"]}
        self.assertIn("pc", changed_regs)
        self.assertIn("r0", changed_regs)
        self.assertNotIn("rip", changed_regs)
        self.assertNotIn("eip", changed_regs)

    def test_esil_trace_pie_binary(self):
        """ESIL dynamic trace on PIE binary resolves symbols and disassembles correctly."""
        rc, data, stdout, stderr = self.run_cmd([
            "-f", str(AUTH_GATE_PIE),
            "dynamic", "trace", "main",
            "--steps", "4"
        ])
        self.assertEqual(rc, 0, f"dynamic trace on PIE failed: {stdout} {stderr}")
        self.assertTrue(data.get("success"))
        self.assertEqual(data["data"]["total_steps"], 4)


class TestDefensiveCliAndErrorEnvelopes(BaseChallengerTestCase):
    """Area 4: Defensive CLI error handling and standardized exit codes."""

    def test_invalid_session_id_exit_code_1(self):
        """Operating on an unknown session ID returns Exit Code 1 (INVALID_ARGUMENT)."""
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "step", "dbg_nonexistent_session_9999"
        ])
        self.assertEqual(rc, 1)
        self.assertFalse(data.get("success"))
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

    def test_memory_write_unmapped_exit_code_3(self):
        """Writing memory to NULL address returns Exit Code 3 (ANALYSIS_ERROR)."""
        sid, _ = self.spawn_session(TEST_TARGET_64)
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "memory", sid,
            "--action", "write",
            "--addr", "0x0",
            "--data", "deadbeef"
        ])
        self.assertEqual(rc, 3)
        self.assertFalse(data.get("success"))
        self.assertEqual(data["error"]["exit_code"], 3)
        self.assertEqual(data["error"]["category"], "ANALYSIS_ERROR")

    def test_memory_write_invalid_hex_exit_code_1(self):
        """Writing invalid hex (odd length or non-hex chars) returns Exit Code 1 (INVALID_ARGUMENT)."""
        sid, _ = self.spawn_session(TEST_TARGET_64)
        rc, data, stdout, stderr = self.run_cmd([
            "dynamic", "debug", "memory", sid,
            "--action", "write",
            "--addr", "rsp",
            "--data", "odd12"
        ])
        self.assertEqual(rc, 1)
        self.assertFalse(data.get("success"))
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")


if __name__ == "__main__":
    unittest.main(verbosity=2)
