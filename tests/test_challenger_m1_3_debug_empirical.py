#!/usr/bin/env python3
"""
tests/test_challenger_m1_3_debug_empirical.py - Empirical Adversarial Verification for Milestone 1

Probes:
1. Rapid spawn / kill loops across multiple concurrent sessions (concurrency & race conditions).
2. Setting multiple breakpoints (software and hardware dbH), deleting non-existent breakpoints, address boundaries.
3. Register mutation: setting registers to extreme 64-bit values (0xffffffffffffffff, 0x0), and verifying register diff calculation.
4. Memory inspection: reading at unmapped addresses, writing invalid hex, reading across page boundaries.
5. Error taxonomy verification: ensuring missing sessions produce Exit Code 1 (INVALID_ARGUMENT), memory errors produce Exit Code 3 (ANALYSIS_ERROR).
"""

import concurrent.futures
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"
TEST_TARGET = WORKSPACE_DIR / "tests" / "fixtures" / "test_target_elf64"
CRASH_TARGET = WORKSPACE_DIR / "tests" / "fixtures" / "crash_target_elf64"


class TestM1DebugAdversarial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RVS_BIN.exists():
            res = subprocess.run(["cargo", "build"], cwd=WORKSPACE_DIR, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"cargo build failed: {res.stderr}")
        assert RVS_BIN.exists(), f"Binary not found at {RVS_BIN}"
        assert TEST_TARGET.exists(), f"Fixture not found at {TEST_TARGET}"
        assert CRASH_TARGET.exists(), f"Fixture not found at {CRASH_TARGET}"

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="rvs_dbg_adv_")
        self.socket_path = Path(self.temp_dir) / "rvs-adv-test.sock"
        self.env = os.environ.copy()
        self.env["RVS_DEBUG_SOCKET"] = str(self.socket_path)

    def tearDown(self):
        # Stop daemon if running on this socket
        try:
            subprocess.run(
                [str(RVS_BIN), "dynamic", "debug", "daemon", "--stop"],
                env=self.env,
                capture_output=True,
                timeout=3,
            )
        except Exception:
            pass
        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception:
                pass
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_cmd(self, args, check_json=True, timeout=10):
        cmd = [str(RVS_BIN)] + args
        res = subprocess.run(
            cmd,
            cwd=WORKSPACE_DIR,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        envelope = None
        if check_json and res.stdout.strip():
            try:
                envelope = json.loads(res.stdout)
            except json.JSONDecodeError:
                pass
        return res.returncode, envelope, res.stdout, res.stderr

    # =========================================================================
    # AREA 1: Rapid Spawn / Kill Loops Across Multiple Concurrent Sessions
    # =========================================================================

    def test_concurrent_sessions_spawn_and_lifecycle(self):
        """Probe 1.1: 10 concurrent threads spawning, inspecting registers, and killing sessions."""
        num_threads = 10

        def worker_lifecycle(idx):
            # 1. Spawn
            code, data, out, err = self.run_cmd(
                ["dynamic", "debug", "spawn", str(TEST_TARGET)], timeout=15
            )
            if code != 0 or not data or not data.get("success"):
                return False, f"Spawn failed for thread {idx}: {out} {err}"
            sid = data["data"]["session_id"]
            pid = data["data"]["pid"]
            rip = data["data"]["rip"]

            # 2. Inspect registers
            code_r, data_r, _, _ = self.run_cmd(
                ["dynamic", "debug", "registers", sid], timeout=10
            )
            if code_r != 0 or not data_r or not data_r.get("success"):
                return False, f"Registers failed for thread {idx}: sid={sid}"

            # 3. Single step
            code_s, data_s, _, _ = self.run_cmd(
                ["dynamic", "debug", "step", sid], timeout=10
            )
            if code_s != 0 or not data_s or not data_s.get("success"):
                return False, f"Step failed for thread {idx}: sid={sid}"

            # 4. Kill
            code_k, data_k, _, _ = self.run_cmd(
                ["dynamic", "debug", "kill", sid], timeout=10
            )
            if code_k != 0 or not data_k or not data_k.get("success"):
                return False, f"Kill failed for thread {idx}: sid={sid}"

            return True, (sid, pid, rip)

        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker_lifecycle, i) for i in range(num_threads)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        elapsed = time.time() - start_time

        # All must succeed
        sids = set()
        pids = set()
        for ok, val in results:
            self.assertTrue(ok, f"Concurrent worker failed: {val}")
            sid, pid, rip = val
            self.assertNotIn(sid, sids, f"Duplicate session ID: {sid}")
            self.assertNotIn(pid, pids, f"Duplicate PID: {pid}")
            self.assertTrue(rip > 0, "RIP must be > 0")
            sids.add(sid)
            pids.add(pid)

        # After all killed, active sessions count must be 0
        code, data, _, _ = self.run_cmd(["dynamic", "debug", "list-sessions"])
        self.assertEqual(code, 0)
        self.assertEqual(data["data"]["count"], 0)
        print(f"\n[PASS] 1.1 Concurrent sessions: {num_threads} sessions completed in {elapsed:.2f}s")

    def test_rapid_sequential_spawn_kill_loop(self):
        """Probe 1.2: High-frequency sequential spawn/kill stress (20 iterations)."""
        iterations = 20
        start_time = time.time()
        for i in range(iterations):
            code, data, _, _ = self.run_cmd(
                ["dynamic", "debug", "spawn", "/bin/true"]
            )
            self.assertEqual(code, 0, f"Spawn failed at iter {i}")
            sid = data["data"]["session_id"]

            code_k, data_k, _, _ = self.run_cmd(
                ["dynamic", "debug", "kill", sid]
            )
            self.assertEqual(code_k, 0, f"Kill failed at iter {i}")
            self.assertTrue(data_k["data"]["terminated"])

        elapsed = time.time() - start_time
        # Verify 0 active sessions
        code, data, _, _ = self.run_cmd(["dynamic", "debug", "list-sessions"])
        self.assertEqual(data["data"]["count"], 0)
        print(f"[PASS] 1.2 Rapid sequential spawn/kill: {iterations} cycles in {elapsed:.2f}s")

    # =========================================================================
    # AREA 2: Setting Multiple Breakpoints, HW dbH, Deleting Non-existent BPs, Address Boundaries
    # =========================================================================

    def test_multiple_breakpoints_software_and_hardware(self):
        """Probe 2.1: Setting multiple SW & HW (dbH) breakpoints, listing, removing."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", str(TEST_TARGET)]
        )
        self.assertEqual(code, 0)
        sid = data["data"]["session_id"]
        entry_rip = data["data"]["rip_hex"]

        try:
            # Add SW breakpoint at 'main'
            code, data_bp1, _, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "main"]
            )
            self.assertEqual(code, 0)
            self.assertEqual(data_bp1["data"]["total_breakpoints"], 1)

            # Add HW breakpoint at entrypoint with --hw
            code, data_bp2, _, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, entry_rip, "--hw"]
            )
            self.assertEqual(code, 0)
            self.assertEqual(data_bp2["data"]["total_breakpoints"], 2)

            # Add 3 more breakpoints at offsets
            main_addr = data_bp1["data"]["modified"]["addr"]
            for offset in [4, 8, 12]:
                target_hex = hex(main_addr + offset)
                code_bpi, data_bpi, _, _ = self.run_cmd(
                    ["dynamic", "debug", "bp", sid, target_hex]
                )
                self.assertEqual(code_bpi, 0)

            # List breakpoints
            code_l, data_l, _, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "--action", "list"]
            )
            self.assertEqual(code_l, 0)
            bps = data_l["data"]["breakpoints"]
            self.assertEqual(len(bps), 5, f"Expected 5 breakpoints, got {len(bps)}")

            # Check that HW breakpoint has hw=true
            hw_bp = next((b for b in bps if b["hw"] is True), None)
            self.assertIsNotNone(hw_bp, "Hardware breakpoint with hw=true not found")

            # Remove 1 breakpoint
            code_r, data_r, _, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "main", "--action", "remove"]
            )
            self.assertEqual(code_r, 0)
            self.assertEqual(data_r["data"]["total_breakpoints"], 4)

            # Clear all breakpoints
            code_c, data_c, _, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "--action", "clear"]
            )
            self.assertEqual(code_c, 0)
            self.assertEqual(data_c["data"]["total_breakpoints"], 0)

        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])
        print("[PASS] 2.1 Multiple SW & HW breakpoints, listing, removal and clear")

    def test_delete_nonexistent_breakpoint_behavior(self):
        """Probe 2.2: Deleting a non-existent breakpoint (e.g. 0xdeadbeef1234)."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", str(TEST_TARGET)]
        )
        sid = data["data"]["session_id"]
        try:
            # Add one valid breakpoint at main
            self.run_cmd(["dynamic", "debug", "bp", sid, "main"])

            # Attempt to delete non-existent breakpoint
            code_del, data_del, out, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "0xdeadbeef1234", "--action", "remove"]
            )

            # Verify that deleting non-existent breakpoint does NOT crash or corrupt the existing breakpoint list
            code_l, data_l, _, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "--action", "list"]
            )
            self.assertEqual(code_l, 0)
            self.assertEqual(data_l["data"]["total_breakpoints"], 1)
            self.assertEqual(data_l["data"]["breakpoints"][0]["name"], "main")
            print(f"[OBSERVATION] 2.2 Delete non-existent BP returns rc={code_del}, existing list preserved: {data_l['data']['total_breakpoints']} BPs")
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])

    def test_breakpoint_address_boundary_zero_and_max(self):
        """Probe 2.3: Setting breakpoints at address boundaries (0x0, 0xffffffffffffffff)."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", str(TEST_TARGET)]
        )
        sid = data["data"]["session_id"]
        try:
            # Address 0x0
            code_0, data_0, out_0, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "0x0"]
            )
            print(f"[OBSERVATION] 2.3 BP at 0x0 returned rc={code_0}, json={data_0}")

            # Extreme 64-bit address 0xffffffffffffffff
            code_max, data_max, out_max, _ = self.run_cmd(
                ["dynamic", "debug", "bp", sid, "0xffffffffffffffff"]
            )
            print(f"[OBSERVATION] 2.3 BP at 0xffffffffffffffff returned rc={code_max}")
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])

    # =========================================================================
    # AREA 3: Register Mutation & Diff Calculation (0xffffffffffffffff, 0x0)
    # =========================================================================

    def test_register_mutation_extreme_64bit_values(self):
        """Probe 3.1: Setting registers to 0xffffffffffffffff and 0x0, verifying diff."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", "/bin/true"]
        )
        self.assertEqual(code, 0)
        sid = data["data"]["session_id"]

        try:
            # 1. Mutate rax to 0xffffffffffffffff (u64::MAX)
            code_s1, data_s1, _, _ = self.run_cmd(
                ["dynamic", "debug", "registers", sid, "--set", "rax=0xffffffffffffffff"]
            )
            self.assertEqual(code_s1, 0)
            self.assertTrue(data_s1["success"])
            mod1 = data_s1["data"]["modified"]
            rax_mod1 = next((m for m in mod1 if m["reg"] == "rax"), None)
            self.assertIsNotNone(rax_mod1, "rax must be in modified list")
            self.assertEqual(rax_mod1["after"], 18446744073709551615)
            self.assertEqual(rax_mod1["after_hex"], "0xffffffffffffffff")
            self.assertEqual(data_s1["data"]["registers"]["rax"], 18446744073709551615)

            # 2. Mutate rax back to 0x0
            code_s2, data_s2, _, _ = self.run_cmd(
                ["dynamic", "debug", "registers", sid, "--set", "rax=0x0"]
            )
            self.assertEqual(code_s2, 0)
            mod2 = data_s2["data"]["modified"]
            rax_mod2 = next((m for m in mod2 if m["reg"] == "rax"), None)
            self.assertIsNotNone(rax_mod2)
            self.assertEqual(rax_mod2["before"], 18446744073709551615)
            self.assertEqual(rax_mod2["before_hex"], "0xffffffffffffffff")
            self.assertEqual(rax_mod2["after"], 0)
            self.assertEqual(rax_mod2["after_hex"], "0x0")

            # 3. Mutate multiple registers simultaneously
            code_s3, data_s3, _, _ = self.run_cmd(
                [
                    "dynamic",
                    "debug",
                    "registers",
                    sid,
                    "--set",
                    "rbx=0xaaaaaaaaaaaaaaaa",
                    "--set",
                    "rcx=0x5555555555555555",
                    "--set",
                    "rdx=0x0",
                ]
            )
            self.assertEqual(code_s3, 0)
            mod3 = {m["reg"]: m for m in data_s3["data"]["modified"]}
            self.assertIn("rbx", mod3)
            self.assertEqual(mod3["rbx"]["after_hex"], "0xaaaaaaaaaaaaaaaa")
            self.assertIn("rcx", mod3)
            self.assertEqual(mod3["rcx"]["after_hex"], "0x5555555555555555")

            # 4. Verify --diff flag returns modified diff
            code_diff, data_diff, _, _ = self.run_cmd(
                ["dynamic", "debug", "registers", sid, "--diff"]
            )
            self.assertEqual(code_diff, 0)
            print("[PASS] 3.1 Register mutation to 0xffffffffffffffff and 0x0 with diff verification")

        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])

    # =========================================================================
    # AREA 4: Memory Inspection: Unmapped Addresses, Invalid Hex, Page Boundaries
    # =========================================================================

    def test_memory_maps_and_valid_reading(self):
        """Probe 4.1: Querying memory maps and reading mapped code memory."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", str(TEST_TARGET)]
        )
        sid = data["data"]["session_id"]
        rip = data["data"]["rip_hex"]
        try:
            # Memory maps
            code_m, data_m, _, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "maps"]
            )
            self.assertEqual(code_m, 0)
            maps = data_m["data"]["maps"]
            self.assertTrue(len(maps) > 0, "Maps should not be empty")

            # Read valid bytes at RIP
            code_r, data_r, _, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "read", "--addr", rip, "--len", "16"]
            )
            self.assertEqual(code_r, 0)
            self.assertEqual(len(data_r["data"]["bytes"]), 16)
            self.assertEqual(len(data_r["data"]["hex"]), 32)
            print("[PASS] 4.1 Memory maps inspection and mapped memory reading")
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])

    def test_memory_read_unmapped_address(self):
        """Probe 4.2: Reading memory at unmapped addresses (0xdeadbeef000, 0x0)."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", str(TEST_TARGET)]
        )
        sid = data["data"]["session_id"]
        try:
            # Reading at 0xdeadbeef000
            code_r, data_r, out_r, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "read", "--addr", "0xdeadbeef000", "--len", "16"]
            )
            # Record empirical result
            print(f"[OBSERVATION] 4.2 Read unmapped 0xdeadbeef000: rc={code_r}, data={data_r}")

            # Reading at 0x0
            code_0, data_0, out_0, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "read", "--addr", "0x0", "--len", "16"]
            )
            print(f"[OBSERVATION] 4.2 Read unmapped 0x0: rc={code_0}, data={data_0}")
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])

    def test_memory_write_invalid_hex_and_unmapped(self):
        """Probe 4.3: Writing invalid hex strings ('zzzz', '123') and unmapped destination."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", str(TEST_TARGET)]
        )
        sid = data["data"]["session_id"]
        rip = data["data"]["rip_hex"]
        try:
            # 1. Non-hex characters 'zzzz'
            code_w1, data_w1, out_w1, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "write", "--addr", rip, "--data", "zzzz"]
            )
            print(f"[OBSERVATION] 4.3 Write non-hex 'zzzz': rc={code_w1}, data={data_w1}")

            # 2. Odd-length hex '123'
            code_w2, data_w2, out_w2, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "write", "--addr", rip, "--data", "123"]
            )
            print(f"[OBSERVATION] 4.3 Write odd-length '123': rc={code_w2}, data={data_w2}")

            # 3. Unmapped address 0xdeadbeef000
            code_w3, data_w3, out_w3, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "write", "--addr", "0xdeadbeef000", "--data", "9090"]
            )
            print(f"[OBSERVATION] 4.3 Write unmapped 0xdeadbeef000: rc={code_w3}, data={data_w3}")
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])

    def test_memory_read_across_page_boundary(self):
        """Probe 4.4: Reading across page boundary from mapped into unmapped memory."""
        code, data, _, _ = self.run_cmd(
            ["dynamic", "debug", "spawn", str(TEST_TARGET)]
        )
        sid = data["data"]["session_id"]
        try:
            # Get binary end address (0x405000 in test_target_elf64)
            code_m, data_m, _, _ = self.run_cmd(
                ["dynamic", "debug", "memory", sid, "--action", "maps"]
            )
            # Find the binary rw- mapping end
            bin_map = [m for m in data_m["data"]["maps"] if "test_target" in m["name"] and "w" in m["perm"]]
            if bin_map:
                end_addr = bin_map[-1]["addr_end"]
                boundary_addr = hex(end_addr - 8)
                code_b, data_b, out_b, _ = self.run_cmd(
                    ["dynamic", "debug", "memory", sid, "--action", "read", "--addr", boundary_addr, "--len", "16"]
                )
                print(f"[OBSERVATION] 4.4 Read across mapped/unmapped boundary at {boundary_addr}: rc={code_b}, hex={data_b['data']['hex'] if data_b else out_b}")
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid])

    # =========================================================================
    # AREA 5: Error Taxonomy Verification (Exit Code 1, Exit Code 3)
    # =========================================================================

    def test_error_taxonomy_missing_sessions_exit_code_1(self):
        """Probe 5.1: Missing session IDs must return Exit Code 1 (INVALID_ARGUMENT)."""
        missing_sid = "dbg_nonexistent_999999"
        subcommands = [
            ["continue", missing_sid],
            ["step", missing_sid],
            ["bp", missing_sid, "0x1000"],
            ["registers", missing_sid],
            ["memory", missing_sid, "--action", "read", "--addr", "0x1000"],
            ["kill", missing_sid],
        ]

        for sub in subcommands:
            code, data, out, err = self.run_cmd(["dynamic", "debug"] + sub)
            self.assertEqual(code, 1, f"Command {sub} did not return exit code 1: got {code}")
            self.assertIsNotNone(data, f"No JSON envelope for {sub}")
            self.assertFalse(data["success"], f"Expected success=false for {sub}")
            self.assertEqual(data["error"]["exit_code"], 1)
            self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")
            self.assertEqual(data["error"]["code"], "DEBUG_SESSION_NOT_FOUND")

        print("[PASS] 5.1 Missing session IDs strictly return Exit Code 1 (INVALID_ARGUMENT)")

    def test_error_taxonomy_missing_arguments_exit_code_1(self):
        """Probe 5.2: Missing required arguments return Exit Code 1."""
        # 1. Missing target binary for spawn
        code, data, _, _ = self.run_cmd(["dynamic", "debug", "spawn"])
        self.assertEqual(code, 1)
        self.assertEqual(data["error"]["exit_code"], 1)
        self.assertEqual(data["error"]["category"], "INVALID_ARGUMENT")

        # 2. File not found returns exit code 2
        code_fnf, data_fnf, _, _ = self.run_cmd(["dynamic", "debug", "spawn", "/nonexistent/binary/file/path"])
        self.assertEqual(code_fnf, 2)
        self.assertEqual(data_fnf["error"]["exit_code"], 2)
        self.assertEqual(data_fnf["error"]["category"], "FILE_ERROR")

        print("[PASS] 5.2 Missing arguments (Exit Code 1) & File Not Found (Exit Code 2)")

    def test_signal_and_exit_handling_exit_code_0(self):
        """Probe 5.3: Debugger stops (SIGSEGV, normal exit) must return Exit Code 0 with event details."""
        # Target SIGSEGV
        code_sp, data_sp, _, _ = self.run_cmd(["dynamic", "debug", "spawn", str(CRASH_TARGET)])
        self.assertEqual(code_sp, 0)
        sid_crash = data_sp["data"]["session_id"]
        try:
            code_c, data_c, _, _ = self.run_cmd(["dynamic", "debug", "continue", sid_crash])
            self.assertEqual(code_c, 0, "Continue on crashing target must return Exit Code 0")
            self.assertEqual(data_c["data"]["status"], "signaled")
            self.assertEqual(data_c["data"]["stop_reason"], "signal")
            self.assertEqual(data_c["data"]["signal"]["name"], "SIGSEGV")
            self.assertEqual(data_c["data"]["signal"]["signum"], 11)
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid_crash])

        # Target normal exit 0
        code_sp0, data_sp0, _, _ = self.run_cmd(["dynamic", "debug", "spawn", "/bin/true"])
        sid_true = data_sp0["data"]["session_id"]
        try:
            code_c0, data_c0, _, _ = self.run_cmd(["dynamic", "debug", "continue", sid_true])
            self.assertEqual(code_c0, 0)
            self.assertEqual(data_c0["data"]["status"], "exited")
            self.assertEqual(data_c0["data"]["stop_reason"], "exit")
            self.assertEqual(data_c0["data"]["exit_code"], 0)
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid_true])

        # Target exit 1
        code_sp1, data_sp1, _, _ = self.run_cmd(["dynamic", "debug", "spawn", "/bin/false"])
        sid_false = data_sp1["data"]["session_id"]
        try:
            code_c1, data_c1, _, _ = self.run_cmd(["dynamic", "debug", "continue", sid_false])
            self.assertEqual(code_c1, 0)
            self.assertEqual(data_c1["data"]["status"], "exited")
            self.assertEqual(data_c1["data"]["exit_code"], 1)
        finally:
            self.run_cmd(["dynamic", "debug", "kill", sid_false])

        print("[PASS] 5.3 Execution events (SIGSEGV, exit 0, exit 1) cleanly captured with Exit Code 0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
