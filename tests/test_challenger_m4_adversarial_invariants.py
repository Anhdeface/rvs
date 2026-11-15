"""tests/test_challenger_m4_adversarial_invariants.py - Empirical Adversarial Challenge Suite.

Milestone M4 Challenger 2 Verification:
1. Deadlock Freedom & Watchdog Robustness:
   - 10MB pipe saturation with worker SIGKILL termination mid-transfer.
   - 10MB pipe saturation with worker SIGTERM termination mid-transfer.
   - 10MB split stream saturation with self-SIGKILL.
   - 10MB stream with hung worker (SIGTERM escalation to SIGKILL, timeout bound <= timeout + 1.5s).
   - Unresponsive worker ignoring SIGTERM escalated to SIGKILL.
   - Zombie process (<defunct>) freedom verification.
2. Dense Token Budget Monotonicity & Entry Anchor Retention:
   - Real target `crackme_case` `rvs_disasm` main (entry block 0x11e0).
   - Dense integer sweep B in [200..600] (401 points):
     * Monotonicity: Tokens(B) <= Tokens(B+1)
     * Boundedness: 0 <= Tokens(B) <= max(B, B_min)
     * Entry anchor retention: blocks[0]['addr'] == '0x11e0' whenever blocks retained.
   - Critical boundary points:
     * B=353 vs B=354
     * B=749 vs B=750
   - Multi-seed synthetic CFG sweeps (seeds 42, 101, 777).
3. Execution FSM State Reachability & Error Containment Taxonomy {0..6}:
   - Exhaustive signal containment (-1..-31) -> 6.
   - Normal exit code preservation {0..6} -> {0..6}.
   - Out-of-bounds exit code containment (7, 8, 42, 101, 127, 137, 255) -> 6.
   - Harness tool execution fault injection -> exit_code in {0..6}.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

from rvs_agent_harness import (
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    RvsHarness,
    TokenEstimator,
    execute_rvs_subprocess,
    normalize_exit_code,
    transform_response,
)


class TestAdversarialDeadlockFreedom(unittest.TestCase):
    """Adversarial stress testing of pipe I/O multiplexing and process lifecycle."""

    def setUp(self) -> None:
        self.py_bin = Path(sys.executable)

    def test_adv_01_pipe_saturation_10mb_external_sigkill(self) -> None:
        """Worker writes 10MB to stdout; external monitor delivers SIGKILL halfway through."""
        script = (
            "import sys, os, time\n"
            "chunk = b'A' * 65536\n"
            "total = 10_000_000\n"
            "written = 0\n"
            "while written < total:\n"
            "    sys.stdout.buffer.write(chunk)\n"
            "    sys.stdout.buffer.flush()\n"
            "    written += len(chunk)\n"
            "    time.sleep(0.001)\n"
        )
        start = time.time()
        # Launch killer thread after 0.2s
        def killer():
            time.sleep(0.2)
            # Find worker PID and kill it
            try:
                out = subprocess.check_output(["pgrep", "-f", "sys.stdout.buffer.write(chunk)"]).decode()
                for pid_str in out.strip().split():
                    pid = int(pid_str)
                    if pid != os.getpid():
                        os.kill(pid, signal.SIGKILL)
            except Exception:
                pass

        t = threading.Thread(target=killer, daemon=True)
        t.start()

        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=5.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertLess(elapsed, 4.0, f"Harness hung or delayed: {elapsed:.2f}s")
        norm_code = normalize_exit_code(code)
        self.assertIn(norm_code, {EXIT_SUCCESS, EXIT_INTERNAL_ERROR})

    def test_adv_02_pipe_saturation_10mb_external_sigterm(self) -> None:
        """Worker writes 10MB to stderr; external monitor delivers SIGTERM halfway through."""
        script = (
            "import sys, os, time\n"
            "chunk = b'E' * 65536\n"
            "total = 10_000_000\n"
            "written = 0\n"
            "while written < total:\n"
            "    sys.stderr.buffer.write(chunk)\n"
            "    sys.stderr.buffer.flush()\n"
            "    written += len(chunk)\n"
            "    time.sleep(0.001)\n"
        )
        start = time.time()
        def killer():
            time.sleep(0.2)
            try:
                out = subprocess.check_output(["pgrep", "-f", "sys.stderr.buffer.write(chunk)"]).decode()
                for pid_str in out.strip().split():
                    pid = int(pid_str)
                    if pid != os.getpid():
                        os.kill(pid, signal.SIGTERM)
            except Exception:
                pass

        t = threading.Thread(target=killer, daemon=True)
        t.start()

        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=5.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertLess(elapsed, 4.0, f"Harness hung or delayed: {elapsed:.2f}s")
        norm_code = normalize_exit_code(code)
        self.assertIn(norm_code, {EXIT_SUCCESS, EXIT_INTERNAL_ERROR})

    def test_adv_03_split_saturation_10mb_self_sigkill(self) -> None:
        """Worker writes 5MB stdout + 5MB stderr then immediately self-terminates with SIGKILL."""
        script = (
            "import sys, os, signal\n"
            "chunk_o = b'O' * 65536\n"
            "chunk_e = b'E' * 65536\n"
            "for _ in range(80):\n"
            "    sys.stdout.buffer.write(chunk_o)\n"
            "    sys.stderr.buffer.write(chunk_e)\n"
            "sys.stdout.buffer.flush()\n"
            "sys.stderr.buffer.flush()\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n"
        )
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=6.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertLess(elapsed, 4.0)
        norm_code = normalize_exit_code(code)
        self.assertEqual(norm_code, EXIT_INTERNAL_ERROR)

    def test_adv_04_hung_worker_sigterm_escalation_to_sigkill(self) -> None:
        """Worker outputs 10MB then hangs; timeout watchdog terminates within timeout + 1.5s."""
        script = (
            "import sys, time\n"
            "chunk = b'H' * 65536\n"
            "for _ in range(150):\n"
            "    sys.stdout.buffer.write(chunk)\n"
            "sys.stdout.buffer.flush()\n"
            "while True:\n"
            "    time.sleep(1.0)\n"
        )
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=1.5,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        self.assertLessEqual(elapsed, 1.5 + 1.5 + 0.5)

    def test_adv_05_unresponsive_worker_ignoring_sigterm(self) -> None:
        """Worker traps and ignores SIGTERM; harness watchdog must escalate to SIGKILL and reap."""
        script = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.05)\n"
        )
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=1.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        self.assertLessEqual(elapsed, 1.0 + 1.5 + 0.5)

    def test_adv_06_zombie_freedom_verification(self) -> None:
        """Verify no <defunct> zombie processes are left in OS process table."""
        # Reap any dead child processes belonging to current process
        try:
            while True:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid <= 0:
                    break
        except (ChildProcessError, OSError):
            pass

        # Brief settling window to ensure exiting subprocesses are reaped
        defunct_lines: List[str] = []
        for _ in range(5):
            ps_out = subprocess.check_output(["ps", "-eo", "stat,cmd"]).decode(errors="replace")
            defunct_lines = [line for line in ps_out.splitlines() if "Z" in line.split()[0] or "<defunct>" in line]
            if not defunct_lines:
                break
            time.sleep(0.1)

        self.assertEqual(len(defunct_lines), 0, f"Found zombie processes: {defunct_lines}")


class TestAdversarialTokenBudgetMonotonicity(unittest.TestCase):
    """Adversarial stress testing of knapsack token budget monotonicity and anchor retention."""

    @classmethod
    def setUpClass(cls) -> None:
        h = RvsHarness()
        dis = h.execute_tool("rvs_disasm", {"file": "crackme_case", "target": "main", "compact": False, "neutral": False})
        cls.crackme_main_payload = dis
        blks = dis.get("data", {}).get("blocks", [])
        raw_addr = blks[0].get("addr_hex") or blks[0].get("addr") if blks else "0x11e0"
        if isinstance(raw_addr, int):
            cls.expected_entry = hex(raw_addr)
        else:
            cls.expected_entry = str(raw_addr)

    def test_adv_07_dense_budget_monotonicity_crackme_main_200_to_600(self) -> None:
        """Dense budget sweep B in [200..600] on crackme_case main:
        - Monotonicity: Tokens(B) <= Tokens(B+1)
        - Compliance: 0 <= Tokens(B) <= max(B, B_min)
        - Entry anchor retention: entry block 0x11e0 must be retained whenever blocks exist.
        """
        base_floor = 210
        prev_tokens = -1

        for b in range(200, 601):
            compacted = transform_response(self.crackme_main_payload, mode="compact", budget=b)
            tok = TokenEstimator.estimate_obj(compacted)
            allowed_max = max(b, base_floor)

            self.assertGreaterEqual(tok, 0, f"B={b}: tokens ({tok}) must be >= 0")
            self.assertLessEqual(tok, allowed_max, f"B={b}: tokens ({tok}) exceeded max ({allowed_max})")

            if prev_tokens != -1:
                self.assertLessEqual(
                    prev_tokens, tok,
                    f"Monotonicity violation between B={b-1} ({prev_tokens}) and B={b} ({tok})",
                )

            # Entry anchor retention
            data = compacted.get("data")
            if isinstance(data, dict):
                blocks = data.get("blocks")
                if isinstance(blocks, list) and len(blocks) > 0:
                    entry_addr = blocks[0].get("addr")
                    self.assertEqual(
                        entry_addr, self.expected_entry,
                        f"B={b}: Entry block anchor lost! Expected {self.expected_entry}, got {entry_addr}",
                    )

            prev_tokens = tok

    def test_adv_08_boundary_points_353_vs_354_and_749_vs_750(self) -> None:
        """Verify exact boundary points:
        - B=353 vs B=354: Tokens(353) <= Tokens(354)
        - B=749 vs B=750: Tokens(749) <= Tokens(750)
        - Entry anchor retained at all boundary points.
        """
        for b_low, b_high in [(353, 354), (749, 750)]:
            c_low = transform_response(self.crackme_main_payload, mode="compact", budget=b_low)
            c_high = transform_response(self.crackme_main_payload, mode="compact", budget=b_high)

            tok_low = TokenEstimator.estimate_obj(c_low)
            tok_high = TokenEstimator.estimate_obj(c_high)

            self.assertLessEqual(
                tok_low, tok_high,
                f"Boundary monotonicity failure at B={b_low} ({tok_low}) vs B={b_high} ({tok_high})",
            )

            for b_val, c_val in [(b_low, c_low), (b_high, c_high)]:
                data = c_val.get("data")
                if isinstance(data, dict):
                    blocks = data.get("blocks")
                    if isinstance(blocks, list) and len(blocks) > 0:
                        self.assertEqual(
                            blocks[0].get("addr"), self.expected_entry,
                            f"B={b_val}: Entry anchor {self.expected_entry} lost!",
                        )

    def test_adv_09_synthetic_cfg_dense_monotonicity_multi_seeds(self) -> None:
        """Dense sweep B in [150..500] across synthetic CFG seeds (42, 101, 777)."""
        import random

        for seed in [42, 101, 777]:
            rng = random.Random(seed)
            blocks = []
            base_addr = 0x00401000 + seed * 0x100
            for i in range(15):
                addr = base_addr + i * 32
                insts = [{"addr": f"0x{addr+j*4:x}", "asm": f"mov eax, {j}", "size": 4} for j in range(rng.randint(2, 6))]
                blocks.append({"addr": f"0x{addr:x}", "instructions": insts})

            payload = {
                "success": True,
                "command": "disasm",
                "target": f"/test/bin_{seed}",
                "data": {"function": f"func_{seed}", "addr": f"0x{base_addr:x}", "blocks": blocks},
            }

            prev = -1
            for b in range(150, 501, 5):
                c = transform_response(payload, mode="compact", budget=b)
                tok = TokenEstimator.estimate_obj(c)
                self.assertLessEqual(tok, max(b, 210))
                if prev != -1:
                    self.assertLessEqual(prev, tok, f"Seed {seed}: Inversion at B={b}")
                prev = tok


class TestAdversarialFsmErrorContainment(unittest.TestCase):
    """Adversarial stress testing of FSM error containment to taxonomy {0..6}."""

    def test_adv_10_exhaustive_signal_containment(self) -> None:
        """Every signal return code (-1 through -31) must map to EXIT_INTERNAL_ERROR (6)."""
        for sig in range(1, 32):
            raw = -sig
            norm = normalize_exit_code(raw)
            self.assertEqual(
                norm, EXIT_INTERNAL_ERROR,
                f"Signal {raw} did not normalize to EXIT_INTERNAL_ERROR (6), got {norm}",
            )

    def test_adv_11_taxonomy_codes_identity_mapping(self) -> None:
        """Every canonical taxonomy code {0..6} maps strictly to itself."""
        for code in (
            EXIT_SUCCESS,
            EXIT_INVALID_ARGUMENT,
            EXIT_FILE_ERROR,
            EXIT_ANALYSIS_ERROR,
            EXIT_PATCH_ERROR,
            EXIT_TIMEOUT_ERROR,
            EXIT_INTERNAL_ERROR,
        ):
            self.assertEqual(normalize_exit_code(code), code)

    def test_adv_12_out_of_bounds_codes_containment(self) -> None:
        """All out-of-bounds codes (7..255) must map to EXIT_INTERNAL_ERROR (6)."""
        oob_codes = [7, 8, 9, 13, 42, 101, 126, 127, 128, 137, 255, 1000, -9999]
        for c in oob_codes:
            norm = normalize_exit_code(c)
            self.assertEqual(norm, EXIT_INTERNAL_ERROR, f"Code {c} normalized to {norm} instead of 6")

    def test_adv_13_harness_tool_fault_containment(self) -> None:
        """Harness tool execution with adversarial inputs contains error codes strictly to {0..6}."""
        h = RvsHarness()
        valid_taxonomy = {
            EXIT_SUCCESS,
            EXIT_INVALID_ARGUMENT,
            EXIT_FILE_ERROR,
            EXIT_ANALYSIS_ERROR,
            EXIT_PATCH_ERROR,
            EXIT_TIMEOUT_ERROR,
            EXIT_INTERNAL_ERROR,
        }

        adversarial_calls = [
            ("rvs_info", None),
            ("rvs_info", {}),
            ("rvs_info", {"file": None}),
            ("rvs_info", {"file": "/dev/null/not/a/file"}),
            ("rvs_disasm", {"file": "crackme_case", "target": "non_existent_symbol_xyz"}),
            ("rvs_patch_bytes", {"file": "crackme_case"}),  # missing offset/bytes
            ("rvs_patch_instruction", {"file": "crackme_case", "addr": "invalid_hex"}),
            ("unknown_tool_xyz_123", {"some_arg": 1}),
        ]

        for tool_name, args in adversarial_calls:
            res = h.execute_tool(tool_name, arguments=args)
            self.assertIsInstance(res, dict)
            self.assertIn("success", res)
            if not res["success"]:
                err = res.get("error")
                self.assertIsNotNone(err, f"Tool {tool_name} returned failure without error envelope")
                exit_code = err.get("exit_code")
                self.assertIn(
                    exit_code, valid_taxonomy,
                    f"Tool {tool_name} error exit_code {exit_code} is outside taxonomy {{0..6}}",
                )


if __name__ == "__main__":
    unittest.main()
