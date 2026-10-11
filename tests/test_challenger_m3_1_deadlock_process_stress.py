"""tests/test_challenger_m3_1_deadlock_process_stress.py - Empirical Adversarial Challenge Suite

Authored by Challenger 1 (Milestone M3: Mathematical & Invariant Verification Suite).
Focus: Deadlock Freedom & Process Group Stress Adversarial Testing.

Empirical verification of:
1. Saturated stdout and stderr streams (>=10MB continuous generation, up to 20MB simultaneous bistreams).
2. Adversarial subprocesses that ignore SIGTERM, spawn grandchildren, and attempt to hang pipes.
3. Bounded termination time invariant: T <= Timeout + 1.5s under SIGKILL escalation.
4. Zero zombie (<defunct>) processes leaked across multiple rapid iterations and crashes.
5. Concurrent multithreaded saturated pipe calls and strict cross-thread process group isolation.
6. File descriptor leak freedom under heavy pipe churn.
7. Boundary timeouts (zero, negative, sub-millisecond).
"""

import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Any, List, Optional, Tuple

from rvs_agent_harness import (
    EXIT_INTERNAL_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    _ACTIVE_SUBPROCESS_PGIDS,
    execute_rvs_subprocess,
    normalize_exit_code,
)


def _get_zombies_for_pid(parent_pid: int) -> List[str]:
    """Helper to detect zombie (<defunct>) processes in the OS process table for parent_pid."""
    try:
        ps_res = subprocess.run(
            ["ps", "-o", "stat,ppid,pid", "-A"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return []

    parent_str = str(parent_pid)
    zombies = []
    for line in ps_res.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            stat, ppid = parts[0], parts[1]
            if ppid == parent_str and "Z" in stat:
                zombies.append(line)
    return zombies


class TestChallengerM3DeadlockProcessStress(unittest.TestCase):
    """Adversarial stress and empirical challenge suite for process lifecycle and pipe I/O."""

    def setUp(self) -> None:
        self.py_bin = Path(sys.executable)
        self.my_pid = os.getpid()

    def test_01_saturated_stdout_continuous_15mb(self) -> None:
        """Stress: 15MB continuous stdout stream exceeds 64KB pipe buffer by >230x."""
        payload_size = 15_000_000
        script = (
            "import sys\n"
            "chunk = 'A' * 65536\n"
            f"total = {payload_size}\n"
            "written = 0\n"
            "while written < total:\n"
            "    to_write = min(len(chunk), total - written)\n"
            "    sys.stdout.write(chunk[:to_write])\n"
            "    written += to_write\n"
            "sys.stdout.flush()\n"
        )
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=10.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), payload_size)
        self.assertEqual(stderr, "")
        self.assertLess(elapsed, 8.0, f"Draining 15MB took too long: {elapsed:.2f}s")

    def test_02_saturated_stderr_continuous_15mb(self) -> None:
        """Stress: 15MB continuous stderr stream exceeds 64KB pipe buffer without pipe stalls."""
        payload_size = 15_000_000
        script = (
            "import sys\n"
            "chunk = 'E' * 65536\n"
            f"total = {payload_size}\n"
            "written = 0\n"
            "while written < total:\n"
            "    to_write = min(len(chunk), total - written)\n"
            "    sys.stderr.write(chunk[:to_write])\n"
            "    written += to_write\n"
            "sys.stderr.flush()\n"
        )
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=10.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(stdout, "")
        self.assertEqual(len(stderr), payload_size)
        self.assertLess(elapsed, 8.0, f"Draining 15MB stderr took too long: {elapsed:.2f}s")

    def test_03_simultaneous_saturated_bistream_20mb(self) -> None:
        """Stress: 10MB stdout + 10MB stderr concurrently produced from separate threads in child."""
        script = (
            "import sys, threading\n"
            "def run_out():\n"
            "    c = 'O' * 65536\n"
            "    w = 0\n"
            "    while w < 10_000_000:\n"
            "        sys.stdout.write(c[:min(len(c), 10_000_000 - w)])\n"
            "        w += len(c)\n"
            "    sys.stdout.flush()\n"
            "def run_err():\n"
            "    c = 'E' * 65536\n"
            "    w = 0\n"
            "    while w < 10_000_000:\n"
            "        sys.stderr.write(c[:min(len(c), 10_000_000 - w)])\n"
            "        w += len(c)\n"
            "    sys.stderr.flush()\n"
            "t1 = threading.Thread(target=run_out)\n"
            "t2 = threading.Thread(target=run_err)\n"
            "t1.start()\n"
            "t2.start()\n"
            "t1.join()\n"
            "t2.join()\n"
        )
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=15.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), 10_000_000)
        self.assertEqual(len(stderr), 10_000_000)
        self.assertLess(elapsed, 8.0)

    def test_04_adversarial_sigterm_ignoring_cpu_loop(self) -> None:
        """Adversarial: Subprocess masks SIGTERM and loops forever; watchdog must escalate to SIGKILL in T <= Timeout + 1.5s."""
        script = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.01)\n"
        )
        timeout = 0.8
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=timeout,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        self.assertGreaterEqual(elapsed, timeout, "Terminated prematurely before timeout")
        self.assertLess(
            elapsed,
            timeout + 1.5,
            f"Escalation exceeded bounded termination guarantee: {elapsed:.2f}s > {timeout + 1.5}s",
        )

    def test_05_adversarial_sigterm_ignoring_pipe_spam(self) -> None:
        """Adversarial: Subprocess masks SIGTERM AND spams stdout/stderr in a loop; watchdog reaps without pipe deadlock."""
        script = (
            "import signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    try:\n"
            "        sys.stdout.write('X' * 8192)\n"
            "        sys.stdout.flush()\n"
            "        sys.stderr.write('Y' * 8192)\n"
            "        sys.stderr.flush()\n"
            "    except Exception:\n"
            "        pass\n"
            "    time.sleep(0.005)\n"
        )
        timeout = 0.8
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=timeout,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        self.assertLess(
            elapsed,
            timeout + 1.5,
            f"Watchdog pipe drain under spam exceeded bound: {elapsed:.2f}s > {timeout + 1.5}s",
        )
        # Verify that output emitted prior to SIGKILL was safely drained without deadlock
        self.assertGreater(len(stdout), 0)
        self.assertGreater(len(stderr), 0)

    def test_06_adversarial_process_tree_grandchildren_sigterm_ignore(self) -> None:
        """Adversarial: Subprocess forks grandchild tree where all descendants mask SIGTERM; entire group is reaped."""
        script = (
            "import os, sys, time, signal\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "p1 = os.fork()\n"
            "if p1 == 0:\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    p2 = os.fork()\n"
            "    if p2 == 0:\n"
            "        signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "        while True:\n"
            "            time.sleep(0.02)\n"
            "    while True:\n"
            "        time.sleep(0.02)\n"
            "while True:\n"
            "    time.sleep(0.02)\n"
        )
        timeout = 0.6
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=timeout,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        self.assertLess(elapsed, timeout + 1.5)

        time.sleep(0.1)
        # Assert zero zombies leaked from current process
        zombies = _get_zombies_for_pid(self.my_pid)
        self.assertEqual(zombies, [], f"Zombies detected: {zombies}")

    def test_07_parent_early_exit_child_pipe_holder(self) -> None:
        """Adversarial: Parent forks child holding stdout/stderr open, and parent exits immediately with 0."""
        script = (
            "import os, sys, time, signal\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    time.sleep(10)\n"
            "    sys.exit(0)\n"
            "else:\n"
            "    sys.exit(0)\n"
        )
        timeout = 0.8
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=timeout,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        self.assertLess(elapsed, timeout + 1.5)

        time.sleep(0.1)
        zombies = _get_zombies_for_pid(self.my_pid)
        self.assertEqual(zombies, [])

    def test_08_rapid_timeout_zero_zombies(self) -> None:
        """Invariant: 30 rapid successive timeouts leave zero zombie (<defunct>) processes."""
        script = "import time; time.sleep(10)"
        for _ in range(30):
            code, _, _, _ = execute_rvs_subprocess(
                ["-c", script],
                timeout=0.01,
                rvs_bin=self.py_bin,
            )
            self.assertEqual(code, EXIT_TIMEOUT_ERROR)

        time.sleep(0.1)
        zombies = _get_zombies_for_pid(self.my_pid)
        self.assertEqual(zombies, [], f"Detected {len(zombies)} zombie processes: {zombies}")

        with threading.Lock():
            self.assertEqual(len(_ACTIVE_SUBPROCESS_PGIDS), 0)

    def test_09_rapid_sigkill_escalations_zero_zombies(self) -> None:
        """Invariant: Rapid timeouts forcing SIGKILL escalation leave zero zombies."""
        script = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.01)\n"
        )
        for _ in range(12):
            code, _, _, _ = execute_rvs_subprocess(
                ["-c", script],
                timeout=0.01,
                rvs_bin=self.py_bin,
            )
            self.assertEqual(code, EXIT_TIMEOUT_ERROR)

        time.sleep(0.1)
        zombies = _get_zombies_for_pid(self.my_pid)
        self.assertEqual(zombies, [], f"Detected {len(zombies)} zombie processes: {zombies}")
        self.assertEqual(len(_ACTIVE_SUBPROCESS_PGIDS), 0)

    def test_10_concurrent_multithreaded_saturated_calls(self) -> None:
        """Concurrency: 8 threads executing heterogeneous saturated streams and watchdog timeouts simultaneously."""
        results: List[Optional[Tuple[int, int, int]]] = [None] * 8
        errors: List[Optional[Exception]] = [None] * 8

        def worker_task(idx: int) -> None:
            try:
                if idx in (0, 1):
                    # Saturated stdout 4MB
                    s = 'import sys; sys.stdout.write("O" * 4_000_000); sys.stdout.flush()'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=8.0, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                elif idx in (2, 3):
                    # Saturated stderr 4MB
                    s = 'import sys; sys.stderr.write("E" * 4_000_000); sys.stderr.flush()'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=8.0, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                elif idx in (4, 5):
                    # Cross-stream 2MB out + 2MB err
                    s = 'import sys; sys.stdout.write("X" * 2_000_000); sys.stderr.write("Y" * 2_000_000); sys.stdout.flush(); sys.stderr.flush()'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=8.0, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                elif idx == 6:
                    # Timeout with SIGTERM ignore
                    s = 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(10)'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=0.3, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                else:
                    # Sudden SIGSEGV crash
                    s = 'import os, signal; os.kill(os.getpid(), signal.SIGSEGV)'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=5.0, rvs_bin=self.py_bin)
                    results[idx] = (normalize_exit_code(c), len(out), len(err))
            except Exception as e:
                errors[idx] = e

        threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(8)]
        start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)
        elapsed = time.perf_counter() - start

        self.assertLess(elapsed, 12.0, "Concurrent threads deadlocked or stalled")

        for i in range(8):
            self.assertIsNone(errors[i], f"Thread {i} raised error: {errors[i]}")
            self.assertIsNotNone(results[i], f"Thread {i} did not finish")

        # Verify exact thread return expectations
        self.assertEqual(results[0], (EXIT_SUCCESS, 4_000_000, 0))
        self.assertEqual(results[1], (EXIT_SUCCESS, 4_000_000, 0))
        self.assertEqual(results[2], (EXIT_SUCCESS, 0, 4_000_000))
        self.assertEqual(results[3], (EXIT_SUCCESS, 0, 4_000_000))
        self.assertEqual(results[4], (EXIT_SUCCESS, 2_000_000, 2_000_000))
        self.assertEqual(results[5], (EXIT_SUCCESS, 2_000_000, 2_000_000))
        self.assertEqual(results[6][0], EXIT_TIMEOUT_ERROR)
        self.assertEqual(results[7][0], EXIT_INTERNAL_ERROR)

        self.assertEqual(len(_ACTIVE_SUBPROCESS_PGIDS), 0)

    def test_11_cross_thread_process_group_isolation(self) -> None:
        """Isolation: Thread A triggering SIGKILL to its process group does NOT terminate Thread B's process group."""
        res_A = None
        res_B = None

        def worker_A() -> None:
            nonlocal res_A
            s = 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(10)'
            res_A = execute_rvs_subprocess(["-c", s], timeout=0.4, rvs_bin=self.py_bin)

        def worker_B() -> None:
            nonlocal res_B
            # 8MB continuous transfer taking ~0.8s
            s = (
                "import sys, time\n"
                "c = 'K' * 65536\n"
                "w = 0\n"
                "while w < 8_000_000:\n"
                "    sys.stdout.write(c[:min(len(c), 8_000_000 - w)])\n"
                "    w += len(c)\n"
                "    time.sleep(0.005)\n"
                "sys.stdout.flush()\n"
            )
            res_B = execute_rvs_subprocess(["-c", s], timeout=6.0, rvs_bin=self.py_bin)

        tA = threading.Thread(target=worker_A)
        tB = threading.Thread(target=worker_B)
        tA.start()
        tB.start()
        tA.join()
        tB.join()

        self.assertIsNotNone(res_A)
        self.assertIsNotNone(res_B)
        self.assertEqual(res_A[0], EXIT_TIMEOUT_ERROR)
        self.assertEqual(res_B[0], EXIT_SUCCESS)
        self.assertEqual(len(res_B[1]), 8_000_000)

    def test_12_pipe_descriptor_leak_freedom_under_stress(self) -> None:
        """Leak Freedom: Pipe file descriptors in /proc/self/fd do not leak across 20 stress runs."""
        if not os.path.exists("/proc/self/fd"):
            self.skipTest("/proc/self/fd unavailable")

        initial_fds = len(os.listdir("/proc/self/fd"))

        for i in range(20):
            if i % 2 == 0:
                s = 'import sys; sys.stdout.write("Z" * 100_000); sys.stderr.write("W" * 100_000)'
                execute_rvs_subprocess(["-c", s], timeout=2.0, rvs_bin=self.py_bin)
            else:
                s = 'import time; time.sleep(5)'
                execute_rvs_subprocess(["-c", s], timeout=0.01, rvs_bin=self.py_bin)

        time.sleep(0.05)
        final_fds = len(os.listdir("/proc/self/fd"))
        # Allow at most 2 transient OS fds, but strictly prevent leaking 20*3 pipes
        self.assertLessEqual(
            final_fds,
            initial_fds + 2,
            f"File descriptors leaked: initial={initial_fds}, final={final_fds}",
        )

    def test_13_boundary_timeouts_zero_and_negative(self) -> None:
        """Boundary: Timeouts <= 0 immediately trigger timeout watchdog without stalling."""
        for t_val in [0.0, -1.0, 0.0001]:
            start = time.perf_counter()
            code, stdout, stderr, dur = execute_rvs_subprocess(
                ["-c", "import time; time.sleep(5)"],
                timeout=t_val,
                rvs_bin=self.py_bin,
            )
            elapsed = time.perf_counter() - start
            self.assertEqual(code, EXIT_TIMEOUT_ERROR)
            self.assertLess(elapsed, 1.5)

        self.assertEqual(len(_ACTIVE_SUBPROCESS_PGIDS), 0)

    def test_14_single_line_unbroken_15mb_stream(self) -> None:
        """Stress: 15MB continuous stream without a single newline character drains without deadlock."""
        payload_size = 15_000_000
        script = (
            "import sys\n"
            "chunk = 'X' * 65536\n"
            f"total = {payload_size}\n"
            "written = 0\n"
            "while written < total:\n"
            "    to_write = min(len(chunk), total - written)\n"
            "    sys.stdout.write(chunk[:to_write])\n"
            "    written += to_write\n"
            "sys.stdout.flush()\n"
        )
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=10.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), payload_size)
        self.assertLess(elapsed, 8.0)


if __name__ == "__main__":
    unittest.main()
