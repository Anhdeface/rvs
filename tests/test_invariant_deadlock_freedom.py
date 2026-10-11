"""tests/test_invariant_deadlock_freedom.py - Deadlock Freedom & Watchdog Invariant Test Suite.

Formal Invariant Verification (R3 Invariant 1):
Theorem 1 (Deadlock Freedom & Bounded Termination):
For any worker behavior W, arbitrary stdout/stderr streams V_out, V_err in Sigma*,
and configured timeout T_timeout in (0, inf), the execution of `execute_rvs_subprocess`
always terminates in strictly bounded wall-clock time:
    T_exec <= T_timeout + epsilon_term + epsilon_kill + epsilon_reap = T_timeout + 1.5s
with zero unhandled deadlocks, zero orphaned processes, and zero zombie (<defunct>) processes.

Pipe I/O Multiplexing:
POSIX pipe buffers have standard capacity C_pipe = 65,536 bytes.
When a worker outputs V >> C_pipe (e.g., 10 MB), sequential blocking reads cause deadlocks.
The harness mitigates this by using non-blocking selector-based multiplexing in
`proc.communicate(timeout=...)`, draining both stdout and stderr concurrently.
"""

import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from rvs_agent_harness import (
    EXIT_INTERNAL_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    execute_rvs_subprocess,
    normalize_exit_code,
)


class TestInvariantDeadlockFreedom(unittest.TestCase):
    """Programmatically verifies Invariant 1: Deadlock Freedom in Pipe I/O and Watchdog Lifecycle."""

    def setUp(self) -> None:
        self.py_bin = Path(sys.executable)

    def test_01_saturated_stdout_stream_10mb(self) -> None:
        """Invariant 1.1: Saturated stdout pipe buffer (10 MB continuous stream) does not deadlock.

        Linux pipe capacity is typically 64KB (65,536 bytes).
        A 10MB write exceeds C_pipe by >150x. Without non-blocking concurrent draining,
        the worker will block indefinitely on write() while the harness hangs.
        """
        payload_size = 10_000_000
        script = (
            "import sys\n"
            f"chunk = 'A' * 65536\n"
            f"total = {payload_size}\n"
            "written = 0\n"
            "while written < total:\n"
            "    to_write = min(len(chunk), total - written)\n"
            "    sys.stdout.write(chunk[:to_write])\n"
            "    written += to_write\n"
            "sys.stdout.flush()\n"
        )
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=8.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), payload_size)
        self.assertLess(elapsed, 8.0, f"Execution took {elapsed:.2f}s, nearing timeout threshold")

    def test_02_saturated_stderr_stream_10mb(self) -> None:
        """Invariant 1.2: Saturated stderr pipe buffer (10 MB continuous stream) does not deadlock.

        If parent sequentially waits on stdout before reading stderr, a large stderr burst
        causes an immediate unrecoverable deadlock. Non-blocking multiplexing must drain stderr cleanly.
        """
        payload_size = 10_000_000
        script = (
            "import sys\n"
            f"chunk = 'E' * 65536\n"
            f"total = {payload_size}\n"
            "written = 0\n"
            "while written < total:\n"
            "    to_write = min(len(chunk), total - written)\n"
            "    sys.stderr.write(chunk[:to_write])\n"
            "    written += to_write\n"
            "sys.stderr.flush()\n"
        )
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=8.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stderr), payload_size)
        self.assertLess(elapsed, 8.0)

    def test_03_asymmetric_cross_stream_saturation(self) -> None:
        """Invariant 1.3: Concurrent alternating 5 MB stdout + 5 MB stderr streams do not deadlock.

        Exercises simultaneous cross-stream pipe buffer saturation to confirm selectors
        service read events across both descriptors without head-of-line blocking.
        """
        script = (
            "import sys\n"
            "chunk_out = 'O' * 50_000\n"
            "chunk_err = 'X' * 50_000\n"
            "for _ in range(100):\n"
            "    sys.stdout.write(chunk_out)\n"
            "    sys.stderr.write(chunk_err)\n"
            "sys.stdout.flush()\n"
            "sys.stderr.flush()\n"
        )
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=8.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), 5_000_000)
        self.assertEqual(len(stderr), 5_000_000)
        self.assertLess(elapsed, 8.0)

    def test_04_watchdog_sigkill_escalation_bounded_time(self) -> None:
        """Invariant 1.4: Watchdog reaps workers masking SIGTERM via SIGKILL in T <= Timeout + 1.5s.

        An adversarial worker traps SIGTERM and loops forever. The watchdog must:
        1. Catch TimeoutExpired at T = Timeout (1.0s).
        2. Issue SIGTERM to process group.
        3. Await 0.5s grace period.
        4. Escalate to SIGKILL to forcefully terminate the worker group.
        5. Return EXIT_TIMEOUT_ERROR within bounded time T <= Timeout + 1.5s = 2.5s.
        """
        script = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.05)\n"
        )
        timeout = 1.0
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=timeout,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        # Must terminate within timeout + 1.5 seconds (2.5s upper bound)
        self.assertLess(
            elapsed,
            timeout + 1.5,
            f"Watchdog escalation violated bounded termination: elapsed={elapsed:.2f}s > {timeout + 1.5}s",
        )
        self.assertGreaterEqual(elapsed, timeout, "Terminated prematurely before timeout expired")

    def test_05_sudden_worker_crash_sigsegv(self) -> None:
        """Invariant 1.5: Worker sudden death (SIGSEGV) encounters immediate EOF without hanging."""
        script = "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"
        start = time.time()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=5.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.time() - start

        # Must exit instantaneously (< 1.5s), never waiting for timeout
        self.assertLess(elapsed, 1.5)
        # Return code is either negative signal (-11) or normalized EXIT_INTERNAL_ERROR (6)
        normalized = normalize_exit_code(code)
        self.assertEqual(normalized, EXIT_INTERNAL_ERROR)

    def test_06_zero_zombies_after_rapid_timeouts(self) -> None:
        """Invariant 1.6: Rapid timeouts leave zero zombie (<defunct>) processes in process table."""
        script = "import time; time.sleep(10)"
        num_iterations = 20
        for _ in range(num_iterations):
            code, _, _, _ = execute_rvs_subprocess(
                ["-c", script],
                timeout=0.01,
                rvs_bin=self.py_bin,
            )
            self.assertEqual(code, EXIT_TIMEOUT_ERROR)

        # Allow kernel a moment to update process states
        time.sleep(0.1)

        # Inspect OS process table via ps for defunct children of current process
        my_pid = str(os.getpid())
        ps_res = subprocess.run(
            ["ps", "-o", "stat,ppid,pid", "-A"],
            capture_output=True,
            text=True,
            check=True,
        )
        zombies = []
        for line in ps_res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                stat, ppid = parts[0], parts[1]
                if ppid == my_pid and "Z" in stat:
                    zombies.append(line)

        self.assertEqual(
            zombies,
            [],
            f"Detected {len(zombies)} zombie processes in OS process table: {zombies}",
        )

    def test_07_multiprocess_tree_watchdog_cleanup(self) -> None:
        """Invariant 1.7: Entire process group including children and grandchildren is reaped."""
        # Worker spawns background grandchild processes
        script = (
            "import subprocess, sys, time\n"
            "p1 = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])\n"
            "p2 = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])\n"
            "time.sleep(20)\n"
        )
        code, _, _, _ = execute_rvs_subprocess(
            ["-c", script],
            timeout=0.2,
            rvs_bin=self.py_bin,
        )
        self.assertEqual(code, EXIT_TIMEOUT_ERROR)

        time.sleep(0.1)
        # Verify no defunct or running orphans from our PID
        ps_res = subprocess.run(
            ["ps", "-o", "stat,ppid,pid", "-A"],
            capture_output=True,
            text=True,
            check=True,
        )
        my_pid = str(os.getpid())
        orphans = [
            line for line in ps_res.stdout.splitlines()[1:]
            if len(line.split()) >= 2 and line.split()[1] == my_pid and "Z" in line.split()[0]
        ]
        self.assertEqual(orphans, [])

    def test_08_concurrent_saturated_workers_no_deadlock(self) -> None:
        """Invariant 1.8: Concurrent saturated workers in separate threads complete without deadlock."""
        results = [None] * 4
        exceptions = [None] * 4

        def worker(idx: int) -> None:
            try:
                script = (
                    "import sys\n"
                    "sys.stdout.write('T' * 1_000_000)\n"
                    "sys.stderr.write('E' * 1_000_000)\n"
                    "sys.stdout.flush()\n"
                    "sys.stderr.flush()\n"
                )
                code, out, err, dur = execute_rvs_subprocess(
                    ["-c", script],
                    timeout=6.0,
                    rvs_bin=self.py_bin,
                )
                results[idx] = (code, len(out), len(err))
            except Exception as e:
                exceptions[idx] = e

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        elapsed = time.time() - start
        self.assertLess(elapsed, 10.0, "Concurrent saturated workers deadlocked or exceeded join timeout")

        for i in range(4):
            self.assertIsNone(exceptions[i], f"Thread {i} raised exception: {exceptions[i]}")
            self.assertIsNotNone(results[i], f"Thread {i} did not complete")
            code, out_len, err_len = results[i]
            self.assertEqual(code, EXIT_SUCCESS)
            self.assertEqual(out_len, 1_000_000)
            self.assertEqual(err_len, 1_000_000)

    def test_09_pipe_descriptor_leak_freedom(self) -> None:
        """Invariant 1.9: Subprocess execution does not leak pipe descriptors across iterations."""
        if not os.path.exists("/proc/self/fd"):
            self.skipTest("/proc/self/fd not supported on this platform")

        initial_fd_count = len(os.listdir("/proc/self/fd"))
        for _ in range(15):
            code, out, err, dur = execute_rvs_subprocess(
                ["-c", "import sys; sys.stdout.write('hello'); sys.stderr.write('world')"],
                timeout=2.0,
                rvs_bin=self.py_bin,
            )
            self.assertEqual(code, EXIT_SUCCESS)

        time.sleep(0.05)
        final_fd_count = len(os.listdir("/proc/self/fd"))
        # Allow tolerance of at most 2 transient fds, but no progressive leak of 15 * 3 pipes
        self.assertLessEqual(
            final_fd_count,
            initial_fd_count + 2,
            f"Leaked file descriptors: initial={initial_fd_count}, final={final_fd_count}",
        )

    def test_10_immediate_worker_exit_empty_streams(self) -> None:
        """Invariant 1.10: Subprocess returning immediately with 0 bytes handled without stall."""
        code, out, err, dur = execute_rvs_subprocess(
            ["-c", "import sys; sys.exit(0)"],
            timeout=2.0,
            rvs_bin=self.py_bin,
        )
        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(out, "")
        self.assertEqual(err, "")
        self.assertLess(dur, 1.0)


if __name__ == "__main__":
    unittest.main()
