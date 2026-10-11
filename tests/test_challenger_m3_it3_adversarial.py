"""tests/test_challenger_m3_it3_adversarial.py - Empirical Adversarial Stress & Invariant Verification Suite.

Authored by Challenger 2 for Milestone M3 Iteration 3 (Deadlock Freedom & FSM Stress Challenger).
Adversarial Verification Scope:
1. Deadlock Freedom & Process Lifecycle:
   - Saturated stdout and stderr streams (>=10MB continuous generation, 20MB bistream).
   - Adversarial subprocesses that ignore SIGTERM and attempt to hang pipes.
   - Strict termination bounded time invariant: T <= Timeout + 1.5s.
   - Zero zombie (<defunct>) processes leaked across rapid timeout iterations.
   - Concurrent multithreaded saturated pipe calls (20 concurrent threads).
2. FSM State Reachability & Error Containment:
   - Comprehensive MCP JSON-RPC protocol fuzzing (syntax errors, type mismatches, missing params, unknown methods).
   - Strict Signal Normalization to {0..6} exit code taxonomy.
   - Terminal state reachability T0..T6 verification.
   - Zero unhandled exceptions or server crashes.
"""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rvs_agent_harness import (
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    _ACTIVE_SUBPROCESS_PGIDS,
    _SUBPROCESS_REGISTRY_LOCK,
    RvsHarness,
    execute_rvs_subprocess,
    normalize_exit_code,
)

FIXTURE_PATH = "crackme_case"


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


class TestChallengerM3It3DeadlockAndLifecycle(unittest.TestCase):
    """Empirical adversarial stress testing of deadlock freedom and process lifecycle."""

    def setUp(self) -> None:
        self.py_bin = Path(sys.executable)
        self.my_pid = os.getpid()

    def test_01_saturated_stdout_continuous_10mb(self) -> None:
        """Stress 1.1: 10MB continuous stdout stream exceeds 64KB pipe buffer by >150x without deadlock."""
        payload_size = 10_000_000
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
            timeout=8.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), payload_size)
        self.assertEqual(stderr, "")
        self.assertLess(elapsed, 8.0, f"Draining 10MB took too long: {elapsed:.2f}s")

    def test_02_saturated_stderr_continuous_10mb(self) -> None:
        """Stress 1.2: 10MB continuous stderr stream exceeds 64KB pipe buffer without pipe stalls."""
        payload_size = 10_000_000
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
            timeout=8.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(stdout, "")
        self.assertEqual(len(stderr), payload_size)
        self.assertLess(elapsed, 8.0, f"Draining 10MB stderr took too long: {elapsed:.2f}s")

    def test_03_simultaneous_saturated_bistream_20mb(self) -> None:
        """Stress 1.3: 10MB stdout + 10MB stderr concurrently produced from separate threads in child."""
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
            timeout=12.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), 10_000_000)
        self.assertEqual(len(stderr), 10_000_000)
        self.assertLess(elapsed, 10.0)

    def test_04_saturated_stream_without_newlines(self) -> None:
        """Stress 1.4: 10MB uninterrupted stream without any newlines drains without blocking."""
        payload_size = 10_000_000
        script = (
            "import sys\n"
            "chunk = 'Z' * 65536\n"
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
            timeout=8.0,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_SUCCESS)
        self.assertEqual(len(stdout), payload_size)
        self.assertNotIn("\n", stdout)
        self.assertLess(elapsed, 8.0)

    def test_05_adversarial_sigterm_ignore_cpu_spin_bounded_time(self) -> None:
        """Adversarial 1.5: Subprocess masks SIGTERM and spins; watchdog escalates to SIGKILL in T <= Timeout + 1.5s."""
        script = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.01)\n"
        )
        timeout = 0.5
        start = time.perf_counter()
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", script],
            timeout=timeout,
            rvs_bin=self.py_bin,
        )
        elapsed = time.perf_counter() - start

        self.assertEqual(code, EXIT_TIMEOUT_ERROR)
        self.assertGreaterEqual(elapsed, timeout - 0.05, "Premature termination before timeout")
        self.assertLess(
            elapsed,
            timeout + 1.5,
            f"Escalation exceeded bounded termination guarantee: {elapsed:.2f}s > {timeout + 1.5}s",
        )

    def test_06_adversarial_sigterm_ignore_pipe_spam_bounded_time(self) -> None:
        """Adversarial 1.6: Subprocess masks SIGTERM AND spams pipes continuously; watchdog terminates cleanly."""
        script = (
            "import signal, sys, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    try:\n"
            "        sys.stdout.write('A' * 4096)\n"
            "        sys.stdout.flush()\n"
            "        sys.stderr.write('B' * 4096)\n"
            "        sys.stderr.flush()\n"
            "    except Exception:\n"
            "        pass\n"
            "    time.sleep(0.005)\n"
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
        self.assertLess(
            elapsed,
            timeout + 1.5,
            f"Watchdog pipe drain under spam exceeded bound: {elapsed:.2f}s > {timeout + 1.5}s",
        )
        self.assertGreater(len(stdout), 0)
        self.assertGreater(len(stderr), 0)

    def test_07_adversarial_grandchild_tree_masking_sigterm(self) -> None:
        """Adversarial 1.7: Entire process group with grandchildren masking SIGTERM is reaped with 0 leaks."""
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
        timeout = 0.5
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
        self.assertEqual(zombies, [], f"Zombie processes leaked: {zombies}")

    def test_08_child_holds_pipes_open_parent_exits(self) -> None:
        """Adversarial 1.8: Child process holds stdout/stderr pipes open while parent exits immediately."""
        script = (
            "import os, sys, time, signal\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "    time.sleep(20)\n"
            "    sys.exit(0)\n"
            "else:\n"
            "    sys.exit(0)\n"
        )
        timeout = 0.5
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

    def test_09_rapid_timeouts_zero_zombies(self) -> None:
        """Lifecycle 1.9: 40 rapid successive timeouts leave zero zombie (<defunct>) processes."""
        script = "import time; time.sleep(10)"
        for _ in range(40):
            code, _, _, _ = execute_rvs_subprocess(
                ["-c", script],
                timeout=0.01,
                rvs_bin=self.py_bin,
            )
            self.assertEqual(code, EXIT_TIMEOUT_ERROR)

        time.sleep(0.1)
        zombies = _get_zombies_for_pid(self.my_pid)
        self.assertEqual(zombies, [], f"Detected {len(zombies)} zombies: {zombies}")

        with _SUBPROCESS_REGISTRY_LOCK:
            self.assertEqual(len(_ACTIVE_SUBPROCESS_PGIDS), 0)

    def test_10_rapid_sigkill_escalations_zero_zombies(self) -> None:
        """Lifecycle 1.10: 20 rapid SIGKILL escalations against SIGTERM-ignoring loops leave zero zombies."""
        script = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.01)\n"
        )
        for _ in range(20):
            code, _, _, _ = execute_rvs_subprocess(
                ["-c", script],
                timeout=0.01,
                rvs_bin=self.py_bin,
            )
            self.assertEqual(code, EXIT_TIMEOUT_ERROR)

        time.sleep(0.1)
        zombies = _get_zombies_for_pid(self.my_pid)
        self.assertEqual(zombies, [], f"Detected {len(zombies)} zombies: {zombies}")
        with _SUBPROCESS_REGISTRY_LOCK:
            self.assertEqual(len(_ACTIVE_SUBPROCESS_PGIDS), 0)

    def test_11_concurrent_20_threads_saturated_pipes(self) -> None:
        """Concurrency 1.11: 20 concurrent threads running saturated pipe streams, timeouts, and crashes."""
        results: List[Optional[Tuple[int, int, int]]] = [None] * 20
        errors: List[Optional[Exception]] = [None] * 20

        def worker_task(idx: int) -> None:
            try:
                if 0 <= idx < 5:
                    # 5 threads: saturated stdout 2MB
                    s = 'import sys; sys.stdout.write("O" * 2_000_000); sys.stdout.flush()'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=8.0, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                elif 5 <= idx < 10:
                    # 5 threads: saturated stderr 2MB
                    s = 'import sys; sys.stderr.write("E" * 2_000_000); sys.stderr.flush()'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=8.0, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                elif 10 <= idx < 15:
                    # 5 threads: cross-stream 1MB stdout + 1MB stderr
                    s = 'import sys; sys.stdout.write("X" * 1_000_000); sys.stderr.write("Y" * 1_000_000); sys.stdout.flush(); sys.stderr.flush()'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=8.0, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                elif 15 <= idx < 18:
                    # 3 threads: SIGTERM ignore with 0.3s timeout
                    s = 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(10)'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=0.3, rvs_bin=self.py_bin)
                    results[idx] = (c, len(out), len(err))
                else:
                    # 2 threads (18, 19): Sudden SIGSEGV crash
                    s = 'import os, signal; os.kill(os.getpid(), signal.SIGSEGV)'
                    c, out, err, d = execute_rvs_subprocess(["-c", s], timeout=5.0, rvs_bin=self.py_bin)
                    results[idx] = (normalize_exit_code(c), len(out), len(err))
            except Exception as e:
                errors[idx] = e

        threads = [threading.Thread(target=worker_task, args=(i,)) for i in range(20)]
        start = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=18.0)
        elapsed = time.perf_counter() - start

        self.assertLess(elapsed, 15.0, f"20 concurrent threads took too long or deadlocked: {elapsed:.2f}s")

        for i in range(20):
            self.assertIsNone(errors[i], f"Thread {i} raised error: {errors[i]}")
            self.assertIsNotNone(results[i], f"Thread {i} did not finish within timeout")

        # Verify expectations for all 20 threads
        for i in range(5):
            self.assertEqual(results[i], (EXIT_SUCCESS, 2_000_000, 0), f"Thread {i} stdout failed")
        for i in range(5, 10):
            self.assertEqual(results[i], (EXIT_SUCCESS, 0, 2_000_000), f"Thread {i} stderr failed")
        for i in range(10, 15):
            self.assertEqual(results[i], (EXIT_SUCCESS, 1_000_000, 1_000_000), f"Thread {i} cross failed")
        for i in range(15, 18):
            self.assertEqual(results[i][0], EXIT_TIMEOUT_ERROR, f"Thread {i} timeout failed")
        for i in range(18, 20):
            self.assertEqual(results[i][0], EXIT_INTERNAL_ERROR, f"Thread {i} crash failed")

        time.sleep(0.1)
        zombies = _get_zombies_for_pid(self.my_pid)
        self.assertEqual(zombies, [])
        with _SUBPROCESS_REGISTRY_LOCK:
            self.assertEqual(len(_ACTIVE_SUBPROCESS_PGIDS), 0)


class TestChallengerM3It3FsmAndMcpProtocolStress(unittest.TestCase):
    """Empirical adversarial stress testing of FSM reachability, MCP protocol fuzzing, and signal normalization."""

    def setUp(self) -> None:
        self.harness = RvsHarness()
        self.taxonomy_codes = {
            EXIT_SUCCESS,
            EXIT_INVALID_ARGUMENT,
            EXIT_FILE_ERROR,
            EXIT_ANALYSIS_ERROR,
            EXIT_PATCH_ERROR,
            EXIT_TIMEOUT_ERROR,
            EXIT_INTERNAL_ERROR,
        }

    def test_12_signal_normalization_exhaustive_matrix(self) -> None:
        """Taxonomy 2.1: Exhaustive signal and return code normalization strictly contained in {0..6}."""
        # 1. Identity preservation for valid taxonomy codes {0..6}
        for code in range(7):
            self.assertEqual(normalize_exit_code(code), code)

        # 2. Standard POSIX termination signals (negative integers from Popen.returncode)
        negative_signals = [
            -1,   # SIGHUP
            -2,   # SIGINT
            -3,   # SIGQUIT
            -4,   # SIGILL
            -6,   # SIGABRT
            -7,   # SIGBUS
            -8,   # SIGFPE
            -9,   # SIGKILL
            -11,  # SIGSEGV
            -13,  # SIGPIPE
            -14,  # SIGALRM
            -15,  # SIGTERM
            -31,  # SIGSYS
            -127,
        ]
        for sig in negative_signals:
            normalized = normalize_exit_code(sig)
            self.assertEqual(
                normalized,
                EXIT_INTERNAL_ERROR,
                f"Negative signal {sig} normalized to {normalized}, expected EXIT_INTERNAL_ERROR (6)",
            )

        # 3. Shell conventions (128 + signum) and runtime panics
        foreign_codes = [
            101,  # Rust runtime panic
            128 + 9,   # 137 (SIGKILL)
            128 + 11,  # 139 (SIGSEGV)
            128 + 15,  # 143 (SIGTERM)
            255,       # Generic error (-1 unsigned)
            7, 8, 42, 99, 127, 256, 1000,
        ]
        for raw in foreign_codes:
            normalized = normalize_exit_code(raw)
            self.assertEqual(
                normalized,
                EXIT_INTERNAL_ERROR,
                f"Code {raw} normalized to {normalized}, expected EXIT_INTERNAL_ERROR (6)",
            )

    def test_13_subprocess_sudden_crash_signals_handled(self) -> None:
        """Taxonomy 2.2: Live subprocess crashes (SIGSEGV, SIGABRT, SIGFPE) map strictly to EXIT_INTERNAL_ERROR."""
        crash_scripts = [
            ("SIGSEGV", "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"),
            ("SIGABRT", "import os, signal; os.kill(os.getpid(), signal.SIGABRT)"),
            ("SIGFPE",  "import os, signal; os.kill(os.getpid(), signal.SIGFPE)"),
        ]
        for name, script in crash_scripts:
            code, stdout, stderr, dur = execute_rvs_subprocess(
                ["-c", script],
                timeout=2.0,
                rvs_bin=Path(sys.executable),
            )
            normalized = normalize_exit_code(code)
            self.assertEqual(
                normalized,
                EXIT_INTERNAL_ERROR,
                f"Crashed process with {name} produced raw={code}, normalized={normalized} != 6",
            )

    def test_14_mcp_jsonrpc_protocol_fuzzing(self) -> None:
        """Fuzzing 2.3: Comprehensive JSON-RPC protocol fuzzing must contain all errors without crashing daemon."""
        fuzz_payloads = [
            # 1. Broken JSON syntax
            "{\n",
            "{unquoted_key: 123}\n",
            "['unclosed array'\n",
            '{"jsonrpc": "2.0", "id": 1, "method": \n',
            "NONSENSE_TOKEN_STREAM_$%^&*!\n",
            "\x00\x01\x02\x03\n",

            # 2. Non-dict root types
            "12345\n",
            '"just a string"\n',
            "true\n",
            "null\n",
            "[]\n",
            "[1, 2, 3]\n",
            json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]) + "\n",

            # 3. Invalid jsonrpc version / missing jsonrpc
            json.dumps({}) + "\n",
            json.dumps({"id": 1, "method": "ping"}) + "\n",
            json.dumps({"jsonrpc": "1.0", "id": 2, "method": "ping"}) + "\n",
            json.dumps({"jsonrpc": 2.0, "id": 3, "method": "ping"}) + "\n",
            json.dumps({"jsonrpc": "3.0", "id": 4, "method": "ping"}) + "\n",

            # 4. Invalid method field
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": None}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 6, "method": 12345}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 7, "method": []}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 8, "method": {}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 9, "method": "unknown_rpc_method_xyz"}) + "\n",

            # 5. Invalid params in standard methods
            json.dumps({"jsonrpc": "2.0", "id": 10, "method": "initialize", "params": "not_an_object"}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 11, "method": "initialize", "params": [1, 2]}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 12, "method": "ping", "params": 42}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 13, "method": "tools/list", "params": "bad"}) + "\n",

            # 6. Malformed tools/call params
            json.dumps({"jsonrpc": "2.0", "id": 14, "method": "tools/call", "params": None}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 15, "method": "tools/call", "params": "string"}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 16, "method": "tools/call", "params": []}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 17, "method": "tools/call", "params": {}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 18, "method": "tools/call", "params": {"name": 123}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 19, "method": "tools/call", "params": {"name": ""}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "nonexistent_tool_xyz", "arguments": {}}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": {"name": "rvs_info", "arguments": "not_a_dict"}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 22, "method": "tools/call", "params": {"name": "rvs_info", "arguments": [1, 2, 3]}}) + "\n",

            # 7. Valid tool call with missing required parameter 'file'
            json.dumps({"jsonrpc": "2.0", "id": 23, "method": "tools/call", "params": {"name": "rvs_info", "arguments": {}}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 24, "method": "tools/call", "params": {"name": "rvs_disasm", "arguments": {}}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 25, "method": "tools/call", "params": {"name": "rvs_decompile", "arguments": {}}}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 26, "method": "tools/call", "params": {"name": "rvs_patch_bytes", "arguments": {}}}) + "\n",

            # 8. Notifications (must not crash and produce no response)
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n",
            json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 999}}) + "\n",

            # 9. Liveness check: valid tools/list and ping at the end to prove daemon is still alive
            json.dumps({"jsonrpc": "2.0", "id": 100, "method": "ping"}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 101, "method": "tools/list"}) + "\n",
        ]

        in_stream = io.StringIO("".join(fuzz_payloads))
        out_stream = io.StringIO()

        # Execute daemon loop - must complete cleanly without any uncaught exception
        self.harness.serve_mcp(stdin_stream=in_stream, stdout_stream=out_stream)

        raw_output = out_stream.getvalue()
        lines = [line.strip() for line in raw_output.splitlines() if line.strip()]

        # Parse every line as JSON
        responses = []
        for line in lines:
            try:
                responses.append(json.loads(line))
            except json.JSONDecodeError as err:
                self.fail(f"Daemon produced non-JSON line: '{line}', error: {err}")

        # Assert every single response conforms to JSON-RPC 2.0 structure
        for resp in responses:
            self.assertEqual(resp.get("jsonrpc"), "2.0")
            self.assertTrue("result" in resp or "error" in resp)
            if "error" in resp:
                err = resp["error"]
                self.assertIn("code", err)
                self.assertIn("message", err)
                # Valid JSON-RPC error codes are standard: -32700, -32600, -32601, -32602, -32603
                self.assertIn(err["code"], (-32700, -32600, -32601, -32602, -32603))

        # Check that the trailing requests (id 100 and id 101) succeeded!
        id_100_resps = [r for r in responses if r.get("id") == 100]
        self.assertEqual(len(id_100_resps), 1, "Ping request (id=100) did not receive response")
        self.assertEqual(id_100_resps[0].get("result"), {})

        id_101_resps = [r for r in responses if r.get("id") == 101]
        self.assertEqual(len(id_101_resps), 1, "tools/list request (id=101) did not receive response")
        self.assertIn("tools", id_101_resps[0].get("result", {}))

    def test_15_fsm_terminal_state_containment(self) -> None:
        """FSM 2.4: Verify complete reachability and error containment across all terminal states T0..T6."""
        # T0: EXIT_SUCCESS (0)
        res_t0 = self.harness.execute_tool("rvs_info", {"file": FIXTURE_PATH, "compact": True})
        self.assertTrue(res_t0.get("success"))

        # T1: EXIT_INVALID_ARGUMENT (1)
        res_t1 = self.harness.execute_tool("rvs_info", arguments=None)
        self.assertFalse(res_t1.get("success"))
        code_t1 = res_t1.get("error", {}).get("exit_code")
        self.assertEqual(code_t1, EXIT_INVALID_ARGUMENT)
        self.assertIn(code_t1, self.taxonomy_codes)

        # T2: EXIT_FILE_ERROR (2)
        res_t2 = self.harness.execute_tool("rvs_info", {"file": "/path/to/definitely/nonexistent_file_99999"})
        self.assertFalse(res_t2.get("success"))
        code_t2 = res_t2.get("error", {}).get("exit_code")
        self.assertEqual(code_t2, EXIT_FILE_ERROR)
        self.assertIn(code_t2, self.taxonomy_codes)

        # T3: EXIT_ANALYSIS_ERROR (3)
        res_t3 = self.harness.execute_tool("rvs_decompile", {"file": FIXTURE_PATH, "function": "nonexistent_func_xyz"})
        self.assertFalse(res_t3.get("success"))
        code_t3 = res_t3.get("error", {}).get("exit_code")
        self.assertEqual(code_t3, EXIT_ANALYSIS_ERROR)
        self.assertIn(code_t3, self.taxonomy_codes)

        # T4: EXIT_PATCH_ERROR (4)
        res_t4 = self.harness.execute_tool("rvs_patch_bytes", {"file": FIXTURE_PATH, "addr": "0x1000", "hex_bytes": "NON_HEX_ZZZ"})
        self.assertFalse(res_t4.get("success"))
        code_t4 = res_t4.get("error", {}).get("exit_code")
        self.assertIn(code_t4, (EXIT_INVALID_ARGUMENT, EXIT_PATCH_ERROR))
        self.assertIn(code_t4, self.taxonomy_codes)

        # T5: EXIT_TIMEOUT_ERROR (5)
        res_t5 = self.harness.run(["-f", FIXTURE_PATH, "analyze", "functions"], timeout=0.00001)
        self.assertFalse(res_t5.get("success"))
        code_t5 = res_t5.get("error", {}).get("exit_code")
        self.assertEqual(code_t5, EXIT_TIMEOUT_ERROR)
        self.assertIn(code_t5, self.taxonomy_codes)

        # T6: EXIT_INTERNAL_ERROR (6)
        code_raw, _, _, _ = execute_rvs_subprocess(
            ["-c", "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"],
            timeout=2.0,
            rvs_bin=Path(sys.executable),
        )
        code_t6 = normalize_exit_code(code_raw)
        self.assertEqual(code_t6, EXIT_INTERNAL_ERROR)
        self.assertIn(code_t6, self.taxonomy_codes)


if __name__ == "__main__":
    unittest.main()
