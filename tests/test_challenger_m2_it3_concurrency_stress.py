#!/usr/bin/env python3
"""
tests/test_challenger_m2_it3_concurrency_stress.py - Empirical Challenger Stress Suite
for Milestone 2 Iteration 3.

Empirically challenges and stress-tests:
1. Multi-process concurrent invocations across worker OS processes (ProcessPoolExecutor).
2. Multi-threaded high-concurrency invocations across threads (ThreadPoolExecutor).
3. Concurrent timeout watchdog enforcement on hanging processes without pipe deadlocks.
4. Concurrent file operations (temporary zero-byte files, non-exec files, script files)
   to ensure zero file lock collisions or race conditions.
5. Pre-flight input validation under concurrent stress (invalid regs, invalid targets, injection tokens).
6. File descriptor leaks and exit code taxonomy determinism.
"""

import concurrent.futures
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def find_rvs() -> str:
    candidates = [
        PROJECT_ROOT / "target" / "release" / "rvs",
        PROJECT_ROOT / "target" / "debug" / "rvs",
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return str(c)
    raise RuntimeError("rvs binary not found in target/release or target/debug")


def run_rvs_cmd(args: List[str], env_override: Dict[str, str] = None) -> Tuple[int, Dict[str, Any], str, str]:
    rvs_bin = find_rvs()
    env = os.environ.copy()
    if env_override:
        env.update(env_override)

    proc = subprocess.run(
        [rvs_bin] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=15,
    )

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    data = {}
    if stdout:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise AssertionError(f"Non-JSON stdout (rc={proc.returncode}):\nSTDOUT: {stdout}\nSTDERR: {stderr}") from e

    return proc.returncode, data, stdout, stderr


def execute_task_top_level(item: Tuple[List[str], List[int]]) -> Tuple[int, Dict[str, Any], List[int]]:
    cmd, allowed = item
    rc, data, stdout, stderr = run_rvs_cmd(cmd)
    return rc, data, allowed


class TestM2It3ConcurrencyAndWatchdogStress(unittest.TestCase):
    """Empirical concurrency, race condition, and watchdog stress test."""

    @classmethod
    def setUpClass(cls):
        cls.rvs_bin = find_rvs()

    def test_01_multiprocess_high_concurrency_stress(self):
        """
        Execute 160 heterogeneous invocations across 16 separate OS worker processes.
        Ensure zero file locking collisions, zero race conditions, and deterministic exit codes.
        """
        tasks = [
            # Env-check (exit 0 or 6)
            (["frida", "env-check"], [0, 6]),
            # Spawn directory (exit 2)
            (["frida", "spawn", "/tmp"], [2]),
            # Spawn non-existent binary (exit 2)
            (["frida", "spawn", "/tmp/definitely_not_existing_bin_xyz123"], [2]),
            # Attach negative PID (exit 1)
            (["frida", "attach", "-42"], [1]),
            # Attach overflow PID (exit 1)
            (["frida", "attach", "9999999999999999999999999999999999999999"], [1]),
            # Trace-regs invalid register (exit 1)
            (["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", "bad@reg!name"], [1]),
            # Trace-regs non-ascii (exit 1)
            (["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", "rax,🦀"], [1]),
            # Trace-regs valid register names syntax (passes preflight, exits 6 without io_frida)
            (["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", "rax,rbx,rcx,rsp"], [6]),
            # Mem-read out of bounds (exit 3)
            (["frida", "mem-read", "-t", "0", "-A", "0xffffffffffffffff", "--len", "16"], [3]),
            # Mem-read invalid len (exit 1)
            (["frida", "mem-read", "-t", "0", "-A", "0x401000", "--len", "0"], [1]),
            # Mem-write non-hex (exit 1)
            (["frida", "mem-write", "-t", "0", "-A", "0x401000", "--data", "ZZZZ"], [1]),
            # Script empty code (exit 1)
            (["frida", "script", "-t", "0", "--code", ""], [1]),
            # Hook-remove invalid id (exit 1)
            (["frida", "hook-remove", "-t", "0", "--id", "invalid_id_not_num"], [1]),
            # Hook-return invalid retval (exit 1)
            (["frida", "hook-return", "-t", "0", "-A", "0x401000", "--retval", "not_a_number"], [1]),
            # Symbols injection characters in module (exit 1)
            (["frida", "symbols", "-t", "0", "--module", "libc.so;rm -rf /"], [1]),
            # RPC invalid js method name (exit 1)
            (["frida", "rpc", "-t", "0", "--method", "123invalid-name"], [1]),
        ]

        work_items = []
        for i in range(160):
            cmd, allowed_rcs = tasks[i % len(tasks)]
            work_items.append((cmd, allowed_rcs))

        with concurrent.futures.ProcessPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(execute_task_top_level, work_items))

        self.assertEqual(len(results), 160)
        for rc, data, allowed in results:
            self.assertIn(rc, allowed, f"Unexpected returncode {rc}, expected one of {allowed}. Data: {data}")
            self.assertIn("command", data)
            self.assertIn("timestamp", data)
            self.assertIn("format_version", data)

    def test_02_multithreaded_high_contention_stress(self):
        """
        Execute 320 invocations across 64 concurrent threads synchronized via a threading.Barrier.
        Forces all threads to hit the binary simultaneously.
        """
        barrier = threading.Barrier(64)
        results = []
        lock = threading.Lock()

        def worker(thread_id: int):
            # Wait for all 64 threads to be ready
            barrier.wait()
            for iteration in range(5):
                cmd = ["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", f"reg_{thread_id}_{iteration},rax"]
                rc, data, stdout, stderr = run_rvs_cmd(cmd)
                with lock:
                    results.append((rc, data))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(64)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 320)
        for rc, data in results:
            # Valid syntax reg_X_Y,rax -> passes preflight -> returns 6 (R2_FRIDA_NOT_INSTALLED)
            self.assertEqual(rc, 6)
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["code"], "R2_FRIDA_NOT_INSTALLED")

    def test_03_concurrent_watchdog_timeouts_under_hanging_processes(self):
        """
        Test concurrent watchdog timeout enforcement.
        Create a mock radare2 script that advertises frida but hangs for 20 seconds.
        Run 10 concurrent requests with --timeout 1.
        All must terminate within 4.5 seconds with exit code 5 (TIMEOUT_EXPIRED).
        """
        mock_dir = tempfile.mkdtemp(prefix="rvs_watchdog_mock_")
        self.addCleanup(lambda: shutil.rmtree(mock_dir, ignore_errors=True))

        mock_r2 = Path(mock_dir) / "radare2"
        mock_script = """#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{"name":"frida","uris":["frida://"]}]'
        exit 0
    fi
done
# flood 10KB then sleep
python3 -c "import sys; sys.stdout.write('A' * 10240); sys.stderr.write('B' * 4096); sys.stdout.flush(); sys.stderr.flush()"
exec sleep 20
"""
        mock_r2.write_text(mock_script)
        mock_r2.chmod(mock_r2.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        env_override = {
            "PATH": f"{mock_dir}:{os.environ.get('PATH', '')}"
        }

        def run_timed_task(target_id: int) -> Tuple[int, float, Dict[str, Any]]:
            t0 = time.time()
            rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", str(1000 + target_id), "--timeout", "1"], env_override=env_override)
            elapsed = time.time() - t0
            return rc, elapsed, data

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(run_timed_task, i) for i in range(10)]
            completed = [f.result() for f in futures]

        self.assertEqual(len(completed), 10)
        for rc, elapsed, data in completed:
            self.assertEqual(rc, 5, f"Expected rc=5 for watchdog timeout, got {rc}. Data: {data}")
            self.assertLess(elapsed, 4.5, f"Watchdog timeout took too long: {elapsed:.2f}s")
            self.assertFalse(data["success"])
            self.assertEqual(data["error"]["code"], "TIMEOUT_EXPIRED")
            self.assertEqual(data["error"]["category"], "TIMEOUT_ERROR")

    def test_04_concurrent_tempfile_races_and_file_locking(self):
        """
        Create 20 distinct temporary files concurrently (some 0-byte, some non-executable, some valid scripts).
        Invoke rvs concurrently on these temporary files to confirm no file-locking or race conditions.
        """
        temp_dir = tempfile.mkdtemp(prefix="rvs_file_race_")
        self.addCleanup(lambda: shutil.rmtree(temp_dir, ignore_errors=True))

        tasks = []
        for i in range(20):
            # 0-byte file
            zero_p = Path(temp_dir) / f"zero_{i}.bin"
            zero_p.touch()
            tasks.append((["frida", "spawn", str(zero_p)], 2, "ZERO_BYTE_FILE"))

            # Non-executable file
            noexec_p = Path(temp_dir) / f"noexec_{i}.bin"
            noexec_p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32)
            os.chmod(noexec_p, 0o600)
            tasks.append((["frida", "spawn", str(noexec_p)], 2, "PERMISSION_DENIED"))

            # Valid JS script file
            script_p = Path(temp_dir) / f"script_{i}.js"
            script_p.write_text(f"console.log('concurrent script {i}');")
            # Passes script preflight -> fails with exit 6 (no io_frida)
            tasks.append((["frida", "script", "-t", "0", "--file", str(script_p)], 6, "R2_FRIDA_NOT_INSTALLED"))

        def run_file_task(item: Tuple[List[str], int, str]) -> Tuple[int, Dict[str, Any], int, str]:
            cmd, expected_rc, expected_code = item
            rc, data, stdout, stderr = run_rvs_cmd(cmd)
            return rc, data, expected_rc, expected_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(run_file_task, tasks))

        self.assertEqual(len(results), 60)
        for rc, data, expected_rc, expected_code in results:
            self.assertEqual(rc, expected_rc, f"Expected rc={expected_rc}, got {rc}. Data: {data}")
            self.assertEqual(data["error"]["code"], expected_code)

    def test_05_extreme_register_list_adversarial_boundary(self):
        """
        Test boundary of register list:
        1. 128 valid registers (maximum allowed) -> passes preflight (rc=6)
        2. 129 valid registers (exceeds maximum allowed 128) -> returns exit 1 (INVALID_ARGUMENT)
        """
        regs_128 = ",".join([f"r{i}" for i in range(128)])
        rc_128, data_128, _, _ = run_rvs_cmd(["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", regs_128])
        self.assertEqual(rc_128, 6, f"128 registers should pass preflight, got rc={rc_128}")
        self.assertEqual(data_128["error"]["code"], "R2_FRIDA_NOT_INSTALLED")

        regs_129 = ",".join([f"r{i}" for i in range(129)])
        rc_129, data_129, _, _ = run_rvs_cmd(["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", regs_129])
        self.assertEqual(rc_129, 1, f"129 registers should fail preflight with rc=1, got rc={rc_129}")
        self.assertEqual(data_129["error"]["code"], "INVALID_ARGUMENT")
        self.assertIn("maximum is 128", data_129["error"]["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
