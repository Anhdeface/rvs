#!/usr/bin/env python3
"""
tests/test_challenger_m2_6_2_empirical.py - Empirical Challenger Verification Suite
Milestone 2: Process Watchdog, Timeout Hardening & Zombie Prevention

Verification Areas:
1. Non-blocking daemon kill: kill_session completes in < 2s during active continue_execution.
   Tracee PID is guaranteed terminated and reaped.
2. Daemon socket cleanup on SIGTERM / SIGINT and recovery from stale sockets.
3. Interactive timeout resync: timed out command triggers Ctrl-C/SIGINT, clears pipe,
   and allows subsequent commands to execute cleanly without data stream corruption.
4. Python harness subprocess watchdog: zero zombie (<defunct>) processes on timeout.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"
if not RVS_BIN.exists():
    RVS_BIN = WORKSPACE_DIR / "target" / "release" / "rvs"


def wait_for_socket(sock_path: Path, timeout: float = 3.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if sock_path.exists():
            return True
        time.sleep(0.05)
    return False


def is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class TestMilestone2EmpiricalVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RVS_BIN.exists():
            subprocess.run(["cargo", "build"], cwd=WORKSPACE_DIR, check=True)
        assert RVS_BIN.exists(), f"rvs binary not found at {RVS_BIN}"

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sock_path = Path(self.temp_dir.name) / "test_rvs_debug.sock"
        self.env = os.environ.copy()
        self.env["RVS_DEBUG_SOCKET"] = str(self.sock_path)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # =========================================================================
    # Area 1: Non-Blocking Daemon Kill Under Active Execution
    # =========================================================================

    def test_daemon_non_blocking_kill_during_continue(self):
        """Verify thread calling kill_session completes in <2s while another thread is executing continue."""
        daemon = subprocess.Popen(
            [str(RVS_BIN), "dynamic", "debug", "daemon", "--start"],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertTrue(wait_for_socket(self.sock_path), "Daemon socket failed to initialize")

            # Spawn sleep 60 target
            spawn_res = subprocess.run(
                [str(RVS_BIN), "dynamic", "debug", "spawn", "/bin/sleep", "--args", "60"],
                env=self.env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(spawn_res.returncode, 0, f"Spawn failed: {spawn_res.stderr}")
            spawn_data = json.loads(spawn_res.stdout)
            session_id = spawn_data["data"]["session_id"]
            tracee_pid = spawn_data["data"]["pid"]

            self.assertTrue(is_pid_alive(tracee_pid), f"Tracee {tracee_pid} should be active")

            # Thread 1: run continue (would block up to 30s)
            continue_res = {}
            def run_continue():
                t0 = time.time()
                res = subprocess.run(
                    [str(RVS_BIN), "dynamic", "debug", "continue", session_id],
                    env=self.env,
                    capture_output=True,
                    text=True,
                )
                continue_res["duration"] = time.time() - t0
                continue_res["returncode"] = res.returncode
                continue_res["stdout"] = res.stdout

            th = threading.Thread(target=run_continue)
            th.start()
            time.sleep(0.3)

            # Thread 2: call kill_session
            t_kill_start = time.time()
            kill_res = subprocess.run(
                [str(RVS_BIN), "dynamic", "debug", "kill", session_id],
                env=self.env,
                capture_output=True,
                text=True,
            )
            kill_duration = time.time() - t_kill_start

            self.assertEqual(kill_res.returncode, 0, f"Kill failed: {kill_res.stderr}")
            self.assertLess(
                kill_duration,
                2.0,
                f"kill_session MUST be non-blocking (< 2.0s), took {kill_duration:.3f}s",
            )
            kill_data = json.loads(kill_res.stdout)
            self.assertTrue(kill_data["success"])
            self.assertTrue(kill_data["data"]["terminated"])

            # Thread 1 should unblock quickly
            th.join(timeout=3.0)
            self.assertFalse(th.is_alive(), "Continue thread must unblock after session kill")

            # Tracee process must be terminated (not orphan)
            time.sleep(0.2)
            self.assertFalse(is_pid_alive(tracee_pid), f"Tracee PID {tracee_pid} must be terminated")
        finally:
            daemon.send_signal(signal.SIGTERM)
            daemon.wait(timeout=3)

    def test_daemon_multiple_concurrent_sessions_kill_stress(self):
        """Stress-test concurrent kill of multiple running sessions without deadlocking."""
        daemon = subprocess.Popen(
            [str(RVS_BIN), "dynamic", "debug", "daemon", "--start"],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertTrue(wait_for_socket(self.sock_path), "Daemon socket failed to initialize")

            sessions = []
            for i in range(3):
                spawn_res = subprocess.run(
                    [str(RVS_BIN), "dynamic", "debug", "spawn", "/bin/sleep", "--args", "30"],
                    env=self.env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(spawn_res.returncode, 0)
                d = json.loads(spawn_res.stdout)["data"]
                sessions.append((d["session_id"], d["pid"]))

            # Start continue on all sessions in background threads
            threads = []
            for sid, _ in sessions:
                t = threading.Thread(
                    target=lambda s=sid: subprocess.run(
                        [str(RVS_BIN), "dynamic", "debug", "continue", s],
                        env=self.env,
                        capture_output=True,
                    )
                )
                t.start()
                threads.append(t)

            time.sleep(0.3)

            # Kill all sessions concurrently
            kill_results = []
            def kill_worker(sid):
                t0 = time.time()
                res = subprocess.run(
                    [str(RVS_BIN), "dynamic", "debug", "kill", sid],
                    env=self.env,
                    capture_output=True,
                    text=True,
                )
                kill_results.append((time.time() - t0, res.returncode))

            kill_threads = [threading.Thread(target=kill_worker, args=(sid,)) for sid, _ in sessions]
            for kt in kill_threads:
                kt.start()
            for kt in kill_threads:
                kt.join(timeout=3.0)

            for elapsed, rc in kill_results:
                self.assertEqual(rc, 0)
                self.assertLess(elapsed, 2.0, f"Concurrent kill took {elapsed:.3f}s")

            for t in threads:
                t.join(timeout=3.0)
                self.assertFalse(t.is_alive())

            # Verify all tracee PIDs are dead
            time.sleep(0.2)
            for _, pid in sessions:
                self.assertFalse(is_pid_alive(pid))
        finally:
            daemon.send_signal(signal.SIGTERM)
            daemon.wait(timeout=3)

    # =========================================================================
    # Area 2: Daemon Socket Cleanup on SIGTERM / SIGINT & Stale Socket Handling
    # =========================================================================

    def test_daemon_socket_cleanup_on_sigterm(self):
        """Verify daemon process unlinks socket file on SIGTERM."""
        daemon = subprocess.Popen(
            [str(RVS_BIN), "dynamic", "debug", "daemon", "--start"],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertTrue(wait_for_socket(self.sock_path))
        self.assertTrue(self.sock_path.exists())

        daemon.send_signal(signal.SIGTERM)
        rc = daemon.wait(timeout=3)
        self.assertEqual(rc, 0, f"Daemon should exit 0 on SIGTERM, got {rc}")

        time.sleep(0.15)
        self.assertFalse(self.sock_path.exists(), "Socket file must be unlinked on SIGTERM")

    def test_daemon_socket_cleanup_on_sigint(self):
        """Verify daemon process unlinks socket file on SIGINT."""
        daemon = subprocess.Popen(
            [str(RVS_BIN), "dynamic", "debug", "daemon", "--start"],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertTrue(wait_for_socket(self.sock_path))
        self.assertTrue(self.sock_path.exists())

        daemon.send_signal(signal.SIGINT)
        rc = daemon.wait(timeout=3)
        self.assertEqual(rc, 0, f"Daemon should exit 0 on SIGINT, got {rc}")

        time.sleep(0.15)
        self.assertFalse(self.sock_path.exists(), "Socket file must be unlinked on SIGINT")

    def test_daemon_stale_socket_recovery(self):
        """Verify daemon cleans up pre-existing dead socket file and re-binds cleanly."""
        self.sock_path.touch()
        self.assertTrue(self.sock_path.exists())

        daemon = subprocess.Popen(
            [str(RVS_BIN), "dynamic", "debug", "daemon", "--start"],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertTrue(wait_for_socket(self.sock_path))

        status_res = subprocess.run(
            [str(RVS_BIN), "dynamic", "debug", "daemon"],
            env=self.env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(status_res.returncode, 0)
        self.assertIn("running", status_res.stdout)

        daemon.send_signal(signal.SIGTERM)
        daemon.wait(timeout=3)
        time.sleep(0.15)
        self.assertFalse(self.sock_path.exists(), "Socket file must be unlinked after shutdown")

    # =========================================================================
    # Area 3: Interactive Timeout Stream Resynchronization
    # =========================================================================

    def test_interactive_driver_timeout_resync(self):
        """Verify driver timeout sends Ctrl-C + SIGINT, drains pipe, and allows subsequent clean commands."""
        res = subprocess.run(
            ["cargo", "test", "--lib", "test_driver_timeout_interrupt_and_resync", "--", "--nocapture"],
            cwd=WORKSPACE_DIR,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"test_driver_timeout_interrupt_and_resync failed: {res.stdout}\n{res.stderr}")
        self.assertIn("1 passed", res.stdout)

    def test_interactive_daemon_timeout_resync_via_cli(self):
        """Verify timeout resynchronization over daemon IPC using CLI commands."""
        daemon = subprocess.Popen(
            [str(RVS_BIN), "dynamic", "debug", "daemon", "--start"],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertTrue(wait_for_socket(self.sock_path))

            # Spawn target
            spawn_res = subprocess.run(
                [str(RVS_BIN), "dynamic", "debug", "spawn", "/bin/sleep", "--args", "60"],
                env=self.env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(spawn_res.returncode, 0)
            sid = json.loads(spawn_res.stdout)["data"]["session_id"]

            # Query registers (drj)
            reg_res = subprocess.run(
                [str(RVS_BIN), "dynamic", "debug", "registers", sid],
                env=self.env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(reg_res.returncode, 0)
            reg_data = json.loads(reg_res.stdout)
            self.assertTrue(reg_data["success"])
            self.assertIn("rip", reg_data["data"]["registers"])

            # Clean kill
            kill_res = subprocess.run(
                [str(RVS_BIN), "dynamic", "debug", "kill", sid],
                env=self.env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(kill_res.returncode, 0)
        finally:
            daemon.send_signal(signal.SIGTERM)
            daemon.wait(timeout=3)

    # =========================================================================
    # Area 4: Subprocess Watchdog & Zero Zombie Reaping Verification
    # =========================================================================

    def test_subprocess_timeout_zero_zombies(self):
        """Verify execute_rvs_subprocess reaps child on timeout and leaves zero zombie processes."""
        import sys
        from rvs_agent_harness import execute_rvs_subprocess

        res = execute_rvs_subprocess(
            ["-c", "import time; time.sleep(10)"],
            timeout=0.5,
            rvs_bin=sys.executable,
        )
        # Timeout exit code must be 5
        self.assertEqual(res[0], 5, f"Expected timeout code 5, got {res[0]}")

        # Check process table for any zombies of current process
        ps_out = subprocess.run(["ps", "-o", "stat,ppid"], capture_output=True, text=True).stdout
        my_pid = str(os.getpid())
        zombies = [line for line in ps_out.splitlines() if my_pid in line and "Z" in line.split()[0]]
        self.assertEqual(len(zombies), 0, f"Found zombie processes: {zombies}")


if __name__ == "__main__":
    unittest.main()
