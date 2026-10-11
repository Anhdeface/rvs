#!/usr/bin/env python3
"""
tests/test_challenger_m1_it2_subprocess_lifecycle.py - Empirical Challenger M1 Iteration 2 Test Suite.

Adversarially tests:
1. Subprocess lifecycle, process group detachment, and orphan prevention under SIGTERM and SIGINT.
2. Deep process trees with descendant processes (grand-children, sleep commands, subshells) that ignore SIGTERM.
3. Multithreaded concurrent subprocess execution terminated abruptly by SIGTERM.
4. Signal storm resilience (rapid consecutive signals).
5. Signal handler lock re-entrancy and self-deadlock vulnerabilities in _SUBPROCESS_REGISTRY_LOCK.
6. Exit code taxonomy conformance {0..6} under termination signals.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import List

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
HARNESS_PATH = WORKSPACE_DIR / "rvs_agent_harness.py"


def get_lingering_processes(marker: str) -> List[str]:
    """Inspect OS process table for any process matching marker that is not python runner or grep."""
    ps = subprocess.run(["ps", "-eo", "pid,ppid,pgid,stat,comm,args"], capture_output=True, text=True)
    return [
        line for line in ps.stdout.splitlines()
        if marker in line and "python" not in line and "defunct" not in line
    ]


def kill_lingering(marker: str) -> None:
    """Safety cleanup for any lingering processes."""
    for line in get_lingering_processes(marker):
        try:
            pid = int(line.strip().split()[0])
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass


class TestSubprocessLifecycleAndSignalHandling(unittest.TestCase):
    """Adversarial challenge for subprocess lifecycle, _ACTIVE_SUBPROCESS_PGIDS, and signal cleanup."""

    def test_01_descendant_tree_ignoring_sigterm_killed_by_sigterm(self) -> None:
        """
        Adversarial test: Subprocess spawns grand-children and ignores SIGTERM.
        When harness receives SIGTERM, the entire process group must be killed with SIGKILL,
        leaving zero orphaned children or grand-children.
        """
        marker = f"m1_term_{int(time.time() * 1000)}"
        script_file = tempfile.NamedTemporaryFile(suffix=f"_{marker}.sh", mode="w", delete=False)
        # Deep tree: parent traps TERM, spawns background child that traps TERM, which spawns sleep
        script_file.write(
            f"#!/bin/bash\n"
            f"trap '' TERM\n"
            f"(trap '' TERM; sleep 120) &\n"
            f"sleep 120 &\n"
            f"wait\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        env = dict(os.environ)
        env["RVS_BIN"] = script_file.name

        try:
            proc = subprocess.Popen(
                [sys.executable, str(HARNESS_PATH), "info"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait until script process appears in process table
            started = False
            for _ in range(50):
                time.sleep(0.05)
                if len(get_lingering_processes(marker)) >= 1:
                    started = True
                    break
            self.assertTrue(started, "Target script process failed to start within 2.5s")

            # Let child and grand-children spawn
            time.sleep(0.2)

            # Send SIGTERM to harness process
            proc.send_signal(signal.SIGTERM)
            ret = proc.wait(timeout=5.0)

            # Harness exit code must normalize to EXIT_INTERNAL_ERROR (6)
            self.assertEqual(ret, 6, f"Expected harness return code 6, got {ret}")

            # Verify no orphan processes remain in OS table
            time.sleep(0.2)
            lingering = get_lingering_processes(marker)
            self.assertEqual(lingering, [], f"Orphaned descendant processes found after SIGTERM: {lingering}")
        finally:
            if "proc" in locals() and proc:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            kill_lingering(marker)
            if os.path.exists(script_file.name):
                os.unlink(script_file.name)

    def test_02_descendant_tree_ignoring_sigterm_killed_by_sigint(self) -> None:
        """
        Adversarial test: Subprocess spawns grand-children and ignores SIGTERM/SIGINT.
        When harness receives SIGINT, the entire process group must be killed with SIGKILL,
        leaving zero orphaned children or grand-children.
        """
        marker = f"m1_int_{int(time.time() * 1000)}"
        script_file = tempfile.NamedTemporaryFile(suffix=f"_{marker}.sh", mode="w", delete=False)
        script_file.write(
            f"#!/bin/bash\n"
            f"trap '' TERM INT\n"
            f"(trap '' TERM INT; sleep 120) &\n"
            f"sleep 120 &\n"
            f"wait\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        env = dict(os.environ)
        env["RVS_BIN"] = script_file.name

        try:
            proc = subprocess.Popen(
                [sys.executable, str(HARNESS_PATH), "info"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            started = False
            for _ in range(50):
                time.sleep(0.05)
                if len(get_lingering_processes(marker)) >= 1:
                    started = True
                    break
            self.assertTrue(started, "Target script process failed to start within 2.5s")

            time.sleep(0.2)

            # Send SIGINT to harness process
            proc.send_signal(signal.SIGINT)
            ret = proc.wait(timeout=5.0)

            # Exit code must normalize to 6
            self.assertEqual(ret, 6, f"Expected harness return code 6, got {ret}")

            time.sleep(0.2)
            lingering = get_lingering_processes(marker)
            self.assertEqual(lingering, [], f"Orphaned descendant processes found after SIGINT: {lingering}")
        finally:
            if "proc" in locals() and proc:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            kill_lingering(marker)
            if os.path.exists(script_file.name):
                os.unlink(script_file.name)

    def test_03_concurrent_multithreaded_subprocesses_killed_by_sigterm(self) -> None:
        """
        Adversarial stress test: Python harness runs 8 concurrent worker threads,
        each executing a subprocess with a distinct PGID in _ACTIVE_SUBPROCESS_PGIDS.
        When parent receives SIGTERM, ALL active process groups must be killed simultaneously.
        """
        marker = f"m1_conc_{int(time.time() * 1000)}"
        script_file = tempfile.NamedTemporaryFile(suffix=f"_{marker}.sh", mode="w", delete=False)
        script_file.write(
            f"#!/bin/bash\n"
            f"sleep 120 &\n"
            f"wait\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        runner_script = tempfile.NamedTemporaryFile(suffix=f"_{marker}_runner.py", mode="w", delete=False)
        runner_script.write(
            f"import os, sys, threading, time\n"
            f"sys.path.insert(0, '{WORKSPACE_DIR}')\n"
            f"from rvs_agent_harness import execute_rvs_subprocess\n"
            f"from pathlib import Path\n"
            f"def worker(idx):\n"
            f"    execute_rvs_subprocess([str(idx)], timeout=60.0, rvs_bin=Path('{script_file.name}'))\n"
            f"threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]\n"
            f"for t in threads: t.start()\n"
            f"for t in threads: t.join()\n"
        )
        runner_script.close()

        try:
            proc = subprocess.Popen(
                [sys.executable, runner_script.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait until at least 4 child processes appear
            started = False
            for _ in range(60):
                time.sleep(0.05)
                if len(get_lingering_processes(marker)) >= 4:
                    started = True
                    break
            self.assertTrue(started, "Concurrent child processes failed to start within 3s")

            # Send SIGTERM to the runner harness
            proc.send_signal(signal.SIGTERM)
            ret = proc.wait(timeout=5.0)
            self.assertEqual(ret, 6, f"Expected exit code 6, got {ret}")

            time.sleep(0.3)
            lingering = get_lingering_processes(marker)
            self.assertEqual(lingering, [], f"Lingering concurrent processes found after SIGTERM: {lingering}")
        finally:
            if "proc" in locals() and proc:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            kill_lingering(marker)
            for p in (script_file.name, runner_script.name):
                if os.path.exists(p):
                    os.unlink(p)

    def test_04_signal_storm_rapid_consecutive_signals_no_crash(self) -> None:
        """
        Adversarial test: Send rapid consecutive signals (SIGTERM followed by SIGINT within 5ms).
        Verify process reaps all children and exits cleanly without hanging or unhandled errors.
        """
        marker = f"m1_storm_{int(time.time() * 1000)}"
        script_file = tempfile.NamedTemporaryFile(suffix=f"_{marker}.sh", mode="w", delete=False)
        script_file.write(
            f"#!/bin/bash\n"
            f"sleep 120 &\n"
            f"wait\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        env = dict(os.environ)
        env["RVS_BIN"] = script_file.name

        try:
            proc = subprocess.Popen(
                [sys.executable, str(HARNESS_PATH), "info"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            for _ in range(50):
                time.sleep(0.05)
                if len(get_lingering_processes(marker)) >= 1:
                    break

            # Signal storm
            proc.send_signal(signal.SIGTERM)
            time.sleep(0.005)
            try:
                proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass

            ret = proc.wait(timeout=5.0)
            self.assertIn(ret, (6, -signal.SIGINT, -signal.SIGTERM), f"Unexpected returncode {ret}")

            time.sleep(0.2)
            lingering = get_lingering_processes(marker)
            self.assertEqual(lingering, [], f"Lingering processes after signal storm: {lingering}")
        finally:
            if "proc" in locals() and proc:
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            kill_lingering(marker)
            if os.path.exists(script_file.name):
                os.unlink(script_file.name)

    def test_05_stress_10_iterations_rapid_spawn_and_kill(self) -> None:
        """
        Stress test: 10 rapid sequential spawn-and-SIGTERM iterations.
        Ensures zero cumulative leaks or orphan processes across rapid lifecycles.
        """
        marker = f"m1_seq_{int(time.time() * 1000)}"
        script_file = tempfile.NamedTemporaryFile(suffix=f"_{marker}.sh", mode="w", delete=False)
        script_file.write(
            f"#!/bin/bash\n"
            f"sleep 120 &\n"
            f"wait\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        env = dict(os.environ)
        env["RVS_BIN"] = script_file.name

        try:
            for i in range(10):
                proc = subprocess.Popen(
                    [sys.executable, str(HARNESS_PATH), "info"],
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                # Wait until process is active
                for _ in range(30):
                    time.sleep(0.02)
                    if len(get_lingering_processes(marker)) >= 1:
                        break

                proc.send_signal(signal.SIGTERM)
                ret = proc.wait(timeout=3.0)
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                self.assertEqual(ret, 6, f"Iteration {i} returned {ret} instead of 6")

            time.sleep(0.2)
            lingering = get_lingering_processes(marker)
            self.assertEqual(lingering, [], f"Lingering processes after rapid iterations: {lingering}")
        finally:
            kill_lingering(marker)
            if os.path.exists(script_file.name):
                os.unlink(script_file.name)

    def test_06_atexit_cleanup_when_subprocesses_active_at_exit(self) -> None:
        """
        Adversarial test: A script registers a child in _ACTIVE_SUBPROCESS_PGIDS and exits normally.
        atexit._cleanup_lingering_subprocesses() must terminate the child.
        """
        marker = f"m1_atexit_{int(time.time() * 1000)}"
        child_sh = tempfile.NamedTemporaryFile(suffix=f"_{marker}.sh", mode="w", delete=False)
        child_sh.write(
            f"#!/bin/bash\n"
            f"sleep 120 &\n"
            f"wait\n"
        )
        child_sh.close()
        os.chmod(child_sh.name, 0o755)

        runner_py = tempfile.NamedTemporaryFile(suffix=f"_{marker}_run.py", mode="w", delete=False)
        runner_py.write(
            f"import subprocess, sys, time\n"
            f"sys.path.insert(0, '{WORKSPACE_DIR}')\n"
            f"from rvs_agent_harness import _ACTIVE_SUBPROCESS_PGIDS, _SUBPROCESS_REGISTRY_LOCK\n"
            f"p = subprocess.Popen(['{child_sh.name}'], start_new_session=True)\n"
            f"with _SUBPROCESS_REGISTRY_LOCK:\n"
            f"    _ACTIVE_SUBPROCESS_PGIDS.add(p.pid)\n"
            f"time.sleep(0.2)\n"
            f"sys.exit(0)\n"
        )
        runner_py.close()

        try:
            res = subprocess.run([sys.executable, runner_py.name], capture_output=True, timeout=5.0)
            self.assertEqual(res.returncode, 0)

            time.sleep(0.2)
            lingering = get_lingering_processes(marker)
            self.assertEqual(lingering, [], f"Child process not cleaned up by atexit: {lingering}")
        finally:
            kill_lingering(marker)
            for p in (child_sh.name, runner_py.name):
                if os.path.exists(p):
                    os.unlink(p)

    def test_07_lock_reentrancy_deadlock_when_signal_arrives_during_registry_mutation(self) -> None:
        """
        Adversarial defect check:
        If a signal arrives on the main thread while _SUBPROCESS_REGISTRY_LOCK is acquired,
        _cleanup_lingering_subprocesses() must NOT deadlock the main thread.
        
        Currently _SUBPROCESS_REGISTRY_LOCK is a non-reentrant threading.Lock().
        When signal handler runs on the thread holding the lock, it deadlocks trying to acquire it.
        """
        runner_py = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False)
        runner_py.write(
            f"import os, signal, sys, time\n"
            f"sys.path.insert(0, '{WORKSPACE_DIR}')\n"
            f"from rvs_agent_harness import _SUBPROCESS_REGISTRY_LOCK\n"
            f"# Simulate signal arriving while lock is held\n"
            f"with _SUBPROCESS_REGISTRY_LOCK:\n"
            f"    os.kill(os.getpid(), signal.SIGTERM)\n"
            f"print('SURVIVED_LOCK')\n"
        )
        runner_py.close()

        try:
            # Strict 3-second timeout
            p = subprocess.Popen([sys.executable, runner_py.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ret = p.wait(timeout=3.0)
                # If it doesn't deadlock, it should exit with return code 6
                self.assertEqual(ret, 6, f"Expected returncode 6 on SIGTERM, got {ret}")
            except subprocess.TimeoutExpired:
                p.kill()
                self.fail(
                    "DEADLOCK DETECTED: _SUBPROCESS_REGISTRY_LOCK is a non-reentrant threading.Lock(). "
                    "When SIGTERM/SIGINT is delivered to the thread holding the lock, "
                    "_cleanup_lingering_subprocesses() deadlocks with itself, hanging the process forever."
                )
        finally:
            if "p" in locals() and p:
                if p.stdout:
                    p.stdout.close()
                if p.stderr:
                    p.stderr.close()
            if os.path.exists(runner_py.name):
                os.unlink(runner_py.name)

    def test_08_subprocesses_orphaned_when_signal_deadlocks_lock(self) -> None:
        """
        Adversarial defect check:
        Empirically prove that when SIGTERM arrives while _SUBPROCESS_REGISTRY_LOCK is held,
        the resulting deadlock leaves the child process running as an orphan in the OS.
        """
        marker = f"m1_orphan_proof_{int(time.time() * 1000)}"
        child_sh = tempfile.NamedTemporaryFile(suffix=f"_{marker}.sh", mode="w", delete=False)
        child_sh.write(
            f"#!/bin/bash\n"
            f"sleep 120 &\n"
            f"wait\n"
        )
        child_sh.close()
        os.chmod(child_sh.name, 0o755)

        runner_py = tempfile.NamedTemporaryFile(suffix=f"_{marker}_run.py", mode="w", delete=False)
        runner_py.write(
            f"import os, signal, sys, time, subprocess\n"
            f"sys.path.insert(0, '{WORKSPACE_DIR}')\n"
            f"from rvs_agent_harness import _ACTIVE_SUBPROCESS_PGIDS, _SUBPROCESS_REGISTRY_LOCK\n"
            f"p = subprocess.Popen(['{child_sh.name}'], start_new_session=True)\n"
            f"with _SUBPROCESS_REGISTRY_LOCK:\n"
            f"    _ACTIVE_SUBPROCESS_PGIDS.add(p.pid)\n"
            f"    # Deliver signal while lock is held\n"
            f"    os.kill(os.getpid(), signal.SIGTERM)\n"
        )
        runner_py.close()

        try:
            p = subprocess.Popen([sys.executable, runner_py.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(0.5)

            # Check if harness is deadlocked (still alive after 0.5s)
            is_deadlocked = (p.poll() is None)
            
            # Check if child process is running
            lingering = get_lingering_processes(marker)

            if is_deadlocked and len(lingering) > 0:
                p.kill()
                self.fail(
                    f"CONFIRMED BUG: Child process {lingering} orphaned due to signal handler self-deadlock "
                    f"on non-reentrant _SUBPROCESS_REGISTRY_LOCK."
                )
        finally:
            if "p" in locals() and p:
                if p.stdout:
                    p.stdout.close()
                if p.stderr:
                    p.stderr.close()
            kill_lingering(marker)
            for path in (child_sh.name, runner_py.name):
                if os.path.exists(path):
                    os.unlink(path)


if __name__ == "__main__":
    unittest.main()
