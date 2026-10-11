#!/usr/bin/env python3
"""
tests/test_challenger_m1_1_concurrency_lifecycle.py - Empirical Challenger M1.1 Test Suite.

Authored by teamwork_preview_challenger_m1_1 (Concurrency & Process Lifecycle Challenger).
Focus Areas:
1. Concurrency and thread safety under 20+ simultaneous threads calling RvsHarness methods.
2. Cross-thread isolation of orchestration state (_in_orchestration / _ORCHESTRATION_CONTEXT).
3. Process lifecycle, process group cleanup, signal handling, and zero zombie/orphan processes.
4. Exit code taxonomic normalization invariant across all signal and panic codes.
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
from typing import List, Tuple
from unittest.mock import patch

from rvs_agent_harness import (
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    RvsHarness,
    execute_rvs_subprocess,
    normalize_exit_code,
)
from tests.fixtures_builder import create_synthetic_apk

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
CRACKME_PATH = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
AUTH_GATE_PATH = WORKSPACE_DIR / "tests" / "fixtures" / "auth_gate_elf64"


class TestM1ConcurrencyAndThreadSafety(unittest.TestCase):
    """Adversarial stress testing of RvsHarness thread safety and concurrency."""

    def setUp(self) -> None:
        self.harness = RvsHarness()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="rvs_m1_challenger_")
        self.apk_path = Path(self.temp_dir.name) / "sample_test.apk"
        create_synthetic_apk(self.apk_path, multidex=True)

    def tearDown(self) -> None:
        self.harness.close()
        self.temp_dir.cleanup()

    def test_01_concurrent_20_threads_shared_harness_read_mutate(self) -> None:
        """20 concurrent threads calling RvsHarness methods and mutating sessions on shared instance."""
        errors: List[Tuple[int, Exception]] = []
        barrier = threading.Barrier(20)

        def worker(tid: int) -> None:
            try:
                barrier.wait(timeout=5.0)
                for i in range(10):
                    op = (tid + i) % 6
                    if op == 0:
                        res = self.harness.info(CRACKME_PATH)
                        self.assertTrue(res.get("success"), f"Thread {tid} info failed: {res}")
                    elif op == 1:
                        res = self.harness.functions(CRACKME_PATH, limit=5)
                        self.assertTrue(res.get("success"), f"Thread {tid} functions failed: {res}")
                    elif op == 2:
                        res = self.harness.strings(CRACKME_PATH, min_len=4, limit=10)
                        self.assertTrue(res.get("success"), f"Thread {tid} strings failed: {res}")
                    elif op == 3:
                        sess = self.harness.get_session(CRACKME_PATH)
                        self.assertIsInstance(sess, dict)
                    elif op == 4:
                        self.harness.clear_session(CRACKME_PATH)
                    elif op == 5:
                        self.harness.clear_session(None)
            except Exception as e:
                errors.append((tid, e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        self.assertEqual(len(errors), 0, f"Concurrent threads encountered errors: {errors}")

    def test_02_concurrent_20_threads_debug_session_state(self) -> None:
        """20 threads simultaneously mutating and resolving active debug sessions."""
        errors: List[Tuple[int, Exception]] = []
        barrier = threading.Barrier(20)

        def worker(tid: int) -> None:
            try:
                barrier.wait(timeout=5.0)
                for i in range(20):
                    sid = f"sess_{tid}_{i}"
                    # Mutate under harness lock
                    with self.harness._lock:
                        self.harness._active_debug_sessions.add(sid)
                        self.harness._most_recent_session_id = sid

                    # Resolve session concurrently
                    resolved = self.harness._resolve_debug_session(None)
                    self.assertIsNotNone(resolved)

                    with self.harness._lock:
                        self.harness._active_debug_sessions.discard(sid)
            except Exception as e:
                errors.append((tid, e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)

        self.assertEqual(len(errors), 0, f"Debug session concurrency errors: {errors}")

    def test_03_orchestration_context_isolation_across_threads(self) -> None:
        """Verify that execute_tool() on APK does not permanently set _in_orchestration on shared harness."""
        h = RvsHarness()
        self.assertFalse(h._is_in_orchestration())

        # Execute APK query via execute_tool (which uses NeutralBinaryOrchestrator)
        res1 = h.execute_tool("rvs_info", {"file": str(self.apk_path)})
        self.assertTrue(res1.get("success"), f"execute_tool failed: {res1}")

        # The harness instance MUST NOT retain _in_orchestration = True after execute_tool returns!
        self.assertFalse(
            h._is_in_orchestration(),
            "RvsHarness._is_in_orchestration() remained True after execute_tool() returned! "
            "This causes subsequent calls to bypass the orchestrator.",
        )

        # Subsequent direct info() on APK must succeed and contain extracted format/arch metadata
        res2 = h.info(self.apk_path)
        self.assertTrue(res2.get("success"), f"h.info(apk) failed: {res2}")
        data = res2.get("data") or {}
        self.assertTrue(
            bool(data.get("format")),
            f"h.info(apk) returned empty metadata due to state bleed: {data}",
        )

    def test_08_concurrent_mixed_target_load_no_bleed(self) -> None:
        """20 threads concurrently calling execute_tool and direct harness methods on mixed targets."""
        failures: List[Tuple[int, str, Any]] = []
        barrier = threading.Barrier(20)

        def orch_worker(tid: int) -> None:
            try:
                barrier.wait(timeout=5.0)
                for _ in range(5):
                    res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
                    if not res.get("success"):
                        failures.append((tid, "execute_tool failed", res))
            except Exception as e:
                failures.append((tid, "exception", e))

        def direct_worker(tid: int) -> None:
            try:
                barrier.wait(timeout=5.0)
                for _ in range(5):
                    res = self.harness.info(self.apk_path)
                    if not res.get("success"):
                        failures.append((tid, "info failed", res))
                    data = res.get("data") or {}
                    if not data.get("format"):
                        failures.append((tid, "info returned empty format", res))
            except Exception as e:
                failures.append((tid, "exception", e))

        threads = []
        for t in range(10):
            threads.append(threading.Thread(target=orch_worker, args=(t,)))
            threads.append(threading.Thread(target=direct_worker, args=(10 + t,)))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        self.assertEqual(
            len(failures),
            0,
            f"20-thread mixed load encountered failures due to state bleed: {failures[:5]}",
        )


class TestM1ProcessLifecycleAndSignalHandling(unittest.TestCase):
    """Adversarial testing of process group cleanup, signal handling, and zombie prevention."""

    def test_04_process_group_cleanup_and_escalation_on_timeout(self) -> None:
        """A subprocess ignoring SIGTERM must be killed with SIGKILL and reaped without zombies."""
        script_file = tempfile.NamedTemporaryFile(suffix=".sh", mode="w", delete=False)
        script_file.write(
            "#!/bin/bash\n"
            "trap '' TERM\n"
            "sleep 30 &\n"
            "wait\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        try:
            start_t = time.time()
            code, out, err, dur = execute_rvs_subprocess(
                [], timeout=0.2, rvs_bin=Path(script_file.name)
            )
            elapsed = time.time() - start_t

            self.assertEqual(code, EXIT_TIMEOUT_ERROR)
            self.assertLess(elapsed, 3.0, "Watchdog took too long to escalate to SIGKILL")

            # Check that neither the script nor the child sleep 30 is still running or zombie
            time.sleep(0.1)
            ps_res = subprocess.run(["ps", "-eo", "pid,stat,comm,args"], capture_output=True, text=True)
            dangling = [
                l for l in ps_res.stdout.splitlines()
                if (script_file.name in l or "sleep 30" in l) and "python" not in l
            ]
            self.assertEqual(dangling, [], f"Lingering process found after timeout: {dangling}")

            # Verify no defunct processes
            zombies = [l for l in dangling if "Z" in l.split()[1]]
            self.assertEqual(zombies, [], f"Zombie processes detected: {zombies}")
        finally:
            if os.path.exists(script_file.name):
                os.unlink(script_file.name)

    def test_05_process_group_cleanup_on_keyboard_interrupt(self) -> None:
        """Simulated KeyboardInterrupt must kill process group with SIGKILL and reap process."""
        script_file = tempfile.NamedTemporaryFile(suffix=".sh", mode="w", delete=False)
        script_file.write(
            "#!/bin/bash\n"
            "sleep 30 &\n"
            "wait\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        try:
            with patch("subprocess.Popen.communicate", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    execute_rvs_subprocess([], timeout=10.0, rvs_bin=Path(script_file.name))

            time.sleep(0.1)
            ps_res = subprocess.run(["ps", "-eo", "pid,stat,comm,args"], capture_output=True, text=True)
            dangling = [
                l for l in ps_res.stdout.splitlines()
                if (script_file.name in l or "sleep 30" in l) and "python" not in l
            ]
            self.assertEqual(dangling, [], f"Lingering process after KeyboardInterrupt: {dangling}")
        finally:
            if os.path.exists(script_file.name):
                os.unlink(script_file.name)

    def test_06_sigterm_to_harness_does_not_orphan_children(self) -> None:
        """Sending SIGTERM to harness process must not leave child subprocess running as an orphan."""
        script_file = tempfile.NamedTemporaryFile(suffix=".sh", mode="w", delete=False)
        script_file.write(
            "#!/bin/bash\n"
            "sleep 30\n"
        )
        script_file.close()
        os.chmod(script_file.name, 0o755)

        harness_script = str(WORKSPACE_DIR / "rvs_agent_harness.py")
        env = dict(os.environ)
        env["RVS_BIN"] = script_file.name

        try:
            proc = subprocess.Popen(
                [sys.executable, harness_script, "info"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(0.5)  # Let harness spawn child

            # Terminate the harness process with SIGTERM
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=3.0)

            time.sleep(0.2)
            ps_res = subprocess.run(["ps", "-eo", "pid,stat,comm,args"], capture_output=True, text=True)
            orphans = [
                l for l in ps_res.stdout.splitlines()
                if (script_file.name in l or "sleep 30" in l) and "python" not in l
            ]
            # Clean up immediately if any orphans were found
            for o in orphans:
                try:
                    os.kill(int(o.split()[0]), signal.SIGKILL)
                except Exception:
                    pass

            self.assertEqual(
                orphans,
                [],
                f"Child processes orphaned after harness received SIGTERM: {orphans}",
            )
        finally:
            if "proc" in locals():
                if proc.stdout and not proc.stdout.closed:
                    proc.stdout.close()
                if proc.stderr and not proc.stderr.closed:
                    proc.stderr.close()
            if os.path.exists(script_file.name):
                os.unlink(script_file.name)

    def test_07_exit_code_normalization_taxonomy(self) -> None:
        """normalize_exit_code() strictly guarantees output belongs to {0..6}."""
        valid_codes = {
            EXIT_SUCCESS: 0,
            EXIT_INVALID_ARGUMENT: 1,
            EXIT_FILE_ERROR: 2,
            EXIT_ANALYSIS_ERROR: 3,
            EXIT_PATCH_ERROR: 4,
            EXIT_TIMEOUT_ERROR: 5,
            EXIT_INTERNAL_ERROR: 6,
        }
        for code, expected in valid_codes.items():
            self.assertEqual(normalize_exit_code(code), expected)

        # Signals and abnormal exit codes MUST normalize to EXIT_INTERNAL_ERROR (6)
        abnormal_codes = [-11, -9, -15, -1, -6, 7, 8, 101, 127, 137, 139, 245, 255]
        for code in abnormal_codes:
            self.assertEqual(
                normalize_exit_code(code),
                EXIT_INTERNAL_ERROR,
                f"Raw exit code {code} failed to normalize to EXIT_INTERNAL_ERROR (6)",
            )


if __name__ == "__main__":
    unittest.main()
