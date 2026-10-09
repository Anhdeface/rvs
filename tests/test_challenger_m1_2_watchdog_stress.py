"""
tests/test_challenger_m1_2_watchdog_stress.py - Empirical Stress & Watchdog Leak Test Suite.

Authored by teamwork_preview_challenger_m1_2 (Watchdog & Leak Challenger).
Empirically stress-tests the 6-Tier Ephemeral Watchdog in neutral_orchestrator/target_ingestion.py:
1. High-throughput sequential ingestion (50 synthetic APKs with normal context exit).
2. High-throughput exception-laden ingestion (50 synthetic APKs with unhandled exceptions inside context).
3. High-throughput GC collection finalization (50 synthetic APKs unreferenced and collected via gc.collect()).
4. Cyclic reference GC collection finalization.
5. Multithreaded concurrent high-throughput stress test (100 parallel ingestions/cleanups).
6. Resilient deletion against restricted / read-only filesystem attributes (chmod 0400 / 0500).
7. Tier 4 subprocess atexit registration and automated cleanup.
8. Tier 5 subprocess signal trapping (SIGTERM) directory reclamation.
9. Tier 5 subprocess signal trapping (SIGINT) directory reclamation.
10. Ingestion failure cleanup under Zip Slip attacks (SecurityViolationError).
11. Ingestion failure cleanup under corrupted / malformed archives (MalformedPackageError).
12. Stress 50 rapid-fire adversarial failures (Zip Slip + Corrupt APKs).
13. Lifecycle re-entry rejection and multiple idempotent cleanup invocations.
14. Tier 6 TTL orphan sweeping and protection of actively tracked directories.
15. Global zero-leak verification across /tmp/rvs_target_*.
"""

from __future__ import annotations

import gc
import glob
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from typing import List, Set

from neutral_orchestrator.target_ingestion import (
    EPHEMERAL_DIR_PREFIX,
    MalformedPackageError,
    SecurityViolationError,
    UnifiedTarget,
    _ACTIVE_EPHEMERAL_DIRS,
    _REGISTRY_LOCK,
    cleanup_ephemeral_dir,
    create_ephemeral_dir,
    ingest_target,
    sweep_orphaned_target_dirs,
)
from tests.fixtures_builder import create_corrupted_apk, create_synthetic_apk


class EphemeralWatchdogStressTests(unittest.TestCase):
    """
    Exhaustive empirical test suite challenging the 6-Tier Ephemeral Watchdog.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.apk_file = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
        cls.apk_file.close()
        create_synthetic_apk(cls.apk_file.name, multidex=True)

        # Create zip slip fixture
        cls.zip_slip_file = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
        cls.zip_slip_file.close()
        with zipfile.ZipFile(cls.zip_slip_file.name, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 104)
            zf.writestr("../../etc/cron.d/malicious", b"echo hacked\n")

        # Create corrupted fixture
        cls.corrupted_file = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
        cls.corrupted_file.close()
        create_corrupted_apk(cls.corrupted_file.name, corruption_type="bad_zip")

    @classmethod
    def tearDownClass(cls) -> None:
        for p in (cls.apk_file.name, cls.zip_slip_file.name, cls.corrupted_file.name):
            if os.path.exists(p):
                os.unlink(p)

    def setUp(self) -> None:
        # Snapshot initial active ephemeral directories
        with _REGISTRY_LOCK:
            self._initial_active_dirs = set(_ACTIVE_EPHEMERAL_DIRS)

    def tearDown(self) -> None:
        # Ensure registry is not polluted
        with _REGISTRY_LOCK:
            new_active = _ACTIVE_EPHEMERAL_DIRS - self._initial_active_dirs
            for d in list(new_active):
                _ACTIVE_EPHEMERAL_DIRS.discard(d)
                shutil.rmtree(d, ignore_errors=True)

    def test_01_stress_50_sequential_ingestions_normal_context(self) -> None:
        """
        Ingest 50 synthetic APK targets in rapid succession under standard context management.
        Verify temp directory creation, tracking, and immediate destruction upon context exit.
        """
        created_dirs: List[str] = []

        for i in range(50):
            with ingest_target(self.apk_file.name) as target:
                self.assertIsNotNone(target.temp_dir)
                temp_dir = target.temp_dir
                created_dirs.append(temp_dir)

                # Directory must exist on disk and be tracked in _ACTIVE_EPHEMERAL_DIRS
                self.assertTrue(os.path.isdir(temp_dir), f"Iteration {i}: temp_dir does not exist on disk")
                with _REGISTRY_LOCK:
                    self.assertIn(os.path.abspath(temp_dir), _ACTIVE_EPHEMERAL_DIRS)

            # Upon exiting context manager, temp_dir must be completely eradicated
            self.assertFalse(os.path.exists(temp_dir), f"Iteration {i}: temp_dir leaked on disk")
            with _REGISTRY_LOCK:
                self.assertNotIn(os.path.abspath(temp_dir), _ACTIVE_EPHEMERAL_DIRS)

        # Confirm all 50 unique directories were destroyed
        self.assertEqual(len(set(created_dirs)), 50)
        for d in created_dirs:
            self.assertFalse(os.path.exists(d), f"Directory {d} still exists after test loop")

        with _REGISTRY_LOCK:
            active_test_dirs = _ACTIVE_EPHEMERAL_DIRS.intersection(set(created_dirs))
            self.assertEqual(len(active_test_dirs), 0)

    def test_02_stress_50_sequential_ingestions_with_unhandled_exceptions(self) -> None:
        """
        Ingest 50 synthetic APK targets in rapid succession, raising severe unhandled exceptions
        inside the context manager.
        Verify zero leaks and that exceptions are propagated correctly without suppression.
        """
        created_dirs: List[str] = []

        class SimulatedAnalysisCrash(Exception):
            pass

        for i in range(50):
            temp_dir_captured = None
            with self.assertRaises(SimulatedAnalysisCrash):
                with ingest_target(self.apk_file.name) as target:
                    temp_dir_captured = target.temp_dir
                    self.assertTrue(os.path.isdir(temp_dir_captured))
                    raise SimulatedAnalysisCrash(f"Fatal crash during analysis #{i}")

            self.assertIsNotNone(temp_dir_captured)
            created_dirs.append(temp_dir_captured)

            # Ephemeral watchdog must have cleaned up the directory despite exception
            self.assertFalse(
                os.path.exists(temp_dir_captured),
                f"Iteration {i}: directory leaked after exception: {temp_dir_captured}"
            )
            with _REGISTRY_LOCK:
                self.assertNotIn(os.path.abspath(temp_dir_captured), _ACTIVE_EPHEMERAL_DIRS)

        self.assertEqual(len(set(created_dirs)), 50)
        for d in created_dirs:
            self.assertFalse(os.path.exists(d))

        with _REGISTRY_LOCK:
            active_test_dirs = _ACTIVE_EPHEMERAL_DIRS.intersection(set(created_dirs))
            self.assertEqual(len(active_test_dirs), 0)

    def test_03_stress_50_gc_finalizer_cleanups(self) -> None:
        """
        Ingest 50 synthetic APK targets without using context manager and without calling cleanup().
        Delete the object references and trigger gc.collect() to invoke Tier 3 weakref finalizer.
        Verify 100% finalization and 0 leaked directories.
        """
        created_dirs: List[str] = []

        for i in range(50):
            target = ingest_target(self.apk_file.name)
            temp_dir = target.temp_dir
            self.assertIsNotNone(temp_dir)
            self.assertTrue(os.path.isdir(temp_dir))
            created_dirs.append(temp_dir)

            with _REGISTRY_LOCK:
                self.assertIn(os.path.abspath(temp_dir), _ACTIVE_EPHEMERAL_DIRS)

            # Sever reference and force garbage collection
            del target
            gc.collect()

            # Verify that Tier 3 weakref.finalize reaped the directory
            self.assertFalse(
                os.path.exists(temp_dir),
                f"Iteration {i}: GC finalizer failed to delete {temp_dir}"
            )
            with _REGISTRY_LOCK:
                self.assertNotIn(os.path.abspath(temp_dir), _ACTIVE_EPHEMERAL_DIRS)

        self.assertEqual(len(set(created_dirs)), 50)
        for d in created_dirs:
            self.assertFalse(os.path.exists(d))

        with _REGISTRY_LOCK:
            active_test_dirs = _ACTIVE_EPHEMERAL_DIRS.intersection(set(created_dirs))
            self.assertEqual(len(active_test_dirs), 0)

    def test_04_stress_gc_finalizer_with_circular_references(self) -> None:
        """
        Verify that Tier 3 weakref finalizers successfully clean up directories even when
        the UnifiedTarget instance is part of an uncollectible-looking cyclic reference graph.
        """
        created_dirs: List[str] = []

        for i in range(10):
            target = ingest_target(self.apk_file.name)
            temp_dir = target.temp_dir
            created_dirs.append(temp_dir)

            # Create circular references
            cycle_container = {"target": target, "nested": [target]}
            target.cycle_ref = cycle_container  # type: ignore[attr-defined]

            del target
            del cycle_container
            gc.collect()

            self.assertFalse(
                os.path.exists(temp_dir),
                f"Cycle {i}: directory leaked despite GC collection: {temp_dir}"
            )

        for d in created_dirs:
            self.assertFalse(os.path.exists(d))

    def test_05_concurrent_multithreaded_high_throughput_ingestion(self) -> None:
        """
        Stress test thread-safety of _REGISTRY_LOCK and ephemeral directory lifecycles.
        Spawns 10 concurrent threads each performing 10 ingestions (100 total) with mixed
        lifecycle paths: context manager, explicit cleanup, exceptions, and GC.
        """
        num_threads = 10
        ops_per_thread = 10
        errors: List[Exception] = []
        all_created_dirs: List[str] = []
        dirs_lock = threading.Lock()

        def worker(thread_idx: int) -> None:
            for j in range(ops_per_thread):
                try:
                    mode = (thread_idx + j) % 4
                    if mode == 0:
                        # Context manager
                        with ingest_target(self.apk_file.name) as t:
                            td = t.temp_dir
                            with dirs_lock:
                                all_created_dirs.append(td)
                            self.assertTrue(os.path.isdir(td))
                        self.assertFalse(os.path.exists(td))

                    elif mode == 1:
                        # Explicit cleanup with multiple idempotent calls
                        t = ingest_target(self.apk_file.name)
                        td = t.temp_dir
                        with dirs_lock:
                            all_created_dirs.append(td)
                        t.cleanup()
                        t.cleanup()  # Idempotent second call
                        self.assertFalse(os.path.exists(td))

                    elif mode == 2:
                        # Context manager with exception
                        td = None
                        try:
                            with ingest_target(self.apk_file.name) as t:
                                td = t.temp_dir
                                with dirs_lock:
                                    all_created_dirs.append(td)
                                raise ValueError("Thread forced error")
                        except ValueError:
                            pass
                        self.assertIsNotNone(td)
                        self.assertFalse(os.path.exists(td))

                    else:
                        # GC collection
                        t = ingest_target(self.apk_file.name)
                        td = t.temp_dir
                        with dirs_lock:
                            all_created_dirs.append(td)
                        del t
                        gc.collect()
                        self.assertFalse(os.path.exists(td))

                except Exception as exc:
                    with dirs_lock:
                        errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=30.0)

        # Assert no thread crashed or encountered race conditions
        self.assertEqual(errors, [], f"Thread errors encountered: {errors}")
        self.assertEqual(len(all_created_dirs), num_threads * ops_per_thread)

        # Confirm all directories were completely eradicated
        for d in all_created_dirs:
            self.assertFalse(os.path.exists(d), f"Concurrent directory leak: {d}")

        with _REGISTRY_LOCK:
            active_test_dirs = _ACTIVE_EPHEMERAL_DIRS.intersection(set(all_created_dirs))
            self.assertEqual(len(active_test_dirs), 0)

    def test_06_resilient_cleanup_with_readonly_and_restricted_files(self) -> None:
        """
        Verify that _shutil_rmtree_helper can aggressively delete directories containing
        read-only files (chmod 0400) and restricted directories (chmod 0500).
        """
        with ingest_target(self.apk_file.name) as target:
            temp_dir = target.temp_dir
            self.assertTrue(os.path.isdir(temp_dir))

            # Introduce restricted nested permissions
            locked_dir = Path(temp_dir) / "locked_subdir"
            locked_dir.mkdir(parents=True, exist_ok=True)

            locked_file = locked_dir / "readonly_file.dat"
            locked_file.write_bytes(b"immutable_data")

            # Make file read-only (0o400)
            os.chmod(str(locked_file), stat.S_IRUSR)
            # Make subdirectory read/execute only, no write (0o500)
            os.chmod(str(locked_dir), stat.S_IRUSR | stat.S_IXUSR)

        # Normal context exit must have successfully wiped it regardless of permissions
        self.assertFalse(os.path.exists(temp_dir))

    def test_07_subprocess_tier4_atexit_cleanup(self) -> None:
        """
        Verify Tier 4 atexit behavior in an isolated subprocess.
        The subprocess creates 5 ephemeral directories and exits immediately via sys.exit(0)
        without calling cleanup().
        The test verifies that the OS process teardown eradicates all 5 directories.
        """
        script = f"""
import sys, os
from neutral_orchestrator.target_ingestion import ingest_target

created = []
for _ in range(5):
    t = ingest_target({repr(self.apk_file.name)})
    created.append(t.temp_dir)

# Print created directories to stdout separated by newlines
for c in created:
    print(c)

# Intentionally terminate without calling cleanup or with block
sys.exit(0)
"""
        res = subprocess.run(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        self.assertEqual(res.returncode, 0, f"Subprocess failed: {res.stderr}")

        paths = [p.strip() for p in res.stdout.strip().splitlines() if p.strip()]
        self.assertEqual(len(paths), 5)

        for p in paths:
            self.assertFalse(
                os.path.exists(p),
                f"Tier 4 atexit failed to eradicate directory: {p}"
            )

    def test_08_subprocess_tier5_signal_cleanup_sigterm(self) -> None:
        """
        Verify Tier 5 signal trap handling in an isolated subprocess for SIGTERM.
        The subprocess creates 3 ephemeral directories and raises SIGTERM to itself.
        Verify that signal handler executes and deletes the ephemeral directories.
        """
        script = f"""
import os, sys, signal, time
from neutral_orchestrator.target_ingestion import ingest_target

created = []
for _ in range(3):
    t = ingest_target({repr(self.apk_file.name)})
    created.append(t.temp_dir)

for c in created:
    print(c, flush=True)

# Deliver SIGTERM to self
os.kill(os.getpid(), signal.SIGTERM)
"""
        res = subprocess.run(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        paths = [p.strip() for p in res.stdout.strip().splitlines() if p.strip()]
        self.assertEqual(len(paths), 3)

        for p in paths:
            self.assertFalse(
                os.path.exists(p),
                f"Tier 5 signal trap failed to eradicate directory upon SIGTERM: {p}"
            )

    def test_09_subprocess_tier5_signal_cleanup_sigint(self) -> None:
        """
        Verify Tier 5 signal trap handling in an isolated subprocess for SIGINT.
        The subprocess creates 3 ephemeral directories and raises SIGINT to itself.
        Verify that signal handler executes and deletes the ephemeral directories.
        """
        script = f"""
import os, sys, signal, time
from neutral_orchestrator.target_ingestion import ingest_target

created = []
for _ in range(3):
    t = ingest_target({repr(self.apk_file.name)})
    created.append(t.temp_dir)

for c in created:
    print(c, flush=True)

# Deliver SIGINT to self
os.kill(os.getpid(), signal.SIGINT)
"""
        res = subprocess.run(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        paths = [p.strip() for p in res.stdout.strip().splitlines() if p.strip()]
        self.assertEqual(len(paths), 3)

        for p in paths:
            self.assertFalse(
                os.path.exists(p),
                f"Tier 5 signal trap failed to eradicate directory upon SIGINT: {p}"
            )

    def test_10_ingestion_failure_cleanup_under_zip_slip(self) -> None:
        """
        Verify that when an ingestion attempt encounters a Zip Slip security violation,
        the temporary extraction directory created prior to the violation check is
        immediately eradicated with 0 directory leaks.
        """
        with _REGISTRY_LOCK:
            before_active = set(_ACTIVE_EPHEMERAL_DIRS)

        with self.assertRaises(SecurityViolationError):
            ingest_target(self.zip_slip_file.name)

        with _REGISTRY_LOCK:
            after_active = set(_ACTIVE_EPHEMERAL_DIRS)

        self.assertEqual(before_active, after_active)

    def test_11_ingestion_failure_cleanup_under_corrupted_archive(self) -> None:
        """
        Verify that when an ingestion attempt encounters a malformed/corrupted archive,
        the temporary extraction directory is immediately eradicated with 0 directory leaks.
        """
        with _REGISTRY_LOCK:
            before_active = set(_ACTIVE_EPHEMERAL_DIRS)

        with self.assertRaises(MalformedPackageError):
            ingest_target(self.corrupted_file.name)

        with _REGISTRY_LOCK:
            after_active = set(_ACTIVE_EPHEMERAL_DIRS)

        self.assertEqual(before_active, after_active)

    def test_12_stress_50_zip_slip_and_corrupt_ingestions(self) -> None:
        """
        Rapidly ingest 50 malicious/corrupted targets (alternating Zip Slip and Corrupted ZIPs).
        Verify that in 100% of cases, the ephemeral directory allocated during initial phase
        is wiped and de-registered, resulting in 0 directory leaks.
        """
        with _REGISTRY_LOCK:
            before_active = set(_ACTIVE_EPHEMERAL_DIRS)

        for i in range(50):
            if i % 2 == 0:
                with self.assertRaises(SecurityViolationError):
                    ingest_target(self.zip_slip_file.name)
            else:
                with self.assertRaises(MalformedPackageError):
                    ingest_target(self.corrupted_file.name)

        with _REGISTRY_LOCK:
            after_active = set(_ACTIVE_EPHEMERAL_DIRS)

        self.assertEqual(
            before_active,
            after_active,
            "Active ephemeral directory registry leaked entries after 50 failed ingestions"
        )

    def test_13_reentry_rejection_and_idempotency_post_cleanup(self) -> None:
        """
        Verify that:
        1. Calling cleanup() multiple times consecutively is completely idempotent and safe.
        2. Attempting to enter the context manager on an already cleaned up UnifiedTarget raises RuntimeError.
        """
        target = ingest_target(self.apk_file.name)
        temp_dir = target.temp_dir
        self.assertTrue(os.path.isdir(temp_dir))

        # First cleanup
        target.cleanup()
        self.assertFalse(os.path.exists(temp_dir))

        # Idempotent cleanups
        for _ in range(5):
            target.cleanup()
            target.close()

        # Re-entry must be rejected
        with self.assertRaises(RuntimeError) as cm:
            with target:
                pass
        self.assertIn("already been cleaned up", str(cm.exception))

    def test_14_tier6_ttl_orphan_sweeper_stress(self) -> None:
        """
        Verify Tier 6 orphan sweeper behavior:
        1. Sweeps abandoned directories older than TTL.
        2. Strictly preserves active directories tracked in _ACTIVE_EPHEMERAL_DIRS even if old.
        """
        base_tmp = tempfile.gettempdir()
        fake_prefix = "rvs_target_test_orphan_"

        # Create 5 artificial stale directories
        stale_dirs: List[str] = []
        for i in range(5):
            d = tempfile.mkdtemp(prefix=fake_prefix)
            Path(d, "stale.bin").write_bytes(b"stale")
            past_time = time.time() - 7200
            os.utime(d, (past_time, past_time))
            stale_dirs.append(os.path.abspath(d))

        # Create 1 actively tracked directory and fake its mtime to be ancient
        active_target = ingest_target(self.apk_file.name)
        active_dir = os.path.abspath(active_target.temp_dir)
        past_time = time.time() - 7200
        os.utime(active_dir, (past_time, past_time))

        try:
            # Run sweeper with TTL of 3600 seconds (1 hour)
            swept = sweep_orphaned_target_dirs(
                base_dir=base_tmp,
                ttl_seconds=3600.0,
                prefix="rvs_target_",
            )

            # All 5 stale directories must have been swept
            for sd in stale_dirs:
                self.assertIn(sd, swept, f"Sweeper missed stale directory: {sd}")
                self.assertFalse(os.path.exists(sd), f"Stale directory still exists: {sd}")

            # Actively tracked directory MUST NOT be swept!
            self.assertNotIn(active_dir, swept, "Active directory was incorrectly swept!")
            self.assertTrue(os.path.isdir(active_dir), "Active directory was deleted by sweeper!")

        finally:
            active_target.cleanup()
            for sd in stale_dirs:
                shutil.rmtree(sd, ignore_errors=True)

        self.assertFalse(os.path.exists(active_dir))

    def test_15_global_eradication_zero_leak_verification(self) -> None:
        """
        Global post-suite invariant check:
        Verify that no residual /tmp/rvs_target_* directories remain on disk.
        """
        matching_dirs = glob.glob(os.path.join(tempfile.gettempdir(), f"{EPHEMERAL_DIR_PREFIX}*"))
        with _REGISTRY_LOCK:
            active_dirs = list(_ACTIVE_EPHEMERAL_DIRS)

        self.assertEqual(
            active_dirs,
            [],
            f"Active registry is not empty: {active_dirs}"
        )
        self.assertEqual(
            matching_dirs,
            [],
            f"Residual /tmp/rvs_target_* directories detected on filesystem: {matching_dirs}"
        )


if __name__ == "__main__":
    unittest.main()
