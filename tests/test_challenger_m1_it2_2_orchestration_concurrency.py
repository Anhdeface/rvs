#!/usr/bin/env python3
"""
tests/test_challenger_m1_it2_2_orchestration_concurrency.py - Empirical Challenger M1 Iteration 2 Test Suite.

Authored by teamwork_preview_challenger_m1_it2_2 (Orchestration Concurrency Re-challenger).
Mission & Focus:
1. Adversarially stress test `_in_orchestration` property under heavy concurrent load:
   - 50 concurrent worker threads executing mixed queries on APK and ELF targets on a shared `RvsHarness` instance.
2. Confirm zero state bleed, zero race conditions, and correct orchestrator vs direct dispatch.
3. Validate context restoration under simulated exceptions and errors.
4. Validate nested / re-entrant orchestration preservation without state leakage.
5. Validate ThreadPoolExecutor thread recycling leaves zero residual orchestration context.
"""

from __future__ import annotations

import concurrent.futures
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

from rvs_agent_harness import (
    RvsHarness,
    _ORCHESTRATION_CONTEXT,
    execute_rvs_subprocess,
)
from tests.fixtures_builder import create_synthetic_apk

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
CRACKME_PATH = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
AUTH_GATE_PATH = WORKSPACE_DIR / "tests" / "fixtures" / "auth_gate_elf64"


class TestM1Iteration2OrchestrationConcurrency(unittest.TestCase):
    """
    Adversarial concurrency & invariant verification suite for _in_orchestration
    and shared RvsHarness instance under 50-thread mixed load.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory(prefix="rvs_m1_it2_chal2_")
        cls.apk_path = Path(cls.temp_dir.name) / "sample_multidex.apk"
        create_synthetic_apk(cls.apk_path, multidex=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def setUp(self) -> None:
        self.shared_harness = RvsHarness()

    def tearDown(self) -> None:
        self.shared_harness.close()

    def test_01_50_threads_mixed_apk_elf_concurrency_stress(self) -> None:
        """
        Adversarial Stress Test: 50 concurrent worker threads on a single shared RvsHarness instance.
        - 25 threads query APK targets (multidex + native SOs) via execute_tool and direct methods.
        - 25 threads query ELF targets (crackme_case, auth_gate_elf64) via execute_tool and direct methods.
        - Synchronized via threading.Barrier(50) for maximum instantaneous thread contention.
        - Invariants verified:
          1. Zero exceptions raised.
          2. Zero responses failure (100% success).
          3. Zero cross-target data corruption (ELF results never contain APK metadata and vice versa).
          4. Zero orchestration state bleed: _is_in_orchestration() is strictly False on every thread after query returns.
        """
        num_threads = 50
        iterations_per_thread = 4
        barrier = threading.Barrier(num_threads)
        errors: List[Tuple[int, str, Any]] = []

        def worker(tid: int) -> None:
            try:
                # Pre-check: thread must start with _in_orchestration == False
                if self.shared_harness._is_in_orchestration():
                    errors.append((tid, "pre_check_bleed", True))
                    return

                barrier.wait(timeout=10.0)

                for iter_idx in range(iterations_per_thread):
                    is_apk_worker = (tid % 2 == 0)

                    if is_apk_worker:
                        # Alternate between execute_tool and direct harness methods
                        sub_mode = (tid + iter_idx) % 3
                        if sub_mode == 0:
                            res = self.shared_harness.execute_tool(
                                "rvs_info",
                                {"file": str(self.apk_path)},
                            )
                            if not res.get("success"):
                                errors.append((tid, "apk_execute_tool_info_failed", res))
                            # APK orchestrated response must have telemetry or active_component
                            if "telemetry" not in res and "data" not in res:
                                errors.append((tid, "apk_missing_envelope_data", res))
                        elif sub_mode == 1:
                            res = self.shared_harness.info(self.apk_path)
                            if not res.get("success"):
                                errors.append((tid, "apk_direct_info_failed", res))
                            data = res.get("data") or {}
                            if not data.get("format"):
                                errors.append((tid, "apk_direct_info_empty_format", res))
                        else:
                            res = self.shared_harness.functions(self.apk_path, limit=5)
                            if not res.get("success"):
                                errors.append((tid, "apk_functions_failed", res))

                    else:
                        # ELF target
                        elf_target = CRACKME_PATH if (tid % 4 == 1) else AUTH_GATE_PATH
                        sub_mode = (tid + iter_idx) % 3
                        if sub_mode == 0:
                            res = self.shared_harness.execute_tool(
                                "rvs_info",
                                {"file": str(elf_target)},
                            )
                            if not res.get("success"):
                                errors.append((tid, "elf_execute_tool_info_failed", res))
                            data = res.get("data") or {}
                            if data.get("format") != "elf":
                                errors.append((tid, "elf_corrupted_format", res))
                        elif sub_mode == 1:
                            res = self.shared_harness.info(elf_target)
                            if not res.get("success"):
                                errors.append((tid, "elf_direct_info_failed", res))
                            data = res.get("data") or {}
                            if data.get("format") != "elf":
                                errors.append((tid, "elf_direct_format_corrupted", res))
                        else:
                            res = self.shared_harness.functions(elf_target, limit=5)
                            if not res.get("success"):
                                errors.append((tid, "elf_functions_failed", res))

                    # Invariant: _is_in_orchestration() MUST be strictly False immediately after every operation
                    if self.shared_harness._is_in_orchestration():
                        errors.append((tid, "post_op_state_bleed", True))

                # Post-check: thread must terminate with _in_orchestration == False
                if self.shared_harness._is_in_orchestration():
                    errors.append((tid, "post_check_bleed", True))

            except Exception as exc:
                errors.append((tid, "exception", exc))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45.0)

        self.assertEqual(
            len(errors),
            0,
            f"50-thread mixed load encountered errors or state bleed: {errors[:10]}",
        )
        self.assertFalse(
            self.shared_harness._is_in_orchestration(),
            "Main thread observed _in_orchestration == True on shared harness!",
        )

    def test_02_strict_cross_thread_isolation_barrier(self) -> None:
        """
        Adversarial Barrier Test: Hold Thread 0 explicitly in orchestration mode,
        while 49 concurrent worker threads hammer the shared harness with direct ELF & APK queries.
        
        Invariant:
        - When Thread 0 has _ORCHESTRATION_CONTEXT.active = True:
          - Every other thread MUST observe self.shared_harness._is_in_orchestration() == False.
          - No other thread must have its queries diverted or corrupted by Thread 0's active orchestration state.
        """
        hold_event = threading.Event()
        started_event = threading.Event()
        thread_0_observed_active = False
        other_threads_errors: List[Tuple[int, str, Any]] = []

        def holding_worker() -> None:
            nonlocal thread_0_observed_active
            try:
                # Explicitly activate orchestration context on this thread
                self.shared_harness._in_orchestration = True
                thread_0_observed_active = self.shared_harness._is_in_orchestration()
                started_event.set()
                # Hold until released
                hold_event.wait(timeout=10.0)
            finally:
                self.shared_harness._in_orchestration = False

        holder = threading.Thread(target=holding_worker)
        holder.start()
        self.assertTrue(started_event.wait(timeout=5.0), "Holder thread failed to start")
        self.assertTrue(thread_0_observed_active, "Holder thread failed to activate orchestration")

        # Now, while holder is STILL holding orchestration active:
        barrier = threading.Barrier(49)

        def observing_worker(tid: int) -> None:
            try:
                barrier.wait(timeout=5.0)
                # 1. Thread MUST observe _is_in_orchestration() == False
                if self.shared_harness._is_in_orchestration():
                    other_threads_errors.append((tid, "observed_true_while_thread_0_active", True))
                if getattr(_ORCHESTRATION_CONTEXT, "active", False):
                    other_threads_errors.append((tid, "raw_contextvars_bleed", True))

                # 2. Run direct info() on ELF target; must execute native command cleanly
                res_elf = self.shared_harness.info(CRACKME_PATH)
                if not res_elf.get("success"):
                    other_threads_errors.append((tid, "elf_info_failed", res_elf))
                data = res_elf.get("data") or {}
                if data.get("format") != "elf":
                    other_threads_errors.append((tid, "elf_format_not_elf", res_elf))

                # 3. Direct info() on APK target; must route to orchestrator and succeed
                res_apk = self.shared_harness.info(self.apk_path)
                if not res_apk.get("success"):
                    other_threads_errors.append((tid, "apk_info_failed", res_apk))
                data_apk = res_apk.get("data") or {}
                if not data_apk.get("format"):
                    other_threads_errors.append((tid, "apk_empty_format", res_apk))

                # 4. Must still observe _is_in_orchestration() == False
                if self.shared_harness._is_in_orchestration():
                    other_threads_errors.append((tid, "observed_true_after_calls", True))

            except Exception as e:
                other_threads_errors.append((tid, "exception", e))

        workers = [threading.Thread(target=observing_worker, args=(i + 1,)) for i in range(49)]
        for w in workers:
            w.start()
        for w in workers:
            w.join(timeout=20.0)

        # Release holder
        hold_event.set()
        holder.join(timeout=5.0)

        self.assertEqual(
            len(other_threads_errors),
            0,
            f"Cross-thread isolation violated while thread 0 in orchestration: {other_threads_errors[:10]}",
        )
        self.assertFalse(self.shared_harness._is_in_orchestration())

    def test_03_zero_state_bleed_under_simulated_exceptions(self) -> None:
        """
        Adversarial Test: Verify that exceptions occurring inside NeutralBinaryOrchestrator
        or execute_tool guarantee that _in_orchestration is restored to False on the calling thread.
        """
        # Case A: Corrupted APK / Ingestion failure
        corrupt_apk = Path(self.temp_dir.name) / "corrupt_crash.apk"
        corrupt_apk.write_bytes(b"PK\x03\x04INVALID_TRUNCATED_BYTES")

        res = self.shared_harness.execute_tool("rvs_info", {"file": str(corrupt_apk)})
        self.assertFalse(res.get("success"))
        self.assertFalse(
            self.shared_harness._is_in_orchestration(),
            "_in_orchestration remained True after corrupted APK failure!",
        )

        # Case B: Mocked exception during NeutralBinaryOrchestrator initialization
        with patch("rvs_agent_harness._get_neutral_orchestrator_cls") as mock_get_orch:
            class ExplodingOrchestrator:
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    raise RuntimeError("Exploding orchestrator in __init__")

            mock_get_orch.return_value = ExplodingOrchestrator

            res_expl = self.shared_harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
            self.assertFalse(res_expl.get("success"))
            self.assertEqual(res_expl.get("error", {}).get("code"), "INTERNAL_ERROR")
            self.assertIn("Exploding orchestrator in __init__", res_expl.get("error", {}).get("message", ""))

            self.assertFalse(
                self.shared_harness._is_in_orchestration(),
                "_in_orchestration remained True after exception in orchestrator __init__!",
            )

        # Case C: Mocked exception during query execution inside context manager
        with patch("neutral_orchestrator.orchestrator.NeutralBinaryOrchestrator.query", side_effect=ValueError("Boom")):
            # Note: orchestrator.query traps exceptions into error envelopes, but if an unhandled
            # exception occurs in Python layer, finally block must restore context
            try:
                self.shared_harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
            except ValueError:
                pass
            self.assertFalse(
                self.shared_harness._is_in_orchestration(),
                "_in_orchestration remained True after exception in query!",
            )

        # Case D: Subsequent legitimate call on same thread succeeds cleanly
        res_after = self.shared_harness.info(CRACKME_PATH)
        self.assertTrue(res_after.get("success"), f"Post-exception query failed: {res_after}")
        self.assertFalse(self.shared_harness._is_in_orchestration())

    def test_04_nested_orchestration_context_preservation(self) -> None:
        """
        Verify that re-entrant or nested orchestration contexts correctly preserve
        outer context state across nested calls.
        """
        h = self.shared_harness
        self.assertFalse(h._is_in_orchestration())

        # Simulate outer orchestration start
        prev_outer = getattr(_ORCHESTRATION_CONTEXT, "active", False)
        _ORCHESTRATION_CONTEXT.active = True
        try:
            self.assertTrue(h._is_in_orchestration())

            # Inside outer orchestration, simulate an inner execute_tool call on APK
            # which wraps in try ... finally restoring prev_ctx
            prev_inner = getattr(_ORCHESTRATION_CONTEXT, "active", False)
            self.assertTrue(prev_inner)
            _ORCHESTRATION_CONTEXT.active = True
            try:
                self.assertTrue(h._is_in_orchestration())
            finally:
                _ORCHESTRATION_CONTEXT.active = prev_inner

            # Upon exiting inner block, outer MUST still be True!
            self.assertTrue(
                h._is_in_orchestration(),
                "Inner block exit prematurely set _in_orchestration to False in outer context!",
            )

        finally:
            _ORCHESTRATION_CONTEXT.active = prev_outer

        # After outer exit, context must be restored to False
        self.assertFalse(h._is_in_orchestration())

    def test_05_direct_vs_orchestrator_dispatch_contract(self) -> None:
        """
        Verify the dispatch contract:
        1. Direct call on ELF -> executes native rvs CLI without orchestrator overhead/telemetry.
        2. Direct call on APK -> automatically dispatches to orchestrator via execute_tool.
        3. execute_tool("rvs_info", {file: elf}) -> dispatches directly to native rvs CLI.
        4. execute_tool("rvs_info", {file: elf, neutral: True}) -> dispatches to orchestrator with codebook.
        5. execute_tool("rvs_info", {file: apk}) -> dispatches to orchestrator with telemetry.
        """
        h = self.shared_harness

        # 1. Direct ELF info
        resp1 = h.info(CRACKME_PATH)
        self.assertTrue(resp1.get("success"))
        self.assertNotIn("telemetry", resp1, "Direct ELF call should not return orchestrator telemetry")
        self.assertEqual(resp1.get("data", {}).get("format"), "elf")

        # 2. execute_tool ELF info (non-neutral)
        resp2 = h.execute_tool("rvs_info", {"file": str(CRACKME_PATH)})
        self.assertTrue(resp2.get("success"))
        self.assertNotIn("telemetry", resp2, "execute_tool on standard ELF should not invoke orchestrator")

        # 3. execute_tool ELF info with neutral=True -> invokes orchestrator
        resp3 = h.execute_tool("rvs_info", {"file": str(CRACKME_PATH), "neutral": True})
        self.assertTrue(resp3.get("success"))
        self.assertIn("codebook", resp3, "Neutral ELF call must contain codebook")
        self.assertIn("telemetry", resp3, "Neutral ELF call must contain orchestrator telemetry")

        # 4. Direct APK info -> routes to orchestrator transparently
        resp4 = h.info(self.apk_path)
        self.assertTrue(resp4.get("success"))
        self.assertTrue(bool(resp4.get("data", {}).get("format")), "Direct APK call must extract valid format")

        # 5. execute_tool APK info -> invokes orchestrator
        resp5 = h.execute_tool("rvs_info", {"file": str(self.apk_path)})
        self.assertTrue(resp5.get("success"))
        self.assertIn("telemetry", resp5, "execute_tool on APK must invoke orchestrator with telemetry")
        self.assertIsNotNone(resp5.get("telemetry", {}).get("active_component"))

    def test_06_thread_pool_executor_50_workers_recycling(self) -> None:
        """
        Stress Test: 100 tasks executed over ThreadPoolExecutor(max_workers=50).
        Verifies that when threads are recycled across tasks, no stale orchestration
        state bleeds from one task to the next.
        """
        h = self.shared_harness
        stale_state_errors: List[str] = []

        def pool_task(task_id: int) -> Dict[str, Any]:
            # Step 1: Thread must start task in clean un-orchestrated state
            if h._is_in_orchestration():
                stale_state_errors.append(f"Task {task_id} began with _in_orchestration == True")

            # Step 2: Execute mixed query
            if task_id % 2 == 0:
                res = h.execute_tool("rvs_info", {"file": str(self.apk_path)})
            else:
                res = h.info(CRACKME_PATH)

            # Step 3: Thread must end task in clean un-orchestrated state
            if h._is_in_orchestration():
                stale_state_errors.append(f"Task {task_id} ended with _in_orchestration == True")

            return res

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(pool_task, i) for i in range(100)]
            results = [f.result(timeout=30.0) for f in futures]

        self.assertEqual(len(results), 100)
        self.assertTrue(all(r.get("success") for r in results))
        self.assertEqual(
            len(stale_state_errors),
            0,
            f"Stale orchestration state detected across recycled worker threads: {stale_state_errors}",
        )
    def test_07_concurrent_clear_session_mutation_under_orchestration_load(self) -> None:
        """
        Adversarial Test: 20 threads rapidly mutating session cache via clear_session(None)
        and clear_session(target) while 30 threads execute active APK and ELF queries.
        
        Invariant:
        - clear_session(None) on mutating threads must NOT clear or corrupt _in_orchestration
          in query threads that are currently in the middle of orchestration.
        - Zero thread contention exceptions or deadlocks.
        """
        num_threads = 50
        barrier = threading.Barrier(num_threads)
        errors: List[Tuple[int, str, Any]] = []

        def worker(tid: int) -> None:
            try:
                barrier.wait(timeout=10.0)
                is_mutator = (tid < 20)

                for iter_idx in range(6):
                    if is_mutator:
                        # Rapidly mutate session cache
                        if iter_idx % 2 == 0:
                            self.shared_harness.clear_session(None)
                        else:
                            self.shared_harness.clear_session(CRACKME_PATH)
                        sess = self.shared_harness.get_session(CRACKME_PATH)
                        self.assertIsInstance(sess, dict)
                    else:
                        # Query worker: mixed APK and ELF
                        if tid % 2 == 0:
                            res = self.shared_harness.info(self.apk_path)
                            if not res.get("success"):
                                errors.append((tid, "apk_query_failed", res))
                        else:
                            res = self.shared_harness.info(CRACKME_PATH)
                            if not res.get("success"):
                                errors.append((tid, "elf_query_failed", res))

                    # Invariant: after any op, thread's _is_in_orchestration() must be False
                    if self.shared_harness._is_in_orchestration():
                        errors.append((tid, "state_bleed_after_mutation_or_query", True))

            except Exception as e:
                errors.append((tid, "exception", e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30.0)

        self.assertEqual(
            len(errors),
            0,
            f"Concurrent session mutation under load produced errors or bleed: {errors[:10]}",
        )
        self.assertFalse(self.shared_harness._is_in_orchestration())

    def test_08_heavy_sustained_load_50_threads_mixed_operations(self) -> None:
        """
        Adversarial Stress Test: Heavy sustained load with 50 threads executing 10 iterations each
        (500 operations total) across functions(), strings(), info(), symbols(), and execute_tool().
        """
        num_threads = 50
        iterations = 10
        barrier = threading.Barrier(num_threads)
        errors: List[Tuple[int, str, Any]] = []

        def worker(tid: int) -> None:
            try:
                barrier.wait(timeout=10.0)
                for i in range(iterations):
                    op = (tid + i) % 5
                    if tid % 2 == 0:
                        # APK target
                        if op == 0:
                            res = self.shared_harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
                        elif op == 1:
                            res = self.shared_harness.info(self.apk_path)
                        elif op == 2:
                            res = self.shared_harness.functions(self.apk_path, limit=3)
                        elif op == 3:
                            res = self.shared_harness.strings(self.apk_path, limit=5)
                        else:
                            res = self.shared_harness.symbols(self.apk_path, limit=5)
                    else:
                        # ELF target
                        elf_target = CRACKME_PATH if (tid % 4 == 1) else AUTH_GATE_PATH
                        if op == 0:
                            res = self.shared_harness.execute_tool("rvs_info", {"file": str(elf_target)})
                        elif op == 1:
                            res = self.shared_harness.info(elf_target)
                        elif op == 2:
                            res = self.shared_harness.functions(elf_target, limit=3)
                        elif op == 3:
                            res = self.shared_harness.strings(elf_target, limit=5)
                        else:
                            res = self.shared_harness.symbols(elf_target, limit=5)

                    if not res.get("success"):
                        errors.append((tid, f"op_{op}_failed", res))
                    if self.shared_harness._is_in_orchestration():
                        errors.append((tid, "state_bleed", True))

            except Exception as e:
                errors.append((tid, "exception", e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=45.0)

        self.assertEqual(
            len(errors),
            0,
            f"Heavy sustained load produced failures or bleed: {errors[:10]}",
        )
        self.assertFalse(self.shared_harness._is_in_orchestration())


if __name__ == "__main__":
    unittest.main()
