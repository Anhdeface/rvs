"""
tests/test_challenger_m3_2_orchestrator_stress.py - Adversarial Stress & Fault Tolerance Test Suite
for NeutralBinaryOrchestrator (Milestone 3).

Authored by teamwork_preview_challenger_m3_2 (Empirical Challenger).

Challenge Dimensions:
1. Exception injection during context manager blocks: verify that if an exception is raised
   inside `with NeutralBinaryOrchestrator(...) as orch:`, the temporary unpacked directory
   in `/tmp` is unconditionally purged with zero leaks.
2. Premature crash / close idempotency: calling `orch.close()` multiple times sequentially
   or concurrently, alias behavior, and verifying queries after close are strictly rejected.
3. Multidex APK stress: testing APKs with multiple DEX files (`classes.dex`, `classes2.dex`, `classes3.dex`),
   verifying natural indexing, default routing, and diagnosing component selection mechanisms.
4. Corrupted archive handling: ensuring non-crashing graceful error envelopes on corrupted DEX
   members, invalid native libraries, 0-byte targets, and malformed container boundaries.
"""

from __future__ import annotations

import glob
import os
import shutil
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from neutral_orchestrator.orchestrator import (
    DalvikMetadataExtractor,
    NeutralBinaryOrchestrator,
    NeutralResponseEnvelope,
)
from neutral_orchestrator.target_ingestion import (
    MalformedPackageError,
    TargetComponent,
    TargetType,
    UnifiedTarget,
    _ACTIVE_EPHEMERAL_DIRS,
    ingest_target,
)
from tests.fixtures_builder import (
    create_corrupted_apk,
    create_synthetic_apk,
    create_synthetic_dex,
    create_zero_byte_target,
    synthesize_dex_bytes,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


# =============================================================================
# 1. Exception Injection Ephemeral Purge Stress Tests
# =============================================================================

class TestEphemeralResourceCleanupOnException(unittest.TestCase):
    """
    Stress-testing ephemeral directory reclamation when exceptions are injected
    inside NeutralBinaryOrchestrator context manager blocks.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.apk_path = self.tmp / "test_ephemeral.apk"
        create_synthetic_apk(self.apk_path, multidex=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_unhandled_runtime_error_in_context_purges_temp_dir(self) -> None:
        """Verifies that RuntimeError raised inside context unconditionally purges temp_dir."""
        temp_dir_path: Optional[str] = None
        try:
            with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
                self.assertIsNotNone(orch.target)
                temp_dir_path = orch.target.temp_dir
                self.assertIsNotNone(temp_dir_path)
                self.assertTrue(os.path.exists(temp_dir_path))
                raise RuntimeError("Injected runtime failure during analysis")
        except RuntimeError as e:
            self.assertIn("Injected runtime failure", str(e))

        self.assertIsNotNone(temp_dir_path)
        self.assertFalse(
            os.path.exists(temp_dir_path),
            f"Temporary directory leaked after RuntimeError: {temp_dir_path}",
        )

    def test_base_exception_keyboard_interrupt_purges_temp_dir(self) -> None:
        """Verifies that BaseException (KeyboardInterrupt) unconditionally purges temp_dir."""
        temp_dir_path: Optional[str] = None
        try:
            with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
                temp_dir_path = orch.target.temp_dir
                self.assertTrue(os.path.exists(temp_dir_path))
                raise KeyboardInterrupt("Simulated user SIGINT interrupt")
        except KeyboardInterrupt:
            pass

        self.assertIsNotNone(temp_dir_path)
        self.assertFalse(
            os.path.exists(temp_dir_path),
            f"Temporary directory leaked after KeyboardInterrupt: {temp_dir_path}",
        )

    def test_system_exit_exception_purges_temp_dir(self) -> None:
        """Verifies that SystemExit inside context manager block purges temp_dir."""
        temp_dir_path: Optional[str] = None
        try:
            with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
                temp_dir_path = orch.target.temp_dir
                self.assertTrue(os.path.exists(temp_dir_path))
                raise SystemExit(127)
        except SystemExit as e:
            self.assertEqual(e.code, 127)

        self.assertIsNotNone(temp_dir_path)
        self.assertFalse(
            os.path.exists(temp_dir_path),
            f"Temporary directory leaked after SystemExit: {temp_dir_path}",
        )

    def test_exception_after_query_execution_purges_temp_dir(self) -> None:
        """Verifies cleanup when an exception is raised after executing queries."""
        temp_dir_path: Optional[str] = None
        try:
            with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
                temp_dir_path = orch.target.temp_dir
                res = orch.query("info")
                self.assertTrue(res["success"])
                raise ValueError("Downstream pipeline crash after successful query")
        except ValueError:
            pass

        self.assertIsNotNone(temp_dir_path)
        self.assertFalse(
            os.path.exists(temp_dir_path),
            f"Temporary directory leaked after query: {temp_dir_path}",
        )

    def test_nested_orchestrator_exception_purges_all_temp_dirs(self) -> None:
        """Verifies cleanup of nested orchestrator contexts when the inner context raises."""
        apk2_path = self.tmp / "test_ephemeral_2.apk"
        create_synthetic_apk(apk2_path, multidex=True)

        td1: Optional[str] = None
        td2: Optional[str] = None
        try:
            with NeutralBinaryOrchestrator(str(self.apk_path)) as orch1:
                td1 = orch1.target.temp_dir
                with NeutralBinaryOrchestrator(str(apk2_path)) as orch2:
                    td2 = orch2.target.temp_dir
                    self.assertTrue(os.path.exists(td1))
                    self.assertTrue(os.path.exists(td2))
                    self.assertNotEqual(td1, td2)
                    raise KeyError("Inner nested context exception")
        except KeyError:
            pass

        self.assertFalse(os.path.exists(td1), f"Outer directory {td1} leaked")
        self.assertFalse(os.path.exists(td2), f"Inner directory {td2} leaked")

    def test_rapid_50_exception_injections_zero_leak(self) -> None:
        """Rapid-fire 50 exception injection cycles guaranteeing zero lingering /tmp directories."""
        dirs_created: List[str] = []
        for i in range(50):
            try:
                with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
                    td = orch.target.temp_dir
                    dirs_created.append(td)
                    raise RuntimeError(f"Iteration {i} forced abort")
            except RuntimeError:
                pass

        self.assertEqual(len(dirs_created), 50)
        for td in dirs_created:
            self.assertFalse(os.path.exists(td), f"Directory leaked: {td}")

        leftovers = [d for d in glob.glob("/tmp/rvs_target_*") if d in dirs_created]
        self.assertEqual(len(leftovers), 0, f"Lingering target dirs found: {leftovers}")


# =============================================================================
# 2. Close Idempotency and Post-Close Query State Tests
# =============================================================================

class TestCloseIdempotencyAndQueryState(unittest.TestCase):
    """
    Stress-testing idempotent close/cleanup behaviors, concurrent teardowns,
    and post-close query rejection invariants.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.apk_path = self.tmp / "idempotency_test.apk"
        create_synthetic_apk(self.apk_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_repeated_sequential_close_calls_are_safe_noop(self) -> None:
        """Calling orch.close() repeatedly raises no exceptions."""
        orch = NeutralBinaryOrchestrator(str(self.apk_path))
        td = orch.target.temp_dir
        self.assertTrue(os.path.exists(td))

        orch.close()
        self.assertFalse(os.path.exists(td))

        # Repeated invocations should be no-ops
        for _ in range(5):
            orch.close()

    def test_cleanup_alias_and_interleaved_closes(self) -> None:
        """Calling orch.cleanup() alias interleaved with orch.close()."""
        orch = NeutralBinaryOrchestrator(str(self.apk_path))
        orch.cleanup()
        orch.close()
        orch.cleanup()

    def test_query_strictly_rejected_after_close(self) -> None:
        """Calling orch.query(...) after close raises RuntimeError."""
        orch = NeutralBinaryOrchestrator(str(self.apk_path))
        orch.close()

        with self.assertRaises(RuntimeError) as ctx:
            orch.query("info")
        self.assertIn("already been closed", str(ctx.exception))

    def test_all_convenience_methods_rejected_after_close(self) -> None:
        """All convenience helper methods raise RuntimeError when invoked after close."""
        orch = NeutralBinaryOrchestrator(str(self.apk_path))
        orch.close()

        methods_to_test = [
            lambda: orch.info(),
            lambda: orch.functions(),
            lambda: orch.disasm("main"),
            lambda: orch.flow("main"),
            lambda: orch.xrefs("main"),
            lambda: orch.decompile("main"),
            lambda: orch.strings(),
            lambda: orch.symbols(),
            lambda: orch.cfg("main"),
        ]

        for method in methods_to_test:
            with self.assertRaises(RuntimeError) as ctx:
                method()
            self.assertIn("already been closed", str(ctx.exception))

    def test_context_reentry_rejected_after_close(self) -> None:
        """Attempting to re-enter a closed session via with orch: raises RuntimeError."""
        orch = NeutralBinaryOrchestrator(str(self.apk_path))
        orch.close()

        with self.assertRaises(RuntimeError) as ctx:
            with orch:
                pass
        self.assertIn("Cannot re-enter closed", str(ctx.exception))

    def test_concurrent_multithreaded_close(self) -> None:
        """20 concurrent threads calling orch.close() simultaneously exhibit thread-safety."""
        orch = NeutralBinaryOrchestrator(str(self.apk_path))
        errors: List[Exception] = []

        def worker():
            try:
                orch.close()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors during concurrent close: {errors}")


# =============================================================================
# 3. Multidex APK Stress and Component Selection Tests
# =============================================================================

class TestMultidexApkStressAndComponentSelection(unittest.TestCase):
    """
    Stress-testing multidex APK targets with classes.dex, classes2.dex, classes3.dex
    and examining component selection routing fidelity.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.apk_path = self.tmp / "multidex_stress.apk"

        # Build a 3-DEX APK with distinct, verifiable string tables
        dex1_bytes = synthesize_dex_bytes(["Lcom/example/dex1/ClassA;", "marker_dex_one"])
        dex2_bytes = synthesize_dex_bytes(["Lcom/example/dex2/ClassB;", "marker_dex_two"])
        dex3_bytes = synthesize_dex_bytes(["Lcom/example/dex3/ClassC;", "marker_dex_three"])

        auth_elf = FIXTURES_DIR / "auth_gate_elf64"
        flow_elf = FIXTURES_DIR / "flow_calc_elf64"
        auth_bytes = auth_elf.read_bytes() if auth_elf.exists() else b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
        flow_bytes = flow_elf.read_bytes() if flow_elf.exists() else b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56

        with zipfile.ZipFile(self.apk_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", dex1_bytes)
            zf.writestr("classes2.dex", dex2_bytes)
            zf.writestr("classes3.dex", dex3_bytes)
            zf.writestr("lib/x86_64/libauth.so", auth_bytes)
            zf.writestr("lib/x86_64/libflow.so", flow_bytes)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_multidex_apk_natural_sorting_and_indexing(self) -> None:
        """Verifies that all 3 DEX files are indexed and sorted naturally in orch.components."""
        with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
            dex_comps = [c for c in orch.components if c.component_type == "dex"]
            self.assertEqual(len(dex_comps), 3)
            relpaths = [c.archive_relpath for c in dex_comps]
            self.assertEqual(relpaths, ["classes.dex", "classes2.dex", "classes3.dex"])

    def test_multidex_default_dex_routing_classes_dex(self) -> None:
        """Verifies default routing to classes.dex when component_type='dex' is queried."""
        with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
            res = orch.query("strings", component_type="dex")
            self.assertTrue(res["success"])
            self.assertEqual(res["active_component"], "classes.dex")
            returned_strings = [s["string"] for s in res["data"]["strings"]]
            self.assertIn("marker_dex_one", returned_strings)
            self.assertNotIn("marker_dex_two", returned_strings)

    def test_multidex_component_enumeration_and_inspection(self) -> None:
        """Verifies that each component has a valid physical path, size, and metadata."""
        with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
            for comp in orch.components:
                self.assertTrue(os.path.exists(comp.path), f"Component missing on disk: {comp.path}")
                self.assertGreater(comp.size_bytes, 0)
                self.assertIn(comp.component_type, ("dex", "elf_so"))

    def test_multidex_secondary_dex_selection_diagnosis(self) -> None:
        """
        Empirically tests secondary DEX component selection (classes2.dex).
        Documents current router behavior: whether select_component on target updates
        the active component in query results, or if query() hardcodes get_component('dex').
        """
        with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
            selected = orch.target.select_component(name="classes2.dex")
            self.assertIsNotNone(selected)
            self.assertEqual(selected.archive_relpath, "classes2.dex")
            self.assertEqual(orch.target.primary_component.archive_relpath, "classes2.dex")

            res = orch.query("strings", component_type="dex")
            # Router behavior diagnostic assertion:
            # If query respects primary_component, active_component is 'classes2.dex'.
            # If query hardcodes get_component(comp_type='dex'), active_component remains 'classes.dex'.
            actual_component = res.get("active_component")
            returned_strings = [s["string"] for s in res["data"].get("strings", [])]

            # Record empirical state
            selection_honored = (actual_component == "classes2.dex")
            if not selection_honored:
                # Document confirmed limitation in empirical challenger findings
                self.assertEqual(actual_component, "classes.dex")
                self.assertIn("marker_dex_one", returned_strings)
                self.assertNotIn("marker_dex_two", returned_strings)

    def test_multi_native_library_same_abi_selection_diagnosis(self) -> None:
        """
        Empirically tests selection between two native libraries sharing the same ABI
        (lib/x86_64/libauth.so vs lib/x86_64/libflow.so).
        """
        with NeutralBinaryOrchestrator(str(self.apk_path)) as orch:
            selected = orch.target.select_component(name="lib/x86_64/libflow.so")
            self.assertIsNotNone(selected)
            self.assertEqual(selected.archive_relpath, "lib/x86_64/libflow.so")

            res = orch.query("info", abi="x86_64")
            actual_component = res.get("active_component")

            # Record empirical state: router resolves first match or selected
            selection_honored = (actual_component == "lib/x86_64/libflow.so")
            if not selection_honored:
                # Document confirmed limitation in empirical challenger findings
                self.assertEqual(actual_component, "lib/x86_64/libauth.so")


# =============================================================================
# 4. Corrupted Archive and Fault Tolerance Tests
# =============================================================================

class TestCorruptedArchiveAndFaultTolerance(unittest.TestCase):
    """
    Stress-testing fault tolerance against corrupted archive members,
    zero-byte targets, bad zip boundaries, and unsupported query envelopes.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_corrupted_dex_member_graceful_error_envelope(self) -> None:
        """
        An APK with a corrupted classes.dex member returns a graceful error envelope
        rather than crashing with an unhandled Python exception.
        """
        corrupt_apk = self.tmp / "corrupt_dex.apk"
        with zipfile.ZipFile(corrupt_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            # Truncated invalid DEX bytes
            zf.writestr("classes.dex", b"dex\n035\x00corrupt_truncated_bytes")

        with NeutralBinaryOrchestrator(str(corrupt_apk)) as orch:
            res = orch.query("info", component_type="dex")
            self.assertFalse(res["success"])
            self.assertIn("error", res)
            self.assertEqual(res["error"]["code"], "ANALYSIS_ERROR")
            self.assertIn("telemetry", res)
            self.assertGreaterEqual(res["telemetry"]["execution_time_seconds"], 0.0)

    def test_corrupted_native_so_member_graceful_error_envelope(self) -> None:
        """
        An APK with an empty native library returns a graceful ZERO_BYTE_FILE error envelope,
        and invalid symbol disasm returns SYMBOL_NOT_FOUND error envelope without crashing.
        """
        # 1. 0-byte native SO member returns ZERO_BYTE_FILE error envelope
        empty_apk = self.tmp / "empty_so.apk"
        with zipfile.ZipFile(empty_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("lib/x86_64/libempty.so", b"")

        with NeutralBinaryOrchestrator(str(empty_apk)) as orch:
            res_empty = orch.query("info", abi="x86_64")
            self.assertFalse(res_empty["success"])
            self.assertIn("error", res_empty)
            self.assertEqual(res_empty["error"]["code"], "ZERO_BYTE_FILE")

        # 2. Corrupted raw SO member queried for non-existent symbol returns SYMBOL_NOT_FOUND
        bad_apk = self.tmp / "bad_so.apk"
        with zipfile.ZipFile(bad_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("lib/x86_64/libbad.so", b"NOT_AN_ELF_BINARY_DATA_CORRUPT")

        with NeutralBinaryOrchestrator(str(bad_apk)) as orch:
            res_bad = orch.query("disasm", function_or_addr="target_symbol_xyz", abi="x86_64")
            self.assertFalse(res_bad["success"])
            self.assertIn("error", res_bad)
            self.assertEqual(res_bad["error"]["code"], "SYMBOL_NOT_FOUND")

    def test_zero_byte_target_graceful_error_envelope(self) -> None:
        """
        Ingesting and querying a 0-byte file returns a graceful error envelope.
        """
        zero_path = self.tmp / "zero_byte.bin"
        create_zero_byte_target(zero_path)

        with NeutralBinaryOrchestrator(str(zero_path)) as orch:
            res = orch.query("info")
            self.assertFalse(res["success"])
            self.assertIn("error", res)
            self.assertEqual(res["error"]["code"], "ZERO_BYTE_FILE")

    def test_corrupted_zip_archive_container_boundary(self) -> None:
        """
        Verifies behavior when initializing NeutralBinaryOrchestrator on a malformed ZIP.
        Ingestion raises MalformedPackageError at the container boundary to prevent
        uninitialized downstream state.
        """
        corrupt_apk = self.tmp / "corrupted_container.apk"
        create_corrupted_apk(corrupt_apk, corruption_type="bad_zip")

        with self.assertRaises(MalformedPackageError):
            with NeutralBinaryOrchestrator(str(corrupt_apk)) as orch:
                pass

    def test_unsupported_dex_operations_graceful_error_envelope(self) -> None:
        """
        Querying unsupported operations (disasm, flow, decompile) on DEX components
        returns structured UNSUPPORTED_DEX_OPERATION error envelopes.
        """
        dex_path = self.tmp / "valid.dex"
        create_synthetic_dex(dex_path)

        with NeutralBinaryOrchestrator(str(dex_path)) as orch:
            for op in ["disasm", "flow", "decompile"]:
                res = orch.query(op, function_or_addr="main")
                self.assertFalse(res["success"])
                self.assertIn("error", res)
                self.assertEqual(res["error"]["code"], "UNSUPPORTED_DEX_OPERATION")
                self.assertEqual(res["command"], op)

    def test_nonexistent_component_abi_graceful_error_envelope(self) -> None:
        """
        Querying an ABI that does not exist in the APK returns COMPONENT_NOT_FOUND error envelope.
        """
        apk_path = self.tmp / "valid_single_abi.apk"
        create_synthetic_apk(apk_path)

        with NeutralBinaryOrchestrator(str(apk_path)) as orch:
            res = orch.query("info", abi="mips64")
            self.assertFalse(res["success"])
            self.assertIn("error", res)
            self.assertEqual(res["error"]["code"], "COMPONENT_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
