"""
tests/test_target_ingestion.py - Comprehensive Unit and Boundary Test Suite
for Milestone 1: Multi-Format Target Ingestion & Unification.

Covers:
1. TargetType & TargetComponent data models.
2. TargetClassifier sniffing & architecture detection (ELF32, ELF64, PIE, APK, DEX, UNKNOWN).
3. Zero-copy standalone ELF ingestion & inode preservation.
4. APK container extraction with Zip Slip defense-in-depth & selective asset pruning.
5. Component & ABI indexing (multidex natural sorting, ABI selection strategy).
6. 6-Tier Ephemeral Lifecycle Watchdog (Context manager, idempotent cleanup, GC finalizer,
   atexit tracking, signal trap safety, TTL orphan sweeper).
7. Error taxonomy and boundary failure modes.
"""

from __future__ import annotations

import gc
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from typing import List

from neutral_orchestrator.target_ingestion import (
    EPHEMERAL_DIR_PREFIX,
    EmptyTargetError,
    MalformedPackageError,
    SecurityViolationError,
    TargetClassification,
    TargetClassifier,
    TargetComponent,
    TargetIngestionError,
    TargetNotFoundError,
    TargetPermissionError,
    TargetType,
    UnifiedTarget,
    _ACTIVE_EPHEMERAL_DIRS,
    cleanup_ephemeral_dir,
    create_ephemeral_dir,
    extract_apk_container,
    get_host_abi,
    ingest_target,
    is_safe_archive_member,
    sweep_orphaned_target_dirs,
)
from tests.fixtures_builder import (
    create_corrupted_apk,
    create_synthetic_apk,
    create_synthetic_dex,
    create_zero_byte_target,
    synthesize_dex_bytes,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ==============================================================================
# Test Suite 1: Data Models & Exception Taxonomy
# ==============================================================================

class TargetIngestionDataModelsTests(unittest.TestCase):
    """Unit tests for TargetType, TargetComponent, and custom exception types."""

    def test_target_type_enum_values(self) -> None:
        self.assertEqual(TargetType.ELF_STANDALONE.value, "elf_standalone")
        self.assertEqual(TargetType.APK_PACKAGE.value, "apk_package")
        self.assertEqual(TargetType.DEX_STANDALONE.value, "dex_standalone")
        self.assertEqual(TargetType.UNKNOWN.value, "unknown")
        # StrEnum string compatibility
        self.assertEqual(TargetType.ELF_STANDALONE, "elf_standalone")

    def test_target_component_dataclass_properties(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f:
            f.write(b"sample_payload_bytes")
            f_path = f.name

        try:
            comp = TargetComponent(
                path=f_path,
                component_type="elf_so",
                abi="x86_64",
                archive_relpath="lib/x86_64/libtest.so",
            )
            self.assertEqual(comp.name, Path(f_path).name)
            self.assertEqual(comp.size_bytes, len(b"sample_payload_bytes"))
            self.assertTrue(comp.is_native)
            self.assertFalse(comp.is_dex)

            d = comp.to_dict()
            self.assertEqual(d["path"], f_path)
            self.assertEqual(d["name"], comp.name)
            self.assertEqual(d["component_type"], "elf_so")
            self.assertEqual(d["abi"], "x86_64")
            self.assertEqual(d["archive_relpath"], "lib/x86_64/libtest.so")
            self.assertEqual(d["size_bytes"], len(b"sample_payload_bytes"))
        finally:
            if os.path.exists(f_path):
                os.unlink(f_path)

    def test_target_component_dex_properties(self) -> None:
        comp = TargetComponent(
            path="/tmp/classes.dex",
            component_type="dex",
            abi=None,
            archive_relpath="classes.dex",
            size_bytes=1024,
        )
        self.assertFalse(comp.is_native)
        self.assertTrue(comp.is_dex)
        self.assertEqual(comp.size_bytes, 1024)

    def test_exception_hierarchy_inheritance(self) -> None:
        not_found = TargetNotFoundError("File missing")
        self.assertIsInstance(not_found, FileNotFoundError)
        self.assertIsInstance(not_found, TargetIngestionError)
        self.assertEqual(not_found.exit_code, 2)

        perm_err = TargetPermissionError("No access")
        self.assertIsInstance(perm_err, PermissionError)
        self.assertIsInstance(perm_err, TargetIngestionError)
        self.assertEqual(perm_err.exit_code, 2)

        empty_err = EmptyTargetError("Zero bytes")
        self.assertIsInstance(empty_err, ValueError)
        self.assertIsInstance(empty_err, TargetIngestionError)

        sec_err = SecurityViolationError("Path traversal")
        self.assertIsInstance(sec_err, ValueError)
        self.assertIsInstance(sec_err, TargetIngestionError)

        malformed = MalformedPackageError("Bad zip")
        self.assertIsInstance(malformed, zipfile.BadZipFile)
        self.assertIsInstance(malformed, ValueError)
        self.assertIsInstance(malformed, TargetIngestionError)


# ==============================================================================
# Test Suite 2: Target Sniffing & Classification
# ==============================================================================

class TargetClassifierTests(unittest.TestCase):
    """Unit tests for TargetClassifier across ELF, DEX, APK, and unknown targets."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_classify_standalone_elf64(self) -> None:
        target = FIXTURES_DIR / "auth_gate_elf64"
        self.assertTrue(target.exists(), f"Fixture missing: {target}")
        cl = TargetClassifier.classify(target)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.format_name, "elf")
        self.assertEqual(cl.bits, 64)
        self.assertEqual(cl.endianness, "little")
        self.assertEqual(cl.abi, "x86_64")
        self.assertEqual(cl.e_type, 2)  # ET_EXEC
        self.assertFalse(cl.is_pie)

    def test_classify_standalone_elf32(self) -> None:
        target = FIXTURES_DIR / "auth_gate_elf32"
        self.assertTrue(target.exists(), f"Fixture missing: {target}")
        cl = TargetClassifier.classify(target)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.bits, 32)
        self.assertEqual(cl.endianness, "little")
        self.assertEqual(cl.abi, "x86")
        self.assertEqual(cl.e_type, 2)
        self.assertFalse(cl.is_pie)

    def test_classify_standalone_elf64_pie(self) -> None:
        target = FIXTURES_DIR / "auth_gate_elf64_pie"
        self.assertTrue(target.exists(), f"Fixture missing: {target}")
        cl = TargetClassifier.classify(target)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.bits, 64)
        self.assertEqual(cl.abi, "x86_64")
        self.assertEqual(cl.e_type, 3)  # ET_DYN
        self.assertTrue(cl.is_pie)

    def test_classify_dalvik_dex_standalone(self) -> None:
        dex_path = self.work_dir / "sample.dex"
        create_synthetic_dex(dex_path, version="035")
        cl = TargetClassifier.classify(dex_path)
        self.assertEqual(cl.target_type, TargetType.DEX_STANDALONE)
        self.assertEqual(cl.format_name, "dex")
        self.assertEqual(cl.dex_version, "035")

    def test_classify_apk_package(self) -> None:
        apk_path = self.work_dir / "sample.apk"
        create_synthetic_apk(apk_path)
        cl = TargetClassifier.classify(apk_path)
        self.assertEqual(cl.target_type, TargetType.APK_PACKAGE)
        self.assertEqual(cl.format_name, "apk")
        self.assertTrue(cl.has_manifest)
        self.assertTrue(cl.has_dex)

    def test_classify_generic_zip_returns_unknown(self) -> None:
        zip_path = self.work_dir / "regular.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("document.txt", "hello world")
        cl = TargetClassifier.classify(zip_path)
        self.assertEqual(cl.target_type, TargetType.UNKNOWN)

    def test_classify_zero_byte_file_returns_unknown(self) -> None:
        zero_file = self.work_dir / "zero.bin"
        create_zero_byte_target(zero_file)
        cl = TargetClassifier.classify(zero_file)
        self.assertEqual(cl.target_type, TargetType.UNKNOWN)

    def test_classify_arbitrary_binary_returns_unknown(self) -> None:
        data_file = self.work_dir / "random.bin"
        data_file.write_bytes(b"\x99\x88\x77\x66\x55\x44\x33\x22" * 10)
        cl = TargetClassifier.classify(data_file)
        self.assertEqual(cl.target_type, TargetType.UNKNOWN)

    def test_classify_nonexistent_path_raises_not_found(self) -> None:
        with self.assertRaises(TargetNotFoundError):
            TargetClassifier.classify(self.work_dir / "nonexistent.bin")

    def test_classify_directory_path_raises_not_found(self) -> None:
        with self.assertRaises(TargetNotFoundError):
            TargetClassifier.classify(self.work_dir)

    def test_classify_corrupted_apk_raises_malformed(self) -> None:
        corrupted_path = self.work_dir / "corrupted.apk"
        create_corrupted_apk(corrupted_path, corruption_type="bad_zip")
        with self.assertRaises((MalformedPackageError, zipfile.BadZipFile, ValueError)):
            TargetClassifier.classify(corrupted_path)


# ==============================================================================
# Test Suite 3: Standalone ELF Zero-Copy Ingestion
# ==============================================================================

class StandaloneElfIngestionTests(unittest.TestCase):
    """Tests zero-copy passthrough, non-destructive lifecycle, and component indexing for ELFs."""

    def test_elf_ingestion_canonical_primary_path(self) -> None:
        target_path = str(FIXTURES_DIR / "flow_calc_elf64")
        unified = ingest_target(target_path)
        self.assertEqual(unified.primary_path, target_path)
        self.assertEqual(unified.target_type, TargetType.ELF_STANDALONE)

    def test_elf_ingestion_zero_copy_no_temp_dir(self) -> None:
        target_path = str(FIXTURES_DIR / "auth_gate_elf64")
        unified = ingest_target(target_path)
        self.assertIsNone(unified.temp_dir)
        self.assertFalse(unified.is_ephemeral)

    def test_elf_ingestion_single_component_created(self) -> None:
        target_path = str(FIXTURES_DIR / "decryptor_target_elf64")
        unified = ingest_target(target_path)
        self.assertEqual(len(unified.components), 1)
        comp = unified.components[0]
        self.assertEqual(comp.path, target_path)
        self.assertTrue(comp.is_native)
        self.assertEqual(comp.abi, "x86_64")

    def test_elf_ingestion_preserves_file_inode_and_hash(self) -> None:
        target_path = FIXTURES_DIR / "antidebug_target_elf64"
        initial_stat = target_path.stat()
        initial_hash = _sha256(target_path.read_bytes())

        with ingest_target(str(target_path)) as unified:
            self.assertEqual(unified.primary_path, str(target_path))
            # Invoke cleanup explicitly inside context
            unified.cleanup()

        after_stat = target_path.stat()
        self.assertEqual(initial_stat.st_ino, after_stat.st_ino)
        self.assertEqual(initial_stat.st_size, after_stat.st_size)
        self.assertEqual(_sha256(target_path.read_bytes()), initial_hash)

    def test_elf_ingestion_respects_default_abi_override(self) -> None:
        target_path = str(FIXTURES_DIR / "auth_gate_elf64")
        unified = ingest_target(target_path, default_abi="x86_64")
        comp = unified.get_component(abi="x86_64")
        self.assertIsNotNone(comp)
        self.assertEqual(comp.abi, "x86_64")


# ==============================================================================
# Test Suite 4: APK Container Extraction & Zip Slip Defense
# ==============================================================================

class ApkExtractionAndSecurityTests(unittest.TestCase):
    """Tests selective extraction, Zip Slip defense-in-depth, and asset pruning."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_zip_slip_rejection_parent_traversal(self) -> None:
        dest_dir = self.work_dir / "sandbox"
        dest_dir.mkdir(parents=True, exist_ok=True)
        self.assertFalse(is_safe_archive_member("../../evil.so", dest_dir))
        self.assertFalse(is_safe_archive_member("lib/x86_64/../../evil.so", dest_dir))
        self.assertFalse(is_safe_archive_member("lib/../../../evil.so", dest_dir))

    def test_zip_slip_rejection_absolute_paths(self) -> None:
        dest_dir = self.work_dir / "sandbox"
        self.assertFalse(is_safe_archive_member("/etc/passwd", dest_dir))
        self.assertFalse(is_safe_archive_member("/tmp/evil.so", dest_dir))
        self.assertFalse(is_safe_archive_member("C:evil.so", dest_dir))
        self.assertFalse(is_safe_archive_member("D:/payload.dex", dest_dir))

    def test_zip_slip_rejection_backslash_paths(self) -> None:
        dest_dir = self.work_dir / "sandbox"
        self.assertFalse(is_safe_archive_member("lib\\x86_64\\..\\..\\evil.so", dest_dir))

    def test_zip_slip_detection_raises_security_violation(self) -> None:
        malicious_apk = self.work_dir / "malicious.apk"
        with zipfile.ZipFile(malicious_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", synthesize_dex_bytes())
            zf.writestr("../../escape.so", b"\x7fELF_EVIL")

        with self.assertRaises(SecurityViolationError):
            with ingest_target(str(malicious_apk)):
                pass

        # Verify escape.so did NOT get written outside sandbox
        self.assertFalse((self.work_dir.parent / "escape.so").exists())

    def test_selective_extraction_prunes_bloat_assets(self) -> None:
        bloated_apk = self.work_dir / "bloated.apk"
        with zipfile.ZipFile(bloated_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", synthesize_dex_bytes())
            zf.writestr("lib/x86_64/libauth.so", (FIXTURES_DIR / "auth_gate_elf64").read_bytes())
            # Non-analyzable bloat assets
            zf.writestr("res/drawable/icon.png", b"IMAGE_DATA" * 50)
            zf.writestr("assets/database.db", b"SQLITE_DATA" * 50)
            zf.writestr("META-INF/CERT.RSA", b"SIGNATURE_DATA" * 20)
            zf.writestr("resources.arsc", b"RESOURCES_TABLE" * 30)

        with ingest_target(str(bloated_apk)) as unified:
            extracted_paths = [Path(c.path) for c in unified.components]
            # Only classes.dex and libauth.so must exist in extraction dir
            self.assertEqual(len(extracted_paths), 2)
            for p in extracted_paths:
                self.assertTrue(p.name in ("classes.dex", "libauth.so"))
            # Confirm bloat files were not extracted
            temp_root = Path(unified.temp_dir)
            self.assertFalse((temp_root / "res").exists())
            self.assertFalse((temp_root / "assets").exists())
            self.assertFalse((temp_root / "resources.arsc").exists())


# ==============================================================================
# Test Suite 5: Component & ABI Indexing
# ==============================================================================

class ComponentAndAbiIndexingTests(unittest.TestCase):
    """Tests component enumeration, natural multidex ordering, and ABI resolution."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_multidex_natural_sorting_order(self) -> None:
        multidex_apk = self.work_dir / "multidex.apk"
        with zipfile.ZipFile(multidex_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            # Write in arbitrary non-numeric order
            zf.writestr("classes10.dex", synthesize_dex_bytes())
            zf.writestr("classes3.dex", synthesize_dex_bytes())
            zf.writestr("classes.dex", synthesize_dex_bytes())
            zf.writestr("classes2.dex", synthesize_dex_bytes())

        with ingest_target(str(multidex_apk)) as unified:
            dex_comps = unified.get_components(comp_type="dex")
            relpaths = [c.archive_relpath for c in dex_comps]
            # Expected exact natural order: classes.dex, classes2.dex, classes3.dex, classes10.dex
            self.assertEqual(
                relpaths,
                ["classes.dex", "classes2.dex", "classes3.dex", "classes10.dex"]
            )

    def test_abi_query_and_filtering(self) -> None:
        apk_path = self.work_dir / "multi_abi.apk"
        create_synthetic_apk(
            apk_path,
            elf_fixtures={
                "lib/x86_64/libauth.so": FIXTURES_DIR / "auth_gate_elf64",
                "lib/arm64-v8a/libauth.so": FIXTURES_DIR / "auth_gate_elf64",
                "lib/armeabi-v7a/libauth.so": FIXTURES_DIR / "auth_gate_elf32",
            },
            multidex=True,
        )

        with ingest_target(str(apk_path)) as unified:
            # Query specific ABIs
            c_x86_64 = unified.get_component(abi="x86_64")
            self.assertIsNotNone(c_x86_64)
            self.assertEqual(c_x86_64.abi, "x86_64")

            c_arm64 = unified.get_component(abi="arm64-v8a")
            self.assertIsNotNone(c_arm64)
            self.assertEqual(c_arm64.abi, "arm64-v8a")

            c_arm32 = unified.get_component(abi="armeabi-v7a")
            self.assertIsNotNone(c_arm32)
            self.assertEqual(c_arm32.abi, "armeabi-v7a")

            # Missing ABI returns None
            self.assertIsNone(unified.get_component(abi="riscv64"))

    def test_fallback_to_dex_when_apk_has_no_native_libs(self) -> None:
        pure_dex_apk = self.work_dir / "pure_dex.apk"
        with zipfile.ZipFile(pure_dex_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", synthesize_dex_bytes())

        with ingest_target(str(pure_dex_apk)) as unified:
            self.assertIsNone(unified.get_component(comp_type="elf_so"))
            dex_comp = unified.get_component(comp_type="dex")
            self.assertIsNotNone(dex_comp)
            # primary_path defaults to classes.dex
            self.assertTrue(unified.primary_path.endswith("classes.dex"))

    def test_select_component_switches_active_target(self) -> None:
        apk_path = self.work_dir / "switchable.apk"
        create_synthetic_apk(
            apk_path,
            elf_fixtures={
                "lib/x86_64/libauth.so": FIXTURES_DIR / "auth_gate_elf64",
                "lib/arm64-v8a/libauth.so": FIXTURES_DIR / "auth_gate_elf64",
            },
            multidex=True,
        )

        with ingest_target(str(apk_path), default_abi="x86_64") as unified:
            # Initially default x86_64 library
            self.assertIn("x86_64", unified.primary_path)

            # Switch to arm64-v8a
            comp_arm = unified.select_component(abi="arm64-v8a", comp_type="elf_so")
            self.assertIsNotNone(comp_arm)
            self.assertIn("arm64-v8a", unified.primary_path)

            # Switch to classes.dex
            comp_dex = unified.select_component(comp_type="dex")
            self.assertIsNotNone(comp_dex)
            self.assertTrue(unified.primary_path.endswith("classes.dex"))


# ==============================================================================
# Test Suite 6: 6-Tier Ephemeral Lifecycle Watchdog
# ==============================================================================

class EphemeralWatchdogTiersTests(unittest.TestCase):
    """Tests all 6 tiers of the Ephemeral Lifecycle Watchdog."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_tier1_context_manager_clean_exit(self) -> None:
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        temp_dir_recorded = None
        with ingest_target(str(apk_path)) as unified:
            temp_dir_recorded = unified.temp_dir
            self.assertTrue(Path(temp_dir_recorded).exists())
            self.assertIn(os.path.abspath(temp_dir_recorded), _ACTIVE_EPHEMERAL_DIRS)

        self.assertFalse(Path(temp_dir_recorded).exists())
        self.assertNotIn(os.path.abspath(temp_dir_recorded), _ACTIVE_EPHEMERAL_DIRS)

    def test_tier1_context_manager_unwinding_on_exception(self) -> None:
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        temp_dir_recorded = None

        with self.assertRaises(ZeroDivisionError):
            with ingest_target(str(apk_path)) as unified:
                temp_dir_recorded = unified.temp_dir
                self.assertTrue(Path(temp_dir_recorded).exists())
                _ = 1 / 0

        self.assertIsNotNone(temp_dir_recorded)
        self.assertFalse(Path(temp_dir_recorded).exists())

    def test_tier2_explicit_cleanup_and_idempotency(self) -> None:
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        unified = ingest_target(str(apk_path))
        temp_dir = unified.temp_dir
        self.assertTrue(Path(temp_dir).exists())

        unified.cleanup()
        self.assertFalse(Path(temp_dir).exists())

        # Calling cleanup and close repeatedly must be safe no-ops
        unified.cleanup()
        unified.close()
        unified.cleanup()

    def test_tier2_reentering_context_after_cleanup_raises_runtime_error(self) -> None:
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        unified = ingest_target(str(apk_path))
        unified.cleanup()

        with self.assertRaises(RuntimeError):
            with unified:
                pass

    def test_tier3_garbage_collection_finalizer(self) -> None:
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        unified = ingest_target(str(apk_path))
        temp_dir_recorded = unified.temp_dir
        self.assertTrue(Path(temp_dir_recorded).exists())

        # Drop all references and trigger GC
        del unified
        gc.collect()

        self.assertFalse(Path(temp_dir_recorded).exists())
        self.assertNotIn(os.path.abspath(temp_dir_recorded), _ACTIVE_EPHEMERAL_DIRS)

    def test_tier4_atexit_registry_tracking(self) -> None:
        temp_dir = create_ephemeral_dir()
        self.assertTrue(os.path.exists(temp_dir))
        self.assertIn(os.path.abspath(temp_dir), _ACTIVE_EPHEMERAL_DIRS)

        cleanup_ephemeral_dir(temp_dir)
        self.assertFalse(os.path.exists(temp_dir))
        self.assertNotIn(os.path.abspath(temp_dir), _ACTIVE_EPHEMERAL_DIRS)

    def test_tier6_prefix_and_ttl_orphan_sweeper(self) -> None:
        old_dir = tempfile.mkdtemp(prefix=EPHEMERAL_DIR_PREFIX, dir=str(self.work_dir))
        fresh_dir = tempfile.mkdtemp(prefix=EPHEMERAL_DIR_PREFIX, dir=str(self.work_dir))

        # Backdate old_dir to 2 hours ago
        two_hours_ago = time.time() - 7200
        os.utime(old_dir, (two_hours_ago, two_hours_ago))

        swept = sweep_orphaned_target_dirs(
            base_dir=str(self.work_dir),
            ttl_seconds=3600.0,
            prefix=EPHEMERAL_DIR_PREFIX,
        )

        self.assertIn(os.path.abspath(old_dir), swept)
        self.assertFalse(os.path.exists(old_dir))
        # Fresh directory must be spared
        self.assertTrue(os.path.exists(fresh_dir))
        shutil.rmtree(fresh_dir)

    def test_tier6_active_directory_immunity(self) -> None:
        active_dir = create_ephemeral_dir()
        # Backdate the active directory to 2 hours ago
        two_hours_ago = time.time() - 7200
        os.utime(active_dir, (two_hours_ago, two_hours_ago))

        swept = sweep_orphaned_target_dirs(
            base_dir=tempfile.gettempdir(),
            ttl_seconds=3600.0,
            prefix=EPHEMERAL_DIR_PREFIX,
        )

        # Active dir must be IMMUNE to sweep because it is tracked in _ACTIVE_EPHEMERAL_DIRS
        self.assertNotIn(os.path.abspath(active_dir), swept)
        self.assertTrue(os.path.exists(active_dir))

        cleanup_ephemeral_dir(active_dir)
        self.assertFalse(os.path.exists(active_dir))


if __name__ == "__main__":
    unittest.main()
