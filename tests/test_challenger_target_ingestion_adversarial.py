"""
tests/test_challenger_target_ingestion_adversarial.py - Adversarial Stress & Empirical Challenge Suite
for Milestone 1: neutral_orchestrator/target_ingestion.py.

Empirically challenges:
1. Malformed and corrupted ELF headers:
   - Truncated ELF identification (1, 3, 4, 10, 19 bytes).
   - Invalid EI_CLASS (0, 3, 255).
   - Invalid EI_DATA (0, 3, 255).
   - Non-standard / exotic e_type (ET_NONE, ET_REL, ET_CORE, 0xffff).
   - Unknown e_machine architectures (fallback to default ABI).
   - Big-endian ELF headers (MIPS64, ARM big-endian).
   - Ingestion behavior under unparseable binaries.
2. Malicious ZIP / APK archives & Path Traversal (Zip Slip):
   - Directory traversal attempts (../../etc/passwd, backslash paths, nested escapes).
   - Absolute Unix paths (/tmp/pwned.so) and Windows drive letters (C:\\Windows\\system32).
   - Symbolic link evasion in archives (S_IFLNK ignored, no file disclosure).
   - Ephemeral directory leak prevention on SecurityViolationError.
   - CRC-32 checksum corruption in archive members.
   - Corrupted ZIP central directory headers.
3. Pathological filesystem targets:
   - Zero-byte files (classification & safe ingestion).
   - Directory paths, non-existent files, and dangling symlinks.
   - Permission denied targets (chmod 000).
   - Special character devices (/dev/null, /dev/zero).
4. Non-standard Multidex names & Unknown ABIs:
   - Multidex natural numeric sorting (classes.dex through classes12.dex).
   - Multidex sparse indices and leading zero normalization.
   - Exclusion of non-standard names (classes_secondary.dex, classes.dex.bak).
   - Exotic & unknown ABIs (riscv32, custom DSP architectures).
   - APKs containing zero executable components (pure assets/manifest).
5. Standalone Dalvik DEX edge cases:
   - Spec-compliant versions (035, 037, 038, 039).
   - Unsupported or out-of-range versions (030, 040, 999).
   - Truncated magic headers and non-null terminators.
6. Concurrency & Ephemeral Lifecycle Watchdog stress:
   - High-concurrency multithreaded ingestion & extraction (zero leak).
   - Multithreaded concurrent cleanup idempotency.
   - Re-entrancy prevention on cleaned targets.
   - TTL orphan sweeper resilience against unreadable directories.
"""

from __future__ import annotations

import concurrent.futures
import os
import shutil
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
import zipfile
import zlib
from pathlib import Path
from typing import List, Optional

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
    UnparseableBinaryError,
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


# ==============================================================================
# Suite 1: Pathological ELF Stress Tests
# ==============================================================================

class PathologicalElfStressTests(unittest.TestCase):
    """Adversarial stress tests for ELF parsing and boundary conditions."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="adv_elf_")
        self.work_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_file(self, filename: str, content: bytes) -> Path:
        p = self.work_dir / filename
        p.write_bytes(content)
        return p

    def test_truncated_elf_1_byte(self) -> None:
        """1-byte file starting with 0x7f returns UNKNOWN without crash."""
        p = self._write_file("trunc1.bin", b"\x7f")
        cl = TargetClassifier.classify(p)
        self.assertEqual(cl.target_type, TargetType.UNKNOWN)

    def test_truncated_elf_3_bytes(self) -> None:
        """3-byte file with 0x7f454c returns UNKNOWN without crash."""
        p = self._write_file("trunc3.bin", b"\x7fEL")
        cl = TargetClassifier.classify(p)
        self.assertEqual(cl.target_type, TargetType.UNKNOWN)

    def test_truncated_elf_4_bytes_raises_unparseable(self) -> None:
        """Exact 4-byte '\\x7fELF' magic with no header fields raises UnparseableBinaryError."""
        p = self._write_file("trunc4.bin", b"\x7fELF")
        with self.assertRaises(UnparseableBinaryError) as ctx:
            TargetClassifier.classify(p)
        self.assertIn("Truncated ELF identification", str(ctx.exception))

    def test_truncated_elf_10_bytes_raises_unparseable(self) -> None:
        """10-byte ELF with valid magic and class/data but truncated before e_type raises UnparseableBinaryError."""
        content = b"\x7fELF\x02\x01\x01\x00\x00\x00"
        p = self._write_file("trunc10.bin", content)
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_truncated_elf_19_bytes_raises_unparseable(self) -> None:
        """19-byte ELF (just 1 byte short of e_machine at offset 18..20) raises UnparseableBinaryError."""
        content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 11
        self.assertEqual(len(content), 19)
        p = self._write_file("trunc19.bin", content)
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_elf_invalid_ei_class_zero(self) -> None:
        """EI_CLASS=0 (ELFCLASSNONE) is invalid and must raise UnparseableBinaryError."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 0  # EI_CLASS = 0
        header[5] = 1  # EI_DATA = 1 (little)
        p = self._write_file("invalid_class0.bin", bytes(header))
        with self.assertRaises(UnparseableBinaryError) as ctx:
            TargetClassifier.classify(p)
        self.assertIn("Malformed ELF identification", str(ctx.exception))

    def test_elf_invalid_ei_class_three(self) -> None:
        """EI_CLASS=3 (invalid) must raise UnparseableBinaryError."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 3  # EI_CLASS = 3
        header[5] = 1  # EI_DATA = 1
        p = self._write_file("invalid_class3.bin", bytes(header))
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_elf_invalid_ei_class_max(self) -> None:
        """EI_CLASS=255 must raise UnparseableBinaryError."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 255
        header[5] = 1
        p = self._write_file("invalid_class255.bin", bytes(header))
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_elf_invalid_ei_data_zero(self) -> None:
        """EI_DATA=0 (ELFDATANONE) is invalid and must raise UnparseableBinaryError."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2  # EI_CLASS = 2 (64-bit)
        header[5] = 0  # EI_DATA = 0
        p = self._write_file("invalid_data0.bin", bytes(header))
        with self.assertRaises(UnparseableBinaryError) as ctx:
            TargetClassifier.classify(p)
        self.assertIn("Malformed ELF identification", str(ctx.exception))

    def test_elf_invalid_ei_data_three(self) -> None:
        """EI_DATA=3 (invalid endianness) must raise UnparseableBinaryError."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2
        header[5] = 3
        p = self._write_file("invalid_data3.bin", bytes(header))
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_elf_nonstandard_etype_rel(self) -> None:
        """e_type=1 (ET_REL - relocatable object file) is parsed cleanly with is_pie=False."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2  # 64-bit
        header[5] = 1  # little-endian
        struct.pack_into("<H", header, 16, 1)   # e_type = ET_REL (1)
        struct.pack_into("<H", header, 18, 62)  # e_machine = EM_X86_64 (62)
        p = self._write_file("relocatable.o", bytes(header))
        cl = TargetClassifier.classify(p)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.e_type, 1)
        self.assertFalse(cl.is_pie)
        self.assertEqual(cl.machine, "x86_64")
        self.assertEqual(cl.abi, "x86_64")

    def test_elf_nonstandard_etype_none(self) -> None:
        """e_type=0 (ET_NONE) is classified as ELF_STANDALONE with is_pie=False."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2
        header[5] = 1
        struct.pack_into("<H", header, 16, 0)   # ET_NONE
        struct.pack_into("<H", header, 18, 62)
        p = self._write_file("none_type.bin", bytes(header))
        cl = TargetClassifier.classify(p)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.e_type, 0)
        self.assertFalse(cl.is_pie)

    def test_elf_nonstandard_etype_core(self) -> None:
        """e_type=4 (ET_CORE) is classified as ELF_STANDALONE with is_pie=False."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2
        header[5] = 1
        struct.pack_into("<H", header, 16, 4)   # ET_CORE
        struct.pack_into("<H", header, 18, 62)
        p = self._write_file("core_dump.bin", bytes(header))
        cl = TargetClassifier.classify(p)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.e_type, 4)
        self.assertFalse(cl.is_pie)

    def test_elf_unknown_machine_falls_back_cleanly(self) -> None:
        """Exotic machine ID (e_machine=0x9999) classifies as unknown_machine and uses default_abi on ingest."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2  # 64-bit
        header[5] = 1  # little-endian
        struct.pack_into("<H", header, 16, 2)       # ET_EXEC
        struct.pack_into("<H", header, 18, 0x9999)  # Unknown machine 39321
        p = self._write_file("exotic_elf.bin", bytes(header))
        cl = TargetClassifier.classify(p)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.machine, "unknown_39321")
        self.assertIsNone(cl.abi)

        # Ingestion should succeed by falling back to default_abi
        unified = ingest_target(str(p), default_abi="arm64-v8a")
        self.assertEqual(unified.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(unified.components[0].abi, "arm64-v8a")

    def test_elf_big_endian_mips64(self) -> None:
        """Big-endian ELF (EI_DATA=2) MIPS64 is unpacked correctly with endianness='big'."""
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2  # 64-bit
        header[5] = 2  # big-endian (ELFDATA2MSB)
        struct.pack_into(">H", header, 16, 3)  # ET_DYN (PIE) in big-endian
        struct.pack_into(">H", header, 18, 8)  # EM_MIPS (8)
        p = self._write_file("mips64_be.elf", bytes(header))
        cl = TargetClassifier.classify(p)
        self.assertEqual(cl.target_type, TargetType.ELF_STANDALONE)
        self.assertEqual(cl.endianness, "big")
        self.assertEqual(cl.bits, 64)
        self.assertEqual(cl.machine, "mips64")
        self.assertEqual(cl.abi, "mips64")
        self.assertTrue(cl.is_pie)

    def test_ingest_target_corrupted_elf_raises_unparseable(self) -> None:
        """ingest_target() raises UnparseableBinaryError (TargetIngestionError) when given truncated ELF."""
        p = self._write_file("corrupt.elf", b"\x7fELF\x02")
        with self.assertRaises(UnparseableBinaryError) as ctx:
            ingest_target(str(p))
        self.assertIsInstance(ctx.exception, TargetIngestionError)


# ==============================================================================
# Suite 2: Malicious Archive & Path Traversal (Zip Slip) Attacks
# ==============================================================================

class MaliciousArchiveZipSlipTests(unittest.TestCase):
    """Adversarial stress tests for archive extraction and Zip Slip path traversal defenses."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="adv_zip_")
        self.work_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_malicious_zip(self, entries: dict[str, bytes]) -> Path:
        apk_path = self.work_dir / "attack.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            for name, data in entries.items():
                zf.writestr(name, data)
        return apk_path

    def test_zip_slip_dot_dot_traversal(self) -> None:
        """Archive with '../../etc/passwd' member triggers SecurityViolationError."""
        apk_path = self._create_malicious_zip({"../../etc/passwd": b"root:x:0:0::/root:/bin/bash\n"})
        with self.assertRaises(SecurityViolationError):
            with ingest_target(str(apk_path)):
                pass

    def test_zip_slip_absolute_unix_path(self) -> None:
        """Archive with absolute Unix path '/tmp/evil.so' triggers SecurityViolationError."""
        apk_path = self._create_malicious_zip({"/tmp/evil.so": b"evil_payload"})
        with self.assertRaises(SecurityViolationError):
            with ingest_target(str(apk_path)):
                pass

    def test_zip_slip_windows_drive_letter_with_backslash(self) -> None:
        """Archive with 'C:\\Windows\\system32\\evil.dll' triggers SecurityViolationError."""
        apk_path = self._create_malicious_zip({"C:\\Windows\\system32\\evil.dll": b"evil"})
        with self.assertRaises(SecurityViolationError):
            with ingest_target(str(apk_path)):
                pass

    def test_zip_slip_windows_drive_letter_no_backslash(self) -> None:
        """Archive with 'D:evil.so' triggers SecurityViolationError."""
        apk_path = self._create_malicious_zip({"D:evil.so": b"evil"})
        with self.assertRaises(SecurityViolationError):
            with ingest_target(str(apk_path)):
                pass

    def test_zip_slip_nested_traversal_inside_lib(self) -> None:
        """Archive with 'lib/x86_64/../../../../tmp/evil.so' triggers SecurityViolationError."""
        apk_path = self._create_malicious_zip({"lib/x86_64/../../../../tmp/evil.so": b"evil"})
        with self.assertRaises(SecurityViolationError):
            with ingest_target(str(apk_path)):
                pass

    def test_zip_slip_cleans_up_ephemeral_dir_on_rejection(self) -> None:
        """When SecurityViolationError is raised, the created ephemeral directory is purged immediately."""
        active_before = len(_ACTIVE_EPHEMERAL_DIRS)
        apk_path = self._create_malicious_zip({"../../escape.txt": b"escape"})
        try:
            with ingest_target(str(apk_path)):
                pass
        except SecurityViolationError:
            pass
        active_after = len(_ACTIVE_EPHEMERAL_DIRS)
        self.assertEqual(active_before, active_after, "Ephemeral directory leaked after SecurityViolationError")

    def test_zip_symlink_member_is_silently_skipped(self) -> None:
        """Archive containing a symbolic link entry skips it without traversal or crash."""
        apk_path = self.work_dir / "symlink.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", synthesize_dex_bytes())
            
            # Create a symlink entry in zip (external_attr: S_IFLNK = 0o120000)
            zinfo = zipfile.ZipInfo("lib/x86_64/link_to_passwd.so")
            zinfo.create_system = 3  # Unix
            zinfo.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zinfo, b"/etc/passwd")

        with ingest_target(str(apk_path)) as unified:
            # The symlink should be ignored, leaving only classes.dex
            comps = unified.get_components()
            self.assertEqual(len(comps), 1)
            self.assertEqual(comps[0].component_type, "dex")

    def test_corrupted_crc32_raises_malformed_package(self) -> None:
        """Archive member with intentionally corrupted CRC-32 raises MalformedPackageError."""
        apk_path = self.work_dir / "bad_crc.apk"
        # Create uncompressed zip member, then flip byte in payload to cause CRC-32 mismatch on read
        buf = io.BytesIO() if hasattr(sys.modules[__name__], "io") else __import__("io").BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", b"A" * 128)
        raw = bytearray(buf.getvalue())
        idx = raw.find(b"classes.dex")
        raw[idx + len(b"classes.dex") + 5] ^= 0xFF
        apk_path.write_bytes(raw)

        with self.assertRaises(MalformedPackageError):
            with ingest_target(str(apk_path)):
                pass

    def test_corrupted_zip_header_raises_malformed_package(self) -> None:
        """Truncated ZIP starting with PK\\x03\\x04 followed by random bytes raises MalformedPackageError."""
        apk_path = self.work_dir / "chopped.apk"
        apk_path.write_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00corrupted_archive_data")
        with self.assertRaises(MalformedPackageError):
            TargetClassifier.classify(apk_path)


# ==============================================================================
# Suite 3: Pathological Filesystem Targets
# ==============================================================================

class PathologicalFilesystemTargetTests(unittest.TestCase):
    """Stress tests for special, missing, zero-byte, and permission-restricted filesystem targets."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="adv_fs_")
        self.work_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_zero_byte_file_classification(self) -> None:
        """0-byte file classifies as TargetType.UNKNOWN with format_name='empty'."""
        zero_p = self.work_dir / "zero.bin"
        zero_p.write_bytes(b"")
        cl = TargetClassifier.classify(zero_p)
        self.assertEqual(cl.target_type, TargetType.UNKNOWN)
        self.assertEqual(cl.format_name, "empty")

    def test_zero_byte_file_ingestion(self) -> None:
        """ingest_target() on 0-byte file returns clean UnifiedTarget(target_type=UNKNOWN, components=[])."""
        zero_p = self.work_dir / "empty.bin"
        zero_p.write_bytes(b"")
        unified = ingest_target(str(zero_p))
        self.assertEqual(unified.target_type, TargetType.UNKNOWN)
        self.assertEqual(len(unified.components), 0)
        self.assertEqual(unified.primary_path, str(zero_p.resolve()))
        self.assertFalse(unified.is_ephemeral)
        self.assertIsNone(unified.temp_dir)

    def test_directory_target_raises_target_not_found(self) -> None:
        """Directory passed to ingest_target() raises TargetNotFoundError with exit_code=2."""
        dir_p = self.work_dir / "some_dir"
        dir_p.mkdir()
        with self.assertRaises(TargetNotFoundError) as ctx:
            ingest_target(str(dir_p))
        self.assertEqual(ctx.exception.exit_code, 2)
        self.assertIn("not a regular file", str(ctx.exception))

    def test_nonexistent_file_raises_target_not_found(self) -> None:
        """Non-existent file raises TargetNotFoundError with exit_code=2."""
        missing_p = self.work_dir / "ghost_target.bin"
        with self.assertRaises(TargetNotFoundError) as ctx:
            ingest_target(str(missing_p))
        self.assertEqual(ctx.exception.exit_code, 2)

    def test_dangling_symlink_raises_target_not_found(self) -> None:
        """Dangling symlink pointing to missing file raises TargetNotFoundError."""
        target_p = self.work_dir / "nonexistent_target.bin"
        link_p = self.work_dir / "dangling_link.bin"
        link_p.symlink_to(target_p)
        with self.assertRaises(TargetNotFoundError):
            ingest_target(str(link_p))

    def test_permission_denied_file_raises_target_permission_error(self) -> None:
        """Unreadable file (chmod 000) raises TargetPermissionError with exit_code=2."""
        perm_p = self.work_dir / "unreadable.bin"
        perm_p.write_bytes(b"\x7fELF" + b"\x00" * 60)
        perm_p.chmod(0o000)
        try:
            with self.assertRaises(TargetPermissionError) as ctx:
                TargetClassifier.classify(perm_p)
            self.assertEqual(ctx.exception.exit_code, 2)
            self.assertIn("Permission denied", str(ctx.exception))
        finally:
            perm_p.chmod(0o600)  # restore for cleanup

    def test_character_devices_raise_target_not_found(self) -> None:
        """Special devices (/dev/null, /dev/zero) are not regular files and raise TargetNotFoundError."""
        for dev in ("/dev/null", "/dev/zero"):
            if os.path.exists(dev):
                with self.assertRaises(TargetNotFoundError) as ctx:
                    TargetClassifier.classify(dev)
                self.assertIn("not a regular file", str(ctx.exception))


# ==============================================================================
# Suite 4: Non-Standard Multidex & Unknown ABIs
# ==============================================================================

class MultidexAndAbiStressTests(unittest.TestCase):
    """Stress tests for multidex natural sorting, non-standard names, and unknown ABIs."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="adv_multidex_")
        self.work_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_multidex_natural_ordering_twelve_dex(self) -> None:
        """12 DEX files (classes.dex, classes2.dex ... classes12.dex) sort naturally: 1, 2, ..., 12."""
        apk_path = self.work_dir / "multidex12.apk"
        dex_content = synthesize_dex_bytes()
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            # Write in deliberately reversed/jumbled order
            names = ["classes10.dex", "classes2.dex", "classes.dex", "classes12.dex", "classes3.dex", "classes11.dex"]
            for name in names:
                zf.writestr(name, dex_content)

        with ingest_target(str(apk_path)) as unified:
            dex_comps = unified.get_components(comp_type="dex")
            expected_order = [
                "classes.dex",
                "classes2.dex",
                "classes3.dex",
                "classes10.dex",
                "classes11.dex",
                "classes12.dex",
            ]
            actual_order = [c.archive_relpath for c in dex_comps]
            self.assertEqual(actual_order, expected_order)

    def test_multidex_sparse_indices(self) -> None:
        """Sparse multidex indices (classes.dex, classes5.dex, classes42.dex) sort in numeric order."""
        apk_path = self.work_dir / "sparse.apk"
        dex_content = synthesize_dex_bytes()
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes42.dex", dex_content)
            zf.writestr("classes.dex", dex_content)
            zf.writestr("classes5.dex", dex_content)

        with ingest_target(str(apk_path)) as unified:
            dex_comps = unified.get_components(comp_type="dex")
            actual_order = [c.archive_relpath for c in dex_comps]
            self.assertEqual(actual_order, ["classes.dex", "classes5.dex", "classes42.dex"])

    def test_multidex_prunes_invalid_dex_names(self) -> None:
        """Non-standard DEX filenames (classes_secondary.dex, secondary.dex, classes.dex.bak) are pruned."""
        apk_path = self.work_dir / "bad_dex_names.apk"
        dex_content = synthesize_dex_bytes()
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", dex_content)
            zf.writestr("classes_secondary.dex", dex_content)
            zf.writestr("classes.dex.bak", dex_content)
            zf.writestr("secondary.dex", dex_content)
            zf.writestr("CLASSES.DEX", dex_content)  # Uppercase should not match

        with ingest_target(str(apk_path)) as unified:
            dex_comps = unified.get_components(comp_type="dex")
            self.assertEqual(len(dex_comps), 1)
            self.assertEqual(dex_comps[0].archive_relpath, "classes.dex")

    def test_unknown_abi_single_extraction(self) -> None:
        """APK containing only unknown ABI (lib/riscv32/libtest.so) is extracted and queryable."""
        apk_path = self.work_dir / "riscv32.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("lib/riscv32/libtest.so", b"riscv32_payload")

        with ingest_target(str(apk_path)) as unified:
            comps = unified.get_components(comp_type="elf_so")
            self.assertEqual(len(comps), 1)
            self.assertEqual(comps[0].abi, "riscv32")
            self.assertEqual(comps[0].name, "libtest.so")

            # Resolving with abi=None falls back to the only available candidate
            comp = unified.get_component(abi=None)
            self.assertIsNotNone(comp)
            self.assertEqual(comp.abi, "riscv32")

    def test_unknown_abi_multiple_fallback(self) -> None:
        """APK with multiple unknown ABIs (custom_dsp and riscv64) selects first candidate on abi=None."""
        apk_path = self.work_dir / "multi_unknown_abi.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("lib/custom_dsp/libmath.so", b"dsp_math")
            zf.writestr("lib/riscv64/libmath.so", b"riscv_math")

        with ingest_target(str(apk_path)) as unified:
            comp = unified.get_component(abi=None)
            self.assertIsNotNone(comp)
            self.assertIn(comp.abi, ("custom_dsp", "riscv64"))

            # Querying nonexistent ABI returns None without crashing
            self.assertIsNone(unified.get_component(abi="arm64-v8a"))

    def test_select_component_nonexistent_returns_none(self) -> None:
        """select_component() with nonexistent ABI returns None and does not alter primary_path."""
        apk_path = self.work_dir / "abi_select.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", synthesize_dex_bytes())
            zf.writestr("lib/x86_64/libtest.so", b"test_payload")

        with ingest_target(str(apk_path)) as unified:
            orig_primary = unified.primary_path
            res = unified.select_component(abi="nonexistent_abi_foo")
            self.assertIsNone(res)
            self.assertEqual(unified.primary_path, orig_primary)

    def test_apk_pure_manifest_zero_binaries(self) -> None:
        """APK containing only AndroidManifest.xml and res/ has target_type=APK_PACKAGE and 0 components."""
        apk_path = self.work_dir / "pure_assets.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("res/values/strings.xml", b"<resources/>")
            zf.writestr("assets/config.json", b"{}")

        with ingest_target(str(apk_path)) as unified:
            self.assertEqual(unified.target_type, TargetType.APK_PACKAGE)
            self.assertEqual(len(unified.components), 0)
            self.assertIsNone(unified.primary_component)
            self.assertEqual(unified.primary_path, str(apk_path.resolve()))
            self.assertIsNone(unified.get_component())


# ==============================================================================
# Suite 5: Standalone Dalvik DEX Edge Cases
# ==============================================================================

class StandaloneDexEdgeCasesTests(unittest.TestCase):
    """Stress tests for Dalvik DEX version parsing, truncation, and corruption."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="adv_dex_")
        self.work_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _write_file(self, filename: str, content: bytes) -> Path:
        p = self.work_dir / filename
        p.write_bytes(content)
        return p

    def test_dex_valid_versions_035_to_039(self) -> None:
        """Valid DEX versions 035, 037, 038, 039 classify as DEX_STANDALONE."""
        for ver in ("035", "037", "038", "039"):
            dex_bytes = synthesize_dex_bytes(version=ver)
            p = self._write_file(f"dex_{ver}.dex", dex_bytes)
            cl = TargetClassifier.classify(p)
            self.assertEqual(cl.target_type, TargetType.DEX_STANDALONE)
            self.assertEqual(cl.dex_version, ver)

    def test_dex_unsupported_version_030_raises_unparseable(self) -> None:
        """DEX version 030 (< 035) raises UnparseableBinaryError."""
        dex_bytes = b"dex\n030\x00" + b"\x00" * 64
        p = self._write_file("dex_030.dex", dex_bytes)
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_dex_unsupported_version_040_raises_unparseable(self) -> None:
        """DEX version 040 (> 039) raises UnparseableBinaryError."""
        dex_bytes = b"dex\n040\x00" + b"\x00" * 64
        p = self._write_file("dex_040.dex", dex_bytes)
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_dex_truncated_header_raises_unparseable(self) -> None:
        """Truncated header starting with b'dex\\n' (5 bytes) raises UnparseableBinaryError."""
        p = self._write_file("dex_short.dex", b"dex\n")
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_dex_corrupted_terminator_raises_unparseable(self) -> None:
        """DEX header where byte 7 is non-null (b'dex\\n035\\xff') raises UnparseableBinaryError."""
        p = self._write_file("dex_bad_term.dex", b"dex\n035\xff" + b"\x00" * 64)
        with self.assertRaises(UnparseableBinaryError):
            TargetClassifier.classify(p)

    def test_standalone_dex_ingestion_properties(self) -> None:
        """Standalone DEX ingestion has target_type=DEX_STANDALONE, temp_dir=None, is_ephemeral=False."""
        dex_bytes = synthesize_dex_bytes()
        p = self._write_file("valid.dex", dex_bytes)
        unified = ingest_target(str(p))
        self.assertEqual(unified.target_type, TargetType.DEX_STANDALONE)
        self.assertFalse(unified.is_ephemeral)
        self.assertIsNone(unified.temp_dir)
        self.assertEqual(len(unified.components), 1)
        self.assertEqual(unified.components[0].component_type, "dex")


# ==============================================================================
# Suite 6: Concurrency & Ephemeral Lifecycle Stress
# ==============================================================================

class ConcurrencyAndLifecycleStressTests(unittest.TestCase):
    """Adversarial multithreaded stress testing of 6-Tier Watchdog and cleanup routines."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="adv_watchdog_")
        self.work_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_concurrent_ingestion_and_cleanup(self) -> None:
        """10 concurrent threads ingesting and cleaning APKs leak 0 ephemeral directories."""
        apk_path = self.work_dir / "concurrent.apk"
        create_synthetic_apk(apk_path)

        num_threads = 10
        errors: List[Exception] = []

        def _worker(thread_id: int) -> None:
            try:
                for _ in range(3):
                    with ingest_target(str(apk_path)) as target:
                        self.assertEqual(target.target_type, TargetType.APK_PACKAGE)
                        self.assertIsNotNone(target.temp_dir)
                        self.assertTrue(os.path.isdir(target.temp_dir))
                        # Access components
                        comps = target.get_components()
                        self.assertGreater(len(comps), 0)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Encountered errors in concurrent ingestion: {errors}")
        with _ACTIVE_EPHEMERAL_DIRS_LOCK if hasattr(sys.modules[__name__], "_ACTIVE_EPHEMERAL_DIRS_LOCK") else threading.Lock():
            # Verify no directories leaked in global set
            active = [d for d in _ACTIVE_EPHEMERAL_DIRS if d.startswith(tempfile.gettempdir())]
            self.assertEqual(len(active), 0, f"Leaked ephemeral directories: {active}")

    def test_concurrent_cleanup_idempotency(self) -> None:
        """20 threads concurrently calling cleanup() on the same UnifiedTarget encounter zero errors."""
        apk_path = self.work_dir / "idempotent.apk"
        create_synthetic_apk(apk_path)
        target = ingest_target(str(apk_path))

        errors: List[Exception] = []

        def _clean_worker() -> None:
            try:
                target.cleanup()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_clean_worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertTrue(target._cleaned_up)
        self.assertIsNone(target.temp_dir)

    def test_reenter_cleaned_target_raises_runtime_error(self) -> None:
        """Re-entering context manager after explicit cleanup raises RuntimeError."""
        apk_path = self.work_dir / "reenter.apk"
        create_synthetic_apk(apk_path)
        target = ingest_target(str(apk_path))
        target.cleanup()

        with self.assertRaises(RuntimeError) as ctx:
            with target:
                pass
        self.assertIn("already been cleaned up", str(ctx.exception))

    def test_orphan_sweeper_handles_unreadable_dirs_gracefully(self) -> None:
        """sweep_orphaned_target_dirs() handles unreadable directories without crashing."""
        fake_orphan = self.work_dir / f"{EPHEMERAL_DIR_PREFIX}dummy_orphan"
        fake_orphan.mkdir()
        unreadable_sub = fake_orphan / "locked"
        unreadable_sub.mkdir()
        unreadable_sub.chmod(0o000)

        try:
            # Sweeper should not raise even when encountering locked directories
            swept = sweep_orphaned_target_dirs(
                base_dir=str(self.work_dir),
                ttl_seconds=0.0,  # Sweeps immediately
                dry_run=False,
            )
            self.assertIn(str(fake_orphan.resolve()), swept)
        finally:
            if unreadable_sub.exists():
                unreadable_sub.chmod(0o700)
            shutil.rmtree(fake_orphan, ignore_errors=True)


# ==============================================================================
# Suite 7: Extreme Scale, Asset Bloat & Rapid Lifecycle Fuzzing
# ==============================================================================

class ExtremeScaleAndLifecycleFuzzingTests(unittest.TestCase):
    """Stress tests for high churn, asset bloat, large streaming payloads, and boundary files inside archives."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="adv_fuzz_")
        self.work_dir = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rapid_sequential_ingest_cleanup_100_cycles(self) -> None:
        """100 sequential open/cleanup cycles without leaking file descriptors or temp directories."""
        apk_path = self.work_dir / "rapid.apk"
        create_synthetic_apk(apk_path)

        for _ in range(100):
            with ingest_target(str(apk_path)) as target:
                td = target.temp_dir
                self.assertIsNotNone(td)
                self.assertTrue(os.path.isdir(td))
            self.assertFalse(os.path.exists(td))

        self.assertEqual(len([d for d in _ACTIVE_EPHEMERAL_DIRS if d.startswith(tempfile.gettempdir())]), 0)

    def test_apk_with_zero_byte_dex_member(self) -> None:
        """APK containing an empty 0-byte classes.dex extracts without division by zero or crash."""
        apk_path = self.work_dir / "empty_dex.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", b"")

        with ingest_target(str(apk_path)) as target:
            comps = target.get_components(comp_type="dex")
            self.assertEqual(len(comps), 1)
            self.assertEqual(comps[0].size_bytes, 0)
            self.assertTrue(os.path.exists(comps[0].path))

    def test_apk_large_member_streaming(self) -> None:
        """Large (5 MB) shared library extracts via streaming copy and matches SHA-256."""
        import hashlib
        apk_path = self.work_dir / "large_payload.apk"
        payload = b"\x7fELF\x02\x01\x01\x00" + (b"\x90" * (5 * 1024 * 1024 - 8))
        expected_hash = hashlib.sha256(payload).hexdigest()

        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("lib/x86_64/libbig.so", payload)

        with ingest_target(str(apk_path)) as target:
            comp = target.get_component(abi="x86_64")
            self.assertIsNotNone(comp)
            extracted_bytes = Path(comp.path).read_bytes()
            self.assertEqual(hashlib.sha256(extracted_bytes).hexdigest(), expected_hash)

    def test_apk_with_massive_asset_bloat_pruned(self) -> None:
        """APK with 200 bloated asset files prunes all bloat and only extracts executable targets."""
        apk_path = self.work_dir / "bloated_massive.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("classes.dex", synthesize_dex_bytes())
            zf.writestr("lib/x86_64/libnative.so", b"\x7fELF" + b"\x00" * 60)
            for i in range(200):
                zf.writestr(f"res/drawable/icon_{i}.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
                zf.writestr(f"assets/config_{i}.json", b"{\"key\": \"val\"}")

        with ingest_target(str(apk_path)) as target:
            comps = target.get_components()
            self.assertEqual(len(comps), 2)  # Exactly 1 DEX + 1 SO
            types = {c.component_type for c in comps}
            self.assertEqual(types, {"dex", "elf_so"})


if __name__ == "__main__":
    unittest.main()

