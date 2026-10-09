#!/usr/bin/env python3
"""
tests/test_challenger_preview_int_empirical.py - Empirical Adversarial Challenge Suite
for Multi-Target Binary Orchestration Integration in rvs_agent_harness.py.

Authored by teamwork_preview_challenger_int_1 (Empirical Challenger).
Mission:
Empirically stress-test and adversarially challenge the multi-target integration:
1. Stress Test 1: Rapid repeated APK queries (25+ sequential and 20+ concurrent calls)
   via execute_tool("rvs_info", {"file": apk_path}) and verify 0 leaked directories in /tmp/rvs_target_*.
2. Stress Test 2: Adversarial APK inputs:
   - Corrupted zip with PK\\x03\\x04 header
   - Random non-zip garbage bytes named .apk
   - Empty 0-byte file named .apk
   - Valid zip without DEX or SO components
   - Zip Slip path traversal attempts (../../evil.so)
   - Non-existent ABI requests (abi="mips64")
   Verify graceful error envelopes with standardized error codes and zero leaked temp dirs.
3. Stress Test 3: DEX bytecode metadata and string extraction stress test:
   - Header validation (magic, checksum, signature, endianness)
   - ULEB128 string parsing (single-byte and multi-byte length prefixes)
   - Truncated and corrupted DEX error envelopes
   - Unsupported operations (disasm/decompile on DEX)
4. Stress Test 4: neutral=True verification:
   - Bijective codebook completeness (forward <-> reverse bijection)
   - Loss-free reverse restoration via deneutralize_data
   - Strict preservation of disassembly invariants (opcodes, registers, addresses)
   - Invariant violation detection on mutated disassembly
"""

from __future__ import annotations

import concurrent.futures
import copy
import glob
import os
import shutil
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Dict, List

import rvs_agent_harness
from rvs_agent_harness import RvsHarness, _neutralize_data_recursive
from neutral_orchestrator.orchestrator import (
    DalvikMetadataExtractor,
    NeutralBinaryOrchestrator,
)
from neutral_orchestrator.neutral_representation import (
    InvariantViolationError,
    NeutralTokenMapper,
    TokenCategory,
    classify_token,
    deneutralize_data,
    diagnose_invariants,
    verify_invariants,
)
from neutral_orchestrator.target_ingestion import (
    MalformedPackageError,
    SecurityViolationError,
    TargetClassifier,
    TargetType,
)
from tests.fixtures_builder import (
    create_synthetic_apk,
    create_synthetic_dex,
    synthesize_dex_bytes,
)


def _get_active_rvs_target_dirs() -> List[str]:
    """Helper returning any lingering ephemeral directories in /tmp/rvs_target_*."""
    return glob.glob(os.path.join(tempfile.gettempdir(), "rvs_target_*"))


class TestStress1RapidRepeatedApkQueries(unittest.TestCase):
    """
    Stress Test 1: Rapid repeated APK queries via execute_tool("rvs_info", {"file": apk_path}).
    Verifies sequential and concurrent stability and asserts 0 leaked directories in /tmp/rvs_target_*.
    """

    temp_dir_obj: tempfile.TemporaryDirectory
    apk_path: Path
    harness: RvsHarness

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir_obj = tempfile.TemporaryDirectory(prefix="rvs_chal_stress1_")
        cls.apk_path = Path(cls.temp_dir_obj.name) / "sample_multidex.apk"
        create_synthetic_apk(cls.apk_path, multidex=True)
        cls.harness = RvsHarness()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir_obj.cleanup()

    def test_01_sequential_rapid_queries_zero_leak(self) -> None:
        """Runs 25 consecutive execute_tool queries and asserts zero lingering temp dirs."""
        initial_leaks = _get_active_rvs_target_dirs()
        self.assertEqual(len(initial_leaks), 0, f"Lingering dirs before test: {initial_leaks}")

        for i in range(25):
            res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
            self.assertTrue(res.get("success"), f"Iteration {i} failed: {res}")
            self.assertEqual(res.get("command"), "info")
            self.assertIn("arch", res.get("data", {}))

        post_leaks = _get_active_rvs_target_dirs()
        self.assertEqual(len(post_leaks), 0, f"Lingering dirs after 25 calls: {post_leaks}")

    def test_02_concurrent_rapid_queries_zero_leak(self) -> None:
        """Runs 24 concurrent queries across a worker pool and asserts thread safety & zero leaks."""
        initial_leaks = _get_active_rvs_target_dirs()
        self.assertEqual(len(initial_leaks), 0, f"Lingering dirs before test: {initial_leaks}")

        tools = ["rvs_info", "rvs_functions", "rvs_strings", "rvs_symbols"]

        def _worker(idx: int) -> Dict[str, Any]:
            tool_name = tools[idx % len(tools)]
            return self.harness.execute_tool(tool_name, {"file": str(self.apk_path)})

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(_worker, range(24)))

        for idx, res in enumerate(results):
            self.assertTrue(res.get("success"), f"Worker task {idx} failed: {res}")

        post_leaks = _get_active_rvs_target_dirs()
        self.assertEqual(len(post_leaks), 0, f"Lingering dirs after concurrent execution: {post_leaks}")


class TestStress2AdversarialApkInputs(unittest.TestCase):
    """
    Stress Test 2: Adversarial APK inputs.
    Tests corrupted zip, random bytes, empty files, containers without executables,
    Zip Slip attempts, and non-existent ABI requests.
    """

    temp_dir_obj: tempfile.TemporaryDirectory
    temp_dir: Path
    harness: RvsHarness

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir_obj = tempfile.TemporaryDirectory(prefix="rvs_chal_stress2_")
        cls.temp_dir = Path(cls.temp_dir_obj.name)
        cls.harness = RvsHarness()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir_obj.cleanup()

    def test_01_corrupted_zip_header(self) -> None:
        """Corrupted ZIP archive with PK\\x03\\x04 header returns error envelope and zero leaks."""
        bad_zip = self.temp_dir / "corrupted_hdr.apk"
        bad_zip.write_bytes(b"PK\x03\x04" + os.urandom(128))

        res = self.harness.execute_tool("rvs_info", {"file": str(bad_zip)})
        self.assertFalse(res.get("success"))
        self.assertIsNotNone(res.get("error"))
        self.assertEqual(len(_get_active_rvs_target_dirs()), 0)

    def test_02_zip_slip_security_violation(self) -> None:
        """Malicious ZIP containing Zip Slip traversal path is rejected with zero leaks."""
        slip_apk = self.temp_dir / "zip_slip.apk"
        with zipfile.ZipFile(slip_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("../../evil.so", b"evil_bytecode")

        res = self.harness.execute_tool("rvs_info", {"file": str(slip_apk)})
        self.assertFalse(res.get("success"))
        err = res.get("error", {})
        self.assertIn("Zip Slip", err.get("message", ""))
        self.assertEqual(len(_get_active_rvs_target_dirs()), 0)

    def test_03_nonexistent_abi_request(self) -> None:
        """Requesting non-existent ABI returns COMPONENT_NOT_FOUND error envelope and exit_code 2."""
        valid_apk = self.temp_dir / "valid_sample.apk"
        create_synthetic_apk(valid_apk, multidex=False)

        res = self.harness.execute_tool("rvs_info", {"file": str(valid_apk), "abi": "mips64"})
        self.assertFalse(res.get("success"))
        err = res.get("error", {})
        self.assertEqual(err.get("code"), "COMPONENT_NOT_FOUND")
        self.assertEqual(err.get("exit_code"), 2)
        self.assertEqual(len(_get_active_rvs_target_dirs()), 0)

    def test_04_random_garbage_apk_recursion_or_error(self) -> None:
        """
        Adversarial test on random non-zip bytes named .apk.
        Observes whether harness returns a standardized error envelope or exhausts recursion.
        """
        garbage_apk = self.temp_dir / "garbage.apk"
        garbage_apk.write_bytes(os.urandom(512))

        res = self.harness.execute_tool("rvs_info", {"file": str(garbage_apk)})
        self.assertFalse(res.get("success"))
        self.assertEqual(len(_get_active_rvs_target_dirs()), 0)
        # Empirical finding check: should not suffer maximum recursion depth exceeded
        err_msg = res.get("error", {}).get("message", "")
        self.assertNotIn("maximum recursion depth exceeded", err_msg)

    def test_05_empty_zero_byte_apk(self) -> None:
        """
        Adversarial test on empty 0-byte file named .apk.
        Observes whether harness returns a standardized error envelope or exhausts recursion.
        """
        empty_apk = self.temp_dir / "empty.apk"
        empty_apk.write_bytes(b"")

        res = self.harness.execute_tool("rvs_info", {"file": str(empty_apk)})
        self.assertFalse(res.get("success"))
        self.assertEqual(len(_get_active_rvs_target_dirs()), 0)
        err_msg = res.get("error", {}).get("message", "")
        self.assertNotIn("maximum recursion depth exceeded", err_msg)

    def test_06_zip_without_dex_or_so(self) -> None:
        """
        Adversarial test on valid ZIP container without any DEX or native .so components.
        Observes whether harness gracefully handles missing executable components.
        """
        nodex_apk = self.temp_dir / "no_exec.apk"
        with zipfile.ZipFile(nodex_apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest/>")
            zf.writestr("res/values/strings.xml", b"<resources/>")

        res = self.harness.execute_tool("rvs_info", {"file": str(nodex_apk)})
        self.assertFalse(res.get("success"))
        self.assertEqual(len(_get_active_rvs_target_dirs()), 0)
        err_msg = res.get("error", {}).get("message", "")
        self.assertNotIn("maximum recursion depth exceeded", err_msg)


class TestStress3DexMetadataAndBytecodeParsing(unittest.TestCase):
    """
    Stress Test 3: DEX bytecode metadata and string extraction stress test.
    Validates header parsing, ULEB128 string parsing, truncated/corrupted DEX resilience,
    and unsupported DEX operations.
    """

    temp_dir_obj: tempfile.TemporaryDirectory
    temp_dir: Path
    harness: RvsHarness

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir_obj = tempfile.TemporaryDirectory(prefix="rvs_chal_stress3_")
        cls.temp_dir = Path(cls.temp_dir_obj.name)
        cls.harness = RvsHarness()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir_obj.cleanup()

    def test_01_valid_dex_header_and_uleb128_parsing(self) -> None:
        """Valid synthetic DEX with single-byte and multi-byte ULEB128 string lengths."""
        # 300 characters requires 2-byte ULEB128 encoding (0xac, 0x02)
        long_str = "A" * 300
        dex_path = self.temp_dir / "valid_strings.dex"
        dex_bytes = synthesize_dex_bytes(strings=["ShortString", long_str, "EntryPointClass"])
        dex_path.write_bytes(dex_bytes)

        meta = DalvikMetadataExtractor.extract_metadata(dex_path)
        self.assertTrue(meta["valid"])
        self.assertEqual(meta["format"], "dex")
        self.assertEqual(meta["version"], "035")
        self.assertEqual(meta["endian_tag"], hex(0x12345678))
        self.assertEqual(meta["header_size"], 112)
        self.assertEqual(meta["string_count"], 3)
        self.assertIn("ShortString", meta["raw_strings"])
        self.assertIn(long_str, meta["raw_strings"])

        # Test execute_tool rvs_info and rvs_strings integration
        res_info = self.harness.execute_tool("rvs_info", {"file": str(dex_path)})
        self.assertTrue(res_info.get("success"))
        self.assertEqual(res_info.get("data", {}).get("format"), "dex")

        res_str = self.harness.execute_tool("rvs_strings", {"file": str(dex_path)})
        self.assertTrue(res_str.get("success"))
        extracted_strings = [s.get("string") for s in res_str.get("data", {}).get("strings", [])]
        self.assertIn(long_str, extracted_strings)

    def test_02_truncated_dex_file(self) -> None:
        """DEX file smaller than 112-byte header returns valid=False and handles gracefully."""
        trunc_dex = self.temp_dir / "truncated.dex"
        trunc_dex.write_bytes(b"dex\n035\x00" + b"\x00" * 30)

        meta = DalvikMetadataExtractor.extract_metadata(trunc_dex)
        self.assertFalse(meta["valid"])
        self.assertIn("truncated", meta.get("error", "").lower())

        res = self.harness.execute_tool("rvs_info", {"file": str(trunc_dex)})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "ANALYSIS_ERROR")
        self.assertEqual(res.get("error", {}).get("exit_code"), 3)

    def test_03_invalid_magic_bytes_dex(self) -> None:
        """DEX file with corrupted magic bytes returns valid=False."""
        bad_magic_dex = self.temp_dir / "bad_magic.dex"
        bad_magic_dex.write_bytes(b"BAD\x00\x00\x00\x00\x00" + b"\x00" * 104)

        meta = DalvikMetadataExtractor.extract_metadata(bad_magic_dex)
        self.assertFalse(meta["valid"])
        self.assertIn("magic", meta.get("error", "").lower())

        res = self.harness.execute_tool("rvs_info", {"file": str(bad_magic_dex)})
        self.assertFalse(res.get("success"))
        err_msg = res.get("error", {}).get("message", "")
        self.assertNotIn("maximum recursion depth exceeded", err_msg)

    def test_04_corrupted_string_table_offsets(self) -> None:
        """DEX with out-of-bounds string table offset handles bounds checking without crash."""
        raw_dex = bytearray(synthesize_dex_bytes(strings=["Sample"]))
        # Corrupt string_ids_off at offset 0x3C to out-of-bounds offset
        struct.pack_into("<I", raw_dex, 0x3C, 0x7FFFFFFF)
        corrupt_str_dex = self.temp_dir / "corrupt_str.dex"
        corrupt_str_dex.write_bytes(raw_dex)

        meta = DalvikMetadataExtractor.extract_metadata(corrupt_str_dex)
        self.assertTrue(meta["valid"])
        self.assertEqual(len(meta.get("strings", [])), 0)

    def test_05_unsupported_dex_disassembly_error_envelope(self) -> None:
        """Calling rvs_disasm on DEX target returns UNSUPPORTED_DEX_OPERATION with exit_code 3."""
        dex_path = self.temp_dir / "ops.dex"
        create_synthetic_dex(dex_path, strings=["FuncA", "FuncB"])

        res = self.harness.execute_tool("rvs_disasm", {"file": str(dex_path), "target": "FuncA"})
        self.assertFalse(res.get("success"))
        err = res.get("error", {})
        self.assertEqual(err.get("code"), "UNSUPPORTED_DEX_OPERATION")
        self.assertEqual(err.get("exit_code"), 3)


class TestStress4NeutralRepresentationAndInvariants(unittest.TestCase):
    """
    Stress Test 4: neutral=True verification.
    Validates bijective codebook completeness, loss-free reverse restoration,
    strict invariant preservation, and invariant violation catching.
    """

    temp_dir_obj: tempfile.TemporaryDirectory
    apk_path: Path
    harness: RvsHarness

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir_obj = tempfile.TemporaryDirectory(prefix="rvs_chal_stress4_")
        cls.apk_path = Path(cls.temp_dir_obj.name) / "sample_multidex.apk"
        create_synthetic_apk(cls.apk_path, multidex=True)
        cls.harness = RvsHarness()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir_obj.cleanup()

    def test_01_bijective_codebook_completeness(self) -> None:
        """Validates that all sanitized symbols have complete, 1-to-1 bijective mappings."""
        res = self.harness.execute_tool("rvs_functions", {"file": str(self.apk_path), "neutral": True})
        self.assertTrue(res.get("success"), f"Query failed: {res}")
        self.assertIn("codebook", res)
        self.assertIn("telemetry", res)

        codebook = res["codebook"]
        fwd = codebook.get("forward_map") or codebook.get("forward")
        rev = codebook.get("reverse_map") or codebook.get("reverse")
        self.assertIsNotNone(fwd)
        self.assertIsNotNone(rev)
        self.assertEqual(len(fwd), len(rev), f"Size mismatch: {len(fwd)} vs {len(rev)}")

        for orig_sym, token in fwd.items():
            self.assertEqual(rev.get(token), orig_sym, f"Bijective mapping broken for {orig_sym} -> {token}")

    def test_02_loss_free_reverse_restoration(self) -> None:
        """Validates that deneutralize_data fully restores sanitized symbols to originals."""
        res = self.harness.execute_tool("rvs_functions", {"file": str(self.apk_path), "neutral": True})
        self.assertTrue(res.get("success"))

        neutral_data = res.get("data", {})
        codebook = res.get("codebook", {})

        restored_data = deneutralize_data(neutral_data, codebook=codebook)
        for fn in restored_data.get("functions", []):
            name = fn.get("name", "")
            self.assertFalse(name.startswith("SYM_TOKEN_"), f"Token failed to restore: {name}")

    def test_03_disassembly_invariant_preservation(self) -> None:
        """Validates that neutral representation strictly preserves opcodes, registers, and addresses."""
        raw_disasm = {
            "blocks": [
                {
                    "addr": 0x1000,
                    "instructions": [
                        {"addr": 0x1000, "disasm": "mov rax, 0x20"},
                        {"addr": 0x1004, "disasm": "call sym.auth_gate_check"},
                        {"addr": 0x1009, "disasm": "test eax, eax"},
                        {"addr": 0x100B, "disasm": "je 0x1020"},
                    ],
                }
            ]
        }

        mapper = NeutralTokenMapper()
        mapper.sanitize_symbol("auth_gate_check", category=TokenCategory.AUTH)
        neutral_disasm = _neutralize_data_recursive(raw_disasm, mapper)

        # Invariants must strictly hold
        is_valid = verify_invariants(raw_disasm, neutral_disasm, codebook=mapper.export_codebook())
        self.assertTrue(is_valid, "Invariants verification failed on valid neutralized disassembly")

    def test_04_invariant_violation_detection(self) -> None:
        """Asserts that verify_invariants catches mutated opcodes, registers, and addresses."""
        base_disasm = [
            {"addr": 0x1000, "disasm": "mov rax, 0x20"},
            {"addr": 0x1004, "disasm": "call 0x1050"},
        ]

        # 1. Mutate opcode
        mutated_op = copy.deepcopy(base_disasm)
        mutated_op[0]["disasm"] = "xor rax, 0x20"
        self.assertFalse(verify_invariants(base_disasm, mutated_op))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(base_disasm, mutated_op, strict=True)

        # 2. Mutate register
        mutated_reg = copy.deepcopy(base_disasm)
        mutated_reg[0]["disasm"] = "mov rbx, 0x20"
        self.assertFalse(verify_invariants(base_disasm, mutated_reg))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(base_disasm, mutated_reg, strict=True)

        # 3. Mutate address
        mutated_addr = copy.deepcopy(base_disasm)
        mutated_addr[0]["addr"] = 0x2000
        self.assertFalse(verify_invariants(base_disasm, mutated_addr))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(base_disasm, mutated_addr, strict=True)


if __name__ == "__main__":
    unittest.main()
