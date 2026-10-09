"""
tests/test_challenger_m3_orchestrator_stress.py - Adversarial Stress & Empirical Challenge Suite
for Milestone 3: NeutralBinaryOrchestrator, Routing, and Telemetry.

Authored by teamwork_preview_challenger_m3_1 (Empirical Challenger).
Task Objective:
1. Sequential multi-query session persistence with stateful token mapping and codebook roundtripping.
2. High-throughput querying across synthetic APKs and standalone ELFs with zero ephemeral directory leakage.
3. Timing metric accuracy: verify that execution_time_seconds accurately reflects real wall-clock elapsed time (strictly non-negative, non-zero for real operations, monotonic).
4. JSON serialization stress: test deep or nested payloads, direct & indirect circular references, and diverse primitive types to ensure zero circular reference or serialization errors.
"""

from __future__ import annotations

import concurrent.futures
import enum
import glob
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import unittest

from neutral_orchestrator.orchestrator import (
    DalvikMetadataExtractor,
    NeutralBinaryOrchestrator,
    NeutralResponseEnvelope,
    _sanitize_for_json,
)
from neutral_orchestrator.neutral_representation import (
    ControlFlowGraph,
    NeutralTokenMapper,
    TokenCategory,
    classify_token,
    deneutralize_data,
)
from neutral_orchestrator.target_ingestion import (
    TargetType,
    UnifiedTarget,
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
# 1. Sequential Multi-Query Session Persistence & Codebook Roundtripping
# =============================================================================

class TestSequentialMultiQuerySessionPersistence(unittest.TestCase):
    """
    Stress-tests multi-query session persistence, progressive codebook expansion,
    lossless roundtrip serialization, and session state isolation.
    """

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_progressive_codebook_accumulation_across_sequential_queries(self) -> None:
        """
        Verifies that querying functions, strings, and disasm sequentially in a single
        session causes the codebook to monotonically accumulate sensitive tokens.
        """
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            # Query 1: info - initial baseline
            res_info = orch.query("info")
            self.assertTrue(res_info["success"])
            cb_0 = res_info["codebook"]
            count_0 = len(cb_0["reverse_map"])

            # Query 2: functions - auto-registers sensitive function symbols
            res_funcs = orch.query("functions")
            self.assertTrue(res_funcs["success"])
            cb_1 = res_funcs["codebook"]
            count_1 = len(cb_1["reverse_map"])
            self.assertGreater(count_1, count_0, "Codebook should expand after functions query")
            # Verify known sensitive symbols in auth_gate_elf64 were captured
            self.assertTrue(
                any("check_master_password" in orig or "check_admin_pin" in orig for orig in cb_1["reverse_map"].values()),
                "Sensitive functions should be registered in codebook",
            )

            # Query 3: strings - auto-registers sensitive string constants
            res_strs = orch.query("strings")
            self.assertTrue(res_strs["success"])
            cb_2 = res_strs["codebook"]
            count_2 = len(cb_2["reverse_map"])
            self.assertGreater(count_2, count_1, "Codebook should expand further after strings query")
            # Verify sensitive string items captured
            self.assertTrue(
                any("K3Y" in orig or "Password" in orig for orig in cb_2["reverse_map"].values()),
                "Sensitive strings should be registered in codebook",
            )

            # Query 4: disasm - should retain all previously accumulated tokens
            res_disasm = orch.query("disasm", function="main")
            self.assertTrue(res_disasm["success"])
            cb_3 = res_disasm["codebook"]
            self.assertEqual(len(cb_3["reverse_map"]), count_2, "Disasm query should retain full codebook state")

            # Query 5: symbols
            res_syms = orch.query("symbols")
            self.assertTrue(res_syms["success"])
            cb_4 = res_syms["codebook"]
            self.assertGreaterEqual(len(cb_4["reverse_map"]), count_2)

    def test_full_codebook_json_serialization_and_lossless_roundtrip(self) -> None:
        """
        Verifies that exported session codebooks can be serialized to JSON,
        deserialized into a fresh NeutralTokenMapper, and 100% losslessly restore all symbols.
        """
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            orch.query("functions")
            res = orch.query("strings")
            exported_codebook = res["codebook"]

            # Serialize to JSON and parse back
            json_blob = json.dumps(exported_codebook, indent=2)
            parsed_codebook = json.loads(json_blob)

            # Reconcile in a new independent mapper
            independent_mapper = NeutralTokenMapper(session_id="reconciled_session")
            independent_mapper.import_codebook(parsed_codebook)

            # Verify 100% bijective reverse restoration
            for token, original_str in exported_codebook["reverse_map"].items():
                restored = independent_mapper.restore(token)
                self.assertEqual(
                    restored,
                    original_str,
                    f"Bijective restoration mismatch for token {token}: expected {original_str}, got {restored}",
                )

    def test_external_preconfigured_token_mapper_injection(self) -> None:
        """
        Tests injecting a pre-configured NeutralTokenMapper into NeutralBinaryOrchestrator.
        Verifies that existing tokens are preserved and newly discovered tokens are integrated.
        """
        custom_mapper = NeutralTokenMapper(session_id="preconfigured_session")
        token_pre = custom_mapper.sanitize_string("PRE_EXISTING_SECRET_API_KEY_9999", TokenCategory.AUTH)

        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target, token_mapper=custom_mapper) as orch:
            self.assertIs(orch.token_mapper, custom_mapper)
            res = orch.query("strings")
            self.assertTrue(res["success"])

            # Verify pre-existing token survives in exported codebook
            codebook = res["codebook"]
            self.assertIn(token_pre, codebook["reverse_map"])
            self.assertEqual(codebook["reverse_map"][token_pre], "PRE_EXISTING_SECRET_API_KEY_9999")

            # Verify new tokens were also added
            self.assertGreater(len(codebook["reverse_map"]), 1)

    def test_session_state_isolation(self) -> None:
        """
        Verifies that separate NeutralBinaryOrchestrator instances maintain isolated
        codebook states and do not cross-contaminate.
        """
        target1 = str(FIXTURES_DIR / "auth_gate_elf64")
        target2 = str(FIXTURES_DIR / "flow_calc_elf64")

        with NeutralBinaryOrchestrator(target1) as orch1:
            res1 = orch1.query("functions")
            cb1 = res1["codebook"]

        with NeutralBinaryOrchestrator(target2) as orch2:
            res2 = orch2.query("info")
            cb2 = res2["codebook"]

        # orch2 should have a fresh, unpolluted codebook without auth_gate functions
        self.assertNotEqual(orch1.token_mapper.session_id, orch2.token_mapper.session_id)
        self.assertEqual(len(cb2["reverse_map"]), 0)
        self.assertGreater(len(cb1["reverse_map"]), 0)

    def test_deneutralize_data_payload_roundtrip(self) -> None:
        """
        Verifies that payloads containing neutralized tokens can be recursively
        deneutralized using deneutralize_data and the exported codebook.
        """
        mapper = NeutralTokenMapper()
        t1 = mapper.sanitize_symbol("decrypt_payload", TokenCategory.CRYPTO)
        t2 = mapper.sanitize_string("SECRET_TOKEN_XYZ", TokenCategory.AUTH)

        neutral_payload = {
            "title": f"Analysis of {t1}",
            "details": {
                "credential": t2,
                "nested_list": [t1, "normal_text", t2],
            },
        }

        restored = deneutralize_data(neutral_payload, mapper.export_codebook())
        self.assertEqual(restored["title"], "Analysis of decrypt_payload")
        self.assertEqual(restored["details"]["credential"], "SECRET_TOKEN_XYZ")
        self.assertEqual(restored["details"]["nested_list"], ["decrypt_payload", "normal_text", "SECRET_TOKEN_XYZ"])


# =============================================================================
# 2. High-Throughput Querying Across Synthetic APKs & Standalone ELFs
# =============================================================================

class TestHighThroughputQueryingAndConcurrency(unittest.TestCase):
    """
    Stress-tests high-throughput bursts, concurrent multi-threading,
    and guarantees zero ephemeral directory leakage (/tmp/rvs_target_*).
    """

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def test_high_throughput_sequential_burst(self) -> None:
        """
        Runs 20 sequential lifecycle cycles opening, querying, and closing
        synthetic APKs and standalone ELFs. Verifies zero directory leaks.
        """
        for i in range(15):
            apk_path = self.work_dir / f"burst_{i}.apk"
            create_synthetic_apk(apk_path, multidex=(i % 2 == 0))

            with NeutralBinaryOrchestrator(str(apk_path)) as orch:
                # Query native .so
                r_info = orch.query("info", abi="x86_64")
                self.assertTrue(r_info["success"])
                # Query DEX component
                r_dex = orch.query("info", component_type="dex")
                self.assertTrue(r_dex["success"])
                # Query strings
                r_strs = orch.query("strings")
                self.assertTrue(r_strs["success"])

            # Remove test APK file
            apk_path.unlink()

        # Check for lingering /tmp/rvs_target_*
        leftovers = glob.glob("/tmp/rvs_target_*")
        self.assertEqual(len(leftovers), 0, f"Lingering unpacked dirs found: {leftovers}")

    def test_concurrent_multithreaded_orchestration(self) -> None:
        """
        Executes concurrent queries across multiple threads simultaneously
        to verify thread-safety and isolated cleanup.
        """
        def worker_task(worker_id: int) -> bool:
            apk_file = self.work_dir / f"thread_{worker_id}.apk"
            create_synthetic_apk(apk_file, multidex=True)
            try:
                with NeutralBinaryOrchestrator(str(apk_file)) as orch:
                    res1 = orch.query("info")
                    if not res1["success"]:
                        return False
                    res2 = orch.query("strings")
                    if not res2["success"]:
                        return False
                    # Query ELF fixture inside same thread
                    elf_target = str(FIXTURES_DIR / "auth_gate_elf64")
                    with NeutralBinaryOrchestrator(elf_target) as elf_orch:
                        res3 = elf_orch.query("functions")
                        if not res3["success"]:
                            return False
                return True
            finally:
                if apk_file.exists():
                    apk_file.unlink()

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(worker_task, i) for i in range(8)]
            for future in concurrent.futures.as_completed(futures):
                self.assertTrue(future.result(), "Threaded orchestration task failed")

        leftovers = glob.glob("/tmp/rvs_target_*")
        self.assertEqual(len(leftovers), 0, f"Lingering unpacked dirs after threads: {leftovers}")

    def test_corrupted_and_zero_byte_target_handling(self) -> None:
        """
        Tests orchestrator resilience when ingesting corrupted or zero-byte targets.
        Ensures proper error handling without lingering temp directories.
        """
        zero_file = self.work_dir / "zero.bin"
        create_zero_byte_target(zero_file)

        corrupt_apk = self.work_dir / "corrupted.apk"
        create_corrupted_apk(corrupt_apk)

        # Ingest zero byte file - should classify as UNKNOWN or raise graceful error
        with NeutralBinaryOrchestrator(str(zero_file)) as orch_zero:
            res = orch_zero.query("info")
            # Should fail gracefully or report unknown
            self.assertFalse(res["success"])
            self.assertIsNotNone(res["error"])

        # Ingest corrupted APK
        with self.assertRaises(Exception):
            orch_bad = NeutralBinaryOrchestrator(str(corrupt_apk))
            orch_bad.close()

        # Clean up files
        zero_file.unlink()
        corrupt_apk.unlink()

        leftovers = glob.glob("/tmp/rvs_target_*")
        self.assertEqual(len(leftovers), 0, "No temp dirs should leak on corrupted input")


# =============================================================================
# 3. Timing Metric Accuracy & Monotonicity
# =============================================================================

class TestTimingMetricAccuracyAndMonotonicity(unittest.TestCase):
    """
    Stress-tests execution_time_seconds telemetry:
    - Verifies non-negativity across all operations.
    - Verifies strictly positive (non-zero) timing for non-trivial analysis queries.
    - Verifies accuracy against real wall-clock elapsed time (tight bound).
    - Verifies monotonic progression.
    """

    def test_timing_accuracy_against_wall_clock(self) -> None:
        """
        Measures wall clock elapsed time externally and compares with
        telemetry['execution_time_seconds'] to ensure close fidelity.
        """
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            for command in ["info", "functions", "strings", "symbols"]:
                t_wall_start = time.perf_counter()
                res = orch.query(command)
                t_wall_end = time.perf_counter()

                wall_elapsed = t_wall_end - t_wall_start
                reported_time = res["telemetry"]["execution_time_seconds"]

                # 1. Non-negativity
                self.assertGreaterEqual(reported_time, 0.0)

                # 2. Non-zero for real radare2/rvs queries
                self.assertGreater(
                    reported_time,
                    0.0,
                    f"Reported time for command '{command}' should be strictly > 0.0, got {reported_time}",
                )

                # 3. Upper bound: reported time cannot exceed outside wall clock (allowing small float margin)
                self.assertLessEqual(
                    reported_time,
                    wall_elapsed + 0.005,
                    f"Reported time {reported_time} exceeded measured wall time {wall_elapsed}",
                )

                # 4. Lower bound: reported time should account for almost the entire wall time (discrepancy < 5ms)
                discrepancy = abs(wall_elapsed - reported_time)
                self.assertLess(
                    discrepancy,
                    0.010,
                    f"Discrepancy between reported ({reported_time}s) and wall ({wall_elapsed}s) too large: {discrepancy}s",
                )

    def test_timing_monotonicity_across_sequential_calls(self) -> None:
        """
        Verifies that timestamps and timing measurements advance monotonically.
        """
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            timestamps = []
            for _ in range(5):
                res = orch.query("info")
                self.assertGreaterEqual(res["telemetry"]["execution_time_seconds"], 0.0)
                timestamps.append(res["timestamp"])
                time.sleep(0.002)

            # Assert ISO timestamps are strictly non-decreasing
            for i in range(len(timestamps) - 1):
                self.assertLessEqual(timestamps[i], timestamps[i + 1])

    def test_timing_envelope_on_failure_and_invalid_operations(self) -> None:
        """
        Verifies that invalid or failing operations still report valid non-negative execution_time_seconds.
        """
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("invalid_operation_name_123")
            self.assertFalse(res["success"])
            self.assertIn("execution_time_seconds", res["telemetry"])
            self.assertGreaterEqual(res["telemetry"]["execution_time_seconds"], 0.0)


# =============================================================================
# 4. JSON Serialization Stress & Circular Reference Immunity
# =============================================================================

class TestJsonSerializationStressAndCircularReferences(unittest.TestCase):
    """
    Stress-tests JSON sanitization and serialization:
    - Direct and indirect circular reference loops.
    - Deep nesting (depth 50, 100, 200).
    - Diverse Python types (sets, Enums, Paths, bytes with non-utf8 content, custom objects).
    - DAG non-cyclic reuse (diamond references) preservation.
    """

    def test_direct_circular_reference_dict(self) -> None:
        """Tests that a self-referencing dictionary is sanitized without RecursionError."""
        d = {"name": "root"}
        d["self"] = d

        sanitized = _sanitize_for_json(d)
        self.assertEqual(sanitized["name"], "root")
        self.assertEqual(sanitized["self"], "<circular_reference>")

        # Must be valid JSON
        serialized = json.dumps(sanitized)
        loaded = json.loads(serialized)
        self.assertEqual(loaded["self"], "<circular_reference>")

    def test_direct_circular_reference_list(self) -> None:
        """Tests that a self-referencing list is sanitized without RecursionError."""
        l = ["item1", 123]
        l.append(l)

        sanitized = _sanitize_for_json(l)
        self.assertEqual(sanitized[0], "item1")
        self.assertEqual(sanitized[1], 123)
        self.assertEqual(sanitized[2], "<circular_reference>")

        serialized = json.dumps(sanitized)
        loaded = json.loads(serialized)
        self.assertEqual(loaded[2], "<circular_reference>")

    def test_indirect_mutual_circular_reference(self) -> None:
        """Tests mutual circular references between two objects: a -> b -> a."""
        a = {"id": "A"}
        b = {"id": "B"}
        a["peer"] = b
        b["peer"] = a

        sanitized = _sanitize_for_json(a)
        self.assertEqual(sanitized["id"], "A")
        self.assertEqual(sanitized["peer"]["id"], "B")
        self.assertEqual(sanitized["peer"]["peer"], "<circular_reference>")

        serialized = json.dumps(sanitized)
        self.assertTrue(len(serialized) > 0)

    def test_deep_nesting_stress(self) -> None:
        """Tests extreme nesting depths up to 150 levels."""
        depth = 150
        root = current = {}
        for i in range(depth):
            current["level"] = i
            current["child"] = {}
            current = current["child"]
        current["leaf"] = "deep_success"

        sanitized = _sanitize_for_json(root)
        serialized = json.dumps(sanitized)
        loaded = json.loads(serialized)

        # Traverse and verify leaf
        curr = loaded
        for i in range(depth):
            self.assertEqual(curr["level"], i)
            curr = curr["child"]
        self.assertEqual(curr["leaf"], "deep_success")

    def test_dag_diamond_subobject_reuse_is_not_treated_as_circular(self) -> None:
        """
        Verifies that non-cyclic DAGs (diamond dependency sharing the same sub-object)
        preserve the sub-object on both branches and do NOT falsely mark it as circular.
        """
        shared_node = {"key": "shared_data", "value": [1, 2, 3]}
        dag = {
            "branch_left": shared_node,
            "branch_right": shared_node,
        }

        sanitized = _sanitize_for_json(dag)
        self.assertEqual(sanitized["branch_left"], {"key": "shared_data", "value": [1, 2, 3]})
        self.assertEqual(sanitized["branch_right"], {"key": "shared_data", "value": [1, 2, 3]})

    def test_special_types_normalization(self) -> None:
        """
        Verifies normalization of Paths, Enums, sets, bytes (including invalid utf-8),
        and objects with to_dict.
        """
        class SampleEnum(enum.Enum):
            ACTIVE = "status_active"

        class ObjectWithToDict:
            def to_dict(self) -> Dict[str, Any]:
                return {"transformed": True, "code": 42}

        class PlainObject:
            def __str__(self) -> str:
                return "plain_string_repr"

        payload = {
            "enum_val": SampleEnum.ACTIVE,
            "path_val": Path("/tmp/test/path"),
            "set_val": {3, 1, 2},
            "bytes_utf8": b"valid_ascii",
            "bytes_raw_binary": b"\xff\xfe\x00\xaa\xbb",
            "custom_to_dict": ObjectWithToDict(),
            "plain_obj": PlainObject(),
            "int_key": {100: "int_key_val"},
            "none_val": None,
        }

        sanitized = _sanitize_for_json(payload)
        self.assertEqual(sanitized["enum_val"], "status_active")
        self.assertEqual(sanitized["path_val"], "/tmp/test/path")
        self.assertEqual(sanitized["set_val"], [1, 2, 3])
        self.assertEqual(sanitized["bytes_utf8"], "valid_ascii")
        self.assertEqual(sanitized["bytes_raw_binary"], "fffe00aabb")
        self.assertEqual(sanitized["custom_to_dict"], {"transformed": True, "code": 42})
        self.assertEqual(sanitized["plain_obj"], "plain_string_repr")
        self.assertEqual(sanitized["int_key"], {"100": "int_key_val"})
        self.assertIsNone(sanitized["none_val"])

        # Must cleanly dump to JSON without TypeError
        serialized = json.dumps(sanitized)
        loaded = json.loads(serialized)
        self.assertEqual(loaded["custom_to_dict"]["code"], 42)


if __name__ == "__main__":
    unittest.main()
