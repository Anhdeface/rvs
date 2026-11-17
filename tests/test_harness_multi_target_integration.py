#!/usr/bin/env python3
"""
tests/test_harness_multi_target_integration.py - Comprehensive Multi-Target Integration Test Suite.

Authoritative Specification: Section 7 of survey2_3/handoff.md
Covers the 28-case test matrix across Groups A through F:
- Group A (A.1 - A.5): APK default ABI auto-extraction (x86_64), functions/strings/disasm queries on APK, fallback.
- Group B (B.1 - B.4): Explicit ABI selection (arm64-v8a), non-existent ABI error envelope, case normalization.
- Group C (C.1 - C.5): Standalone DEX auto-detection, APK component_type="dex", strings query on DEX, unsupported DEX ops.
- Group D (D.1 - D.5): neutral=True attaches codebook & telemetry, tokenizes sensitive symbols/strings, preserves semantic invariants, boolean coercion, roundtrip deneutralization.
- Group E (E.1 - E.7): CLI subprocess execution with -f <apk> info, --abi arm64-v8a, --neutral, standalone DEX, --export-tools mcp schema validation.
- Group F (F.1 - F.4): Zero ephemeral leakage verification (assert zero lingering /tmp/rvs_target_* directories across repeated tool calls, CLI executions, malformed APKs, multi-tool workflows).
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Set

# Ensure project root is in sys.path
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import RvsHarness, CANONICAL_TOOLS, get_tool_schemas
from tests.fixtures_builder import (
    create_synthetic_apk,
    create_synthetic_dex,
    create_corrupted_apk,
    synthesize_elf_bytes,
    create_synthetic_react_native_apk,
    create_synthetic_flutter_apk,
    create_synthetic_native_cpp_apk,
    create_synthetic_java_only_apk,
    create_synthetic_hybrid_apk,
)
from neutral_orchestrator.neutral_representation import (
    NeutralTokenMapper,
    TokenCategory,
    classify_token,
    verify_invariants,
    deneutralize_data,
)

FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"


class BaseMultiTargetIntegrationTest(unittest.TestCase):
    """Base class for multi-target integration tests providing shared fixtures."""

    temp_dir_obj: tempfile.TemporaryDirectory
    temp_dir: Path
    apk_path: Path
    dex_path: Path
    crackme_path: Path
    auth_gate_path: Path
    harness: RvsHarness

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir_obj = tempfile.TemporaryDirectory(prefix="rvs_test_suite_")
        cls.temp_dir = Path(cls.temp_dir_obj.name)
        cls.apk_path = cls.temp_dir / "sample_multidex.apk"
        cls.dex_path = cls.temp_dir / "classes.dex"
        cls.crackme_path = FIXTURES_DIR / "crackme_case"
        cls.auth_gate_path = FIXTURES_DIR / "auth_gate_elf64"

        # Synthesize standard test multi-ABI APK and standalone DEX
        create_synthetic_apk(cls.apk_path, multidex=True)
        create_synthetic_dex(cls.dex_path, strings=["Lcom/example/Main;", "HelloDexString", "SecretKey123"])
        cls.harness = RvsHarness()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir_obj.cleanup()


# =============================================================================
# Group A: Default ABI Auto-Extraction on APK (A.1 - A.5)
# =============================================================================

class TestGroupAApkDefaultAbi(BaseMultiTargetIntegrationTest):
    """Group A: Default ABI Auto-Extraction on APK."""

    def test_execute_tool_apk_auto_extracts_default_x86_64_abi(self) -> None:
        """Case A.1: execute_tool('rvs_info', {'file': apk}) auto-extracts default x86_64 ABI."""
        res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
        self.assertTrue(res.get("success"), f"Query failed: {res}")
        self.assertEqual(res.get("command"), "info")
        data = res.get("data", {})
        # Native library extracted from x86_64 should report x86 architecture or 64 bits
        self.assertTrue(
            data.get("arch") in ("x86", "x86_64") or data.get("bits") == 64,
            f"Expected x86_64 arch metadata, got: {data}",
        )

    def test_execute_tool_apk_functions_query_default_abi(self) -> None:
        """Case A.2: execute_tool('rvs_functions') discovers functions in default x86_64 ABI."""
        res = self.harness.execute_tool("rvs_functions", {"file": str(self.apk_path), "filter": "check"})
        self.assertTrue(res.get("success"), f"Functions query failed: {res}")
        functions = res.get("data", {}).get("functions", [])
        self.assertIsInstance(functions, list)
        self.assertGreater(len(functions), 0, "Expected functions in default x86_64 native library")

    def test_execute_tool_apk_strings_query_default_abi(self) -> None:
        """Case A.3: execute_tool('rvs_strings') extracts strings from default x86_64 native library."""
        res = self.harness.execute_tool("rvs_strings", {"file": str(self.apk_path), "min_len": 4})
        self.assertTrue(res.get("success"), f"Strings query failed: {res}")
        strings = res.get("data", {}).get("strings", [])
        self.assertIsInstance(strings, list)
        self.assertGreater(len(strings), 0, "Expected extracted strings from native library")

    def test_execute_tool_apk_disasm_query_default_abi(self) -> None:
        """Case A.4: execute_tool('rvs_disasm') disassembles main function in default x86_64 component."""
        res = self.harness.execute_tool("rvs_disasm", {"file": str(self.apk_path), "target": "main"})
        self.assertTrue(res.get("success"), f"Disasm query failed: {res}")
        data = res.get("data", {})
        has_code = ("blocks" in data and len(data["blocks"]) > 0) or ("instructions" in data and len(data["instructions"]) > 0)
        self.assertTrue(has_code, f"Expected blocks or instructions in disasm: {data}")

    def test_execute_tool_apk_single_arm64_library_fallback(self) -> None:
        """Case A.5: APK with single arm64 library falls back gracefully when x86_64 is absent."""
        single_arm_apk = self.temp_dir / "arm_only.apk"
        auth_bytes = self.auth_gate_path.read_bytes()
        create_synthetic_apk(
            single_arm_apk,
            elf_fixtures={"lib/arm64-v8a/libauth.so": auth_bytes},
            multidex=False,
        )
        res = self.harness.execute_tool("rvs_info", {"file": str(single_arm_apk)})
        self.assertTrue(res.get("success"), f"Fallback failed: {res}")
        self.assertEqual(res.get("command"), "info")


# =============================================================================
# Group B: Explicit ABI Analysis (B.1 - B.4)
# =============================================================================

class TestGroupBExplicitAbi(BaseMultiTargetIntegrationTest):
    """Group B: Explicit ABI Selection & Normalization."""

    def test_execute_tool_apk_explicit_arm64_abi(self) -> None:
        """Case B.1: Querying with explicit abi='arm64-v8a' targets the arm64 component."""
        res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path), "abi": "arm64-v8a"})
        self.assertTrue(res.get("success"), f"Explicit ABI query failed: {res}")
        # Active component should reflect arm64
        active_comp = res.get("active_component") or res.get("telemetry", {}).get("active_component")
        self.assertIn("arm64-v8a", str(active_comp))

    def test_execute_tool_apk_functions_explicit_abi(self) -> None:
        """Case B.2: Querying functions with abi='arm64-v8a' enumerates functions in arm64 library."""
        res = self.harness.execute_tool("rvs_functions", {"file": str(self.apk_path), "abi": "arm64-v8a"})
        self.assertTrue(res.get("success"), f"Explicit ABI functions query failed: {res}")
        self.assertIn("functions", res.get("data", {}))

    def test_execute_tool_apk_nonexistent_abi_returns_error_envelope(self) -> None:
        """Case B.3: Querying non-existent ABI returns COMPONENT_NOT_FOUND error envelope with exit code 2."""
        res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path), "abi": "mips64"})
        self.assertFalse(res.get("success"), f"Expected failure for mips64: {res}")
        err = res.get("error", {})
        self.assertEqual(err.get("code"), "COMPONENT_NOT_FOUND")
        self.assertEqual(err.get("exit_code"), 2)

    def test_execute_tool_apk_cased_abi_normalization(self) -> None:
        """Case B.4: Uppercase abi='X86_64' is normalized and succeeds without error."""
        res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path), "abi": "X86_64"})
        self.assertTrue(res.get("success"), f"Cased ABI normalization failed: {res}")


# =============================================================================
# Group C: Dalvik DEX Metadata Extraction (C.1 - C.5)
# =============================================================================

class TestGroupCDalvikDexRouting(BaseMultiTargetIntegrationTest):
    """Group C: Standalone DEX and APK DEX Component Routing."""

    def test_execute_tool_standalone_dex_auto_detects_dalvik(self) -> None:
        """Case C.1: Standalone DEX file is auto-detected and parsed via Dalvik extractor."""
        res = self.harness.execute_tool("rvs_info", {"file": str(self.dex_path)})
        self.assertTrue(res.get("success"), f"DEX info failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("valid"), f"DEX invalid: {data}")
        self.assertIn("string_count", data)

    def test_execute_tool_apk_with_component_type_dex(self) -> None:
        """Case C.2: Querying APK with component_type='dex' routes to classes.dex metadata."""
        res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path), "component_type": "dex"})
        self.assertTrue(res.get("success"), f"APK DEX component query failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("valid"))
        self.assertIn("string_count", data)

    def test_execute_tool_dex_strings_query(self) -> None:
        """Case C.3: execute_tool('rvs_strings') on standalone DEX extracts string table."""
        res = self.harness.execute_tool("rvs_strings", {"file": str(self.dex_path), "min_len": 4})
        self.assertTrue(res.get("success"), f"DEX strings failed: {res}")
        strings = [s.get("string", "") for s in res.get("data", {}).get("strings", [])]
        self.assertTrue(any("HelloDexString" in s for s in strings), f"Expected 'HelloDexString' in: {strings}")

    def test_execute_tool_apk_dex_strings_with_component_type(self) -> None:
        """Case C.4: Querying APK with rvs_strings and component_type='dex' extracts Dalvik strings."""
        res = self.harness.execute_tool("rvs_strings", {"file": str(self.apk_path), "component_type": "dex"})
        self.assertTrue(res.get("success"), f"APK DEX strings failed: {res}")
        self.assertIn("strings", res.get("data", {}))

    def test_execute_tool_unsupported_dex_operation_envelope(self) -> None:
        """Case C.5: Unsupported operations on DEX (e.g. decompile) return UNSUPPORTED_DEX_OPERATION (exit_code 3)."""
        res = self.harness.execute_tool("rvs_decompile", {"file": str(self.dex_path), "function": "main"})
        self.assertFalse(res.get("success"), f"Expected failure for DEX decompile: {res}")
        err = res.get("error", {})
        self.assertEqual(err.get("code"), "UNSUPPORTED_DEX_OPERATION")
        self.assertEqual(err.get("exit_code"), 3)


# =============================================================================
# Group D: Neutral Representation & Telemetry (D.1 - D.5)
# =============================================================================

class TestGroupDNeutralRepresentation(BaseMultiTargetIntegrationTest):
    """Group D: Neutral Representation, Bijective Codebooks, and Telemetry."""

    def test_execute_tool_neutral_includes_codebook_and_telemetry(self) -> None:
        """Case D.1: neutral=True returns envelope containing bijective codebook and execution telemetry."""
        res = self.harness.execute_tool("rvs_info", {"file": str(self.crackme_path), "neutral": True})
        self.assertTrue(res.get("success"), f"Neutral info failed: {res}")
        self.assertIn("codebook", res)
        self.assertIsInstance(res["codebook"], dict)
        self.assertIn("telemetry", res)
        self.assertGreaterEqual(res["telemetry"].get("execution_time_seconds", -1.0), 0.0)

    def test_execute_tool_neutral_sanitizes_sensitive_symbols(self) -> None:
        """Case D.2: neutral=True sanitizes sensitive function names and registers them in codebook."""
        res = self.harness.execute_tool("rvs_functions", {"file": str(self.auth_gate_path), "neutral": True})
        self.assertTrue(res.get("success"), f"Neutral functions failed: {res}")
        codebook = res.get("codebook", {})
        fwd = codebook.get("forward_map", {})
        self.assertTrue(
            any("check_" in k for k in fwd.keys()),
            f"Expected sensitive check functions in codebook: {fwd}",
        )
        fn_names = [f.get("name", "") for f in res.get("data", {}).get("functions", [])]
        self.assertTrue(
            any("SYM_TOKEN_" in name for name in fn_names),
            f"Expected sanitized token names in functions list: {fn_names}",
        )

    def test_execute_tool_neutral_preserves_semantic_invariants(self) -> None:
        """Case D.3: neutral=True disasm preserves semantic invariants (opcodes, registers, addresses intact)."""
        raw = self.harness.execute_tool("rvs_disasm", {"file": str(self.crackme_path), "target": "main", "neutral": False})
        neut = self.harness.execute_tool("rvs_disasm", {"file": str(self.crackme_path), "target": "main", "neutral": True})
        self.assertTrue(raw.get("success"))
        self.assertTrue(neut.get("success"))

        mapper = NeutralTokenMapper()
        mapper.import_codebook(neut.get("codebook", {}))
        self.assertTrue(
            verify_invariants(raw.get("data"), neut.get("data"), codebook=mapper._codebook),
            "Semantic invariants failed verification between raw and neutral disassembly",
        )

    def test_execute_tool_neutral_boolean_coercion(self) -> None:
        """Case D.4: String booleans 'true' and 'false' coerce correctly for neutral argument."""
        res_t = self.harness.execute_tool("rvs_info", {"file": str(self.crackme_path), "neutral": "true"})
        res_f = self.harness.execute_tool("rvs_info", {"file": str(self.crackme_path), "neutral": "false"})
        self.assertTrue(res_t.get("success"))
        self.assertIn("codebook", res_t)
        self.assertTrue(res_f.get("success"))
        self.assertNotIn("codebook", res_f)

    def test_execute_tool_lossless_deneutralization_roundtrip(self) -> None:
        """Case D.5: Data neutralized via neutral=True restores 100% losslessly via deneutralize_data."""
        raw = self.harness.execute_tool("rvs_functions", {"file": str(self.auth_gate_path), "neutral": False})
        neut = self.harness.execute_tool("rvs_functions", {"file": str(self.auth_gate_path), "neutral": True})
        self.assertTrue(raw.get("success"))
        self.assertTrue(neut.get("success"))

        restored = deneutralize_data(neut.get("data"), codebook=neut.get("codebook"))
        self.assertEqual(restored, raw.get("data"), "Lossless deneutralization roundtrip mismatch")


# =============================================================================
# Group E: CLI Subprocess Execution with --abi and --neutral (E.1 - E.7)
# =============================================================================

class TestGroupECliExecution(BaseMultiTargetIntegrationTest):
    """Group E: CLI Subprocess Execution and Schema Validation."""

    harness_script: str = str(WORKSPACE_DIR / "rvs_agent_harness.py")

    def test_cli_apk_default_abi_info(self) -> None:
        """Case E.1: CLI command '-f sample.apk info' executes successfully with return code 0."""
        p = subprocess.run(
            [sys.executable, self.harness_script, "-f", str(self.apk_path), "info"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, f"CLI error: {p.stderr}")
        parsed = json.loads(p.stdout)
        self.assertTrue(parsed.get("success"))
        self.assertEqual(parsed.get("command"), "info")

    def test_cli_apk_explicit_abi_flag(self) -> None:
        """Case E.2: CLI command with '--abi arm64-v8a' targets arm64 component."""
        p = subprocess.run(
            [sys.executable, self.harness_script, "-f", str(self.apk_path), "--abi", "arm64-v8a", "info"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, f"CLI error: {p.stderr}")
        parsed = json.loads(p.stdout)
        self.assertTrue(parsed.get("success"))

    def test_cli_apk_explicit_abi_equals_syntax(self) -> None:
        """Case E.3: CLI syntax '--abi=x86_64' succeeds with returncode 0."""
        p = subprocess.run(
            [sys.executable, self.harness_script, "-f", str(self.apk_path), "--abi=x86_64", "info"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, f"CLI error: {p.stderr}")
        parsed = json.loads(p.stdout)
        self.assertTrue(parsed.get("success"))

    def test_cli_standalone_elf_neutral_flag(self) -> None:
        """Case E.4: CLI command '-f crackme_case --neutral info' includes codebook and telemetry."""
        p = subprocess.run(
            [sys.executable, self.harness_script, "-f", str(self.crackme_path), "--neutral", "info"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, f"CLI error: {p.stderr}")
        parsed = json.loads(p.stdout)
        self.assertTrue(parsed.get("success"))
        self.assertIn("codebook", parsed)
        self.assertIn("telemetry", parsed)

    def test_cli_apk_combined_abi_and_neutral(self) -> None:
        """Case E.5: CLI combining '--abi arm64-v8a' and '--neutral' succeeds."""
        p = subprocess.run(
            [sys.executable, self.harness_script, "-f", str(self.apk_path), "--abi", "arm64-v8a", "--neutral", "info"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, f"CLI error: {p.stderr}")
        parsed = json.loads(p.stdout)
        self.assertTrue(parsed.get("success"))
        self.assertIn("codebook", parsed)
        self.assertIn("telemetry", parsed)

    def test_cli_standalone_dex_info(self) -> None:
        """Case E.6: CLI '-f classes.dex info' returns Dalvik metadata with returncode 0."""
        p = subprocess.run(
            [sys.executable, self.harness_script, "-f", str(self.dex_path), "info"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, f"CLI error: {p.stderr}")
        parsed = json.loads(p.stdout)
        self.assertTrue(parsed.get("success"))
        self.assertTrue(parsed.get("data", {}).get("valid"))

    def test_cli_export_tools_schemas_include_abi_and_neutral(self) -> None:
        """Case E.7: CLI '--export-tools mcp' outputs schemas with optional abi, neutral, component_type."""
        p = subprocess.run(
            [sys.executable, self.harness_script, "--export-tools", "mcp"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, f"CLI error: {p.stderr}")
        tools = json.loads(p.stdout)
        info_tool = next((t for t in tools if t.get("name") == "rvs_info"), None)
        self.assertIsNotNone(info_tool, "rvs_info tool not found in exported MCP schemas")
        props = info_tool["inputSchema"]["properties"]
        self.assertIn("abi", props)
        self.assertIn("neutral", props)
        self.assertIn("component_type", props)
        required = info_tool["inputSchema"].get("required", [])
        self.assertNotIn("abi", required, "abi must not be marked required")
        self.assertNotIn("neutral", required, "neutral must not be marked required")
        self.assertNotIn("component_type", required, "component_type must not be marked required")


# =============================================================================
# Group F: Zero Ephemeral Leakage (/tmp/rvs_target_*) (F.1 - F.4)
# =============================================================================

class TestGroupFZeroEphemeralLeakage(BaseMultiTargetIntegrationTest):
    """Group F: 100% Clean Room Verification: Zero Ephemeral Leakage."""

    def test_zero_ephemeral_leakage_on_repeated_mcp_tool_calls(self) -> None:
        """Case F.1: 10 consecutive tool calls on APK leave zero lingering /tmp/rvs_target_* directories."""
        pattern = os.path.join(tempfile.gettempdir(), "rvs_target_*")
        before = set(glob.glob(pattern))

        for _ in range(10):
            res = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
            self.assertTrue(res.get("success"))

        after = set(glob.glob(pattern))
        leaked = after - before
        self.assertEqual(leaked, set(), f"Detected lingering ephemeral directories: {leaked}")

    def test_zero_ephemeral_leakage_on_cli_subprocesses(self) -> None:
        """Case F.2: CLI execution on APK leaves zero lingering /tmp/rvs_target_* directories."""
        pattern = os.path.join(tempfile.gettempdir(), "rvs_target_*")
        before = set(glob.glob(pattern))

        harness_script = str(WORKSPACE_DIR / "rvs_agent_harness.py")
        p = subprocess.run(
            [sys.executable, harness_script, "-f", str(self.apk_path), "info"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0)

        after = set(glob.glob(pattern))
        leaked = after - before
        self.assertEqual(leaked, set(), f"Detected lingering ephemeral directories: {leaked}")

    def test_zero_ephemeral_leakage_on_malformed_apk_failure(self) -> None:
        """Case F.3: Malformed APK failure cleans up completely with zero lingering directories."""
        corrupted_apk = self.temp_dir / "corrupted.apk"
        create_corrupted_apk(corrupted_apk, corruption_type="bad_zip")

        pattern = os.path.join(tempfile.gettempdir(), "rvs_target_*")
        before = set(glob.glob(pattern))

        res = self.harness.execute_tool("rvs_info", {"file": str(corrupted_apk)})
        self.assertFalse(res.get("success"))

        after = set(glob.glob(pattern))
        leaked = after - before
        self.assertEqual(leaked, set(), f"Detected lingering ephemeral directories: {leaked}")

    def test_zero_ephemeral_leakage_on_multi_tool_workflow(self) -> None:
        """Case F.4: Multi-tool workflow on single APK cleans up after every tool call."""
        pattern = os.path.join(tempfile.gettempdir(), "rvs_target_*")
        before = set(glob.glob(pattern))

        # 1. info
        r1 = self.harness.execute_tool("rvs_info", {"file": str(self.apk_path)})
        self.assertTrue(r1.get("success"))
        self.assertEqual(set(glob.glob(pattern)) - before, set())

        # 2. functions
        r2 = self.harness.execute_tool("rvs_functions", {"file": str(self.apk_path)})
        self.assertTrue(r2.get("success"))
        self.assertEqual(set(glob.glob(pattern)) - before, set())

        # 3. strings
        r3 = self.harness.execute_tool("rvs_strings", {"file": str(self.apk_path)})
        self.assertTrue(r3.get("success"))
        self.assertEqual(set(glob.glob(pattern)) - before, set())


# =============================================================================
# Group G: Framework Triage Recommendations & Deduplication (G.1 - G.2)
# =============================================================================

class TestGroupGFrameworkTriageRecommendations(BaseMultiTargetIntegrationTest):
    """Group G: Multi-language framework recognition and deduplication in rvs_agent_triage."""

    def test_react_native_triage_recommendations_preserved(self) -> None:
        """Case G.1: React Native recommendations preserved without collision with DEX in full and compact modes."""
        rn_apk = self.temp_dir / "rn_triage_test.apk"
        create_synthetic_react_native_apk(rn_apk)

        # 1. Full mode triage
        res_full = self.harness.execute_tool("rvs_agent_triage", {"file": str(rn_apk), "compact": False, "neutral": False})
        self.assertTrue(res_full.get("success"), f"Full triage failed: {res_full}")
        recs_full = res_full["data"].get("recommendations", [])
        self.assertTrue(any("react native" in r.lower() for r in recs_full), f"React Native rec missing in full: {recs_full}")
        self.assertTrue(any("dex" in r.lower() for r in recs_full), f"DEX rec missing in full: {recs_full}")

        # 2. Compact mode triage
        res_comp = self.harness.execute_tool("rvs_agent_triage", {"file": str(rn_apk), "compact": True, "neutral": False})
        self.assertTrue(res_comp.get("success"), f"Compact triage failed: {res_comp}")
        recs_comp = res_comp["data"].get("recommendations", [])
        self.assertTrue(any("react native" in r.lower() for r in recs_comp), f"React Native rec missing in compact: {recs_comp}")
        self.assertLessEqual(len(recs_comp), 2)

    def test_flutter_triage_recommendations_preserved(self) -> None:
        """Case G.2: Flutter / Dart recommendations preserved without collision in full and compact modes."""
        flutter_apk = self.temp_dir / "flutter_triage_test.apk"
        create_synthetic_flutter_apk(flutter_apk)

        # 1. Full mode triage
        res_full = self.harness.execute_tool("rvs_agent_triage", {"file": str(flutter_apk), "compact": False, "neutral": False})
        self.assertTrue(res_full.get("success"), f"Full triage failed: {res_full}")
        recs_full = res_full["data"].get("recommendations", [])
        self.assertTrue(any("flutter" in r.lower() or "dart" in r.lower() for r in recs_full), f"Flutter rec missing in full: {recs_full}")

        # 2. Compact mode triage
        res_comp = self.harness.execute_tool("rvs_agent_triage", {"file": str(flutter_apk), "compact": True, "neutral": False})
        self.assertTrue(res_comp.get("success"), f"Compact triage failed: {res_comp}")
        recs_comp = res_comp["data"].get("recommendations", [])
        self.assertTrue(any("flutter" in r.lower() or "dart" in r.lower() for r in recs_comp), f"Flutter rec missing in compact: {recs_comp}")
        self.assertLessEqual(len(recs_comp), 2)


# =============================================================================
# Group H: Multi-Language Framework Recognition in rvs_apk_info (H.1 - H.5)
# =============================================================================

class TestGroupHMultiLanguageRecognition(BaseMultiTargetIntegrationTest):
    """Group H: Multi-Language framework recognition in rvs_apk_info across full and compact formats."""

    def test_apk_info_react_native_recognition(self) -> None:
        """Case H.1: rvs_apk_info recognizes React Native in full and compact modes."""
        apk_path = self.temp_dir / "test_rn_recog.apk"
        create_synthetic_react_native_apk(apk_path)

        # Full mode
        res_full = self.harness.execute_tool("rvs_apk_info", {"file": str(apk_path), "compact": False, "neutral": False})
        self.assertTrue(res_full.get("success"), f"Failed: {res_full}")
        languages = res_full.get("data", {}).get("languages", [])
        lang_names = [l["language"] for l in languages]
        self.assertIn("React Native", lang_names)
        self.assertIn("Java", lang_names)
        self.assertIn("C/C++", lang_names)
        rn_entry = next(l for l in languages if l["language"] == "React Native")
        self.assertEqual(rn_entry.get("confidence"), "High")
        self.assertTrue(any("libreactnativejni.so" in e or "index.android.bundle" in e for e in rn_entry.get("evidence", [])))

        # Compact mode
        res_comp = self.harness.execute_tool("rvs_apk_info", {"file": str(apk_path), "compact": True, "neutral": False})
        self.assertTrue(res_comp.get("success"), f"Failed: {res_comp}")
        langs_comp = res_comp.get("data", {}).get("langs", [])
        self.assertIn("React Native", langs_comp)
        self.assertIn("Java", langs_comp)

    def test_apk_info_flutter_recognition(self) -> None:
        """Case H.2: rvs_apk_info recognizes Flutter / Dart in full and compact modes."""
        apk_path = self.temp_dir / "test_flutter_recog.apk"
        create_synthetic_flutter_apk(apk_path)

        # Full mode
        res_full = self.harness.execute_tool("rvs_apk_info", {"file": str(apk_path), "compact": False, "neutral": False})
        self.assertTrue(res_full.get("success"), f"Failed: {res_full}")
        languages = res_full.get("data", {}).get("languages", [])
        lang_names = [l["language"] for l in languages]
        self.assertIn("Flutter / Dart", lang_names)
        flutter_entry = next(l for l in languages if l["language"] == "Flutter / Dart")
        self.assertEqual(flutter_entry.get("confidence"), "High")
        self.assertTrue(any("libflutter.so" in e or "kernel_blob.bin" in e for e in flutter_entry.get("evidence", [])))

        # Compact mode
        res_comp = self.harness.execute_tool("rvs_apk_info", {"file": str(apk_path), "compact": True, "neutral": False})
        self.assertTrue(res_comp.get("success"), f"Failed: {res_comp}")
        langs_comp = res_comp.get("data", {}).get("langs", [])
        self.assertIn("Flutter / Dart", langs_comp)

    def test_apk_info_native_cpp_recognition(self) -> None:
        """Case H.3: rvs_apk_info recognizes C/C++ without false-positive framework markers."""
        apk_path = self.temp_dir / "test_cpp_recog.apk"
        create_synthetic_native_cpp_apk(apk_path)

        res = self.harness.execute_tool("rvs_apk_info", {"file": str(apk_path), "compact": False, "neutral": False})
        self.assertTrue(res.get("success"), f"Failed: {res}")
        languages = res.get("data", {}).get("languages", [])
        lang_names = [l["language"] for l in languages]
        self.assertIn("Java", lang_names)
        self.assertIn("C/C++", lang_names)
        self.assertNotIn("React Native", lang_names)
        self.assertNotIn("Flutter / Dart", lang_names)

    def test_apk_info_pure_java_recognition(self) -> None:
        """Case H.4: rvs_apk_info on pure Java APK detects only Java with no native C/C++."""
        apk_path = self.temp_dir / "test_java_recog.apk"
        create_synthetic_java_only_apk(apk_path)

        res = self.harness.execute_tool("rvs_apk_info", {"file": str(apk_path), "compact": True, "neutral": False})
        self.assertTrue(res.get("success"), f"Failed: {res}")
        langs = res.get("data", {}).get("langs", [])
        self.assertEqual(langs, ["Java"])

    def test_apk_info_hybrid_recognition(self) -> None:
        """Case H.5: rvs_apk_info on hybrid APK detects Java, C/C++, and React Native simultaneously."""
        apk_path = self.temp_dir / "test_hybrid_recog.apk"
        create_synthetic_hybrid_apk(apk_path)

        res = self.harness.execute_tool("rvs_apk_info", {"file": str(apk_path), "compact": True, "neutral": False})
        self.assertTrue(res.get("success"), f"Failed: {res}")
        langs = set(res.get("data", {}).get("langs", []))
        self.assertTrue({"Java", "C/C++", "React Native"}.issubset(langs))


# =============================================================================
# Group I: Native ELF Shared Library Inspection via rvs_apk_native (I.1 - I.5)
# =============================================================================

class TestGroupINativeSoExtraction(BaseMultiTargetIntegrationTest):
    """Group I: Native ELF metadata extraction and library filtering in rvs_apk_native."""

    def test_apk_native_metadata_extraction_arm64(self) -> None:
        """Case I.1: rvs_apk_native extracts ABI, bits, elf_type, endianness, soname, and DT_NEEDED."""
        apk_path = self.temp_dir / "test_native_meta.apk"
        create_synthetic_native_cpp_apk(apk_path)

        res = self.harness.execute_tool(
            "rvs_apk_native",
            {"file": str(apk_path), "abi": "arm64-v8a", "compact": False, "neutral": False},
        )
        self.assertTrue(res.get("success"), f"Query failed: {res}")
        data = res.get("data", {})
        self.assertEqual(data.get("architecture"), "arm64")
        self.assertEqual(data.get("abi"), "arm64-v8a")
        self.assertTrue(data.get("is_64_bit"))
        self.assertEqual(data.get("bits"), 64)
        self.assertEqual(data.get("elf_type"), "DYN")
        self.assertEqual(data.get("endianness"), "little")
        self.assertEqual(data.get("soname"), "libnative.so")
        self.assertIn("libc.so", data.get("needed_libraries", []))
        self.assertIn("libstdc++.so", data.get("needed_libraries", []))

    def test_apk_native_jni_unmangling(self) -> None:
        """Case I.2: rvs_apk_native unmangles static Java_* JNI function exports."""
        apk_path = self.temp_dir / "test_native_jni.apk"
        create_synthetic_native_cpp_apk(apk_path)

        res = self.harness.execute_tool("rvs_apk_native", {"file": str(apk_path), "compact": False, "neutral": False})
        self.assertTrue(res.get("success"), f"Query failed: {res}")
        jni_funcs = res.get("data", {}).get("jni_functions", [])
        self.assertGreaterEqual(len(jni_funcs), 2)
        
        string_from_jni = next((j for j in jni_funcs if "stringFromJNI" in j.get("name", "")), None)
        self.assertIsNotNone(string_from_jni)
        self.assertEqual(string_from_jni.get("demangled_class"), "com.example.nativecpp.MainActivity")
        self.assertEqual(string_from_jni.get("demangled_method"), "stringFromJNI")
        self.assertTrue(string_from_jni.get("is_exported"))

    def test_apk_native_library_filter(self) -> None:
        """Case I.3: rvs_apk_native with library filter targets specified library and detects RegisterNatives."""
        apk_path = self.temp_dir / "test_native_filter.apk"
        create_synthetic_hybrid_apk(apk_path)

        # Target libcustom_sec.so
        res = self.harness.execute_tool(
            "rvs_apk_native",
            {"file": str(apk_path), "library": "libcustom_sec.so", "compact": False, "neutral": False},
        )
        self.assertTrue(res.get("success"), f"Query failed: {res}")
        data = res.get("data", {})
        self.assertIn("libcustom_sec.so", data.get("file_name", ""))
        self.assertTrue(data.get("register_natives_detected"))
        self.assertEqual(data.get("soname"), "libcustom_sec.so")

    def test_apk_native_compact_mode(self) -> None:
        """Case I.4: rvs_apk_native in compact mode emits token-optimized schema."""
        apk_path = self.temp_dir / "test_native_compact.apk"
        create_synthetic_hybrid_apk(apk_path)

        res = self.harness.execute_tool(
            "rvs_apk_native",
            {"file": str(apk_path), "library": "libcustom_sec.so", "compact": True, "neutral": False},
        )
        self.assertTrue(res.get("success"), f"Query failed: {res}")
        data = res.get("data", {})
        # Verify compact keys
        self.assertEqual(data.get("arch"), "arm64")
        self.assertEqual(data.get("abi"), "arm64-v8a")
        self.assertTrue(data.get("is_64"))
        self.assertEqual(data.get("elf_type"), "DYN")
        self.assertEqual(data.get("endian"), "little")
        self.assertTrue(data.get("reg_natives"))
        self.assertIn("deps", data)
        self.assertIn("jni", data)
        self.assertIn("exports", data)
        self.assertIn("imports", data)

    def test_apk_native_missing_so_graceful_handling(self) -> None:
        """Case I.5: rvs_apk_native gracefully reports absent native libraries on pure Java APK."""
        apk_path = self.temp_dir / "test_java_no_so.apk"
        create_synthetic_java_only_apk(apk_path)

        res = self.harness.execute_tool("rvs_apk_native", {"file": str(apk_path), "compact": False, "neutral": False})
        self.assertTrue(res.get("success"), f"Query should succeed gracefully: {res}")
        data = res.get("data", {})
        self.assertEqual(data.get("architecture"), "unknown")
        self.assertEqual(data.get("needed_libraries"), [])
        self.assertEqual(data.get("jni_functions"), [])


# =============================================================================
# Group J: APK Resources and Asset Inspection via rvs_apk_resources (J.1 - J.5)
# =============================================================================

class TestGroupJApkResources(BaseMultiTargetIntegrationTest):
    """Group J: Resources and assets inspection, filtering, entry extraction, and directory dumping."""

    def test_apk_resources_listing_full_and_compact(self) -> None:
        """Case J.1: rvs_apk_resources lists resource and asset entries in full and compact modes."""
        apk_path = self.temp_dir / "test_res_list.apk"
        create_synthetic_apk(apk_path)

        # Full mode
        res_full = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": str(apk_path), "compact": False},
        )
        self.assertTrue(res_full.get("success"), f"Query failed: {res_full}")
        data_full = res_full.get("data", {})
        self.assertGreaterEqual(data_full.get("total_resources", 0), 1)
        self.assertGreaterEqual(data_full.get("total_assets", 0), 1)
        self.assertTrue(data_full.get("has_arsc"))
        entries = data_full.get("entries", [])
        entry_names = [e["name"] for e in entries]
        self.assertTrue(any("assets/app_config.json" in n for n in entry_names))
        self.assertTrue(any("res/values/strings.xml" in n for n in entry_names))

        # Compact mode
        res_comp = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": str(apk_path), "compact": True},
        )
        self.assertTrue(res_comp.get("success"), f"Query failed: {res_comp}")
        data_comp = res_comp.get("data", {})
        self.assertGreaterEqual(data_comp.get("res_cnt", 0), 1)
        self.assertGreaterEqual(data_comp.get("asset_cnt", 0), 1)
        self.assertTrue(data_comp.get("arsc"))

    def test_apk_resources_filtering_by_type_and_name(self) -> None:
        """Case J.2: rvs_apk_resources filters entries by type and name substring."""
        apk_path = self.temp_dir / "test_res_filter.apk"
        create_synthetic_apk(apk_path)

        # Filter by type="asset"
        res_asset = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": str(apk_path), "type": "asset", "compact": False},
        )
        self.assertTrue(res_asset.get("success"), f"Asset filter failed: {res_asset}")
        asset_entries = res_asset.get("data", {}).get("entries", [])
        self.assertTrue(len(asset_entries) > 0)
        self.assertTrue(all(e.get("type") == "asset" or e.get("name", "").startswith("assets/") for e in asset_entries))

        # Filter by name="secret_token"
        res_name = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": str(apk_path), "name": "secret_token", "compact": False},
        )
        self.assertTrue(res_name.get("success"), f"Name filter failed: {res_name}")
        name_entries = res_name.get("data", {}).get("entries", [])
        self.assertEqual(len(name_entries), 1)
        self.assertIn("secret_token.txt", name_entries[0]["name"])

    def test_apk_resources_entry_extraction(self) -> None:
        """Case J.3: rvs_apk_resources extracts and decodes text and XML content."""
        apk_path = self.temp_dir / "test_res_extract.apk"
        create_synthetic_apk(apk_path)

        res = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": str(apk_path), "name": "assets/app_config.json", "compact": False},
        )
        self.assertTrue(res.get("success"), f"Extraction failed: {res}")
        extracted = res.get("data", {}).get("extracted", {})
        self.assertIn("app_config.json", extracted.get("name", ""))
        self.assertIn("production", extracted.get("content", ""))

    def test_apk_resources_directory_dump(self) -> None:
        """Case J.4: rvs_apk_resources dumps extracted assets and resources to directory."""
        apk_path = self.temp_dir / "test_res_dump.apk"
        create_synthetic_apk(apk_path)
        dump_target_dir = self.temp_dir / "dumped_resources"

        res = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": str(apk_path), "dump": str(dump_target_dir), "compact": False},
        )
        self.assertTrue(res.get("success"), f"Dump failed: {res}")
        data = res.get("data", {})
        self.assertEqual(data.get("dump_dir"), str(dump_target_dir))
        self.assertGreaterEqual(data.get("dumped_files_count", 0), 1)
        self.assertTrue((dump_target_dir / "assets" / "app_config.json").exists())

    def test_apk_resources_dump_failure_zero_ephemeral_leakage(self) -> None:
        """Case J.5: rvs_apk_resources with dump=True cleans up and leaves zero leaked directories on failure."""
        pattern = "/tmp/rvs_res_dump_*"

        # Scenario 1: Non-existent file
        before = set(glob.glob(pattern))
        res_missing = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": "nonexistent.apk", "dump": True},
        )
        self.assertFalse(res_missing.get("success"), f"Expected failure on nonexistent file: {res_missing}")
        after = set(glob.glob(pattern))
        leaked = after - before
        self.assertEqual(leaked, set(), f"Lingering dump directories detected after nonexistent file failure: {leaked}")

        # Scenario 2: Corrupted APK
        corrupted_apk = self.temp_dir / "corrupted_res_dump.apk"
        create_corrupted_apk(corrupted_apk, corruption_type="bad_zip")

        before = set(glob.glob(pattern))
        res_corrupt = self.harness.execute_tool(
            "rvs_apk_resources",
            {"file": str(corrupted_apk), "dump": True},
        )
        self.assertFalse(res_corrupt.get("success"), f"Expected failure on corrupted APK: {res_corrupt}")
        after = set(glob.glob(pattern))
        leaked = after - before
        self.assertEqual(leaked, set(), f"Lingering dump directories detected after corrupt APK failure: {leaked}")


# =============================================================================
# Group K: APK Signature and Certificate Verification (K.1 - K.3)
# =============================================================================

class TestGroupKApkSignature(BaseMultiTargetIntegrationTest):
    """Group K: APK signing schemes (v1, v2) and X.509 certificate extraction / verification."""

    def test_apk_signature_verification_full_mode(self) -> None:
        """Case K.1: rvs_apk_signature extracts schemes, signers, certificates, and validates integrity."""
        apk_path = Path("tests/fixtures/sample_raw.apk")
        if not apk_path.exists():
            self.skipTest("sample_raw.apk fixture not found")

        res = self.harness.execute_tool(
            "rvs_apk_signature",
            {"file": str(apk_path), "verify": True, "compact": False},
        )
        self.assertTrue(res.get("success"), f"Signature query failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("is_signed"))
        self.assertTrue(data.get("signing_block_present"))
        self.assertTrue(data.get("verified"))
        self.assertIn("v1", data.get("schemes", []))
        self.assertIn("v2", data.get("schemes", []))

        signers = data.get("signers", [])
        self.assertGreaterEqual(len(signers), 1)
        signer = signers[0]
        self.assertIn("RvsTestSigner", signer.get("subject", ""))
        self.assertIn("RvsTestSigner", signer.get("issuer", ""))
        self.assertTrue(len(signer.get("sha256_fingerprint", "")) > 0)
        self.assertTrue(len(signer.get("sha1_fingerprint", "")) > 0)

    def test_apk_signature_compact_mode(self) -> None:
        """Case K.2: rvs_apk_signature emits token-compact schema with compact keys."""
        apk_path = Path("tests/fixtures/sample_raw.apk")
        if not apk_path.exists():
            self.skipTest("sample_raw.apk fixture not found")

        res = self.harness.execute_tool(
            "rvs_apk_signature",
            {"file": str(apk_path), "verify": True, "compact": True},
        )
        self.assertTrue(res.get("success"), f"Compact signature query failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("signed"))
        self.assertTrue(data.get("sig_block"))
        self.assertTrue(data.get("verified"))
        signers = data.get("signers", [])
        self.assertGreaterEqual(len(signers), 1)
        self.assertIn("sha256", signers[0])
        self.assertIn("algo", signers[0])

    def test_apk_signature_no_verify_flag(self) -> None:
        """Case K.3: rvs_apk_signature with verify=False extracts details without asserting validity."""
        apk_path = Path("tests/fixtures/sample_raw.apk")
        if not apk_path.exists():
            self.skipTest("sample_raw.apk fixture not found")

        res = self.harness.execute_tool(
            "rvs_apk_signature",
            {"file": str(apk_path), "verify": False, "compact": False},
        )
        self.assertTrue(res.get("success"), f"Signature query failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("is_signed"))
        self.assertNotIn("verified", data)


# =============================================================================
# Group L: Dalvik DEX Method Decompilation (L.1 - L.2)
# =============================================================================

class TestGroupLDexDecompilation(BaseMultiTargetIntegrationTest):
    """Group L: Dalvik DEX bytecode decompilation into pseudo-code."""

    def test_apk_dex_decompile_method(self) -> None:
        """Case L.1: rvs_apk_dex with decompile=True decompiles matched methods."""
        raw_apk = Path("tests/fixtures/sample_raw.apk")
        if not raw_apk.exists():
            self.skipTest("sample_raw.apk fixture not found")

        res = self.harness.execute_tool(
            "rvs_apk_dex",
            {
                "file": str(raw_apk),
                "class": "QuickActionItem",
                "method": "toggle",
                "decompile": True,
                "compact": False,
            },
        )
        self.assertTrue(res.get("success"), f"DEX decompile query failed: {res}")
        data = res.get("data", {})
        self.assertIn("decompiled", data)
        decomp_text = data.get("decompiled", "")
        self.assertTrue("QuickActionItem" in decomp_text or "toggle" in decomp_text)

    def test_apk_dex_decompile_flag_false_by_default(self) -> None:
        """Case L.2: rvs_apk_dex without decompile flag omits decompiled pseudo-code."""
        raw_apk = Path("tests/fixtures/sample_raw.apk")
        if not raw_apk.exists():
            self.skipTest("sample_raw.apk fixture not found")

        res = self.harness.execute_tool(
            "rvs_apk_dex",
            {
                "file": str(raw_apk),
                "class": "QuickActionItem",
                "method": "toggle",
                "compact": False,
            },
        )
        self.assertTrue(res.get("success"), f"DEX query failed: {res}")
        data = res.get("data", {})
        self.assertNotIn("decompiled", data)


# =============================================================================
# Group M: Dynamic Frida APK & Package Connection Support (M.1 - M.3)
# =============================================================================

class TestGroupMFridaApkConnection(BaseMultiTargetIntegrationTest):
    """Group M: Frida dynamic connection support targeting APK archives and Android packages."""

    def test_frida_spawn_apk_archive_target(self) -> None:
        """Case M.1: rvs_frida_spawn connects to APK archive with fallback envelope and USB device URI."""
        apk_path = self.temp_dir / "test_frida_target.apk"
        create_synthetic_apk(apk_path)

        res = self.harness.execute_tool(
            "rvs_frida_spawn",
            {"path": str(apk_path), "compact": True},
        )
        self.assertTrue(res.get("success"), f"Frida spawn APK failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("connected"))
        self.assertTrue(data.get("fallback"))
        self.assertEqual(data.get("os"), "android")
        self.assertEqual(data.get("arch"), "arm64")
        self.assertIn("frida://spawn/usb///", data.get("target_uri", ""))

    def test_frida_spawn_package_parameter(self) -> None:
        """Case M.2: rvs_frida_spawn accepts package parameter and generates canonical target URI."""
        res = self.harness.execute_tool(
            "rvs_frida_spawn",
            {"package": "com.example.secure.app", "compact": True},
        )
        self.assertTrue(res.get("success"), f"Frida spawn package failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("connected"))
        self.assertTrue(data.get("fallback"))
        self.assertEqual(data.get("target_uri"), "frida://spawn/usb///com.example.secure.app")
        self.assertEqual(data.get("process_name"), "com.example.secure.app")

    def test_frida_attach_package_parameter(self) -> None:
        """Case M.3: rvs_frida_attach accepts package parameter and attaches to Android package."""
        res = self.harness.execute_tool(
            "rvs_frida_attach",
            {"package": "com.example.secure.app", "compact": True},
        )
        self.assertTrue(res.get("success"), f"Frida attach package failed: {res}")
        data = res.get("data", {})
        self.assertTrue(data.get("connected"))
        self.assertTrue(data.get("fallback"))
        self.assertEqual(data.get("target_uri"), "frida://attach/usb///com.example.secure.app")


if __name__ == "__main__":
    unittest.main()
