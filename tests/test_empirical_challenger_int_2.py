#!/usr/bin/env python3
"""
tests/test_empirical_challenger_int_2.py - Empirical Challenger 2 Stress Test Suite.

Adversarial stress testing and empirical verification for:
1. CLI flag fuzzing & subprocess execution syntax:
   - `--abi arm64-v8a`, `--abi=x86_64`
   - `--neutral`, `--neutral=true`, `--neutral=false`, `--no-neutral`
   - `--component-type dex`, `--component-type=elf_so`
   - Combinations, boolean coercions (1/0/yes/no), case variations, error paths
   - Strict assertion of valid stdout JSON and zero `/tmp/rvs_target_*` leaks.
2. Concurrent multi-target queries across threads:
   - Multi-target ingestion thread safety
   - Ephemeral watchdog registration lock safety
   - Parallel query execution across APK, DEX, and ELF targets
   - Complete zero-leak guarantee after concurrent workloads.
3. Schema validation & synchronization:
   - Tool schemas across all 4 formats: 'openai', 'anthropic', 'gemini', 'mcp'
   - Parameter properties & optionality for multi-target parameters (abi, neutral, component_type)
   - 100% pass verification of tests/test_challenger_m4_skill_sync.py (16/16).
4. Memory and file descriptor leak stability:
   - Linux /proc/self/fd tracking across 50+ repeated APK & DEX queries
   - Memory RSS stability across 100+ queries
   - Exception path FD stability and ephemeral directory cleanup.
"""

from __future__ import annotations

import concurrent.futures
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness as h
from rvs_agent_harness import (
    RvsHarness,
    CANONICAL_TOOLS,
    get_tool_schemas,
    coerce_bool_param,
    coerce_int_param,
)
from neutral_orchestrator.target_ingestion import (
    _ACTIVE_EPHEMERAL_DIRS,
    _REGISTRY_LOCK,
    _register_ephemeral_dir,
    _unregister_ephemeral_dir,
    ingest_target,
    TargetType,
)
from neutral_orchestrator.orchestrator import NeutralBinaryOrchestrator
from tests.fixtures_builder import (
    create_synthetic_apk,
    create_synthetic_dex,
    create_corrupted_apk,
)

FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"


def get_open_fd_count() -> int:
    """Returns number of open file descriptors in current process via /proc/self/fd."""
    try:
        return len(os.listdir("/proc/self/fd"))
    except Exception:
        return 0


def get_process_rss_kb() -> int:
    """Returns Resident Set Size in KB via /proc/self/statm."""
    try:
        with open("/proc/self/statm", "r") as f:
            parts = f.read().split()
            pagesize = os.sysconf("SC_PAGE_SIZE")
            return int(parts[1]) * pagesize // 1024
    except Exception:
        return 0


def count_ephemeral_dirs() -> int:
    """Count number of matching /tmp/rvs_target_* directories on disk."""
    return len(glob.glob("/tmp/rvs_target_*"))


class BaseChallengerFixture(unittest.TestCase):
    """Base fixture setting up temporary workspace and synthetic APK/DEX binaries."""

    temp_dir_obj: tempfile.TemporaryDirectory
    temp_dir: Path
    apk_path: Path
    dex_path: Path
    elf_path: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir_obj = tempfile.TemporaryDirectory(prefix="rvs_challenger2_")
        cls.temp_dir = Path(cls.temp_dir_obj.name)
        cls.apk_path = cls.temp_dir / "challenger_multi.apk"
        cls.dex_path = cls.temp_dir / "challenger_classes.dex"
        cls.elf_path = FIXTURES_DIR / "auth_gate_elf64"

        create_synthetic_apk(cls.apk_path, multidex=True)
        create_synthetic_dex(
            cls.dex_path,
            strings=["Lcom/challenger/Main;", "TokenSecretKey456", "auth_token_alpha"],
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir_obj.cleanup()


# =============================================================================
# Stress Test 1: CLI Subprocess Execution Fuzzing & Flag Syntax
# =============================================================================

class TestEmpiricalCliSubprocessFuzzing(BaseChallengerFixture):
    """Stress Test 1: CLI subprocess execution fuzzing with various flag syntax."""

    def _run_cli(self, args: List[str], expected_exit: Optional[int] = 0) -> Tuple[int, Dict[str, Any], str]:
        """Helper to invoke CLI in subprocess, verify JSON stdout, and assert zero /tmp leak."""
        leaks_before = count_ephemeral_dirs()
        cmd = [sys.executable, str(WORKSPACE_DIR / "rvs_agent_harness.py")] + args
        proc = subprocess.run(
            cmd,
            cwd=str(WORKSPACE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        leaks_after = count_ephemeral_dirs()
        self.assertEqual(
            leaks_after,
            leaks_before,
            f"Lingering /tmp/rvs_target_* detected after command: {' '.join(cmd)}. Before: {leaks_before}, After: {leaks_after}",
        )

        if expected_exit is not None:
            self.assertEqual(
                proc.returncode,
                expected_exit,
                f"Unexpected exit code {proc.returncode} (expected {expected_exit}). Stderr: {proc.stderr}. Stdout: {proc.stdout}",
            )

        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as err:
            self.fail(f"CLI stdout failed to parse as JSON: {err}. Raw output:\n{proc.stdout}")

        return proc.returncode, parsed, proc.stderr

    def test_cli_flag_abi_separated_syntax(self) -> None:
        """Verify CLI flag '--abi arm64-v8a' extracts arm64-v8a native library."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--abi", "arm64-v8a", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        self.assertEqual(out.get("command"), "info")
        self.assertIn("telemetry", out)
        self.assertIn("arm64-v8a", str(out.get("telemetry", {}).get("active_component", "")))

    def test_cli_flag_abi_equals_syntax(self) -> None:
        """Verify CLI flag '--abi=x86_64' extracts x86_64 native library."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--abi=x86_64", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        self.assertIn("x86_64", str(out.get("telemetry", {}).get("active_component", "")))

    def test_cli_flag_neutral_standalone(self) -> None:
        """Verify CLI flag '--neutral' attaches bijective codebook and telemetry."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--neutral", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        self.assertIn("codebook", out)
        self.assertIsInstance(out["codebook"], dict)
        self.assertIn("telemetry", out)
        self.assertIn("execution_time_seconds", out["telemetry"])

    def test_cli_flag_neutral_equals_true(self) -> None:
        """Verify CLI flag '--neutral=true' activates neutral representation."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--neutral=true", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        self.assertIn("codebook", out)
        self.assertIsInstance(out["codebook"], dict)

    def test_cli_flag_neutral_equals_false(self) -> None:
        """Verify CLI flag '--neutral=false' disables neutral representation (no codebook in root)."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--neutral=false", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        self.assertNotIn("codebook", out)

    def test_cli_flag_no_neutral(self) -> None:
        """Verify CLI flag '--no-neutral' explicitly strips codebook."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--no-neutral", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        self.assertNotIn("codebook", out)

    def test_cli_flag_component_type_dex_separated(self) -> None:
        """Verify CLI flag '--component-type dex' routes to Dalvik DEX component."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--component-type", "dex", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        data = out.get("data", {})
        self.assertEqual(data.get("format"), "dex")
        self.assertIn("classes.dex", str(out.get("telemetry", {}).get("active_component", "")))

    def test_cli_flag_component_type_elf_so_equals(self) -> None:
        """Verify CLI flag '--component-type=elf_so' routes to native library."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--component-type=elf_so", "info"], expected_exit=0)
        self.assertTrue(out.get("success"), f"Query failed: {out}")
        self.assertIn(".so", str(out.get("telemetry", {}).get("active_component", "")))

    def test_cli_flag_combinations_matrix(self) -> None:
        """Verify multi-flag combinations: ABI + component-type + neutral + strings options."""
        # 1. ABI arm64-v8a + neutral + functions query
        code, out, _ = self._run_cli(
            ["-f", str(self.apk_path), "--abi", "arm64-v8a", "--neutral", "functions", "--limit", "5"],
            expected_exit=0,
        )
        self.assertTrue(out.get("success"))
        self.assertIn("codebook", out)

        # 2. component-type=dex + strings query + min-len + filter
        code, out, _ = self._run_cli(
            ["-f", str(self.apk_path), "--component-type=dex", "strings", "--min-len=4"],
            expected_exit=0,
        )
        self.assertTrue(out.get("success"))
        self.assertIn("strings", out.get("data", {}))

        # 3. abi=x86_64 + component-type=elf_so + neutral=true + info
        code, out, _ = self._run_cli(
            ["-f", str(self.apk_path), "--abi=x86_64", "--component-type=elf_so", "--neutral=true", "info"],
            expected_exit=0,
        )
        self.assertTrue(out.get("success"))
        self.assertIn("codebook", out)

    def test_cli_flag_truthy_falsy_fuzzing(self) -> None:
        """Fuzz boolean flag syntax: --neutral=1, --neutral=0, --neutral=yes, --neutral=no, --neutral=t."""
        truthy_cases = ["--neutral=1", "--neutral=yes", "--neutral=t", "--neutral=TRUE"]
        falsy_cases = ["--neutral=0", "--neutral=no", "--neutral=f", "--neutral=FALSE"]

        for flag in truthy_cases:
            code, out, _ = self._run_cli(["-f", str(self.apk_path), flag, "info"], expected_exit=0)
            self.assertTrue(out.get("success"), f"Failed for {flag}")
            self.assertIn("codebook", out, f"Expected codebook for truthy flag {flag}")

        for flag in falsy_cases:
            code, out, _ = self._run_cli(["-f", str(self.apk_path), flag, "info"], expected_exit=0)
            self.assertTrue(out.get("success"), f"Failed for {flag}")
            self.assertNotIn("codebook", out, f"Did not expect codebook for falsy flag {flag}")

    def test_cli_flag_comp_type_alias_and_case(self) -> None:
        """Verify '--comp-type' alias and case-insensitive ABI matching."""
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--comp-type=dex", "info"], expected_exit=0)
        self.assertTrue(out.get("success"))
        self.assertEqual(out.get("data", {}).get("format"), "dex")

        # Case normalization for ABI: ARM64-V8A
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--abi=ARM64-V8A", "info"], expected_exit=0)
        self.assertTrue(out.get("success"))
        self.assertIn("arm64-v8a", str(out.get("telemetry", {}).get("active_component", "")))

    def test_cli_standalone_dex_and_elf_flags(self) -> None:
        """Verify CLI behaves properly with standalone DEX and ELF targets."""
        # Standalone DEX with --neutral
        code, out, _ = self._run_cli(["-f", str(self.dex_path), "--neutral", "info"], expected_exit=0)
        self.assertTrue(out.get("success"))
        self.assertIn("codebook", out)

        # Standalone DEX with unsupported operation 'disasm' returns exit code 3
        code, out, _ = self._run_cli(["-f", str(self.dex_path), "disasm", "main"], expected_exit=3)
        self.assertFalse(out.get("success"))
        self.assertEqual(out.get("error", {}).get("code"), "UNSUPPORTED_DEX_OPERATION")

        # Standalone ELF with --neutral
        code, out, _ = self._run_cli(["-f", str(self.elf_path), "--neutral", "info"], expected_exit=0)
        self.assertTrue(out.get("success"))
        self.assertIn("codebook", out)

    def test_cli_error_paths_zero_leak(self) -> None:
        """Verify error paths (nonexistent ABI, malformed package) exit cleanly with zero leaks."""
        # Non-existent ABI
        code, out, _ = self._run_cli(["-f", str(self.apk_path), "--abi", "mips64", "info"], expected_exit=2)
        self.assertFalse(out.get("success"))
        self.assertEqual(out.get("error", {}).get("code"), "COMPONENT_NOT_FOUND")

        # Malformed APK
        corrupt_apk = self.temp_dir / "corrupted_cli.apk"
        create_corrupted_apk(corrupt_apk)
        code, out, _ = self._run_cli(["-f", str(corrupt_apk), "info"], expected_exit=None)
        self.assertFalse(out.get("success"))
        # Zero leak check is performed inside _run_cli assertion


# =============================================================================
# Stress Test 2: Concurrent Multi-Target Queries Across Threads
# =============================================================================

class TestEmpiricalConcurrentMultiTarget(BaseChallengerFixture):
    """Stress Test 2: Concurrent multi-target queries across threads."""

    def test_concurrent_multi_target_ingestion(self) -> None:
        """Verify thread safety of target ingestion across 16 threads."""
        num_workers = 16

        def ingest_task(idx: int) -> Dict[str, Any]:
            # Alternate between APK and DEX
            target = self.apk_path if idx % 2 == 0 else self.dex_path
            target_obj = ingest_target(target, default_abi="x86_64" if idx % 4 == 0 else "arm64-v8a")
            comp_count = len(target_obj.components)
            # Clean up target
            target_obj.cleanup()
            return {"index": idx, "components": comp_count, "type": target_obj.target_type.value}

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(ingest_task, i) for i in range(num_workers)]
            results = [f.result(timeout=10) for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(results), num_workers)
        for r in results:
            self.assertGreater(r["components"], 0)

        # Assert no lingering entries in _ACTIVE_EPHEMERAL_DIRS and zero /tmp leaks
        self.assertEqual(len(_ACTIVE_EPHEMERAL_DIRS), 0)
        self.assertEqual(count_ephemeral_dirs(), 0)

    def test_concurrent_harness_execute_tool_multi_target(self) -> None:
        """Verify execute_tool() thread safety with shared RvsHarness across 24 concurrent queries."""
        harness = RvsHarness()
        num_tasks = 24

        def query_task(i: int) -> Dict[str, Any]:
            if i % 3 == 0:
                # Query APK x86_64 info
                return harness.execute_tool("rvs_info", {"file": str(self.apk_path), "abi": "x86_64", "neutral": True})
            elif i % 3 == 1:
                # Query APK arm64-v8a functions
                return harness.execute_tool("rvs_functions", {"file": str(self.apk_path), "abi": "arm64-v8a", "limit": 10})
            else:
                # Query DEX strings
                return harness.execute_tool("rvs_strings", {"file": str(self.dex_path), "neutral": False, "min_len": 4})

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(query_task, i) for i in range(num_tasks)]
            results = [f.result(timeout=15) for f in concurrent.futures.as_completed(futures)]

        self.assertEqual(len(results), num_tasks)
        for idx, res in enumerate(results):
            self.assertTrue(res.get("success"), f"Task {idx} failed: {res}")

        self.assertEqual(len(_ACTIVE_EPHEMERAL_DIRS), 0)
        self.assertEqual(count_ephemeral_dirs(), 0)

    def test_concurrent_watchdog_thread_safety(self) -> None:
        """Verify _register_ephemeral_dir and _unregister_ephemeral_dir thread safety under stress."""
        num_threads = 20
        ops_per_thread = 50

        def register_cycle(tid: int) -> None:
            for op in range(ops_per_thread):
                path = f"/tmp/rvs_mock_stress_{tid}_{op}"
                _register_ephemeral_dir(path)
                with _REGISTRY_LOCK:
                    self.assertIn(path, _ACTIVE_EPHEMERAL_DIRS)
                _unregister_ephemeral_dir(path)
                with _REGISTRY_LOCK:
                    self.assertNotIn(path, _ACTIVE_EPHEMERAL_DIRS)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(register_cycle, i) for i in range(num_threads)]
            for f in concurrent.futures.as_completed(futures):
                f.result(timeout=10)

        with _REGISTRY_LOCK:
            self.assertEqual(len(_ACTIVE_EPHEMERAL_DIRS), 0)


# =============================================================================
# Stress Test 3: Schema Validation Across All 4 Formats & Skill Parity
# =============================================================================

class TestEmpiricalSchemaValidationAndSkillSync(unittest.TestCase):
    """Stress Test 3: Schema validation across all 4 formats and skill sync verification."""

    AFFECTED_TOOLS = {
        "rvs_info",
        "rvs_functions",
        "rvs_disasm",
        "rvs_decompile",
        "rvs_flow",
        "rvs_xrefs",
        "rvs_strings",
        "rvs_symbols",
        "rvs_agent_triage",
    }

    def test_schemas_all_four_formats_structure(self) -> None:
        """Verify get_tool_schemas() returns valid schemas across 'openai', 'anthropic', 'gemini', 'mcp'."""
        formats = ["openai", "anthropic", "gemini", "mcp"]
        for fmt in formats:
            schemas = get_tool_schemas(fmt)  # type: ignore
            self.assertIsInstance(schemas, list, f"Format {fmt} should return a list")
            self.assertEqual(len(schemas), len(CANONICAL_TOOLS), f"Format {fmt} tool count mismatch")

    def test_schemas_parameter_extension_contract(self) -> None:
        """Verify 'abi', 'neutral', 'component_type' exist with correct contracts across all 4 formats."""
        # 1. OpenAI
        openai_schemas = {t["function"]["name"]: t["function"] for t in get_tool_schemas("openai")}  # type: ignore
        for t_name in self.AFFECTED_TOOLS:
            self.assertIn(t_name, openai_schemas)
            props = openai_schemas[t_name]["parameters"]["properties"]
            req = openai_schemas[t_name]["parameters"]["required"]

            self.assertIn("abi", props)
            self.assertEqual(props["abi"]["type"], "string")
            self.assertNotIn("abi", req, "abi must be optional")

            self.assertIn("neutral", props)
            self.assertEqual(props["neutral"]["type"], "boolean")
            self.assertNotIn("neutral", req, "neutral must be optional")

            self.assertIn("component_type", props)
            self.assertEqual(props["component_type"]["type"], "string")
            self.assertEqual(props["component_type"]["enum"], ["elf_so", "dex"])
            self.assertNotIn("component_type", req, "component_type must be optional")

        # 2. Anthropic
        anthropic_schemas = {t["name"]: t for t in get_tool_schemas("anthropic")}  # type: ignore
        for t_name in self.AFFECTED_TOOLS:
            self.assertIn(t_name, anthropic_schemas)
            props = anthropic_schemas[t_name]["input_schema"]["properties"]
            req = anthropic_schemas[t_name]["input_schema"]["required"]
            self.assertIn("abi", props)
            self.assertIn("neutral", props)
            self.assertIn("component_type", props)
            self.assertNotIn("abi", req)

        # 3. Gemini (capitalized types)
        gemini_schemas = {t["name"]: t for t in get_tool_schemas("gemini")}  # type: ignore
        for t_name in self.AFFECTED_TOOLS:
            self.assertIn(t_name, gemini_schemas)
            props = gemini_schemas[t_name]["parameters"]["properties"]
            req = gemini_schemas[t_name]["parameters"]["required"]
            self.assertEqual(props["abi"]["type"], "STRING")
            self.assertEqual(props["neutral"]["type"], "BOOLEAN")
            self.assertEqual(props["component_type"]["type"], "STRING")
            self.assertNotIn("abi", req)

        # 4. MCP
        mcp_schemas = {t["name"]: t for t in get_tool_schemas("mcp")}  # type: ignore
        for t_name in self.AFFECTED_TOOLS:
            self.assertIn(t_name, mcp_schemas)
            props = mcp_schemas[t_name]["inputSchema"]["properties"]
            req = mcp_schemas[t_name]["inputSchema"]["required"]
            self.assertIn("abi", props)
            self.assertIn("neutral", props)
            self.assertIn("component_type", props)
            self.assertNotIn("abi", req)

    def test_schemas_case_insensitivity_and_invalid_format(self) -> None:
        """Verify format name is case-insensitive and invalid format raises ValueError."""
        # Case variations
        self.assertEqual(len(get_tool_schemas("OPENAI")), len(CANONICAL_TOOLS))  # type: ignore
        self.assertEqual(len(get_tool_schemas("Anthropic")), len(CANONICAL_TOOLS))  # type: ignore
        self.assertEqual(len(get_tool_schemas("GEMINI")), len(CANONICAL_TOOLS))  # type: ignore
        self.assertEqual(len(get_tool_schemas("Mcp")), len(CANONICAL_TOOLS))  # type: ignore

        # Invalid format
        with self.assertRaises(ValueError) as ctx:
            get_tool_schemas("unknown_vendor")  # type: ignore
        self.assertIn("Unsupported schema format", str(ctx.exception))

    def test_skill_sync_suite_passes_all_16(self) -> None:
        """Empirically invoke tests/test_challenger_m4_skill_sync.py and assert 16/16 tests pass."""
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_challenger_m4_skill_sync.py"],
            cwd=str(WORKSPACE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        self.assertEqual(proc.returncode, 0, f"Skill sync suite failed: {proc.stderr}\n{proc.stdout}")
        self.assertIn("Ran 16 tests", proc.stderr)
        self.assertIn("OK", proc.stderr)


# =============================================================================
# Stress Test 4: Memory and File Descriptor Leak Checks
# =============================================================================

class TestEmpiricalMemoryAndFdLeakStability(BaseChallengerFixture):
    """Stress Test 4: Memory and file descriptor leak checks."""

    def test_fd_leak_repeated_apk_queries(self) -> None:
        """Assert file descriptors remain strictly stable across 50 repeated queries on APK."""
        harness = RvsHarness()
        # Warmup iteration
        harness.execute_tool("rvs_info", {"file": str(self.apk_path)})

        baseline_fds = get_open_fd_count()
        iterations = 50

        for i in range(iterations):
            res = harness.execute_tool("rvs_info", {"file": str(self.apk_path), "abi": "x86_64"})
            self.assertTrue(res.get("success"))

        final_fds = get_open_fd_count()
        # Allow +/- 1 FD tolerance for ephemeral directory listing internal handles
        self.assertLessEqual(
            abs(final_fds - baseline_fds),
            1,
            f"FD leak detected: baseline={baseline_fds}, final={final_fds} after {iterations} APK queries",
        )
        self.assertEqual(count_ephemeral_dirs(), 0, "Lingering ephemeral directories after 50 APK queries")

    def test_fd_leak_repeated_dex_queries(self) -> None:
        """Assert file descriptors remain strictly stable across 50 repeated queries on DEX."""
        harness = RvsHarness()
        harness.execute_tool("rvs_strings", {"file": str(self.dex_path)})

        baseline_fds = get_open_fd_count()
        iterations = 50

        for i in range(iterations):
            res = harness.execute_tool("rvs_strings", {"file": str(self.dex_path), "min_len": 4})
            self.assertTrue(res.get("success"))

        final_fds = get_open_fd_count()
        self.assertLessEqual(
            abs(final_fds - baseline_fds),
            1,
            f"FD leak detected: baseline={baseline_fds}, final={final_fds} after {iterations} DEX queries",
        )
        self.assertEqual(count_ephemeral_dirs(), 0)

    def test_fd_leak_repeated_neutral_token_mappings(self) -> None:
        """Assert FDs and codebooks remain stable across 50 repeated neutral representations."""
        harness = RvsHarness()
        baseline_fds = get_open_fd_count()
        iterations = 50

        for i in range(iterations):
            res = harness.execute_tool(
                "rvs_functions",
                {"file": str(self.apk_path), "abi": "arm64-v8a", "neutral": True, "limit": 5},
            )
            self.assertTrue(res.get("success"))
            self.assertIn("codebook", res)

        final_fds = get_open_fd_count()
        self.assertLessEqual(
            abs(final_fds - baseline_fds),
            1,
            f"FD leak detected under neutral mappings: baseline={baseline_fds}, final={final_fds}",
        )
        self.assertEqual(count_ephemeral_dirs(), 0)

    def test_fd_leak_exception_paths(self) -> None:
        """Assert FDs remain stable even under repeated exception and error conditions."""
        harness = RvsHarness()
        baseline_fds = get_open_fd_count()
        iterations = 30

        for i in range(iterations):
            # Query non-existent ABI
            res = harness.execute_tool(
                "rvs_info",
                {"file": str(self.apk_path), "abi": "non_existent_abi_x99"},
            )
            self.assertFalse(res.get("success"))

        final_fds = get_open_fd_count()
        self.assertLessEqual(
            abs(final_fds - baseline_fds),
            1,
            f"FD leak detected on error paths: baseline={baseline_fds}, final={final_fds}",
        )
        self.assertEqual(count_ephemeral_dirs(), 0)

    def test_memory_rss_stability(self) -> None:
        """Verify memory RSS does not suffer runaway growth across 100 queries."""
        harness = RvsHarness()
        # Warmup
        for _ in range(10):
            harness.execute_tool("rvs_info", {"file": str(self.apk_path)})

        rss_start = get_process_rss_kb()
        iterations = 100

        for i in range(iterations):
            harness.execute_tool("rvs_info", {"file": str(self.apk_path), "abi": "x86_64", "neutral": True})
            harness.execute_tool("rvs_strings", {"file": str(self.dex_path)})

        rss_end = get_process_rss_kb()
        rss_growth_mb = (rss_end - rss_start) / 1024.0

        # Memory growth should be negligible (< 35 MB across 200 operations)
        self.assertLess(
            rss_growth_mb,
            35.0,
            f"Unreasonable RSS growth observed: {rss_growth_mb:.2f} MB across {iterations * 2} queries",
        )
        self.assertEqual(count_ephemeral_dirs(), 0)


if __name__ == "__main__":
    unittest.main()
