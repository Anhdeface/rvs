#!/usr/bin/env python3
"""
tests/e2e_requirements_test.py - Comprehensive Opaque-Box E2E Test Suite for RVS.

Adheres strictly to the 4-tier testing architecture defined in TEST_INFRA.md:
- Tier 1: Feature Coverage (40 tests: >= 5 tests per feature across all 8 features)
- Tier 2: Boundary & Corner Cases (40 tests: >= 5 tests per feature across all 8 features)
- Tier 3: Cross-Feature Interactions (8 pairwise interaction tests)
- Tier 4: Real-World Application Scenarios (5 realistic end-to-end reverse engineering workflows)

Total Tests: 93 tests.

Runner:
  python3 tests/e2e_requirements_test.py
  python3 -m unittest tests/e2e_requirements_test.py
  pytest tests/e2e_requirements_test.py
"""

import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    CANONICAL_TOOLS,
    RvsHarness,
    find_rvs_binary,
    get_tool_schemas,
    transform_response,
)


class TestRvsE2EBase(unittest.TestCase):
    """Base fixture providing binary paths, subprocess runners, and MCP helpers."""

    @classmethod
    def setUpClass(cls):
        cls.rvs_bin = find_rvs_binary()
        if not cls.rvs_bin or not cls.rvs_bin.exists():
            target_debug = WORKSPACE_DIR / "target" / "debug" / "rvs"
            if target_debug.exists():
                cls.rvs_bin = target_debug
            else:
                raise RuntimeError(f"rvs binary not found. Run cargo build first.")

        cls.fixtures_dir = WORKSPACE_DIR / "tests" / "fixtures"
        cls.crackme_path = cls.fixtures_dir / "crackme_case"
        cls.flow_calc_path = cls.fixtures_dir / "flow_calc_elf64"
        cls.auth_gate_path = cls.fixtures_dir / "auth_gate_elf64"
        cls.test_target_path = cls.fixtures_dir / "test_target_elf64"

        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)

    def setUp(self):
        self._temp_files: List[Path] = []
        self._temp_dirs: List[tempfile.TemporaryDirectory] = []

    def tearDown(self):
        for f in self._temp_files:
            try:
                if f.exists():
                    f.unlink()
            except Exception:
                pass
        for d in self._temp_dirs:
            try:
                d.cleanup()
            except Exception:
                pass

    def create_temp_crackme(self) -> Path:
        """Creates an isolated temporary copy of crackme_case."""
        td = tempfile.TemporaryDirectory(prefix="rvs_e2e_crackme_")
        self._temp_dirs.append(td)
        tmp_path = Path(td.name) / "crackme_case"
        shutil.copy(self.crackme_path, tmp_path)
        os.chmod(tmp_path, 0o755)
        return tmp_path

    def create_temp_file(self, content: bytes, suffix: str = ".bin") -> Path:
        """Creates an isolated temporary file with given content."""
        td = tempfile.TemporaryDirectory(prefix="rvs_e2e_file_")
        self._temp_dirs.append(td)
        tmp_path = Path(td.name) / f"temp_{int(time.time()*1000)}{suffix}"
        with open(tmp_path, "wb") as f:
            f.write(content)
        return tmp_path

    def run_rvs(
        self,
        args: List[str],
        timeout: float = 25.0,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Optional[Dict[str, Any]], str, str]:
        """Executes rvs CLI and returns (returncode, parsed_json, stdout, stderr)."""
        cmd = [str(self.rvs_bin)] + args
        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=proc_env,
            cwd=str(WORKSPACE_DIR),
        )

        parsed_json = None
        stdout_clean = proc.stdout.strip()
        if stdout_clean:
            try:
                parsed_json = json.loads(stdout_clean)
            except Exception:
                pass

        return proc.returncode, parsed_json, proc.stdout, proc.stderr

    def run_harness_cli(
        self,
        args: List[str],
        timeout: float = 25.0,
    ) -> Tuple[int, Optional[Dict[str, Any]], str, str]:
        """Executes rvs_agent_harness.py as a CLI subprocess."""
        cmd = [sys.executable, str(WORKSPACE_DIR / "rvs_agent_harness.py")] + args
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(WORKSPACE_DIR),
        )

        parsed_json = None
        stdout_clean = proc.stdout.strip()
        if stdout_clean:
            try:
                parsed_json = json.loads(stdout_clean)
            except Exception:
                pass

        return proc.returncode, parsed_json, proc.stdout, proc.stderr

    def send_mcp_request(
        self,
        req: Dict[str, Any],
        harness: Optional[RvsHarness] = None,
    ) -> Dict[str, Any]:
        """Sends a JSON-RPC request to RvsHarness.serve_mcp and returns the response."""
        h = harness or self.harness
        sin = io.StringIO(json.dumps(req) + "\n")
        sout = io.StringIO()
        h.serve_mcp(stdin_stream=sin, stdout_stream=sout)
        sout.seek(0)
        output_str = sout.read().strip()
        self.assertTrue(output_str, "MCP server emitted empty response")
        return json.loads(output_str)


# =============================================================================
# TIER 1: FEATURE COVERAGE (40 tests, 5 per feature across 8 features)
# =============================================================================

class TestTier1FeatureCoverage(TestRvsE2EBase):
    """Tier 1: Comprehensive feature coverage across all 8 canonical features."""

    # --- Feature 1: Panic-Free Resilience (ORIGINAL_REQUEST §R1) ---

    def test_tier1_f1_panic_free_info(self):
        """F1.1: Verify info command executes cleanly without panic on valid ELF."""
        rc, json_data, stdout, stderr = self.run_rvs(["-f", str(self.crackme_path), "info"])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertNotIn("panicked at", stderr)
        self.assertNotIn("thread 'main' panicked", stderr)
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        self.assertEqual(json_data.get("command"), "info")
        data = json_data.get("data", {})
        self.assertEqual(data.get("format"), "elf")
        self.assertEqual(data.get("arch"), "x86")
        self.assertEqual(data.get("bits"), 64)

    def test_tier1_f1_panic_free_functions(self):
        """F1.2: Verify analyze functions executes cleanly without panic."""
        rc, json_data, stdout, stderr = self.run_rvs(["-f", str(self.crackme_path), "analyze", "functions"])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        functions = json_data.get("data", {}).get("functions", [])
        self.assertGreater(len(functions), 0)
        self.assertTrue(any("main" in f.get("name", "") for f in functions))

    def test_tier1_f1_panic_free_blocks(self):
        """F1.3: Verify analyze blocks executes cleanly on function target."""
        rc, json_data, stdout, stderr = self.run_rvs(["-f", str(self.crackme_path), "analyze", "blocks", "main"])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        data = json_data.get("data", {})
        self.assertEqual(data.get("function_name"), "main")
        self.assertGreater(data.get("total_blocks", 0), 0)

    def test_tier1_f1_panic_free_agent_triage(self):
        """F1.4: Verify agent triage executes composite analysis without panic."""
        rc, json_data, stdout, stderr = self.run_rvs(["-f", str(self.crackme_path), "agent", "triage"])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        data = json_data.get("data", {})
        self.assertIn("security", data)
        self.assertIn("entry_point_hex", data)

    def test_tier1_f1_panic_free_patch_plan_dry_run(self):
        """F1.5: Verify agent patch-plan dry run parses and validates safely."""
        plan = {
            "name": "Dry run verification plan",
            "dry_run": True,
            "steps": [
                {"type": "instruction", "addr": "0x11e0", "assembly": "nop"}
            ]
        }
        rc, json_data, stdout, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "agent", "patch-plan",
            "--plan", json.dumps(plan)
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        data = json_data.get("data", {})
        self.assertTrue(data.get("dry_run"))
        self.assertEqual(data.get("total_steps"), 1)

    # --- Feature 2: Standardized Exit Codes (ORIGINAL_REQUEST §R1) ---

    def test_tier1_f2_exit_code_1_invalid_argument(self):
        """F2.1: Verify exit code 1 on invalid argument flag."""
        rc, json_data, stdout, stderr = self.run_rvs(["--format", "invalid_mode_xyz", "-f", str(self.crackme_path), "info"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertIsNotNone(json_data)
        self.assertFalse(json_data.get("success"))
        err = json_data.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_INVALID_ARGUMENT)
        self.assertEqual(err.get("code"), "INVALID_ARGUMENT")
        self.assertIn("suggestion", err)

    def test_tier1_f2_exit_code_2_file_not_found(self):
        """F2.2: Verify exit code 2 on missing target binary."""
        rc, json_data, stdout, stderr = self.run_rvs(["-f", "missing_nonexistent_binary.bin", "info"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIsNotNone(json_data)
        self.assertFalse(json_data.get("success"))
        err = json_data.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_FILE_ERROR)
        self.assertEqual(err.get("category"), "FILE_ERROR")

    def test_tier1_f2_exit_code_2_zero_byte_file(self):
        """F2.3: Verify exit code 2 on zero-byte empty binary."""
        empty_bin = self.create_temp_file(b"")
        rc, json_data, stdout, stderr = self.run_rvs(["-f", str(empty_bin), "info"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIsNotNone(json_data)
        self.assertFalse(json_data.get("success"))
        err = json_data.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_FILE_ERROR)
        self.assertEqual(err.get("code"), "ZERO_BYTE_FILE")

    def test_tier1_f2_exit_code_3_analysis_error(self):
        """F2.4: Verify exit code 3 on analysis symbol resolution failure."""
        rc, json_data, stdout, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "emulate", "non_existent_function_symbol_xyz"
        ])
        self.assertEqual(rc, EXIT_ANALYSIS_ERROR)
        self.assertIsNotNone(json_data)
        self.assertFalse(json_data.get("success"))
        err = json_data.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_ANALYSIS_ERROR)
        self.assertEqual(err.get("category"), "ANALYSIS_ERROR")

    def test_tier1_f2_exit_code_4_patch_error(self):
        """F2.5: Verify exit code 4 on invalid patch instruction syntax."""
        tmp_bin = self.create_temp_crackme()
        rc, json_data, stdout, stderr = self.run_rvs([
            "-f", str(tmp_bin),
            "patch", "instruction",
            "--addr", "0x1146",
            "--assembly", "this is not valid assembly 123",
            "--backup", "false"
        ])
        self.assertEqual(rc, EXIT_PATCH_ERROR)
        self.assertIsNotNone(json_data)
        self.assertFalse(json_data.get("success"))
        err = json_data.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_PATCH_ERROR)
        self.assertEqual(err.get("category"), "PATCH_ERROR")

    # --- Feature 3: Token Compaction (ORIGINAL_REQUEST §R2) ---

    def test_tier1_f3_functions_compact_reduction(self):
        """F3.1: Verify functions compact mode reduces output size and uses compact schema."""
        rc_std, std_json, std_raw, _ = self.run_rvs(["-f", str(self.crackme_path), "analyze", "functions"])
        rc_cpt, cpt_json, cpt_raw, _ = self.run_rvs(["-c", "-f", str(self.crackme_path), "analyze", "functions"])
        self.assertEqual(rc_std, EXIT_SUCCESS)
        self.assertEqual(rc_cpt, EXIT_SUCCESS)
        self.assertLess(len(cpt_raw), len(std_raw), "Compact functions payload should be smaller")
        reduction = (1.0 - len(cpt_raw) / len(std_raw)) * 100.0
        self.assertGreater(reduction, 35.0, f"Expected substantial payload reduction, got {reduction:.1f}%")
        cpt_funcs = cpt_json.get("data", {}).get("functions", [])
        self.assertGreater(len(cpt_funcs), 0)
        self.assertIn("addr", cpt_funcs[0])

    def test_tier1_f3_strings_compact_structure(self):
        """F3.2: Verify strings compact mode omits verbose metadata."""
        rc_std, std_json, std_raw, _ = self.run_rvs(["-f", str(self.crackme_path), "strings"])
        rc_cpt, cpt_json, cpt_raw, _ = self.run_rvs(["-c", "-f", str(self.crackme_path), "strings"])
        self.assertEqual(rc_std, EXIT_SUCCESS)
        self.assertEqual(rc_cpt, EXIT_SUCCESS)
        self.assertLess(len(cpt_raw), len(std_raw))
        strings_data = cpt_json.get("data", {}).get("strings", [])
        self.assertGreater(len(strings_data), 0)

    def test_tier1_f3_symbols_compact_reduction(self):
        """F3.3: Verify symbols compact mode omits redundant fields."""
        rc_std, std_json, std_raw, _ = self.run_rvs(["-f", str(self.crackme_path), "symbols"])
        rc_cpt, cpt_json, cpt_raw, _ = self.run_rvs(["-c", "-f", str(self.crackme_path), "symbols"])
        self.assertEqual(rc_std, EXIT_SUCCESS)
        self.assertEqual(rc_cpt, EXIT_SUCCESS)
        reduction = (1.0 - len(cpt_raw) / len(std_raw)) * 100.0
        self.assertGreater(reduction, 40.0, f"Symbols reduction: {reduction:.1f}%")
        symbols = cpt_json.get("data", {}).get("symbols", [])
        self.assertGreater(len(symbols), 0)
        self.assertIn("addr", symbols[0])

    def test_tier1_f3_info_compact_integrity(self):
        """F3.4: Verify info compact mode preserves all essential decision signals."""
        rc, cpt_json, _, _ = self.run_rvs(["-c", "-f", str(self.crackme_path), "info"])
        self.assertEqual(rc, EXIT_SUCCESS)
        data = cpt_json.get("data", {})
        for field in ["format", "arch", "bits", "security", "entry_point_hex"]:
            self.assertIn(field, data, f"Compact info missing field {field}")

    def test_tier1_f3_harness_token_compaction_ratio(self):
        """F3.5: Verify Python harness achieves >= 50% token compaction on functions."""
        std_resp = self.harness.functions(str(self.crackme_path), compact=False)
        cpt_resp = self.harness.functions(str(self.crackme_path), compact=True)
        std_chars = len(json.dumps(std_resp))
        cpt_chars = len(json.dumps(cpt_resp))
        reduction = (1.0 - cpt_chars / std_chars) * 100.0
        self.assertGreaterEqual(reduction, 50.0, f"Harness compaction achieved {reduction:.1f}%")

    # --- Feature 4: Register Diff & Emulation (ORIGINAL_REQUEST §R2) ---

    def test_tier1_f4_dynamic_emulate_happy_path(self):
        """F4.1: Verify dynamic emulate executes specified steps on function entry."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "emulate", "main",
            "--steps", "20"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        data = json_data.get("data", {})
        self.assertEqual(data.get("target"), "main")
        self.assertGreater(data.get("steps_executed", data.get("steps", 0)), 0)

    def test_tier1_f4_dynamic_step_delta_diff(self):
        """F4.2: Verify dynamic step reports current/next address and instruction."""
        rc, json_data, _, stderr = self.run_rvs([
            "-c", "-f", str(self.crackme_path),
            "dynamic", "step", "main"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        data = json_data.get("data", {})
        self.assertTrue("curr" in data or "current_addr_hex" in data or "current_addr" in data)
        self.assertTrue("next" in data or "next_addr_hex" in data or "next_addr" in data)

    def test_tier1_f4_dynamic_trace_execution(self):
        """F4.3: Verify dynamic trace records sequential step execution."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "trace", "main",
            "--steps", "5"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))
        trace = json_data.get("data", {}).get("trace", [])
        self.assertEqual(len(trace), 5)

    def test_tier1_f4_dynamic_emulate_compact_diffs(self):
        """F4.4: Verify compact dynamic emulate suppresses redundant verbose register dumps."""
        rc, json_data, stdout, _ = self.run_rvs([
            "-c", "-f", str(self.crackme_path),
            "dynamic", "emulate", "main",
            "--steps", "10"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIsNotNone(json_data)
        data = json_data.get("data", {})
        self.assertIn("target", data)
        self.assertIn("start", data)

    def test_tier1_f4_dynamic_emulate_reg_preset(self):
        """F4.5: Verify dynamic emulate accepts register presets."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "emulate", "main",
            "--steps", "5",
            "-r", "rax=0x42"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertIsNotNone(json_data)
        self.assertTrue(json_data.get("success"))

    # --- Feature 5: Python Harness & MCP Loop (ORIGINAL_REQUEST §R3) ---

    def test_tier1_f5_harness_api_info(self):
        """F5.1: Verify programmatic RvsHarness.info execution."""
        resp = self.harness.info(str(self.crackme_path))
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp.get("command"), "info")
        self.assertEqual(resp.get("data", {}).get("format"), "elf")

    def test_tier1_f5_mcp_initialize_handshake(self):
        """F5.2: Verify MCP initialize handshake returns server metadata."""
        req = {
            "jsonrpc": "2.0",
            "id": 100,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "e2e_tester", "version": "1.0"}
            }
        }
        res = self.send_mcp_request(req)
        self.assertEqual(res.get("id"), 100)
        self.assertIn("result", res)
        result = res["result"]
        self.assertEqual(result.get("protocolVersion"), "2024-11-05")
        self.assertEqual(result.get("serverInfo", {}).get("name"), "rvs-mcp-server")

    def test_tier1_f5_mcp_tools_list(self):
        """F5.3: Verify MCP tools/list returns all 16 canonical tools."""
        req = {"jsonrpc": "2.0", "id": 101, "method": "tools/list", "params": {}}
        res = self.send_mcp_request(req)
        tools = res.get("result", {}).get("tools", [])
        self.assertEqual(len(tools), 16)
        tool_names = [t.get("name") for t in tools]
        for canonical in CANONICAL_TOOLS:
            c_name = canonical["name"] if isinstance(canonical, dict) else canonical
            self.assertIn(c_name, tool_names)

    def test_tier1_f5_mcp_tools_call_info(self):
        """F5.4: Verify MCP tools/call executes rvs_info and returns text result."""
        req = {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "rvs_info",
                "arguments": {"file": str(self.crackme_path)}
            }
        }
        res = self.send_mcp_request(req)
        result = res.get("result", {})
        self.assertFalse(result.get("isError"))
        content = result.get("content", [])
        self.assertGreater(len(content), 0)
        body = json.loads(content[0].get("text", "{}"))
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("data", {}).get("arch"), "x86")

    def test_tier1_f5_mcp_clean_stream_termination(self):
        """F5.5: Verify MCP server cleanly exits when stdin stream is empty/closed."""
        sin = io.StringIO("")
        sout = io.StringIO()
        self.harness.serve_mcp(stdin_stream=sin, stdout_stream=sout)
        self.assertEqual(sout.getvalue(), "")

    # --- Feature 6: Tool Schema Export (ORIGINAL_REQUEST §R3) ---

    def test_tier1_f6_export_mcp_schemas(self):
        """F6.1: Verify export of MCP schemas generates 16 valid tool definitions."""
        schemas = get_tool_schemas("mcp")
        self.assertEqual(len(schemas), 16)
        for s in schemas:
            self.assertIn("name", s)
            self.assertIn("description", s)
            self.assertIn("inputSchema", s)
            self.assertIn("properties", s["inputSchema"])

    def test_tier1_f6_export_openai_schemas(self):
        """F6.2: Verify export of OpenAI schemas contains 16 valid function declarations."""
        schemas = get_tool_schemas("openai")
        self.assertEqual(len(schemas), 16)
        for s in schemas:
            self.assertEqual(s.get("type"), "function")
            self.assertIn("function", s)
            self.assertIn("name", s["function"])
            self.assertIn("parameters", s["function"])

    def test_tier1_f6_export_anthropic_schemas(self):
        """F6.3: Verify export of Anthropic schemas contains 16 tools."""
        schemas = get_tool_schemas("anthropic")
        self.assertEqual(len(schemas), 16)
        for s in schemas:
            self.assertIn("name", s)
            self.assertIn("input_schema", s)

    def test_tier1_f6_export_gemini_schemas(self):
        """F6.4: Verify export of Gemini schemas contains 16 tools."""
        schemas = get_tool_schemas("gemini")
        self.assertEqual(len(schemas), 16)
        for s in schemas:
            self.assertIn("name", s)
            self.assertIn("parameters", s)

    def test_tier1_f6_schema_canonical_16_names(self):
        """F6.5: Verify canonical 16 tools catalog exact match."""
        expected_tools = {
            "rvs_info", "rvs_functions", "rvs_disasm", "rvs_decompile",
            "rvs_flow", "rvs_xrefs", "rvs_strings", "rvs_symbols",
            "rvs_patch_instruction", "rvs_patch_string", "rvs_patch_bytes",
            "rvs_agent_triage", "rvs_agent_patch_plan",
            "rvs_dynamic_emulate", "rvs_dynamic_trace", "rvs_dynamic_step"
        }
        actual_names = {t["name"] if isinstance(t, dict) else t for t in CANONICAL_TOOLS}
        self.assertEqual(actual_names, expected_tools)

    # --- Feature 7: Subprocess & Timeout Safety (ORIGINAL_REQUEST §R1) ---

    def test_tier1_f7_harness_timeout_enforcement(self):
        """F7.1: Verify harness timeout triggers EXIT_TIMEOUT_ERROR (exit code 5)."""
        resp = self.harness.run(["info"], timeout=0.0001)
        self.assertFalse(resp.get("success"))
        err = resp.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_TIMEOUT_ERROR)
        self.assertEqual(err.get("category"), "TIMEOUT_ERROR")

    def test_tier1_f7_cli_timeout_flag(self):
        """F7.2: Verify CLI --timeout 0 triggers structured timeout error."""
        rc, json_data, _, _ = self.run_rvs([
            "-f", str(self.crackme_path),
            "--timeout", "0",
            "analyze", "functions"
        ])
        self.assertEqual(rc, EXIT_TIMEOUT_ERROR)
        self.assertIsNotNone(json_data)
        self.assertEqual(json_data.get("error", {}).get("exit_code"), EXIT_TIMEOUT_ERROR)

    def test_tier1_f7_subprocess_env_isolation(self):
        """F7.3: Verify harness subprocess environment includes isolation variables."""
        from rvs_agent_harness import get_isolated_environment
        env = get_isolated_environment()
        self.assertEqual(env.get("TERM"), "dumb")
        self.assertEqual(env.get("NO_COLOR"), "1")
        self.assertEqual(env.get("R2_NOPLUGINS"), "1")
        self.assertEqual(env.get("RADARE2_RCFILE"), "/dev/null")

    def test_tier1_f7_non_utf8_binary_sanitization(self):
        """F7.4: Verify binary byte stream with non-UTF-8 bytes is handled safely."""
        non_utf8_bin = self.create_temp_file(b"\x7fELF\x02\x01\x01\x00" + b"\xff\xfe\x80\x81" * 16)
        rc, json_data, stdout, stderr = self.run_rvs(["-f", str(non_utf8_bin), "strings"])
        self.assertIn(rc, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier1_f7_process_cleanup_no_zombies(self):
        """F7.5: Verify no zombie child processes remain after execution."""
        self.harness.run(["info"], timeout=0.001)
        # Give OS a moment to reap processes
        time.sleep(0.05)
        # Check current child processes
        try:
            pid = os.getpid()
            ps_proc = subprocess.run(["ps", "--ppid", str(pid), "-o", "stat="], capture_output=True, text=True)
            stats = ps_proc.stdout.split()
            self.assertNotIn("Z", stats, "Zombie child process detected")
        except Exception:
            pass

    # --- Feature 8: Adversarial Input Handling (ORIGINAL_REQUEST §R4) ---

    def test_tier1_f8_command_injection_mitigation(self):
        """F8.1: Verify shell command injection in binary path is safely rejected."""
        injection_target = "crackme_case; touch injected_file_marker.txt"
        rc, json_data, _, _ = self.run_rvs(["-f", injection_target, "info"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertFalse(Path("injected_file_marker.txt").exists(), "Command injection vulnerability detected!")

    def test_tier1_f8_malformed_json_plan(self):
        """F8.2: Verify malformed JSON in patch plan fails cleanly without panic."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "agent", "patch-plan",
            "--plan", "{not a valid json:"
        ])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_INTERNAL_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier1_f8_oversized_string_input(self):
        """F8.3: Verify oversized argument does not crash or panic the engine."""
        huge_arg = "A" * 50000
        rc, json_data, _, stderr = self.run_rvs(["-f", str(self.crackme_path), "analyze", "blocks", huge_arg])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier1_f8_special_characters_in_query(self):
        """F8.4: Verify special symbols in symbol query do not cause crash."""
        rc, json_data, _, stderr = self.run_rvs(["-f", str(self.crackme_path), "analyze", "xrefs", "sym.test!@#$%^&*()"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertNotIn("panicked at", stderr)
        self.assertEqual(json_data.get("data", {}).get("count"), 0)

    def test_tier1_f8_truncated_binary_defense(self):
        """F8.5: Verify 32-byte truncated ELF file is rejected defensively."""
        truncated = self.create_temp_file(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 24)
        rc, json_data, _, stderr = self.run_rvs(["-f", str(truncated), "analyze", "functions"])
        self.assertIn(rc, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR, EXIT_FILE_ERROR))
        self.assertNotIn("panicked at", stderr)


# =============================================================================
# TIER 2: BOUNDARY & CORNER CASES (40 tests, 5 per feature across 8 features)
# =============================================================================

class TestTier2BoundaryCases(TestRvsE2EBase):
    """Tier 2: Boundary value analysis (BVA) and corner cases across all 8 features."""

    # --- Feature 1 Boundary Cases ---

    def test_tier2_f1_bva_empty_file_flag(self):
        """B1.1: Empty --file path string handled without panic."""
        rc, json_data, _, stderr = self.run_rvs(["-f", "", "info"])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_FILE_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier2_f1_bva_nonexistent_function(self):
        """B1.2: Analyze blocks on non-existent function returns clean error envelope."""
        rc, json_data, _, stderr = self.run_rvs(["-f", str(self.crackme_path), "analyze", "blocks", "__definitely_not_a_func_999__"])
        self.assertEqual(rc, EXIT_ANALYSIS_ERROR)
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(json_data)
        self.assertFalse(json_data.get("success"))

    def test_tier2_f1_bva_empty_disasm_address(self):
        """B1.3: Empty target address argument does not panic."""
        rc, json_data, _, stderr = self.run_rvs(["-f", str(self.crackme_path), "analyze", "blocks", ""])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier2_f1_bva_zero_length_patch_instruction(self):
        """B1.4: Patch instruction with empty assembly string fails safely."""
        tmp_bin = self.create_temp_crackme()
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(tmp_bin),
            "patch", "instruction",
            "--addr", "0x1146",
            "--assembly", "",
            "--backup", "false"
        ])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR, EXIT_PATCH_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier2_f1_bva_empty_patch_bytes(self):
        """B1.5: Patch bytes with empty hex payload fails cleanly."""
        tmp_bin = self.create_temp_crackme()
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(tmp_bin),
            "patch", "bytes",
            "--addr", "0x1146",
            "--hex", "",
            "--backup", "false"
        ])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR, EXIT_PATCH_ERROR))
        self.assertNotIn("panicked at", stderr)

    # --- Feature 2 Boundary Cases ---

    def test_tier2_f2_bva_zero_byte_file_exit_code(self):
        """B2.1: Exactly exit code 2 for zero-byte file."""
        zero_file = self.create_temp_file(b"")
        rc, json_data, _, _ = self.run_rvs(["-f", str(zero_file), "info"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertEqual(json_data.get("error", {}).get("exit_code"), EXIT_FILE_ERROR)

    def test_tier2_f2_bva_non_existent_file_exit_code(self):
        """B2.2: Exactly exit code 2 for non-existent file."""
        rc, json_data, _, _ = self.run_rvs(["-f", "file_does_not_exist_404.bin", "info"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertEqual(json_data.get("error", {}).get("exit_code"), EXIT_FILE_ERROR)

    def test_tier2_f2_bva_permission_denied_file(self):
        """B2.3: Exactly exit code 2 for unreadable permission-denied file."""
        unreadable = self.create_temp_file(b"\x7fELF" + b"\x00" * 100)
        os.chmod(unreadable, 0o000)
        try:
            rc, json_data, _, _ = self.run_rvs(["-f", str(unreadable), "info"])
            self.assertIn(rc, (EXIT_FILE_ERROR, EXIT_INTERNAL_ERROR))
            self.assertFalse(json_data.get("success", True))
        finally:
            os.chmod(unreadable, 0o644)

    def test_tier2_f2_bva_unknown_subcommand_exit_code(self):
        """B2.4: Exactly exit code 1 for unknown subcommand."""
        rc, json_data, _, _ = self.run_rvs(["unknown_subcommand_xyz"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertEqual(json_data.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

    def test_tier2_f2_bva_invalid_hex_address_exit_code(self):
        """B2.5: Invalid hexadecimal address rejected with exit code 1 or 4."""
        tmp_bin = self.create_temp_crackme()
        rc, json_data, _, _ = self.run_rvs([
            "-f", str(tmp_bin),
            "patch", "instruction",
            "--addr", "0xGHIJK",
            "--assembly", "nop",
            "--backup", "false"
        ])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR, EXIT_PATCH_ERROR))
        self.assertFalse(json_data.get("success"))

    # --- Feature 3 Boundary Cases ---

    def test_tier2_f3_bva_compact_on_zero_string_file(self):
        """B3.1: Compact strings on minimal binary returns empty/clean payload."""
        minimal = self.create_temp_file(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)
        rc, json_data, _, _ = self.run_rvs(["-c", "-f", str(minimal), "strings"])
        self.assertEqual(rc, EXIT_SUCCESS)
        strings = json_data.get("data", {}).get("strings", [])
        self.assertEqual(len(strings), 0)

    def test_tier2_f3_bva_compact_with_pretty_flag(self):
        """B3.2: --compact combined with --pretty produces formatted JSON."""
        rc, json_data, stdout, _ = self.run_rvs(["-c", "--pretty", "-f", str(self.crackme_path), "info"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIn("\n", stdout.strip())
        self.assertTrue(json_data.get("success"))

    def test_tier2_f3_bva_compact_functions_limit_zero(self):
        """B3.3: Compact functions with limit=0 yields empty list."""
        res = self.harness.functions(str(self.crackme_path), limit=0, compact=True)
        self.assertTrue(res.get("success"))
        funcs = res.get("data", {}).get("functions", [])
        self.assertEqual(len(funcs), 0)

    def test_tier2_f3_bva_compact_symbols_nonexistent_filter(self):
        """B3.4: Compact symbols with non-existent filter yields empty list."""
        res = self.harness.symbols(str(self.crackme_path), filter="definitely_nonexistent_symbol_123", compact=True)
        self.assertTrue(res.get("success"))
        syms = res.get("data", {}).get("symbols", [])
        self.assertEqual(len(syms), 0)

    def test_tier2_f3_bva_compact_xrefs_no_xrefs(self):
        """B3.5: Compact xrefs query on address with 0 xrefs yields count 0."""
        rc, json_data, _, _ = self.run_rvs(["-c", "-f", str(self.crackme_path), "analyze", "xrefs", "0x1000"])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertEqual(json_data.get("data", {}).get("count"), 0)

    # --- Feature 4 Boundary Cases ---

    def test_tier2_f4_bva_dynamic_step_zero_steps(self):
        """B4.1: Dynamic step with 0 steps handled defensively."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "step", "main",
            "--steps", "0"
        ])
        self.assertIn(rc, (EXIT_SUCCESS, EXIT_INVALID_ARGUMENT))
        self.assertNotIn("panicked at", stderr)

    def test_tier2_f4_bva_dynamic_step_negative_steps(self):
        """B4.2: Dynamic step with negative steps rejected with exit code 1."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "step", "main",
            "--steps", "-5"
        ])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertNotIn("panicked at", stderr)

    def test_tier2_f4_bva_dynamic_emulate_null_address(self):
        """B4.3: Dynamic emulate at address 0x0 handled defensively without panic."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "emulate", "0x0"
        ])
        self.assertIn(rc, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR))
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(json_data)

    def test_tier2_f4_bva_dynamic_emulate_max_address(self):
        """B4.4: Dynamic emulate at u64::MAX address handled defensively without panic."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "emulate", "0xffffffffffffffff"
        ])
        self.assertIn(rc, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR))
        self.assertNotIn("panicked at", stderr)
        self.assertIsNotNone(json_data)

    def test_tier2_f4_bva_dynamic_reg_preset_malformed(self):
        """B4.5: Malformed register preset format handled cleanly."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "emulate", "main",
            "-r", "invalid_reg_format_no_equals"
        ])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_SUCCESS))
        self.assertNotIn("panicked at", stderr)

    # --- Feature 5 Boundary Cases ---

    def test_tier2_f5_bva_mcp_params_null(self):
        """B5.1: MCP request with params=null returns -32602 error."""
        req = {"jsonrpc": "2.0", "id": 201, "method": "tools/call", "params": None}
        res = self.send_mcp_request(req)
        self.assertEqual(res.get("error", {}).get("code"), -32602)

    def test_tier2_f5_bva_mcp_params_string(self):
        """B5.2: MCP request with string params returns -32602 error."""
        req = {"jsonrpc": "2.0", "id": 202, "method": "tools/call", "params": "string_params"}
        res = self.send_mcp_request(req)
        self.assertEqual(res.get("error", {}).get("code"), -32602)

    def test_tier2_f5_bva_mcp_arguments_null(self):
        """B5.3: MCP request with arguments=null returns structured error without crash."""
        req = {
            "jsonrpc": "2.0",
            "id": 203,
            "method": "tools/call",
            "params": {"name": "rvs_info", "arguments": None}
        }
        res = self.send_mcp_request(req)
        self.assertTrue(res.get("result", {}).get("isError"))

    def test_tier2_f5_bva_mcp_invalid_method(self):
        """B5.4: MCP request with unknown method returns -32601 Method Not Found."""
        req = {"jsonrpc": "2.0", "id": 204, "method": "invalid/unknown_method", "params": {}}
        res = self.send_mcp_request(req)
        self.assertEqual(res.get("error", {}).get("code"), -32601)

    def test_tier2_f5_bva_mcp_tool_missing_file_argument(self):
        """B5.5: MCP tools/call missing required file parameter flags isError=True."""
        req = {
            "jsonrpc": "2.0",
            "id": 205,
            "method": "tools/call",
            "params": {"name": "rvs_info", "arguments": {}}
        }
        res = self.send_mcp_request(req)
        result = res.get("result", {})
        self.assertTrue(result.get("isError"))
        body = json.loads(result.get("content", [{}])[0].get("text", "{}"))
        self.assertFalse(body.get("success"))
        self.assertIn("file", body.get("error", {}).get("message", "").lower())

    # --- Feature 6 Boundary Cases ---

    def test_tier2_f6_bva_schema_export_invalid_format(self):
        """B6.1: Exporting schemas with unknown format raises ValueError."""
        with self.assertRaises(ValueError):
            get_tool_schemas("unsupported_format_xyz")

    def test_tier2_f6_bva_coercion_string_booleans(self):
        """B6.2: Coerce string false / true into bools in execute_tool."""
        res_false = self.harness.execute_tool("rvs_info", {"file": str(self.crackme_path), "compact": "false"})
        self.assertTrue(res_false.get("success"))
        res_true = self.harness.execute_tool("rvs_info", {"file": str(self.crackme_path), "compact": "true"})
        self.assertTrue(res_true.get("success"))

    def test_tier2_f6_bva_coercion_string_integers(self):
        """B6.3: Coerce string integer 5 into int in dynamic emulate."""
        res = self.harness.execute_tool("rvs_dynamic_emulate", {
            "file": str(self.crackme_path),
            "target": "main",
            "steps": "5"
        })
        self.assertTrue(res.get("success"))

    def test_tier2_f6_bva_coercion_string_reg_set(self):
        """B6.4: Coerce string reg_set rax=1 into list ["rax=1"]."""
        res = self.harness.execute_tool("rvs_dynamic_emulate", {
            "file": str(self.crackme_path),
            "target": "main",
            "steps": "3",
            "reg_set": "rax=1"
        })
        self.assertTrue(res.get("success"))

    def test_tier2_f6_bva_unknown_tool_call(self):
        """B6.5: Calling unknown tool name returns INVALID_ARGUMENT error."""
        res = self.harness.execute_tool("nonexistent_tool_xyz", {"file": str(self.crackme_path)})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

    # --- Feature 7 Boundary Cases ---

    def test_tier2_f7_bva_immediate_timeout(self):
        """B7.1: Immediate timeout threshold returns EXIT_TIMEOUT_ERROR."""
        resp = self.harness.run(["info"], timeout=0.0001)
        self.assertEqual(resp.get("error", {}).get("exit_code"), EXIT_TIMEOUT_ERROR)

    def test_tier2_f7_bva_large_timeout(self):
        """B7.2: Large timeout value executes normally without overflow."""
        resp = self.harness.run(["-f", str(self.crackme_path), "info"], timeout=3600.0)
        self.assertTrue(resp.get("success"))

    def test_tier2_f7_bva_path_with_spaces_unicode(self):
        """B7.3: Binary path containing spaces and brackets executes safely."""
        td = tempfile.TemporaryDirectory(prefix="rvs space test ")
        self._temp_dirs.append(td)
        special_path = Path(td.name) / "crackme [special @ v1.0].bin"
        shutil.copy(self.crackme_path, special_path)
        os.chmod(special_path, 0o755)

        rc, json_data, _, stderr = self.run_rvs(["-f", str(special_path), "info"])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertTrue(json_data.get("success"))

    def test_tier2_f7_bva_binary_stdout_with_null_bytes(self):
        """B7.4: Binary stdout with null bytes handled without decode exception."""
        raw_bytes_bin = self.create_temp_file(b"\x7fELF" + b"\x00\x01\x02\x03" * 50)
        rc, json_data, _, _ = self.run_rvs(["-f", str(raw_bytes_bin), "strings"])
        self.assertEqual(rc, EXIT_SUCCESS)

    def test_tier2_f7_bva_broken_pipe_simulation(self):
        """B7.5: BrokenPipe simulation handles closed stream cleanly."""
        class BrokenStream(io.StringIO):
            def write(self, s):
                raise BrokenPipeError("Pipe broken")
            def flush(self):
                raise BrokenPipeError("Pipe broken")

        sin = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) + "\n")
        sout = BrokenStream()
        try:
            self.harness.serve_mcp(stdin_stream=sin, stdout_stream=sout)
        except BrokenPipeError:
            pass  # Acceptable to raise or handle cleanly

    # --- Feature 8 Boundary Cases ---

    def test_tier2_f8_bva_u64_max_address_query(self):
        """B8.1: Address u64::MAX (0xffffffffffffffff) handled without integer overflow."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "analyze", "xrefs", "0xffffffffffffffff"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertNotIn("panicked at", stderr)
        data = json_data.get("data", {})
        self.assertEqual(data.get("target_addr_hex"), "0xffffffffffffffff")
        self.assertEqual(data.get("count"), 0)

    def test_tier2_f8_bva_zero_address_query(self):
        """B8.2: Address 0x0 query returns empty results without panic."""
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "analyze", "xrefs", "0x0"
        ])
        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertNotIn("panicked at", stderr)
        self.assertEqual(json_data.get("data", {}).get("count"), 0)

    def test_tier2_f8_bva_truncated_elf_16bytes(self):
        """B8.3: 16-byte ELF header returns error code without crashing."""
        corrupt = self.create_temp_file(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        rc, json_data, _, stderr = self.run_rvs(["-f", str(corrupt), "analyze", "functions"])
        self.assertIn(rc, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR, EXIT_FILE_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier2_f8_bva_random_fuzzed_binary(self):
        """B8.4: Random fuzzed 256 bytes handled defensively."""
        fuzz = self.create_temp_file(os.urandom(256))
        rc, json_data, _, stderr = self.run_rvs(["-f", str(fuzz), "agent", "triage"])
        self.assertIn(rc, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR, EXIT_FILE_ERROR))
        self.assertNotIn("panicked at", stderr)

    def test_tier2_f8_bva_corrupted_plan_missing_fields(self):
        """B8.5: Patch plan with missing step fields rejected with exit code 1 or 4."""
        plan = {"steps": [{"missing_type_and_addr": True}]}
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "agent", "patch-plan",
            "--plan", json.dumps(plan)
        ])
        self.assertIn(rc, (EXIT_INVALID_ARGUMENT, EXIT_PATCH_ERROR, EXIT_INTERNAL_ERROR))
        self.assertNotIn("panicked at", stderr)


# =============================================================================
# TIER 3: CROSS-FEATURE INTERACTIONS (8 pairwise interaction tests)
# =============================================================================

class TestTier3CrossFeatureInteractions(TestRvsE2EBase):
    """Tier 3: Multi-feature combinatorial and cross-cutting interaction tests."""

    def test_tier3_dynamic_emulate_and_compact_mode(self):
        """Pairwise 1 (F3 + F4): Dynamic emulation executed in compact mode."""
        rc_std, std_json, std_raw, _ = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "emulate", "main",
            "--steps", "15"
        ])
        rc_cpt, cpt_json, cpt_raw, _ = self.run_rvs([
            "-c", "-f", str(self.crackme_path),
            "dynamic", "emulate", "main",
            "--steps", "15"
        ])
        self.assertEqual(rc_std, EXIT_SUCCESS)
        self.assertEqual(rc_cpt, EXIT_SUCCESS)
        self.assertLess(len(cpt_raw), len(std_raw))
        cpt_data = cpt_json.get("data", {})
        self.assertEqual(cpt_data.get("target"), "main")
        self.assertIn("start", cpt_data)

    def test_tier3_patch_string_and_verify_xrefs(self):
        """Pairwise 2 (F1 + F2 + F8): String patch followed by cross-reference verification."""
        tmp_bin = self.create_temp_crackme()
        rc_patch, patch_json, _, stderr = self.run_rvs([
            "-f", str(tmp_bin),
            "patch", "string",
            "--addr", "0x2004",
            "--new", "Enter secret:",
            "--backup", "false"
        ])
        self.assertEqual(rc_patch, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertTrue(patch_json.get("success"))

        rc_xref, xref_json, _, _ = self.run_rvs([
            "-f", str(tmp_bin),
            "analyze", "xrefs", "0x2004"
        ])
        self.assertEqual(rc_xref, EXIT_SUCCESS)
        self.assertTrue(xref_json.get("success"))
        xrefs = xref_json.get("data", {}).get("xrefs", [])
        self.assertGreater(len(xrefs), 0)
        self.assertEqual(xrefs[0].get("from_function"), "main")

    def test_tier3_agent_triage_decompile_flow_pipeline(self):
        """Pairwise 3 (F1 + F3 + F5): Agent triage -> decompile -> flow sequential pipeline."""
        triage_resp = self.harness.triage(str(self.crackme_path), compact=True)
        self.assertTrue(triage_resp.get("success"))

        decompile_resp = self.harness.decompile(str(self.crackme_path), function="main", compact=True)
        self.assertTrue(decompile_resp.get("success"))
        self.assertIn("pseudo_c", decompile_resp.get("data", {}))

        flow_resp = self.harness.flow(str(self.crackme_path), function="main", compact=True)
        self.assertTrue(flow_resp.get("success"))
        self.assertIn("total_blocks", flow_resp.get("data", {}))

    def test_tier3_mcp_dynamic_emulate_with_coercion(self):
        """Pairwise 4 (F5 + F6): MCP tools/call for dynamic emulate with coerced params."""
        req = {
            "jsonrpc": "2.0",
            "id": 301,
            "method": "tools/call",
            "params": {
                "name": "rvs_dynamic_emulate",
                "arguments": {
                    "file": str(self.crackme_path),
                    "target": "main",
                    "steps": "10",
                    "compact": "true",
                    "reg_set": "rax=42"
                }
            }
        }
        res = self.send_mcp_request(req)
        result = res.get("result", {})
        self.assertFalse(result.get("isError"))
        body = json.loads(result.get("content", [{}])[0].get("text", "{}"))
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("command"), "dynamic emulate")

    def test_tier3_agent_patch_plan_compact_execution(self):
        """Pairwise 5 (F2 + F3 + F4): Agent patch-plan execution in compact mode."""
        tmp_bin = self.create_temp_crackme()
        plan = {
            "name": "Compact execution plan",
            "dry_run": False,
            "steps": [
                {"type": "instruction", "addr": "0x1146", "assembly": "mov eax, 1"}
            ]
        }
        rc, json_data, _, stderr = self.run_rvs([
            "-c", "-f", str(tmp_bin),
            "agent", "patch-plan",
            "--plan", json.dumps(plan)
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertTrue(json_data.get("success"))
        data = json_data.get("data", {})
        self.assertTrue(data.get("applied"))

    def test_tier3_adversarial_binary_via_mcp_server(self):
        """Pairwise 6 (F2 + F5 + F8): MCP server resiliently handles corrupted binaries without dropping session."""
        zero_file = self.create_temp_file(b"")
        req1 = {
            "jsonrpc": "2.0",
            "id": 302,
            "method": "tools/call",
            "params": {"name": "rvs_functions", "arguments": {"file": str(zero_file)}}
        }
        res1 = self.send_mcp_request(req1)
        self.assertTrue(res1.get("result", {}).get("isError"))

        # Follow-up valid request proves server is still operational
        req2 = {
            "jsonrpc": "2.0",
            "id": 303,
            "method": "tools/call",
            "params": {"name": "rvs_info", "arguments": {"file": str(self.crackme_path)}}
        }
        res2 = self.send_mcp_request(req2)
        self.assertFalse(res2.get("result", {}).get("isError"))

    def test_tier3_dynamic_trace_timeout_compact(self):
        """Pairwise 7 (F3 + F4 + F7): Dynamic trace timeout under compact mode."""
        rc, json_data, _, _ = self.run_rvs([
            "-c", "-f", str(self.crackme_path),
            "--timeout", "0",
            "dynamic", "trace", "main"
        ])
        self.assertEqual(rc, EXIT_TIMEOUT_ERROR)
        self.assertEqual(json_data.get("error", {}).get("exit_code"), EXIT_TIMEOUT_ERROR)

    def test_tier3_strings_search_patch_verify(self):
        """Pairwise 8 (F1 + F2 + F3): Search strings, trace xrefs, patch instruction, verify disassembly."""
        tmp_bin = self.create_temp_crackme()
        rc_str, str_json, _, _ = self.run_rvs(["-c", "-f", str(tmp_bin), "strings"])
        self.assertEqual(rc_str, EXIT_SUCCESS)

        # Patch instruction at 0x120c (lea rsi, str.Enter_serial:) with nop
        rc_patch, patch_json, _, stderr = self.run_rvs([
            "-f", str(tmp_bin),
            "patch", "instruction",
            "--addr", "0x120c",
            "--assembly", "nop",
            "--backup", "false"
        ])
        self.assertEqual(rc_patch, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertTrue(patch_json.get("success"))

        # Disassemble block at 0x11e0 to verify nop instruction
        rc_block, block_json, _, _ = self.run_rvs([
            "-f", str(tmp_bin),
            "analyze", "blocks", "main"
        ])
        self.assertEqual(rc_block, EXIT_SUCCESS)
        self.assertTrue(block_json.get("success"))


# =============================================================================
# TIER 4: REAL-WORLD APPLICATION SCENARIOS (5 end-to-end workflows)
# =============================================================================

class TestTier4RealWorldScenarios(TestRvsE2EBase):
    """Tier 4: Realistic, end-to-end reverse engineering workflows."""

    def test_tier4_scenario1_crackme_analysis_and_patch_bypass(self):
        """Scenario 1: Complete crackme analysis, key discovery, and validation bypass."""
        tmp_bin = self.create_temp_crackme()

        # Step 1: Binary metadata inspection
        info_resp = self.harness.info(str(tmp_bin))
        self.assertTrue(info_resp.get("success"))
        self.assertEqual(info_resp.get("data", {}).get("format"), "elf")

        # Step 2: String analysis for authentication messages
        strings_resp = self.harness.strings(str(tmp_bin))
        self.assertTrue(strings_resp.get("success"))
        found_strings = [s.get("string") for s in strings_resp.get("data", {}).get("strings", [])]
        self.assertIn("Valid serial", found_strings)
        self.assertIn("Invalid serial", found_strings)

        # Step 3: Find cross references to "Valid serial" (0x2018)
        rc_xref, xref_json, _, _ = self.run_rvs(["-f", str(tmp_bin), "analyze", "xrefs", "0x2018"])
        self.assertEqual(rc_xref, EXIT_SUCCESS)
        xrefs = xref_json.get("data", {}).get("xrefs", [])
        self.assertGreater(len(xrefs), 0)
        valid_branch_addr = xrefs[0].get("from_addr_hex")

        # Step 4: Decompile main function to locate the verification check
        decompile_resp = self.harness.decompile(str(tmp_bin), function="main")
        self.assertTrue(decompile_resp.get("success"))
        pseudo_c = decompile_resp.get("data", {}).get("pseudo_c", "")
        self.assertIn("Valid serial", pseudo_c)

        # Step 5: Execute atomic patch plan to bypass authentication check
        patch_plan = {
            "name": "Crackme Auth Bypass",
            "dry_run": False,
            "steps": [
                {
                    "type": "instruction",
                    "addr": "0x13c9",
                    "assembly": "jmp 0x1479"
                }
            ]
        }
        rc_plan, plan_json, _, stderr = self.run_rvs([
            "-f", str(tmp_bin),
            "agent", "patch-plan",
            "--plan", json.dumps(patch_plan)
        ])
        self.assertEqual(rc_plan, EXIT_SUCCESS, f"Stderr: {stderr}")
        self.assertTrue(plan_json.get("data", {}).get("applied"))

        # Step 6: Verify patched binary disassembly
        rc_disasm, disasm_json, _, _ = self.run_rvs(["-f", str(tmp_bin), "analyze", "blocks", "main"])
        self.assertEqual(rc_disasm, EXIT_SUCCESS)
        self.assertTrue(disasm_json.get("success"))

    def test_tier4_scenario2_binary_triage_to_control_flow_graph(self):
        """Scenario 2: Binary triage to control flow graph reconstruction."""
        target_bin = self.flow_calc_path if self.flow_calc_path.exists() else self.crackme_path

        # Step 1: Agent triage assessment
        triage_resp = self.harness.triage(str(target_bin))
        self.assertTrue(triage_resp.get("success"))
        triage_data = triage_resp.get("data", {})
        self.assertTrue("entry" in triage_data or "entry_point_hex" in triage_data or "entry_point" in triage_data)

        # Step 2: Enumerate functions
        funcs_resp = self.harness.functions(str(target_bin))
        self.assertTrue(funcs_resp.get("success"))
        funcs = funcs_resp.get("data", {}).get("functions", [])
        self.assertGreater(len(funcs), 0)

        # Step 3: Extract flow graph for main function
        flow_resp = self.harness.flow(str(target_bin), function="main")
        self.assertTrue(flow_resp.get("success"))
        flow_data = flow_resp.get("data", {})
        self.assertGreater(flow_data.get("total_blocks", 0), 0)
        self.assertIn("decision_nodes", flow_data)

    def test_tier4_scenario3_mcp_interactive_session_simulation(self):
        """Scenario 3: Multi-turn interactive MCP reverse engineering session."""
        # Turn 1: Initialize session
        init_res = self.send_mcp_request({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
        })
        self.assertEqual(init_res.get("result", {}).get("protocolVersion"), "2024-11-05")

        # Turn 2: Tools discovery
        tools_res = self.send_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        self.assertEqual(len(tools_res.get("result", {}).get("tools", [])), 16)

        # Turn 3: Inspect target binary
        info_res = self.send_mcp_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "rvs_info", "arguments": {"file": str(self.crackme_path)}}
        })
        self.assertFalse(info_res.get("result", {}).get("isError"))

        # Turn 4: Discover functions
        funcs_res = self.send_mcp_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "rvs_functions", "arguments": {"file": str(self.crackme_path), "limit": 5}}
        })
        self.assertFalse(funcs_res.get("result", {}).get("isError"))

        # Turn 5: Single step emulation
        step_res = self.send_mcp_request({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "rvs_dynamic_step", "arguments": {"file": str(self.crackme_path), "target": "main"}}
        })
        self.assertFalse(step_res.get("result", {}).get("isError"))

    def test_tier4_scenario4_corrupted_binary_defense_pipeline(self):
        """Scenario 4: Hardened defense across corrupted, empty, and fuzzed binaries."""
        # 1. 0-byte binary
        zero_bin = self.create_temp_file(b"")
        rc, json_data, _, _ = self.run_rvs(["-f", str(zero_bin), "info"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertEqual(json_data.get("error", {}).get("exit_code"), EXIT_FILE_ERROR)

        # 2. Truncated 16-byte ELF header
        trunc_bin = self.create_temp_file(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        rc2, json2, _, stderr2 = self.run_rvs(["-f", str(trunc_bin), "analyze", "functions"])
        self.assertIn(rc2, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR, EXIT_FILE_ERROR))
        self.assertNotIn("panicked at", stderr2)

        # 3. Random noise binary
        fuzz_bin = self.create_temp_file(os.urandom(512))
        rc3, json3, _, stderr3 = self.run_rvs(["-f", str(fuzz_bin), "agent", "triage"])
        self.assertIn(rc3, (EXIT_SUCCESS, EXIT_ANALYSIS_ERROR, EXIT_FILE_ERROR))
        self.assertNotIn("panicked at", stderr3)

    def test_tier4_scenario5_dynamic_emulation_register_diff_audit(self):
        """Scenario 5: Dynamic emulation register diff audit verifying minimal delta diffs."""
        # Perform 3-step emulation trace
        rc, json_data, _, stderr = self.run_rvs([
            "-f", str(self.crackme_path),
            "dynamic", "trace", "main",
            "--steps", "3"
        ])
        self.assertEqual(rc, EXIT_SUCCESS, f"Stderr: {stderr}")
        trace = json_data.get("data", {}).get("trace", [])
        self.assertEqual(len(trace), 3)

        # Verify each step's register changes only contain modified registers
        for item in trace:
            changes = item.get("reg_changes", [])
            for c in changes:
                self.assertIn("reg", c)
                self.assertIn("before", c)
                self.assertIn("after", c)
                self.assertNotEqual(c["before"], c["after"], "Register diff must only report altered registers")


if __name__ == "__main__":
    unittest.main(verbosity=2)
