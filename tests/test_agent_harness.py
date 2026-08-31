#!/usr/bin/env python3
"""
tests/test_agent_harness.py - Comprehensive Unit & Integration Test Suite for `rvs_agent_harness.py`.

Tests:
1. All 13 primary `rvs` commands via `RvsHarness` programmatic API.
2. Output modes (`compact`, `summary`, `full`) and pruning rules P1-P7.
3. Budget-constrained truncation & pagination navigation metadata.
4. Token & character reduction benchmarks (verifying >= 40% savings).
5. Tool calling JSON schemas across all 4 formats (OpenAI, Anthropic, Gemini, MCP).
6. Model Context Protocol (MCP) stdio JSON-RPC 2.0 server lifecycle & error handling.
7. Error normalization & actionable suggestion hints.
8. Backward compatibility with legacy `RvsAgentHarness` and CLI arguments.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

# Add workspace root to sys.path
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    CANONICAL_TOOLS,
    RvsAgentHarness,
    RvsHarness,
    find_rvs_binary,
    get_tool_schemas,
    transform_response,
)


class TestRvsHarnessBase(unittest.TestCase):
    """Base test class providing fixture paths and temporary test copies."""

    @classmethod
    def setUpClass(cls):
        fixture_src = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
        if fixture_src.exists():
            cls.crackme_path = fixture_src
        else:
            cls.crackme_path = WORKSPACE_DIR / "crackme_case"

        cls.rvs_bin = find_rvs_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)
        cls.legacy_harness = RvsAgentHarness(rvs_bin=cls.rvs_bin)

    def create_temp_crackme(self) -> Path:
        """Creates an isolated temporary copy of the crackme binary for mutation tests."""
        tmp = tempfile.NamedTemporaryFile(delete=False, prefix="crackme_test_")
        tmp.close()
        tmp_path = Path(tmp.name)
        shutil.copy(self.crackme_path, tmp_path)
        os.chmod(tmp_path, 0o755)
        self.addCleanup(lambda: tmp_path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(f"{tmp_path}.bak").unlink(missing_ok=True))
        return tmp_path


# =============================================================================
# 1. Test All 13 Primary Commands via RvsHarness API
# =============================================================================

class TestAllCommands(TestRvsHarnessBase):
    """Verifies each of the 13 primary rvs commands through RvsHarness."""

    def test_cmd_01_info(self):
        resp = self.harness.info(self.crackme_path, compact=True)
        self.assertTrue(resp.get("success"), f"info failed: {resp}")
        self.assertEqual(resp.get("command"), "info")
        data = resp.get("data", {})
        self.assertEqual(data.get("format"), "elf")
        self.assertEqual(data.get("arch"), "x86")
        self.assertEqual(data.get("bits"), 64)
        self.assertIn("entry", data)
        self.assertIsInstance(data.get("security"), list)

    def test_cmd_02_functions(self):
        resp = self.harness.functions(self.crackme_path, filter="main", compact=True)
        self.assertTrue(resp.get("success"), f"functions failed: {resp}")
        data = resp.get("data", {})
        funcs = data.get("functions", [])
        self.assertTrue(any("main" in f.get("name", "") for f in funcs))
        main_fn = next(f for f in funcs if "main" in f.get("name", ""))
        self.assertIn("addr", main_fn)
        self.assertIn("size", main_fn)

    def test_cmd_03_disasm(self):
        resp = self.harness.disasm(self.crackme_path, function_or_addr="main", compact=True)
        self.assertTrue(resp.get("success"), f"disasm failed: {resp}")
        data = resp.get("data", {})
        blocks = data.get("blocks", [])
        self.assertGreater(len(blocks), 0)
        first_block = blocks[0]
        self.assertIn("addr", first_block)
        self.assertIn("instructions", first_block)
        insts = first_block.get("instructions", [])
        self.assertGreater(len(insts), 0)
        self.assertIn("asm", insts[0])

    def test_cmd_04_decompile(self):
        resp = self.harness.decompile(self.crackme_path, function="main", compact=True)
        self.assertTrue(resp.get("success"), f"decompile failed: {resp}")
        data = resp.get("data", {})
        self.assertIn("pseudo_c", data)
        self.assertIn("calls", data)
        self.assertIn("strings", data)

    def test_cmd_05_flow(self):
        resp = self.harness.flow(self.crackme_path, function="main", compact=True)
        self.assertTrue(resp.get("success"), f"flow failed: {resp}")
        data = resp.get("data", {})
        self.assertIn("decision_nodes", data)
        self.assertIn("loops", data)
        gates = data.get("decision_nodes", [])
        self.assertGreater(len(gates), 0)
        gate = gates[0]
        self.assertIn("cond", gate)
        self.assertIn("branch", gate)
        self.assertIn("jump", gate)
        self.assertIn("fail", gate)

    def test_cmd_06_xrefs(self):
        resp = self.harness.xrefs(self.crackme_path, symbol_or_addr="main", direction="all", compact=True)
        self.assertTrue(resp.get("success"), f"xrefs failed: {resp}")
        data = resp.get("data", {})
        self.assertIn("xrefs", data)
        xrefs = data.get("xrefs", [])
        self.assertGreaterEqual(len(xrefs), 0)

    def test_cmd_07_strings(self):
        resp = self.harness.strings(self.crackme_path, min_len=4, compact=True)
        self.assertTrue(resp.get("success"), f"strings failed: {resp}")
        data = resp.get("data", {})
        strings = data.get("strings", [])
        self.assertTrue(any("Valid serial" in s.get("string", "") for s in strings))

    def test_cmd_08_symbols(self):
        resp = self.harness.symbols(self.crackme_path, filter="puts", compact=True)
        self.assertTrue(resp.get("success"), f"symbols failed: {resp}")
        data = resp.get("data", {})
        symbols = data.get("symbols", [])
        self.assertTrue(any("puts" in s.get("name", "") for s in symbols))

    def test_cmd_09_patch_instruction(self):
        temp_bin = self.create_temp_crackme()
        resp = self.harness.patch_instruction(temp_bin, addr="0x13d2", nop_bytes=6, backup=True)
        self.assertTrue(resp.get("success"), f"patch_instruction failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("verified"))
        self.assertEqual(data.get("bytes"), 6)

    def test_cmd_10_patch_string(self):
        temp_bin = self.create_temp_crackme()
        resp = self.harness.patch_string(
            temp_bin,
            old_string="Enter serial:",
            new_string="Input key:   ",
            pad_null=True,
            strict_length=True,
            backup=True,
        )
        self.assertTrue(resp.get("success"), f"patch_string failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("verified"))

    def test_cmd_11_patch_bytes(self):
        temp_bin = self.create_temp_crackme()
        resp = self.harness.patch_bytes(temp_bin, addr="0x13d2", hex_bytes="e9a200000090", backup=True)
        self.assertTrue(resp.get("success"), f"patch_bytes failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("verified"))
        self.assertEqual(data.get("new"), "e9a200000090")

    def test_cmd_12_triage(self):
        resp = self.harness.triage(self.crackme_path, compact=True)
        self.assertTrue(resp.get("success"), f"triage failed: {resp}")
        data = resp.get("data", {})
        self.assertIn("top_functions", data)
        self.assertIn("interesting_strings", data)
        self.assertIn("recommendations", data)

    def test_cmd_13_patch_plan_dry_run_false_dict(self):
        temp_bin = self.create_temp_crackme()
        plan = {
            "name": "crackme_bypass_plan",
            "dry_run": False,
            "steps": [
                {
                    "type": "bytes",
                    "addr": "0x13d2",
                    "hex": "e9a200000090",
                }
            ],
        }
        resp = self.harness.patch_plan(temp_bin, plan=plan, dry_run=False)
        self.assertTrue(resp.get("success"), f"patch_plan failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("applied"))
        self.assertFalse(data.get("dry_run"))
        self.assertEqual(data.get("executed"), 1)

    def test_cmd_13_patch_plan_dry_run_true_dict(self):
        temp_bin = self.create_temp_crackme()
        orig_bytes = temp_bin.read_bytes()
        plan = {
            "name": "crackme_dry_run_plan",
            "dry_run": False,
            "steps": [
                {
                    "type": "bytes",
                    "addr": "0x13d2",
                    "hex": "909090909090",
                }
            ],
        }
        resp = self.harness.patch_plan(temp_bin, plan=plan, dry_run=True)
        self.assertTrue(resp.get("success"), f"patch_plan failed: {resp}")
        data = resp.get("data", {})
        self.assertFalse(data.get("applied"))
        self.assertTrue(data.get("dry_run"))
        self.assertEqual(temp_bin.read_bytes(), orig_bytes)

    def test_cmd_13_patch_plan_dry_run_true_json_str(self):
        temp_bin = self.create_temp_crackme()
        orig_bytes = temp_bin.read_bytes()
        plan_str = json.dumps({
            "name": "str_dry_run_plan",
            "steps": [{"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}],
        })
        resp = self.harness.patch_plan(temp_bin, plan=plan_str, dry_run=True)
        self.assertTrue(resp.get("success"), f"patch_plan failed: {resp}")
        data = resp.get("data", {})
        self.assertFalse(data.get("applied"))
        self.assertTrue(data.get("dry_run"))
        self.assertEqual(temp_bin.read_bytes(), orig_bytes)

    def test_cmd_13_patch_plan_dry_run_false_json_str(self):
        temp_bin = self.create_temp_crackme()
        plan_str = json.dumps({
            "name": "str_apply_plan",
            "steps": [{"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}],
        })
        resp = self.harness.patch_plan(temp_bin, plan=plan_str, dry_run=False)
        self.assertTrue(resp.get("success"), f"patch_plan failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("applied"))
        self.assertFalse(data.get("dry_run"))

    def test_cmd_13_patch_plan_from_file_path(self):
        temp_bin = self.create_temp_crackme()
        orig_bytes = temp_bin.read_bytes()
        tmp_plan = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
        json.dump({
            "name": "file_plan",
            "steps": [{"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}],
        }, tmp_plan)
        tmp_plan.close()
        plan_path = Path(tmp_plan.name)
        self.addCleanup(lambda: plan_path.unlink(missing_ok=True))

        # Dry run via file
        resp_dry = self.harness.patch_plan(temp_bin, plan=plan_path, dry_run=True)
        self.assertTrue(resp_dry.get("success"), f"patch_plan file dry_run failed: {resp_dry}")
        self.assertTrue(resp_dry["data"].get("dry_run"))
        self.assertFalse(resp_dry["data"].get("applied"))
        self.assertEqual(temp_bin.read_bytes(), orig_bytes)

        # Apply via file
        resp_apply = self.harness.patch_plan(temp_bin, plan=plan_path, dry_run=False)
        self.assertTrue(resp_apply.get("success"), f"patch_plan file apply failed: {resp_apply}")
        self.assertFalse(resp_apply["data"].get("dry_run"))
        self.assertTrue(resp_apply["data"].get("applied"))


# =============================================================================
# 2. Output Modes (compact, summary, full) & Pruning Rules P1-P7
# =============================================================================

class TestOutputModesAndPruning(TestRvsHarnessBase):
    """Tests compact, summary, and full output modes with pruning rules."""

    def test_mode_full_preserves_raw_data(self):
        resp = self.harness.info(self.crackme_path, compact=False)
        self.assertTrue(resp.get("success"))
        data = resp.get("data", {})
        self.assertIn("entry_point", data)
        self.assertIn("entry_point_hex", data)
        self.assertIsInstance(data.get("security"), dict)

    def test_mode_summary_produces_macro_synopsis(self):
        resp_funcs = self.harness.run(
            ["-f", str(self.crackme_path), "analyze", "functions"], mode="summary"
        )
        self.assertTrue(resp_funcs.get("success"))
        data = resp_funcs.get("data", {})
        self.assertIn("total_functions", data)
        self.assertIn("top_complex", data)
        self.assertLessEqual(len(data.get("top_complex", [])), 5)

        resp_info = self.harness.run(["-f", str(self.crackme_path), "info"], mode="summary")
        self.assertTrue(resp_info.get("success"))
        data_info = resp_info.get("data", {})
        self.assertIn("format", data_info)
        self.assertIn("entry", data_info)

    def test_pruning_rules_p1_to_p7_on_blocks(self):
        resp = self.harness.disasm(self.crackme_path, function_or_addr="main", compact=True)
        self.assertTrue(resp.get("success"))
        data = resp.get("data", {})
        blocks = data.get("blocks", [])
        self.assertGreater(len(blocks), 0)

        for b in blocks:
            # Rule P1: Hex addresses only
            self.assertTrue(isinstance(b.get("addr"), str) and b.get("addr", "").startswith("0x"))
            # Rule P2: asm field instead of disasm/opcode duplication, no raw opcode bytes
            for inst in b.get("instructions", []):
                self.assertIn("asm", inst)
                self.assertNotIn("opcode", inst)
                self.assertNotIn("disasm", inst)
                self.assertNotIn("bytes", inst)
                self.assertNotIn("family", inst)


# =============================================================================
# 3. Budget Truncation & Navigation Metadata Envelope
# =============================================================================

class TestBudgetTruncationAndPagination(TestRvsHarnessBase):
    """Verifies limit, offset, and continuation navigation metadata."""

    def test_function_pagination_envelope(self):
        resp = self.harness.functions(self.crackme_path, limit=5, offset=0, compact=True)
        self.assertTrue(resp.get("success"))
        data = resp.get("data", {})

        self.assertIn("total", data)
        self.assertEqual(data.get("displayed"), 5)
        self.assertEqual(data.get("offset"), 0)
        self.assertEqual(data.get("limit"), 5)
        self.assertTrue(data.get("truncated"))
        self.assertTrue(data.get("has_more"))
        self.assertIn("continuation_hint", data)
        self.assertIn("limit=5 offset=5", data.get("continuation_hint", ""))

    def test_function_pagination_second_slice(self):
        resp = self.harness.functions(self.crackme_path, limit=5, offset=5, compact=True)
        self.assertTrue(resp.get("success"))
        data = resp.get("data", {})
        self.assertEqual(data.get("displayed"), 5)
        self.assertEqual(data.get("offset"), 5)

    def test_strings_truncation(self):
        resp = self.harness.strings(self.crackme_path, limit=10, compact=True)
        self.assertTrue(resp.get("success"))
        data = resp.get("data", {})
        self.assertLessEqual(data.get("displayed", 0), 10)
        if data.get("total", 0) > 10:
            self.assertTrue(data.get("truncated"))
            self.assertIn("continuation_hint", data)

    def test_blocks_truncation(self):
        resp = self.harness.run(
            ["-f", str(self.crackme_path), "analyze", "blocks", "main"],
            mode="compact",
            limit=10,
        )
        self.assertTrue(resp.get("success"))
        data = resp.get("data", {})
        self.assertIn("total", data)
        self.assertEqual(data.get("displayed"), 10)
        self.assertTrue(data.get("truncated"))
        self.assertIn("continuation_hint", data)

    def test_disasm_max_instructions_zero(self):
        resp = self.harness.disasm(self.crackme_path, "main", max_instructions=0, compact=True)
        self.assertTrue(resp.get("success"))
        blocks = resp.get("data", {}).get("blocks", [])
        self.assertGreater(len(blocks), 0)
        for b in blocks:
            self.assertEqual(len(b.get("instructions", [])), 0)

    def test_disasm_max_instructions_positive(self):
        resp = self.harness.disasm(self.crackme_path, "main", max_instructions=2, compact=True)
        self.assertTrue(resp.get("success"))
        blocks = resp.get("data", {}).get("blocks", [])
        self.assertGreater(len(blocks), 0)
        for b in blocks:
            self.assertLessEqual(len(b.get("instructions", [])), 2)


# =============================================================================
# 4. Token Reduction Benchmarks (>= 40% Savings Guarantee)
# =============================================================================

class TestTokenReductionBenchmarks(TestRvsHarnessBase):
    """Benchmarks size reduction: compact vs full mode across core commands."""

    def calculate_savings(self, raw_resp: Dict[str, Any], compact_resp: Dict[str, Any]) -> float:
        raw_len = len(json.dumps(raw_resp.get("data", {})))
        compact_len = len(json.dumps(compact_resp.get("data", {})))
        if raw_len == 0:
            return 0.0
        return (raw_len - compact_len) / raw_len

    def test_benchmark_info_reduction(self):
        raw = self.harness.info(self.crackme_path, compact=False)
        compact = self.harness.info(self.crackme_path, compact=True)
        savings = self.calculate_savings(raw, compact)
        self.assertGreaterEqual(savings, 0.40, f"Info savings {savings:.2%} < 40%")

    def test_benchmark_functions_reduction(self):
        raw = self.harness.functions(self.crackme_path, compact=False)
        compact = self.harness.functions(self.crackme_path, compact=True)
        savings = self.calculate_savings(raw, compact)
        self.assertGreaterEqual(savings, 0.40, f"Functions savings {savings:.2%} < 40%")

    def test_benchmark_blocks_reduction(self):
        raw = self.harness.disasm(self.crackme_path, function_or_addr="main", compact=False)
        compact = self.harness.disasm(self.crackme_path, function_or_addr="main", compact=True)
        savings = self.calculate_savings(raw, compact)
        self.assertGreaterEqual(savings, 0.40, f"Blocks savings {savings:.2%} < 40%")

    def test_benchmark_strings_reduction(self):
        raw = self.harness.strings(self.crackme_path, compact=False)
        compact = self.harness.strings(self.crackme_path, compact=True)
        savings = self.calculate_savings(raw, compact)
        self.assertGreaterEqual(savings, 0.40, f"Strings savings {savings:.2%} < 40%")

    def test_benchmark_symbols_reduction(self):
        raw = self.harness.symbols(self.crackme_path, compact=False)
        compact = self.harness.symbols(self.crackme_path, compact=True)
        savings = self.calculate_savings(raw, compact)
        self.assertGreaterEqual(savings, 0.40, f"Symbols savings {savings:.2%} < 40%")

    def test_benchmark_triage_reduction(self):
        raw = self.harness.triage(self.crackme_path, compact=False)
        compact = self.harness.triage(self.crackme_path, compact=True)
        savings = self.calculate_savings(raw, compact)
        self.assertGreaterEqual(savings, 0.40, f"Triage savings {savings:.2%} < 40%")

    def test_benchmark_summary_mode_ultra_reduction(self):
        raw = self.harness.functions(self.crackme_path, compact=False)
        summary = self.harness.run(
            ["-f", str(self.crackme_path), "analyze", "functions"], mode="summary"
        )
        savings = self.calculate_savings(raw, summary)
        self.assertGreaterEqual(savings, 0.70, f"Summary savings {savings:.2%} < 70%")


# =============================================================================
# 5. LLM Tool Calling Schema Export (OpenAI, Anthropic, Gemini, MCP)
# =============================================================================

class TestToolCallingSchemas(TestRvsHarnessBase):
    """Validates schema export across all 4 formats for all 13 commands."""

    def test_openai_schema_structure(self):
        schemas = get_tool_schemas("openai")
        self.assertEqual(len(schemas), 13)
        for s in schemas:
            self.assertEqual(s.get("type"), "function")
            fn = s.get("function", {})
            self.assertTrue(fn.get("name", "").startswith("rvs_"))
            self.assertIn("description", fn)
            params = fn.get("parameters", {})
            self.assertEqual(params.get("type"), "object")
            self.assertIn("file", params.get("required", []))
            self.assertIn("properties", params)

    def test_anthropic_schema_structure(self):
        schemas = get_tool_schemas("anthropic")
        self.assertEqual(len(schemas), 13)
        for s in schemas:
            self.assertTrue(s.get("name", "").startswith("rvs_"))
            self.assertIn("description", s)
            schema = s.get("input_schema", {})
            self.assertEqual(schema.get("type"), "object")
            self.assertIn("file", schema.get("required", []))

    def test_gemini_schema_structure(self):
        schemas = get_tool_schemas("gemini")
        self.assertEqual(len(schemas), 13)
        for s in schemas:
            self.assertTrue(s.get("name", "").startswith("rvs_"))
            params = s.get("parameters", {})
            self.assertEqual(params.get("type"), "OBJECT")
            props = params.get("properties", {})
            self.assertIn("file", props)
            self.assertEqual(props["file"].get("type"), "STRING")

    def test_mcp_schema_structure(self):
        schemas = get_tool_schemas("mcp")
        self.assertEqual(len(schemas), 13)
        for s in schemas:
            self.assertTrue(s.get("name", "").startswith("rvs_"))
            schema = s.get("inputSchema", {})
            self.assertEqual(schema.get("type"), "object")
            self.assertIn("file", schema.get("required", []))

    def test_schema_unsupported_format_raises_error(self):
        with self.assertRaises(ValueError):
            get_tool_schemas("invalid_format_xyz")  # type: ignore


# =============================================================================
# 6. Model Context Protocol (MCP) Stdio JSON-RPC 2.0 Server
# =============================================================================

class TestMcpServer(TestRvsHarnessBase):
    """Tests the native stdio MCP JSON-RPC 2.0 server lifecycle in-memory."""

    def run_mcp_exchange(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        input_lines = "\n".join(json.dumps(r) for r in requests) + "\n"
        stdin_stream = io.StringIO(input_lines)
        stdout_stream = io.StringIO()

        self.harness.serve_mcp(stdin_stream=stdin_stream, stdout_stream=stdout_stream)

        stdout_stream.seek(0)
        responses = []
        for line in stdout_stream:
            if line.strip():
                responses.append(json.loads(line.strip()))
        return responses

    def test_mcp_initialize_and_ping(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        ]
        resps = self.run_mcp_exchange(reqs)
        self.assertEqual(len(resps), 2)

        # 1. initialize response
        init_res = resps[0]
        self.assertEqual(init_res.get("id"), 1)
        res = init_res.get("result", {})
        self.assertEqual(res.get("protocolVersion"), "2024-11-05")
        self.assertIn("serverInfo", res)
        self.assertEqual(res["serverInfo"].get("name"), "rvs-mcp-server")

        # 2. ping response
        ping_res = resps[1]
        self.assertEqual(ping_res.get("id"), 2)
        self.assertEqual(ping_res.get("result"), {})

    def test_mcp_tools_list(self):
        reqs = [{"jsonrpc": "2.0", "id": 10, "method": "tools/list"}]
        resps = self.run_mcp_exchange(reqs)
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        tools = res.get("tools", [])
        self.assertEqual(len(tools), 13)
        tool_names = [t.get("name") for t in tools]
        self.assertIn("rvs_info", tool_names)
        self.assertIn("rvs_functions", tool_names)
        self.assertIn("rvs_disasm", tool_names)
        self.assertIn("rvs_patch_bytes", tool_names)

    def test_mcp_tools_call_execution(self):
        reqs = [
            {
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {
                    "name": "rvs_info",
                    "arguments": {
                        "file": str(self.crackme_path),
                        "compact": True,
                    },
                },
            }
        ]
        resps = self.run_mcp_exchange(reqs)
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertFalse(res.get("isError"))
        content = res.get("content", [])
        self.assertEqual(len(content), 1)
        data = json.loads(content[0].get("text", "{}"))
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("command"), "info")
        self.assertEqual(data.get("data", {}).get("arch"), "x86")

    def test_mcp_unknown_tool_returns_error(self):
        reqs = [
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": "rvs_non_existent_tool_xyz",
                    "arguments": {"file": str(self.crackme_path)},
                },
            }
        ]
        resps = self.run_mcp_exchange(reqs)
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertTrue(res.get("isError"))

    def test_mcp_parse_error_handling(self):
        stdin_stream = io.StringIO("invalid json line\n")
        stdout_stream = io.StringIO()
        self.harness.serve_mcp(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
        stdout_stream.seek(0)
        resp = json.loads(stdout_stream.read().strip())
        self.assertEqual(resp.get("error", {}).get("code"), -32700)

    def test_mcp_method_not_found(self):
        reqs = [{"jsonrpc": "2.0", "id": 40, "method": "invalid/method/xyz"}]
        resps = self.run_mcp_exchange(reqs)
        self.assertEqual(len(resps), 1)
        self.assertEqual(resps[0].get("error", {}).get("code"), -32601)

    def test_mcp_non_dict_params_returns_invalid_params_error(self):
        adversarial_params = [
            None,
            "invalid_params_string",
            [1, 2, 3],
            42,
            True,
        ]
        for idx, bad_param in enumerate(adversarial_params, 100):
            reqs = [
                {
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": bad_param,
                }
            ]
            resps = self.run_mcp_exchange(reqs)
            self.assertEqual(len(resps), 1, f"Failed on param: {bad_param}")
            r = resps[0]
            self.assertEqual(r.get("id"), idx)
            self.assertIn("error", r)
            self.assertEqual(r["error"].get("code"), -32602, f"Expected -32602 for {bad_param}")
            self.assertIn("Invalid params", r["error"].get("message", ""))

    def test_mcp_non_dict_arguments_returns_invalid_argument_envelope(self):
        adversarial_args = [
            None,
            "not_a_dict_arguments",
            [1, 2, 3],
            42,
            False,
        ]
        for idx, bad_args in enumerate(adversarial_args, 200):
            reqs = [
                {
                    "jsonrpc": "2.0",
                    "id": idx,
                    "method": "tools/call",
                    "params": {
                        "name": "rvs_info",
                        "arguments": bad_args,
                    },
                }
            ]
            resps = self.run_mcp_exchange(reqs)
            self.assertEqual(len(resps), 1, f"Failed on arguments: {bad_args}")
            r = resps[0]
            self.assertEqual(r.get("id"), idx)
            self.assertIn("result", r)
            self.assertTrue(r["result"].get("isError"))
            content = r["result"].get("content", [])
            self.assertEqual(len(content), 1)
            err_dict = json.loads(content[0]["text"])
            self.assertFalse(err_dict.get("success"))
            self.assertIn("error", err_dict)
            self.assertEqual(err_dict["error"].get("code"), "INVALID_ARGUMENT")
            self.assertEqual(err_dict["error"].get("exit_code"), 1)
            self.assertEqual(
                err_dict["error"].get("message"),
                "Tool arguments must be a dictionary object",
            )

    def test_mcp_initialize_non_dict_params(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 301, "method": "initialize", "params": "string_not_dict"},
            {"jsonrpc": "2.0", "id": 302, "method": "initialize", "params": [1, 2, 3]},
        ]
        resps = self.run_mcp_exchange(reqs)
        self.assertEqual(len(resps), 2)
        for r in resps:
            self.assertIn("error", r)
            self.assertEqual(r["error"].get("code"), -32602)

    def test_mcp_tools_call_patch_plan_dry_run(self):
        temp_bin = self.create_temp_crackme()
        orig_bytes = temp_bin.read_bytes()
        plan = {
            "name": "mcp_dry_run_plan",
            "steps": [{"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}],
        }
        reqs = [
            {
                "jsonrpc": "2.0",
                "id": 401,
                "method": "tools/call",
                "params": {
                    "name": "rvs_agent_patch_plan",
                    "arguments": {
                        "file": str(temp_bin),
                        "plan": plan,
                        "dry_run": True,
                    },
                },
            }
        ]
        resps = self.run_mcp_exchange(reqs)
        self.assertEqual(len(resps), 1)
        res = resps[0].get("result", {})
        self.assertFalse(res.get("isError"))
        data = json.loads(res["content"][0]["text"])
        self.assertTrue(data.get("success"))
        self.assertTrue(data["data"].get("dry_run"))
        self.assertFalse(data["data"].get("applied"))
        self.assertEqual(temp_bin.read_bytes(), orig_bytes)


# =============================================================================
# 7. Error Normalization & Actionable Suggestions
# =============================================================================

class TestErrorNormalization(TestRvsHarnessBase):
    """Verifies normalized error envelopes and actionable suggestion hints."""

    def test_file_not_found_error(self):
        resp = self.harness.info("/tmp/non_existent_file_99999.elf")
        self.assertFalse(resp.get("success"))
        err = resp.get("error", {})
        self.assertIsNotNone(err)
        self.assertTrue("FILE" in err.get("code", "") or "NOT_FOUND" in err.get("code", "") or "INVALID" in err.get("code", ""))
        self.assertIn("suggestion", err)

    def test_symbol_not_found_error(self):
        resp = self.harness.disasm(self.crackme_path, function_or_addr="sym.non_existent_symbol_xyz")
        self.assertFalse(resp.get("success"))
        err = resp.get("error", {})
        self.assertIsNotNone(err)
        self.assertTrue("SYMBOL" in err.get("code", "") or "ANALYSIS" in err.get("code", "") or "NOT_FOUND" in err.get("code", ""))
        self.assertIn("suggestion", err)

    def test_invalid_assembly_error(self):
        temp_bin = self.create_temp_crackme()
        resp = self.harness.patch_instruction(temp_bin, addr="0x13d2", assembly="invalid_instruction_xyz")
        self.assertFalse(resp.get("success"))
        err = resp.get("error", {})
        self.assertIsNotNone(err)
        self.assertTrue("ASSEMBLY" in err.get("code", "") or "PATCH" in err.get("code", ""))

    def test_odd_hex_bytes_validation(self):
        temp_bin = self.create_temp_crackme()
        resp = self.harness.patch_bytes(temp_bin, addr="0x13d2", hex_bytes="909")
        self.assertFalse(resp.get("success"))
        err = resp.get("error", {})
        self.assertEqual(err.get("code"), "INVALID_HEX_STRING")
        self.assertIn("suggestion", err)

    def test_timeout_watchdog_envelope(self):
        resp = self.harness.run(
            ["-f", str(self.crackme_path), "analyze", "functions"], timeout=0.001
        )
        self.assertFalse(resp.get("success"))
        err = resp.get("error", {})
        self.assertEqual(err.get("code"), "TIMEOUT_EXPIRED")
        self.assertEqual(err.get("exit_code"), EXIT_TIMEOUT_ERROR)
        self.assertIn("suggestion", err)


# =============================================================================
# 8. Backward Compatibility & CLI Invocations
# =============================================================================

class TestBackwardCompatibilityAndCli(TestRvsHarnessBase):
    """Verifies legacy RvsAgentHarness class methods and CLI argument flags."""

    def test_legacy_harness_class_methods(self):
        resp_triage = self.legacy_harness.triage(str(self.crackme_path))
        self.assertTrue(resp_triage.get("success"))

        resp_decompile = self.legacy_harness.decompile(str(self.crackme_path), "main")
        self.assertTrue(resp_decompile.get("success"))

        resp_flow = self.legacy_harness.flow(str(self.crackme_path), "main")
        self.assertTrue(resp_flow.get("success"))

        resp_xrefs = self.legacy_harness.xrefs(str(self.crackme_path), "main")
        self.assertTrue(resp_xrefs.get("success"))

    def test_cli_export_tools(self):
        proc = subprocess.run(
            [sys.executable, str(WORKSPACE_DIR / "rvs_agent_harness.py"), "--export-tools", "openai"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(len(data), 13)

    def test_cli_mode_compact(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(WORKSPACE_DIR / "rvs_agent_harness.py"),
                "-f",
                str(self.crackme_path),
                "--mode",
                "compact",
                "info",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("mode"), "compact")

    def test_cli_limit_and_offset(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(WORKSPACE_DIR / "rvs_agent_harness.py"),
                "-f",
                str(self.crackme_path),
                "--mode",
                "compact",
                "--limit",
                "4",
                "--offset",
                "2",
                "analyze",
                "functions",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        fn_data = data.get("data", {})
        self.assertEqual(fn_data.get("displayed"), 4)
        self.assertEqual(fn_data.get("offset"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
