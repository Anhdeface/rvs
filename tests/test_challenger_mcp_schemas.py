#!/usr/bin/env python3
"""
tests/test_challenger_mcp_schemas.py - Challenger 2 Empirical & Adversarial Stress Suite.

Comprehensive validation of:
1. MCP Stdio Protocol & JSON-RPC 2.0 Lifecycle & Error Resilience.
2. Universal Tool Schemas across OpenAI, Anthropic, Gemini, MCP formats for all 13 canonical commands.
3. Python API RvsHarness direct execution, patch execution, and dry-run simulation.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    CANONICAL_TOOLS,
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    RvsAgentHarness,
    RvsHarness,
    find_rvs_binary,
    get_tool_schemas,
    sanitize_terminal_output,
    transform_response,
)


class TestChallengerBase(unittest.TestCase):
    """Base fixture setup for Challenger 2 tests."""

    @classmethod
    def setUpClass(cls):
        cls.crackme_path = WORKSPACE_DIR / "crackme_case"
        if not cls.crackme_path.exists():
            fixture_src = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
            if fixture_src.exists():
                shutil.copy(fixture_src, cls.crackme_path)
                os.chmod(cls.crackme_path, 0o755)

        cls.rvs_bin = find_rvs_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)
        cls.harness_script = WORKSPACE_DIR / "rvs_agent_harness.py"

    def create_temp_crackme(self) -> Path:
        """Create a disposable temporary binary for mutation tests."""
        tmp = tempfile.NamedTemporaryFile(delete=False, prefix="challenger_crackme_")
        tmp.close()
        tmp_path = Path(tmp.name)
        shutil.copy(self.crackme_path, tmp_path)
        os.chmod(tmp_path, 0o755)
        self.addCleanup(lambda: tmp_path.unlink(missing_ok=True))
        self.addCleanup(lambda: Path(f"{tmp_path}.bak").unlink(missing_ok=True))
        return tmp_path


# =============================================================================
# PART 1: MCP Stdio Protocol & JSON-RPC 2.0 Compliance (Valid & Adversarial)
# =============================================================================

class TestMcpProtocolAndJsonRpc(TestChallengerBase):
    """Deep adversarial testing of MCP Stdio protocol and JSON-RPC 2.0 conformance."""

    def run_in_memory_mcp(self, raw_input: str) -> List[Dict[str, Any]]:
        stdin_stream = io.StringIO(raw_input)
        stdout_stream = io.StringIO()
        self.harness.serve_mcp(stdin_stream=stdin_stream, stdout_stream=stdout_stream)
        stdout_stream.seek(0)
        responses = []
        for line in stdout_stream:
            line_s = line.strip()
            if line_s:
                responses.append(json.loads(line_s))
        return responses

    def run_subprocess_mcp(self, raw_input: str, timeout: float = 5.0) -> List[Dict[str, Any]]:
        proc = subprocess.Popen(
            [sys.executable, str(self.harness_script), "--mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(input=raw_input, timeout=timeout)
        responses = []
        for line in stdout.splitlines():
            line_s = line.strip()
            if line_s:
                responses.append(json.loads(line_s))
        return responses

    def test_01_valid_mcp_lifecycle_in_memory(self):
        """Test full MCP lifecycle: initialize -> notification -> ping -> tools/list -> tools/call."""
        reqs = [
            # 1. Initialize
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
            # 2. Initialized notification (no id => no response line)
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            # 3. Ping
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            # 4. Tools list
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
            # 5. Tools call
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "rvs_info",
                    "arguments": {"file": str(self.crackme_path), "compact": True},
                },
            },
        ]
        raw = "\n".join(json.dumps(r) for r in reqs) + "\n"
        resps = self.run_in_memory_mcp(raw)

        # There should be exactly 4 responses because notification has no id and produces no response
        self.assertEqual(len(resps), 4)

        # Resp 1: initialize
        r1 = resps[0]
        self.assertEqual(r1.get("jsonrpc"), "2.0")
        self.assertEqual(r1.get("id"), 1)
        self.assertIn("result", r1)
        self.assertEqual(r1["result"].get("protocolVersion"), "2024-11-05")
        self.assertEqual(r1["result"]["serverInfo"].get("name"), "rvs-mcp-server")

        # Resp 2: ping
        r2 = resps[1]
        self.assertEqual(r2.get("jsonrpc"), "2.0")
        self.assertEqual(r2.get("id"), 2)
        self.assertEqual(r2.get("result"), {})

        # Resp 3: tools/list
        r3 = resps[2]
        self.assertEqual(r3.get("jsonrpc"), "2.0")
        self.assertEqual(r3.get("id"), 3)
        tools = r3["result"].get("tools", [])
        self.assertEqual(len(tools), 13)

        # Resp 4: tools/call
        r4 = resps[3]
        self.assertEqual(r4.get("jsonrpc"), "2.0")
        self.assertEqual(r4.get("id"), 4)
        self.assertFalse(r4["result"].get("isError"))
        content = r4["result"].get("content", [])
        self.assertEqual(len(content), 1)
        inner = json.loads(content[0]["text"])
        self.assertTrue(inner.get("success"))
        self.assertEqual(inner.get("command"), "info")

    def test_02_valid_mcp_lifecycle_subprocess_stdio(self):
        """Test full MCP lifecycle over actual subprocess stdio pipes."""
        reqs = [
            {"jsonrpc": "2.0", "id": "req-1", "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": "req-2", "method": "ping"},
            {"jsonrpc": "2.0", "id": "req-3", "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": "req-4",
                "method": "tools/call",
                "params": {
                    "name": "rvs_agent_triage",
                    "arguments": {"file": str(self.crackme_path)},
                },
            },
        ]
        raw = "\n".join(json.dumps(r) for r in reqs) + "\n"
        resps = self.run_subprocess_mcp(raw)
        self.assertEqual(len(resps), 4)
        self.assertEqual(resps[0]["id"], "req-1")
        self.assertEqual(resps[1]["id"], "req-2")
        self.assertEqual(resps[2]["id"], "req-3")
        self.assertEqual(resps[3]["id"], "req-4")
        triage_data = json.loads(resps[3]["result"]["content"][0]["text"])
        self.assertTrue(triage_data.get("success"))

    def test_03_jsonrpc_parse_error_32700(self):
        """Assert -32700 Parse error on invalid JSON strings."""
        invalid_json_inputs = [
            "{ bad json",
            "not a json line",
            '{"jsonrpc": "2.0", "method": "ping", id: 1}',
            "[{unterminated array",
        ]
        for bad_input in invalid_json_inputs:
            resps = self.run_in_memory_mcp(bad_input + "\n")
            self.assertEqual(len(resps), 1, f"Failed on input: {bad_input}")
            r = resps[0]
            self.assertEqual(r.get("jsonrpc"), "2.0")
            self.assertIsNone(r.get("id"))
            self.assertIn("error", r)
            self.assertEqual(r["error"].get("code"), -32700, f"Expected -32700 for {bad_input}")

    def test_04_jsonrpc_invalid_request_32600(self):
        """Assert -32600 Invalid Request on malformed JSON-RPC objects."""
        invalid_requests = [
            {"id": 1, "method": "ping"},  # Missing "jsonrpc": "2.0"
            {"jsonrpc": "1.0", "id": 2, "method": "ping"},  # Invalid jsonrpc version
            {"jsonrpc": "3.0", "id": 3, "method": "ping"},  # Invalid jsonrpc version
            "hello string json",  # Top level is string not dict
            12345,  # Top level is integer not dict
            [1, 2, 3],  # Top level is list not dict
        ]
        for bad_req in invalid_requests:
            raw = json.dumps(bad_req) + "\n"
            resps = self.run_in_memory_mcp(raw)
            self.assertEqual(len(resps), 1, f"Failed on: {bad_req}")
            r = resps[0]
            self.assertEqual(r.get("jsonrpc"), "2.0")
            self.assertIn("error", r)
            self.assertEqual(r["error"].get("code"), -32600, f"Expected -32600 for {bad_req}")

    def test_05_jsonrpc_method_not_found_32601(self):
        """Assert -32601 Method not found on unrecognized method names."""
        unknown_methods = [
            "unknown/method",
            "tools/delete",
            "resources/list",
            "prompts/get",
            "custom_method_xyz",
        ]
        for idx, m in enumerate(unknown_methods, 100):
            req = {"jsonrpc": "2.0", "id": idx, "method": m}
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1)
            r = resps[0]
            self.assertEqual(r.get("id"), idx)
            self.assertIn("error", r)
            self.assertEqual(r["error"].get("code"), -32601, f"Expected -32601 for {m}")

    def test_06_mcp_tool_execution_errors_iserror_envelope(self):
        """Test MCP tool call failures return isError: true and structured error envelope."""
        test_cases = [
            # Unknown tool name
            (
                {"name": "rvs_nonexistent_tool", "arguments": {"file": str(self.crackme_path)}},
                "TOOL_NOT_FOUND",
            ),
            # Missing required 'file' argument
            (
                {"name": "rvs_info", "arguments": {}},
                "INVALID_ARGUMENT",
            ),
            # Non-existent target binary file
            (
                {"name": "rvs_info", "arguments": {"file": "/path/to/definitely/nonexistent_file_999.elf"}},
                "FILE",
            ),
            # Missing 'target' in disasm
            (
                {"name": "rvs_disasm", "arguments": {"file": str(self.crackme_path)}},
                "INVALID_ARGUMENT",
            ),
            # Missing 'function' in decompile
            (
                {"name": "rvs_decompile", "arguments": {"file": str(self.crackme_path)}},
                "INVALID_ARGUMENT",
            ),
            # Missing 'function' in flow
            (
                {"name": "rvs_flow", "arguments": {"file": str(self.crackme_path)}},
                "INVALID_ARGUMENT",
            ),
            # Missing 'target' in xrefs
            (
                {"name": "rvs_xrefs", "arguments": {"file": str(self.crackme_path)}},
                "INVALID_ARGUMENT",
            ),
            # Missing 'addr' in patch_instruction
            (
                {"name": "rvs_patch_instruction", "arguments": {"file": str(self.crackme_path)}},
                "INVALID_ARGUMENT",
            ),
            # Missing 'new_string' in patch_string
            (
                {"name": "rvs_patch_string", "arguments": {"file": str(self.crackme_path)}},
                "INVALID_ARGUMENT",
            ),
            # Missing 'hex_bytes' in patch_bytes
            (
                {"name": "rvs_patch_bytes", "arguments": {"file": str(self.crackme_path), "addr": "0x13d2"}},
                "INVALID_ARGUMENT",
            ),
            # Missing 'plan' in patch_plan
            (
                {"name": "rvs_agent_patch_plan", "arguments": {"file": str(self.crackme_path)}},
                "INVALID_ARGUMENT",
            ),
        ]

        for i, (params, expected_err_fragment) in enumerate(test_cases, 200):
            req = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": params,
            }
            resps = self.run_in_memory_mcp(json.dumps(req) + "\n")
            self.assertEqual(len(resps), 1, f"Failed on case {i}")
            r = resps[0]
            self.assertEqual(r.get("id"), i)
            self.assertIn("result", r)
            self.assertTrue(r["result"].get("isError"), f"Expected isError: true for {params}")
            content = r["result"].get("content", [])
            self.assertEqual(len(content), 1)
            err_dict = json.loads(content[0]["text"])
            self.assertFalse(err_dict.get("success"))
            self.assertIn("error", err_dict)
            code = err_dict["error"].get("code", "")
            self.assertTrue(
                expected_err_fragment in code or expected_err_fragment in err_dict["error"].get("message", ""),
                f"Expected {expected_err_fragment} in {err_dict}",
            )


# =============================================================================
# PART 2: Universal Tool Schema Validation (OpenAI, Anthropic, Gemini, MCP)
# =============================================================================

class TestUniversalToolSchemas(TestChallengerBase):
    """Exhaustive validation of all 13 canonical tool schemas across 4 formats."""

    EXPECTED_13_TOOLS = [
        "rvs_info",
        "rvs_functions",
        "rvs_disasm",
        "rvs_decompile",
        "rvs_flow",
        "rvs_xrefs",
        "rvs_strings",
        "rvs_symbols",
        "rvs_patch_instruction",
        "rvs_patch_string",
        "rvs_patch_bytes",
        "rvs_agent_triage",
        "rvs_agent_patch_plan",
    ]

    def test_01_canonical_tools_count_and_completeness(self):
        """Verify CANONICAL_TOOLS contains all 13 expected tools with valid definitions."""
        self.assertEqual(len(CANONICAL_TOOLS), 13)
        tool_names = [t["name"] for t in CANONICAL_TOOLS]
        self.assertEqual(tool_names, self.EXPECTED_13_TOOLS)

        for t in CANONICAL_TOOLS:
            self.assertIn("name", t)
            self.assertIn("description", t)
            self.assertIn("properties", t)
            self.assertIn("required", t)
            self.assertIsInstance(t["properties"], dict)
            self.assertIsInstance(t["required"], list)
            self.assertIn("file", t["required"])
            self.assertIn("file", t["properties"])

    def test_02_openai_schema_compliance(self):
        """Verify OpenAI function calling schema specifications."""
        schemas = get_tool_schemas("openai")
        self.assertEqual(len(schemas), 13)
        for s in schemas:
            self.assertEqual(s.get("type"), "function")
            fn = s.get("function")
            self.assertIsInstance(fn, dict)
            self.assertIn(fn.get("name"), self.EXPECTED_13_TOOLS)
            self.assertIsInstance(fn.get("description"), str)
            self.assertGreater(len(fn.get("description", "")), 10)
            params = fn.get("parameters")
            self.assertIsInstance(params, dict)
            self.assertEqual(params.get("type"), "object")
            self.assertIsInstance(params.get("properties"), dict)
            self.assertIn("file", params.get("required", []))
            self.assertEqual(params.get("additionalProperties"), False)

    def test_03_anthropic_schema_compliance(self):
        """Verify Anthropic tool calling schema specifications."""
        schemas = get_tool_schemas("anthropic")
        self.assertEqual(len(schemas), 13)
        for s in schemas:
            self.assertIn(s.get("name"), self.EXPECTED_13_TOOLS)
            self.assertIsInstance(s.get("description"), str)
            self.assertGreater(len(s.get("description", "")), 10)
            input_schema = s.get("input_schema")
            self.assertIsInstance(input_schema, dict)
            self.assertEqual(input_schema.get("type"), "object")
            self.assertIsInstance(input_schema.get("properties"), dict)
            self.assertIn("file", input_schema.get("required", []))
            self.assertEqual(input_schema.get("additionalProperties"), False)

    def test_04_gemini_schema_compliance(self):
        """Verify Gemini function declaration schema with uppercase types."""
        schemas = get_tool_schemas("gemini")
        self.assertEqual(len(schemas), 13)
        valid_gemini_types = {"STRING", "INTEGER", "NUMBER", "BOOLEAN", "OBJECT", "ARRAY"}
        for s in schemas:
            self.assertIn(s.get("name"), self.EXPECTED_13_TOOLS)
            self.assertIsInstance(s.get("description"), str)
            params = s.get("parameters")
            self.assertIsInstance(params, dict)
            self.assertEqual(params.get("type"), "OBJECT")
            props = params.get("properties", {})
            self.assertIn("file", props)
            for prop_name, prop_val in props.items():
                p_type = prop_val.get("type")
                self.assertIn(p_type, valid_gemini_types, f"Invalid Gemini type {p_type} for {prop_name}")
                if p_type == "OBJECT" and "properties" in prop_val:
                    for sub_k, sub_v in prop_val["properties"].items():
                        self.assertIn(sub_v.get("type"), valid_gemini_types)

    def test_05_mcp_schema_compliance(self):
        """Verify MCP tool schema specifications."""
        schemas = get_tool_schemas("mcp")
        self.assertEqual(len(schemas), 13)
        for s in schemas:
            self.assertIn(s.get("name"), self.EXPECTED_13_TOOLS)
            self.assertIsInstance(s.get("description"), str)
            schema = s.get("inputSchema")
            self.assertIsInstance(schema, dict)
            self.assertEqual(schema.get("type"), "object")
            self.assertIsInstance(schema.get("properties"), dict)
            self.assertIn("file", schema.get("required", []))

    def test_06_tool_schema_json_serializability(self):
        """Verify all exported schemas are strictly valid JSON without functions/custom objects."""
        for fmt in ("openai", "anthropic", "gemini", "mcp"):
            schemas = get_tool_schemas(fmt)  # type: ignore
            dumped = json.dumps(schemas)
            loaded = json.loads(dumped)
            self.assertEqual(len(loaded), 13)


# =============================================================================
# PART 3: Python API Stress Testing (RvsHarness across 13 commands & dry-run)
# =============================================================================

class TestPythonApiStress(TestChallengerBase):
    """Direct execution and stress-testing of RvsHarness API methods."""

    def test_01_all_13_commands_direct_execution(self):
        """Execute all 13 commands directly and verify ApiResponse envelope structure."""
        temp_bin = self.create_temp_crackme()

        # 1. info
        r1 = self.harness.info(temp_bin, compact=True)
        self.assertTrue(r1.get("success"), f"info failed: {r1}")
        self.assertIn("entry", r1["data"])

        # 2. functions
        r2 = self.harness.functions(temp_bin, limit=10, compact=True)
        self.assertTrue(r2.get("success"), f"functions failed: {r2}")
        self.assertIn("functions", r2["data"])

        # 3. disasm
        r3 = self.harness.disasm(temp_bin, function_or_addr="main", compact=True)
        self.assertTrue(r3.get("success"), f"disasm failed: {r3}")
        self.assertIn("blocks", r3["data"])

        # 4. decompile
        r4 = self.harness.decompile(temp_bin, function="main", compact=True)
        self.assertTrue(r4.get("success"), f"decompile failed: {r4}")
        self.assertIn("pseudo_c", r4["data"])

        # 5. flow
        r5 = self.harness.flow(temp_bin, function="main", compact=True)
        self.assertTrue(r5.get("success"), f"flow failed: {r5}")
        self.assertIn("decision_nodes", r5["data"])

        # 6. xrefs
        r6 = self.harness.xrefs(temp_bin, symbol_or_addr="main", compact=True)
        self.assertTrue(r6.get("success"), f"xrefs failed: {r6}")

        # 7. strings
        r7 = self.harness.strings(temp_bin, min_len=4, compact=True)
        self.assertTrue(r7.get("success"), f"strings failed: {r7}")
        self.assertIn("strings", r7["data"])

        # 8. symbols
        r8 = self.harness.symbols(temp_bin, compact=True)
        self.assertTrue(r8.get("success"), f"symbols failed: {r8}")
        self.assertIn("symbols", r8["data"])

        # 9. patch_instruction (NOP sled)
        r9 = self.harness.patch_instruction(temp_bin, addr="0x13d2", nop_bytes=6, backup=True)
        self.assertTrue(r9.get("success"), f"patch_instruction failed: {r9}")
        self.assertTrue(r9["data"].get("verified"))

        # 10. patch_string
        r10 = self.harness.patch_string(
            temp_bin,
            old_string="Enter serial:",
            new_string="Passcode?   :",
            pad_null=True,
            backup=True,
        )
        self.assertTrue(r10.get("success"), f"patch_string failed: {r10}")
        self.assertTrue(r10["data"].get("verified"))

        # 11. patch_bytes
        r11 = self.harness.patch_bytes(temp_bin, addr="0x13d2", hex_bytes="e9a200000090", backup=True)
        self.assertTrue(r11.get("success"), f"patch_bytes failed: {r11}")
        self.assertTrue(r11["data"].get("verified"))

        # 12. triage
        r12 = self.harness.triage(temp_bin, compact=True)
        self.assertTrue(r12.get("success"), f"triage failed: {r12}")
        self.assertIn("top_functions", r12["data"])

        # 13. patch_plan (applied execution)
        plan = {
            "name": "challenger_multi_patch",
            "dry_run": False,
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "909090909090"}
            ],
        }
        r13 = self.harness.patch_plan(temp_bin, plan=plan, dry_run=False)
        self.assertTrue(r13.get("success"), f"patch_plan failed: {r13}")
        self.assertTrue(r13["data"].get("applied"))

    def test_02_patch_plan_dry_run_flag_defect_investigation(self):
        """
        Verify that patch_plan with dry_run=True embeds dry_run into plan JSON and executes simulation cleanly.
        """
        temp_bin = self.create_temp_crackme()
        orig_bytes = temp_bin.read_bytes()
        plan = {
            "name": "dry_run_test_plan",
            "dry_run": True,
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "e9a200000090"}
            ],
        }
        resp = self.harness.patch_plan(temp_bin, plan=plan, dry_run=True)
        self.assertTrue(resp.get("success"), f"patch_plan with dry_run=True failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("dry_run"))
        self.assertFalse(data.get("applied"))
        self.assertEqual(temp_bin.read_bytes(), orig_bytes)

    def test_03_patch_plan_dry_run_via_json_payload_success(self):
        """
        Demonstrates that when dry_run=False (default) is passed to python method,
        and 'dry_run: true' is embedded in the plan payload, the rvs binary engine works properly.
        """
        temp_bin = self.create_temp_crackme()
        orig_bytes = temp_bin.read_bytes()

        plan = {
            "name": "dry_run_json_embedded",
            "dry_run": True,
            "steps": [
                {"type": "bytes", "addr": "0x13d2", "hex": "e9a200000090"}
            ],
        }
        resp = self.harness.patch_plan(temp_bin, plan=plan, dry_run=False)
        self.assertTrue(resp.get("success"), f"patch_plan failed: {resp}")
        data = resp.get("data", {})
        self.assertTrue(data.get("dry_run"))
        self.assertFalse(data.get("applied"))

        # Binary is unchanged
        self.assertEqual(orig_bytes, temp_bin.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
