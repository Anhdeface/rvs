#!/usr/bin/env python3
"""
tests/test_challenger_m4_skill_sync.py - Empirical Challenger 2 Verification Suite.

Comprehensive validation of:
1. Tool synchronization: 100% parity between CANONICAL_TOOLS (rvs_agent_harness.py) and SKILL.md.
2. Parameter signatures: exact parameter names, data types, and required/optional status.
3. Global vs local skill parity: SKILL.md vs ~/.gemini/config/skills/rvs/SKILL.md.
4. Phase partitions, enum invariants, exit codes 0-6, and token conservation directives.
5. Crackme recipes: validity of documented tool calls and parameter bindings.
6. Adversarial oracle tests proving sensitivity to schema and documentation drift.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Set

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness as h

LOCAL_SKILL_PATH = WORKSPACE_DIR / "SKILL.md"
GLOBAL_SKILL_PATH = Path("/home/quanh/.gemini/config/skills/rvs/SKILL.md")


def extract_skill_tools(content: str) -> Dict[str, Dict[str, Any]]:
    """
    Parse SKILL.md and extract structured tool specifications:
    returns { tool_name: { 'body': str, 'params': { param_name: {'type': str, 'required': bool, 'desc': str} } } }
    """
    tool_pattern = r"#### `(rvs_[a-z0-9_]+)`\s*\n(.*?)(?=\n#### `|\n---|\n## |\Z)"
    matches = list(re.finditer(tool_pattern, content, re.DOTALL))
    tools: Dict[str, Dict[str, Any]] = {}

    param_pattern = re.compile(
        r"-\s*`([a-z0-9_]+)`\s*\(`?([a-zA-Z0-9_]+)`?,\s*(\*\*required\*\*|optional)\):\s*(.*)"
    )

    for m in matches:
        tool_name = m.group(1)
        tool_body = m.group(2)
        params: Dict[str, Dict[str, Any]] = {}

        params_section = re.search(
            r"\*\*Parameters:\*\*\s*\n(.*?)(?=\n#### |\n---|\n## |\Z)",
            tool_body,
            re.DOTALL,
        )
        if params_section:
            for line in params_section.group(1).strip().splitlines():
                line = line.strip()
                pmatch = param_pattern.match(line)
                if pmatch:
                    p_name, p_type, p_req, p_desc = pmatch.groups()
                    params[p_name] = {
                        "type": p_type.lower(),
                        "required": (p_req == "**required**"),
                        "description": p_desc.strip(),
                    }

        tools[tool_name] = {
            "body": tool_body,
            "params": params,
        }

    return tools


class TestSkillToolSynchronization(unittest.TestCase):
    """Empirical verification of tool documentation synchronization against CANONICAL_TOOLS."""

    @classmethod
    def setUpClass(cls):
        cls.assertTrue(LOCAL_SKILL_PATH.exists(), f"Local SKILL.md not found at {LOCAL_SKILL_PATH}")
        cls.assertTrue(GLOBAL_SKILL_PATH.exists(), f"Global SKILL.md not found at {GLOBAL_SKILL_PATH}")
        cls.local_content = LOCAL_SKILL_PATH.read_text(encoding="utf-8")
        cls.global_content = GLOBAL_SKILL_PATH.read_text(encoding="utf-8")
        cls.canonical_by_name = {t["name"]: t for t in h.CANONICAL_TOOLS}
        cls.doc_tools = extract_skill_tools(cls.local_content)

    def test_01_skill_md_local_vs_global_byte_exact_match(self):
        """Verify SKILL.md and ~/.gemini/config/skills/rvs/SKILL.md are 100% identical."""
        local_hash = hashlib.sha256(self.local_content.encode("utf-8")).hexdigest()
        global_hash = hashlib.sha256(self.global_content.encode("utf-8")).hexdigest()
        self.assertEqual(
            local_hash,
            global_hash,
            "SHA-256 mismatch between local SKILL.md and global config skill",
        )
        self.assertEqual(
            self.local_content,
            self.global_content,
            "Byte content mismatch between local SKILL.md and global config skill",
        )

    def test_02_all_44_canonical_tools_documented(self):
        """Verify all 44 canonical tools are documented in SKILL.md with no omissions or phantom tools."""
        self.assertEqual(len(h.CANONICAL_TOOLS), 44, "CANONICAL_TOOLS count must be exactly 44")
        self.assertEqual(len(self.doc_tools), 44, "SKILL.md documented tools count must be exactly 44")

        canonical_names = set(self.canonical_by_name.keys())
        documented_names = set(self.doc_tools.keys())

        missing_in_doc = canonical_names - documented_names
        extra_in_doc = documented_names - canonical_names

        self.assertEqual(missing_in_doc, set(), f"Tools missing in SKILL.md: {missing_in_doc}")
        self.assertEqual(extra_in_doc, set(), f"Extraneous tools in SKILL.md: {extra_in_doc}")

    def test_03_parameter_names_types_and_required_flags_match_exactly(self):
        """
        Verify that for every canonical tool, each parameter name, data type,
        and required/optional flag in SKILL.md matches CANONICAL_TOOLS 1:1.
        """
        discrepancies: List[str] = []

        for name, c_tool in self.canonical_by_name.items():
            doc_tool = self.doc_tools[name]
            doc_params = doc_tool["params"]
            c_props = c_tool.get("properties", {})
            c_req = set(c_tool.get("required", []))

            # Check for parameters missing in documentation
            for p_name, p_def in c_props.items():
                if p_name not in doc_params:
                    discrepancies.append(f"[{name}] Parameter '{p_name}' defined in schema but missing in SKILL.md")
                    continue

                d_param = doc_params[p_name]
                c_type = p_def.get("type", "").lower()
                d_type = d_param["type"]

                # Type match
                if c_type != d_type:
                    discrepancies.append(
                        f"[{name}.{p_name}] Type mismatch: schema '{c_type}' vs doc '{d_type}'"
                    )

                # Required match
                c_is_req = p_name in c_req
                d_is_req = d_param["required"]
                if c_is_req != d_is_req:
                    discrepancies.append(
                        f"[{name}.{p_name}] Required mismatch: schema={c_is_req} vs doc={d_is_req}"
                    )

            # Check for undocumented / phantom parameters in documentation
            for p_name in doc_params:
                if p_name not in c_props:
                    discrepancies.append(f"[{name}] Parameter '{p_name}' in SKILL.md but not in schema")

        self.assertEqual(discrepancies, [], f"Parameter discrepancies found:\n" + "\n".join(discrepancies))

    def test_04_enum_values_documented(self):
        """Verify that all enum/allowed parameter values defined in schema are explicitly mentioned in SKILL.md."""
        for name, c_tool in self.canonical_by_name.items():
            doc_body = self.doc_tools[name]["body"]
            for p_name, p_def in c_tool.get("properties", {}).items():
                if "enum" in p_def:
                    allowed_values = p_def["enum"]
                    for val in allowed_values:
                        self.assertIn(
                            str(val),
                            doc_body,
                            f"Tool {name}.{p_name} enum value '{val}' not found in SKILL.md documentation",
                        )

    def test_05_six_phase_catalog_partition(self):
        """Verify that all 44 tools are cleanly partitioned into 6 phases in the MCP Catalog in SKILL.md without overlap."""
        phases = {
            "Phase 1: Static Reconnaissance & Triage": 9,
            "Phase 2: Dynamic Emulation & ESIL Tracing": 3,
            "Phase 3: Interactive Dynamic Debugging": 9,
            "Phase 4: Live Runtime Instrumentation via Frida": 15,
            "Phase 5: High-Level Composite": 4,
            "Phase 6: Binary Patching & Verification": 4,
        }

        # Extract only the catalog section: from "## 🛠️ Complete 44-Tool Canonical MCP Catalog" to next major section
        catalog_match = re.search(
            r"## 🛠️ Complete 44-Tool Canonical MCP Catalog\s*\n(.*?)(?=\n## 💡 |\Z)",
            self.local_content,
            re.DOTALL,
        )
        self.assertIsNotNone(catalog_match, "Catalog section header not found in SKILL.md")
        catalog_text = catalog_match.group(1)

        # Find the tools under each phase section within the catalog
        phase_pattern = r"### (Phase [1-6]: [^\n]+)\n(.*?)(?=\n### Phase |\Z)"
        phase_matches = list(re.finditer(phase_pattern, catalog_text, re.DOTALL))
        self.assertEqual(len(phase_matches), 6, "Must have exactly 6 phase headers in catalog section")

        all_phase_tools: Set[str] = set()
        for pm in phase_matches:
            phase_title = pm.group(1).strip()
            phase_text = pm.group(2)
            matched_key = next((k for k in phases if k in phase_title), None)
            self.assertIsNotNone(matched_key, f"Unrecognized phase header: {phase_title}")
            expected_count = phases[matched_key]

            # Find tools in this section
            t_in_phase = re.findall(r"#### `(rvs_[a-z0-9_]+)`", phase_text)
            self.assertEqual(
                len(t_in_phase),
                expected_count,
                f"Phase '{phase_title}' expected {expected_count} tools, found {len(t_in_phase)}: {t_in_phase}",
            )
            for t in t_in_phase:
                self.assertNotIn(t, all_phase_tools, f"Tool {t} duplicated across phases in SKILL.md")
                all_phase_tools.add(t)

        self.assertEqual(len(all_phase_tools), 44, "Total tools across all 6 phases must equal 44")

    def test_06_standardized_exit_codes_parity(self):
        """Verify all 7 exit codes (0-6) in SKILL.md match harness constants."""
        expected_codes = {
            0: ("SUCCESS", h.EXIT_SUCCESS),
            1: ("INVALID_ARGUMENT", h.EXIT_INVALID_ARGUMENT),
            2: ("FILE_ERROR", h.EXIT_FILE_ERROR),
            3: ("ANALYSIS_ERROR", h.EXIT_ANALYSIS_ERROR),
            4: ("PATCH_ERROR", h.EXIT_PATCH_ERROR),
            5: ("TIMEOUT_ERROR", h.EXIT_TIMEOUT_ERROR),
            6: ("INTERNAL_ERROR", h.EXIT_INTERNAL_ERROR),
        }

        for code_num, (ident, h_const) in expected_codes.items():
            self.assertEqual(code_num, h_const)
            pattern = rf"\|\s*\*\*{code_num}\*\*\s*\|\s*`{ident}`\s*\|"
            self.assertIsNotNone(
                re.search(pattern, self.local_content),
                f"Exit code {code_num} ({ident}) table entry missing in SKILL.md",
            )

    def test_07_token_conservation_directives_presence(self):
        """Verify all 6 token conservation directives are explicitly articulated in SKILL.md."""
        directives = [
            "Always Use Compact Mode",
            "Enforce Endpoint Pagination",
            "Prefer Register Diffs",
            "Strict Trace Step Budgets",
            "Stripped Terminal Formatting",
            "Parameterless Tool Calling",
        ]
        for d in directives:
            self.assertIn(d, self.local_content, f"Token directive '{d}' missing in SKILL.md")

    def test_08_crackme_recipes_tool_call_validity(self):
        """
        Verify that all python tool invocations inside the 4 crackme recipes
        in SKILL.md reference valid canonical tools and legal parameter arguments.
        """
        # Extract python code blocks
        code_blocks = re.findall(r"```python\s*\n(.*?)```", self.local_content, re.DOTALL)
        self.assertGreaterEqual(len(code_blocks), 4, "Must contain at least 4 crackme python code blocks")

        tool_names = set(self.canonical_by_name.keys())

        for block_idx, code in enumerate(code_blocks, 1):
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    fn_name = node.func.id
                    if fn_name.startswith("rvs_"):
                        self.assertIn(
                            fn_name,
                            tool_names,
                            f"Recipe {block_idx} calls non-canonical tool: '{fn_name}'",
                        )
                        c_tool = self.canonical_by_name[fn_name]
                        legal_params = set(c_tool.get("properties", {}).keys())
                        for kw in node.keywords:
                            self.assertIn(
                                kw.arg,
                                legal_params,
                                f"Recipe {block_idx} tool call '{fn_name}' uses invalid param: '{kw.arg}'",
                            )

    def test_09_multi_format_schemas_generation_invariants(self):
        """Verify get_tool_schemas generates exactly 44 valid schemas across all 4 formats."""
        for fmt in ("openai", "anthropic", "gemini", "mcp"):
            schemas = h.get_tool_schemas(fmt)  # type: ignore
            self.assertEqual(
                len(schemas),
                44,
                f"Format {fmt} produced {len(schemas)} schemas, expected 44",
            )
            # Ensure serialization round-trip
            serialized = json.dumps(schemas)
            deserialized = json.loads(serialized)
            self.assertEqual(len(deserialized), 44)

    def test_10_no_file_required_invariant(self):
        """
        Verify NO_FILE_REQUIRED_TOOLS invariant holds:
        1. All 15 Frida tools operate on target/path and never declare or require a 'file' parameter.
        2. Parameterless tools (rvs_debug_sessions, rvs_frida_env_check) have empty required parameter lists.
        3. Composite tools in NO_FILE_REQUIRED_TOOLS accept both 'file' and 'target' dynamically.
        """
        frida_tools = [t for t in h.CANONICAL_TOOLS if t["name"].startswith("rvs_frida_")]
        self.assertEqual(len(frida_tools), 15, "Must have exactly 15 Frida tools")
        for t in frida_tools:
            name = t["name"]
            props = t.get("properties", {})
            req = t.get("required", [])
            self.assertNotIn("file", props, f"Frida tool '{name}' has 'file' property")
            self.assertNotIn("file", req, f"Frida tool '{name}' requires 'file'")

        # Parameterless tools
        dbg_sess = self.canonical_by_name["rvs_debug_sessions"]
        self.assertEqual(dbg_sess.get("required", []), [], "rvs_debug_sessions must have no required parameters")

        frida_env = self.canonical_by_name["rvs_frida_env_check"]
        self.assertEqual(frida_env.get("required", []), [], "rvs_frida_env_check must have no required parameters")

        # Composite tools can accept either file or target at runtime
        for comp_name in ("rvs_triage_crash", "rvs_bypass_decision_gate", "rvs_dump_decrypted_buffer", "rvs_detect_anti_debug"):
            self.assertIn(comp_name, h.NO_FILE_REQUIRED_TOOLS)

    def test_11_parameter_defaults_documentation_fidelity(self):
        """Verify that every parameter default mentioned in schema descriptions is documented in SKILL.md."""
        diffs = []
        for t in h.CANONICAL_TOOLS:
            tname = t["name"]
            d_tool = self.doc_tools[tname]
            for p_name, p_def in t["properties"].items():
                s_desc = p_def.get("description", "")
                d_desc = d_tool["params"][p_name]["description"]

                sm = re.search(r"default[s]?\s*(?:to|:|=)?\s*([0-9a-zA-Z_\.]+)", s_desc, re.I)
                dm = re.search(r"default[s]?\s*(?:to|:|=)?\s*([0-9a-zA-Z_\.]+)", d_desc, re.I)
                if sm and dm:
                    s_val = sm.group(1).rstrip(".").lower()
                    d_val = dm.group(1).rstrip(".").lower()
                    if s_val != d_val:
                        diffs.append(f"{tname}.{p_name}: schema default={s_val} vs doc default={d_val}")
                elif sm and not dm:
                    s_val = sm.group(1).rstrip(".").lower()
                    if s_val not in d_desc.lower():
                        diffs.append(f"{tname}.{p_name}: schema default={s_val} missing in doc: '{d_desc}'")

        self.assertEqual(diffs, [], f"Parameter default discrepancies:\n" + "\n".join(diffs))

    def test_12_adversarial_error_envelopes_and_exit_codes(self):
        """
        Verify that missing required arguments, invalid types, or invalid file paths
        return valid ApiResponse error envelopes with standardized exit codes.
        """
        harness = h.RvsHarness()

        # 1. Missing required parameter 'target' in rvs_disasm returns INVALID_ARGUMENT (exit code 1)
        res_missing = harness.execute_tool("rvs_disasm", {"file": "some_binary"})
        self.assertFalse(res_missing.get("success"))
        self.assertEqual(res_missing.get("error", {}).get("code"), "INVALID_ARGUMENT")
        self.assertEqual(res_missing.get("error", {}).get("exit_code"), h.EXIT_INVALID_ARGUMENT)

        # 2. Missing required 'hex_bytes' in rvs_patch_bytes
        res_pb = harness.execute_tool("rvs_patch_bytes", {"file": "some_binary", "addr": "0x1000"})
        self.assertFalse(res_pb.get("success"))
        self.assertEqual(res_pb.get("error", {}).get("code"), "INVALID_ARGUMENT")
        self.assertEqual(res_pb.get("error", {}).get("exit_code"), h.EXIT_INVALID_ARGUMENT)

        # 3. Invalid argument types: non-integer for limit
        res_type = harness.execute_tool("rvs_functions", {"file": "some_binary", "limit": "not_an_integer"})
        self.assertFalse(res_type.get("success"))
        self.assertEqual(res_type.get("error", {}).get("code"), "INVALID_ARGUMENT")
        self.assertEqual(res_type.get("error", {}).get("exit_code"), h.EXIT_INVALID_ARGUMENT)

        # 4. Negative integer for limit
        res_neg = harness.execute_tool("rvs_functions", {"file": "some_binary", "limit": -10})
        self.assertFalse(res_neg.get("success"))
        self.assertEqual(res_neg.get("error", {}).get("code"), "INVALID_ARGUMENT")
        self.assertEqual(res_neg.get("error", {}).get("exit_code"), h.EXIT_INVALID_ARGUMENT)

        # 5. Non-existent binary returns FILE_ERROR (exit code 2)
        res_file = harness.execute_tool(
            "rvs_info", {"file": "/path/to/definitely/nonexistent_crackme_binary_9999.bin"}
        )
        self.assertFalse(res_file.get("success"))
        self.assertIn("FILE", res_file.get("error", {}).get("code", ""))
        self.assertEqual(res_file.get("error", {}).get("exit_code"), h.EXIT_FILE_ERROR)

    def test_13_mcp_protocol_tools_call_for_composite_and_parameterless(self):
        """Verify MCP JSON-RPC protocol correctly executes parameterless and composite tools."""
        import io
        harness = h.RvsHarness()

        # 1. Parameterless rvs_debug_sessions call
        req1 = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {"name": "rvs_debug_sessions", "arguments": {}},
        }
        stdout1 = io.StringIO()
        harness.serve_mcp(stdin_stream=io.StringIO(json.dumps(req1) + "\n"), stdout_stream=stdout1)
        resp1 = json.loads(stdout1.getvalue().strip())
        self.assertEqual(resp1.get("id"), 101)
        self.assertFalse(resp1.get("result", {}).get("isError"))
        inner1 = json.loads(resp1["result"]["content"][0]["text"])
        self.assertTrue(inner1.get("success"))
        self.assertIn("sessions", inner1.get("data", {}))

        # 2. Parameterless rvs_frida_env_check call
        req2 = {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {"name": "rvs_frida_env_check", "arguments": {}},
        }
        stdout2 = io.StringIO()
        harness.serve_mcp(stdin_stream=io.StringIO(json.dumps(req2) + "\n"), stdout_stream=stdout2)
        resp2 = json.loads(stdout2.getvalue().strip())
        self.assertEqual(resp2.get("id"), 102)
        inner2 = json.loads(resp2["result"]["content"][0]["text"])
        self.assertEqual(inner2.get("command"), "frida env-check")


class TestAdversarialSchemaOracle(unittest.TestCase):
    """
    Adversarial meta-tests: prove that our schema validation oracle is sensitive
    and will fail loudly if any tool, parameter, type, or required status drifts.
    """

    def test_missing_tool_detection(self):
        synthetic_doc = "# Tools\n#### `rvs_info`\n**Parameters:**\n- `file` (`string`, **required**): File\n- `compact` (`boolean`, optional): Compact\n"
        tools = extract_skill_tools(synthetic_doc)
        self.assertEqual(len(tools), 1)
        self.assertNotIn("rvs_functions", tools)

    def test_parameter_type_mismatch_detection(self):
        synthetic_doc = "#### `rvs_info`\n**Parameters:**\n- `file` (`integer`, **required**): File\n- `compact` (`boolean`, optional): Compact\n"
        tools = extract_skill_tools(synthetic_doc)
        self.assertEqual(tools["rvs_info"]["params"]["file"]["type"], "integer")
        # Differs from canonical 'string'
        c_type = h.CANONICAL_TOOLS[0]["properties"]["file"]["type"]
        self.assertNotEqual(tools["rvs_info"]["params"]["file"]["type"], c_type)

    def test_parameter_required_mismatch_detection(self):
        synthetic_doc = "#### `rvs_info`\n**Parameters:**\n- `file` (`string`, optional): File\n- `compact` (`boolean`, optional): Compact\n"
        tools = extract_skill_tools(synthetic_doc)
        self.assertFalse(tools["rvs_info"]["params"]["file"]["required"])
        # Canonical 'file' is required
        c_req = "file" in h.CANONICAL_TOOLS[0].get("required", [])
        self.assertTrue(c_req)


if __name__ == "__main__":
    unittest.main(verbosity=2)
