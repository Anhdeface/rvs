#!/usr/bin/env python3
"""
tests/test_m3_lean_verification.py - Quota-conscious verification of Milestone 3 features.
Covers F12 (parameterless dispatch), F13 (schema cleanup), F14 (token compaction & polymorphic pruning),
F15 (endpoint pagination), and F16 (composite workflows). Execution time < 3s.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any, Dict

import rvs_agent_harness
from rvs_agent_harness import (
    CANONICAL_TOOLS,
    NO_FILE_REQUIRED_TOOLS,
    RvsHarness,
    prune_emulate,
    prune_functions,
    prune_strings,
    prune_symbols,
)

CRACKME_BIN = Path(__file__).resolve().parent / "fixtures" / "crackme_case"
CRASH_BIN = Path(__file__).resolve().parent / "fixtures" / "crash_target_elf64"
DECRYPTOR_BIN = Path(__file__).resolve().parent / "fixtures" / "decryptor_target_elf64"


class TestMilestone3LeanVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = RvsHarness()

    def test_f12_parameterless_tool_dispatch(self):
        """F12: Verify parameterless dispatch with None, {}, and omitted args."""
        for args in [None, {}]:
            res = self.harness.execute_tool("rvs_debug_sessions", args)
            self.assertTrue(res.get("success"), f"Failed on args={args}")
            self.assertIn("sessions", res.get("data", {}))

            env_res = self.harness.execute_tool("rvs_frida_env_check", args)
            self.assertNotEqual(env_res.get("error", {}).get("code"), "INVALID_ARGUMENT")
            self.assertEqual(env_res.get("command"), "frida env-check")

        # Omitted arguments
        res_omitted = self.harness.execute_tool("rvs_debug_sessions")
        self.assertTrue(res_omitted.get("success"))

    def test_f13_frida_schema_cleanup(self):
        """F13: Verify all 15 frida tools and debug_sessions do not require 'file'."""
        tools_by_name = {t["name"]: t for t in CANONICAL_TOOLS}
        frida_tools = [t for t in CANONICAL_TOOLS if t["name"].startswith("rvs_frida_")]
        self.assertEqual(len(frida_tools), 15)

        for t in frida_tools:
            self.assertNotIn("file", t.get("properties", {}), f"{t['name']} has 'file' property")
            self.assertNotIn("file", t.get("required", []), f"{t['name']} requires 'file'")

        dbg_sess = tools_by_name["rvs_debug_sessions"]
        self.assertEqual(dbg_sess.get("required", []), [])

    def test_f14_token_compaction_and_polymorphism(self):
        """F14: Verify >=70% compaction ratio on trace/emulate and polymorphic pruning."""
        # Trace compaction ratio test: 50 redundant steps
        raw_emulate = {
            "steps": 50,
            "trace": [
                {
                    "step": i,
                    "addr": 0x401000 + i,
                    "addr_hex": hex(0x401000 + i),
                    "opcode": "nop",
                    "esil": ",",
                    "diff": [{"register": "rip", "before": hex(0x401000 + i), "after": hex(0x401000 + i + 1)}],
                }
                for i in range(50)
            ],
            "final_registers": {"rax": 0, "rip": hex(0x401032)},
            "memory_writes": [],
        }
        compact_emulate = prune_emulate(raw_emulate, "compact")
        raw_len = len(json.dumps(raw_emulate))
        compact_len = len(json.dumps(compact_emulate))
        reduction = (raw_len - compact_len) / raw_len
        self.assertGreaterEqual(reduction, 0.70, f"Reduction {reduction:.1%} is less than 70%")

        # Polymorphic function pruning (Rust -c schema vs legacy)
        rust_c_fn = {"functions": [{"name": "main", "addr": "0x401100", "sz": 64, "cc": 3, "bb": 4, "ins": 12}]}
        pruned_fn = prune_functions(rust_c_fn, "compact")
        self.assertEqual(pruned_fn["functions"][0]["name"], "main")
        self.assertEqual(pruned_fn["functions"][0]["addr"], "0x401100")

        # Polymorphic string pruning (dict mapping vs list of dicts)
        dict_str = {"strings": {"0x402000": "Hello, World!"}}
        pruned_str = prune_strings(dict_str, "compact")
        self.assertEqual(pruned_str["strings"][0].get("string") or pruned_str["strings"][0].get("v"), "Hello, World!")

    def test_f15_endpoint_pagination_and_defaults(self):
        """F15: Verify pagination defaults and parameters for symbols, modules, classes."""
        # Static symbols pagination limit=50 default
        raw_syms = {"symbols": [{"name": f"sym_{i}", "addr": hex(0x401000 + i), "type": "FUNC"} for i in range(100)]}
        pruned_syms = prune_symbols(raw_syms, "compact")
        self.assertEqual(len(pruned_syms["symbols"]), 50)
        self.assertEqual(pruned_syms["total"], 100)
        self.assertEqual(pruned_syms["limit"], 50)

        # CLI execution with limit & offset forwards properly
        if CRACKME_BIN.exists():
            sym_res = self.harness.symbols(str(CRACKME_BIN), limit=5, offset=2)
            self.assertTrue(sym_res.get("success"))
            self.assertLessEqual(len(sym_res.get("data", {}).get("symbols", [])), 5)

    def test_f16_composite_workflows(self):
        """F16: Verify 4 high-level composite workflows return valid envelopes."""
        # 1. detect_anti_debug
        if CRACKME_BIN.exists():
            ad_res = self.harness.detect_anti_debug(target=str(CRACKME_BIN))
            self.assertTrue(ad_res.get("success"))
            self.assertIn("anti_debug_detected", ad_res)
            self.assertIn("techniques", ad_res.get("data", {}))

        # 2. triage_crash
        if CRASH_BIN.exists():
            tc_res = self.harness.triage_crash(target=str(CRASH_BIN))
            self.assertTrue(tc_res.get("success"))
            self.assertEqual(tc_res.get("signal"), 11)
            self.assertEqual(tc_res.get("cause"), "NULL_POINTER_DEREFERENCE")

        # 3. dump_decrypted_buffer
        if DECRYPTOR_BIN.exists():
            dump_res = self.harness.dump_decrypted_buffer(target=str(DECRYPTOR_BIN))
            self.assertTrue(dump_res.get("success"))
            self.assertIn("FLAG{", str(dump_res.get("buffer", "")))
            self.assertTrue(bool(dump_res.get("hex")), "dump_res.hex must not be empty")
            self.assertGreater(len(dump_res.get("bytes", [])), 0, "dump_res.bytes must not be empty")

        # 4. MCP dispatch for composite workflows
        mcp_res = self.harness.execute_tool("rvs_agent_detect_anti_debug", {"file": str(CRACKME_BIN)})
        self.assertTrue(mcp_res.get("success"))


if __name__ == "__main__":
    unittest.main()
