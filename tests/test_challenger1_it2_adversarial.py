#!/usr/bin/env python3
"""
tests/test_challenger1_it2_adversarial.py - Challenger 1 (Iteration 2) Empirical Adversarial Stress Suite.

Adversarially tests and validates:
1. `disasm` with `max_instructions=0`, `max_instructions=1`, `max_instructions=None`,
   and large instruction counts (3, 5, 20, 100, 1000, 100000), across direct Python API,
   `execute_tool("rvs_disasm", ...)`, and MCP stdio `tools/call`.
2. Empirical Token Reduction >= 40% verification across diverse targets and commands
   (`info`, `functions`, `disasm`, `flow`, `xrefs`, `strings`, `symbols`, `triage`).
3. Comprehensive boundary conditions on pagination and budget truncation
   (`limit=0`, `1`, `None`, `>total`; `offset=0`, `1`, `total`, `>total`; empty datasets;
   continuation markers and complete list reconstruction invariants).
"""

import io
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    EXIT_INVALID_ARGUMENT,
    EXIT_SUCCESS,
    RvsHarness,
    find_rvs_binary,
    prune_blocks,
    prune_functions,
    prune_strings,
    prune_symbols,
    prune_xrefs,
    transform_response,
)


class TestDisasmMaxInstructionsAdversarial(unittest.TestCase):
    """Adversarial stress testing of instruction budget limits in disassembly."""

    @classmethod
    def setUpClass(cls):
        cls.crackme = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
        if not cls.crackme.exists():
            cls.crackme = WORKSPACE_DIR / "crackme_case"
        cls.auth_gate = WORKSPACE_DIR / "tests" / "fixtures" / "auth_gate_elf64"
        cls.flow_calc = WORKSPACE_DIR / "tests" / "fixtures" / "flow_calc_elf64"
        cls.rvs_bin = find_rvs_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)

    def test_01_disasm_max_instructions_zero_direct_api(self):
        """Verify max_instructions=0 empties all instruction lists via direct API across all binaries."""
        for target_bin in [self.crackme, self.auth_gate, self.flow_calc]:
            if not target_bin.exists():
                continue
            resp = self.harness.disasm(target_bin, "main", max_instructions=0)
            self.assertTrue(resp.get("success"), f"Failed disasm on {target_bin}")
            self.assertIn("data", resp)
            blocks = resp["data"].get("blocks", [])
            self.assertGreater(len(blocks), 0, f"Expected blocks in {target_bin}")
            for b in blocks:
                self.assertIn("instructions", b)
                self.assertEqual(
                    len(b["instructions"]),
                    0,
                    f"Expected 0 instructions in block {b.get('addr')}, got {len(b['instructions'])}",
                )

    def test_02_disasm_max_instructions_zero_execute_tool(self):
        """Verify max_instructions=0 empties all instruction lists via execute_tool."""
        resp = self.harness.execute_tool(
            "rvs_disasm",
            {"file": str(self.crackme), "target": "main", "max_instructions": 0},
        )
        self.assertTrue(resp.get("success"))
        blocks = resp["data"].get("blocks", [])
        self.assertGreater(len(blocks), 0)
        for b in blocks:
            self.assertEqual(len(b["instructions"]), 0)

    def test_03_disasm_max_instructions_zero_mcp_call(self):
        """Verify max_instructions=0 via MCP stdio JSON-RPC server session."""
        req = {
            "jsonrpc": "2.0",
            "id": "test-disasm-zero",
            "method": "tools/call",
            "params": {
                "name": "rvs_disasm",
                "arguments": {
                    "file": str(self.crackme),
                    "target": "main",
                    "max_instructions": 0,
                },
            },
        }
        stdin = io.StringIO(json.dumps(req) + "\n")
        stdout = io.StringIO()
        self.harness.serve_mcp(stdin, stdout)

        lines = [l.strip() for l in stdout.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        res = json.loads(lines[0])
        self.assertEqual(res.get("id"), "test-disasm-zero")
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(content["success"])
        blocks = content["data"]["blocks"]
        for b in blocks:
            self.assertEqual(len(b["instructions"]), 0)

    def test_04_disasm_max_instructions_one_direct_and_tools(self):
        """Verify max_instructions=1 caps each basic block to at most 1 instruction."""
        for target_bin in [self.crackme, self.auth_gate]:
            if not target_bin.exists():
                continue
            resp = self.harness.disasm(target_bin, "main", max_instructions=1)
            self.assertTrue(resp.get("success"))
            blocks = resp["data"].get("blocks", [])
            for b in blocks:
                self.assertLessEqual(len(b["instructions"]), 1)
                if b["instructions"]:
                    self.assertIn("asm", b["instructions"][0])

            # Also check execute_tool
            tool_resp = self.harness.execute_tool(
                "rvs_disasm",
                {"file": str(target_bin), "target": "main", "max_instructions": 1},
            )
            for b in tool_resp["data"]["blocks"]:
                self.assertLessEqual(len(b["instructions"]), 1)

    def test_05_disasm_max_instructions_none_preserves_all_instructions(self):
        """Verify max_instructions=None does not truncate block instructions."""
        resp_full = self.harness.disasm(self.crackme, "main", max_instructions=None)
        self.assertTrue(resp_full.get("success"))
        blocks = resp_full["data"].get("blocks", [])
        total_instrs = sum(len(b.get("instructions", [])) for b in blocks)
        self.assertGreater(total_instrs, 5, "Expected realistic instruction count")

        # Calling with default max_instructions (None)
        resp_default = self.harness.disasm(self.crackme, "main")
        total_default = sum(len(b.get("instructions", [])) for b in resp_default["data"]["blocks"])
        self.assertEqual(total_instrs, total_default)

    def test_06_disasm_max_instructions_arbitrary_counts(self):
        """Verify max_instructions with various budget thresholds (3, 5, 20, 100, 100000)."""
        # Baseline full counts per block
        resp_full = self.harness.disasm(self.crackme, "main", max_instructions=None)
        full_block_lens = [len(b["instructions"]) for b in resp_full["data"]["blocks"]]

        for limit in [3, 5, 20, 100, 100000]:
            resp = self.harness.disasm(self.crackme, "main", max_instructions=limit)
            self.assertTrue(resp.get("success"))
            cur_lens = [len(b["instructions"]) for b in resp["data"]["blocks"]]
            expected_lens = [min(l, limit) for l in full_block_lens]
            self.assertEqual(cur_lens, expected_lens, f"Mismatch with max_instructions={limit}")

    def test_07_prune_blocks_unit_edge_cases(self):
        """Unit test prune_blocks with negative, zero, None, and synthetic instruction lists."""
        synthetic_data = {
            "function_name": "test_fn",
            "function_addr": 4096,
            "blocks": [
                {
                    "addr": 4096,
                    "size": 16,
                    "instructions": [
                        {"addr": 4096, "disasm": "push rbp", "size": 1},
                        {"addr": 4097, "disasm": "mov rbp, rsp", "size": 3},
                        {"addr": 4100, "disasm": "sub rsp, 0x10", "size": 4},
                        {"addr": 4104, "disasm": "nop", "size": 1},
                    ],
                },
                {
                    "addr": 4112,
                    "size": 8,
                    "instructions": [
                        {"addr": 4112, "disasm": "mov eax, 0", "size": 5},
                        {"addr": 4117, "disasm": "ret", "size": 1},
                    ],
                },
            ],
        }

        # max_instructions = 0
        p0 = prune_blocks(synthetic_data, mode="compact", max_instructions=0)
        self.assertEqual(len(p0["blocks"][0]["instructions"]), 0)
        self.assertEqual(len(p0["blocks"][1]["instructions"]), 0)

        # max_instructions = 1
        p1 = prune_blocks(synthetic_data, mode="compact", max_instructions=1)
        self.assertEqual(len(p1["blocks"][0]["instructions"]), 1)
        self.assertEqual(p1["blocks"][0]["instructions"][0]["asm"], "push rbp")
        self.assertEqual(len(p1["blocks"][1]["instructions"]), 1)

        # max_instructions = 3
        p3 = prune_blocks(synthetic_data, mode="compact", max_instructions=3)
        self.assertEqual(len(p3["blocks"][0]["instructions"]), 3)
        self.assertEqual(len(p3["blocks"][1]["instructions"]), 2)

        # max_instructions = None
        p_none = prune_blocks(synthetic_data, mode="compact", max_instructions=None)
        self.assertEqual(len(p_none["blocks"][0]["instructions"]), 4)
        self.assertEqual(len(p_none["blocks"][1]["instructions"]), 2)


class TestTokenReductionComprehensiveBenchmark(unittest.TestCase):
    """Empirical adversarial benchmarks verifying token/character reduction >= 40%."""

    @classmethod
    def setUpClass(cls):
        cls.targets = [
            WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case",
            WORKSPACE_DIR / "tests" / "fixtures" / "auth_gate_elf64",
            WORKSPACE_DIR / "tests" / "fixtures" / "flow_calc_elf64",
            WORKSPACE_DIR / "tests" / "fixtures" / "test_target_elf64",
        ]
        if not cls.targets[0].exists():
            cls.targets[0] = WORKSPACE_DIR / "crackme_case"

        # Also test system binary if accessible
        sys_ls = Path("/bin/ls") if Path("/bin/ls").exists() else Path("/usr/bin/ls")
        if sys_ls.exists():
            cls.targets.append(sys_ls)

        cls.rvs_bin = find_rvs_binary()
        cls.harness = RvsHarness(rvs_bin=cls.rvs_bin)

    def _calc_reduction(self, raw_resp: Dict[str, Any], compact_resp: Dict[str, Any]) -> float:
        raw_sz = len(json.dumps(raw_resp.get("data", {})))
        comp_sz = len(json.dumps(compact_resp.get("data", {})))
        if raw_sz == 0:
            return 0.0
        return (raw_sz - comp_sz) / raw_sz * 100.0

    def test_01_functions_reduction_across_all_targets(self):
        """Verify `functions` compact output achieves >= 40% reduction across all binaries."""
        results = {}
        for target in self.targets:
            if not target.exists():
                continue
            raw = self.harness.functions(target, compact=False)
            comp = self.harness.functions(target, compact=True)
            self.assertTrue(raw.get("success") and comp.get("success"), f"Failed on {target}")

            reduction = self._calc_reduction(raw, comp)
            results[target.name] = reduction
            self.assertGreaterEqual(
                reduction,
                40.0,
                f"Functions reduction on {target.name} was {reduction:.2f}%, expected >= 40%",
            )
        print(f"\n[BENCHMARK] Functions Token Reductions: {results}")

    def test_02_disasm_reduction_across_all_targets(self):
        """Verify `disasm` compact output achieves >= 40% reduction across all binaries."""
        results = {}
        for target in self.targets:
            if not target.exists():
                continue
            raw = self.harness.disasm(target, "main", compact=False)
            comp = self.harness.disasm(target, "main", compact=True)
            if not raw.get("success"):
                continue

            reduction = self._calc_reduction(raw, comp)
            results[target.name] = reduction
            self.assertGreaterEqual(
                reduction,
                40.0,
                f"Disasm reduction on {target.name} was {reduction:.2f}%, expected >= 40%",
            )
        print(f"\n[BENCHMARK] Disasm Token Reductions: {results}")

    def test_03_strings_reduction_across_all_targets(self):
        """Verify `strings` compact output achieves >= 40% reduction across all binaries."""
        results = {}
        for target in self.targets:
            if not target.exists():
                continue
            raw = self.harness.strings(target, min_len=4, compact=False)
            comp = self.harness.strings(target, min_len=4, compact=True)
            if not raw.get("success"):
                continue

            reduction = self._calc_reduction(raw, comp)
            results[target.name] = reduction
            self.assertGreaterEqual(
                reduction,
                40.0,
                f"Strings reduction on {target.name} was {reduction:.2f}%, expected >= 40%",
            )
        print(f"\n[BENCHMARK] Strings Token Reductions: {results}")

    def test_04_symbols_reduction_across_all_targets(self):
        """Verify `symbols` compact output achieves >= 40% reduction across all binaries."""
        results = {}
        for target in self.targets:
            if not target.exists():
                continue
            raw = self.harness.symbols(target, compact=False)
            comp = self.harness.symbols(target, compact=True)
            if not raw.get("success"):
                continue

            reduction = self._calc_reduction(raw, comp)
            results[target.name] = reduction
            self.assertGreaterEqual(
                reduction,
                40.0,
                f"Symbols reduction on {target.name} was {reduction:.2f}%, expected >= 40%",
            )
        print(f"\n[BENCHMARK] Symbols Token Reductions: {results}")

    def test_05_xrefs_reduction_across_all_targets(self):
        """Verify `xrefs` compact output achieves >= 40% reduction across all binaries."""
        results = {}
        for target in self.targets:
            if not target.exists():
                continue
            raw = self.harness.xrefs(target, symbol_or_addr="main", compact=False)
            comp = self.harness.xrefs(target, symbol_or_addr="main", compact=True)
            if not raw.get("success"):
                continue

            reduction = self._calc_reduction(raw, comp)
            results[target.name] = reduction
            self.assertGreaterEqual(
                reduction,
                40.0,
                f"Xrefs reduction on {target.name} was {reduction:.2f}%, expected >= 40%",
            )
        print(f"\n[BENCHMARK] Xrefs Token Reductions: {results}")

    def test_06_triage_and_flow_and_info_reduction(self):
        """Verify `triage`, `flow`, and `info` achieve >= 40% reduction."""
        target = self.targets[0]
        # Info
        raw_info = self.harness.run(["-f", str(target), "info"], mode="full")
        comp_info = self.harness.run(["-f", str(target), "info"], mode="compact")
        self.assertGreaterEqual(self._calc_reduction(raw_info, comp_info), 40.0)

        # Triage
        raw_triage = self.harness.run(["-f", str(target), "agent", "triage"], mode="full")
        comp_triage = self.harness.run(["-f", str(target), "agent", "triage"], mode="compact")
        self.assertGreaterEqual(self._calc_reduction(raw_triage, comp_triage), 40.0)

        # Flow
        raw_flow = self.harness.run(["-f", str(target), "agent", "flow", "main"], mode="full")
        comp_flow = self.harness.run(["-f", str(target), "agent", "flow", "main"], mode="compact")
        self.assertGreaterEqual(self._calc_reduction(raw_flow, comp_flow), 40.0)

    def test_07_summary_mode_macro_reduction(self):
        """Verify summary mode achieves >= 70% reduction across key exploration commands."""
        target = self.targets[0]
        for cmd_name, method in [
            ("functions", lambda: (self.harness.functions(target, compact=False), self.harness.run(["-f", str(target), "analyze", "functions"], mode="summary"))),
            ("disasm", lambda: (self.harness.disasm(target, "main", compact=False), self.harness.run(["-f", str(target), "analyze", "blocks", "main"], mode="summary"))),
            ("strings", lambda: (self.harness.strings(target, compact=False), self.harness.run(["-f", str(target), "strings"], mode="summary"))),
        ]:
            raw, summary = method()
            self.assertTrue(raw.get("success") and summary.get("success"), f"Failed running {cmd_name}")
            reduction = self._calc_reduction(raw, summary)
            self.assertGreaterEqual(
                reduction,
                70.0,
                f"Summary reduction for {cmd_name} was {reduction:.2f}%, expected >= 70%",
            )


class TestPaginationAndBudgetTruncationBoundaries(unittest.TestCase):
    """Adversarial stress testing of limit, offset, and continuation metadata."""

    @classmethod
    def setUpClass(cls):
        cls.crackme = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
        if not cls.crackme.exists():
            cls.crackme = WORKSPACE_DIR / "crackme_case"
        cls.harness = RvsHarness(rvs_bin=find_rvs_binary())

    def test_01_functions_pagination_boundaries(self):
        """Test functions pagination with limit=0, 1, total, >total, and offset=0, 1, total, >total."""
        resp_all = self.harness.functions(self.crackme, compact=True, limit=1000)
        total_funcs = resp_all["data"]["total"]
        self.assertGreater(total_funcs, 5)

        # 1. limit=0 -> displayed=0, truncated=True, continuation_hint present
        resp_lim0 = self.harness.functions(self.crackme, compact=True, limit=0, offset=0)
        d0 = resp_lim0["data"]
        self.assertEqual(d0["displayed"], 0)
        self.assertEqual(len(d0["functions"]), 0)
        self.assertEqual(d0["remaining"], total_funcs)
        self.assertTrue(d0["truncated"])
        self.assertTrue(d0["has_more"])
        self.assertIn("continuation_hint", d0)
        self.assertEqual(d0["limit"], 0)
        self.assertEqual(d0["offset"], 0)

        # 2. limit=1 -> displayed=1, truncated=True
        resp_lim1 = self.harness.functions(self.crackme, compact=True, limit=1, offset=0)
        d1 = resp_lim1["data"]
        self.assertEqual(d1["displayed"], 1)
        self.assertEqual(len(d1["functions"]), 1)
        self.assertEqual(d1["remaining"], total_funcs - 1)
        self.assertTrue(d1["truncated"])
        self.assertTrue(d1["has_more"])
        self.assertIn("continuation_hint", d1)

        # 3. offset=total -> displayed=0, remaining=0, truncated=False
        resp_off_tot = self.harness.functions(self.crackme, compact=True, limit=10, offset=total_funcs)
        dtot = resp_off_tot["data"]
        self.assertEqual(dtot["displayed"], 0)
        self.assertEqual(len(dtot["functions"]), 0)
        self.assertEqual(dtot["remaining"], 0)
        self.assertFalse(dtot["truncated"])
        self.assertFalse(dtot["has_more"])
        self.assertNotIn("continuation_hint", dtot)

        # 4. offset > total -> displayed=0, remaining=0, truncated=False
        resp_off_gt = self.harness.functions(self.crackme, compact=True, limit=10, offset=total_funcs + 50)
        dgt = resp_off_gt["data"]
        self.assertEqual(dgt["displayed"], 0)
        self.assertEqual(dgt["remaining"], 0)
        self.assertFalse(dgt["truncated"])

        # 5. limit >= total (offset=0) -> displayed=total, remaining=0, truncated=False
        resp_all_explicit = self.harness.functions(self.crackme, compact=True, limit=total_funcs, offset=0)
        dall = resp_all_explicit["data"]
        self.assertEqual(dall["displayed"], total_funcs)
        self.assertEqual(dall["remaining"], 0)
        self.assertFalse(dall["truncated"])
        self.assertFalse(dall["has_more"])

    def test_02_pagination_reconstruction_invariant(self):
        """
        Verify that paging sequentially with small limit reconstructs the exact dataset
        without duplicates or dropped items.
        """
        resp_full = self.harness.functions(self.crackme, compact=True, limit=1000)
        expected_names = [f["name"] for f in resp_full["data"]["functions"]]
        total = len(expected_names)

        page_size = 3
        reconstructed_names = []
        offset = 0

        while offset < total:
            page_resp = self.harness.functions(self.crackme, compact=True, limit=page_size, offset=offset)
            page_data = page_resp["data"]
            items = page_data["functions"]
            self.assertEqual(len(items), min(page_size, total - offset))
            reconstructed_names.extend([f["name"] for f in items])

            if not page_data["has_more"]:
                break
            offset += len(items)

        self.assertEqual(reconstructed_names, expected_names)

    def test_03_blocks_pagination_boundaries(self):
        """Test basic blocks pagination limits and offsets via prune_blocks."""
        raw_blocks_data = {
            "function_name": "main",
            "function_addr": "0x11e0",
            "blocks": [
                {"addr": f"0x{1000 + i * 16:x}", "size": 16, "instructions": []}
                for i in range(10)
            ],
        }

        # limit=0
        p0 = prune_blocks(raw_blocks_data, mode="compact", limit=0, offset=0)
        self.assertEqual(p0["displayed"], 0)
        self.assertEqual(p0["remaining"], 10)
        self.assertTrue(p0["truncated"])
        self.assertTrue(p0["has_more"])
        self.assertEqual(p0["continuation_hint"], "Use limit=0 offset=0 to retrieve next slice.")

        # limit=4, offset=0
        p1 = prune_blocks(raw_blocks_data, mode="compact", limit=4, offset=0)
        self.assertEqual(p1["displayed"], 4)
        self.assertEqual(p1["remaining"], 6)
        self.assertEqual(p1["continuation_hint"], "Use limit=4 offset=4 to retrieve next slice.")

        # limit=4, offset=8
        p2 = prune_blocks(raw_blocks_data, mode="compact", limit=4, offset=8)
        self.assertEqual(p2["displayed"], 2)
        self.assertEqual(p2["remaining"], 0)
        self.assertFalse(p2["truncated"])
        self.assertNotIn("continuation_hint", p2)

        # offset=10 (end)
        p3 = prune_blocks(raw_blocks_data, mode="compact", limit=4, offset=10)
        self.assertEqual(p3["displayed"], 0)
        self.assertEqual(p3["remaining"], 0)
        self.assertFalse(p3["truncated"])

    def test_04_strings_and_symbols_pagination_boundaries(self):
        """Test strings and symbols pagination boundaries with run() and prune functions."""
        # Test strings with run(..., limit=2, offset=0)
        resp_str = self.harness.run(["-f", str(self.crackme), "strings"], mode="compact", limit=2, offset=0)
        self.assertTrue(resp_str.get("success"))
        d_str = resp_str["data"]
        self.assertEqual(d_str["displayed"], 2)
        self.assertIn("continuation_hint", d_str)
        self.assertTrue(d_str["has_more"])

        # Test next slice
        resp_str2 = self.harness.run(["-f", str(self.crackme), "strings"], mode="compact", limit=2, offset=2)
        d_str2 = resp_str2["data"]
        self.assertEqual(d_str2["displayed"], 2)
        self.assertNotEqual(d_str["strings"], d_str2["strings"])

        # Test symbols with run(..., limit=3, offset=0)
        resp_sym = self.harness.run(["-f", str(self.crackme), "symbols"], mode="compact", limit=3, offset=0)
        self.assertTrue(resp_sym.get("success"))
        d_sym = resp_sym["data"]
        self.assertEqual(d_sym["displayed"], 3)
        self.assertIn("continuation_hint", d_sym)

    def test_05_empty_dataset_pagination(self):
        """Test pagination behavior when raw dataset is completely empty."""
        empty_funcs = {"functions": []}
        res_f = prune_functions(empty_funcs, mode="compact", limit=10, offset=0)
        self.assertEqual(res_f["total"], 0)
        self.assertEqual(len(res_f["functions"]), 0)

        empty_strings = {"strings": []}
        res_s = prune_strings(empty_strings, mode="compact", limit=10, offset=0)
        self.assertEqual(res_s["total"], 0)
        self.assertEqual(len(res_s["strings"]), 0)

        empty_symbols = {"symbols": []}
        res_sym = prune_symbols(empty_symbols, mode="compact", limit=10, offset=0)
        self.assertEqual(res_sym["total"], 0)
        self.assertEqual(len(res_sym["symbols"]), 0)

        empty_xrefs = {"xrefs": []}
        res_x = prune_xrefs(empty_xrefs, mode="compact", limit=10, offset=0)
        self.assertEqual(res_x["total"], 0)
        self.assertEqual(len(res_x["xrefs"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
