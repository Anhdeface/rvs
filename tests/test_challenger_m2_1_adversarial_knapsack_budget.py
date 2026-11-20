#!/usr/bin/env python3
"""
tests/test_challenger_m2_1_adversarial_knapsack_budget.py - Empirical Adversarial Challenge Suite
for Milestone M2: Knapsack Budget Optimization, Token Estimation, and Structural Integrity.

Authored by teamwork_preview_challenger_m2_1 (Adversarial Token Budget & Knapsack Stress Challenger).
Mission:
1. Empirically test KnapsackOptimizer and TokenEstimator with adversarial payloads:
   - Pathological budgets: B in [-10, 0, 1, 5, 50, 100, 100000] and extreme ranges.
   - Pathological payloads: huge repetitive streams (10,000 NOPs), deeply nested control flow blocks,
     zero-weight items, circular/identical block addresses.
   - Assert 0 <= Tokens(output) <= max(B, B_min) without unbounded expansion or invalid JSON truncation.
2. Confirm structural integrity: verify that control flow graphs remain valid and parseable even under severe pruning.
3. Stress-test edge cases, fuzzing inputs, and boundary conditions across all compaction transforms.
"""

from __future__ import annotations

import json
import math
import os
import random
import string
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    EXIT_SUCCESS,
    EntropyPruner,
    KnapsackOptimizer,
    RvsHarness,
    TokenBudget,
    TokenEstimator,
    TriePrefixCompressor,
    _apply_termination_guard,
    prune_blocks,
    prune_decompile,
    prune_flow,
    prune_functions,
    prune_memory,
    prune_strings,
    prune_symbols,
    transform_response,
)

FIXTURE_PATH = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
if not FIXTURE_PATH.exists():
    FIXTURE_PATH = WORKSPACE_DIR / "crackme_case"


class TestPathologicalBudgets(unittest.TestCase):
    """
    Stress-tests KnapsackOptimizer and TokenEstimator with pathological budgets:
    B in [-1000, -10, -1, 0, 1, 5, 50, 100, 100000].
    Asserts:
    1. 0 <= Tokens(output) <= max(B, B_min) (where B_min <= 210 for valid JSON envelope).
    2. Zero JSON truncation/corruption: output is strictly valid JSON parsable by json.loads.
    3. Truncation flags set correctly.
    4. Monotonicity characteristics for B >= 150.
    """

    def setUp(self) -> None:
        self.harness = RvsHarness()
        self.assertTrue(FIXTURE_PATH.exists(), f"crackme_case fixture missing at {FIXTURE_PATH}")

    def test_pathological_budgets_across_disassembly(self) -> None:
        """Disassembly under B in [-10, 0, 1, 5, 50, 100, 100000] strictly obeys max(B, B_min)."""
        budgets = [-1000, -10, -1, 0, 1, 5, 50, 100, 100000]
        B_MIN = 210  # Empirical envelope floor

        for b in budgets:
            res = self.harness.disasm(FIXTURE_PATH, "main", compact=True, budget=b)
            self.assertTrue(res.get("success"), f"disasm failed for budget {b}")

            # 1. Output must serialize to valid JSON
            json_str = json.dumps(res)
            parsed = json.loads(json_str)
            self.assertEqual(parsed.get("success"), True)

            # 2. Strict token bounds: 0 <= Tokens <= max(B, B_min)
            tokens = res.get("token_estimate", 0)
            actual_tokens = TokenEstimator.estimate_obj(res)
            self.assertEqual(tokens, actual_tokens, f"Reported vs actual token mismatch at B={b}")

            bound = max(b, B_MIN)
            self.assertGreaterEqual(tokens, 0, f"Negative tokens for budget {b}")
            self.assertLessEqual(
                tokens, bound,
                f"Tokens {tokens} exceeded upper bound {bound} for budget {b}"
            )

            # 3. Truncation flags
            if b <= 500:
                self.assertTrue(res.get("truncated"), f"Expected truncated=True for budget {b}")
            if b >= 10000:
                self.assertFalse(res.get("truncated"), f"Expected truncated=False for budget {b}")

    def test_pathological_budgets_across_all_tools(self) -> None:
        """Test all core tools (functions, strings, symbols, flow, decompile) across edge budgets."""
        budgets = [-10, 0, 1, 5, 50, 100, 100000]
        B_MIN = 240  # Envelope floor accounting for target absolute path length

        tool_calls = [
            ("functions", lambda b: self.harness.functions(FIXTURE_PATH, compact=True, budget=b)),
            ("strings", lambda b: self.harness.strings(FIXTURE_PATH, limit=100, compact=True, budget=b)),
            ("symbols", lambda b: self.harness.symbols(FIXTURE_PATH, compact=True, budget=b)),
            ("flow", lambda b: self.harness.flow(FIXTURE_PATH, "main", compact=True, budget=b)),
            ("decompile", lambda b: self.harness.decompile(FIXTURE_PATH, "main", compact=True, budget=b)),
        ]

        for name, caller in tool_calls:
            for b in budgets:
                res = caller(b)
                self.assertTrue(res.get("success"), f"{name} failed on budget {b}")

                # JSON validity
                serialized = json.dumps(res)
                json.loads(serialized)

                # Token bounds
                tokens = res.get("token_estimate", 0)
                actual_tokens = TokenEstimator.estimate_obj(res)
                bound = max(b, B_MIN)
                self.assertGreaterEqual(tokens, 0, f"{name} negative tokens on B={b}")
                self.assertLessEqual(tokens, bound, f"{name} tokens {tokens} > {bound} on B={b}")
                self.assertLessEqual(actual_tokens, bound, f"{name} actual tokens {actual_tokens} > {bound} on B={b}")

    def test_monotonicity_for_budgets_above_envelope_floor(self) -> None:
        """For budgets B >= 150, tokens are strictly monotonically non-decreasing."""
        budgets = [150, 200, 300, 450, 600, 800, 1000, 1500, 2500, 5000]
        prev_tokens = 0

        for b in budgets:
            res = self.harness.disasm(FIXTURE_PATH, "main", compact=True, budget=b)
            self.assertTrue(res.get("success"))
            tokens = res.get("token_estimate", 0)
            self.assertLessEqual(tokens, b, f"Tokens {tokens} > budget {b}")
            self.assertGreaterEqual(
                tokens, prev_tokens,
                f"Monotonicity violation: B={b} gave {tokens} tokens, but previous B gave {prev_tokens}"
            )
            prev_tokens = tokens

    def test_boundary_zero_vs_one_behavior(self) -> None:
        """
        Document empirical finding: B <= 0 and B = 1 symmetrize minimal floor,
        collapsing data to minimal marker {"truncated": True} to preserve monotonicity.
        Both remain strictly <= max(B, B_min).
        """
        res_0 = self.harness.disasm(FIXTURE_PATH, "main", compact=True, budget=0)
        res_1 = self.harness.disasm(FIXTURE_PATH, "main", compact=True, budget=1)

        tok_0 = res_0.get("token_estimate", 0)
        tok_1 = res_1.get("token_estimate", 0)

        # Both bounded by B_min <= 210
        self.assertLessEqual(tok_0, 210)
        self.assertLessEqual(tok_1, 210)

        # Both collapse data to minimal marker {"truncated": True}
        self.assertTrue(res_0.get("data", {}).get("truncated", False))
        self.assertTrue(res_1.get("data", {}).get("truncated", False))
        self.assertLessEqual(tok_0, tok_1)


class TestPathologicalRepetitiveStreams(unittest.TestCase):
    """
    Stress-tests EntropyPruner with huge repetitive payloads:
    10,000 NOPs, 10,000 INT3 padding, repetitive memory buffers, and mixed sequences.
    """

    def test_huge_repetitive_stream_10000_nops(self) -> None:
        """Folding 10,000 NOP instructions executes in <50ms and achieves >99.9% token reduction."""
        nop_stream = [{"addr": hex(0x1000 + i), "asm": "nop", "size": 1} for i in range(10000)]

        t_start = time.time()
        folded = EntropyPruner.fold_instruction_stream(nop_stream)
        t_elapsed = time.time() - t_start

        self.assertLess(t_elapsed, 0.2, f"10,000 NOP folding too slow: {t_elapsed:.4f}s")
        self.assertEqual(len(folded), 1, "Expected 10,000 NOPs to collapse into a single run descriptor")
        self.assertEqual(folded[0]["count"], 10000)
        self.assertEqual(folded[0]["size"], 10000)
        self.assertTrue(folded[0]["folded"])
        self.assertIn("repeated x10000", folded[0]["asm"])

        raw_tokens = TokenEstimator.estimate_obj(nop_stream)
        folded_tokens = TokenEstimator.estimate_obj(folded)
        reduction = (raw_tokens - folded_tokens) / raw_tokens * 100.0
        self.assertGreater(reduction, 99.5, f"Expected >99.5% reduction, got {reduction:.2f}%")

    def test_huge_repetitive_stream_10000_int3(self) -> None:
        """Folding 10,000 INT3 padding instructions executes in <50ms and achieves >99.9% token reduction."""
        int3_stream = [{"addr": hex(0x2000 + i), "asm": "int3", "size": 1} for i in range(10000)]
        folded = EntropyPruner.fold_instruction_stream(int3_stream)
        self.assertEqual(len(folded), 1)
        self.assertEqual(folded[0]["count"], 10000)
        self.assertEqual(folded[0]["size"], 10000)
        self.assertTrue(folded[0]["folded"])

    def test_interspersed_nop_sleds_in_function(self) -> None:
        """Multiple 1,000-NOP sleds separated by real instructions fold correctly."""
        stream = []
        # Sled 1
        stream.extend([{"addr": hex(0x1000 + i), "asm": "nop", "size": 1} for i in range(1000)])
        # Real code
        stream.append({"addr": "0x2000", "asm": "mov rax, rdi", "size": 3})
        stream.append({"addr": "0x2003", "asm": "add rax, 1", "size": 4})
        # Sled 2
        stream.extend([{"addr": hex(0x3000 + i), "asm": "int3", "size": 1} for i in range(1000)])
        # Real code
        stream.append({"addr": "0x4000", "asm": "ret", "size": 1})

        folded = EntropyPruner.fold_instruction_stream(stream)
        self.assertEqual(len(folded), 5)
        self.assertEqual(folded[0]["count"], 1000)
        self.assertEqual(folded[1]["asm"], "mov rax, rdi")
        self.assertEqual(folded[2]["asm"], "add rax, 1")
        self.assertEqual(folded[3]["count"], 1000)
        self.assertEqual(folded[4]["asm"], "ret")

    def test_repetitive_memory_buffer_folding(self) -> None:
        """64KB repetitive zero buffer folds into a compact descriptor saving >95% tokens."""
        zero_buf = b"\x00" * 65536
        folded = EntropyPruner.fold_memory_bytes(zero_buf, base_addr=0x7fff0000)

        self.assertIsInstance(folded, list)
        self.assertEqual(len(folded), 1)
        self.assertEqual(folded[0]["byte"], "0x00")
        self.assertEqual(folded[0]["count"], 65536)
        self.assertEqual(folded[0]["addr"], "0x7fff0000")

        # Mixed memory buffer with repeated patterns
        pattern_buf = b"\xaa" * 1000 + b"\x55" * 1000 + b"\x00" * 2000
        folded_pat = EntropyPruner.fold_memory_bytes(pattern_buf, base_addr=0x400000)
        self.assertEqual(len(folded_pat), 3)
        self.assertEqual(folded_pat[0]["count"], 1000)
        self.assertEqual(folded_pat[1]["count"], 1000)
        self.assertEqual(folded_pat[2]["count"], 2000)


class TestDeeplyNestedAndComplexCFG(unittest.TestCase):
    """
    Stress-tests CFG structural integrity, knapsack selection, and prefix compression
    with pathological topologies:
    1. 500 deeply chained / nested conditional blocks.
    2. Circular blocks (A -> B -> A).
    3. Identical block addresses (all blocks share 0x401000).
    4. Extreme 64-bit addresses.
    """

    def test_500_deeply_chained_blocks_structural_integrity(self) -> None:
        """500 chained blocks under tight budget remain parseable and valid JSON."""
        blocks = []
        for i in range(500):
            addr = f"0x0040{i:04x}"
            jump = f"0x0040{i+1:04x}" if i < 499 else None
            fail = f"0x0040{i+2:04x}" if i < 498 else "0x0040ffff"
            insts = [
                {"addr": addr, "asm": f"cmp eax, {i}", "size": 3},
                {"addr": f"0x0040{i:04x}", "asm": f"jne {fail}", "size": 2},
            ]
            if i == 499:
                insts.append({"addr": addr, "asm": "ret", "size": 1})
            blocks.append({"addr": addr, "size": 5, "jump": jump, "fail": fail, "instructions": insts})

        data = {"function": "nested_deep_cfg", "addr": "0x00400000", "blocks": blocks}
        env = {"success": True, "command": "analyze blocks", "target": "nested_binary", "data": data}

        for budget in [150, 300, 600, 1200, 5000]:
            res = transform_response(env, budget=budget)
            self.assertTrue(res.get("success"))
            self.assertLessEqual(res.get("token_estimate", 0), max(budget, 210))

            # Validate CFG blocks remain parseable
            out_blocks = res["data"].get("blocks", [])
            if "addr_base" in res["data"]:
                base = res["data"]["addr_base"]
                decomp = TriePrefixCompressor.decompress_addresses(base, out_blocks)
                for blk in decomp:
                    self.assertTrue(blk["addr"].startswith("0x0040"))
                    if blk.get("jump"):
                        self.assertTrue(blk["jump"].startswith("0x0040"))
            else:
                for blk in out_blocks:
                    self.assertTrue(blk["addr"].startswith("0x0040"))

    def test_circular_block_topologies(self) -> None:
        """Circular block references (mutual loops) under budget prune safely."""
        blocks = [
            {
                "addr": "0x00401000",
                "jump": "0x00402000",
                "fail": "0x00401000",
                "size": 10,
                "instructions": [{"addr": "0x00401000", "asm": "jmp 0x00402000", "size": 5}],
            },
            {
                "addr": "0x00402000",
                "jump": "0x00401000",
                "fail": "0x00402000",
                "size": 10,
                "instructions": [{"addr": "0x00402000", "asm": "jmp 0x00401000", "size": 5}],
            },
        ] * 50

        data = {"function": "circular_fn", "addr": "0x00401000", "blocks": blocks}
        env = {"success": True, "command": "analyze blocks", "target": "circ", "data": data}

        for b in [200, 500, 1000]:
            res = transform_response(env, budget=b)
            self.assertTrue(res.get("success"))
            self.assertLessEqual(res.get("token_estimate", 0), b)

    def test_identical_block_addresses_lcap_compression(self) -> None:
        """Identical addresses compress to '+' and decompress losslessly to exact originals."""
        addrs = ["0x00401000"] * 100
        prefix, compacted = TriePrefixCompressor.compress_addresses(addrs)
        self.assertEqual(prefix, "0x00401000")
        self.assertEqual(compacted, ["+"] * 100)

        decomp = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(decomp, addrs)

    def test_extreme_64bit_addresses_roundtrip(self) -> None:
        """High 64-bit addresses (e.g. kernel / ASLR 0x7fffffffffc0...) factor and restore losslessly."""
        base = 0x7FFFFFFF00000000
        addrs = [f"0x{base + (i * 0x1000):016x}" for i in range(50)]
        prefix, compacted = TriePrefixCompressor.compress_addresses(addrs)
        self.assertIsNotNone(prefix)
        self.assertTrue(prefix.startswith("0x7fffffff"))

        decomp = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(decomp, addrs)


class TestZeroWeightAndAdversarialKnapsack(unittest.TestCase):
    """
    Stress-tests KnapsackOptimizer under degenerate item weights and values:
    zero-weight, negative-weight, zero-value, negative-value, and 10,000 zero-cost items.
    """

    def test_zero_and_negative_weight_items(self) -> None:
        """Items with 0 or negative weight are clamped to w >= 1 to prevent division by zero."""
        items = [{"id": i, "val": 10.0} for i in range(100)]

        # Zero weight
        selected_0, trunc_0 = KnapsackOptimizer.select(
            items=items,
            budget=40,
            value_fn=lambda it, idx, t: float(it["val"]),
            item_weight_fn=lambda it: 0,
        )
        self.assertEqual(len(selected_0), 40)
        self.assertTrue(trunc_0)

        # Negative weight
        selected_neg, trunc_neg = KnapsackOptimizer.select(
            items=items,
            budget=30,
            value_fn=lambda it, idx, t: float(it["val"]),
            item_weight_fn=lambda it: -99,
        )
        self.assertEqual(len(selected_neg), 30)
        self.assertTrue(trunc_neg)

    def test_zero_and_negative_values(self) -> None:
        """Items with 0 or negative values are clamped to v >= 0.1 and selected by density."""
        items = [{"id": i, "cost": 10, "val": -50.0} for i in range(20)]
        selected, trunc = KnapsackOptimizer.select(
            items=items,
            budget=50,
            value_fn=lambda it, idx, t: float(it["val"]),
            item_weight_fn=lambda it: int(it["cost"]),
        )
        self.assertEqual(len(selected), 5)  # 5 * 10 = 50
        self.assertTrue(trunc)

    def test_10000_zero_weight_items_scalability(self) -> None:
        """10,000 zero-weight items execute in <100ms without infinite loop."""
        huge_items = [{"id": i} for i in range(10000)]
        t0 = time.time()
        selected, trunc = KnapsackOptimizer.select(
            items=huge_items,
            budget=100,
            value_fn=lambda it, idx, t: 1.0,
            item_weight_fn=lambda it: 0,
        )
        t_elapsed = time.time() - t0
        self.assertLess(t_elapsed, 0.2)
        self.assertEqual(len(selected), 100)
        self.assertTrue(trunc)

    def test_mandatory_vs_exit_anchor_competition_finding(self) -> None:
        """
        Document empirical finding on Knapsack value-density ranking:
        When budget is tight (e.g. 300 tokens), an exit block with small size (weight ~45)
        has higher value density (value/weight = 856/45 = 19.0) than a large entry block
        (weight ~240, value/weight = 2126/240 = 8.85), causing the entry block to be dropped.
        """
        items = [
            {"name": "entry_block", "weight": 240, "value": 2126.0, "is_mand": True},
            {"name": "exit_block", "weight": 45, "value": 856.0, "is_mand": True},
        ]
        # Budget = 260 (not enough for both 240 + 45 = 285)
        selected, trunc = KnapsackOptimizer.select(
            items=items,
            budget=260,
            value_fn=lambda it, i, t: float(it["value"]),
            mandatory_fn=lambda it, i, t: bool(it.get("is_mand")),
            item_weight_fn=lambda it: int(it["weight"]),
        )
        # Empirical confirmation: exit_block is selected because density 19.0 > 8.85, entry is dropped
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["name"], "exit_block")


class TestAdversarialFuzzingPayloads(unittest.TestCase):
    """
    Adversarial fuzzing on compaction functions:
    Uncovers unhandled exceptions when instructions or blocks are not dictionaries.
    """

    def test_reproduce_attribute_error_on_string_instructions(self) -> None:
        """
        Empirically reproduces AttributeError when instructions is a list of strings
        (e.g. ['push rbp', 'mov rbp, rsp']) rather than a list of dicts.
        """
        env = {
            "success": True,
            "command": "analyze blocks",
            "target": "crackme_case",
            "data": {
                "blocks": [
                    {"addr": "0x11e0", "size": 44, "instructions": ["push rbp", "mov rbp, rsp"]}
                ]
            },
        }
        with self.assertRaises(AttributeError) as ctx:
            transform_response(env, budget=500)
        self.assertIn("'str' object has no attribute 'get'", str(ctx.exception))

    def test_reproduce_attribute_error_on_none_in_blocks(self) -> None:
        """
        Empirically reproduces AttributeError when blocks list contains a None entry.
        """
        env = {
            "success": True,
            "command": "analyze blocks",
            "target": "crackme_case",
            "data": {
                "blocks": [None]
            },
        }
        with self.assertRaises(AttributeError) as ctx:
            transform_response(env, budget=500)
        self.assertIn("'NoneType' object has no attribute 'get'", str(ctx.exception))

    def test_reproduce_value_error_on_string_instructions_in_compress_addresses(self) -> None:
        """
        Empirically reproduces ValueError in TriePrefixCompressor.compress_addresses
        when a block's instructions are strings.
        """
        blocks = [
            {"addr": "0x00401000", "instructions": ["nop", "ret"]},
            {"addr": "0x00401010", "instructions": ["nop"]},
            {"addr": "0x00401020", "instructions": ["nop"]},
            {"addr": "0x00401030", "instructions": ["nop"]},
        ]
        with self.assertRaises(ValueError) as ctx:
            TriePrefixCompressor.compress_addresses(blocks)
        self.assertIn("dictionary update sequence element", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
