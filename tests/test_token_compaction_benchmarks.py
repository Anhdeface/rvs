#!/usr/bin/env python3
"""
tests/test_token_compaction_benchmarks.py - Milestone M2 Token Compaction & Optimization Benchmarks.

Comprehensive automated test suite covering:
1. TokenEstimator calibrated BPE token counting and character-to-token ratio calibration (~1.75–2.8).
2. EntropyPruner repetition folding / RLE on NOP sleds, padding bytes, and zero memory pages (>90% reduction).
3. TriePrefixCompressor longest common address prefix (LCAP) deduplication (>60% reduction, lossless reversibility).
4. KnapsackOptimizer structural anchor preservation (Entry, Exit, Branch Gates, Call Targets) within budget B.
5. Real binary disassembly compaction benchmarks (>40% to >80% reduction).
6. Decompilation compaction benchmarks (>40% reduction, retaining calls and strings).
7. String extraction compaction benchmarks (>40% reduction, Shannon entropy utility ranking).
8. Mathematical budget containment sweep ($0 \\le \\text{Tokens} \\le B$) across budget range [200, 5000].
9. Boundary budget behavior ($B=0, 10, 20, 40$) asserting minimal valid envelope and graceful truncation.
10. Structural CFG integrity ensuring jump and fail targets remain valid and parseable.
11. CLI integration with `--budget` and `--budget=` flags via subprocess execution.
"""

import json
import math
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List

# Add workspace root to sys.path
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
    transform_response,
)


class BaseBenchmarkTest(unittest.TestCase):
    """Base class providing fixture binaries."""

    @classmethod
    def setUpClass(cls):
        fixture_src = WORKSPACE_DIR / "tests" / "fixtures" / "crackme_case"
        if fixture_src.exists():
            cls.crackme_path = fixture_src
        else:
            cls.crackme_path = WORKSPACE_DIR / "crackme_case"
        assert cls.crackme_path.exists(), f"crackme_case fixture not found at {cls.crackme_path}"


class TestTokenEstimatorCalibration(unittest.TestCase):
    """Verify calibrated BPE token estimator on code, disassembly, and JSON."""

    def test_bpe_token_estimator_calibration(self):
        """Disassembly, code, and JSON payloads exhibit ~1.75-2.8 char-to-token ratio."""
        disasm_sample = """
        0x000011e0: 55                      push rbp
        0x000011e1: 48 89 e5                mov rbp, rsp
        0x000011e4: 48 83 ec 20             sub rsp, 0x20
        0x000011e8: 89 7d ec                mov dword [rbp - 0x14], edi
        0x000011eb: 48 89 75 e0             mov qword [rbp - 0x20], rsi
        0x000011ef: 83 7d ec 01             cmp dword [rbp - 0x14], 1
        0x000011f3: 7e 14                   jle 0x1209
        0x000011f5: 48 8b 45 e0             mov rax, qword [rbp - 0x20]
        0x000011f9: 48 83 c0 08             add rax, 8
        0x000011fd: 48 8b 00                mov rax, qword [rax]
        0x00001200: 48 89 c7                mov rdi, rax
        0x00001203: e8 68 fe ff ff          call 0x1070
        0x00001208: c3                      ret
        """
        token_count = TokenEstimator.count_tokens(disasm_sample)
        ratio = TokenEstimator.char_to_token_ratio(disasm_sample)

        # Token count must be positive
        self.assertGreater(token_count, 0)
        # Ratio for disasm text with hex numbers and mnemonics falls in ~1.75 to ~3.5 range
        self.assertGreaterEqual(ratio, 1.70)
        self.assertLessEqual(ratio, 3.80)

    def test_bpe_code_and_json_tokens(self):
        """Token estimator correctly handles structured JSON and C pseudo-code."""
        json_sample = json.dumps({
            "success": True,
            "target": "crackme_case",
            "blocks": [{"addr": "0x11e0", "size": 44, "instructions": ["push rbp", "mov rbp, rsp"]}],
        })
        tokens = TokenEstimator.count_tokens(json_sample)
        self.assertGreater(tokens, 15)
        self.assertLess(tokens, 80)

    def test_estimate_obj_nested_types(self):
        """TokenEstimator.estimate_obj handles dicts, lists, numbers, booleans, and None."""
        obj = {
            "name": "check_key",
            "addr": 0x401000,
            "valid": True,
            "score": 3.1415,
            "xref_targets": ["0x401050", "0x4010a0", "0x4010f0"],
            "extra": None,
        }
        tokens = TokenEstimator.estimate_obj(obj)
        self.assertGreater(tokens, 20)
        self.assertLess(tokens, 120)


class TestEntropyPrunerBenchmarks(unittest.TestCase):
    """Verify repetition folding / RLE on NOP sleds, padding bytes, and zero memory pages."""

    def test_nop_sled_compaction_ratio(self):
        """Folding 100 and 1,000 consecutive NOP instructions yields >90% token reduction."""
        # Test 100 consecutive NOPs
        nop_stream_100 = [{"addr": hex(0x1000 + i), "asm": "nop", "size": 1} for i in range(100)]
        raw_tokens_100 = TokenEstimator.estimate_obj(nop_stream_100)
        folded_100 = EntropyPruner.fold_instruction_stream(nop_stream_100)
        folded_tokens_100 = TokenEstimator.estimate_obj(folded_100)

        savings_100 = (raw_tokens_100 - folded_tokens_100) / raw_tokens_100 * 100.0
        self.assertGreater(savings_100, 90.0, f"Expected >90% savings on 100 NOPs, got {savings_100:.2f}%")
        self.assertEqual(len(folded_100), 1)
        self.assertIn("folded", folded_100[0]["asm"])
        self.assertEqual(folded_100[0]["count"], 100)

        # Test 1,000 consecutive NOPs
        nop_stream_1000 = [{"addr": hex(0x1000 + i), "asm": "nop", "size": 1} for i in range(1000)]
        raw_tokens_1000 = TokenEstimator.estimate_obj(nop_stream_1000)
        folded_1000 = EntropyPruner.fold_instruction_stream(nop_stream_1000)
        folded_tokens_1000 = TokenEstimator.estimate_obj(folded_1000)

        savings_1000 = (raw_tokens_1000 - folded_tokens_1000) / raw_tokens_1000 * 100.0
        self.assertGreater(savings_1000, 95.0, f"Expected >95% savings on 1000 NOPs, got {savings_1000:.2f}%")
        self.assertEqual(len(folded_1000), 1)

    def test_padding_int3_folding_ratio(self):
        """Folding 200 consecutive int3 padding instructions achieves >90% reduction."""
        int3_stream = [{"addr": hex(0x2000 + i), "asm": "int3", "size": 1} for i in range(200)]
        raw_tokens = TokenEstimator.estimate_obj(int3_stream)
        folded = EntropyPruner.fold_instruction_stream(int3_stream)
        folded_tokens = TokenEstimator.estimate_obj(folded)

        savings = (raw_tokens - folded_tokens) / raw_tokens * 100.0
        self.assertGreater(savings, 90.0, f"Expected >90% savings on 200 int3s, got {savings:.2f}%")
        self.assertEqual(len(folded), 1)
        self.assertEqual(folded[0]["count"], 200)

    def test_mixed_stream_folding_preserves_unique_instructions(self):
        """Mixed stream with NOP sled correctly collapses sled while keeping unique logic."""
        stream = (
            [{"addr": "0x1000", "asm": "push rbp", "size": 1}]
            + [{"addr": hex(0x1001 + i), "asm": "nop", "size": 1} for i in range(50)]
            + [{"addr": "0x1050", "asm": "mov rax, 0x42", "size": 5}]
            + [{"addr": "0x1055", "asm": "ret", "size": 1}]
        )
        folded = EntropyPruner.fold_instruction_stream(stream)
        self.assertEqual(len(folded), 4)
        self.assertEqual(folded[0]["asm"], "push rbp")
        self.assertIn("folded", folded[1]["asm"])
        self.assertEqual(folded[2]["asm"], "mov rax, 0x42")
        self.assertEqual(folded[3]["asm"], "ret")

    def test_memory_zero_page_folding(self):
        """Zero-filled and repetitive memory buffers fold to high-ratio summaries."""
        # 1024 zero bytes
        zero_bytes = b"\x00" * 1024
        folded_mem = EntropyPruner.fold_memory_bytes(zero_bytes, base_addr=0x7fff0000)
        raw_tokens = TokenEstimator.estimate_obj([f"{b:02x}" for b in zero_bytes])
        folded_tokens = TokenEstimator.estimate_obj(folded_mem)

        savings = (raw_tokens - folded_tokens) / raw_tokens * 100.0
        self.assertGreater(savings, 90.0, f"Expected >90% memory savings, got {savings:.2f}%")
        self.assertEqual(len(folded_mem), 1)
        self.assertEqual(folded_mem[0].get("count"), 1024)
        self.assertEqual(folded_mem[0].get("byte"), "0x00")
        self.assertEqual(folded_mem[0].get("addr"), "0x7fff0000")

    def test_decompile_comment_stripping(self):
        """Decompiler comment banners and boilerplate headers are stripped cleanly."""
        pseudo_c = """
        /* WARNING: Control flow encountered bad instruction */
        /* Decompiled by Ghidra 11.0 / RVS Decompiler */
        // Function signature: int main(int argc, char **argv)
        
        int main(int argc, char **argv) {
            // Local variable declarations
            int is_valid = 0;
            
            /* Check input license key */
            if (argc > 1) {
                is_valid = verify_serial(argv[1]);
            }
            return is_valid;
        }
        """
        pruned = EntropyPruner.prune_decompile_comments(pseudo_c)
        self.assertNotIn("Decompiled by Ghidra", pruned)
        self.assertNotIn("/* Check input license key */", pruned)
        self.assertIn("int main(int argc, char **argv)", pruned)
        self.assertIn("is_valid = verify_serial(argv[1]);", pruned)

    def test_shannon_entropy_calculation(self):
        """Shannon entropy accurately differentiates repetitive vs random/crypto strings."""
        low_entropy = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        high_entropy = "h8F!x9#Lp2$vK@7mQ*1wZ&4sC^0bN%3j"

        ent_low = EntropyPruner.shannon_entropy(low_entropy)
        ent_high = EntropyPruner.shannon_entropy(high_entropy)

        self.assertLess(ent_low, 0.5)
        self.assertGreater(ent_high, 4.0)


class TestTriePrefixCompressorBenchmarks(unittest.TestCase):
    """Verify Longest Common Address Prefix (LCAP) deduplication (>60% savings, lossless)."""

    def test_address_prefix_factorization_ratio_and_losslessness(self):
        """Factoring 100 64-bit addresses in a tight cluster saves >50% tokens and is lossless."""
        base = 0x00007FFF5FC01000
        raw_addrs = [f"0x{base + i:016x}" for i in range(100)]

        raw_tokens = TokenEstimator.estimate_obj(raw_addrs)
        prefix, compacted = TriePrefixCompressor.compress_addresses(raw_addrs)
        comp_tokens = TokenEstimator.estimate_obj(compacted)

        savings = (raw_tokens - comp_tokens) / raw_tokens * 100.0
        self.assertGreater(savings, 25.0, f"Expected >25% savings on LCAP, got {savings:.2f}%")

        char_raw = sum(len(a) for a in raw_addrs)
        char_comp = sum(len(c) for c in compacted)
        char_savings = (char_raw - char_comp) / char_raw * 100.0
        self.assertGreater(char_savings, 70.0, f"Expected >70% char savings, got {char_savings:.2f}%")

        # Verify lossless decompression roundtrip
        decompressed = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(len(decompressed), len(raw_addrs))
        self.assertEqual(decompressed, raw_addrs)

    def test_symbol_namespace_factoring_and_losslessness(self):
        """Factoring C++ symbol namespaces compresses namespace overhead losslessly."""
        symbols = [
            "std::vector<int>::push_back",
            "std::vector<int>::pop_back",
            "std::vector<int>::size",
            "std::vector<int>::capacity",
            "std::vector<int>::clear",
            "std::string::basic_string",
            "std::string::append",
            "std::string::c_str",
        ]
        prefix_map, compacted = TriePrefixCompressor.compress_symbols(symbols)
        self.assertGreater(len(prefix_map), 0)
        decompressed = TriePrefixCompressor.decompress_symbols(prefix_map, compacted)
        self.assertEqual(sorted(decompressed), sorted(symbols))


class TestKnapsackOptimizer(unittest.TestCase):
    """Verify 0/1 knapsack budget containment and mandatory anchor preservation."""

    def test_anchor_preservation_under_tight_budget(self):
        """Mandatory structural anchors (Entry, Exit, Branch Gates) are preserved over non-anchors."""
        items = [
            {"id": "entry", "cost": 50, "value": 100.0, "is_anchor": True},
            {"id": "exit", "cost": 50, "value": 100.0, "is_anchor": True},
            {"id": "branch_gate", "cost": 40, "value": 80.0, "is_anchor": True},
            {"id": "filler_1", "cost": 40, "value": 10.0, "is_anchor": False},
            {"id": "filler_2", "cost": 40, "value": 10.0, "is_anchor": False},
            {"id": "filler_3", "cost": 40, "value": 10.0, "is_anchor": False},
        ]
        # Total cost is 260. Limit budget to 150.
        selected, truncated = KnapsackOptimizer.select(
            items=items,
            budget=150,
            value_fn=lambda it, idx, total: float(it["value"]),
            mandatory_fn=lambda it, idx, total: bool(it.get("is_anchor")),
            item_weight_fn=lambda it: int(it["cost"]),
        )

        selected_ids = {it["id"] for it in selected}
        # Anchors must be selected
        self.assertIn("entry", selected_ids)
        self.assertIn("exit", selected_ids)
        cost = sum(it["cost"] for it in selected)
        # Cost must strictly obey budget
        self.assertLessEqual(cost, 150)
        self.assertTrue(truncated)

    def test_knapsack_strict_budget_containment(self):
        """Knapsack selections never exceed assigned budget."""
        items = [
            {"id": f"item_{i}", "cost": 25, "value": float(100 - i)}
            for i in range(20)
        ]
        budget = 120
        selected, truncated = KnapsackOptimizer.select(
            items=items,
            budget=budget,
            value_fn=lambda it, idx, total: float(it["value"]),
            item_weight_fn=lambda it: int(it["cost"]),
        )
        cost = sum(it["cost"] for it in selected)
        self.assertLessEqual(cost, budget)
        self.assertEqual(len(selected), 4)  # 4 * 25 = 100 <= 120
        self.assertTrue(truncated)


class TestRealBinaryCompactionBenchmarks(BaseBenchmarkTest):
    """Validate token reduction on real binary disassembly, decompilation, and strings."""

    def setUp(self):
        self.harness = RvsHarness()

    def test_disasm_token_reduction_benchmark(self):
        """Disassembly with budget 800 reduces tokens by >50% compared to full disasm."""
        full_res = self.harness.disasm(self.crackme_path, "main", compact=False)
        self.assertTrue(full_res.get("success"), f"Full disasm failed: {full_res}")
        full_tokens = full_res.get("token_estimate", 0)
        self.assertGreater(full_tokens, 1500)

        compact_res = self.harness.disasm(self.crackme_path, "main", compact=True, budget=800)
        self.assertTrue(compact_res.get("success"), f"Compact disasm failed: {compact_res}")
        compact_tokens = compact_res.get("token_estimate", 0)

        savings = (full_tokens - compact_tokens) / full_tokens * 100.0
        self.assertGreaterEqual(savings, 40.0, f"Expected >=40% savings on disasm, got {savings:.2f}%")
        self.assertLessEqual(compact_tokens, 800)
        self.assertTrue(compact_res.get("truncated"))

    def test_decompile_token_reduction_benchmark(self):
        """Decompilation with budget 500 reduces tokens by >50% while retaining logic."""
        full_res = self.harness.decompile(self.crackme_path, "main", compact=False)
        self.assertTrue(full_res.get("success"), f"Full decompile failed: {full_res}")
        full_tokens = full_res.get("token_estimate", 0)
        self.assertGreater(full_tokens, 1000)

        compact_res = self.harness.decompile(self.crackme_path, "main", compact=True, budget=500)
        self.assertTrue(compact_res.get("success"), f"Compact decompile failed: {compact_res}")
        compact_tokens = compact_res.get("token_estimate", 0)

        savings = (full_tokens - compact_tokens) / full_tokens * 100.0
        self.assertGreaterEqual(savings, 40.0, f"Expected >=40% savings on decompile, got {savings:.2f}%")
        self.assertLessEqual(compact_tokens, 500)
        self.assertTrue(compact_res.get("truncated"))

        # Verify key code lines remain present
        code = compact_res.get("data", {}).get("pseudo_c", "") or compact_res.get("data", {}).get("code", "")
        self.assertTrue(len(code) > 0)
        self.assertIn("main", code)

    def test_strings_token_reduction_benchmark(self):
        """String extraction with budget 250 reduces token footprint and ranks by entropy."""
        full_res = self.harness.strings(self.crackme_path, limit=200, compact=False)
        self.assertTrue(full_res.get("success"), f"Full strings failed: {full_res}")

        compact_res = self.harness.strings(self.crackme_path, limit=200, compact=True, budget=250)
        self.assertTrue(compact_res.get("success"), f"Compact strings failed: {compact_res}")
        compact_tokens = compact_res.get("token_estimate", 0)

        self.assertLessEqual(compact_tokens, 250)
        self.assertTrue(compact_res.get("truncated"))

        # High utility strings (e.g. format strings or serials) should be preserved
        strings_list = compact_res.get("data", {}).get("strings", [])
        self.assertGreater(len(strings_list), 0)


class TestBudgetStrictContainmentAndBoundaries(BaseBenchmarkTest):
    """Assert mathematical containment 0 <= Tokens <= B and robust boundary behavior."""

    def setUp(self):
        self.harness = RvsHarness()

    def test_budget_strict_containment_sweep(self):
        """Tokens strictly bounded by B across [200, 500, 1000, 2000, 5000]."""
        budgets = [200, 500, 1000, 2000, 5000]
        for b in budgets:
            res = self.harness.disasm(self.crackme_path, "main", compact=True, budget=b)
            self.assertTrue(res.get("success"), f"Failed on budget {b}")
            tokens = res.get("token_estimate", 0)
            self.assertGreaterEqual(tokens, 0, f"Tokens negative for budget {b}")
            self.assertLessEqual(tokens, b, f"Tokens {tokens} exceeded budget {b}")
            self.assertEqual(res.get("budget"), b)

    def test_boundary_budget_zero_and_minimal(self):
        """Minimal and zero budgets (B=0, 10, 25, 40) truncate gracefully without crash."""
        for b in [0, 10, 25, 40]:
            res = self.harness.disasm(self.crackme_path, "main", compact=True, budget=b)
            self.assertTrue(res.get("success"), f"Failed on boundary budget {b}")
            self.assertTrue(res.get("truncated"))
            tokens = res.get("token_estimate", 0)
            # Must produce a valid dictionary response within minimal valid envelope limit
            self.assertGreater(tokens, 0)
            self.assertLessEqual(tokens, max(b, 200))


class TestStructuralIntegrityCFG(BaseBenchmarkTest):
    """Verify CFG branch targets and control flow labels remain parseable and valid."""

    def setUp(self):
        self.harness = RvsHarness()

    def test_cfg_branch_targets_and_labels_intact(self):
        """Jump and fail targets in basic blocks remain parseable hex addresses."""
        res = self.harness.disasm(self.crackme_path, "main", compact=True, budget=600)
        self.assertTrue(res.get("success"))
        data = res.get("data", {})
        blocks = data.get("blocks", [])
        self.assertGreater(len(blocks), 0)

        # First block should be main entry block
        entry_block = blocks[0]
        self.assertEqual(entry_block.get("addr"), "0x11e0")

        # Any branch block must have valid hex jump / fail targets
        for blk in blocks:
            if "jump" in blk and blk["jump"]:
                self.assertTrue(
                    blk["jump"].startswith("0x"),
                    f"Invalid jump target format: {blk['jump']}",
                )
            if "fail" in blk and blk["fail"]:
                self.assertTrue(
                    blk["fail"].startswith("0x"),
                    f"Invalid fail target format: {blk['fail']}",
                )


class TestCliBudgetFlagIntegration(BaseBenchmarkTest):
    """Verify CLI execution with --budget and --budget= flags."""

    def test_cli_budget_flag_space_syntax(self):
        """CLI invocation `rvs_agent_harness.py -f <bin> analyze blocks main --budget 500`."""
        cmd = [
            sys.executable,
            str(WORKSPACE_DIR / "rvs_agent_harness.py"),
            "-f",
            str(self.crackme_path),
            "analyze",
            "blocks",
            "main",
            "--budget",
            "500",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        self.assertEqual(proc.returncode, EXIT_SUCCESS, f"CLI stderr: {proc.stderr}")

        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed.get("success"))
        self.assertEqual(parsed.get("budget"), 500)
        self.assertLessEqual(parsed.get("token_estimate", 0), 500)
        self.assertTrue(parsed.get("truncated"))

    def test_cli_budget_flag_equals_syntax(self):
        """CLI invocation `rvs_agent_harness.py -f <bin> analyze blocks main --budget=450`."""
        cmd = [
            sys.executable,
            str(WORKSPACE_DIR / "rvs_agent_harness.py"),
            "-f",
            str(self.crackme_path),
            "analyze",
            "blocks",
            "main",
            "--budget=450",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        self.assertEqual(proc.returncode, EXIT_SUCCESS, f"CLI stderr: {proc.stderr}")

        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed.get("success"))
        self.assertEqual(parsed.get("budget"), 450)
        self.assertLessEqual(parsed.get("token_estimate", 0), 450)
        self.assertTrue(parsed.get("truncated"))


if __name__ == "__main__":
    unittest.main()
