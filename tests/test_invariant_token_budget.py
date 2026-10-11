"""tests/test_invariant_token_budget.py - Token Budget Monotonicity Property-Based Suite.

Formal Invariant Verification (R3 Invariant 2):
1. Strict Budget Bound:
   For any payload D in Domain and budget B >= 1:
       0 <= Tokens(Compactor(D, B)) <= max(B, B_min)
2. Budget Monotonicity:
   For any B1 <= B2:
       Tokens(Compactor(D, B1)) <= Tokens(Compactor(D, B2))
   across all budgets including the zero boundary B <= 0 -> B = 1.
3. Knapsack Non-Expansion (Contraction Invariant):
   For raw response D_raw and compact response D_compact:
       Tokens(D_compact) <= Tokens(D_raw) + O(1)
4. Structural Integrity & JSON Roundtrip:
   json.loads(json.dumps(Compactor(D, B))) == Compactor(D, B)
   Retained blocks preserve valid hex addresses and branch targets (jump, fail).
"""

import json
import random
import unittest
from typing import Any, Dict, List

from rvs_agent_harness import (
    EntropyPruner,
    RvsHarness,
    TokenEstimator,
    TriePrefixCompressor,
    prune_blocks,
    prune_functions,
    prune_strings,
    prune_symbols,
    transform_response,
)


def generate_synthetic_cfg_payload(seed: int, num_blocks: int = 25) -> Dict[str, Any]:
    """Generates a deterministic synthetic disasm CFG payload with realistic control flow."""
    rng = random.Random(seed)
    blocks: List[Dict[str, Any]] = []
    base_addr = 0x00401000 + (seed % 100) * 0x10000

    mnemonics = [
        ("mov eax, 1", 5),
        ("xor edx, edx", 2),
        ("add rcx, 8", 4),
        ("cmp eax, 0", 3),
        ("test rdi, rdi", 3),
        ("nop", 1),
        ("push rbp", 1),
        ("pop rbp", 1),
        ("call 0x00402000", 5),
    ]

    for i in range(num_blocks):
        block_addr = base_addr + i * 64
        inst_count = rng.randint(2, 12)
        insts = []
        cur_offset = 0
        for j in range(inst_count):
            asm, sz = rng.choice(mnemonics)
            if j == inst_count - 1 and i == num_blocks - 1:
                asm, sz = "ret", 1
            insts.append({
                "addr": f"0x{block_addr + cur_offset:x}",
                "asm": asm,
                "size": sz,
            })
            cur_offset += sz

        jump_target = f"0x{base_addr + (i + 1) * 64:x}" if i < num_blocks - 1 else None
        fail_target = f"0x{base_addr + (i + 2) * 64:x}" if i < num_blocks - 2 and rng.random() > 0.5 else None

        blocks.append({
            "addr": f"0x{block_addr:x}",
            "size": cur_offset,
            "instructions": insts,
            "jump": jump_target,
            "fail": fail_target,
        })

    return {
        "success": True,
        "command": "disasm",
        "target": f"/test/bin_seed_{seed}",
        "data": {
            "function": f"sym.func_{seed}",
            "addr": f"0x{base_addr:x}",
            "blocks": blocks,
            "total_blocks": len(blocks),
        },
    }


def generate_synthetic_functions_payload(seed: int, count: int = 50) -> Dict[str, Any]:
    """Generates a deterministic functions response envelope."""
    rng = random.Random(seed)
    funcs = []
    for i in range(count):
        addr = 0x00401000 + i * 0x200
        funcs.append({
            "name": f"sym.sub_{addr:x}",
            "addr": f"0x{addr:x}",
            "size": rng.randint(16, 1024),
            "nbbs": rng.randint(1, 20),
            "is_imported": rng.random() > 0.8,
        })
    return {
        "success": True,
        "command": "functions",
        "target": f"/test/bin_{seed}",
        "data": {
            "functions": funcs,
            "total": len(funcs),
        },
    }


def generate_synthetic_strings_payload(seed: int, count: int = 60) -> Dict[str, Any]:
    """Generates a deterministic strings response envelope with variable entropy."""
    rng = random.Random(seed)
    strings = []
    for i in range(count):
        addr = 0x00408000 + i * 32
        length = rng.randint(4, 40)
        # Random mix of printable characters
        content = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789_./-", k=length))
        strings.append({
            "vaddr": f"0x{addr:x}",
            "string": content,
            "length": length,
            "type": "ascii",
        })
    return {
        "success": True,
        "command": "strings",
        "target": f"/test/bin_{seed}",
        "data": {
            "strings": strings,
            "total": len(strings),
        },
    }


class TestInvariantTokenBudget(unittest.TestCase):
    """Property-based verification of Invariant 2 (Token Budget Monotonicity & Knapsack Boundedness)."""

    def test_01_property_bounded_token_budget_across_50_seeds(self) -> None:
        """Invariant 2.1: 0 <= Tokens(C(D, B)) <= max(B, B_min) across 50 seeds and pathological budgets."""
        pathological_budgets = [-100, 0, 1, 10, 50, 100, 250, 500, 1000, 5000]

        for seed in range(50):
            payload = generate_synthetic_cfg_payload(seed=seed, num_blocks=20)
            base_floor = 210  # Upper bound on minimal envelope skeleton floor

            for budget in pathological_budgets:
                compacted = transform_response(payload, mode="compact", budget=budget)
                tokens = TokenEstimator.estimate_obj(compacted)
                allowed_upper_bound = max(budget, base_floor)

                self.assertGreaterEqual(
                    tokens, 0,
                    f"Seed {seed}, Budget {budget}: tokens ({tokens}) must be non-negative",
                )
                self.assertLessEqual(
                    tokens, allowed_upper_bound,
                    f"Seed {seed}, Budget {budget}: tokens ({tokens}) exceeded upper bound ({allowed_upper_bound})",
                )

    def test_02_property_budget_monotonicity_across_50_seeds(self) -> None:
        """Invariant 2.2: B1 <= B2 ==> Tokens(C(D, B1)) <= Tokens(C(D, B2)) across 50 seeds."""
        budgets = [1, 50, 150, 250, 400, 600, 900, 1500, 3000]

        for seed in range(50):
            payload = generate_synthetic_cfg_payload(seed=seed, num_blocks=25)
            prev_tok = -1

            for b in budgets:
                compacted = transform_response(payload, mode="compact", budget=b)
                tok = TokenEstimator.estimate_obj(compacted)

                if prev_tok != -1:
                    self.assertLessEqual(
                        prev_tok, tok,
                        f"Seed {seed}: Monotonicity violation: Tokens(B={prev_b})={prev_tok} > Tokens(B={b})={tok}",
                    )
                prev_tok = tok
                prev_b = b

    def test_03_property_zero_boundary_monotonicity_across_50_seeds(self) -> None:
        """Invariant 2.2b: Monotonicity strictly holds across the zero boundary: B = 0 -> B = 1 -> B > 1.
        Also asserts data payload tokens are monotonic across negative budgets to B=1."""
        zero_boundary_budgets = [0, 1, 10, 50, 100]

        for seed in range(50):
            payload = generate_synthetic_cfg_payload(seed=seed, num_blocks=15)
            prev_tokens = -1
            prev_b = None

            for b in zero_boundary_budgets:
                compacted = transform_response(payload, mode="compact", budget=b)
                toks = TokenEstimator.estimate_obj(compacted)

                if prev_tokens != -1:
                    self.assertLessEqual(
                        prev_tokens, toks,
                        f"Seed {seed}: Zero boundary inversion! B={prev_b} ({prev_tokens} toks) > B={b} ({toks} toks)",
                    )
                prev_tokens = toks
                prev_b = b

            # Verify data payload tokens across negative to positive boundary
            data_neg = transform_response(payload, mode="compact", budget=-50).get("data", {})
            data_zero = transform_response(payload, mode="compact", budget=0).get("data", {})
            data_one = transform_response(payload, mode="compact", budget=1).get("data", {})
            self.assertLessEqual(TokenEstimator.estimate_obj(data_neg), TokenEstimator.estimate_obj(data_zero))
            self.assertLessEqual(TokenEstimator.estimate_obj(data_zero), TokenEstimator.estimate_obj(data_one))

    def test_04_property_knapsack_non_expansion_across_50_seeds(self) -> None:
        """Invariant 2.3: Compaction never expands token footprint: Tokens(compact) <= Tokens(full)."""
        for seed in range(50):
            payload = generate_synthetic_cfg_payload(seed=seed, num_blocks=18)
            full_resp = transform_response(payload, mode="full")
            compact_resp = transform_response(payload, mode="compact")

            tok_full = TokenEstimator.estimate_obj(full_resp)
            tok_compact = TokenEstimator.estimate_obj(compact_resp)

            self.assertLessEqual(
                tok_compact, tok_full,
                f"Seed {seed}: Expansion violation! Compact ({tok_compact}) > Full ({tok_full})",
            )

    def test_05_property_cfg_structural_integrity_across_50_seeds(self) -> None:
        """Invariant 2.4: Retained blocks preserve hex addresses, valid instructions, and branch targets."""
        for seed in range(50):
            payload = generate_synthetic_cfg_payload(seed=seed, num_blocks=20)
            # Budget forces knapsack pruning down to a small subset
            compacted = transform_response(payload, mode="compact", budget=400)
            data = compacted.get("data", {})
            blocks = data.get("blocks", [])

            for b in blocks:
                self.assertIsInstance(b, dict)
                addr = b.get("addr")
                self.assertTrue(
                    isinstance(addr, str) and (addr.startswith("0x") or addr.startswith("+")),
                    f"Seed {seed}: Malformed block address: {addr}",
                )
                if "jump" in b and b["jump"] is not None:
                    jmp = b["jump"]
                    self.assertTrue(
                        isinstance(jmp, str) and (jmp.startswith("0x") or jmp.startswith("+")),
                        f"Seed {seed}: Malformed jump target: {jmp}",
                    )
                if "fail" in b and b["fail"] is not None:
                    fail = b["fail"]
                    self.assertTrue(
                        isinstance(fail, str) and (fail.startswith("0x") or fail.startswith("+")),
                        f"Seed {seed}: Malformed fail target: {fail}",
                    )
                insts = b.get("instructions", [])
                for inst in insts:
                    self.assertIsInstance(inst, dict)
                    self.assertIn("asm", inst)

    def test_06_property_json_roundtrip_validity_across_50_seeds(self) -> None:
        """Invariant 2.5: Compacted payloads serialize and deserialize losslessly via json.loads(dumps)."""
        rng = random.Random(42)
        for seed in range(50):
            payload = generate_synthetic_cfg_payload(seed=seed, num_blocks=15)
            budget = rng.choice([0, 10, 50, 150, 300, 500, 1000])
            compacted = transform_response(payload, mode="compact", budget=budget)

            serialized = json.dumps(compacted)
            deserialized = json.loads(serialized)
            self.assertEqual(
                compacted, deserialized,
                f"Seed {seed}, Budget {budget}: JSON roundtrip deserialization mismatch",
            )

    def test_07_property_entropy_pruning_linear_efficiency(self) -> None:
        """Invariant 2.6: NOP sleds and padding sequences fold with >90% token savings."""
        for count in [50, 100, 500, 2000]:
            instructions = [
                {"addr": f"0x{0x1000 + i:x}", "asm": "nop", "size": 1}
                for i in range(count)
            ]
            raw_tokens = TokenEstimator.estimate_obj(instructions)
            folded = EntropyPruner.fold_instruction_stream(instructions)
            folded_tokens = TokenEstimator.estimate_obj(folded)

            self.assertEqual(len(folded), 1)
            self.assertEqual(folded[0]["count"], count)
            self.assertEqual(folded[0]["size"], count)

            reduction_ratio = 1.0 - (folded_tokens / raw_tokens)
            self.assertGreater(
                reduction_ratio, 0.90,
                f"Count {count}: Expected >90% token reduction, got {reduction_ratio * 100:.2f}%",
            )

    def test_08_property_prefix_deduplication_lossless_roundtrip(self) -> None:
        """Invariant 2.7: Address and symbol prefix compression roundtrips losslessly."""
        for seed in range(25):
            rng = random.Random(seed)
            base = 0x7fff5fbff000
            addrs = [f"0x{base + rng.randint(0, 0xFFF):x}" for _ in range(20)]

            prefix, comp = TriePrefixCompressor.compress_addresses(addrs)
            if prefix:
                restored = TriePrefixCompressor.decompress_addresses(prefix, comp)
                self.assertEqual(
                    restored, addrs,
                    f"Seed {seed}: Address decompression roundtrip failed",
                )

            sym_base = "sym.imp.libc.so.6."
            symbols = [f"{sym_base}func_{rng.randint(1, 100)}" for _ in range(15)]
            pmap, scomp = TriePrefixCompressor.compress_symbols(symbols)
            if pmap:
                s_restored = TriePrefixCompressor.decompress_symbols(pmap, scomp)
                self.assertEqual(
                    s_restored, symbols,
                    f"Seed {seed}: Symbol decompression roundtrip failed",
                )

    def test_09_property_pagination_metadata_consistency(self) -> None:
        """Invariant 2.8: Pagination navigation metadata satisfies displayed + remaining <= total."""
        for seed in range(30):
            fn_payload = generate_synthetic_functions_payload(seed=seed, count=40)
            res = prune_functions(fn_payload["data"], mode="compact", budget=300)

            total = res.get("total", 0)
            displayed = res.get("displayed", 0)
            remaining = res.get("remaining", 0)

            self.assertLessEqual(
                displayed + remaining, total,
                f"Seed {seed}: Pagination inconsistency: {displayed} + {remaining} > {total}",
            )
            if res.get("truncated"):
                self.assertEqual(displayed + remaining, total)

    def test_10_pathological_boundary_inputs(self) -> None:
        """Invariant 2.9: Extreme boundary inputs (empty, massive, negative, huge budget) do not crash."""
        # Empty dict
        empty_env = {"success": True, "command": "info", "target": "t", "data": {}}
        res_empty = transform_response(empty_env, mode="compact", budget=50)
        self.assertTrue(res_empty.get("success"))

        # Extreme budget B = 10,000,000
        payload = generate_synthetic_cfg_payload(seed=1, num_blocks=10)
        res_huge = transform_response(payload, mode="compact", budget=10_000_000)
        self.assertFalse(res_huge.get("truncated", False))

        # Negative budget B = -999999
        res_neg = transform_response(payload, mode="compact", budget=-999999)
        self.assertTrue(res_neg.get("truncated", False))
        self.assertLessEqual(TokenEstimator.estimate_obj(res_neg), 150)

        # 500 basic blocks with tight budget
        massive = generate_synthetic_cfg_payload(seed=999, num_blocks=500)
        res_massive = transform_response(massive, mode="compact", budget=300)
        self.assertTrue(res_massive.get("truncated"))
        self.assertLessEqual(TokenEstimator.estimate_obj(res_massive), 300)

    def test_11_negative_budget_monotonicity_all_commands(self) -> None:
        """Invariant 2.10: Tokens(B1) <= Tokens(B2) for all B1 <= B2 <= 0 across all harness commands."""
        h = RvsHarness()
        for cmd in ["disasm", "functions", "strings", "symbols", "decompile", "flow"]:
            fn = getattr(h, cmd)
            if cmd in ("disasm", "decompile", "flow"):
                r_neg = fn("crackme_case", "main", compact=True, budget=-1)
                r_zero = fn("crackme_case", "main", compact=True, budget=0)
            else:
                r_neg = fn("crackme_case", compact=True, budget=-1)
                r_zero = fn("crackme_case", compact=True, budget=0)

            t_neg = r_neg.get("token_estimate", TokenEstimator.estimate_obj(r_neg))
            t_zero = r_zero.get("token_estimate", TokenEstimator.estimate_obj(r_zero))
            self.assertLessEqual(
                t_neg, t_zero,
                f"Negative budget inversion in {cmd}: Tokens(B=-1)={t_neg} > Tokens(B=0)={t_zero}",
            )

    def test_12_entry_block_preservation_tight_budgets(self) -> None:
        """Invariant 2.11: Function entry block (0x11e0) is preserved across all tight budgets down to B=200."""
        h = RvsHarness()
        for b in [200, 250, 300, 350, 400, 500, 600]:
            res = h.disasm("crackme_case", "main", compact=True, budget=b)
            blocks = res.get("data", {}).get("blocks", [])
            addrs = [blk.get("addr") for blk in blocks]
            self.assertIn(
                "0x11e0", addrs,
                f"Entry block 0x11e0 missing at budget {b}: {addrs}",
            )

    def test_13_fine_grained_budget_monotonicity(self) -> None:
        """Invariant 2.12: Strict monotonicity holds across fine-grained budget pairs in disasm and decompile."""
        h = RvsHarness()
        pairs = [(200, 210), (353, 354), (700, 710), (749, 750), (850, 860)]
        for b1, b2 in pairs:
            t1 = h.disasm("crackme_case", "main", compact=True, budget=b1)["token_estimate"]
            t2 = h.disasm("crackme_case", "main", compact=True, budget=b2)["token_estimate"]
            self.assertLessEqual(
                t1, t2,
                f"Fine-grained monotonicity drop in disasm: Tokens({b1})={t1} > Tokens({b2})={t2}",
            )

        dec370 = h.decompile("crackme_case", "main", compact=True, budget=370)["token_estimate"]
        dec380 = h.decompile("crackme_case", "main", compact=True, budget=380)["token_estimate"]
        self.assertLessEqual(
            dec370, dec380,
            f"Fine-grained monotonicity drop in decompile: Tokens(370)={dec370} > Tokens(380)={dec380}",
        )

    def test_14_dense_sweep_disasm_monotonicity(self) -> None:
        """Invariant 2.13: Dense step=1 sweeps across critical transition windows (340..370, 740..760) have zero drops."""
        h = RvsHarness()
        for budget_range in [range(340, 371), range(740, 761)]:
            prev_tok = -1
            prev_b = None
            for b in budget_range:
                tok = h.disasm("crackme_case", "main", compact=True, budget=b)["token_estimate"]
                if prev_tok != -1:
                    self.assertLessEqual(
                        prev_tok, tok,
                        f"Dense step=1 monotonicity drop in disasm: Tokens(B={prev_b})={prev_tok} > Tokens(B={b})={tok}",
                    )
                prev_tok = tok
                prev_b = b

    def test_15_dense_synthetic_cfg_seeds_monotonicity(self) -> None:
        """Invariant 2.14: Dense sweeps across synthetic CFG seeds (including challenger seeds 2, 4, 6, 9) have zero drops."""
        for seed in [2, 4, 6, 9]:
            payload = generate_synthetic_cfg_payload(seed=seed, num_blocks=25)
            prev_tok = -1
            prev_b = None
            for b in range(200, 801, 10):
                compacted = transform_response(payload, mode="compact", budget=b)
                tok = TokenEstimator.estimate_obj(compacted)
                if prev_tok != -1:
                    self.assertLessEqual(
                        prev_tok, tok,
                        f"Seed {seed}: Dense budget monotonicity drop: Tokens(B={prev_b})={prev_tok} > Tokens(B={b})={tok}",
                    )
                prev_tok = tok
                prev_b = b


if __name__ == "__main__":
    unittest.main()

