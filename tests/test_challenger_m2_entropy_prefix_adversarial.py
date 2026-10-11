"""
tests/test_challenger_m2_entropy_prefix_adversarial.py - Empirical Adversarial Challenge Suite
for Milestone M2: Entropy Pruning, Prefix Compression, and Token Compaction Invariants.

Authored by teamwork_preview_challenger_m2_2 (Entropy & Prefix Compression Adversarial Challenger).

Mission & Verification Scope:
1. Empirically stress-test EntropyPruner and TriePrefixCompressor against adversarial inputs:
   - Mixed alternating instructions (nop, mov, nop, mov, ...).
   - High-entropy cryptographic random strings vs low-entropy padding strings.
   - 64-bit address clusters with disjoint prefixes (mixed 32-bit and 64-bit, non-hex, negative addresses).
   - Verify lossless roundtrip decompression for TriePrefixCompressor (addresses and symbols).
2. Measure and verify actual token savings percentages on real binary disassembly, decompilation, and strings.
3. Validate strict token budget containment invariants on real binary targets.
"""

from __future__ import annotations

import math
import os
import secrets
import unittest
from typing import Any, Dict, List

from rvs_agent_harness import (
    EntropyPruner,
    KnapsackOptimizer,
    RvsHarness,
    TokenEstimator,
    TriePrefixCompressor,
    prune_blocks,
    prune_decompile,
    prune_strings,
)


class TestEntropyPrunerAdversarial(unittest.TestCase):
    """Adversarial stress-testing of EntropyPruner instruction folding, byte folding, and Shannon entropy."""

    def test_alternating_instructions_no_erroneous_folding(self) -> None:
        """
        Adversarial scenario: 100 alternating instructions (nop, mov, nop, mov, ...).
        Asserts that NO non-consecutive instructions are folded, length is exactly preserved,
        and every instruction retains its original address, assembly mnemonic, and size.
        """
        instructions = []
        for i in range(100):
            if i % 2 == 0:
                instructions.append({"addr": hex(0x1000 + i * 2), "asm": "nop", "size": 1})
            else:
                instructions.append({"addr": hex(0x1000 + i * 2), "asm": f"mov eax, {i}", "size": 5})

        folded = EntropyPruner.fold_instruction_stream(instructions)
        self.assertEqual(len(folded), 100, "Alternating instructions must NOT be folded!")
        for orig, res in zip(instructions, folded):
            self.assertEqual(res["addr"], orig["addr"])
            self.assertEqual(res["asm"], orig["asm"])
            self.assertEqual(res["size"], orig["size"])
            self.assertNotIn("folded", res)

    def test_massive_alternating_instructions_scalability(self) -> None:
        """Tests 1,000 alternating instructions for linear scalability and structural preservation."""
        instructions = []
        for i in range(1000):
            asm = "nop" if i % 2 == 0 else "xor eax, eax"
            instructions.append({"addr": hex(0x2000 + i), "asm": asm, "size": 1 if asm == "nop" else 2})

        folded = EntropyPruner.fold_instruction_stream(instructions)
        self.assertEqual(len(folded), 1000)
        self.assertEqual(folded[0]["asm"], "nop")
        self.assertEqual(folded[1]["asm"], "xor eax, eax")

    def test_alternating_padding_mnemonics(self) -> None:
        """
        Adversarial scenario: Alternating distinct padding instructions (nop, int3, pause, align).
        Asserts that distinct padding opcodes are NOT coalesced together.
        """
        ops = ["nop", "int3", "pause", "align", "endbr64", "ud2"]
        instructions = [
            {"addr": hex(0x3000 + i), "asm": ops[i % len(ops)], "size": 1}
            for i in range(30)
        ]
        folded = EntropyPruner.fold_instruction_stream(instructions)
        self.assertEqual(len(folded), 30, "Distinct padding instructions must remain distinct runs of 1!")

    def test_interspersed_padding_runs_and_code(self) -> None:
        """
        Realistic scenario: Repeated padding runs separated by active instruction code:
        [nop x 20] -> [mov] -> [nop x 1] -> [xor] -> [int3 x 15].
        Asserts exact run-length folding of runs >= 2 while leaving single instructions untouched.
        """
        instructions = (
            [{"addr": hex(0x4000 + i), "asm": "nop", "size": 1} for i in range(20)]
            + [{"addr": "0x4014", "asm": "mov eax, [rbp - 4]", "size": 3}]
            + [{"addr": "0x4017", "asm": "nop", "size": 1}]
            + [{"addr": "0x4018", "asm": "xor edx, edx", "size": 2}]
            + [{"addr": hex(0x401a + i), "asm": "int3", "size": 1} for i in range(15)]
        )
        folded = EntropyPruner.fold_instruction_stream(instructions)
        self.assertEqual(len(folded), 5, "Should fold into exactly 5 stream descriptors!")

        # Run 1: nop x 20
        self.assertEqual(folded[0]["addr"], "0x4000")
        self.assertTrue(folded[0].get("folded"))
        self.assertEqual(folded[0].get("count"), 20)
        self.assertEqual(folded[0].get("size"), 20)

        # Item 2: mov
        self.assertEqual(folded[1]["addr"], "0x4014")
        self.assertNotIn("folded", folded[1])

        # Item 3: single nop
        self.assertEqual(folded[2]["addr"], "0x4017")
        self.assertEqual(folded[2]["asm"], "nop")
        self.assertNotIn("folded", folded[2])

        # Item 4: xor
        self.assertEqual(folded[3]["addr"], "0x4018")
        self.assertNotIn("folded", folded[3])

        # Run 5: int3 x 15
        self.assertEqual(folded[4]["addr"], "0x401a")
        self.assertTrue(folded[4].get("folded"))
        self.assertEqual(folded[4].get("count"), 15)
        self.assertEqual(folded[4].get("size"), 15)

    def test_instruction_edge_cases_and_missing_keys(self) -> None:
        """Tests instruction stream folding under missing keys, empty asm, and zero addr."""
        edge_insts = [
            {"addr": 0, "asm": "", "size": None},
            {"addr": 0, "asm": "", "size": 0},
            {"addr_hex": "0x5000", "disasm": "nop"},
            {"addr": "0x5001", "opcode": "nop"},
            {"addr": -1, "asm": "ret"},
        ]
        folded = EntropyPruner.fold_instruction_stream(edge_insts)
        self.assertIsInstance(folded, list)
        self.assertGreater(len(folded), 0)

    def test_shannon_entropy_mathematical_properties(self) -> None:
        """Tests Shannon entropy against exact mathematical limits."""
        # 1. Empty string -> 0.0
        self.assertEqual(EntropyPruner.shannon_entropy(""), 0.0)

        # 2. Monomorphic string (single character repeated) -> 0.0
        self.assertEqual(EntropyPruner.shannon_entropy("A" * 1000), 0.0)
        self.assertEqual(EntropyPruner.shannon_entropy("\x00" * 500), 0.0)

        # 3. Exactly binary alphabet with equal probability -> 1.0 bit
        self.assertEqual(EntropyPruner.shannon_entropy("AB" * 500), 1.0)

        # 4. 4 uniform characters -> log2(4) = 2.0 bits
        self.assertEqual(EntropyPruner.shannon_entropy("ABCD" * 250), 2.0)

        # 5. 16 uniform hex characters -> log2(16) = 4.0 bits
        hex_uniform = "".join(f"{i:x}" for i in range(16)) * 100
        self.assertAlmostEqual(EntropyPruner.shannon_entropy(hex_uniform), 4.0, delta=0.01)

    def test_high_entropy_crypto_vs_low_entropy_padding_pruning(self) -> None:
        """
        Adversarial scenario: Mixed set of high-entropy cryptographic strings,
        security-critical strings, and low-entropy padding strings.
        Asserts that knapsack budgeting under tight limits prioritizes high-entropy strings
        over monomorphic padding.
        """
        crypto_hex = secrets.token_hex(32)
        crypto_b64 = secrets.token_urlsafe(32)

        string_records = [
            {"vaddr": 0x1000, "string": "0" * 80},                       # Entropy = 0.0 (padding)
            {"vaddr": 0x1050, "string": "A" * 80},                       # Entropy = 0.0 (padding)
            {"vaddr": 0x1100, "string": "===================="},         # Entropy = 0.0 (banner delimiter)
            {"vaddr": 0x1200, "string": crypto_hex},                     # Entropy ~ 3.7+ (crypto hash)
            {"vaddr": 0x1300, "string": crypto_b64},                     # Entropy ~ 5.0+ (crypto secret)
            {"vaddr": 0x1400, "string": "flag{algorithmic_token_opt}"},  # Security keyword + medium entropy
            {"vaddr": 0x1500, "string": "https://api.internal/v1/auth"},  # URL / auth keyword
        ]

        # Prune with a tight budget
        res = prune_strings({"strings": string_records}, mode="compact", budget=120)
        self.assertTrue(res["truncated"])
        selected_texts = [s["string"] for s in res["strings"]]

        # Critical security and high-entropy strings must be prioritized
        self.assertIn("flag{algorithmic_token_opt}", selected_texts)
        self.assertIn("https://api.internal/v1/auth", selected_texts)

        # Low-entropy padding must NOT starve out the high-entropy / critical strings
        self.assertNotIn("0" * 80, selected_texts)
        self.assertNotIn("A" * 80, selected_texts)

    def test_fold_memory_bytes_rle_and_non_inflation(self) -> None:
        """
        Tests run-length encoding on repetitive zero pages and byte sequences.
        Specifically verifies:
        1. Non-inflation invariant: For small runs (e.g. 64 bytes) where JSON run descriptors
           would consume more tokens than the raw hex string, folding is skipped to avoid token inflation.
        2. Compaction on large runs: For pages >= 128 bytes (e.g. 512, 1024 bytes), repetitive
           sequences fold into compact descriptors, achieving >90% token reduction.
        3. Byte/bytearray folding.
        """
        # Small run: 64 bytes (128 hex chars = 32 raw tokens vs 44 tokens for JSON dict)
        small_hex = "00" * 64
        small_res = EntropyPruner.fold_memory_bytes(small_hex, min_run_length=8, base_addr=0x400000)
        self.assertIsInstance(small_res, str, "Should preserve raw string to avoid token inflation!")

        # Large run: 512 bytes (1024 hex chars = 256 raw tokens -> folded into 44 tokens)
        large_hex = "00" * 512
        folded_hex = EntropyPruner.fold_memory_bytes(large_hex, min_run_length=8, base_addr=0x400000)
        self.assertIsInstance(folded_hex, list)
        self.assertEqual(len(folded_hex), 1)
        self.assertEqual(folded_hex[0]["byte"], "0x00")
        self.assertEqual(folded_hex[0]["count"], 512)
        self.assertEqual(folded_hex[0]["addr"], "0x400000")

        # 1024 bytes zero page: verify >90% token reduction
        page_hex = "00" * 1024
        raw_tok = TokenEstimator.count_tokens(page_hex)
        page_res = EntropyPruner.fold_memory_bytes(page_hex, min_run_length=8, base_addr=0x400000)
        comp_tok = TokenEstimator.estimate_obj(page_res)
        reduction = ((raw_tok - comp_tok) / raw_tok) * 100.0
        self.assertGreaterEqual(reduction, 90.0, f"Token reduction on 1024-byte zero page should be >= 90%, got {reduction:.1f}%")

        # Bytearray run
        data_bytes = bytes([0xCC] * 32 + [0x90] * 32)
        folded_b = EntropyPruner.fold_memory_bytes(data_bytes, min_run_length=8, base_addr=0x500000)
        self.assertIsInstance(folded_b, list)
        self.assertEqual(len(folded_b), 2)
        self.assertEqual(folded_b[0]["byte"], "0xcc")
        self.assertEqual(folded_b[0]["count"], 32)
        self.assertEqual(folded_b[1]["byte"], "0x90")
        self.assertEqual(folded_b[1]["count"], 32)


class TestTriePrefixCompressorAdversarial(unittest.TestCase):
    """Adversarial stress-testing of TriePrefixCompressor address and symbol compression."""

    def test_clustered_64bit_addresses_lossless_roundtrip(self) -> None:
        """Tests LCAP factoring on clustered 64-bit virtual memory addresses with 100% roundtrip restoration."""
        base = 0x00007FFF5FC00000
        addrs = [f"0x{base + i * 0x40:016x}" for i in range(20)]

        prefix, compacted = TriePrefixCompressor.compress_addresses(addrs)
        self.assertIsNotNone(prefix)
        self.assertTrue(prefix.startswith("0x00007fff5fc0"))
        self.assertEqual(len(compacted), 20)
        for item in compacted:
            self.assertTrue(item.startswith("+"), f"Item {item} should start with '+' offset")

        restored = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(restored, addrs, "Decompressed addresses must exactly match original addresses!")

    def test_disjoint_prefix_addresses_graceful_handling(self) -> None:
        """
        Adversarial scenario: Addresses with disjoint prefixes:
        ['0x100000', '0x200000', '0x300000', '0x400000'].
        Asserts graceful fallback (prefix=None) and exact lossless roundtrip.
        """
        addrs = ["0x100000", "0x200000", "0x300000", "0x400000"]
        prefix, compacted = TriePrefixCompressor.compress_addresses(addrs)
        self.assertIsNone(prefix)
        self.assertEqual(compacted, addrs)

        restored = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(restored, addrs)

    def test_mixed_32bit_and_64bit_addresses(self) -> None:
        """
        Adversarial scenario: Mixed 32-bit short addresses and clustered 64-bit addresses.
        Asserts that short non-matching addresses remain untouched while clustered addresses are factored,
        and roundtrip restoration is 100% lossless.
        """
        addrs = [
            "0x10",
            "0x20",
            "0x00007fff5fc01000",
            "0x00007fff5fc02000",
            "0x00007fff5fc03000",
            "0x00007fff5fc04000",
        ]
        prefix, compacted = TriePrefixCompressor.compress_addresses(addrs)
        self.assertIsNotNone(prefix)
        self.assertEqual(compacted[0], "0x10")
        self.assertEqual(compacted[1], "0x20")
        self.assertEqual(compacted[2], "+1000")

        restored = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(restored, addrs)

    def test_non_hex_and_negative_addresses(self) -> None:
        """
        Adversarial scenario: Addresses containing labels ('loc_entry'), negative hex ('-0x1000'),
        and clustered 64-bit addresses.
        Asserts that non-hex tokens are preserved without corruption and roundtrip is lossless.
        """
        addrs = [
            "loc_entry",
            "sub_unresolved",
            "-0x1000",
            "0x0000555555551000",
            "0x0000555555552000",
            "0x0000555555553000",
            "0x0000555555554000",
        ]
        prefix, compacted = TriePrefixCompressor.compress_addresses(addrs)
        self.assertIsNotNone(prefix)
        self.assertTrue(prefix.startswith("0x000055555555"))

        restored = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(restored, addrs, "Roundtrip restoration must handle non-hex and negative addresses!")

    def test_cfg_block_dictionary_address_roundtrip(self) -> None:
        """
        Tests address prefix compression and roundtrip on structured CFG basic block dictionaries
        with nested instruction lists, branch targets ('jump', 'fail'), and block addresses.
        """
        blocks = [
            {
                "addr": "0x00007fff5fc01000",
                "jump": "0x00007fff5fc01050",
                "fail": "0x00007fff5fc01080",
                "instructions": [
                    {"addr": "0x00007fff5fc01000", "asm": "test eax, eax"},
                    {"addr": "0x00007fff5fc01002", "asm": "jz 0x00007fff5fc01050"},
                ],
            },
            {
                "addr": "0x00007fff5fc01050",
                "jump": None,
                "fail": "external_exit",
                "instructions": [
                    {"addr": "0x00007fff5fc01050", "asm": "mov eax, 1"},
                    {"addr": "0x00007fff5fc01055", "asm": "ret"},
                ],
            },
            {
                "addr": "0x00007fff5fc01080",
                "jump": "-0x2000",
                "fail": None,
                "instructions": [
                    {"addr": "0x00007fff5fc01080", "asm": "xor eax, eax"},
                    {"addr": "0x00007fff5fc01082", "asm": "ret"},
                ],
            },
            {
                "addr": "0x00007fff5fc01090",
                "jump": None,
                "fail": None,
                "instructions": [],
            },
        ]

        prefix, compacted = TriePrefixCompressor.compress_addresses(blocks)
        self.assertIsNotNone(prefix)
        self.assertTrue(compacted[0]["addr"].startswith("+"))
        self.assertTrue(compacted[0]["jump"].startswith("+"))
        self.assertTrue(compacted[0]["instructions"][0]["addr"].startswith("+"))

        # Non-matching jump target 'external_exit' and '-0x2000' must remain intact
        self.assertEqual(compacted[1]["fail"], "external_exit")
        self.assertEqual(compacted[2]["jump"], "-0x2000")

        # Full lossless roundtrip
        restored = TriePrefixCompressor.decompress_addresses(prefix, compacted)
        self.assertEqual(restored, blocks, "CFG basic block roundtrip must be 100% identical!")

    def test_tuple_and_dict_envelope_decompression_support(self) -> None:
        """Tests that decompress_addresses supports direct tuple and envelope dictionary formats."""
        addrs = [f"0x00007fff5fc0{i:04x}" for i in range(10)]
        comp_tuple = TriePrefixCompressor.compress_addresses(addrs)

        # 1. Tuple unpack
        res_from_tuple = TriePrefixCompressor.decompress_addresses(comp_tuple)
        self.assertEqual(res_from_tuple, addrs)

        # 2. Envelope dict
        envelope = {"prefix": comp_tuple[0], "items": comp_tuple[1]}
        res_from_envelope = TriePrefixCompressor.decompress_addresses(envelope)
        self.assertEqual(res_from_envelope, addrs)

    def test_symbols_prefix_deduplication_and_lossless_roundtrip(self) -> None:
        """
        Tests namespace factoring on standard C++ (std::), Java (Lcom/example/),
        and radare2/r2 (sym.imp.) symbol namespaces.
        """
        symbols = [
            "std::string::basic_string",
            "std::string::c_str",
            "std::string::length",
            "std::vector::push_back",
            "std::vector::size",
            "std::vector::capacity",
            "Lcom/example/app/MainActivity;",
            "Lcom/example/app/NetworkHelper;",
            "Lcom/example/app/DatabaseHelper;",
            "sym.imp.malloc",
            "sym.imp.free",
            "sym.imp.__libc_start_main",
            "standalone_function",
            "main",
        ]

        prefix_map, compacted = TriePrefixCompressor.compress_symbols(symbols)
        self.assertGreaterEqual(len(prefix_map), 2)
        self.assertIn("std::string::", prefix_map.values())
        self.assertIn("std::vector::", prefix_map.values())

        # Verify exact roundtrip
        restored = TriePrefixCompressor.decompress_symbols(prefix_map, compacted)
        self.assertEqual(restored, symbols, "Symbol decompress must restore all original names exactly!")

    def test_symbols_dictionary_roundtrip(self) -> None:
        """Tests symbol factoring on dictionary lists with metadata."""
        symbol_dicts = [
            {"name": f"std::vector::elem_{i}", "vaddr": hex(0x1000 + i * 8), "size": 8}
            for i in range(5)
        ] + [
            {"name": f"sym.imp.func_{i}", "vaddr": hex(0x2000 + i * 8), "size": 8}
            for i in range(4)
        ] + [
            {"name": "unmatched_symbol", "vaddr": "0x3000", "size": 16},
            {"other_key": "no_name_field"},
        ]

        prefix_map, compacted = TriePrefixCompressor.compress_symbols(symbol_dicts)
        restored = TriePrefixCompressor.decompress_symbols(prefix_map, compacted)
        self.assertEqual(restored, symbol_dicts)

    def test_sub_threshold_item_counts_noop(self) -> None:
        """
        Tests that when item count is strictly below min_items (e.g. 0, 1, 2, 3):
        TriePrefixCompressor returns prefix=None and leaves items untouched.
        Decompression on (None, items) restores items identically.
        """
        for count in (0, 1, 2, 3):
            raw = [f"0x00007fff5fc0{i:04x}" for i in range(count)]
            prefix, comp = TriePrefixCompressor.compress_addresses(raw, min_items=4)
            self.assertIsNone(prefix)
            self.assertEqual(comp, raw)
            restored = TriePrefixCompressor.decompress_addresses(prefix, comp)
            self.assertEqual(restored, raw)

    def test_heterogeneous_symbol_delimiters_and_dots(self) -> None:
        """
        Tests symbol prefix compression across multiple delimiter styles:
        - C++ namespaces: 'boost::asio::ip::tcp::'
        - Java/Dalvik packages: 'com/google/protobuf/'
        - JVM inner classes: 'com.android.server.am.ActivityManager$Task'
        - r2 prefixes: 'sym.imp.'
        """
        symbols = [
            "boost::asio::ip::tcp::socket",
            "boost::asio::ip::tcp::acceptor",
            "boost::asio::ip::tcp::endpoint",
            "com/google/protobuf/MessageLite;",
            "com/google/protobuf/ByteString;",
            "com/google/protobuf/Parser;",
            "sym.imp.libc.so.6.printf",
            "sym.imp.libc.so.6.scanf",
            "sym.imp.libc.so.6.puts",
        ]
        pmap, comp = TriePrefixCompressor.compress_symbols(symbols)
        self.assertGreaterEqual(len(pmap), 3)
        restored = TriePrefixCompressor.decompress_symbols(pmap, comp)
        self.assertEqual(restored, symbols)

    def test_non_mapping_item_attribute_error_discovery(self) -> None:
        """
        Empirically confirms the edge-case behavior of TriePrefixCompressor:
        When passed a list of non-string, non-mapping items (e.g. integer addresses [1, 2, 3, 4]
        or [None, None, ...]), the compressor expects mapping objects with a .get() method,
        raising AttributeError rather than silently suppressing.
        """
        with self.assertRaises(AttributeError):
            TriePrefixCompressor.compress_addresses([1, 2, 3, 4])

        with self.assertRaises(AttributeError):
            TriePrefixCompressor.compress_symbols([1, 2, 3, 4])


class TestBudgetBoundaryAndMonotonicity(unittest.TestCase):
    """Verifies mathematical boundary limits and token budget monotonicity on real targets."""

    def setUp(self) -> None:
        self.harness = RvsHarness()
        self.target = "crackme_case"

    def test_boundary_budget_zero_and_minimal_floor(self) -> None:
        """
        Boundary scenario: Budget B=0 and B=50.
        Asserts that data is cleanly emptied, truncated=True, and valid JSON envelope is produced.
        """
        if not os.path.exists(self.target):
            return

        resp_zero = self.harness.disasm(self.target, "main", compact=True, budget=0)
        self.assertTrue(resp_zero.get("success"))
        self.assertTrue(resp_zero.get("truncated"))
        self.assertEqual(resp_zero.get("budget"), 0)
        self.assertIsInstance(resp_zero.get("data"), dict)
        self.assertEqual(resp_zero["data"].get("blocks"), [])

        resp_floor = self.harness.disasm(self.target, "main", compact=True, budget=50)
        self.assertTrue(resp_floor.get("success"))
        self.assertTrue(resp_floor.get("truncated"))

    def test_budget_monotonicity(self) -> None:
        """
        Verifies monotonicity invariant:
        For B1 <= B2 <= B3: Tokens(B1) <= Tokens(B2) <= Tokens(B3).
        """
        if not os.path.exists(self.target):
            return

        budgets = [250, 500, 1000]
        tokens = []
        for b in budgets:
            resp = self.harness.disasm(self.target, "main", compact=True, budget=b)
            tok = TokenEstimator.estimate_obj(resp)
            tokens.append(tok)
            self.assertLessEqual(tok, b, f"Token count {tok} must not exceed budget {b}")

        # Assert monotonic growth
        self.assertLessEqual(tokens[0], tokens[1], f"Tokens({budgets[0]})={tokens[0]} should be <= Tokens({budgets[1]})={tokens[1]}")
        self.assertLessEqual(tokens[1], tokens[2], f"Tokens({budgets[1]})={tokens[1]} should be <= Tokens({budgets[2]})={tokens[2]}")


class TestRealBinaryCompactionSavings(unittest.TestCase):
    """
    Empirical measurements of actual token savings percentages on real ELF binaries:
    - crackme_case
    - tests/fixtures/auth_gate_elf64
    - tests/fixtures/test_target_elf64
    """

    def setUp(self) -> None:
        self.harness = RvsHarness()
        self.targets = [
            "crackme_case",
            "tests/fixtures/auth_gate_elf64",
            "tests/fixtures/test_target_elf64",
        ]

    def test_empirical_disassembly_token_savings_and_budget_bounding(self) -> None:
        """
        Verifies that on real binaries:
        1. Compacted mode achieves >40% token reduction compared to raw mode.
        2. Budget constraint (B=500) strictly holds: Tokens <= 500.
        3. Structural CFG anchors remain present.
        """
        for target in self.targets:
            if not os.path.exists(target):
                continue
            with self.subTest(target=target):
                raw = self.harness.disasm(target, "main", compact=False)
                compact = self.harness.disasm(target, "main", compact=True)
                budgeted = self.harness.disasm(target, "main", compact=True, budget=500)

                tok_raw = TokenEstimator.estimate_obj(raw)
                tok_compact = TokenEstimator.estimate_obj(compact)
                tok_budgeted = TokenEstimator.estimate_obj(budgeted)

                self.assertGreater(tok_raw, 0)
                reduction_pct = ((tok_raw - tok_compact) / tok_raw) * 100.0

                # Measured reduction must exceed 40%
                self.assertGreaterEqual(
                    reduction_pct,
                    40.0,
                    f"Disassembly reduction on {target} must be >= 40%, got {reduction_pct:.2f}%",
                )

                # Strict budget bounding
                self.assertLessEqual(
                    tok_budgeted,
                    500,
                    f"Budgeted disassembly token count on {target} must be <= 500, got {tok_budgeted}",
                )
                self.assertTrue(budgeted.get("truncated"))

    def test_empirical_decompilation_token_savings_and_budget_bounding(self) -> None:
        """
        Verifies that on real binaries:
        1. Budgeted decompilation (B=300) achieves >80% reduction compared to raw decompilation.
        2. Budget constraint strictly holds: Tokens <= 300.
        3. Decompilation output remains valid JSON envelope.
        """
        for target in self.targets:
            if not os.path.exists(target):
                continue
            with self.subTest(target=target):
                raw = self.harness.decompile(target, "main", compact=False)
                budgeted = self.harness.decompile(target, "main", compact=True, budget=300)

                tok_raw = TokenEstimator.estimate_obj(raw)
                tok_budgeted = TokenEstimator.estimate_obj(budgeted)

                self.assertGreater(tok_raw, 0)
                reduction_pct = ((tok_raw - tok_budgeted) / tok_raw) * 100.0

                # Under budget 300, reduction must exceed 80%
                self.assertGreaterEqual(
                    reduction_pct,
                    80.0,
                    f"Budgeted decompile reduction on {target} must be >= 80%, got {reduction_pct:.2f}%",
                )
                self.assertLessEqual(tok_budgeted, 300)
                self.assertTrue(budgeted.get("success"))

    def test_empirical_strings_token_savings_and_budget_bounding(self) -> None:
        """
        Verifies that on real binaries:
        1. Compacted strings mode achieves >35% token reduction compared to raw strings.
        2. Budget constraint (B=400) strictly holds: Tokens <= 400.
        """
        for target in self.targets:
            if not os.path.exists(target):
                continue
            with self.subTest(target=target):
                raw = self.harness.strings(target, compact=False)
                compact = self.harness.strings(target, compact=True)
                budgeted = self.harness.strings(target, compact=True, budget=400)

                tok_raw = TokenEstimator.estimate_obj(raw)
                tok_compact = TokenEstimator.estimate_obj(compact)
                tok_budgeted = TokenEstimator.estimate_obj(budgeted)

                self.assertGreater(tok_raw, 0)
                reduction_pct = ((tok_raw - tok_compact) / tok_raw) * 100.0

                self.assertGreaterEqual(
                    reduction_pct,
                    35.0,
                    f"Strings reduction on {target} must be >= 35%, got {reduction_pct:.2f}%",
                )
                self.assertLessEqual(tok_budgeted, 400)
                self.assertTrue(budgeted.get("success"))


if __name__ == "__main__":
    unittest.main()
