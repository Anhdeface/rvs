"""
tests/test_challenger_preview_m2_empirical.py - Empirical Adversarial Challenge Suite
for Milestone 2: Bijective Codebook & Semantic Invariant Engine.

Authored by teamwork_preview_challenger_m2_1 (Bijective Roundtrip & Invariant Challenger).
Mission:
1. Empirically stress-test the bidirectional codebook and semantic invariant engine:
   - High-entropy strings, token prefix collisions (SYM_TOKEN_FUNC_0001 vs SYM_TOKEN_FUNC_00010),
     multiline C code, nested JSON structures.
   - Deliberately mutate opcodes, registers, addresses, or immediates, and assert whether
     verify_invariants() unfailingly catches every mutation.
2. Verify 100% roundtrip restoration fidelity and uncover any false negatives in invariant verification.
"""

from __future__ import annotations

import base64
import json
import os
import random
import string
import threading
import unittest
from typing import Any, Dict, List

from neutral_orchestrator.neutral_representation import (
    BijectiveCodebook,
    InstructionSemantics,
    InvariantViolationError,
    NeutralTokenMapper,
    TokenCategory,
    classify_token,
    deneutralize_data,
    diagnose_invariants,
    parse_instruction_semantics,
    verify_invariants,
)


class TestHighEntropyBijectiveRoundtrip(unittest.TestCase):
    """
    Stress-testing Feature 8 (Bijective Reversible Codebook) with high-entropy data,
    special characters, multiline C code, and deeply nested JSON structures.
    """

    def setUp(self) -> None:
        self.mapper = NeutralTokenMapper(session_id="stress_session_001")

    def test_high_entropy_random_strings_roundtrip(self) -> None:
        """Tests 200 high-entropy random strings of various lengths and encodings."""
        random.seed(42)
        test_strings = []

        # 1. Base64 high entropy blobs
        for _ in range(50):
            blob = os.urandom(random.randint(16, 128))
            test_strings.append(base64.b64encode(blob).decode("ascii"))

        # 2. Hex strings
        for _ in range(50):
            test_strings.append(os.urandom(random.randint(8, 64)).hex())

        # 3. Punctuation and control characters
        for _ in range(50):
            s = "".join(random.choices(string.punctuation + string.ascii_letters + string.digits, k=64))
            test_strings.append(s)

        # 4. Unicode, emojis, accents, regex special symbols
        unicode_samples = [
            "Khóa_Bảo_Mật_Hệ_Thống_2026_🇻🇳",
            "こんにちは世界_暗号鍵_🔑",
            "*(?:[a-zA-Z0-9]+)*?+^$|[]{}()\\/.,;:'\"`~@#!%^&*-_=+",
            "\u200b\u200c\u200d\u202e\u202d\u202a\ufeff",
            "SELECT * FROM users WHERE pass = 'admin' OR '1'='1' --",
            "<script>alert(document.cookie)</script>",
            "line1\nline2\r\nline3\t\t\tline4\0end",
        ]
        test_strings.extend(unicode_samples)

        # Sanitize and verify roundtrip
        for idx, raw_str in enumerate(test_strings):
            tok = self.mapper.sanitize_string(raw_str, TokenCategory.CRYPTO)
            restored = self.mapper.restore(tok)
            self.assertEqual(
                restored,
                raw_str,
                f"Failed roundtrip for high-entropy string #{idx}: {raw_str!r} -> {tok} -> {restored!r}",
            )

    def test_multiline_c_code_neutralize_and_restore(self) -> None:
        """Tests preservation of full multiline C decompilation logic and syntax."""
        c_source = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ATTEMPTS 3

typedef struct {
    char username[32];
    char password_hash[64];
    int access_level;
} user_profile_t;

int verify_admin_credentials(const char* usr, const char* pwd) {
    if (!usr || !pwd) return 0;
    
    // Check master key
    if (strcmp(usr, "admin_superuser") == 0) {
        if (strcmp(pwd, "Master_Secr3t_K3y_2026!") == 0) {
            printf("[SECURITY] Access granted for superuser: %s\\n", usr);
            return 1;
        }
    }
    
    printf("[SECURITY] Access denied for user: %s\\n", usr);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) return 1;
    return verify_admin_credentials(argv[1], argv[2]) ? 0 : 1;
}
"""
        # Register symbols and strings
        self.mapper.sanitize_symbol("verify_admin_credentials", TokenCategory.AUTH)
        self.mapper.sanitize_string("admin_superuser", TokenCategory.AUTH)
        self.mapper.sanitize_string("Master_Secr3t_K3y_2026!", TokenCategory.CRYPTO)
        self.mapper.sanitize_string("[SECURITY] Access granted for superuser: %s\\n", TokenCategory.GATE)
        self.mapper.sanitize_string("[SECURITY] Access denied for user: %s\\n", TokenCategory.GATE)

        neutralized = self.mapper.neutralize(c_source)
        self.assertIn("SYM_TOKEN_FUNC_0001", neutralized)
        self.assertIn("SYM_STR_0001", neutralized)
        self.assertIn("SYM_STR_0002", neutralized)

        restored = self.mapper.restore(neutralized)
        self.assertEqual(restored, c_source, "Multiline C code failed 100% bijective restoration!")

    def test_deeply_nested_json_structures_deneutralize(self) -> None:
        """Tests recursive deneutralize_data() on deeply nested data structures."""
        tok_fn = self.mapper.sanitize_symbol("crypto_decrypt_aes", TokenCategory.CRYPTO)
        tok_str = self.mapper.sanitize_string("PAYLOAD_CONFIDENTIAL", TokenCategory.CRYPTO)
        tok_gate = self.mapper.sanitize_predicate("rdi == 0x0")
        tok_addr = self.mapper.sanitize_address(0x7FFFF7A01000)
        tok_data = self.mapper.sanitize_data("g_private_key_table", TokenCategory.CRYPTO)

        # Build nested structure with depth 20
        curr: Dict[str, Any] = {
            "endpoint": tok_fn,
            "secret": tok_str,
            "gate": tok_gate,
            "address": tok_addr,
            "data_blob": tok_data,
            "list": [tok_fn, tok_str, 999, False, None],
            "tuple": (tok_gate, 3.14159),
            "set": {tok_str, "static_elem"},
        }
        for level in range(20):
            curr = {
                f"level_{level}": curr,
                "metadata": {tok_fn: tok_str},
                "numeric_key": {123: tok_gate},
            }

        restored = self.mapper.deneutralize_data(curr)

        # Verify deepest level restoration
        deepest = restored
        for level in range(19, -1, -1):
            deepest = deepest[f"level_{level}"]

        self.assertEqual(deepest["endpoint"], "crypto_decrypt_aes")
        self.assertEqual(deepest["secret"], "PAYLOAD_CONFIDENTIAL")
        self.assertEqual(deepest["gate"], "rdi == 0x0")
        self.assertEqual(deepest["address"], "0x7ffff7a01000")
        self.assertEqual(deepest["data_blob"], "g_private_key_table")
        self.assertEqual(deepest["list"][0], "crypto_decrypt_aes")
        self.assertEqual(deepest["tuple"][0], "rdi == 0x0")
        self.assertIn("PAYLOAD_CONFIDENTIAL", deepest["set"])

    def test_json_codebook_export_import_serialization_fidelity(self) -> None:
        """Tests complete JSON serializability and counter reconciliation across sessions."""
        for i in range(50):
            self.mapper.sanitize_symbol(f"sym_sub_{i}", TokenCategory.AUTH)
            self.mapper.sanitize_string(f"str_lit_{i}", TokenCategory.GATE)
            self.mapper.sanitize_predicate(f"cond_gate_{i} > 0")
            self.mapper.sanitize_address(0x401000 + i * 4)
            self.mapper.sanitize_data(f"data_sec_{i}", TokenCategory.CRYPTO)

        codebook = self.mapper.export_codebook()
        codebook_json = json.dumps(codebook)
        loaded_dict = json.loads(codebook_json)

        new_mapper = NeutralTokenMapper()
        new_mapper.import_codebook(loaded_dict)

        # Verify exact forward and reverse mappings
        self.assertEqual(self.mapper.forward_map, new_mapper.forward_map)
        self.assertEqual(self.mapper.reverse_map, new_mapper.reverse_map)

        # Verify counter synchronization
        for k in ["FUNC", "STR", "GATE", "ADDR", "DATA"]:
            self.assertEqual(self.mapper.counters[k], new_mapper.counters[k])

        # Verify new registration in new_mapper does not collide
        next_tok = new_mapper.sanitize_symbol("new_after_import", TokenCategory.AUTH)
        self.assertEqual(next_tok, "SYM_TOKEN_FUNC_0051")

    def test_concurrency_thread_safety(self) -> None:
        """Tests concurrent token registration and restoration across multiple threads."""
        mapper = NeutralTokenMapper()
        errors = []

        def worker(thread_idx: int) -> None:
            try:
                for i in range(50):
                    raw = f"thread_{thread_idx}_token_{i}"
                    tok = mapper.sanitize_symbol(raw, TokenCategory.GENERAL)
                    restored = mapper.restore(tok)
                    if restored != raw:
                        errors.append(f"Mismatch in thread {thread_idx}: {restored} != {raw}")
            except Exception as e:
                errors.append(f"Exception in thread {thread_idx}: {e}")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Thread-safety violations detected: {errors}")
        self.assertEqual(mapper.counters["FUNC"], 400)


class TestTokenPrefixCollisionsAndIsolation(unittest.TestCase):
    """
    Adversarial tests on token prefix collisions and boundary isolation.
    """

    def test_registered_token_prefix_collision_resolution(self) -> None:
        """
        Tests that when both short and long tokens are registered (e.g. SYM_TOKEN_FUNC_0001
        and SYM_TOKEN_FUNC_00010), length-descending sort prevents prefix collision.
        """
        mapper = NeutralTokenMapper()
        mapper.codebook.register_alias("func_short", "SYM_TOKEN_FUNC_0001")
        mapper.codebook.register_alias("func_long", "SYM_TOKEN_FUNC_00010")

        text = "call SYM_TOKEN_FUNC_00010; call SYM_TOKEN_FUNC_0001"
        restored = mapper.restore(text)
        self.assertEqual(restored, "call func_long; call func_short")

    def test_unregistered_token_prefix_vulnerability(self) -> None:
        """
        Tests that restore() maintains token boundary isolation:
        When SYM_TOKEN_FUNC_0001 is registered, an unregistered token sharing the prefix
        (such as SYM_TOKEN_FUNC_00010) is NOT corrupted into 'auth_check0'.
        """
        mapper = NeutralTokenMapper()
        tok = mapper.sanitize_symbol("auth_check", TokenCategory.AUTH)  # SYM_TOKEN_FUNC_0001
        self.assertEqual(tok, "SYM_TOKEN_FUNC_0001")

        # Disassembly line containing an UNREGISTERED token that shares the prefix
        unregistered_text = "call SYM_TOKEN_FUNC_00010"
        corrupted = mapper.restore(unregistered_text)

        # Boundary isolation guarantees unregistered tokens remain intact
        self.assertEqual(
            corrupted,
            unregistered_text,
            "Boundary isolation confirmed: unregistered prefix token was preserved without corruption.",
        )

    def test_raw_string_substring_collision_in_neutralize(self) -> None:
        """
        Tests that neutralize() enforces identifier boundaries:
        Registering 'add' must NOT corrupt the substring inside 'address calculation'.
        """
        mapper = NeutralTokenMapper()
        mapper.sanitize_symbol("add", TokenCategory.GENERAL)  # registers 'add'

        text = "address calculation"
        neutralized = mapper.neutralize(text)

        self.assertEqual(
            neutralized,
            "address calculation",
            f"Boundary isolation confirmed: 'add' inside 'address' was NOT modified: {neutralized}",
        )
        # Legitimate standalone instruction should neutralize properly
        self.assertEqual(
            mapper.neutralize("add rax, rbx"),
            "SYM_TOKEN_FUNC_0001 rax, rbx",
        )


class TestSemanticInvariantEngineMutations(unittest.TestCase):
    """
    Empirical mutation testing of Feature 9: 100% Semantic Invariant Engine.
    Tests verify_invariants() against deliberately mutated opcodes, registers,
    addresses, memory operands, and immediates to detect false negatives.
    """

    def test_valid_disassembly_passes_invariant_check(self) -> None:
        """Asserts that identical or legitimately neutralized disassembly passes."""
        orig = [
            {"addr": 0x401000, "asm": "push rbp", "size": 1},
            {"addr": 0x401001, "asm": "mov rbp, rsp", "size": 3},
            {"addr": 0x401004, "asm": "call 0x401050 ; check_password", "size": 5},
            {"addr": 0x401009, "asm": "cmp eax, 0x1", "size": 3},
            {"addr": 0x40100C, "asm": "pop rbp", "size": 1},
            {"addr": 0x40100D, "asm": "ret", "size": 1},
        ]
        neut = [
            {"addr": 0x401000, "asm": "push rbp", "size": 1},
            {"addr": 0x401001, "asm": "mov rbp, rsp", "size": 3},
            {"addr": 0x401004, "asm": "call SYM_TOKEN_FUNC_0001", "size": 5},
            {"addr": 0x401009, "asm": "cmp eax, 0x1", "size": 3},
            {"addr": 0x40100C, "asm": "pop rbp", "size": 1},
            {"addr": 0x40100D, "asm": "ret", "size": 1},
        ]
        self.assertTrue(verify_invariants(orig, neut, strict=False))

    def test_standard_opcode_alteration_is_caught(self) -> None:
        """Asserts that changing standard opcode mnemonics is caught."""
        orig = [{"addr": 0x401000, "asm": "cmp eax, 0", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov eax, 0", "size": 3}]
        self.assertFalse(verify_invariants(orig, neut))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_standard_register_alteration_is_caught(self) -> None:
        """Asserts that altering recognized CPU registers is caught."""
        orig = [{"addr": 0x401000, "asm": "mov rax, rdi", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov rbx, rdi", "size": 3}]
        self.assertFalse(verify_invariants(orig, neut))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_standard_address_drift_is_caught(self) -> None:
        """Asserts that virtual address drift is caught."""
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"addr": 0x401004, "asm": "nop", "size": 1}]
        self.assertFalse(verify_invariants(orig, neut))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_instruction_count_mismatch_is_caught(self) -> None:
        """Asserts that dropping or injecting instructions is caught."""
        orig = [
            {"addr": 0x401000, "asm": "push rbp", "size": 1},
            {"addr": 0x401001, "asm": "nop", "size": 1},
        ]
        neut = [{"addr": 0x401000, "asm": "push rbp", "size": 1}]
        self.assertFalse(verify_invariants(orig, neut))

    # ==========================================================================
    # EMPIRICALLY CONFIRMED FALSE NEGATIVES IN INVARIANT ENGINE
    # ==========================================================================

    def test_false_negative_1_empty_or_stripped_opcode(self) -> None:
        """
        Asserts that stripped, omitted, or comment-only opcodes in neutralized disassembly
        are strictly detected and rejected with OPCODE_ALTERATION discrepancy.
        """
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"addr": 0x401000, "asm": "; comment only", "size": 1}]

        discrepancies = diagnose_invariants(orig, neut)
        passed = verify_invariants(orig, neut)

        self.assertNotEqual(discrepancies, [], "diagnose_invariants() must detect stripped opcode!")
        self.assertTrue(
            any(d["rule"] == "OPCODE_ALTERATION" for d in discrepancies),
            "Discrepancies must include OPCODE_ALTERATION",
        )
        self.assertFalse(passed, "verify_invariants() must reject stripped opcode!")
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_false_negative_2_extended_vector_and_float_registers(self) -> None:
        """
        Asserts that extended x86_64 vector registers (xmm8-xmm31, ymm8-ymm31, zmm0-zmm31)
        and ARM floating point registers (d0-d31, s0-s31) are strictly verified.
        """
        # x86_64 xmm8 -> xmm9
        orig_x86 = [{"addr": 0x401000, "asm": "movaps xmm8, xmm0", "size": 4}]
        neut_x86 = [{"addr": 0x401000, "asm": "movaps xmm9, xmm0", "size": 4}]

        self.assertFalse(
            verify_invariants(orig_x86, neut_x86),
            "verify_invariants() must reject xmm8 -> xmm9 register mutation!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig_x86, neut_x86, strict=True)

        # ARM64 d0 -> d2
        orig_arm = [{"addr": 0x401000, "asm": "fmov d0, d1", "size": 4}]
        neut_arm = [{"addr": 0x401000, "asm": "fmov d2, d1", "size": 4}]

        self.assertFalse(
            verify_invariants(orig_arm, neut_arm),
            "verify_invariants() must reject ARM d0 -> d2 register mutation!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig_arm, neut_arm, strict=True)

    def test_false_negative_3_signed_immediate_mutation(self) -> None:
        """
        Asserts that mutating immediate constant signs (+8 to -8) is detected and rejected.
        """
        orig = [{"addr": 0x401000, "asm": "add rax, 8", "size": 4}]
        neut = [{"addr": 0x401000, "asm": "add rax, -8", "size": 4}]

        self.assertFalse(
            verify_invariants(orig, neut),
            "verify_invariants() must reject immediate sign flip (+8 -> -8)!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_false_negative_4_masm_hex_suffix_immediates(self) -> None:
        """
        Asserts that MASM-style hex literals with 'h' suffix (10h -> 20h) are verified.
        """
        orig = [{"addr": 0x401000, "asm": "add eax, 10h", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "add eax, 20h", "size": 3}]

        self.assertFalse(
            verify_invariants(orig, neut),
            "verify_invariants() must reject MASM hex immediate mutation (10h -> 20h)!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_false_negative_5_character_literal_immediates(self) -> None:
        """
        Asserts that character literal immediates ('A' -> 'B') are verified.
        """
        orig = [{"addr": 0x401000, "asm": "cmp al, 'A'", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "cmp al, 'B'", "size": 3}]

        self.assertFalse(
            verify_invariants(orig, neut),
            "verify_invariants() must reject character literal mutation ('A' -> 'B')!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_false_negative_6_arbitrary_branch_target_address_corruption(self) -> None:
        """
        Asserts that arbitrary concrete branch target corruption (call 0x401050 -> call 0x999999)
        is strictly detected and rejected with BRANCH_TARGET_ALTERATION.
        """
        orig = [{"addr": 0x401000, "asm": "call 0x401050", "size": 5}]
        neut = [{"addr": 0x401000, "asm": "call 0x999999", "size": 5}]

        discrepancies = diagnose_invariants(orig, neut)
        self.assertNotEqual(discrepancies, [])
        self.assertTrue(any(d["rule"] == "BRANCH_TARGET_ALTERATION" for d in discrepancies))
        self.assertFalse(
            verify_invariants(orig, neut),
            "verify_invariants() must reject concrete branch target corruption!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_false_negative_7_memory_operand_size_qualifier_with_ptr(self) -> None:
        """
        Asserts that size qualifier modifications in Intel syntax ('dword ptr' -> 'byte ptr')
        are detected and rejected.
        """
        orig = [{"addr": 0x401000, "asm": "mov eax, dword ptr [rbp - 0x14]", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov eax, byte ptr [rbp - 0x14]", "size": 3}]

        discrepancies = diagnose_invariants(orig, neut)
        self.assertNotEqual(discrepancies, [])
        self.assertTrue(any(d["rule"] == "MEMORY_OPERAND_ALTERATION" for d in discrepancies))
        self.assertFalse(
            verify_invariants(orig, neut),
            "verify_invariants() must reject memory operand size mutation (dword ptr -> byte ptr)!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_false_negative_8_arm_alu_shift_modifiers(self) -> None:
        """
        Asserts that ARM ALU shift modifier alterations (lsl -> lsr) are detected and rejected
        with SHIFT_MODIFIER_ALTERATION.
        """
        orig = [{"addr": 0x401000, "asm": "add w0, w1, w2, lsl #2", "size": 4}]
        neut = [{"addr": 0x401000, "asm": "add w0, w1, w2, lsr #2", "size": 4}]

        discrepancies = diagnose_invariants(orig, neut)
        self.assertNotEqual(discrepancies, [])
        self.assertTrue(any(d["rule"] == "SHIFT_MODIFIER_ALTERATION" for d in discrepancies))
        self.assertFalse(
            verify_invariants(orig, neut),
            "verify_invariants() must reject ARM shift modifier mutation (lsl -> lsr)!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_false_negative_9_dropped_address_field(self) -> None:
        """
        Asserts that omitting or dropping the 'addr' field in neutralized instructions
        is detected and rejected with MISSING_ADDRESS.
        """
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"asm": "nop", "size": 1}]  # 'addr' omitted

        discrepancies = diagnose_invariants(orig, neut)
        self.assertNotEqual(discrepancies, [])
        self.assertTrue(any(d["rule"] == "MISSING_ADDRESS" for d in discrepancies))
        self.assertFalse(
            verify_invariants(orig, neut),
            "verify_invariants() must reject omitted 'addr' field!",
        )
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)


if __name__ == "__main__":
    unittest.main()
