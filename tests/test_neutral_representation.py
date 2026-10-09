"""
tests/test_neutral_representation.py - Comprehensive Unit Test Suite for Milestone 2:
Neutral Technical Framing & Representation Layer.

Covers:
- Feature 6: Sensitive Token Taxonomy (TokenCategory, classify_token, prioritization)
- Feature 7: Deterministic Token Substitution (NeutralTokenMapper, symbols, strings, predicates, addresses, data)
- Feature 8: Bijective Reversible Codebook (restore, deneutralize_data, export/import codebook, counters)
- Feature 9: 100% Semantic Invariant Engine (verify_invariants, diagnose_invariants, InvariantViolationError)
- Feature 10: Control Flow Graph (ControlFlowGraph, CFGNode, CFGEdge, from_rvs_flow, metrics)
- Feature 10: Finite State Machine (FiniteStateMachine, from_cfg, Moore outputs, transitions)
- Feature 10: Algorithmic Pattern Detector (AlgorithmicPatternDetector, all 6 archetypes)
"""

from __future__ import annotations

import json
import unittest
from typing import Any, Dict, List

from neutral_orchestrator.neutral_representation import (
    CFGEdge,
    CFGEdgeType,
    CFGNode,
    ControlFlowGraph,
    FiniteStateMachine,
    InstructionSemantics,
    InvariantViolationError,
    NeutralTokenMapper,
    PatternMatch,
    TokenCategory,
    AlgorithmicPatternDetector,
    classify_token,
    deneutralize_data,
    diagnose_invariants,
    normalize_disassembly_input,
    parse_instruction_semantics,
    verify_invariants,
)


class TestTokenTaxonomy(unittest.TestCase):
    """Unit tests for Feature 6: Sensitive Token Taxonomy."""

    def test_token_category_enum_values(self) -> None:
        expected = {"AUTH", "GATE", "EVASION", "CRYPTO", "SYSTEM", "GENERAL"}
        actual = {c.value for c in TokenCategory}
        self.assertEqual(actual, expected)

    def test_classify_token_auth(self) -> None:
        self.assertEqual(classify_token("check_master_password"), TokenCategory.AUTH)
        self.assertEqual(classify_token("user_credentials"), TokenCategory.AUTH)
        self.assertEqual(classify_token("jwt_token_validator"), TokenCategory.AUTH)
        self.assertEqual(classify_token("admin_login"), TokenCategory.AUTH)

    def test_classify_token_evasion(self) -> None:
        self.assertEqual(classify_token("is_debugger_present"), TokenCategory.EVASION)
        self.assertEqual(classify_token("ptrace_traceme"), TokenCategory.EVASION)
        self.assertEqual(classify_token("detect_frida_hook"), TokenCategory.EVASION)
        self.assertEqual(classify_token("check_tracerpid"), TokenCategory.EVASION)

    def test_classify_token_crypto(self) -> None:
        self.assertEqual(classify_token("decrypt_buffer"), TokenCategory.CRYPTO)
        self.assertEqual(classify_token("aes_cipher_key"), TokenCategory.CRYPTO)
        self.assertEqual(classify_token("g_encrypted_payload"), TokenCategory.CRYPTO)
        self.assertEqual(classify_token("K3Y-V4L1D-2026"), TokenCategory.CRYPTO)
        self.assertEqual(classify_token("FLAG{s3cr3t_fl4g}"), TokenCategory.CRYPTO)

    def test_classify_token_system(self) -> None:
        self.assertEqual(classify_token("/system/bin/su"), TokenCategory.SYSTEM)
        self.assertEqual(classify_token("/proc/self/status"), TokenCategory.SYSTEM)
        self.assertEqual(classify_token("/data/local/tmp"), TokenCategory.SYSTEM)

    def test_classify_token_gate(self) -> None:
        self.assertEqual(classify_token("verify_license_key"), TokenCategory.GATE)
        self.assertEqual(classify_token("check_serial_number"), TokenCategory.GATE)
        self.assertEqual(classify_token("is_valid_registration"), TokenCategory.GATE)

    def test_classify_token_general_fallback(self) -> None:
        self.assertEqual(classify_token("calculate_sum"), TokenCategory.GENERAL)
        self.assertEqual(classify_token("matrix_multiply"), TokenCategory.GENERAL)
        self.assertEqual(classify_token(""), TokenCategory.GENERAL)


class TestNeutralTokenMapper(unittest.TestCase):
    """Unit tests for Feature 7: Deterministic Token Substitution & NeutralTokenMapper."""

    def setUp(self) -> None:
        self.mapper = NeutralTokenMapper()

    def test_sanitize_symbol_sequential(self) -> None:
        t1 = self.mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        t2 = self.mapper.sanitize_symbol("decrypt_buffer", TokenCategory.CRYPTO)
        self.assertEqual(t1, "SYM_TOKEN_FUNC_0001")
        self.assertEqual(t2, "SYM_TOKEN_FUNC_0002")

    def test_sanitize_symbol_deterministic(self) -> None:
        t1 = self.mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        t2 = self.mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        self.assertEqual(t1, t2)
        self.assertEqual(self.mapper.counters["FUNC"], 1)

    def test_sanitize_symbol_sym_prefix_preservation(self) -> None:
        t = self.mapper.sanitize_symbol("sym.check_master_password", TokenCategory.AUTH)
        self.assertEqual(t, "sym.SYM_TOKEN_FUNC_0001")
        # Restoring both decorated and undecorated forms
        self.assertEqual(self.mapper.restore("sym.SYM_TOKEN_FUNC_0001"), "sym.check_master_password")
        self.assertEqual(self.mapper.restore("SYM_TOKEN_FUNC_0001"), "check_master_password")

    def test_sanitize_string_sequential_and_deterministic(self) -> None:
        s1 = self.mapper.sanitize_string("AUTH_FAIL: Bad Password", TokenCategory.AUTH)
        s2 = self.mapper.sanitize_string("Access Denied", TokenCategory.GATE)
        s3 = self.mapper.sanitize_string("AUTH_FAIL: Bad Password", TokenCategory.AUTH)
        self.assertEqual(s1, "SYM_STR_0001")
        self.assertEqual(s2, "SYM_STR_0002")
        self.assertEqual(s3, "SYM_STR_0001")

    def test_sanitize_string_str_prefix_preservation(self) -> None:
        s = self.mapper.sanitize_string("str.AUTH_FAIL:_Bad_Password", TokenCategory.AUTH)
        self.assertEqual(s, "str.SYM_STR_0001")
        self.assertEqual(self.mapper.restore("str.SYM_STR_0001"), "str.AUTH_FAIL:_Bad_Password")
        self.assertEqual(self.mapper.restore("SYM_STR_0001"), "AUTH_FAIL:_Bad_Password")

    def test_sanitize_predicate_sequential(self) -> None:
        p1 = self.mapper.sanitize_predicate("eax == 0")
        p2 = self.mapper.sanitize_predicate("dword [rbp - 0x14] <= 1")
        self.assertEqual(p1, "PREDICATE_GATE_0001")
        self.assertEqual(p2, "PREDICATE_GATE_0002")

    def test_sanitize_address(self) -> None:
        a1 = self.mapper.sanitize_address("0x401146")
        a2 = self.mapper.sanitize_address(0x401170)
        self.assertEqual(a1, "ADDR_REF_0001")
        self.assertEqual(a2, "ADDR_REF_0002")
        self.assertEqual(self.mapper.restore(a1), "0x401146")
        self.assertEqual(self.mapper.restore(a2), "0x401170")

    def test_sanitize_data(self) -> None:
        d1 = self.mapper.sanitize_data("g_encrypted_payload", TokenCategory.CRYPTO)
        self.assertEqual(d1, "SYM_TOKEN_DATA_0001")
        self.assertEqual(self.mapper.restore(d1), "g_encrypted_payload")

    def test_empty_string_sanitization(self) -> None:
        self.assertEqual(self.mapper.sanitize_symbol("", TokenCategory.AUTH), "")
        self.assertEqual(self.mapper.sanitize_string("", TokenCategory.AUTH), "")
        self.assertEqual(self.mapper.sanitize_predicate(""), "")
        self.assertEqual(self.mapper.sanitize_address(""), "")
        self.assertEqual(self.mapper.sanitize_data(""), "")
        self.assertEqual(self.mapper.restore(""), "")
        self.assertEqual(self.mapper.neutralize(""), "")


class TestBidirectionalRestoreAndCodebook(unittest.TestCase):
    """Unit tests for Feature 8: Bijective Reversible Codebook."""

    def setUp(self) -> None:
        self.mapper = NeutralTokenMapper()

    def test_restore_complex_disasm_line(self) -> None:
        sym = self.mapper.sanitize_symbol("validate_pin", TokenCategory.AUTH)
        msg = self.mapper.sanitize_string("Pin is valid", TokenCategory.AUTH)
        disasm_line = f"call {sym} ; msg: {msg}"
        self.assertEqual(self.mapper.restore(disasm_line), "call validate_pin ; msg: Pin is valid")

    def test_neutralize_and_restore_roundtrip(self) -> None:
        self.mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        self.mapper.sanitize_string("ACCESS_GRANTED", TokenCategory.GATE)
        raw_text = "call check_master_password ; returns ACCESS_GRANTED"
        neutral = self.mapper.neutralize(raw_text)
        self.assertIn("SYM_TOKEN_FUNC_0001", neutral)
        self.assertIn("SYM_STR_0001", neutral)
        restored = self.mapper.restore(neutral)
        self.assertEqual(restored, raw_text)

    def test_restore_unregistered_tokens_intact(self) -> None:
        text = "SYM_UNKNOWN_1234 untouched mov rax, rbx"
        self.assertEqual(self.mapper.restore(text), text)

    def test_substring_collision_immunity(self) -> None:
        # Register both short and long symbol
        short_tok = self.mapper.sanitize_symbol("pwd", TokenCategory.AUTH)
        long_tok = self.mapper.sanitize_symbol("check_pwd_master", TokenCategory.AUTH)
        text = f"{long_tok} and {short_tok}"
        self.assertEqual(self.mapper.restore(text), "check_pwd_master and pwd")

    def test_export_and_import_codebook_roundtrip(self) -> None:
        tok1 = self.mapper.sanitize_symbol("check_license", TokenCategory.GATE)
        tok2 = self.mapper.sanitize_string("License OK", TokenCategory.GATE)
        book = self.mapper.export_codebook()

        self.assertIn("forward_map", book)
        self.assertIn("forward", book)
        self.assertIn("reverse_map", book)
        self.assertIn("reverse", book)
        self.assertIn("counters", book)

        # JSON serialization
        json_str = json.dumps(book)
        loaded_book = json.loads(json_str)

        mapper2 = NeutralTokenMapper()
        mapper2.import_codebook(loaded_book)
        self.assertEqual(mapper2.restore(tok1), "check_license")
        self.assertEqual(mapper2.restore(tok2), "License OK")

        # Ensure counter synchronization persists into new registrations
        tok3 = mapper2.sanitize_symbol("new_func", TokenCategory.GENERAL)
        self.assertEqual(tok3, "SYM_TOKEN_FUNC_0002")

    def test_deneutralize_data_recursive(self) -> None:
        tok_func = self.mapper.sanitize_symbol("decrypt_flag", TokenCategory.CRYPTO)
        tok_str = self.mapper.sanitize_string("FLAG_FOUND", TokenCategory.CRYPTO)

        payload = {
            "function": tok_func,
            "count": 42,
            "is_active": True,
            "messages": [tok_str, "static_text"],
            "nested": {
                tok_func: {"details": (tok_str, 3.14)},
                "tags": {tok_str},
            },
        }

        restored = self.mapper.deneutralize_data(payload)
        self.assertEqual(restored["function"], "decrypt_flag")
        self.assertEqual(restored["count"], 42)
        self.assertTrue(restored["is_active"])
        self.assertEqual(restored["messages"], ["FLAG_FOUND", "static_text"])
        self.assertEqual(restored["nested"]["decrypt_flag"]["details"], ("FLAG_FOUND", 3.14))
        self.assertIn("FLAG_FOUND", restored["nested"]["tags"])

    def test_standalone_deneutralize_data_with_codebook(self) -> None:
        tok = self.mapper.sanitize_symbol("auth_check", TokenCategory.AUTH)
        book = self.mapper.export_codebook()
        res = deneutralize_data({"target": tok}, codebook=book)
        self.assertEqual(res["target"], "auth_check")

    def test_unregistered_token_prefix_boundary_isolation(self) -> None:
        tok = self.mapper.sanitize_symbol("auth_check", TokenCategory.AUTH)
        self.assertEqual(tok, "SYM_TOKEN_FUNC_0001")
        unregistered = "call SYM_TOKEN_FUNC_00010"
        self.assertEqual(self.mapper.restore(unregistered), unregistered)

    def test_neutralize_identifier_boundary_isolation(self) -> None:
        self.mapper.sanitize_symbol("add", TokenCategory.GENERAL)
        self.assertEqual(self.mapper.neutralize("address calculation"), "address calculation")
        self.assertEqual(self.mapper.neutralize("add rax, rbx"), "SYM_TOKEN_FUNC_0001 rax, rbx")


class TestSemanticInvariantEngine(unittest.TestCase):
    """Unit tests for Feature 9: 100% Semantic Invariant Engine."""

    def setUp(self) -> None:
        self.mapper = NeutralTokenMapper()

    def test_valid_disasm_passes(self) -> None:
        orig = [
            {"addr": 0x401000, "asm": "push rbp", "size": 1},
            {"addr": 0x401001, "asm": "mov rbp, rsp", "size": 3},
            {"addr": 0x401004, "asm": "sub rsp, 0x20", "size": 4},
        ]
        neut = [
            {"addr": 0x401000, "asm": "push rbp", "size": 1},
            {"addr": 0x401001, "asm": "mov rbp, rsp", "size": 3},
            {"addr": 0x401004, "asm": "sub rsp, 0x20", "size": 4},
        ]
        self.assertTrue(verify_invariants(orig, neut))
        self.assertTrue(self.mapper.verify_invariants(orig, neut))

    def test_opcode_alteration_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "cmp eax, 0", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov eax, 0", "size": 3}]
        self.assertFalse(verify_invariants(orig, neut))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_register_alteration_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "mov rax, rdi", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov rbx, rdi", "size": 3}]
        self.assertFalse(verify_invariants(orig, neut))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_address_drift_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"addr": 0x401001, "asm": "nop", "size": 1}]
        self.assertFalse(verify_invariants(orig, neut))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_instruction_count_mismatch_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = []
        self.assertFalse(verify_invariants(orig, neut))
        with self.assertRaises(InvariantViolationError):
            verify_invariants(orig, neut, strict=True)

    def test_size_mismatch_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"addr": 0x401000, "asm": "nop", "size": 2}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_memory_operand_alteration_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "mov eax, dword [rbp - 0x14]", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov eax, dword [rbp - 0x20]", "size": 3}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_branch_target_neutralization_permitted(self) -> None:
        orig = [{"addr": 0x401000, "asm": "call 0x401156 ; check_password", "size": 5}]
        neut = [{"addr": 0x401000, "asm": "call SYM_TOKEN_FUNC_0001", "size": 5}]
        self.assertTrue(verify_invariants(orig, neut))

    def test_empty_or_stripped_opcode_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"addr": 0x401000, "asm": "; comment only", "size": 1}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_dropped_address_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"asm": "nop", "size": 1}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_branch_target_concrete_mismatch_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "call 0x401050", "size": 5}]
        neut = [{"addr": 0x401000, "asm": "call 0x999999", "size": 5}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_arm_shift_modifier_alteration_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "add w0, w1, w2, lsl #2", "size": 4}]
        neut = [{"addr": 0x401000, "asm": "add w0, w1, w2, lsr #2", "size": 4}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_extended_vector_register_alteration_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "movaps xmm8, xmm0", "size": 4}]
        neut = [{"addr": 0x401000, "asm": "movaps xmm9, xmm0", "size": 4}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_signed_immediate_alteration_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "add rax, 8", "size": 4}]
        neut = [{"addr": 0x401000, "asm": "add rax, -8", "size": 4}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_intel_ptr_memory_size_alteration_detected(self) -> None:
        orig = [{"addr": 0x401000, "asm": "mov eax, dword ptr [rbp - 0x14]", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov eax, byte ptr [rbp - 0x14]", "size": 3}]
        self.assertFalse(verify_invariants(orig, neut))

    def test_polymorphic_disasm_input(self) -> None:
        # Test string array input
        orig_strs = ["mov rax, rdi", "cmp eax, 0"]
        neut_strs = ["mov rax, rdi", "cmp eax, 0"]
        self.assertTrue(verify_invariants(orig_strs, neut_strs))

        # Test block list input
        orig_blocks = [{"addr": 0x401000, "instructions": [{"addr": 0x401000, "asm": "nop"}]}]
        neut_blocks = [{"addr": 0x401000, "instructions": [{"addr": 0x401000, "asm": "nop"}]}]
        self.assertTrue(verify_invariants(orig_blocks, neut_blocks))


class TestControlFlowGraph(unittest.TestCase):
    """Unit tests for Feature 10: Control Flow Graph (CFG)."""

    def test_cfg_basic_to_dict(self) -> None:
        nodes = [
            {"id": "BB_0", "start_addr": "0x401000", "node_type": "ENTRY", "instruction_count": 5},
            {"id": "BB_1", "start_addr": "0x401020", "node_type": "EXIT", "instruction_count": 2},
        ]
        edges = [
            {"source": "BB_0", "target": "BB_1", "type": "UNCONDITIONAL"}
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        d = cfg.to_dict()

        self.assertEqual(len(d["nodes"]), 2)
        self.assertEqual(len(d["edges"]), 1)
        self.assertIn("metrics", d)
        self.assertEqual(d["metrics"]["total_nodes"], 2)
        self.assertEqual(d["metrics"]["total_edges"], 1)
        self.assertEqual(d["metrics"]["cyclomatic_complexity"], 1)

    def test_cfg_leaf_function_single_node(self) -> None:
        nodes = [{"id": "BB_ENTRY", "start_addr": "0x401000", "node_type": "ENTRY"}]
        cfg = ControlFlowGraph(nodes=nodes, edges=[])
        d = cfg.to_dict()
        self.assertEqual(len(d["nodes"]), 1)
        self.assertEqual(len(d["edges"]), 0)
        self.assertEqual(d["metrics"]["cyclomatic_complexity"], 1)
        self.assertEqual(d["metrics"]["loop_count"], 0)

    def test_cfg_backward_edge_loop_head_detection(self) -> None:
        nodes = [
            {"id": "BB_HEAD", "start_addr": "0x401000", "address": "0x401000", "node_type": "NORMAL"},
            {"id": "BB_BODY", "start_addr": "0x401010", "address": "0x401010", "node_type": "NORMAL"},
        ]
        edges = [
            {"source": "BB_HEAD", "target": "BB_BODY", "type": "FALLTHROUGH"},
            {"source": "BB_BODY", "target": "BB_HEAD", "type": "CONDITIONAL_TAKEN"},
        ]
        # Ingestion from flow
        raw_flow = {
            "blocks": [
                {
                    "addr": 0x401000, "addr_hex": "0x401000", "size": 16,
                    "jump": 0x401010, "instructions": [{"asm": "nop"}]
                },
                {
                    "addr": 0x401010, "addr_hex": "0x401010", "size": 16,
                    "jump": 0x401000, "fail": 0x401020,
                    "instructions": [{"asm": "jle 0x401000", "opcode": "jle 0x401000"}]
                },
                {
                    "addr": 0x401020, "addr_hex": "0x401020", "size": 4,
                    "jump": None, "fail": None,
                    "instructions": [{"asm": "ret", "opcode": "ret"}]
                },
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        head_node = next((n for n in cfg.nodes if n["address"] == "0x401000"), None)
        self.assertIsNotNone(head_node)
        self.assertTrue(head_node["is_loop_head"])
        self.assertEqual(cfg.calculate_metrics()["loop_count"], 1)

    def test_cfg_from_decision_nodes_flow(self) -> None:
        raw_flow = {
            "function": "sym.auth_check",
            "addr": "0x401000",
            "decision_nodes": [
                {
                    "addr": "0x401015",
                    "condition_instruction": "cmp eax, 0",
                    "jump_target_hex": "0x401030",
                    "fail_target_hex": "0x401020",
                }
            ],
            "exit_nodes": ["0x401040"],
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        d = cfg.to_dict()
        self.assertGreaterEqual(len(d["nodes"]), 3)
        self.assertEqual(len(d["edges"]), 2)
        exit_node = next((n for n in cfg.nodes if n["address"] == "0x401040"), None)
        self.assertIsNotNone(exit_node)
        self.assertTrue(exit_node["is_exit"])


class TestFiniteStateMachine(unittest.TestCase):
    """Unit tests for Feature 10: Finite State Machine (FSM)."""

    def test_fsm_initialization_and_to_dict(self) -> None:
        fsm = FiniteStateMachine(
            states=["S0", "S1", "S_END"],
            initial_state="S0",
            terminal_states=["S_END"],
            transitions=[
                {"source": "S0", "predicate": "PREDICATE_GATE_0001", "target": "S1"},
                {"source": "S1", "predicate": "TRUE", "target": "S_END"},
            ],
        )
        d = fsm.to_dict()
        self.assertEqual(d["initial_state"], "S0")
        self.assertEqual(d["terminal_states"], ["S_END"])
        self.assertEqual(len(d["transitions"]), 2)

    def test_fsm_from_cfg(self) -> None:
        nodes = [
            {"id": "BB_0", "start_addr": "0x401000", "node_type": "ENTRY", "instruction_count": 4},
            {"id": "BB_1", "start_addr": "0x401010", "node_type": "DECISION", "instruction_count": 3},
            {"id": "BB_EXIT", "start_addr": "0x401020", "node_type": "EXIT", "instruction_count": 1},
        ]
        edges = [
            {"source": "BB_0", "target": "BB_1", "type": "FALLTHROUGH"},
            {"source": "BB_1", "target": "BB_EXIT", "type": "CONDITIONAL_TAKEN", "condition": "eax == 0"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()

        self.assertEqual(fsm.initial_state, "BB_0")
        self.assertEqual(fsm.terminal_states, ["BB_EXIT"])
        self.assertEqual(len(fsm.transitions), 2)
        self.assertEqual(fsm.transitions[1]["predicate"], "eax == 0")
        self.assertIsNotNone(fsm.outputs)
        self.assertEqual(fsm.outputs["BB_0"]["instruction_count"], 4)


class TestAlgorithmicPatternDetector(unittest.TestCase):
    """Unit tests for Feature 10: Algorithmic Equivalence Pattern Detection Engine."""

    def test_detect_crypto_xor_loop(self) -> None:
        raw_flow = {
            "blocks": [
                {
                    "addr": 0x401000, "addr_hex": "0x401000", "size": 16,
                    "jump": 0x401010, "instructions": [{"asm": "push rbp"}]
                },
                {
                    "addr": 0x401010, "addr_hex": "0x401010", "size": 24,
                    "jump": 0x401010, "fail": 0x401030,
                    "instructions": [
                        {"asm": "mov al, byte [rdx]", "opcode": "mov"},
                        {"asm": "xor al, byte [rcx]", "opcode": "xor"},
                        {"asm": "mov byte [rdx], al", "opcode": "mov"},
                        {"asm": "jne 0x401010", "opcode": "jne"},
                    ]
                },
                {
                    "addr": 0x401030, "addr_hex": "0x401030", "size": 4,
                    "jump": None, "fail": None,
                    "instructions": [{"asm": "ret", "opcode": "ret"}]
                },
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        patterns = cfg.detect_patterns()
        pattern_ids = [p["pattern_id"] for p in patterns]
        self.assertIn("ALG_BYTE_TRANS", pattern_ids)

    def test_detect_aggregation_loop(self) -> None:
        raw_flow = {
            "blocks": [
                {
                    "addr": 0x401000, "addr_hex": "0x401000", "size": 16,
                    "jump": 0x401010, "instructions": [{"asm": "mov eax, 1"}]
                },
                {
                    "addr": 0x401010, "addr_hex": "0x401010", "size": 20,
                    "jump": 0x401010, "fail": 0x401025,
                    "instructions": [
                        {"asm": "imul eax, edx", "opcode": "imul"},
                        {"asm": "sub edx, 1", "opcode": "sub"},
                        {"asm": "jg 0x401010", "opcode": "jg"},
                    ]
                },
                {
                    "addr": 0x401025, "addr_hex": "0x401025", "size": 4,
                    "jump": None, "fail": None,
                    "instructions": [{"asm": "ret", "opcode": "ret"}]
                },
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        patterns = cfg.detect_patterns()
        pattern_ids = [p["pattern_id"] for p in patterns]
        self.assertIn("ALG_ACC_LOOP", pattern_ids)

    def test_detect_collatz_parity_loop(self) -> None:
        raw_flow = {
            "blocks": [
                {
                    "addr": 0x401000, "addr_hex": "0x401000", "size": 16,
                    "jump": 0x401010, "instructions": [{"asm": "nop"}]
                },
                {
                    "addr": 0x401010, "addr_hex": "0x401010", "size": 16,
                    "jump": 0x401020, "fail": 0x401030,
                    "instructions": [
                        {"asm": "test eax, 1", "opcode": "test"},
                        {"asm": "jne 0x401020", "opcode": "jne"},
                    ]
                },
                {
                    "addr": 0x401020, "addr_hex": "0x401020", "size": 16,
                    "jump": 0x401010, "instructions": [
                        {"asm": "lea eax, [rax + rax*2 + 1]", "opcode": "lea"},
                        {"asm": "jmp 0x401010", "opcode": "jmp"},
                    ]
                },
                {
                    "addr": 0x401030, "addr_hex": "0x401030", "size": 16,
                    "jump": 0x401010, "instructions": [
                        {"asm": "sar eax, 1", "opcode": "sar"},
                        {"asm": "jmp 0x401010", "opcode": "jmp"},
                    ]
                },
                {
                    "addr": 0x401050, "addr_hex": "0x401050", "size": 4,
                    "jump": None, "fail": None,
                    "instructions": [{"asm": "ret", "opcode": "ret"}]
                },
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        patterns = cfg.detect_patterns()
        pattern_ids = [p["pattern_id"] for p in patterns]
        self.assertIn("ALG_COLLATZ", pattern_ids)

    def test_detect_switch_dispatch_table(self) -> None:
        nodes = [
            {"id": f"BB_{i}", "start_addr": f"0x4010{i:02x}", "node_type": "NORMAL"}
            for i in range(10)
        ]
        edges = [
            {"source": "BB_0", "target": f"BB_{i}", "type": "INDIRECT_SWITCH", "metadata": {"case_val": i}}
            for i in range(1, 10)
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        patterns = cfg.detect_patterns()
        pattern_ids = [p["pattern_id"] for p in patterns]
        self.assertIn("ALG_SWITCH_TAB", pattern_ids)

    def test_detect_recursive_recurrence_tree(self) -> None:
        nodes = [
            {
                "id": "BB_0",
                "start_addr": "0x401000",
                "node_type": "NORMAL",
                "instructions": [
                    {"asm": "call sym.calc_fibonacci", "opcode": "call"},
                    {"asm": "call sym.calc_fibonacci", "opcode": "call"},
                ],
            }
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=[], metadata={"function_name": "calc_fibonacci"})
        patterns = cfg.detect_patterns()
        pattern_ids = [p["pattern_id"] for p in patterns]
        self.assertIn("ALG_REC_BRANCH", pattern_ids)


if __name__ == "__main__":
    unittest.main()
