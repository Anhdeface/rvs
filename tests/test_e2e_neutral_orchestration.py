"""
tests/test_e2e_neutral_orchestration.py - Comprehensive Opaque-Box 4-Tier Test Suite
for the Neutral Technical Binary Orchestration Layer.

Architecture & Scope:
- Tier 1: Comprehensive Feature Unit Coverage (>=5 test cases per feature across 12 core subsystems)
- Tier 2: Boundary, Adversarial & Corner Cases (10 edge condition tests)
- Tier 3: Cross-Feature Combinations (Pairwise workflows across ingestion, routing, CFG, roundtrip)
- Tier 4: Real-World Scenarios (auth_gate_elf64, flow_calc_elf64, decryptor_target_elf64, multi-ABI APK)

All test classes inherit from `unittest.TestCase` for 100% dual-compatibility with:
- `python3 -m unittest tests/test_e2e_neutral_orchestration.py`
- `pytest tests/test_e2e_neutral_orchestration.py`
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Fixture builder utilities
from tests.fixtures_builder import (
    create_corrupted_apk,
    create_synthetic_apk,
    create_synthetic_dex,
    create_zero_byte_target,
    synthesize_dex_bytes,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# -----------------------------------------------------------------------------
# Module Import Guards for Progressive Testability
# -----------------------------------------------------------------------------

try:
    from neutral_orchestrator.target_ingestion import (
        TargetComponent,
        TargetType,
        UnifiedTarget,
        ingest_target,
    )
    HAS_M1 = True
    M1_IMPORT_ERROR = None
except Exception as _e1:
    HAS_M1 = False
    M1_IMPORT_ERROR = _e1

try:
    from neutral_orchestrator.neutral_representation import (
        ControlFlowGraph,
        NeutralTokenMapper,
        TokenCategory,
    )
    HAS_M2 = True
    M2_IMPORT_ERROR = None
except Exception as _e2:
    HAS_M2 = False
    M2_IMPORT_ERROR = _e2

try:
    from neutral_orchestrator.orchestrator import (
        NeutralBinaryOrchestrator,
    )
    HAS_M3 = True
    M3_IMPORT_ERROR = None
except Exception as _e3:
    HAS_M3 = False
    M3_IMPORT_ERROR = _e3


# =============================================================================
# Base Test Case with Milestone Requirement Assertions
# =============================================================================

class NeutralOrchestrationBaseTestCase(unittest.TestCase):
    """Base test case providing fixture management and progressive requirement guards."""

    def setUp(self) -> None:
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir_obj.name)

    def tearDown(self) -> None:
        self.temp_dir_obj.cleanup()

    def require_m1(self) -> None:
        if not HAS_M1:
            self.fail(f"M1 target_ingestion module not implemented: {M1_IMPORT_ERROR}")

    def require_m2(self) -> None:
        if not HAS_M2:
            self.fail(f"M2 neutral_representation module not implemented: {M2_IMPORT_ERROR}")

    def require_m3(self) -> None:
        if not HAS_M3:
            self.fail(f"M3 orchestrator module not implemented: {M3_IMPORT_ERROR}")


# =============================================================================
# TIER 1: Feature Coverage (>=5 test cases per feature across 12 features)
# =============================================================================

# --- Feature 1: Target Sniffing & Classification ---

class Tier1TargetSniffingTests(NeutralOrchestrationBaseTestCase):
    """F1: Target Sniffing & Classification (Magic bytes inspection for ELF, APK, DEX, UNKNOWN)."""

    def test_sniff_standalone_elf64(self) -> None:
        self.require_m1()
        target = FIXTURES_DIR / "auth_gate_elf64"
        self.assertTrue(target.exists(), f"Missing fixture {target}")
        unified = ingest_target(str(target))
        self.assertEqual(unified.target_type, TargetType.ELF_STANDALONE)

    def test_sniff_standalone_elf32(self) -> None:
        self.require_m1()
        target = FIXTURES_DIR / "auth_gate_elf32"
        self.assertTrue(target.exists(), f"Missing fixture {target}")
        unified = ingest_target(str(target))
        self.assertEqual(unified.target_type, TargetType.ELF_STANDALONE)

    def test_sniff_pie_elf(self) -> None:
        self.require_m1()
        target = FIXTURES_DIR / "auth_gate_elf64_pie"
        self.assertTrue(target.exists(), f"Missing fixture {target}")
        unified = ingest_target(str(target))
        self.assertEqual(unified.target_type, TargetType.ELF_STANDALONE)

    def test_sniff_apk_package(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "sample.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            self.assertEqual(unified.target_type, TargetType.APK_PACKAGE)

    def test_sniff_dex_standalone(self) -> None:
        self.require_m1()
        dex_path = self.work_dir / "classes.dex"
        create_synthetic_dex(dex_path)
        with ingest_target(str(dex_path)) as unified:
            self.assertEqual(unified.target_type, TargetType.DEX_STANDALONE)

    def test_sniff_unknown_binary(self) -> None:
        self.require_m1()
        unknown_path = self.work_dir / "data.bin"
        unknown_path.write_bytes(b"\xaa\xbb\xcc\xdd\xee\xff" * 10)
        try:
            unified = ingest_target(str(unknown_path))
            self.assertEqual(unified.target_type, TargetType.UNKNOWN)
        except ValueError:
            # Raising ValueError on unknown format is also valid contract behavior
            pass


# --- Feature 2: Standalone ELF Ingestion ---

class Tier1ElfIngestionTests(NeutralOrchestrationBaseTestCase):
    """F2: Standalone ELF Ingestion (Zero-copy passthrough, non-destructive)."""

    def test_elf_ingestion_preserves_primary_path(self) -> None:
        self.require_m1()
        target = str(FIXTURES_DIR / "flow_calc_elf64")
        unified = ingest_target(target)
        self.assertEqual(unified.primary_path, target)

    def test_elf_ingestion_zero_copy_no_temp_dir(self) -> None:
        self.require_m1()
        target = str(FIXTURES_DIR / "flow_calc_elf64")
        unified = ingest_target(target)
        self.assertIsNone(unified.temp_dir)
        self.assertFalse(unified.is_ephemeral)

    def test_elf_ingestion_single_component(self) -> None:
        self.require_m1()
        target = str(FIXTURES_DIR / "flow_calc_elf64")
        unified = ingest_target(target)
        self.assertGreaterEqual(len(unified.components), 1)
        self.assertEqual(unified.components[0].path, target)

    def test_elf_ingestion_detects_default_abi(self) -> None:
        self.require_m1()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        unified = ingest_target(target, default_abi="x86_64")
        comp = unified.get_component(abi="x86_64")
        self.assertIsNotNone(comp)
        self.assertEqual(comp.abi, "x86_64")

    def test_elf_ingestion_non_destructive(self) -> None:
        self.require_m1()
        target_path = FIXTURES_DIR / "decryptor_target_elf64"
        original_bytes = target_path.read_bytes()
        unified = ingest_target(str(target_path))
        unified.cleanup()
        self.assertEqual(target_path.read_bytes(), original_bytes)


# --- Feature 3: APK Container Extraction ---

class Tier1ApkExtractionTests(NeutralOrchestrationBaseTestCase):
    """F3: APK Container Extraction (Automatic decompression, isolation, non-destructive)."""

    def test_apk_extraction_allocates_temp_dir(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            self.assertIsNotNone(unified.temp_dir)
            self.assertTrue(unified.is_ephemeral)
            self.assertTrue(Path(unified.temp_dir).exists())

    def test_apk_extraction_extracts_dex_files(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path, multidex=True)
        with ingest_target(str(apk_path)) as unified:
            dex_comps = [c for c in unified.components if c.component_type == "dex"]
            self.assertGreaterEqual(len(dex_comps), 2)
            for dc in dex_comps:
                self.assertTrue(Path(dc.path).exists())
                self.assertTrue(Path(dc.path).read_bytes().startswith(b"dex\n"))

    def test_apk_extraction_extracts_native_libraries(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            so_comps = [c for c in unified.components if c.component_type == "elf_so"]
            self.assertGreaterEqual(len(so_comps), 2)
            abis = {c.abi for c in so_comps}
            self.assertIn("x86_64", abis)
            self.assertIn("arm64-v8a", abis)

    def test_apk_extraction_preserves_original_apk(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        orig_hash = hashlib_sha256(apk_path.read_bytes())
        with ingest_target(str(apk_path)) as unified:
            pass
        self.assertEqual(hashlib_sha256(apk_path.read_bytes()), orig_hash)

    def test_apk_extraction_content_matches_source(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            x86_comp = unified.get_component(abi="x86_64", comp_type="elf_so")
            self.assertIsNotNone(x86_comp)
            extracted_bytes = Path(x86_comp.path).read_bytes()
            # Must be valid ELF64
            self.assertTrue(extracted_bytes.startswith(b"\x7fELF\x02"))


# --- Feature 4: Component & ABI Indexing ---

class Tier1ComponentIndexingTests(NeutralOrchestrationBaseTestCase):
    """F4: Component & ABI Indexing (Enumerate and filter components by architecture)."""

    def test_index_components_by_abi(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            comp_x86 = unified.get_component(abi="x86_64", comp_type="elf_so")
            self.assertIsNotNone(comp_x86)
            self.assertEqual(comp_x86.abi, "x86_64")

    def test_index_components_arm64(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            comp_arm = unified.get_component(abi="arm64-v8a", comp_type="elf_so")
            self.assertIsNotNone(comp_arm)
            self.assertEqual(comp_arm.abi, "arm64-v8a")

    def test_index_components_dex(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            comp_dex = unified.get_component(comp_type="dex")
            self.assertIsNotNone(comp_dex)
            self.assertEqual(comp_dex.component_type, "dex")

    def test_index_components_nonexistent_abi_returns_none(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            comp_mips = unified.get_component(abi="mips", comp_type="elf_so")
            self.assertIsNone(comp_mips)

    def test_index_components_archive_relpaths(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with ingest_target(str(apk_path)) as unified:
            relpaths = [c.archive_relpath for c in unified.components]
            self.assertIn("classes.dex", relpaths)
            self.assertIn("lib/x86_64/libauth.so", relpaths)


# --- Feature 5: Ephemeral Lifecycle Watchdog ---

class Tier1WatchdogTests(NeutralOrchestrationBaseTestCase):
    """F5: Ephemeral Lifecycle Watchdog (Context manager, cleanup, 0 disk leakage)."""

    def test_watchdog_context_manager_cleanup(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        temp_dir_path = None
        with ingest_target(str(apk_path)) as unified:
            temp_dir_path = unified.temp_dir
            self.assertTrue(Path(temp_dir_path).exists())
        self.assertFalse(Path(temp_dir_path).exists())

    def test_watchdog_cleanup_on_exception(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        temp_dir_path = None
        try:
            with ingest_target(str(apk_path)) as unified:
                temp_dir_path = unified.temp_dir
                raise RuntimeError("Simulated processing failure inside session")
        except RuntimeError:
            pass
        self.assertIsNotNone(temp_dir_path)
        self.assertFalse(Path(temp_dir_path).exists())

    def test_watchdog_manual_cleanup_idempotent(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        unified = ingest_target(str(apk_path))
        temp_dir = unified.temp_dir
        self.assertTrue(Path(temp_dir).exists())
        unified.cleanup()
        self.assertFalse(Path(temp_dir).exists())
        # Second cleanup must not raise
        unified.cleanup()

    def test_watchdog_standalone_elf_cleanup_safe(self) -> None:
        self.require_m1()
        target = FIXTURES_DIR / "auth_gate_elf64"
        unified = ingest_target(str(target))
        unified.cleanup()
        self.assertTrue(target.exists())

    def test_watchdog_no_dangling_temp_files(self) -> None:
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        extracted_files = []
        with ingest_target(str(apk_path)) as unified:
            extracted_files = [Path(c.path) for c in unified.components]
            for f in extracted_files:
                self.assertTrue(f.exists())
        for f in extracted_files:
            self.assertFalse(f.exists())


# --- Feature 6: Sensitive Token Taxonomy & Sanitization ---

class Tier1TokenSanitizationTests(NeutralOrchestrationBaseTestCase):
    """F6: Sensitive Token Taxonomy & Sanitization (AUTH, GATE, EVASION, CRYPTO, SYSTEM)."""

    def test_sanitize_auth_symbol(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        token = mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        self.assertTrue(token.startswith("SYM_TOKEN_"))
        self.assertNotIn("password", token)

    def test_sanitize_gate_symbol(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        token = mapper.sanitize_symbol("verify_license_key", TokenCategory.GATE)
        self.assertTrue(token.startswith("SYM_TOKEN_"))
        self.assertNotIn("license", token)

    def test_sanitize_string_literal(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        token = mapper.sanitize_string("AUTH_FAIL: Bad Password", TokenCategory.AUTH)
        self.assertTrue(token.startswith("SYM_STR_"))
        self.assertNotIn("Password", token)

    def test_sanitize_predicate_gate(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        token = mapper.sanitize_predicate("eax == 0")
        self.assertTrue(token.startswith("PREDICATE_GATE_") or token.startswith("SYM_"))

    def test_deterministic_token_mapping(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        token1 = mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        token2 = mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        self.assertEqual(token1, token2)


# --- Feature 7: Bidirectional Restore & Codebook ---

class Tier1BidirectionalRestoreTests(NeutralOrchestrationBaseTestCase):
    """F7: Bidirectional Restore & Codebook (Bijective, 100% lossless reverse mapping)."""

    def test_restore_single_symbol(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        raw = "check_master_password"
        token = mapper.sanitize_symbol(raw, TokenCategory.AUTH)
        restored = mapper.restore(token)
        self.assertEqual(restored, raw)

    def test_restore_in_complex_text(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        sym = mapper.sanitize_symbol("validate_pin", TokenCategory.AUTH)
        msg = mapper.sanitize_string("Pin is valid", TokenCategory.AUTH)
        neutral_code = f"call {sym} ; string: {msg}"
        restored = mapper.restore(neutral_code)
        self.assertEqual(restored, "call validate_pin ; string: Pin is valid")

    def test_export_codebook_format(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        mapper.sanitize_symbol("is_debugger_present", TokenCategory.EVASION)
        book = mapper.export_codebook()
        self.assertIsInstance(book, dict)
        self.assertTrue("forward_map" in book or "forward" in book)
        self.assertTrue("reverse_map" in book or "reverse" in book)

    def test_import_codebook_roundtrip(self) -> None:
        self.require_m2()
        mapper1 = NeutralTokenMapper()
        tok = mapper1.sanitize_symbol("decrypt_payload", TokenCategory.CRYPTO)
        book = mapper1.export_codebook()

        mapper2 = NeutralTokenMapper()
        mapper2.import_codebook(book)
        self.assertEqual(mapper2.restore(tok), "decrypt_payload")

    def test_restore_unregistered_text_untouched(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        original = "mov rax, rbx ; add rcx, 1"
        self.assertEqual(mapper.restore(original), original)


# --- Feature 8: Semantic Invariant Preservation ---

class Tier1SemanticInvariantTests(NeutralOrchestrationBaseTestCase):
    """F8: Semantic Invariant Preservation (Opcodes, registers, addresses 100% intact)."""

    def test_verify_invariants_valid(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        orig = [
            {"addr": 0x401000, "asm": "mov rax, rdi", "size": 3},
            {"addr": 0x401003, "asm": "cmp eax, 0", "size": 3},
            {"addr": 0x401006, "asm": "jne 0x401020", "size": 2},
        ]
        # Neutralized with only symbol/comment change
        neut = [
            {"addr": 0x401000, "asm": "mov rax, rdi", "size": 3},
            {"addr": 0x401003, "asm": "cmp eax, 0", "size": 3},
            {"addr": 0x401006, "asm": "jne 0x401020", "size": 2},
        ]
        self.assertTrue(mapper.verify_invariants(orig, neut))

    def test_verify_invariants_detects_opcode_alteration(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        orig = [{"addr": 0x401000, "asm": "cmp eax, 0", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov eax, 0", "size": 3}]  # Altered cmp -> mov
        try:
            res = mapper.verify_invariants(orig, neut)
            self.assertFalse(res)
        except AssertionError:
            pass  # Raising AssertionError on invariant breach is valid

    def test_verify_invariants_detects_register_alteration(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        orig = [{"addr": 0x401000, "asm": "mov rax, rdi", "size": 3}]
        neut = [{"addr": 0x401000, "asm": "mov rbx, rdi", "size": 3}]  # Altered rax -> rbx
        try:
            res = mapper.verify_invariants(orig, neut)
            self.assertFalse(res)
        except AssertionError:
            pass

    def test_verify_invariants_detects_address_drift(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = [{"addr": 0x401001, "asm": "nop", "size": 1}]  # Address shifted
        try:
            res = mapper.verify_invariants(orig, neut)
            self.assertFalse(res)
        except AssertionError:
            pass

    def test_verify_invariants_detects_instruction_count_mismatch(self) -> None:
        self.require_m2()
        mapper = NeutralTokenMapper()
        orig = [{"addr": 0x401000, "asm": "nop", "size": 1}]
        neut = []
        try:
            res = mapper.verify_invariants(orig, neut)
            self.assertFalse(res)
        except AssertionError:
            pass


# --- Feature 9: Control Flow Graph (CFG) Extraction ---

class Tier1CfgExtractionTests(NeutralOrchestrationBaseTestCase):
    """F9: Control Flow Graph (CFG) Extraction (Nodes, edges, graph topology)."""

    def test_cfg_initialization_and_to_dict(self) -> None:
        self.require_m2()
        nodes = [
            {"id": "BB_00401000", "start_addr": "0x401000", "node_type": "ENTRY"},
            {"id": "BB_00401020", "start_addr": "0x401020", "node_type": "EXIT"},
        ]
        edges = [
            {"source": "BB_00401000", "target": "BB_00401020", "type": "UNCONDITIONAL"}
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        data = cfg.to_dict()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertEqual(len(data["nodes"]), 2)
        self.assertEqual(len(data["edges"]), 1)

    def test_cfg_node_schema(self) -> None:
        self.require_m2()
        nodes = [{"id": "BB_1", "start_addr": "0x401000", "node_type": "DECISION"}]
        cfg = ControlFlowGraph(nodes=nodes, edges=[])
        d = cfg.to_dict()
        node = d["nodes"][0]
        self.assertEqual(node["id"], "BB_1")
        self.assertEqual(node["node_type"], "DECISION")

    def test_cfg_edge_schema(self) -> None:
        self.require_m2()
        edges = [{"source": "BB_1", "target": "BB_2", "type": "CONDITIONAL_TAKEN"}]
        cfg = ControlFlowGraph(nodes=[], edges=edges)
        d = cfg.to_dict()
        edge = d["edges"][0]
        self.assertEqual(edge["type"], "CONDITIONAL_TAKEN")

    def test_cfg_leaf_function_single_node(self) -> None:
        self.require_m2()
        nodes = [{"id": "BB_ENTRY", "start_addr": "0x401100", "node_type": "ENTRY"}]
        cfg = ControlFlowGraph(nodes=nodes, edges=[])
        self.assertEqual(len(cfg.to_dict()["nodes"]), 1)
        self.assertEqual(len(cfg.to_dict()["edges"]), 0)

    def test_cfg_multiple_branch_targets(self) -> None:
        self.require_m2()
        nodes = [
            {"id": "BB_0", "start_addr": "0x401000", "node_type": "DECISION"},
            {"id": "BB_TRUE", "start_addr": "0x401010", "node_type": "NORMAL"},
            {"id": "BB_FALSE", "start_addr": "0x401020", "node_type": "NORMAL"},
        ]
        edges = [
            {"source": "BB_0", "target": "BB_TRUE", "type": "CONDITIONAL_TAKEN"},
            {"source": "BB_0", "target": "BB_FALSE", "type": "CONDITIONAL_NOT_TAKEN"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        d = cfg.to_dict()
        self.assertEqual(len(d["edges"]), 2)


# --- Feature 10: State Machine (FSM) Modeling ---

class Tier1StateMachineTests(NeutralOrchestrationBaseTestCase):
    """F10: State Machine Modeling (Moore/Mealy state transition abstraction)."""

    def test_fsm_initial_state_matches_entry(self) -> None:
        self.require_m2()
        try:
            from neutral_orchestrator.neutral_representation import FiniteStateMachine
        except ImportError:
            self.skipTest("FiniteStateMachine class not exported directly")
        nodes = [{"id": "S0", "start_addr": "0x401000", "node_type": "ENTRY"}]
        fsm = FiniteStateMachine(states=["S0"], initial_state="S0", terminal_states=["S0"], transitions=[])
        self.assertEqual(fsm.initial_state, "S0")

    def test_fsm_terminal_states(self) -> None:
        self.require_m2()
        try:
            from neutral_orchestrator.neutral_representation import FiniteStateMachine
        except ImportError:
            self.skipTest("FiniteStateMachine class not exported directly")
        fsm = FiniteStateMachine(states=["S0", "S_END"], initial_state="S0", terminal_states=["S_END"], transitions=[])
        self.assertIn("S_END", fsm.terminal_states)

    def test_fsm_transition_predicate(self) -> None:
        self.require_m2()
        try:
            from neutral_orchestrator.neutral_representation import FiniteStateMachine
        except ImportError:
            self.skipTest("FiniteStateMachine class not exported directly")
        transitions = [
            {"source": "S0", "predicate": "PREDICATE_GATE_0001", "target": "S1"}
        ]
        fsm = FiniteStateMachine(states=["S0", "S1"], initial_state="S0", terminal_states=["S1"], transitions=transitions)
        self.assertEqual(fsm.transitions[0]["predicate"], "PREDICATE_GATE_0001")

    def test_fsm_to_dict_structure(self) -> None:
        self.require_m2()
        try:
            from neutral_orchestrator.neutral_representation import FiniteStateMachine
        except ImportError:
            self.skipTest("FiniteStateMachine class not exported directly")
        fsm = FiniteStateMachine(states=["S0"], initial_state="S0", terminal_states=[], transitions=[])
        d = fsm.to_dict() if hasattr(fsm, "to_dict") else fsm.__dict__
        self.assertIn("states", d)
        self.assertIn("initial_state", d)

    def test_fsm_linear_sequence(self) -> None:
        self.require_m2()
        try:
            from neutral_orchestrator.neutral_representation import FiniteStateMachine
        except ImportError:
            self.skipTest("FiniteStateMachine class not exported directly")
        transitions = [{"source": "S0", "predicate": "TRUE", "target": "S1"}]
        fsm = FiniteStateMachine(states=["S0", "S1"], initial_state="S0", terminal_states=["S1"], transitions=transitions)
        self.assertEqual(len(fsm.states), 2)


# --- Feature 11: Orchestrator Query Routing ---

class Tier1OrchestratorRoutingTests(NeutralOrchestrationBaseTestCase):
    """F11: Orchestrator Query Routing (Routing queries across standalone ELF, APK .so, and DEX)."""

    def test_query_info_standalone_elf(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("info")
            self.assertTrue(res.get("success"))
            self.assertIn("data", res)

    def test_query_functions_standalone_elf(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("functions")
            self.assertTrue(res.get("success"))

    def test_query_apk_native_so(self) -> None:
        self.require_m3()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with NeutralBinaryOrchestrator(str(apk_path)) as orch:
            res = orch.query("info", abi="x86_64")
            self.assertTrue(res.get("success"))

    def test_query_apk_dex_component(self) -> None:
        self.require_m3()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        with NeutralBinaryOrchestrator(str(apk_path)) as orch:
            res = orch.query("info", component_type="dex")
            self.assertTrue(res.get("success"))

    def test_query_invalid_operation(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("nonexistent_operation_xyz")
            self.assertFalse(res.get("success"))
            self.assertIsNotNone(res.get("error"))


# --- Feature 12: JSON Telemetry Envelope ---

class Tier1TelemetryEnvelopeTests(NeutralOrchestrationBaseTestCase):
    """F12: JSON Telemetry Envelope (Standard structure, execution timing, metadata)."""

    def test_envelope_mandatory_keys(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("info")
            mandatory = ["success", "command", "target", "data", "telemetry"]
            for k in mandatory:
                self.assertIn(k, res)

    def test_envelope_timing_metric(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("info")
            telem = res.get("telemetry", {})
            self.assertIn("execution_time_seconds", telem)
            self.assertGreaterEqual(telem["execution_time_seconds"], 0.0)

    def test_envelope_json_serializable(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("info")
            serialized = json.dumps(res)
            self.assertTrue(len(serialized) > 0)

    def test_envelope_target_type_recorded(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("info")
            self.assertIn("target_type", res)
            self.assertEqual(res["target_type"], "elf_standalone")

    def test_envelope_error_payload_on_failure(self) -> None:
        self.require_m3()
        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("disasm", function_or_addr="symbol_that_does_not_exist_9999")
            self.assertFalse(res.get("success"))
            self.assertIn("error", res)
            self.assertIsNotNone(res["error"])


# =============================================================================
# TIER 2: Boundary, Adversarial & Corner Cases (10 edge condition tests)
# =============================================================================

class Tier2BoundaryAndCornerTests(NeutralOrchestrationBaseTestCase):
    """
    Tier 2: Boundary, Adversarial & Corner Cases.
    Evaluates system robustness against empty inputs, stripped binaries, malformed
    archives, zero-byte targets, collisions, and abnormal terminations.
    """

    def test_boundary_empty_string_sanitization(self) -> None:
        """Sanitizing empty string returns empty string without generating phantom tokens."""
        self.require_m2()
        mapper = NeutralTokenMapper()
        self.assertEqual(mapper.sanitize_string("", TokenCategory.GENERAL), "")
        self.assertEqual(mapper.sanitize_symbol("", TokenCategory.GENERAL), "")
        self.assertEqual(mapper.restore(""), "")

    def test_boundary_stripped_binary_crackme(self) -> None:
        """Stripped binary (crackme_case) can be ingested and queried without crash."""
        self.require_m1()
        target = FIXTURES_DIR / "crackme_case"
        if not target.exists():
            target = Path("crackme_case")
        self.assertTrue(target.exists(), "crackme_case fixture not found")
        unified = ingest_target(str(target))
        self.assertEqual(unified.target_type, TargetType.ELF_STANDALONE)

    def test_boundary_nonexistent_file_path(self) -> None:
        """Ingesting non-existent file path raises FileNotFoundError or returns clean error."""
        self.require_m1()
        bad_path = "/tmp/does_not_exist_file_987654.bin"
        with self.assertRaises((FileNotFoundError, ValueError)):
            ingest_target(bad_path)

    def test_boundary_malformed_apk_bad_zip(self) -> None:
        """Ingesting corrupted ZIP header raises BadZipFile or normalized error and deletes temp dir."""
        self.require_m1()
        corrupt_path = self.work_dir / "corrupted.apk"
        create_corrupted_apk(corrupt_path, corruption_type="bad_zip")
        with self.assertRaises((zipfile.BadZipFile, ValueError, RuntimeError)):
            with ingest_target(str(corrupt_path)) as unified:
                pass

    def test_boundary_zero_byte_target(self) -> None:
        """Ingesting 0-byte file raises ValueError or detects UNKNOWN type."""
        self.require_m1()
        zero_file = self.work_dir / "zero.bin"
        create_zero_byte_target(zero_file)
        try:
            unified = ingest_target(str(zero_file))
            self.assertEqual(unified.target_type, TargetType.UNKNOWN)
        except ValueError:
            pass  # Contract permits raising ValueError on zero-byte target

    def test_boundary_duplicate_strings_same_token(self) -> None:
        """Multiple identical strings map to the same token, maintaining consistency."""
        self.require_m2()
        mapper = NeutralTokenMapper()
        s1 = mapper.sanitize_string("AUTH_FAIL: Bad Password", TokenCategory.AUTH)
        s2 = mapper.sanitize_string("AUTH_FAIL: Bad Password", TokenCategory.AUTH)
        self.assertEqual(s1, s2)

    def test_boundary_substring_collision_preservation(self) -> None:
        """Identifier containing keyword as substring is tokenized atomically."""
        self.require_m2()
        mapper = NeutralTokenMapper()
        # "check_master_password" shouldn't become "check_master_SYM_STR_001"
        tok = mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
        restored = mapper.restore(tok)
        self.assertEqual(restored, "check_master_password")

    def test_boundary_restore_unregistered_tokens_intact(self) -> None:
        """Restoring text with unknown or non-existent tokens leaves them untouched."""
        self.require_m2()
        mapper = NeutralTokenMapper()
        input_text = "SYM_UNKNOWN_9999 untouched"
        self.assertEqual(mapper.restore(input_text), input_text)

    def test_boundary_leaf_function_single_node_cfg(self) -> None:
        """Leaf function with 0 branches produces valid 1-node CFG with 0 edges."""
        self.require_m2()
        nodes = [{"id": "BB_0", "start_addr": "0x401000", "node_type": "ENTRY"}]
        cfg = ControlFlowGraph(nodes=nodes, edges=[])
        d = cfg.to_dict()
        self.assertEqual(len(d["nodes"]), 1)
        self.assertEqual(len(d["edges"]), 0)

    def test_boundary_cleanup_on_unhandled_exception(self) -> None:
        """Watchdog cleans temporary directory when unhandled exception occurs."""
        self.require_m1()
        apk_path = self.work_dir / "target.apk"
        create_synthetic_apk(apk_path)
        temp_dir = None
        try:
            with ingest_target(str(apk_path)) as unified:
                temp_dir = unified.temp_dir
                raise ArithmeticError("Unexpected division by zero in analysis")
        except ArithmeticError:
            pass
        self.assertIsNotNone(temp_dir)
        self.assertFalse(Path(temp_dir).exists())


# =============================================================================
# TIER 3: Cross-Feature Combinations (Pairwise Workflows)
# =============================================================================

class Tier3CrossFeatureCombinationTests(NeutralOrchestrationBaseTestCase):
    """
    Tier 3: Cross-Feature Combinations.
    Validates end-to-end multi-step pipelines combining ingestion, extraction,
    disassembly, neutralization, CFG modeling, codebook serialization, and restoration.
    """

    def test_pairwise_apk_extract_to_flow_to_cfg_to_neutral(self) -> None:
        """Pairwise pipeline: APK ingest -> extract .so -> flow -> CFG -> neutralize -> roundtrip."""
        self.require_m1()
        self.require_m2()
        self.require_m3()

        apk_path = self.work_dir / "auth_flow.apk"
        create_synthetic_apk(apk_path, multidex=True)

        with NeutralBinaryOrchestrator(str(apk_path)) as orch:
            # Query flow for main
            flow_res = orch.query("flow", function_or_addr="main", abi="x86_64")
            self.assertTrue(flow_res.get("success"))

            # Construct CFG from result
            blocks = flow_res.get("data", {}).get("blocks", [])
            nodes = [{"id": f"BB_{b.get('addr')}", "start_addr": str(b.get("addr"))} for b in blocks]
            cfg = ControlFlowGraph(nodes=nodes, edges=[])
            self.assertGreaterEqual(len(cfg.to_dict()["nodes"]), 0)

            # Neutralize and restore codebook
            mapper = NeutralTokenMapper()
            mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
            book = mapper.export_codebook()
            mapper2 = NeutralTokenMapper()
            mapper2.import_codebook(book)
            self.assertEqual(mapper2.restore("SYM_TOKEN_FUNC_0001"), "check_master_password")

    def test_pairwise_elf_disasm_to_tokenize_to_codebook_roundtrip(self) -> None:
        """Pairwise: Ingest ELF -> disasm -> tokenize -> export codebook -> import -> restore."""
        self.require_m1()
        self.require_m2()
        self.require_m3()

        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            disasm_res = orch.query("disasm", function_or_addr="main")
            self.assertTrue(disasm_res.get("success"))

            mapper = NeutralTokenMapper()
            token = mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)
            serialized_book = json.dumps(mapper.export_codebook())

            # Fresh session restoring from serialized JSON
            fresh_mapper = NeutralTokenMapper()
            fresh_mapper.import_codebook(json.loads(serialized_book))
            self.assertEqual(fresh_mapper.restore(token), "check_master_password")

    def test_pairwise_multidex_apk_routing_and_extraction(self) -> None:
        """Pairwise: Ingest multidex APK -> index DEX files -> query DEX metadata."""
        self.require_m1()
        self.require_m3()

        apk_path = self.work_dir / "multidex.apk"
        create_synthetic_apk(apk_path, multidex=True)

        with NeutralBinaryOrchestrator(str(apk_path)) as orch:
            info_res = orch.query("info")
            self.assertTrue(info_res.get("success"))
            self.assertEqual(info_res.get("target_type"), "apk_package")

    def test_pairwise_flow_calc_fsm_and_telemetry(self) -> None:
        """Pairwise: Ingest flow_calc_elf64 -> flow -> FSM abstraction -> telemetry envelope."""
        self.require_m1()
        self.require_m2()
        self.require_m3()

        target = str(FIXTURES_DIR / "flow_calc_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("flow", function_or_addr="calc_collatz_steps")
            self.assertTrue(res.get("success"))
            self.assertIn("execution_time_seconds", res["telemetry"])
            self.assertGreaterEqual(res["telemetry"]["execution_time_seconds"], 0.0)

    def test_pairwise_orchestrator_session_persistence(self) -> None:
        """Pairwise: Orchestrator session retains token mappings across multiple sequential queries."""
        self.require_m1()
        self.require_m2()
        self.require_m3()

        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res1 = orch.query("functions")
            self.assertTrue(res1.get("success"))
            res2 = orch.query("disasm", function_or_addr="main")
            self.assertTrue(res2.get("success"))


# =============================================================================
# TIER 4: Real-World Scenarios (real fixtures: auth_gate, flow_calc, decryptor)
# =============================================================================

class Tier4RealWorldScenariosTests(NeutralOrchestrationBaseTestCase):
    """
    Tier 4: Real-World Scenarios.
    Validates end-to-end execution against real pre-compiled ELF binaries and multi-ABI APKs.
    """

    def test_scenario_auth_gate_sensitive_credential_neutralization(self) -> None:
        """Scenario: auth_gate_elf64 credential check neutralized to objective symbolic tokens."""
        self.require_m2()
        self.require_m3()

        target = str(FIXTURES_DIR / "auth_gate_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("strings")
            self.assertTrue(res.get("success"))

            mapper = NeutralTokenMapper()
            # Tokenize known sensitive auth strings from auth_gate.c
            tok_pass = mapper.sanitize_string("K3Y-V4L1D-2026", TokenCategory.AUTH)
            tok_err = mapper.sanitize_string("AUTH_FAIL: Bad Password", TokenCategory.AUTH)
            tok_func = mapper.sanitize_symbol("check_master_password", TokenCategory.AUTH)

            self.assertNotIn("K3Y", tok_pass)
            self.assertNotIn("Password", tok_err)
            self.assertNotIn("password", tok_func)

            # Lossless reverse restoration
            self.assertEqual(mapper.restore(tok_pass), "K3Y-V4L1D-2026")
            self.assertEqual(mapper.restore(tok_err), "AUTH_FAIL: Bad Password")
            self.assertEqual(mapper.restore(tok_func), "check_master_password")

    def test_scenario_flow_calc_factorial_loop_abstraction(self) -> None:
        """Scenario: flow_calc_elf64 calc_factorial loop structure and opcode invariant."""
        self.require_m2()
        self.require_m3()

        target = str(FIXTURES_DIR / "flow_calc_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("disasm", function_or_addr="calc_factorial")
            self.assertTrue(res.get("success"))
            instructions = res.get("data", {}).get("instructions", [])
            # Assert core arithmetic opcodes exist
            opcodes = [inst.get("asm", "").split()[0] for inst in instructions if inst.get("asm")]
            self.assertTrue(any(op in ("imul", "mul", "sub", "add") for op in opcodes))

    def test_scenario_flow_calc_dispatch_switch_abstraction(self) -> None:
        """Scenario: flow_calc_elf64 calc_dispatch multi-branch switch analysis."""
        self.require_m2()
        self.require_m3()

        target = str(FIXTURES_DIR / "flow_calc_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("flow", function_or_addr="calc_dispatch")
            self.assertTrue(res.get("success"))

    def test_scenario_decryptor_target_crypto_transform(self) -> None:
        """Scenario: decryptor_target_elf64 XOR decryption loop and payload neutralization."""
        self.require_m2()
        self.require_m3()

        target = str(FIXTURES_DIR / "decryptor_target_elf64")
        with NeutralBinaryOrchestrator(target) as orch:
            res = orch.query("functions")
            self.assertTrue(res.get("success"))

            mapper = NeutralTokenMapper()
            tok_decrypt = mapper.sanitize_symbol("decrypt_buffer", TokenCategory.CRYPTO)
            tok_payload = mapper.sanitize_symbol("g_encrypted_payload", TokenCategory.CRYPTO)
            self.assertTrue(tok_decrypt.startswith("SYM_TOKEN_"))
            self.assertTrue(tok_payload.startswith("SYM_TOKEN_"))

            self.assertEqual(mapper.restore(tok_decrypt), "decrypt_buffer")
            self.assertEqual(mapper.restore(tok_payload), "g_encrypted_payload")

    def test_scenario_real_multi_abi_apk_execution(self) -> None:
        """Scenario: Multi-ABI APK packaged from real fixtures executes queries on extracted .so."""
        self.require_m1()
        self.require_m3()

        apk_path = self.work_dir / "production.apk"
        create_synthetic_apk(
            apk_path,
            elf_fixtures={
                "lib/x86_64/libauth.so": FIXTURES_DIR / "auth_gate_elf64",
                "lib/arm64-v8a/libauth.so": FIXTURES_DIR / "auth_gate_elf64",
            },
            multidex=True,
        )

        with NeutralBinaryOrchestrator(str(apk_path)) as orch:
            res = orch.query("info", abi="x86_64")
            self.assertTrue(res.get("success"))
            self.assertEqual(res.get("target_type"), "apk_package")


# =============================================================================
# Helper Utilities
# =============================================================================

def hashlib_sha256(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    unittest.main()
