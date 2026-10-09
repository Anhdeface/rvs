"""
tests/test_challenger_m2_2_cfg_fsm_stress.py - Empirical Stress & Adversarial Challenge Suite.

Authored by teamwork_preview_challenger_m2_2 (CFG & State Transition Challenger).
Empirically stress-tests CFG (Control Flow Graph) and FSM (Finite State Machine) state transition
modeling in neutral_orchestrator/neutral_representation.py under pathological and extreme inputs:

1. Pathological Control Flow Topologies:
   - Self-loops (direct cycle BB_0 -> BB_0)
   - Tight mutual infinite loops (BB_0 <-> BB_1 with no exit)
   - Large circular ring loops (100-node cycle with no entry or exit)
   - Figure-8 knot intersecting cycles
   - Unreachable dead code loops (islands disconnected from entry)
   - Backward loop edges with non-monotonic virtual addresses
   - Deeply nested loop hierarchies (50 nested loop levels)

2. Disconnected Basic Blocks & Degenerate Topologies:
   - Completely isolated basic blocks (V=50, E=0)
   - Multiple disconnected graph components
   - Dangling edges pointing to undefined / out-of-range block targets
   - Missing entry and exit annotations with automatic fallback resolution
   - Multi-entry and multi-exit topologies

3. Complex Switch Jump Tables & Dispatch Architectures:
   - High-fanout dense jump tables (128 case targets)
   - Sparse jump tables with extreme case values (negative, 64-bit max, non-numeric)
   - Nested multi-stage switch dispatchers
   - Duff's device style interleaved switch-loop topologies
   - Binary search cascade dispatchers

4. Empty, Malformed, and Boundary Flow Ingestion:
   - Completely empty flow dict ({})
   - Empty blocks list ({"blocks": []})
   - Blocks with empty dicts or missing keys (None values for addr, jump, fail, size)
   - Non-numeric and malformed string addresses ("sub_401000", hex, dec)
   - Negative and extreme 64-bit addresses (0xFFFFFFFFFFFFFFF0)
   - Duplicate block addresses
   - Empty or malformed decision_nodes payloads

5. State Machine Reachability, Consistency & Moore Model Verification:
   - BFS reachability oracle validating reachable vs unreachable state sets
   - State transition predicate determinism and sequence numbering
   - Complete Moore output mapping across all states
   - Complete JSON serialization roundtrip across all models

6. Algorithmic Pattern Detector Stress & Performance:
   - Exponential DAG diamond lattice (2^20 = 1,048,576 execution paths)
   - Ultra-deep linear chain (1,000 basic blocks)
   - Dense mesh multigraphs (500 nodes, 1,500 edges)
   - Algorithmic pattern detection robustness across XOR crypto, accumulator, Collatz,
     switch tables, recurrence trees, and predicate chains

7. Adversarial Failure Modes & Exception Reproduction:
   - Empirical proof of TypeError when instructions is None (JSON null)
   - Empirical proof of TypeError in ControlFlowGraph.__init__ when instructions is None
   - Empirical proof of TypeError in from_raw_flow when opcode/asm is None
   - Empirical proof of AttributeError in AlgorithmicPatternDetector when opcode is None
   - Empirical proof of AttributeError in FiniteStateMachine.from_cfg when metadata is None
   - Empirical proof of gate counter desync under inverted conditional edge ordering
"""

from __future__ import annotations

import collections
import json
import time
import unittest
from typing import Any, Dict, List, Set

from neutral_orchestrator.neutral_representation import (
    AlgorithmicPatternDetector,
    CFGEdge,
    CFGEdgeType,
    CFGNode,
    ControlFlowGraph,
    FiniteStateMachine,
    PatternMatch,
)


class TestPathologicalCircularLoops(unittest.TestCase):
    """Stress tests on circular, cyclic, and infinite loop control flow structures."""

    def test_self_loop_single_block(self) -> None:
        """Single basic block branching directly back to itself."""
        raw_flow = {
            "function": "sym.infinite_spin",
            "blocks": [
                {
                    "addr": 0x401000,
                    "addr_hex": "0x401000",
                    "size": 5,
                    "jump": 0x401000,
                    "fail": None,
                    "instructions": [
                        {"asm": "jmp 0x401000", "opcode": "jmp"}
                    ],
                }
            ],
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 1)
        self.assertEqual(len(cfg.edges), 1)

        node = cfg.nodes[0]
        self.assertEqual(node["id"], "BB_0x401000")
        self.assertTrue(node["is_entry"])
        # Self-loop detected as loop head because target addr <= source addr
        self.assertTrue(node["is_loop_head"])

        metrics = cfg.calculate_metrics()
        self.assertEqual(metrics["total_nodes"], 1)
        self.assertEqual(metrics["total_edges"], 1)
        self.assertEqual(metrics["loop_count"], 1)
        # Cyclomatic complexity: max(1, 1 - 1 + 2) = 2
        self.assertEqual(metrics["cyclomatic_complexity"], 2)

        # FSM transformation
        fsm = cfg.to_fsm()
        self.assertEqual(fsm.states, ["BB_0x401000"])
        self.assertEqual(fsm.initial_state, "BB_0x401000")
        self.assertEqual(len(fsm.transitions), 1)
        self.assertEqual(fsm.transitions[0]["source"], "BB_0x401000")
        self.assertEqual(fsm.transitions[0]["target"], "BB_0x401000")

        # Pattern detector must not crash or hang
        patterns = cfg.detect_patterns()
        self.assertIsInstance(patterns, list)

    def test_mutual_two_node_infinite_loop_no_exit(self) -> None:
        """Two blocks mutually calling each other with no exit instruction."""
        raw_flow = {
            "function": "sym.ping_pong_loop",
            "blocks": [
                {
                    "addr": 0x401000,
                    "addr_hex": "0x401000",
                    "size": 10,
                    "jump": 0x401010,
                    "fail": None,
                    "instructions": [{"asm": "jmp 0x401010", "opcode": "jmp"}],
                },
                {
                    "addr": 0x401010,
                    "addr_hex": "0x401010",
                    "size": 10,
                    "jump": 0x401000,
                    "fail": None,
                    "instructions": [{"asm": "jmp 0x401000", "opcode": "jmp"}],
                },
            ],
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 2)
        self.assertEqual(len(cfg.edges), 2)

        # Loop head detection: BB_0x401000 should be loop head (jumped to by 0x401010)
        head_node = next(n for n in cfg.nodes if n["id"] == "BB_0x401000")
        self.assertTrue(head_node["is_loop_head"])

        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 2)
        self.assertEqual(fsm.initial_state, "BB_0x401000")
        # Terminal fallback when no exit exists
        self.assertEqual(len(fsm.terminal_states), 1)

        patterns = cfg.detect_patterns()
        self.assertIsInstance(patterns, list)

    def test_large_circular_ring_100_nodes(self) -> None:
        """100 basic blocks forming a single large circular ring."""
        n_blocks = 100
        blocks = []
        for i in range(n_blocks):
            curr_addr = 0x401000 + (i * 0x10)
            next_addr = 0x401000 + (((i + 1) % n_blocks) * 0x10)
            blocks.append({
                "addr": curr_addr,
                "addr_hex": hex(curr_addr),
                "size": 16,
                "jump": next_addr,
                "fail": None,
                "instructions": [
                    {"asm": f"jmp {hex(next_addr)}", "opcode": "jmp"}
                ],
            })

        cfg = ControlFlowGraph.from_rvs_flow({"function": "sym.ring_100", "blocks": blocks})
        self.assertEqual(len(cfg.nodes), 100)
        self.assertEqual(len(cfg.edges), 100)

        metrics = cfg.calculate_metrics()
        self.assertEqual(metrics["total_nodes"], 100)
        self.assertEqual(metrics["total_edges"], 100)
        self.assertEqual(metrics["cyclomatic_complexity"], 2)
        self.assertEqual(metrics["loop_count"], 1)

        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 100)
        self.assertEqual(len(fsm.transitions), 100)

        # Pattern detector on 100-node circular ring terminates promptly
        t0 = time.perf_counter()
        patterns = cfg.detect_patterns()
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 0.5, f"Pattern detection on 100-node ring took too long: {elapsed:.3f}s")

    def test_figure_eight_intersecting_loops(self) -> None:
        """Two loops intersecting at a common hub node (Figure-8 knot topology)."""
        raw_flow = {
            "function": "sym.figure_eight",
            "blocks": [
                {
                    "addr": 0x401000,
                    "addr_hex": "0x401000",
                    "size": 16,
                    "jump": 0x401010,
                    "fail": 0x401020,
                    "instructions": [{"asm": "je 0x401010", "opcode": "je"}],
                },
                {
                    "addr": 0x401010,
                    "addr_hex": "0x401010",
                    "size": 16,
                    "jump": 0x401000,
                    "fail": None,
                    "instructions": [{"asm": "jmp 0x401000", "opcode": "jmp"}],
                },
                {
                    "addr": 0x401020,
                    "addr_hex": "0x401020",
                    "size": 16,
                    "jump": 0x401000,
                    "fail": 0x401030,
                    "instructions": [{"asm": "jne 0x401000", "opcode": "jne"}],
                },
                {
                    "addr": 0x401030,
                    "addr_hex": "0x401030",
                    "size": 4,
                    "jump": None,
                    "fail": None,
                    "instructions": [{"asm": "ret", "opcode": "ret"}],
                },
            ],
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 4)
        self.assertEqual(len(cfg.edges), 5)

        # Loop head is 0x401000
        hub_node = next(n for n in cfg.nodes if n["id"] == "BB_0x401000")
        self.assertTrue(hub_node["is_loop_head"])

        # Natural loop search does not hang on figure-8
        detector = AlgorithmicPatternDetector()
        loop_nodes = detector._find_natural_loop_nodes(cfg, "BB_0x401000")
        self.assertIn("BB_0x401000", loop_nodes)
        self.assertIn("BB_0x401010", loop_nodes)
        self.assertIn("BB_0x401020", loop_nodes)

        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 4)
        self.assertEqual(fsm.terminal_states, ["BB_0x401030"])

    def test_unreachable_dead_loop_islands(self) -> None:
        """Main flow terminates normally, but graph contains an unreachable infinite loop island."""
        raw_flow = {
            "function": "sym.dead_loop_island",
            "blocks": [
                # Main reachable flow
                {
                    "addr": 0x401000,
                    "addr_hex": "0x401000",
                    "size": 10,
                    "jump": 0x401010,
                    "fail": None,
                    "instructions": [{"asm": "jmp 0x401010", "opcode": "jmp"}],
                },
                {
                    "addr": 0x401010,
                    "addr_hex": "0x401010",
                    "size": 4,
                    "jump": None,
                    "fail": None,
                    "instructions": [{"asm": "ret", "opcode": "ret"}],
                },
                # Unreachable dead island cycle: 0x402000 <-> 0x402010
                {
                    "addr": 0x402000,
                    "addr_hex": "0x402000",
                    "size": 10,
                    "jump": 0x402010,
                    "fail": None,
                    "instructions": [{"asm": "jmp 0x402010", "opcode": "jmp"}],
                },
                {
                    "addr": 0x402010,
                    "addr_hex": "0x402010",
                    "size": 10,
                    "jump": 0x402000,
                    "fail": None,
                    "instructions": [{"asm": "jmp 0x402000", "opcode": "jmp"}],
                },
            ],
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 4)
        self.assertEqual(len(cfg.edges), 3)

        fsm = cfg.to_fsm()
        self.assertEqual(fsm.initial_state, "BB_0x401000")
        self.assertEqual(fsm.terminal_states, ["BB_0x401010"])

        # BFS reachability analysis verifies dead island is unreachable from initial_state
        adj: Dict[str, Set[str]] = collections.defaultdict(set)
        for t in fsm.transitions:
            adj[t["source"]].add(t["target"])

        visited: Set[str] = set()
        queue = collections.deque([fsm.initial_state])
        while queue:
            curr = queue.popleft()
            if curr not in visited:
                visited.add(curr)
                queue.extend(adj[curr] - visited)

        self.assertIn("BB_0x401000", visited)
        self.assertIn("BB_0x401010", visited)
        self.assertNotIn("BB_0x402000", visited)
        self.assertNotIn("BB_0x402010", visited)

    def test_loop_backward_edge_non_monotonic_addresses(self) -> None:
        """Loop where the loop header has a HIGHER address than the latch block."""
        nodes = [
            {"id": "BB_ENTRY", "address": "0x401000", "node_type": "ENTRY"},
            {"id": "BB_LATCH", "address": "0x401020", "node_type": "NORMAL"},
            {"id": "BB_HEAD", "address": "0x401050", "node_type": "NORMAL", "is_loop_head": True},
            {"id": "BB_EXIT", "address": "0x401080", "node_type": "EXIT"},
        ]
        edges = [
            {"source": "BB_ENTRY", "target": "BB_HEAD", "type": "FALLTHROUGH"},
            {"source": "BB_HEAD", "target": "BB_LATCH", "type": "CONDITIONAL_TAKEN"},
            {"source": "BB_HEAD", "target": "BB_EXIT", "type": "CONDITIONAL_NOT_TAKEN"},
            {"source": "BB_LATCH", "target": "BB_HEAD", "type": "UNCONDITIONAL"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 4)
        self.assertEqual(fsm.initial_state, "BB_ENTRY")
        self.assertEqual(fsm.terminal_states, ["BB_EXIT"])

        detector = AlgorithmicPatternDetector()
        loop_nodes = detector._find_natural_loop_nodes(cfg, "BB_HEAD")
        self.assertIn("BB_HEAD", loop_nodes)
        self.assertIn("BB_LATCH", loop_nodes)

    def test_deeply_nested_loops_50_levels(self) -> None:
        """50 nested loop levels with nested latch back-edges."""
        nodes = [{"id": "BB_ENTRY", "address": "0x400000", "node_type": "ENTRY"}]
        edges = [{"source": "BB_ENTRY", "target": "BB_H_0", "type": "FALLTHROUGH"}]

        depth = 50
        for d in range(depth):
            nodes.append({"id": f"BB_H_{d}", "address": hex(0x401000 + d * 0x100), "is_loop_head": True})
            if d + 1 < depth:
                edges.append({"source": f"BB_H_{d}", "target": f"BB_H_{d+1}", "type": "FALLTHROUGH"})
            else:
                nodes.append({"id": "BB_INNER_BODY", "address": "0x409000"})
                edges.append({"source": f"BB_H_{d}", "target": "BB_INNER_BODY", "type": "FALLTHROUGH"})

        # Back-edges from inner body outwards
        edges.append({"source": "BB_INNER_BODY", "target": f"BB_H_{depth-1}", "type": "UNCONDITIONAL"})
        for d in range(depth - 1, 0, -1):
            edges.append({"source": f"BB_H_{d}", "target": f"BB_H_{d-1}", "type": "CONDITIONAL_NOT_TAKEN"})
        nodes.append({"id": "BB_EXIT", "address": "0x410000", "node_type": "EXIT"})
        edges.append({"source": "BB_H_0", "target": "BB_EXIT", "type": "CONDITIONAL_NOT_TAKEN"})

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        metrics = cfg.calculate_metrics()
        self.assertEqual(metrics["loop_count"], depth)

        # FSM and patterns run without recursion depth error
        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), len(nodes))
        patterns = cfg.detect_patterns()
        self.assertIsInstance(patterns, list)


class TestDisconnectedAndDegenerateTopologies(unittest.TestCase):
    """Stress tests on disconnected basic blocks, dangling edges, and degenerate topologies."""

    def test_completely_isolated_blocks_no_edges(self) -> None:
        """CFG containing 50 completely isolated vertices with zero edges."""
        n_nodes = 50
        nodes = [
            {"id": f"BB_{i}", "address": hex(0x401000 + i * 0x10), "node_type": "ENTRY" if i == 0 else "NORMAL"}
            for i in range(n_nodes)
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=[])
        self.assertEqual(len(cfg.nodes), 50)
        self.assertEqual(len(cfg.edges), 0)

        metrics = cfg.calculate_metrics()
        self.assertEqual(metrics["total_nodes"], 50)
        self.assertEqual(metrics["total_edges"], 0)
        self.assertEqual(metrics["cyclomatic_complexity"], 1)

        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 50)
        self.assertEqual(fsm.initial_state, "BB_0")
        self.assertEqual(len(fsm.transitions), 0)
        self.assertEqual(fsm.terminal_states, ["BB_49"])

        patterns = cfg.detect_patterns()
        self.assertIsInstance(patterns, list)

    def test_multiple_disconnected_components(self) -> None:
        """5 completely separate connected components (clusters), each with 3 blocks."""
        nodes = []
        edges = []
        for comp in range(5):
            for step in range(3):
                nid = f"C{comp}_B{step}"
                addr = hex(0x400000 + comp * 0x1000 + step * 0x10)
                nodes.append({
                    "id": nid,
                    "address": addr,
                    "is_entry": (comp == 0 and step == 0),
                    "is_exit": (step == 2),
                })
                if step < 2:
                    edges.append({
                        "source": nid,
                        "target": f"C{comp}_B{step+1}",
                        "type": "FALLTHROUGH",
                    })

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        self.assertEqual(len(cfg.nodes), 15)
        self.assertEqual(len(cfg.edges), 10)

        fsm = cfg.to_fsm()
        self.assertEqual(fsm.initial_state, "C0_B0")
        self.assertEqual(len(fsm.terminal_states), 5)
        self.assertEqual(len(fsm.transitions), 10)

    def test_dangling_edge_referencing_nonexistent_target(self) -> None:
        """Edge pointing to a target block ID that does not exist in nodes."""
        nodes = [
            {"id": "BB_0", "address": "0x401000", "is_entry": True},
            {"id": "BB_1", "address": "0x401010", "is_exit": True},
        ]
        edges = [
            {"source": "BB_0", "target": "BB_1", "type": "FALLTHROUGH"},
            {"source": "BB_0", "target": "BB_NONEXISTENT_EXTERNAL_PLT", "type": "CALL"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        metrics = cfg.calculate_metrics()
        self.assertEqual(metrics["total_nodes"], 2)
        self.assertEqual(metrics["total_edges"], 2)

        # FSM must construct gracefully without KeyError
        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.transitions), 2)
        self.assertIn("BB_0", fsm.states)
        self.assertIn("BB_1", fsm.states)
        self.assertEqual(fsm.transitions[1]["target"], "BB_NONEXISTENT_EXTERNAL_PLT")

        # Pattern detector does not crash
        patterns = cfg.detect_patterns()
        self.assertIsInstance(patterns, list)

    def test_dangling_edge_referencing_nonexistent_source(self) -> None:
        """Edge originating from an unknown source ID."""
        nodes = [{"id": "BB_0", "address": "0x401000", "is_entry": True}]
        edges = [{"source": "BB_UNKNOWN_GHOST", "target": "BB_0", "type": "UNCONDITIONAL"}]

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()
        self.assertEqual(fsm.transitions[0]["source"], "BB_UNKNOWN_GHOST")
        self.assertEqual(fsm.transitions[0]["target"], "BB_0")

    def test_missing_entry_and_exit_annotations(self) -> None:
        """Graph with neither entry nor exit flags; verifies deterministic fallback."""
        nodes = [
            {"id": "BB_ALPHA", "address": "0x401000"},
            {"id": "BB_BETA", "address": "0x401010"},
        ]
        edges = [{"source": "BB_ALPHA", "target": "BB_BETA", "type": "FALLTHROUGH"}]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()

        self.assertEqual(fsm.initial_state, "BB_ALPHA")
        self.assertEqual(fsm.terminal_states, ["BB_BETA"])

    def test_multiple_entry_points(self) -> None:
        """Graph with multiple entry points (e.g. shared library multiple exports)."""
        nodes = [
            {"id": "BB_ENTRY_A", "address": "0x401000", "is_entry": True},
            {"id": "BB_ENTRY_B", "address": "0x401050", "is_entry": True},
            {"id": "BB_COMMON_EXIT", "address": "0x401090", "is_exit": True},
        ]
        edges = [
            {"source": "BB_ENTRY_A", "target": "BB_COMMON_EXIT", "type": "FALLTHROUGH"},
            {"source": "BB_ENTRY_B", "target": "BB_COMMON_EXIT", "type": "FALLTHROUGH"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()

        self.assertIn(fsm.initial_state, ["BB_ENTRY_A", "BB_ENTRY_B"])
        self.assertEqual(fsm.terminal_states, ["BB_COMMON_EXIT"])


class TestComplexSwitchJumpTables(unittest.TestCase):
    """Stress tests on complex, large-scale, and pathological switch dispatchers."""

    def test_dense_switch_128_cases(self) -> None:
        """Dispatcher branching to 128 distinct case blocks via INDIRECT_SWITCH."""
        n_cases = 128
        nodes = [{"id": "BB_DISPATCHER", "address": "0x401000", "is_entry": True, "node_type": "DECISION"}]
        edges = []

        for c in range(n_cases):
            cid = f"BB_CASE_{c}"
            caddr = hex(0x402000 + c * 0x10)
            nodes.append({"id": cid, "address": caddr, "node_type": "NORMAL"})
            edges.append({
                "source": "BB_DISPATCHER",
                "target": cid,
                "type": CFGEdgeType.INDIRECT_SWITCH.value,
                "metadata": {"case_val": c},
            })

        # Add single common exit
        nodes.append({"id": "BB_EXIT", "address": "0x405000", "is_exit": True, "node_type": "EXIT"})
        for c in range(n_cases):
            edges.append({
                "source": f"BB_CASE_{c}",
                "target": "BB_EXIT",
                "type": CFGEdgeType.FALLTHROUGH.value,
            })

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        self.assertEqual(len(cfg.nodes), 1 + n_cases + 1)
        self.assertEqual(len(cfg.edges), 2 * n_cases)

        # FSM checks
        fsm = cfg.to_fsm()
        self.assertEqual(fsm.initial_state, "BB_DISPATCHER")
        self.assertEqual(fsm.terminal_states, ["BB_EXIT"])
        self.assertEqual(len(fsm.transitions), 2 * n_cases)

        # Verify switch predicates are synthesized as CASE_<val>
        switch_transitions = [t for t in fsm.transitions if t["source"] == "BB_DISPATCHER"]
        self.assertEqual(len(switch_transitions), n_cases)
        for c, t in enumerate(switch_transitions):
            self.assertEqual(t["predicate"], f"CASE_{c}")

        # Algorithmic pattern detector identifies DISPATCH_SELECTOR
        patterns = cfg.detect_patterns()
        archetypes = [p["archetype"] for p in patterns]
        self.assertIn("DISPATCH_SELECTOR", archetypes)

    def test_sparse_switch_extreme_values(self) -> None:
        """Switch table with extreme case values (negative, huge 64-bit int, non-numeric)."""
        extreme_cases = [-1, 0, 1, 999999, 0x7FFFFFFFFFFFFFFF, "FALLBACK_DEFAULT"]
        nodes = [{"id": "BB_DISP", "address": "0x401000", "is_entry": True}]
        edges = []

        for idx, val in enumerate(extreme_cases):
            cid = f"BB_CASE_{idx}"
            nodes.append({"id": cid, "address": hex(0x402000 + idx * 0x10)})
            edges.append({
                "source": "BB_DISP",
                "target": cid,
                "type": CFGEdgeType.INDIRECT_SWITCH.value,
                "metadata": {"case_val": val},
            })

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.transitions), len(extreme_cases))
        predicates = [t["predicate"] for t in fsm.transitions]
        self.assertIn("CASE_-1", predicates)
        self.assertIn("CASE_9223372036854775807", predicates)
        self.assertIn("CASE_FALLBACK_DEFAULT", predicates)

    def test_nested_multi_stage_switches(self) -> None:
        """Two cascaded switch dispatchers where case 0 invokes a secondary switch table."""
        nodes = [
            {"id": "BB_SW1", "address": "0x401000", "is_entry": True},
            {"id": "BB_SW2", "address": "0x401050"},
            {"id": "BB_SW1_CASE1", "address": "0x401080"},
            {"id": "BB_SW2_CASE0", "address": "0x401090"},
            {"id": "BB_SW2_CASE1", "address": "0x4010A0"},
            {"id": "BB_EXIT", "address": "0x4010F0", "is_exit": True},
        ]
        edges = [
            {"source": "BB_SW1", "target": "BB_SW2", "type": "INDIRECT_SWITCH", "metadata": {"case_val": 0}},
            {"source": "BB_SW1", "target": "BB_SW1_CASE1", "type": "INDIRECT_SWITCH", "metadata": {"case_val": 1}},
            {"source": "BB_SW2", "target": "BB_SW2_CASE0", "type": "INDIRECT_SWITCH", "metadata": {"case_val": "SUB_A"}},
            {"source": "BB_SW2", "target": "BB_SW2_CASE1", "type": "INDIRECT_SWITCH", "metadata": {"case_val": "SUB_B"}},
            {"source": "BB_SW1_CASE1", "target": "BB_EXIT", "type": "FALLTHROUGH"},
            {"source": "BB_SW2_CASE0", "target": "BB_EXIT", "type": "FALLTHROUGH"},
            {"source": "BB_SW2_CASE1", "target": "BB_EXIT", "type": "FALLTHROUGH"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 6)
        self.assertEqual(fsm.initial_state, "BB_SW1")
        self.assertEqual(fsm.terminal_states, ["BB_EXIT"])

        patterns = cfg.detect_patterns()
        self.assertTrue(any(p["archetype"] == "DISPATCH_SELECTOR" for p in patterns))

    def test_duffs_device_interleaved_switch_loop(self) -> None:
        """Duff's device pattern where switch cases jump directly into a loop body."""
        nodes = [
            {"id": "BB_DISPATCH", "address": "0x401000", "is_entry": True},
            {"id": "BB_LOOP_HEAD", "address": "0x401010", "is_loop_head": True},
            {"id": "BB_CASE_1", "address": "0x401020"},
            {"id": "BB_CASE_2", "address": "0x401030"},
            {"id": "BB_LOOP_LATCH", "address": "0x401040"},
            {"id": "BB_EXIT", "address": "0x401050", "is_exit": True},
        ]
        edges = [
            {"source": "BB_DISPATCH", "target": "BB_LOOP_HEAD", "type": "INDIRECT_SWITCH", "metadata": {"case_val": 0}},
            {"source": "BB_DISPATCH", "target": "BB_CASE_2", "type": "INDIRECT_SWITCH", "metadata": {"case_val": 1}},
            {"source": "BB_LOOP_HEAD", "target": "BB_CASE_1", "type": "FALLTHROUGH"},
            {"source": "BB_CASE_1", "target": "BB_CASE_2", "type": "FALLTHROUGH"},
            {"source": "BB_CASE_2", "target": "BB_LOOP_LATCH", "type": "FALLTHROUGH"},
            {"source": "BB_LOOP_LATCH", "target": "BB_LOOP_HEAD", "type": "CONDITIONAL_TAKEN"},
            {"source": "BB_LOOP_LATCH", "target": "BB_EXIT", "type": "CONDITIONAL_NOT_TAKEN"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 6)
        self.assertEqual(fsm.initial_state, "BB_DISPATCH")
        self.assertEqual(fsm.terminal_states, ["BB_EXIT"])

        detector = AlgorithmicPatternDetector()
        loop_nodes = detector._find_natural_loop_nodes(cfg, "BB_LOOP_HEAD")
        self.assertIn("BB_LOOP_HEAD", loop_nodes)
        self.assertIn("BB_LOOP_LATCH", loop_nodes)


class TestEmptyMalformedAndBoundaryFlowDicts(unittest.TestCase):
    """Stress tests on empty, malformed, non-numeric, and boundary flow inputs."""

    def test_completely_empty_flow_dict(self) -> None:
        """Ingesting an empty dict {}."""
        cfg = ControlFlowGraph.from_rvs_flow({})
        self.assertEqual(len(cfg.nodes), 0)
        self.assertEqual(len(cfg.edges), 0)
        metrics = cfg.calculate_metrics()
        self.assertEqual(metrics["total_nodes"], 0)
        self.assertEqual(metrics["total_edges"], 0)
        self.assertEqual(metrics["cyclomatic_complexity"], 0)
        self.assertEqual(metrics["loop_count"], 0)

        fsm = cfg.to_fsm()
        self.assertEqual(fsm.states, [])
        self.assertEqual(fsm.initial_state, "S0")
        self.assertEqual(fsm.terminal_states, [])
        self.assertEqual(fsm.transitions, [])
        self.assertEqual(fsm.outputs, {})

        patterns = cfg.detect_patterns()
        self.assertEqual(patterns, [])

        json_cfg = json.dumps(cfg.to_dict())
        json_fsm = json.dumps(fsm.to_dict())
        self.assertIn('"nodes": []', json_cfg)
        self.assertIn('"states": []', json_fsm)

    def test_flow_dict_empty_blocks_list(self) -> None:
        """Ingesting flow dict with 'blocks': []."""
        cfg = ControlFlowGraph.from_rvs_flow({"function": "sym.empty", "blocks": []})
        self.assertEqual(len(cfg.nodes), 0)
        self.assertEqual(len(cfg.edges), 0)

    def test_flow_dict_empty_block_objects(self) -> None:
        """Ingesting flow with blocks that are empty dicts [{}, {}]."""
        raw_flow = {
            "blocks": [
                {},
                {"size": 10},
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 2)
        node0 = cfg.nodes[0]
        self.assertIn("id", node0)
        self.assertIn("address", node0)
        self.assertTrue(node0["is_entry"])

        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 2)
        self.assertIn(node0["id"], fsm.states)

    def test_flow_dict_none_values_and_missing_keys(self) -> None:
        """Blocks with None scalar values (addr, jump, fail, size) and omitted instructions."""
        raw_flow = {
            "blocks": [
                {
                    "addr": None,
                    "addr_hex": None,
                    "jump": None,
                    "fail": None,
                    "size": None,
                    "instructions": [],
                }
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 1)
        self.assertEqual(len(cfg.edges), 0)
        self.assertEqual(cfg.nodes[0]["instruction_count"], 0)

    def test_flow_dict_non_numeric_and_symbolic_addresses(self) -> None:
        """Addresses represented as symbolic names or non-hex strings."""
        raw_flow = {
            "blocks": [
                {
                    "addr": "label_entry",
                    "addr_hex": "label_entry",
                    "jump": "label_target",
                    "instructions": [{"asm": "jmp label_target"}],
                },
                {
                    "addr": "label_target",
                    "addr_hex": "label_target",
                    "jump": None,
                    "instructions": [{"asm": "ret"}],
                },
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 2)
        self.assertEqual(len(cfg.edges), 1)
        self.assertEqual(cfg.edges[0]["source"], "BB_label_entry")
        self.assertEqual(cfg.edges[0]["target"], "BB_label_target")

        fsm = cfg.to_fsm()
        self.assertEqual(fsm.initial_state, "BB_label_entry")
        self.assertEqual(fsm.terminal_states, ["BB_label_target"])

    def test_flow_dict_negative_and_64bit_max_addresses(self) -> None:
        """Addresses at 64-bit boundaries and negative integers."""
        raw_flow = {
            "blocks": [
                {
                    "addr": -4096,
                    "jump": 0xFFFFFFFFFFFFFF00,
                    "instructions": [{"asm": "jmp 0xfffffffffffffff00"}],
                },
                {
                    "addr": 0xFFFFFFFFFFFFFF00,
                    "jump": None,
                    "instructions": [{"asm": "ret"}],
                },
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 2)
        self.assertEqual(len(cfg.edges), 1)

        fsm = cfg.to_fsm()
        self.assertEqual(len(fsm.states), 2)

    def test_flow_dict_duplicate_block_addresses(self) -> None:
        """Raw flow containing two blocks with identical addresses."""
        raw_flow = {
            "blocks": [
                {"addr": 0x401000, "instructions": [{"asm": "nop"}]},
                {"addr": 0x401000, "instructions": [{"asm": "ret"}]},
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertEqual(len(cfg.nodes), 2)
        fsm = cfg.to_fsm()
        self.assertIsInstance(fsm, FiniteStateMachine)

    def test_decision_nodes_empty_and_malformed(self) -> None:
        """Ingestion via decision_nodes payload with empty/malformed values."""
        raw_decision_empty = {"decision_nodes": []}
        cfg1 = ControlFlowGraph.from_rvs_flow(raw_decision_empty)
        self.assertEqual(len(cfg1.nodes), 1)
        self.assertEqual(len(cfg1.edges), 0)

        raw_decision_none = {
            "decision_nodes": [
                {"addr": "0x401000", "jump": None, "fail": None, "condition": None}
            ]
        }
        cfg2 = ControlFlowGraph.from_rvs_flow(raw_decision_none)
        self.assertEqual(len(cfg2.edges), 0)


class TestStateMachineReachabilityAndConsistency(unittest.TestCase):
    """Stress tests verifying FSM state reachability, Moore outputs, and invariants."""

    def test_fsm_bfs_reachability_oracle(self) -> None:
        """Oracle testing reachability of all declared states from initial_state."""
        nodes = [
            {"id": "S_ENTRY", "address": "0x401000", "is_entry": True},
            {"id": "S_1", "address": "0x401010"},
            {"id": "S_2", "address": "0x401020"},
            {"id": "S_EXIT", "address": "0x401030", "is_exit": True},
            {"id": "S_DEAD1", "address": "0x409000"},
            {"id": "S_DEAD2", "address": "0x409010"},
        ]
        edges = [
            {"source": "S_ENTRY", "target": "S_1", "type": "FALLTHROUGH"},
            {"source": "S_1", "target": "S_2", "type": "CONDITIONAL_TAKEN", "condition": "eax == 0"},
            {"source": "S_2", "target": "S_EXIT", "type": "FALLTHROUGH"},
            {"source": "S_DEAD1", "target": "S_DEAD2", "type": "FALLTHROUGH"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()

        adj: Dict[str, Set[str]] = collections.defaultdict(set)
        for t in fsm.transitions:
            adj[t["source"]].add(t["target"])

        reachable: Set[str] = set()
        queue = collections.deque([fsm.initial_state])
        while queue:
            curr = queue.popleft()
            if curr not in reachable:
                reachable.add(curr)
                queue.extend(adj[curr] - reachable)

        expected_reachable = {"S_ENTRY", "S_1", "S_2", "S_EXIT"}
        self.assertEqual(reachable, expected_reachable)
        self.assertNotIn("S_DEAD1", reachable)
        self.assertNotIn("S_DEAD2", reachable)

    def test_fsm_moore_outputs_complete_mapping(self) -> None:
        """Verify Moore outputs map 100% of declared states with exact instruction counts."""
        nodes = [
            {"id": f"BB_{i}", "address": hex(0x401000 + i * 0x10), "instruction_count": (i + 1) * 3}
            for i in range(10)
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=[])
        fsm = cfg.to_fsm()

        self.assertIsNotNone(fsm.outputs)
        for i in range(10):
            nid = f"BB_{i}"
            self.assertIn(nid, fsm.outputs)
            self.assertEqual(fsm.outputs[nid]["instruction_count"], (i + 1) * 3)

    def test_fsm_serialization_roundtrip(self) -> None:
        """Verify FSM and CFG serialize losslessly to JSON without circular reference errors."""
        nodes = [
            {"id": "BB_0", "address": "0x401000", "is_entry": True},
            {"id": "BB_1", "address": "0x401010", "is_exit": True},
        ]
        edges = [
            {"source": "BB_0", "target": "BB_1", "type": "FALLTHROUGH"},
            {"source": "BB_1", "target": "BB_0", "type": "UNCONDITIONAL"},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()

        cfg_dict = cfg.to_dict()
        fsm_dict = fsm.to_dict()

        cfg_json = json.dumps(cfg_dict)
        fsm_json = json.dumps(fsm_dict)

        loaded_cfg = json.loads(cfg_json)
        loaded_fsm = json.loads(fsm_json)

        self.assertEqual(len(loaded_cfg["nodes"]), 2)
        self.assertEqual(len(loaded_fsm["transitions"]), 2)


class TestAlgorithmicPatternDetectorPerformance(unittest.TestCase):
    """Stress tests on pattern detector scaling across exponential DAGs and large graphs."""

    def test_diamond_dag_exponential_paths(self) -> None:
        """Diamond lattice DAG with 20 stages (2^20 = 1,048,576 execution paths)."""
        stages = 20
        nodes = [{"id": "D_ENTRY", "address": "0x400000", "node_type": "ENTRY"}]
        edges = []

        prev_left = "D_ENTRY"
        prev_right = "D_ENTRY"

        for s in range(stages):
            l_id = f"D_{s}_L"
            r_id = f"D_{s}_R"
            l_addr = hex(0x401000 + s * 0x100)
            r_addr = hex(0x401000 + s * 0x100 + 0x50)

            nodes.append({"id": l_id, "address": l_addr, "node_type": "DECISION"})
            nodes.append({"id": r_id, "address": r_addr, "node_type": "DECISION"})

            edges.append({"source": prev_left, "target": l_id, "type": "CONDITIONAL_TAKEN"})
            edges.append({"source": prev_left, "target": r_id, "type": "CONDITIONAL_NOT_TAKEN"})
            if prev_right != prev_left:
                edges.append({"source": prev_right, "target": l_id, "type": "CONDITIONAL_TAKEN"})
                edges.append({"source": prev_right, "target": r_id, "type": "CONDITIONAL_NOT_TAKEN"})

            prev_left = l_id
            prev_right = r_id

        nodes.append({"id": "D_EXIT", "address": "0x409000", "node_type": "EXIT"})
        edges.append({"source": prev_left, "target": "D_EXIT", "type": "FALLTHROUGH"})
        edges.append({"source": prev_right, "target": "D_EXIT", "type": "FALLTHROUGH"})

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        self.assertEqual(len(cfg.nodes), 42)

        t0 = time.perf_counter()
        patterns = cfg.detect_patterns()
        elapsed = time.perf_counter() - t0

        self.assertLess(elapsed, 0.2, f"Pattern detection on diamond DAG took {elapsed:.3f}s (exponential blowup)")
        self.assertIsInstance(patterns, list)

    def test_deep_linear_chain_1000_nodes(self) -> None:
        """Ultra-deep linear sequence of 1,000 basic blocks."""
        n_nodes = 1000
        nodes = []
        edges = []

        for i in range(n_nodes):
            nid = f"CHAIN_{i}"
            nodes.append({
                "id": nid,
                "address": hex(0x400000 + i * 4),
                "is_entry": (i == 0),
                "is_exit": (i == n_nodes - 1),
                "instructions": [{"asm": "nop", "opcode": "nop"}],
            })
            if i > 0:
                edges.append({"source": f"CHAIN_{i-1}", "target": nid, "type": "FALLTHROUGH"})

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        self.assertEqual(len(cfg.nodes), 1000)
        self.assertEqual(len(cfg.edges), 999)

        t0 = time.perf_counter()
        fsm = cfg.to_fsm()
        fsm_time = time.perf_counter() - t0
        self.assertLess(fsm_time, 0.5, f"FSM synthesis on 1000-node chain took {fsm_time:.3f}s")

        t0 = time.perf_counter()
        patterns = cfg.detect_patterns()
        pattern_time = time.perf_counter() - t0
        self.assertLess(pattern_time, 0.5, f"Pattern detection on 1000-node chain took {pattern_time:.3f}s")

    def test_dense_multigraph_500_nodes(self) -> None:
        """Dense mesh multigraph with 500 nodes and 1,500 edges."""
        n_nodes = 500
        nodes = [{"id": f"MESH_{i}", "address": hex(0x400000 + i * 8)} for i in range(n_nodes)]
        edges = []

        for i in range(n_nodes):
            for step in (1, 2, 3):
                target = (i + step) % n_nodes
                edges.append({
                    "source": f"MESH_{i}",
                    "target": f"MESH_{target}",
                    "type": "FALLTHROUGH",
                })

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        self.assertEqual(len(cfg.nodes), 500)
        self.assertEqual(len(cfg.edges), 1500)

        t0 = time.perf_counter()
        metrics = cfg.calculate_metrics()
        self.assertGreater(metrics["cyclomatic_complexity"], 1000)

        patterns = cfg.detect_patterns()
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 1.0, f"Dense mesh processing took {elapsed:.3f}s")


class TestAlgorithmicPatternArchetypeRobustness(unittest.TestCase):
    """Stress tests on detection accuracy and resilience for all 6 algorithmic archetypes."""

    def test_crypto_xor_loop_instruction_permutations(self) -> None:
        """XOR loop pattern detection across differing byte registers and memory syntaxes."""
        raw_flow = {
            "blocks": [
                {"addr": 0x401000, "jump": 0x401010, "instructions": [{"asm": "push rbp"}]},
                {
                    "addr": 0x401010,
                    "jump": 0x401010,
                    "fail": 0x401030,
                    "instructions": [
                        {"asm": "xor byte [rdi + rax], 0x5a", "opcode": "xor"},
                        {"asm": "inc rax", "opcode": "inc"},
                        {"asm": "jnz 0x401010", "opcode": "jnz"},
                    ],
                },
                {"addr": 0x401030, "jump": None, "instructions": [{"asm": "ret", "opcode": "ret"}]},
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        patterns = cfg.detect_patterns()
        p_ids = [p["pattern_id"] for p in patterns]
        self.assertIn("ALG_BYTE_TRANS", p_ids)

    def test_aggregation_loop_multiplication_and_addition(self) -> None:
        """Accumulator loop with imul and add instructions."""
        raw_flow = {
            "blocks": [
                {"addr": 0x401000, "jump": 0x401010, "instructions": [{"asm": "mov eax, 1"}]},
                {
                    "addr": 0x401010,
                    "jump": 0x401010,
                    "fail": 0x401020,
                    "instructions": [
                        {"asm": "imul eax, ecx", "opcode": "imul"},
                        {"asm": "loop 0x401010", "opcode": "loop"},
                    ],
                },
                {"addr": 0x401020, "jump": None, "instructions": [{"asm": "ret"}]},
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        patterns = cfg.detect_patterns()
        self.assertTrue(any(p["pattern_id"] == "ALG_ACC_LOOP" for p in patterns))

    def test_collatz_parity_loop_arm_syntax(self) -> None:
        """Collatz loop with ARM bitwise and shift instructions."""
        raw_flow = {
            "blocks": [
                {"addr": 0x401000, "jump": 0x401010, "instructions": [{"asm": "mov w0, 27"}]},
                {
                    "addr": 0x401010,
                    "jump": 0x401020,
                    "fail": 0x401030,
                    "instructions": [
                        {"asm": "and w1, w0, 1", "opcode": "and"},
                        {"asm": "cbnz w1, 0x401020", "opcode": "cbnz"},
                    ],
                },
                {
                    "addr": 0x401020,
                    "jump": 0x401010,
                    "instructions": [
                        {"asm": "lea w0, [w0 + w0*2 + 1]", "opcode": "lea"},
                        {"asm": "b 0x401010", "opcode": "b"},
                    ],
                },
                {
                    "addr": 0x401030,
                    "jump": 0x401010,
                    "instructions": [
                        {"asm": "shr w0, 1", "opcode": "shr"},
                        {"asm": "b 0x401010", "opcode": "b"},
                    ],
                },
                {"addr": 0x401050, "jump": None, "instructions": [{"asm": "ret"}]},
            ]
        }
        cfg = ControlFlowGraph.from_rvs_flow(raw_flow)
        patterns = cfg.detect_patterns()
        self.assertTrue(any(p["pattern_id"] == "ALG_COLLATZ" for p in patterns))

    def test_recurrence_tree_fibonacci_stress(self) -> None:
        """Recurrence tree pattern detection with multiple recursive branch calls."""
        nodes = [
            {
                "id": "BB_0",
                "address": "0x401000",
                "instructions": [
                    {"asm": "call sym.fibonacci", "opcode": "call"},
                    {"asm": "call sym.fibonacci", "opcode": "call"},
                    {"asm": "call sym.fibonacci", "opcode": "call"},
                ],
            }
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=[], metadata={"function_name": "fibonacci"})
        patterns = cfg.detect_patterns()
        self.assertTrue(any(p["pattern_id"] == "ALG_REC_BRANCH" for p in patterns))

    def test_predicate_chain_20_sequential_gates(self) -> None:
        """20-gate sequential predicate verification chain."""
        n_gates = 20
        nodes = [{"id": "P_ENTRY", "address": "0x401000", "is_entry": True, "node_type": "ENTRY"}]
        edges = []

        prev = "P_ENTRY"
        for g in range(n_gates):
            gid = f"P_GATE_{g}"
            nodes.append({
                "id": gid,
                "address": hex(0x401010 + g * 0x10),
                "node_type": "DECISION",
            })
            edges.append({"source": prev, "target": gid, "type": "FALLTHROUGH"})
            prev = gid

        nodes.append({"id": "P_EXIT", "address": "0x402000", "is_exit": True, "node_type": "EXIT"})
        edges.append({"source": prev, "target": "P_EXIT", "type": "FALLTHROUGH"})

        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        patterns = cfg.detect_patterns()
        self.assertTrue(any(p["pattern_id"] == "ALG_PRED_CHAIN" for p in patterns))


class TestAdversarialFailureModesAndExceptions(unittest.TestCase):
    """
    Adversarial challenge tests verifying and documenting empirical crash failure modes
    under pathological inputs where fields contain None or invalid types.
    """

    def test_vulnerability_none_instructions_in_raw_flow_crashes(self) -> None:
        """
        Empirically verifies that raw_blocks containing instructions: None (JSON null)
        crashes from_raw_flow at line 1089 with TypeError: object of type 'NoneType' has no len().
        """
        raw_flow = {
            "blocks": [
                {
                    "addr": 0x401000,
                    "instructions": None,
                }
            ]
        }
        with self.assertRaises(TypeError) as ctx:
            ControlFlowGraph.from_rvs_flow(raw_flow)
        self.assertIn("NoneType", str(ctx.exception))

    def test_vulnerability_none_instructions_in_cfg_init_crashes(self) -> None:
        """
        Empirically verifies that direct ControlFlowGraph instantiation with a node
        having instructions: None crashes at line 999 with TypeError.
        """
        nodes = [{"id": "BB_0", "instructions": None}]
        with self.assertRaises(TypeError) as ctx:
            ControlFlowGraph(nodes=nodes)
        self.assertIn("NoneType", str(ctx.exception))

    def test_vulnerability_none_opcode_asm_in_from_raw_flow_crashes(self) -> None:
        """
        Empirically verifies that instructions with opcode: None and asm: None
        crashes from_raw_flow at line 1078 with TypeError when evaluating 'ret' in last_op.
        """
        raw_flow = {
            "blocks": [
                {
                    "addr": 0x401000,
                    "instructions": [{"opcode": None, "asm": None}],
                }
            ]
        }
        with self.assertRaises(TypeError) as ctx:
            ControlFlowGraph.from_raw_flow(raw_flow)
        self.assertIn("iterable", str(ctx.exception))

    def test_vulnerability_none_opcode_in_algorithmic_detectors_crashes(self) -> None:
        """
        Empirically verifies that instructions with opcode: None crash AlgorithmicPatternDetector
        methods with AttributeError (None.startswith).
        """
        cfg = ControlFlowGraph(
            nodes=[{
                "id": "BB_0",
                "address": "0x1000",
                "instructions": [{"opcode": None}],
            }],
            edges=[],
        )
        detector = AlgorithmicPatternDetector()
        with self.assertRaises(AttributeError) as ctx:
            detector.detect_switch_tables(cfg)
        self.assertIn("startswith", str(ctx.exception))

    def test_vulnerability_none_metadata_in_fsm_switch_edge_crashes(self) -> None:
        """
        Empirically verifies that CFG edge with type INDIRECT_SWITCH and metadata: None
        crashes to_fsm() at line 1297 with AttributeError (None.get).
        """
        cfg = ControlFlowGraph(
            nodes=[{"id": "A"}, {"id": "B"}],
            edges=[{
                "source": "A",
                "target": "B",
                "type": CFGEdgeType.INDIRECT_SWITCH.value,
                "metadata": None,
            }],
        )
        with self.assertRaises(AttributeError) as ctx:
            cfg.to_fsm()
        self.assertIn("'NoneType' object has no attribute 'get'", str(ctx.exception))

    def test_vulnerability_predicate_counter_order_desync(self) -> None:
        """
        Empirically verifies that listing CONDITIONAL_NOT_TAKEN edge before
        CONDITIONAL_TAKEN causes predicate gate counter desynchronization
        (!PREDICATE_GATE_0000 vs PREDICATE_GATE_0001).
        """
        nodes = [
            {"id": "BB_COND", "address": "0x401000", "node_type": "DECISION"},
            {"id": "BB_TAKEN", "address": "0x401010"},
            {"id": "BB_NOT_TAKEN", "address": "0x401020"},
        ]
        # Inverted edge order: NOT_TAKEN listed before TAKEN
        edges = [
            {"source": "BB_COND", "target": "BB_NOT_TAKEN", "type": CFGEdgeType.CONDITIONAL_NOT_TAKEN.value},
            {"source": "BB_COND", "target": "BB_TAKEN", "type": CFGEdgeType.CONDITIONAL_TAKEN.value},
        ]
        cfg = ControlFlowGraph(nodes=nodes, edges=edges)
        fsm = cfg.to_fsm()

        not_taken_t = next(t for t in fsm.transitions if t["edge_type"] == CFGEdgeType.CONDITIONAL_NOT_TAKEN.value)
        taken_t = next(t for t in fsm.transitions if t["edge_type"] == CFGEdgeType.CONDITIONAL_TAKEN.value)

        # Because NOT_TAKEN appeared first before counter incremented, it received 0000
        self.assertEqual(not_taken_t["predicate"], "!PREDICATE_GATE_0000")
        # Taken received 0001
        self.assertEqual(taken_t["predicate"], "PREDICATE_GATE_0001")


if __name__ == "__main__":
    unittest.main()
