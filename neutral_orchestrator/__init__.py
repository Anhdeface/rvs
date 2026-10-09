"""
neutral_orchestrator - Neutral Technical Binary Orchestration Layer.

Combines multi-format target ingestion (M1), neutral technical representation (M2),
and harness orchestration routing with JSON telemetry (M3).
"""

from neutral_orchestrator.target_ingestion import (
    TargetComponent,
    TargetType,
    UnifiedTarget,
    ingest_target,
)
from neutral_orchestrator.neutral_representation import (
    BijectiveCodebook,
    ControlFlowGraph,
    FiniteStateMachine,
    NeutralTokenMapper,
    TokenCategory,
    classify_token,
    deneutralize_data,
    diagnose_invariants,
    verify_invariants,
)
from neutral_orchestrator.orchestrator import (
    NeutralBinaryOrchestrator,
    NeutralResponseEnvelope,
)

__all__ = [
    # M3 Orchestrator & Envelopes
    "NeutralBinaryOrchestrator",
    "NeutralResponseEnvelope",
    # M1 Target Ingestion
    "UnifiedTarget",
    "ingest_target",
    "TargetType",
    "TargetComponent",
    # M2 Neutral Representation
    "NeutralTokenMapper",
    "ControlFlowGraph",
    "FiniteStateMachine",
    "TokenCategory",
    "BijectiveCodebook",
    "classify_token",
    "verify_invariants",
    "diagnose_invariants",
    "deneutralize_data",
]
