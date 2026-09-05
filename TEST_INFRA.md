# E2E Test Infra: RVS Engine & MCP Harness

## Test Philosophy
- **Opaque-Box & Requirement-Driven**: Tests are derived strictly from `ORIGINAL_REQUEST.md` specifications, exercising the CLI binaries and Python harness as external users. No coupling to internal private functions.
- **Methodology**: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Combinatorial Testing + Real-World Workload Scenarios.
- **Progressive Testability**: Verification checks use standard JSON envelopes and exit codes (1 to 6) without requiring advanced internal states.

## Feature Inventory
| # | Feature | Source (Requirement) | Tier 1 (Coverage) | Tier 2 (BVA) | Tier 3 (Pairwise) |
|---|---------|----------------------|:-----------------:|:------------:|:-----------------:|
| 1 | Panic-Free Resilience | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 2 | Standardized Exit Codes | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 3 | Token Compaction (>= 60%) | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 4 | Register Diff & Emulation | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ |
| 5 | Python Harness & MCP Loop | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |
| 6 | Tool Schema Export (16 tools)| ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ |
| 7 | Subprocess & Timeout Safety | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ |
| 8 | Adversarial Input Handling | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ |

## Test Architecture
- **Test Runner**: Python-based test runner or cargo test suite invoking CLI binary (`target/debug/rvs`) and Python harness (`rvs_agent_harness.py`).
- **Pass/Fail Semantics**: All tests must exit with expected exit code (0 for success, 1..6 for specific errors) and emit valid JSON matching the standardized envelope.
- **Location**: `tests/e2e_requirements_test.py` or `tests/e2e_opaque_box.rs`.
- **Publication**: Publishes `TEST_READY.md` once test suite design is verified.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Crackme Analysis & Patching Workflow | F1, F2, F3, F4 | High |
| 2 | Agent Automated Triage & Flow Analysis | F1, F3, F5, F6 | Medium |
| 3 | MCP Interactive Server Session | F5, F6, F7 | High |
| 4 | Corrupted / Malformed Binary Defense | F1, F2, F7, F8 | Medium |
| 5 | Dynamic Emulation Register Diff Audit | F3, F4, F8 | High |

## Coverage Thresholds
- Tier 1: ≥ 5 test cases per feature (40 tests minimum)
- Tier 2: ≥ 5 boundary/corner test cases per feature (40 tests minimum)
- Tier 3: ≥ 8 pairwise cross-feature interaction test cases
- Tier 4: ≥ 5 realistic end-to-end application scenarios
- **Total Minimum Target**: ≥ 93 test cases
