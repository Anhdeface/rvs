# Project: RVS Engine & MCP Harness Hardening

## Architecture
RVS is a high-performance binary analysis engine written in Rust backed by radare2, coupled with a Python-based agent harness and stdio MCP (Model Context Protocol) server.
- **Rust Engine Core (`src/`)**: CLI entry point (`cli.rs`, `main.rs`), radare2 driver interface (`r2/driver.rs`), error taxonomy (`error.rs`), response serialization envelopes (`response.rs`), analysis engines (`analysis/`), agent-assisted reverse engineering commands (`agent/`), binary patching engines (`patch/`), and token compaction data structures (`compact.rs`).
- **Python Agent Harness (`rvs_agent_harness.py`)**: Subprocess execution bridge, 16 canonical reverse engineering tools catalog, schema exports for MCP / OpenAI / Anthropic / Gemini, response transform/pruning engine, and JSON-RPC 2.0 stdio MCP server.
- **Test Infrastructure (`tests/`)**: Rust integration test suites (146 existing tests), Python unit & adversarial test suites (`test_agent_harness.py`, `test_challenger_mcp_schemas.py`), and test binary fixtures (`tests/fixtures/`).

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Rust Core Panic Elimination | Eliminate all 8 production `unwrap()`, 2 `unreachable!()`, and raw indexing in `src/agent/patch_plan.rs` and `src/analysis/frame.rs` | M1 | Survey (Explorer 1) |
| F2 | Defensive Error Handling & Exit Codes | Standardize exit codes (1=InvalidArgument, 2=FileError, 3=AnalysisError, 4=PatchError, 5=Timeout, 6=InternalError). Fix timeout mapping, 0-byte file mapping, IoError kind mapping, UTF-8 char boundary slice in `driver.rs:247`, command injection sanitization in `resolve_address`, and add `--timeout` CLI flag. | M1 | Survey (Explorer 1) |
| F3 | Token Compaction Data Structures | Implement/harden compact representations across analysis commands (`functions`, `strings`, `symbols`, `graph`, `prologue-epilogue`, `info`, `agent triage/flow/xrefs`) to consistently achieve >= 60% payload size reduction while preserving 100% of essential decision signals. Optimize hot path allocations in symbols and xrefs. | M2 | Survey (Explorer 2) |
| F4 | Emulation Register Diffs & Dynamic Compaction | Replace bloated 5-field `RegisterDiff` with compact delta `CompactRegisterDiff`. Suppress 25+ register full dumps on `dynamic step` and compact `dynamic emulate`. Suppress redundant `rip` diff in `dynamic trace`. Validate boundary conditions (`--steps 0`, `--count 0`). | M2 | Survey (Explorer 2, Explorer 3) |
| F5 | Python Agent Harness & MCP Protocol Hardening | Harden `rvs_agent_harness.py`: clean exit on `BrokenPipeError`, robust parameter coercion for string booleans, string integers, and string lists (`reg_set`), normalize session cache paths, and sanitize non-UTF8 binary bytes. | M3 | Survey (Explorer 3) |
| F6 | Python Test Suite Realignment | Update `tests/test_agent_harness.py` and `tests/test_challenger_mcp_schemas.py` from outdated 13-tool expectation to the full 16-tool catalog, resolving all 13 Python test failures. | M3 | Survey (Explorer 3) |
| F7 | Adversarial Edge-Case & Regression Test Suite | Unit tests for `src/analysis/dynamic.rs`, integration tests in `tests/adversarial_edge_cases.rs` for malformed/truncated JSON, negative/zero steps, u64::MAX address queries, and zero regressions across `cargo test`. | M4 | Survey (Explorer 1, 3) |
| F8 | Opaque-Box E2E Test Suite (Dual Track) | Comprehensive requirement-driven opaque-box test suite across Tiers 1-4 with test runner and publication of `TEST_READY.md`. | E2E-Track | Survey (Project Pattern) |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Rust Core Resilience & Defensive Error Taxonomy | F1, F2: Panic-free `src/`, exit codes 1..6 alignment, r2 driver error handling & timeout, CLI `--timeout` | none | PLANNED |
| M2 | Token Compaction & Dynamic Emulation Optimization | F3, F4: Compact data structures, >= 60% payload reduction across commands, compact register diffs, suppress full register dumps | M1 | PLANNED |
| M3 | Python Agent Harness & MCP Protocol Hardening | F5, F6: Broken pipe handling, parameter coercion, session cache path normalization, 16 tools realignment in Python tests | none | PLANNED |
| M4 | Final E2E Integration & Adversarial Verification | F7: Zero regressions (`cargo test` clean, zero clippy warnings), edge-case tests, Phase 1 (100% E2E test pass) + Phase 2 (Adversarial coverage hardening) | M1, M2, M3, E2E-Track | PLANNED |
| E2E | E2E Testing Track | F8: Independent requirement-driven opaque-box test suite (Tiers 1-4) published to `TEST_READY.md` | none | IN_PROGRESS |

## Interface Contracts

### Standardized Exit Code Taxonomy (Rust Core & Python Harness)
- `0`: Success
- `1`: Invalid Argument (`AppError::InvalidArgument`, `AppError::InvalidMode`, invalid CLI flags)
- `2`: File Error (`AppError::FileNotFound`, `AppError::ZeroByteFile`, `AppError::PermissionDenied`, `IoError` where kind is `NotFound` or `PermissionDenied`)
- `3`: Analysis Error (`AppError::FunctionNotFound`, `AppError::InvalidBinary`, `AppError::DecompilationFailed`, `AppError::DisassemblyFailed`, `AppError::InvalidAddress`, `AppError::EmulationFailed`)
- `4`: Patch Error (`AppError::PatchFailed`, `AppError::PatchPlanError`, `AppError::VerificationFailed`, `AppError::AssemblyFailed`)
- `5`: Timeout Error (`AppError::Timeout`)
- `6`: Internal Error (`AppError::R2ExecutionError`, `AppError::JsonError`, other unmapped `IoError`)

### Standardized Error Envelope (`ApiResponse`)
```json
{
  "success": false,
  "command": "<command_name>",
  "target": "<binary_path>",
  "timestamp": "<iso8601_timestamp>",
  "error": {
    "code": <integer_exit_code_1_to_6>,
    "type": "<SNAKE_CASE_ERROR_TYPE>",
    "message": "<human_readable_description>",
    "suggestion": "<actionable_remediation_guidance>"
  }
}
```

### Compact Response Envelopes & Data Models
- **Functions (`CompactFunction`)**: `{ "name": String, "addr": "0x...", "sz": u64, "cc": Option<u64>, "bb": Option<u64> }` (drops verbose C signatures unless `--detail` requested).
- **Strings (`CompactStringsResponse`)**: `{ "count": usize, "strings": BTreeMap<String, String> }` (maps `"0xaddr"` -> `"string"`).
- **Symbols (`CompactSymbolEntry`)**: `{ "name": String, "addr": "0x...", "t": String, "bind": Option<String> }` (omits LOCAL bind).
- **Register Diff (`CompactRegisterDiff`)**: `{ "reg": String, "from": "0x...", "to": "0x..." }` (omits redundant decimal values).
- **Dynamic Step (`CompactDynamicStepResponse`)**: `{ "curr": "0x...", "next": "0x...", "asm": String, "diff": Vec<CompactRegisterDiff> }` (omits full 25+ register dump).

### Python Harness MCP Schema Contract
- 16 canonical tools: `rvs_info`, `rvs_functions`, `rvs_disasm`, `rvs_decompile`, `rvs_flow`, `rvs_xrefs`, `rvs_strings`, `rvs_symbols`, `rvs_patch_instruction`, `rvs_patch_string`, `rvs_patch_bytes`, `rvs_agent_triage`, `rvs_agent_patch_plan`, `rvs_dynamic_emulate`, `rvs_dynamic_trace`, `rvs_dynamic_step`.
- Coercion contract: string booleans (`"true"`/`"false"`) -> `bool`; string integers (`"5"`) -> `int`; string `reg_set` (`"rax=1"`) -> `["rax=1"]`.
- MCP stdio contract: On `BrokenPipeError`, terminate cleanly with code 0/1 without printing unhandled tracebacks to stderr.

## Code Layout
- `src/main.rs`: CLI dispatch, envelope formatting, exit code handling.
- `src/cli.rs`: CLI argument parsing, flags (`--compact`, `--format`, `--timeout`).
- `src/error.rs`: `AppError` enum and standardized exit code mapping.
- `src/response.rs`: `ApiResponse` and `ApiError` serialization.
- `src/compact.rs`: Compact data models and response transformations.
- `src/r2/driver.rs`: Radare2 subprocess execution, timeout enforcement, JSON extraction.
- `src/analysis/`: Analysis submodules (`functions.rs`, `blocks.rs`, `dynamic.rs`, `symbols.rs`, `strings.rs`, `xrefs.rs`, `graph.rs`, `frame.rs`).
- `src/agent/`: Agent-oriented submodules (`triage.rs`, `patch_plan.rs`, `flow.rs`, `decompile.rs`).
- `src/patch/`: Binary patching submodules (`bytes.rs`, `instruction.rs`, `string.rs`, `verify.rs`).
- `rvs_agent_harness.py`: Python MCP server and CLI tool harness.
- `tests/`: Rust integration tests and Python test suites.
