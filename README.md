# `rvs` — Radare2 Binary Analysis, Dynamic RE & Patching Engine for AI Agents

[![Version](https://img.shields.io/badge/version-v0.2.0-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/protocol-MCP_Compliant-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)

**`rvs` (Reverse Visual Static/Dynamic Engine)** is a high-performance binary analysis, dynamic reverse engineering, and in-place patching toolkit built in Rust on top of `radare2`. Designed from the ground up for both **human security engineers** and **autonomous AI coding agents** (e.g. Claude, GPT-4o, Gemini, Cursor, Antigravity).

`rvs` solves the classic pain points of integrating binary analysis tools into LLM agent workflows: noisy terminal output, runaway context window exhaustion, non-deterministic error codes, command injection vulnerabilities, and brittle subprocess management.

---

## 🌟 What's New in v0.2.0

- **⚙️ Dynamic RE & ESIL Emulation Engine**:
  - Full ESIL emulation supporting function execution simulation (`dynamic emulate`), instruction trace with register deltas (`dynamic trace`), and step-by-step debugging (`dynamic step`).
  - Pre-execution register overrides (`--reg-set rax=0x1337`).
  - Automated return value extraction (`rax`/`eax`), memory snapshots before/after execution, and agent branch outcome analysis (`agent emulate`).
- **🛡️ Panic-Free Resilience & Defensive Hardening**:
  - 100% elimination of risky `unwrap()` and `expect()` calls across untrusted inputs, binary offsets, and JSON parsing paths.
  - Command Injection Prevention: Added strict character filtering (`FORBIDDEN_CHARS` in address resolution, `FORBIDDEN_ASM_CHARS` in assembly patching) to prevent shell redirection or arbitrary command injection into radare2.
  - Safe UTF-8 character boundary iteration protecting against multi-byte sequence truncation crashes.
  - Pre-flight validation rejecting empty files (`ZERO_BYTE_FILE`) and directory inputs before spawning subprocesses.
- **📉 Advanced Token Compaction (60%–99% Payload Reduction)**:
  - Redesigned compact data models across all endpoints (`CompactBinaryInfo`, `CompactFunctionsResponse`, `CompactStringsResponse`, `CompactSymbolsResponse`, `CompactBlocksResponse`, `CompactDynamicTraceResponse`, `CompactDynamicEmulateResponse`).
  - Functions: ~65.8% reduction; Disassembly/Blocks: 62%–96% reduction; Strings: 52%–95% reduction; Symbols: 57%–84% reduction; Xrefs: 76%–99% reduction.
- **🔌 16 Canonical Tools for AI Agents & MCP**:
  - Expanded tool catalog from 13 to **16 canonical tools** including 3 dynamic reverse-engineering tools (`rvs_dynamic_emulate`, `rvs_dynamic_trace`, `rvs_dynamic_step`).
  - Native schema exports for **OpenAI**, **Anthropic**, **Gemini**, and **MCP (Model Context Protocol)**.
  - Parameter coercion engine handling string booleans, integers, and register arrays seamlessly.
  - Graceful `BrokenPipeError` handling, session caching with normalized pathing, and non-UTF8 terminal scrubbing.
- **⏱️ Process Timeout Watchdog**:
  - Global `--timeout <SECS>` flag wired end-to-end to prevent runaway analysis or infinite emulation loops (standardized exit code 5).
- **🧪 400+ Automated Tests**:
  - Full suite passing with 0 warnings: 150+ Rust unit & integration tests, 93 Opaque-Box E2E tests, 177 Python unit/adversarial tests, and 155 system binary stress tests.

---

## 🏗️ Architecture Overview

```
                          ┌────────────────────────────────────────┐
                          │   LLM Agent / MCP Client / Engineer    │
                          └───────────────────┬────────────────────┘
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    │                                                   │
        [Python API / MCP Server]                             [Direct CLI Execution]
        `rvs_agent_harness.py`                                `rvs` binary
         ├── 16 Universal Tool Schemas                         ├── Static & Dynamic Engine
         ├── Compaction Engine (60-99% drop)                   ├── 7-Level Exit Taxonomy
         ├── BrokenPipe & Non-UTF8 Sanitizer                   ├── Zero-Panic Rust Core
         └── Session Cache & Coercion Engine                   └── Timeout Watchdog (`--timeout`)
                    │                                                   │
                    └─────────────────────────┬─────────────────────────┘
                                              │
                                  ┌───────────▼───────────┐
                                  │       rvs Core        │
                                  │ (Safe Rust Controller)│
                                  └───────────┬───────────┘
                                              │ Isolated Subprocess (Env Scrubbing, Delimiter Boundaries)
                                  ┌───────────▼───────────┐
                                  │       radare2         │
                                  │ (Static & ESIL Engine)│
                                  └───────────────────────┘
```

---

## 📦 Prerequisites & Installation

### 1. Requirements
- **Rust Toolchain**: `cargo` & `rustc` 1.75+ (2021 edition)
- **Radare2**: `radare2` 5.8+ (accessible in `PATH`)
- **Python**: Python 3.9+ (for the agent harness and MCP server)

### 2. Building from Source
```bash
# Clone the repository
git clone https://github.com/Anhdeface/rvs.git
cd rvs

# Build release binary (v0.2.0)
cargo build --release

# The compiled binary will be located at:
# ./target/release/rvs
```

Add `target/release` to your `PATH` or set `RVS_BIN`:
```bash
export PATH="$PWD/target/release:$PATH"
# or
export RVS_BIN="$PWD/target/release/rvs"
```

---

## 💻 CLI Usage

All commands require a target binary passed via `-f` / `--file`.

### 1. Static Binary Analysis & Inspection
```bash
# Inspect basic file headers, architecture, entry point, security flags
rvs -f /bin/ls info

# Extract printable strings (supports --min-len filter)
rvs -f /bin/ls strings --min-len 8

# List functions and symbols
rvs -f /bin/ls analyze functions
rvs -f /bin/ls symbols

# Disassemble a function
rvs -f /bin/ls analyze blocks main

# Call graph generation (formats: json, ascii, tree, dot, mermaid)
rvs -f /bin/ls analyze graph --format tree
```

### 2. Dynamic Reverse Engineering (New in v0.2.0)
```bash
# Emulate execution of a function (default 100 steps)
rvs -f ./crackme dynamic emulate main --steps 50

# Emulate with pre-set register state
rvs -f ./crackme dynamic emulate main --steps 50 --reg-set rdi=0x1337 --reg-set rsi=0x4000

# Instruction trace recording register deltas at each step
rvs -f ./crackme dynamic trace main --steps 15

# Single-step debugging inspection
rvs -f ./crackme dynamic step main --count 1

# Agent branch outcome evaluation (taken/not taken)
rvs -f ./crackme agent emulate main --steps 50
```

### 3. Binary Patching & Dry-Run Simulation
```bash
# Replace an instruction at an address with automatic backup
rvs -f ./target_bin patch instruction --addr 0x1149 --assembly "nop" --backup

# Patch NOP sequence by length
rvs -f ./target_bin patch instruction --addr 0x1149 --nop 4

# Patch string in-place with strict length validation
rvs -f ./target_bin patch string --addr 0x2000 --string "UNLOCKED"

# Overwrite raw hex bytes
rvs -f ./target_bin patch bytes --addr 0x1149 --hex "90909090"
```

### 4. Autonomous Agent Workflows
```bash
# Rapid binary triage (identifies security checks, auth gates, crypto strings)
rvs -f ./target_bin agent triage

# Decompile function to pseudo-C with string xref annotations
rvs -f ./target_bin agent decompile main

# Analyze control flow with conditional gate identification
rvs -f ./target_bin agent flow main

# Execute a declarative multi-step patch plan with dry-run support
rvs -f ./target_bin agent patch-plan --plan '{"target_file":"./target_bin","patches":[{"address":"0x1149","type":"instruction","value":"nop"}],"dry_run":true}'
```

### 5. Token Compaction & Output Formats
Add `-c` / `--compact` to any command for optimized agent payloads:
```bash
# Standard functions output (~4.9 KB) vs Compact functions (~1.3 KB -> 72% reduction)
rvs -f ./crackme -c analyze functions

# Compact dynamic trace (omits unchanged registers)
rvs -f ./crackme -c dynamic trace main --steps 15

# Alternative formatting: --format [json|agent|jsonl|markdown]
rvs -f ./crackme --format markdown info
```

---

## 🤖 AI Agent & MCP Integration

`rvs` provides a production-grade Python agent harness (`rvs_agent_harness.py`) designed for zero-overhead tool-calling across any LLM architecture.

### 1. Running as a Model Context Protocol (MCP) Server

Add `rvs` to your MCP configuration (`claude_desktop_config.json`, Cursor MCP, or Antigravity):

```json
{
  "mcpServers": {
    "rvs": {
      "command": "python3",
      "args": ["/path/to/rvs/rvs_agent_harness.py", "--mcp"]
    }
  }
}
```

The MCP server exposes all **16 canonical reverse-engineering tools**:
- **Inspection**: `rvs_info`, `rvs_functions`, `rvs_disasm`, `rvs_decompile`, `rvs_flow`, `rvs_xrefs`, `rvs_strings`, `rvs_symbols`
- **Dynamic RE**: `rvs_dynamic_emulate`, `rvs_dynamic_trace`, `rvs_dynamic_step`
- **Patching**: `rvs_patch_instruction`, `rvs_patch_string`, `rvs_patch_bytes`
- **Composite Agent**: `rvs_agent_triage`, `rvs_agent_patch_plan`

### 2. Exporting Universal Tool Calling Schemas

```bash
# Export schemas for major LLM providers
python3 rvs_agent_harness.py --export-tools openai > openai_tools.json
python3 rvs_agent_harness.py --export-tools anthropic > anthropic_tools.json
python3 rvs_agent_harness.py --export-tools gemini > gemini_tools.json
python3 rvs_agent_harness.py --export-tools mcp > mcp_tools.json
```

### 3. Python SDK (`RvsHarness`)

```python
from rvs_agent_harness import RvsHarness

harness = RvsHarness()
target = "tests/fixtures/crackme_case"

# 1. Macro triage of the binary (< 200 tokens)
triage = harness.triage(target, compact=True)
print("Security & Gates:", triage["data"])

# 2. Dynamic emulation with register delta extraction
emu = harness.dynamic_emulate(target, target="main", steps=25, compact=True)
print("Emulation Stop Reason:", emu["data"]["stop"])
print("Modified Registers:", emu["data"]["diff"])

# 3. Simulate instruction patching safely with dry_run
patch = harness.patch_instruction(
    target, 
    addr="0x120c", 
    assembly="nop", 
    dry_run=True
)
print("Patch Dry-Run Status:", patch["success"])
```

---

## 📉 Token Optimization Benchmarks

When interfacing with LLMs, raw radare2 outputs can exceed 10,000+ tokens. `rvs` achieves **60%–99% payload size reduction** in compact mode:

| Analysis Endpoint | Standard Size | Compact Size | Token Reduction | Strategy |
|---|:---:|:---:|:---:|---|
| **Functions** | 4,944 B | 1,361 B | **~72.5%** | Shortened keys (`sz`, `cc`, `bb`), omitted unused C signatures. |
| **Blocks / Disasm** | 26,174 B | 9,869 B | **~62.3% – 96%** | Merged disasm/opcode into single `asm`, stripped raw byte blobs. |
| **Xrefs** | 3,980 B | 510 B | **~76.5% – 99%** | O(1) HashSet deduplication, hex-only address references. |
| **Strings** | 823 B | 340 B | **~58.7% – 95%** | Key-value mapping `"0xaddr": "string"` omitting offset/type noise. |
| **Symbols** | 3,371 B | 1,228 B | **~63.6% – 84%** | Omitted default `LOCAL` bindings, typed struct deserialization. |
| **Dynamic Trace** | 1,257 B | 483 B | **~61.6%** | Register deltas only; suppresses redundant instruction pointer diffs. |

---

## 🚦 Standardized Exit Code Taxonomy

All commands emit machine-readable JSON envelopes with standardized exit codes:

| Code | Type | Description |
|:---:|---|---|
| **0** | `SUCCESS` | Operation completed successfully. |
| **1** | `INVALID_ARGUMENT` | Missing or malformed CLI arguments, negative steps/counts. |
| **2** | `FILE_ERROR` | File not found, permission denied, 0-byte file (`ZERO_BYTE_FILE`), directory target. |
| **3** | `ANALYSIS_ERROR` | Symbol not found, disassembly failure, invalid address, emulation crash. |
| **4** | `PATCH_ERROR` | Assembly failed, verification mismatch, string length overflow, invalid hex. |
| **5** | `TIMEOUT_ERROR` | Subprocess exceeded configured timeout watchdog (via `--timeout`). |
| **6** | `INTERNAL_ERROR` | Radare2 driver crash, corrupted pipe, or JSON deserialization error. |

#### Error Envelope Example:
```json
{
  "success": false,
  "command": "rvs -f target dynamic emulate non_existent_function",
  "target": "target",
  "timestamp": "2026-09-06T00:00:00Z",
  "data": null,
  "error": {
    "code": 3,
    "type": "FUNCTION_NOT_FOUND",
    "message": "Function 'non_existent_function' was not found in binary symbols.",
    "suggestion": "Run 'rvs -f <file> analyze functions' to inspect available function names."
  }
}
```

---

## 🧪 Comprehensive Verification & QA

`rvs` is continuously validated against strict adversarial test suites:

```bash
# 1. Compile C test fixtures
./tests/fixtures/compile_fixtures.sh

# 2. Run full Rust test suite (150+ tests)
cargo test

# 3. Verify strict Clippy static analysis (0 warnings)
cargo clippy --all-targets --all-features -- -D warnings

# 4. Run Opaque-Box E2E Requirements suite (93 tests)
python3 -m unittest tests/e2e_requirements_test.py

# 5. Run Python Unit & Adversarial suites (177 tests)
python3 -m unittest discover -s tests -p "test_*.py"

# 6. Run System Binary Stress Testing (155 tests)
python3 tests/stress_harness.py
```

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
