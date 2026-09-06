# rvs: High-Performance Binary Analysis, ESIL Dynamic Emulation, and Deterministic Patching Engine

[![Version](https://img.shields.io/badge/version-v0.2.0-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/protocol-MCP_Compliant-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)

`rvs` (Reverse Visual Static/Dynamic Engine) is a systems-level binary analysis, instruction-level dynamic emulation, and deterministic binary modification engine written in Rust on top of `radare2`. It is designed as an infrastructure bridge between low-level binary reversing workflows and autonomous AI coding agents (such as Google Antigravity, Claude Code, Gemini CLI, and Cursor), as well as human reverse engineers requiring machine-readable, deterministic tooling.

The engine addresses critical barriers encountered when interfacing LLM agents with traditional reverse-engineering tools: terminal stream pollution, context window exhaustion, unhandled subprocess panics, non-deterministic error codes, and command injection vulnerabilities.

---

## Technical Overview

### Core Design Principles

1. Zero Terminal Stream Pollution: Raw radare2 commands output interactive escape sequences and terminal noise. `rvs` forces `TERM=dumb`, isolates execution across clean subprocess pipes, and normalizes output into strictly formatted, deterministic JSON.
2. Standardized 7-Level Exit Taxonomy: Standardizes all operational outcomes into a strict machine-readable exit hierarchy (Codes 0 through 6) accompanied by structured error envelopes with remediation suggestions.
3. Adaptive Token Compaction: Implements an algorithmic compaction layer yielding 60% to 99% reduction in JSON payload size without loss of essential reversing signals (register diffs, control-flow edges, xref targets).
4. Isolated Dynamic Emulation (ESIL): Leverages the radare2 Evaluable Strings Instruction Language (ESIL) virtual machine to simulate instruction execution, calculate register diff deltas, and evaluate branch decisions without native binary execution, ptrace privileges, or root permissions.
5. Defensive Subprocess Engineering: Enforces character-boundary-aware UTF-8 slicing, strict address/assembly input character filtering (`FORBIDDEN_CHARS`), and global timeout watchdogs to prevent command injection, multi-byte panic aborts, and infinite execution loops.

---

## Architecture

The system operates as a tiered architecture linking high-level AI agents to low-level binary analysis backends:

```
+-------------------------------------------------------------------------+
|                  AI Agents / MCP Clients / Security Analysts            |
|            (Google Antigravity, Claude Code, Cursor IDE, Terminal)      |
+------------------------------------+------------------------------------+
                                     |
                +--------------------+--------------------+
                |                                         |
+---------------v---------------+         +---------------v---------------+
|     Python Agent Harness      |         |      Direct CLI Subcommands   |
|    (rvs_agent_harness.py)     |         |         (target/release/rvs)  |
| - 16 Canonical MCP Tools      |         | - Static Analysis Engines     |
| - JSON-RPC 2.0 stdio Server   |         | - ESIL Emulation VM Bridge    |
| - Schema Exporters (MCP/LLM)  |         | - In-Place Binary Patching    |
| - Parameter Coercion Engine   |         | - Token Compaction Formatting |
| - BrokenPipe & UTF-8 Scrubber |         | - Process Timeout Watchdog    |
+---------------+---------------+         +---------------+---------------+
                |                                         |
                +--------------------+--------------------+
                                     |
                        +------------v------------+
                        |      Rust Core Layer    |
                        |  - Memory-Safe Parsers  |
                        |  - Zero-Panic Contracts |
                        |  - Exit Code Taxonomy   |
                        +------------+------------+
                                     | Isolated Subprocess (Env Scrubbing)
                        +------------v------------+
                        |      radare2 Subsystem  |
                        |  - Static Dissasembly   |
                        |  - ESIL Emulation VM    |
                        +-------------------------+
```

### Component Breakdown

- Rust Engine Core (`src/`):
  - `src/main.rs`, `src/cli.rs`: Command-line interface definitions, flag parsing, pre-flight file validation (rejecting empty files and directories before spawning r2).
  - `src/r2/driver.rs`: Low-level radare2 driver managing subprocess lifecycles, environment scrubbing, pipe communications, and sanitization of user-supplied addresses against shell redirection metacharacters.
  - `src/analysis/`: Static analysis modules covering binary metadata extraction, function enumeration, basic block parsing, cross-reference calculation, symbol resolution, and call graph construction.
  - `src/analysis/dynamic.rs`: ESIL dynamic emulation engine orchestrating `aei`, `aeim`, `aer`, `aes`, and `aetr` operations, snapshotting register states, and computing execution diff deltas.
  - `src/agent/`: High-level composite commands designed for autonomous decision-making: `agent triage`, `agent decompile`, `agent flow`, `agent emulate`, and `agent patch-plan`.
  - `src/patch/`: Deterministic patching drivers for x86/x86_64/ARM instruction replacement, string in-place editing, and raw byte overrides with automated backup creation.
  - `src/compact.rs`: Serialization models converting verbose radare2 payloads into minimal token representations.
  - `src/error.rs`, `src/response.rs`: Standardized error models, response envelopes, and exit code mappings.

- Python Agent Harness (`rvs_agent_harness.py`):
  - Model Context Protocol (MCP) JSON-RPC 2.0 stdio server compliant with the Anthropic MCP specification.
  - Exposes 16 canonical tools with typed JSON schemas.
  - Handles client disconnections gracefully via `BrokenPipeError` suppression.
  - Sanitizes invalid UTF-8 sequences and normalizes cache paths.
  - Provides standalone schema export utilities for OpenAI, Anthropic, Gemini, and MCP.

---

## Token Compaction Engine

Large binaries can produce tens of megabytes of raw analysis data, exhausting LLM context limits. `rvs` introduces compact data representations specifically tailored for context-constrained models:

### Compaction Benchmarks

| Analysis Endpoint | Standard Size | Compact Size | Token Reduction | Compaction Strategy |
|:---|:---:|:---:|:---:|:---|
| Functions (`analyze functions`) | 4,944 B | 1,361 B | ~72.5% | Key truncation (`sz`, `cc`, `bb`), omits unused C signatures. |
| Basic Blocks (`analyze blocks`) | 26,174 B | 9,869 B | ~62.3% - 96% | Merges disasm and opcode into single field, strips byte hex blobs. |
| Cross References (`xrefs`) | 3,980 B | 510 B | ~76.5% - 99% | O(1) HashSet deduplication, hex-only address references. |
| Strings (`strings`) | 823 B | 340 B | ~58.7% - 95% | Transforms arrays into `"0xaddr": "string"` key-value mappings. |
| Symbols (`symbols`) | 3,371 B | 1,228 B | ~63.6% - 84% | Omits default `LOCAL` bindings, typed struct deserialization. |
| Dynamic Trace (`dynamic trace`) | 1,257 B | 483 B | ~61.6% | Emits register diff deltas only; suppresses static instruction pointer dumps. |

To enable compact mode across CLI commands, pass `-c` or `--compact`:
```bash
rvs -f ./target_bin -c analyze functions
rvs -f ./target_bin -c dynamic trace main --steps 20
```

---

## 16 Canonical MCP Tools Catalog

The Python harness (`rvs_agent_harness.py`) and setup installer expose 16 canonical tools:

### Static Analysis & Inspection
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_info` | `file: str, compact: bool` | Extracts file architecture, bitness, endianness, entry point, and security mitigations (PIE, Canary, NX, RELRO). |
| `rvs_functions` | `file: str, compact: bool` | Lists all detected functions with entry offsets, sizes, cyclomatic complexity, and basic block counts. |
| `rvs_disasm` | `file: str, target: str, count: int, compact: bool` | Disassembles a specified function or address range. |
| `rvs_decompile` | `file: str, target: str, timeout: int` | Decompiles target function into pseudo-C with annotated string cross-references. |
| `rvs_flow` | `file: str, target: str, compact: bool` | Computes basic block control-flow graph and conditional jump conditions. |
| `rvs_xrefs` | `file: str, target: str, compact: bool` | Identifies code and data cross-references to and from target symbols. |
| `rvs_strings` | `file: str, min_len: int, filter: str, compact: bool` | Extracts printable ASCII/UTF-8 strings with offset tracking. |
| `rvs_symbols` | `file: str, filter: str, compact: bool` | Resolves imported, exported, and internal binary symbols. |

### Dynamic Reverse Engineering (ESIL Emulation)
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_dynamic_emulate` | `file: str, target: str, steps: int, reg_set: list, compact: bool` | Simulates function execution under ESIL VM, captures stop reasons, return registers, and memory snapshots. |
| `rvs_dynamic_trace` | `file: str, target: str, steps: int, reg_set: list, compact: bool` | Generates instruction-level execution trace logging register deltas at each step. |
| `rvs_dynamic_step` | `file: str, target: str, count: int, compact: bool` | Executes single-step instruction debugging inspection from entry or specified offset. |

### Deterministic Binary Patching
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_patch_instruction` | `file: str, addr: str, assembly: str, nop: int, backup: bool, dry_run: bool` | Assembles and overwrites instructions at address, supports NOP padding and backup creation. |
| `rvs_patch_string` | `file: str, addr: str, string: str, backup: bool, dry_run: bool` | Overwrites string literals in binary data sections with strict length bounds checking. |
| `rvs_patch_bytes` | `file: str, addr: str, hex: str, backup: bool, dry_run: bool` | Writes raw hexadecimal byte sequences directly to specified offsets. |

### Composite Agent Automations
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_agent_triage` | `file: str, compact: bool` | Comprehensive binary profile combining security mitigations, suspicious strings, and high-complexity functions. |
| `rvs_agent_patch_plan` | `file: str, plan: dict, dry_run: bool` | Executes multi-step declarative patch transactions with validation and rollback safety. |

---

## Installation & Setup Automation

The repository provides a defensive, zero-dependency Bash automation tool (`install.sh`) supporting both guided interactive configuration and manual configuration export.

### Quick Start via install.sh

```bash
# Clone the repository
git clone https://github.com/Anhdeface/rvs.git
cd rvs

# Run the installer
./install.sh
```

### Installation Features

1. Pre-flight Dependency Diagnostic:
   - Scans and verifies system requirements: Python 3 (>= 3.9), radare2, Git, jq, and Cargo.
   - Detects existing AI agents on host (Google Antigravity, Claude Desktop/CLI, Cursor IDE).
   - Strictly notification-only: If dependencies are missing, displays package manager commands for Ubuntu/Debian, macOS, and Arch Linux without running unprivileged package modifications.
2. Dynamic Environment Resolution:
   - Calculates repository paths dynamically (`pwd -P`). Never hardcodes absolute user paths.
3. Manual Setup Mode (Option 2):
   - Generates `rvs_mcp_config.json` containing exact dynamic paths for users who prefer manual configuration.
   - Disables automatic background checks in manual mode to prevent unprompted background operations.
4. Test Suite Exclusion (Git Sparse-Checkout):
   - Option to exclude `tests/` and `.agents/` via native `git sparse-checkout set --no-cone '/*' '!/tests' '!/.agents'`.
   - Prevents test fixtures from being fetched during subsequent git updates, conserving disk space and network bandwidth.
5. Non-Blocking Release Synchronization:
   - Checks GitHub release tags in the background when the MCP proxy is invoked (throttled to at most once per 24 hours).
   - Never modifies or checks out source code automatically.
   - Highlights pending updates directly on the installer banner (`Notice: A new release vX.Y.Z is available!`) and displays a menu badge (`Option 3: Check GitHub Update (vX.Y.Z available)`).
6. Security Hardening:
   - Sanitizes remote Git tags using strict semantic version regular expressions to prevent argument injection.
   - Verifies SHA256 hashes against release assets prior to binary installation.
   - Writes configuration files atomically using PID-suffixed temporary files (`.tmp.$$`) with restricted permissions (`0700` directories, `0600` cache files).

### Interactive Menu Navigation

```text
1) Setup / Configure Agents (Interactive Wizard)
2) Manual Setup (Export MCP Config Snippet)
3) Check GitHub Update
4) Toggle Test Suites (Exclude or Include)
5) System & Agent Diagnostic
6) Uninstall
0) Exit
```

---

## Agent Integrations

### 1. Google Antigravity

Automated configuration via `install.sh` updates `~/.gemini/config/mcp_config.json`, extracts tool schemas into `~/.gemini/antigravity-cli/mcp/rvs/`, and symlinks `SKILL.md` into `~/.gemini/config/skills/rvs/SKILL.md`.

Manual configuration snippet:
```json
{
  "mcpServers": {
    "rvs": {
      "command": "python3",
      "args": [
        "/absolute/path/to/rvs/rvs_agent_harness.py",
        "--mcp"
      ]
    }
  }
}
```

### 2. Claude Desktop & Claude Code CLI

For Claude Desktop, configuration is placed in:
- Linux: `~/.config/Claude/claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

For Claude Code CLI:
```bash
claude mcp add rvs -- python3 /absolute/path/to/rvs/rvs_agent_harness.py --mcp
```

### 3. Cursor IDE

Configuration file: `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "rvs": {
      "command": "python3",
      "args": [
        "/absolute/path/to/rvs/rvs_agent_harness.py",
        "--mcp"
      ]
    }
  }
}
```

---

## CLI Usage Reference

### Static Analysis Commands

```bash
# General binary metadata and mitigation inspection
rvs -f /bin/ls info

# Extract strings with custom minimum length and substring filter
rvs -f /bin/ls strings --min-len 8 --filter "auth"

# Enumerate function entries and symbols
rvs -f /bin/ls analyze functions
rvs -f /bin/ls symbols --filter "main"

# Disassemble function blocks
rvs -f /bin/ls analyze blocks main

# Export call graph in tree or mermaid format
rvs -f /bin/ls analyze graph --format tree
rvs -f /bin/ls analyze graph --format mermaid
```

### Dynamic Reverse Engineering (ESIL)

```bash
# Emulate main entry execution for 50 steps
rvs -f ./crackme dynamic emulate main --steps 50

# Emulate with explicit register preconditions
rvs -f ./crackme dynamic emulate main --steps 50 --reg-set rdi=0x1337 --reg-set rsi=0x4000

# Instruction-level trace logging register state transitions
rvs -f ./crackme dynamic trace main --steps 20

# Single-step instruction inspection
rvs -f ./crackme dynamic step main --count 1

# Analyze conditional gate branch outcomes
rvs -f ./crackme agent emulate main --steps 50
```

### Binary Modification & Patching

```bash
# Replace instruction at address with assembly string
rvs -f ./binary patch instruction --addr 0x1149 --assembly "nop" --backup

# Fill address range with NOP instructions
rvs -f ./binary patch instruction --addr 0x1149 --nop 4

# Overwrite in-place string literal
rvs -f ./binary patch string --addr 0x2000 --string "AUTHORIZED"

# Direct raw hexadecimal byte patch
rvs -f ./binary patch bytes --addr 0x1149 --hex "90909090"

# Declarative multi-patch plan execution (dry-run simulation)
rvs -f ./binary agent patch-plan --plan '{"target_file":"./binary","patches":[{"address":"0x1149","type":"instruction","value":"nop"}],"dry_run":true}'
```

### Process Watchdog & Timeouts

To prevent runaway analysis or infinite emulation loops on unknown binaries:
```bash
rvs -f ./untrusted_bin --timeout 10 dynamic emulate main --steps 10000
```

---

## Standardized Exit Code Taxonomy

All commands adhere to a standardized exit code hierarchy:

| Exit Code | Identifier | Description |
|:---:|:---|:---|
| `0` | `SUCCESS` | Operation finished successfully. |
| `1` | `INVALID_ARGUMENT` | Malformed CLI arguments, invalid format flag, negative steps. |
| `2` | `FILE_ERROR` | File not found, permission denied, zero-byte file (`ZERO_BYTE_FILE`), directory target. |
| `3` | `ANALYSIS_ERROR` | Symbol not found, disassembly failure, invalid target address, emulation fault. |
| `4` | `PATCH_ERROR` | Assembly failed, verification mismatch, string length overflow, invalid hex format. |
| `5` | `TIMEOUT_ERROR` | Operation exceeded configured execution deadline (`--timeout`). |
| `6` | `INTERNAL_ERROR` | Driver crash, radare2 pipe error, unhandled I/O exception. |

### Error Envelope Schema

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

## Testing & Verification

The test suite covers unit, integration, opaque-box requirements, and adversarial fuzz tests:

```bash
# 1. Compile C test binary fixtures
./tests/fixtures/compile_fixtures.sh

# 2. Execute Rust core test suite
cargo test

# 3. Verify static analysis and linting (0 warnings)
cargo clippy --all-targets --all-features -- -D warnings

# 4. Run 4-Tier Opaque-Box E2E Requirements suite (93 tests)
python3 tests/e2e_requirements_test.py

# 5. Run Python harness and adversarial schema tests
python3 -m unittest discover -s tests -p "test_*.py"

# 6. Execute system binary stress harness
python3 tests/stress_harness.py
```

### Test Coverage Architecture

- Tier 1: Functional Feature Coverage (Panic-free execution, exit codes 1..6, token compaction, register diff extraction, schema exports).
- Tier 2: Boundary Value Analysis & Corner Cases (Zero steps, zero-byte files, out-of-range addresses, negative inputs, invalid ELF headers).
- Tier 3: Pairwise Combinatorial Interactions (Multi-step patch plans combined with ESIL execution validation).
- Tier 4: Real-World Scenarios (End-to-end crackme analysis, authentication gate bypass, and dynamic tracing).

---

## License

This project is licensed under the GNU General Public License v3.0 ([GPL-3.0](LICENSE)).
