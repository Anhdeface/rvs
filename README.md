# `rvs` — Radare2 Binary Analysis & Reverse Engineering Engine for AI Agents

[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/protocol-MCP_Compliant-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)

**`rvs`** is a high-performance binary analysis, reverse engineering, and in-place patching toolkit built in Rust on top of `radare2`. It is designed from the ground up for both **human security engineers** and **autonomous AI coding agents** (e.g. Claude, GPT-4o, Gemini, Cursor, Antigravity).

`rvs` solves the classic issues of integrating binary analysis tools with LLMs: noisy terminal output, runaway context sizes, non-deterministic error codes, and brittle subprocess management.

---

## 🌟 Key Features

- **⚡ Strict Subprocess & Terminal Isolation**: Complete sanitization (`TERM=dumb`, `NO_COLOR=1`, `R2_NOPLUGINS=1`, ANSI sequence scrubbing) ensuring zero terminal corruption and zero hang vulnerabilities.
- **📉 Token-Optimized AI Agent Layer**: Built-in Python harness (`rvs_agent_harness.py`) achieving **40%–90%+ token reduction** through smart field pruning, compact representations, and budget-constrained instruction truncation.
- **🔌 Native Model Context Protocol (MCP) Server**: Full JSON-RPC 2.0 stdio MCP server for zero-configuration integration with MCP clients (Claude Desktop, Cursor, Antigravity, Cline).
- **🛠️ Universal LLM Tool Calling**: Native schema generator exporting 13 canonical reverse-engineering tools in OpenAI, Anthropic, and Google Gemini formats.
- **🔍 Static Binary Analysis**: Deep inspection for ELF, PE, Mach-O architectures, header metadata, functions, basic blocks, pseudocode decompilation, strings, and symbols.
- **📊 Control Flow & Call Graph Engine**: Non-recursive DAG traversal with cycle detection, depth limits, and cross-reference (`xrefs`) tracing.
- **🩹 Safe Binary Patching & Dry-Run Simulation**: In-place instruction modification, NOP injection, byte overwrites, automatic atomic backups, and declarative JSON Patch Plans (`patch-plan`).
- **📋 7-Level Standardized Exit Code Taxonomy**: Strict machine-readable envelopes (`ApiResponse` / `ApiError`) with actionable suggestions for autonomous error recovery.

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
         ├── Compaction Engine (40-90% token drop)             ├── 7-Level Exit Taxonomy
         ├── MCP JSON-RPC 2.0 Stdio Handler                    ├── Multi-Format Engine (json, agent, md)
         ├── OpenAI/Gemini/Anthropic Schemas                   └── Composite Commands (triage, flow)
                    │                                                   │
                    └─────────────────────────┬─────────────────────────┘
                                              │
                                  ┌───────────▼───────────┐
                                  │     `rvs` Engine      │
                                  │ (Rust Core Controller)│
                                  └───────────┬───────────┘
                                              │ Isolated Subprocess (Env Scrubbing, Timeouts)
                                  ┌───────────▼───────────┐
                                  │       radare2         │
                                  │  (Backend Analysis)   │
                                  └───────────────────────┘
```

---

## 📦 Prerequisites & Installation

### 1. Requirements
- **Rust Toolchain**: `cargo` & `rustc` 1.75+
- **Radare2**: `radare2` 5.8+ (accessible in `PATH`)
- **Python**: Python 3.9+ (for the agent harness and MCP server)

### 2. Building from Source
```bash
# Clone the repository
git clone https://github.com/Anhdeface/rvs.git
cd rvs

# Build release binary
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

### 1. Binary Information & Metadata
```bash
# Basic file headers, architecture, entry point, security flags
rvs -f /bin/ls info

# Extract all printable strings (min length 4)
rvs -f /bin/ls strings --min-len 6

# List functions and symbols
rvs -f /bin/ls functions
rvs -f /bin/ls symbols
```

### 2. Disassembly & Decompilation
```bash
# Disassemble a specific function or address
rvs -f /bin/ls disasm main

# Decompile a function to pseudo-C
rvs -f /bin/ls decompile main
```

### 3. Control Flow & Cross References
```bash
# Generate basic blocks and control flow graph
rvs -f /bin/ls flow main

# Find cross references to a function, string, or address
rvs -f /bin/ls xrefs main
```

### 4. Binary Patching
```bash
# Replace an instruction at an address
rvs -f ./target_bin patch instruction 0x1149 "nop" --backup

# Patch string in-place
rvs -f ./target_bin patch string 0x2000 "UNLOCKED"

# Patch raw hex bytes
rvs -f ./target_bin patch bytes 0x1149 "90909090"
```

### 5. Composite Agent Workflows
```bash
# Rapid binary triage (identifies security checks, auth gates, crypto strings)
rvs -f ./target_bin agent triage

# Execute a declarative multi-step patch plan with dry-run support
rvs -f ./target_bin agent patch-plan --plan '{"target_file":"./target_bin","patches":[{"address":"0x1149","type":"instruction","value":"nop"}],"dry_run":true}'
```

---

## 🤖 AI Agent & MCP Integration

`rvs` comes with a dedicated Python agent harness layer (`rvs_agent_harness.py`) designed for minimal token overhead and seamless tool-calling.

### 1. Running as a Model Context Protocol (MCP) Server

To use `rvs` with MCP-compatible clients (e.g. Claude Desktop, Cursor, Antigravity, Cline), add the following configuration to your client's MCP settings:

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

The MCP server automatically exposes all 13 canonical reverse-engineering tools:
- `rvs_info`, `rvs_functions`, `rvs_disasm`, `rvs_decompile`
- `rvs_flow`, `rvs_xrefs`, `rvs_strings`, `rvs_symbols`
- `rvs_patch_instruction`, `rvs_patch_string`, `rvs_patch_bytes`
- `rvs_agent_triage`, `rvs_agent_patch_plan`

### 2. Exporting Function Calling Schemas

Export ready-to-use tool schemas for major LLM providers:

```bash
# Export for OpenAI Function Calling
python3 rvs_agent_harness.py --export-tools openai > openai_tools.json

# Export for Google Gemini
python3 rvs_agent_harness.py --export-tools gemini > gemini_tools.json

# Export for Anthropic Tool Use
python3 rvs_agent_harness.py --export-tools anthropic > anthropic_tools.json

# Export for Model Context Protocol (MCP)
python3 rvs_agent_harness.py --export-tools mcp > mcp_tools.json
```

### 3. Python SDK (`RvsHarness`) Usage

```python
from rvs_agent_harness import RvsHarness, execute_tool

harness = RvsHarness()
target = "tests/fixtures/crackme_case"

# 1. Macro triage of the binary in summary mode (uses < 200 tokens)
triage_result = harness.triage(target, mode="summary")
print("Triage Summary:", triage_result["data"])

# 2. Extract functions with pagination (compact mode reduces 70%+ tokens)
funcs = harness.functions(target, mode="compact", max_items=10, offset=0)
print(f"Functions (Showing {funcs['data']['displayed']} of {funcs['data']['total']}):")

# 3. Disassemble specific target with instruction truncation
disasm = harness.disasm(target, target="main", mode="compact", max_instructions=25)
print("Disassembly:", disasm["data"])

# 4. Simulate a patch safely with dry_run
patch_res = harness.patch_instruction(
    target, 
    address="0x1149", 
    instruction="nop", 
    dry_run=True
)
print("Patch Simulation:", patch_res)
```

---

## 📉 Token Optimization Modes

When interfacing with LLMs, raw radare2 outputs can easily consume 10,000+ tokens. `rvs` provides 3 output transformation modes:

| Mode | Token Savings | Use Case |
|---|:---:|---|
| **`compact`** *(Default)* | **40% – 85%** | Strips duplicate metadata, standardizes hex addresses, consolidates xrefs, and minimizes JSON keys while retaining full semantic fidelity. |
| **`summary`** | **85% – 99%** | Macro-level overview (entrypoint, function counts, section layouts, security flags) for initial agent exploration. |
| **`full`** | **0%** | Verbatim raw output when exact low-level details are needed. |

---

## 🚦 Exit Code Taxonomy & Error Handling

All commands return structured envelopes with standardized exit codes:

| Code | Name | Description |
|:---:|---|---|
| **0** | `SUCCESS` | Command completed successfully. |
| **1** | `INVALID_ARGUMENT` | Missing or malformed CLI arguments / flags. |
| **2** | `FILE_ERROR` | Target file not found, permission denied, or invalid binary format. |
| **3** | `ANALYSIS_ERROR` | Symbol not found, disassembly failure, or graph cycle error. |
| **4** | `PATCH_ERROR` | Address out of bounds, invalid assembly syntax, or string length overflow. |
| **5** | `TIMEOUT_ERROR` | Subprocess exceeded configured timeout watchdog (default 30s). |
| **6** | `INTERNAL_ERROR` | Radare2 crash or unhandled runtime failure. |

#### Error Envelope Example:
```json
{
  "success": false,
  "command": "rvs -f target disasm non_existent_function",
  "target": "target",
  "timestamp": "2026-08-31T18:00:00Z",
  "data": null,
  "error": {
    "code": "SYMBOL_NOT_FOUND",
    "message": "Function 'non_existent_function' was not found in binary symbols or functions table.",
    "category": "ANALYSIS_ERROR",
    "exit_code": 3,
    "suggestion": "Run 'rvs -f <file> functions' to inspect available function names and offsets."
  }
}
```

---

## 🧪 Testing

`rvs` maintains an extensive test suite covering unit tests, end-to-end integration tests, adversarial stress drivers, and schema validators.

```bash
# 1. Compile C test fixtures
./tests/fixtures/compile_fixtures.sh

# 2. Run full Rust Cargo test suite (116 tests)
cargo test --all-targets

# 3. Run Python Harness & MCP test suite (100 tests)
python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 📄 License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
