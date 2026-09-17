# rvs: High-Performance Binary Analysis, Dynamic RE, Debugging & Runtime Instrumentation Engine

[![Version](https://img.shields.io/badge/version-v0.3.1-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/protocol-MCP_Compliant-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)

`rvs` (Reverse Visual Static/Dynamic Engine) is an enterprise systems-level binary analysis, instruction-level dynamic emulation, native interactive debugging, live runtime instrumentation (`r2frida`), and deterministic binary patching engine written in Rust on top of `radare2` and Frida. It is engineered as a high-throughput, deterministic infrastructure bridge between low-level reverse engineering toolchains and autonomous AI coding agents (such as Google Antigravity, Claude Code, Gemini CLI, Cursor, and Copilot), as well as human security researchers requiring clean, machine-readable telemetry.

The engine eliminates the critical failure modes encountered when interfacing LLMs with traditional binary reversing tools: terminal stream pollution, context window exhaustion, unhandled subprocess panics, hanging zombie processes, non-deterministic exit schemas, and command injection vulnerabilities.

---

## Technical Overview

### Core Design Principles

1. **Zero Terminal Stream Pollution**: Raw RE utilities output interactive ANSI sequences and cursor movements. `rvs` forces `TERM=dumb`, `NO_COLOR=1`, `CLICOLOR=0`, `R2_NOPLUGINS=1`, and `RADARE2_RCFILE=/dev/null`, isolating execution across clean subprocess pipes and normalizing outputs into strict, deterministic JSON envelopes (`ApiResponseDict`).
2. **Standardized 7-Level Exit Code Taxonomy**: Maps all outcomes to an explicit machine-readable exit hierarchy (Codes `0` through `6`) accompanied by structured error envelopes with remediation suggestions.
3. **Adaptive Token Compression (71%–83.5% Reduction)**: Implements polymorphic compaction (`-c` flag / `compact=True`) that strips redundant headers, emits minimal register diffs (modified registers only), and applies strict symmetrical pagination (`--limit`, `--offset`) across high-volume symbols, modules, and classes.
4. **4-Tier Safety Execution Architecture**:
   - **Tier 1 (Static)**: Zero code execution. Safe metadata extraction, CFG parsing, xrefs, and decompilation.
   - **Tier 2 (ESIL Dynamic Emulation)**: Instruction emulation in user-space VM. Simulates loops, flags, and decryption algorithms without OS process execution, ptrace privileges, or root permissions.
   - **Tier 3 (Native Interactive Debugging)**: State-isolated `ptrace` debugging orchestrated by a persistent Unix Domain Socket (UDS) daemon (`/run/user/<uid>/rvs/rvs-debug.sock`).
   - **Tier 4 (Live Instrumentation via r2frida)**: Dynamic process injection, JavaScript hook evaluation, memory reading/writing, and RPC invocations via `r2frida`.
5. **Process Watchdog & Guaranteed Zombie Reaping**: Subprocesses run inside isolated process groups (`process_group(0)` in Rust, `start_new_session=True` in Python). Sessions explicitly terminate tracee processes (`SIGKILL` + `waitpid`) and wrap all executions in `try...finally: proc.wait()` to permanently prevent orphan background processes.
6. **Defensive Input & Memory Engineering**: Enforces character-boundary-aware UTF-8 slicing, strict address sanitization against shell injection, hex byte validation, and unmapped address write protections.

---

## Architecture

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
| - 40 Canonical MCP Tools      |         | - Static Analysis Modules     |
| - JSON-RPC 2.0 stdio Server   |         | - ESIL Emulation VM Engine    |
| - 4-Format Schema Exporters   |         | - Native Debug UDS Daemon     |
| - 4 Composite Agent Workflows |         | - r2frida Live Dynamic Driver |
| - Subprocess Watchdog Reaping |         | - Polymorphic Compaction (-c) |
| - Token Compaction Layer      |         | - Exit Code Taxonomy (0..6)   |
+---------------+---------------+         +---------------+---------------+
                |                                         |
                +--------------------+--------------------+
                                     |
                        +------------v------------+
                        |      Rust Core Layer    |
                        |  - Memory-Safe Parsers  |
                        |  - Zero-Panic Contracts |
                        |  - Process Group Isol.  |
                        +------------+------------+
                                     | Isolated Subprocesses & UDS Sockets
        +----------------------------+----------------------------+
        |                                                         |
+-------v-----------------+                             +---------v---------------+
|    radare2 Subsystem    |                             |      r2frida Engine     |
| - Static Disassembly    |                             | - Live Process Attach   |
| - ESIL Emulation VM     |                             | - JS Hook Injection     |
| - Native ptrace Driver  |                             | - In-Memory Read/Write  |
+-------------------------+                             +-------------------------+
```

### Component Breakdown

- **Rust Engine Core (`src/`)**:
  - `src/main.rs`, `src/cli.rs`: CLI argument parsing, subcommands dispatch (`analyze`, `dynamic`, `debug`, `frida`, `patch`, `agent`), pagination limits, and pre-flight validation.
  - `src/r2/driver.rs`: Low-level radare2 driver with subprocess lifecycle management, pipe communications, and sanitization of user-supplied addresses.
  - `src/debug/`: Native interactive debugging subsystem:
    - `daemon.rs`: Unix Domain Socket server managing debug sessions, fine-grained `Arc<Mutex<DebugSession>>` locking, and POSIX signal handlers (`SIGINT`/`SIGTERM`) for atomic socket unlinking.
    - `driver.rs`: Interactive radare2 driver with timeout stream resynchronization (`\x03` + SIGINT + stdout flush) and tracee PID termination.
    - `session.rs`, `types.rs`: Breakpoint management, register inspection, and memory read/write handlers.
  - `src/frida/`: Live dynamic instrumentation engine:
    - `driver.rs`, `detect.rs`: Frida environment validation, process attach/spawn, and command multiplexing.
    - `hook.rs`, `script.rs`, `memory.rs`: Dynamic hook injection, return value interception, memory inspection, and JS RPC evaluation.
    - `modules.rs`, `target.rs`, `types.rs`: Module/symbol/class enumeration with pagination support.
  - `src/analysis/dynamic.rs`: ESIL dynamic emulation engine with architecture-agnostic Program Counter resolution (x86_64, x86, ARM, AArch64) and register diff tracking.
  - `src/agent/`: Autonomous composite workflows (`triage`, `flow`, `decompile`, `patch_plan`).
  - `src/patch/`: Deterministic assembly, string, and raw hex patching with automated `.bak` backup generation.
  - `src/compact.rs`: Serialization models transforming verbose telemetry into token-optimized payloads.
  - `src/error.rs`, `src/response.rs`: Standardized error models and API envelopes (`CURRENT_FORMAT_VERSION = "0.3.1"`).

- **Python Agent Harness (`rvs_agent_harness.py`)**:
  - Native Model Context Protocol (MCP) JSON-RPC 2.0 stdio server exposing 40 canonical tools.
  - 4-Format Schema Exporters (OpenAI, Anthropic, Gemini, MCP format definitions).
  - Parameterless tool dispatch (`env_check`, `sessions`) and Frida parameter cleanup.
  - 4 High-Level Composite Workflows (`triage_crash`, `bypass_decision_gate`, `dump_decrypted_buffer`, `detect_anti_debug`).
  - Subprocess watchdog with `try...finally: proc.wait()` guaranteed zombie reaping.

---

## Token Compaction Engine

`rvs` enforces token conservation heuristics yielding **71.0% to 83.5% payload reduction** across reverse engineering telemetry:

### Compaction Benchmarks

| Analysis Endpoint | Verbose Payload | Compact Payload | Reduction | Compaction Strategy |
|:---|:---:|:---:|:---:|:---|
| **Dynamic Trace** (`dynamic trace`) | 2,840 B | 512 B | **~82.0%** | Emits modified register diffs only; omits static registers. |
| **ESIL Emulation** (`dynamic emulate`) | 3,150 B | 610 B | **~80.6%** | Compresses execution path, register deltas, and stop reasons. |
| **Functions** (`analyze functions`) | 4,944 B | 1,361 B | **~72.5%** | Key truncation (`sz`, `cc`, `bb`), omits redundant prototypes. |
| **Basic Blocks** (`analyze blocks`) | 26,174 B | 4,320 B | **~83.5%** | Merges disassembly/opcodes, strips raw byte hex dumps. |
| **Cross References** (`xrefs`) | 3,980 B | 510 B | **~87.2%** | O(1) HashSet deduplication, hex-only address references. |
| **Strings** (`strings`) | 823 B | 210 B | **~74.5%** | Transforms arrays into `"0xaddr": "string"` key-value mappings. |
| **Frida Symbols** (`frida symbols`) | 12,400 B | 2,150 B | **~82.6%** | Enforces `--limit 50`, `--offset`, strips internal mangling. |
| **Memory Dump** (`debug memory`) | 1,840 B | 420 B | **~77.2%** | Strips ASCII padding, compacts hex byte sequences. |

Pass `-c` / `--compact` on CLI or `compact=True` via MCP:
```bash
rvs -f ./crackme -c dynamic trace main --steps 20
rvs frida symbols 1234 --limit 50 -c
```

---

## 40 Canonical MCP Tools Catalog

The MCP server exposes 40 canonical tools organized across the 6-Phase Reverse Engineering Operational Playbook:

### 1. Reconnaissance & Static Metadata
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_info` | `file: str, compact: bool` | Extract architecture, bitness, endianness, entry point, and security mitigations (PIE, Canary, NX, RELRO). |
| `rvs_strings` | `file: str, min_len: int, filter: str, limit: int, compact: bool` | Extract printable ASCII/UTF-8 strings with offset tracking. |
| `rvs_symbols` | `file: str, filter: str, limit: int, compact: bool` | Resolve imported, exported, and internal binary symbols. |
| `rvs_agent_triage` | `file: str, compact: bool` | Complete autonomous binary profile ranking functions by cyclomatic complexity and suspicious strings. |

### 2. Static Flow & Decompilation
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_functions` | `file: str, filter: str, limit: int, compact: bool` | Enumerate function offsets, sizes, and cyclomatic complexity. |
| `rvs_disasm` | `file: str, target: str, max_instructions: int, compact: bool` | Disassemble function blocks or specified address ranges. |
| `rvs_decompile` | `file: str, function: str, compact: bool` | Decompile target function into pseudo-C with annotated string xrefs and call sites. |
| `rvs_flow` | `file: str, function: str, compact: bool` | Compute decision gate nodes, branch instructions (`je`, `jne`), jump targets, and fallthroughs. |
| `rvs_xrefs` | `file: str, target: str, direction: str, compact: bool` | Identify cross-references to/from symbol, address, or string literal. |
| `rvs_symbols` | `file: str, filter: str, limit: int, compact: bool` | Enumerate PLT symbols, external imports, and function exports. |

### 3. Dynamic Analysis & ESIL Emulation (Safe User-Space VM)
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_dynamic_emulate` | `file: str, target: str, steps: int, until: str, reg_set: list, read_mem: str, mem_len: int, compact: bool` | Simulate execution under ESIL VM, capturing stop reasons, return registers, and memory buffers. |
| `rvs_dynamic_trace` | `file: str, target: str, steps: int, reg_set: list, compact: bool` | Step-by-step instruction execution trace emitting register deltas at each step. |
| `rvs_dynamic_step` | `file: str, target: str, count: int, reg_set: list, compact: bool` | Single-step (or N-step) execution advancing program counter. |

### 4. Native Dynamic Debugging (UDS Daemon Managed)
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_debug_spawn` | `file: str, args: list` | Spawn target executable under ptrace debugger session daemon. |
| `rvs_debug_attach` | `pid: int` | Attach debugger daemon to existing running process by PID. |
| `rvs_debug_continue` | `session_id: str` | Continue execution until breakpoint hit, signal, or process exit. |
| `rvs_debug_step` | `session_id: str, count: int` | Single-step N native instructions under debugger. |
| `rvs_debug_breakpoint`| `session_id: str, addr: str, action: str` | Set, remove, or list software breakpoints. |
| `rvs_debug_registers` | `session_id: str, set_regs: list` | Read architectural registers or mutate specific register values. |
| `rvs_debug_memory` | `session_id: str, addr: str, length: int, write_hex: str` | Read or write raw memory bytes in live debuggee process space. |
| `rvs_debug_kill` | `session_id: str` | Terminate debug session, kill tracee PID, and release resources. |
| `rvs_debug_sessions` | *(none)* | List all currently active debugger sessions on daemon. |

### 5. Live Runtime Instrumentation via r2frida
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_frida_env_check` | *(none)* | Verify r2frida installation and host runtime capabilities. |
| `rvs_frida_attach` | `target: str` | Attach Frida to running process by PID, process name, or URI. |
| `rvs_frida_spawn` | `target: str, args: list` | Spawn target executable under dynamic Frida instrumentation. |
| `rvs_frida_modules` | `target: str, limit: int, offset: int` | Enumerate loaded shared libraries and memory bases. |
| `rvs_frida_symbols` | `target: str, module: str, limit: int, offset: int` | Enumerate exported symbols in target process/module. |
| `rvs_frida_classes` | `target: str, limit: int, offset: int` | Enumerate Objective-C, Swift, or Java classes in memory. |
| `rvs_frida_hook` | `target: str, addr: str, signature: str` | Register function entry/exit hook to trace arguments. |
| `rvs_frida_trace_regs`| `target: str, addr: str` | Trace CPU register values at function entry/exit. |
| `rvs_frida_hook_return`| `target: str, addr: str, return_value: str` | Intercept and override function return value dynamically. |
| `rvs_frida_hooks_list`| `target: str` | List all active hooks registered in target process. |
| `rvs_frida_hook_remove`| `target: str, hook_id: str` | Remove active dynamic hook by ID. |
| `rvs_frida_script` | `target: str, script: str, file: str` | Inject and evaluate custom JavaScript snippet or script file. |
| `rvs_frida_rpc` | `target: str, method: str, args: list` | Invoke exported Frida RPC method (`rpc.exports.<method>`). |
| `rvs_frida_mem_read` | `target: str, addr: str, length: int` | Read raw bytes from live process memory. |
| `rvs_frida_mem_write`| `target: str, addr: str, hex: str` | Live patch memory bytes in running process. |

### 6. Binary Patching & Composite Agent Workflows
| Tool Name | Parameters | Description |
|:---|:---|:---|
| `rvs_patch_instruction`| `file: str, addr: str, assembly: str, nop_bytes: int, backup: bool` | Patch assembly instruction or write NOP sled. |
| `rvs_patch_string` | `file: str, new_string: str, addr: str, backup: bool` | Overwrite string literal with strict length overflow protection. |
| `rvs_patch_bytes` | `file: str, addr: str, hex_bytes: str, backup: bool` | Write raw hex bytes at specified binary offset. |
| `rvs_agent_patch_plan`| `file: str, plan: dict, dry_run: bool` | Declarative multi-step patch plan with dry-run verification. |
| `rvs_triage_crash` | `file: str, args: list` | Automatically triage crash, fault address, and registers. |
| `rvs_bypass_decision_gate`| `file: str, gate_addr: str, target_func: str` | Analyze decision gate and generate breakpoint bypass patch. |
| `rvs_dump_decrypted_buffer`| `file: str, break_addr: str, mem_addr: str, length: int` | Dynamically dump decrypted memory buffer at breakpoint. |
| `rvs_detect_anti_debug`| `file: str` | Detect ptrace anti-debugging and anti-analysis gates. |

---

## Installation & Setup Automation

`rvs` provides a zero-dependency Bash automation installer (`install.sh`) supporting interactive wizard and manual setup export.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Anhdeface/rvs.git
cd rvs

# Run the installer
./install.sh
```

### Automated Configuration for AI Agents

#### 1. Google Antigravity
The installer auto-configures `~/.gemini/config/mcp_config.json`, extracts tool schemas into `~/.gemini/antigravity-cli/mcp/rvs/`, and links `SKILL.md` into `~/.gemini/config/skills/rvs/SKILL.md`.

Manual snippet:
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

#### 2. Claude Desktop & Claude Code CLI
```bash
claude mcp add rvs -- python3 /absolute/path/to/rvs/rvs_agent_harness.py --mcp
```

#### 3. Cursor IDE (`~/.cursor/mcp.json`)
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

### 1. Static Analysis & Flow
```bash
# Triage binary security mitigations and high-complexity functions
rvs -f ./binary -c agent triage

# Decompile target validation function
rvs -f ./binary -c agent decompile sym.check_key

# Analyze decision gate conditions and branch targets
rvs -f ./binary -c agent flow sym.check_key
```

### 2. Dynamic Reverse Engineering (ESIL)
```bash
# Emulate execution for 50 steps with register preconditions
rvs -f ./crackme -c dynamic emulate sym.check_key --steps 50 --reg-set rdi=0x1337

# Trace loop decryption logging register diffs at each step
rvs -f ./crackme -c dynamic trace 0x1140 --steps 25
```

### 3. Native Interactive Debugging (ptrace UDS Daemon)
```bash
# Spawn binary under debug session
rvs debug spawn ./crackme

# Set breakpoint at decision gate
rvs debug bp <SESSION_ID> set 0x1180

# Continue execution until breakpoint
rvs debug continue <SESSION_ID>

# Inspect registers and memory
rvs debug regs <SESSION_ID>
rvs debug mem <SESSION_ID> 0x4020 --len 32

# Terminate session and reap process
rvs debug kill <SESSION_ID>
```

### 4. Live Dynamic Instrumentation (r2frida)
```bash
# Verify Frida environment
rvs frida env-check

# List loaded modules in target PID
rvs frida modules 1234 --limit 30 -c

# Trace function arguments
rvs frida hook 1234 0x1140 --signature "void(int, char*)"

# Intercept and force return value
rvs frida hook-return 1234 0x1140 1
```

### 5. Deterministic Binary Patching
```bash
# Invert conditional jump (dry-run simulation first)
rvs -f ./crackme agent patch-plan --plan '{"name":"bypass","dry_run":true,"steps":[{"type":"instruction","addr":"0x1180","assembly":"jmp 0x1195"}]}'

# Apply patch directly with automated backup
rvs -f ./crackme patch instruction --addr 0x1180 --assembly "jmp 0x1195" --backup
```

---

## Standardized Exit Code Taxonomy

All commands and MCP responses adhere to a standardized machine-readable exit code hierarchy:

| Exit Code | Identifier | Description | Remediation Action |
|:---:|:---|:---|:---|
| `0` | `SUCCESS` | Operation finished successfully. | None required. |
| `1` | `INVALID_ARGUMENT` | Malformed CLI arguments, invalid hex, bad syntax. | Verify `0x` hex prefixes and CPU instruction mnemonics. |
| `2` | `FILE_ERROR` | File not found, permission denied, zero-byte file. | Check file path and read/write permissions (`chmod +rx`). |
| `3` | `ANALYSIS_ERROR` | Symbol not found, disassembly failure, emulation fault. | Verify symbol names using `rvs_symbols` or entry addresses. |
| `4` | `PATCH_ERROR` | Assembly failed, string overflow, invalid patch bytes. | Shorten replacement string or verify instruction size. |
| `5` | `TIMEOUT_ERROR` | Operation exceeded deadline (`--timeout`). | Reduce `steps` budget or increase `--timeout 60`. |
| `6` | `INTERNAL_ERROR` | Driver crash, radare2 pipe error, unhandled I/O. | Check system dependencies (`r2`, `frida`) and daemon socket. |

---

## Testing & Verification

The suite is backed by **382 independent automated tests** passing at 100%:

```bash
# 1. Compile multi-arch and crackme C test binary fixtures
./tests/fixtures/compile_fixtures.sh

# 2. Execute Rust core tests (80/80 passed, 0 compiler/clippy warnings)
cargo test --lib --quiet
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run Python agent harness unit tests (64/64 passed)
python3 -m unittest tests/test_agent_harness.py

# 4. Run MCP tool schema compliance tests (15/15 passed)
python3 -m unittest tests/test_challenger_mcp_schemas.py

# 5. Run lean verification suite (5/5 passed)
python3 -m unittest tests/test_m3_lean_verification.py

# 6. Run skill documentation synchronization tests (16/16 passed)
python3 -m unittest tests/test_challenger_m4_skill_sync.py

# 7. Run crackme stress and adversarial tests (22/22 passed)
python3 -m unittest tests/test_challenger_m4_crackme_stress.py

# 8. Run dynamic RE tier test suites (180/180 passed)
python3 -m unittest tests/test_dynamic_tier1.py tests/test_dynamic_tier2.py
```

---

## License

This project is licensed under the GNU General Public License v3.0 ([GPL-3.0](LICENSE)).
