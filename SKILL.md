---
name: rvs-reverse-engineering
description: Autonomous binary reverse engineering, ESIL dynamic emulation, execution tracing, control-flow gate analysis, and deterministic binary patching using rvs and its MCP agent harness.
compatibility: Antigravity CLI, Claude Code, Google Gemini CLI, GitHub Copilot CLI, Cursor
version: 2.1.0
---

# `rvs` Autonomous Reverse Engineering Agent Skill

This skill guides AI agents (Antigravity CLI, Claude Code, Gemini CLI, Copilot CLI) in performing end-to-end static, dynamic, interactive debugging, runtime instrumentation (Frida), and binary patching workflows using `rvs` via Model Context Protocol (MCP) or the Python agent harness.

---

## 🧠 Core Mental Model & Operational Principles

`rvs` provides a deterministic, token-optimized, agent-native abstraction over `radare2` and dynamic instrumentation engines. Unlike raw RE utilities that flood context windows with uncontrollable terminal streams, `rvs` enforces five core invariants:

1. **Zero Terminal Pollution & Subprocess Isolation**:
   - Every subprocess invocation runs under strict environment isolation: `TERM=dumb`, `NO_COLOR=1`, `CLICOLOR=0`, `R2_NOPLUGINS=1`, and `RADARE2_RCFILE=/dev/null`.
   - All ANSI escape sequences, terminal cursor movements, and control sequences are stripped before responses reach LLM context.
2. **Deterministic Standardized Response Envelopes**:
   - Responses adhere strictly to structured JSON (`ApiResponseDict`):
     ```json
     {
       "success": true,
       "command": "disasm",
       "target": "crackme",
       "timestamp": "2026-09-13T11:00:00Z",
       "data": { ... },
       "warnings": [],
       "error": null
     }
     ```
   - Errors populate an actionable `ApiErrorDict` containing standard exit codes, categories, root-cause messages, and suggested remediation steps.
3. **Adaptive Token Compression (70%–90% Reduction)**:
   - Compact mode (`-c` CLI flag or `compact=True` in harness/MCP) aggressively strips redundant offsets, repetitive opcode metadata, and static registers.
   - Traces emit only **register diffs** (modified registers) rather than full architectural register snapshots.
   - High-volume endpoints enforce strict pagination defaults (symbols: 50, classes: 50, modules: 30) with explicit `--limit` and `--offset`.
4. **Multi-Tier Execution Safety**:
   - **Tier 1 (Static)**: Zero code execution. Safe metadata extraction, CFG parsing, and decompilation.
   - **Tier 2 (ESIL Emulation)**: CPU instruction emulation in user memory. Safely simulates loops and decryptors without OS process execution or root privileges.
   - **Tier 3 (Dynamic Debugging)**: State-isolated ptrace debugging managed by a persistent Unix Domain Socket (UDS) daemon (`/run/user/<uid>/rvs/rvs-debug.sock`).
   - **Tier 4 (Live Instrumentation)**: In-process Frida runtime inspection and JavaScript hooking via `r2frida`.
5. **Atomic Patching & Safe Recovery**:
   - Binary modifications automatically create timestamped `.bak` backups.
   - Multi-step patch plans support `dry_run=True` simulation to verify instruction encoding and byte offsets before modifying disk.

---

## 🔄 6-Phase Reverse Engineering Operational Playbook

```
┌────────────────────────────────────────────────────────┐
│  Phase 1: Static Reconnaissance & Triage               │
│  rvs_agent_triage ──> rvs_info ──> rvs_strings/symbols │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 2: Static Flow, Disasm & Decompilation          │
│  rvs_functions ──> rvs_flow ──> rvs_decompile          │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 3: Dynamic Emulation & ESIL Tracing             │
│  rvs_dynamic_emulate ──> rvs_dynamic_trace ──> step    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 4: Interactive Dynamic Debugging (UDS Daemon)   │
│  rvs_debug_spawn ──> rvs_debug_breakpoint ──> continue │
│  ──> rvs_debug_registers (diff/edit) ──> step          │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 5: Live Instrumentation (Frida) & Workflows     │
│  rvs_frida_hook ──> rvs_bypass_decision_gate           │
│  rvs_dump_decrypted_buffer ──> rvs_detect_anti_debug   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 6: Binary Patching & Verification               │
│  rvs_patch_instruction ──> rvs_agent_patch_plan        │
│  ──> Verify via rvs_dynamic_emulate or rvs_debug_spawn │
└────────────────────────────────────────────────────────┘
```

### Phase 1: Static Reconnaissance & Triage
1. **Initial Profile**: Call `rvs_agent_triage(file=...)` to automatically extract format, architecture, bitness, security mitigations (PIE, Canary, NX, RELRO, stripped), top complex functions, and interesting strings.
2. **Targeted Search**: Query strings with `rvs_strings(file=..., filter="...", min_len=4)` and symbols with `rvs_symbols(file=..., filter="...", limit=50)`.
3. **Cross-References**: Use `rvs_xrefs(file=..., target="<string_or_symbol_addr>")` to map callers and reference points.

### Phase 2: Static Flow & Decompilation
1. **Control Flow Graph**: Call `rvs_flow(file=..., function="<name_or_addr>")` to identify decision gates, condition/branch instructions (`cmp`, `test`, `je`, `jne`), jump targets, and fallthrough addresses.
2. **Decompilation**: Call `rvs_decompile(file=..., function="<name_or_addr>")` to read high-level pseudo-C logic and variable structures.
3. **Disassembly**: Call `rvs_disasm(file=..., target="<addr>", max_instructions=50)` to inspect exact opcode bytes and operands.

### Phase 3: Dynamic Emulation & ESIL Tracing
1. **Safe Emulation**: Call `rvs_dynamic_emulate(file=..., target="<func_or_addr>", steps=100, until="<stop_addr>", reg_set=["rdi=1"])` to simulate execution without native execution.
2. **Instruction Tracing**: Call `rvs_dynamic_trace(file=..., target="<addr>", steps=20)` to capture instruction-by-instruction register deltas inside loops or decryptors.
3. **Single Stepping**: Call `rvs_dynamic_step(file=..., target="<addr>", count=1)` to step and evaluate CPU condition flags (e.g. `ZF`).

### Phase 4: Interactive Dynamic Debugging (UDS Daemon)
1. **Spawn / Attach**: Call `rvs_debug_spawn(file=..., args=[...], no_aslr=True)` or `rvs_debug_attach(file=..., pid=...)`. Obtains a persistent `session` ID.
2. **Breakpoints**: Add breakpoints with `rvs_debug_breakpoint(file=..., session=..., action="add", addr="0x401146")`.
3. **Run to Gate**: Call `rvs_debug_continue(file=..., session=..., until="0x401146")`. Inspect halt event and stopping IP.
4. **Register Diffs & Modification**:
   - Inspect changes: `rvs_debug_registers(file=..., session=..., diff=True)`.
   - Invert decision flags: `rvs_debug_registers(file=..., session=..., reg_set=["rflags=0x246", "rax=1"])`.
5. **Step & Memory**: Call `rvs_debug_step(file=..., session=...)` and inspect memory with `rvs_debug_memory(file=..., session=..., action="read", addr="0x404060", len=64)`.
6. **Clean Termination**: Always call `rvs_debug_kill(file=..., session=...)` to clean up debug sessions and avoid orphan processes. Check active sessions anytime with `rvs_debug_sessions()`.

### Phase 5: Live Runtime Instrumentation via Frida (`r2frida`) & Composite Workflows
1. **Environment Verification**: Call `rvs_frida_env_check()` to verify Frida core and r2frida plugin readiness.
2. **Process Attachment**: Call `rvs_frida_attach(target="<pid_or_name>")` or `rvs_frida_spawn(path="<binary_path>")`. Note: Frida tools require `target`, NOT a mandatory `file` parameter!
3. **Inspection & Interception**:
   - Enumerate modules: `rvs_frida_modules(target=..., limit=30)`.
   - Enumerate symbols: `rvs_frida_symbols(target=..., module="libc.so.6", filter="open", limit=50)`.
   - Intercept calls: `rvs_frida_hook(target=..., addr="0x401200", format="x")`.
   - Dynamic return override: `rvs_frida_hook_return(target=..., addr="sym.check_license", retval="0x1")`.
   - Script injection: `rvs_frida_script(target=..., code="Interceptor.attach(...)")`.
4. **Autonomous Composite Workflows**:
   - `rvs_triage_crash(file=..., args=[...])`: Automatically diagnoses segfaults, signal 11/FPE, NULL pointer dereferences, faulting RIP, and register state.
   - `rvs_bypass_decision_gate(file=..., gate_addr="...")`: Identifies branch instructions, calculates opposite branch opcode, and tests gate bypass.
   - `rvs_dump_decrypted_buffer(file=...)`: Breaks after decryption loops and extracts plaintext buffers directly from live process memory.
   - `rvs_detect_anti_debug(file=...)`: Detects `ptrace(PTRACE_TRACEME)`, `/proc/self/status` `TracerPid` checks, and generates tailored Frida bypass scripts.

### Phase 6: Binary Patching & Verification
1. **Dry-Run Validation**: Validate patches with `rvs_agent_patch_plan(file=..., plan={...}, dry_run=True)`.
2. **Apply Patch**:
   - Invert branch: `rvs_patch_instruction(file=..., addr="0x40117a", assembly="je 0x401183")`.
   - NOP sled: `rvs_patch_instruction(file=..., addr="0x40117a", nop_bytes=6)`.
   - String overwrite: `rvs_patch_string(file=..., new_string="Access Granted", old_string="Access Denied")`.
   - Raw bytes: `rvs_patch_bytes(file=..., addr="0x40117a", hex_bytes="9090909090")`.
3. **Verification**: Verify patched executable behavior using `rvs_dynamic_emulate` or `rvs_debug_spawn`.

---

## ⚡ Token Conservation Directives

AI agent context windows are finite. Conformance with these directives is mandatory:

| Directive | Specification | Impact |
|---|---|---|
| **1. Always Use Compact Mode** | Ensure `compact=True` (or `-c` CLI flag). Enabled by default across all 44 tools. | **70%–90% token reduction** |
| **2. Enforce Endpoint Pagination** | Large endpoints enforce strict pagination defaults: `symbols` (default: 50), `classes` (default: 50), `modules` (default: 30). Use `limit` and `offset`. | Eliminates 10k+ line JSON dumps |
| **3. Prefer Register Diffs** | Read `register_diff` / `data.diff` instead of full architectural dumps. Unchanged registers are excluded. | Eliminates 95% redundant register tokens |
| **4. Strict Trace Step Budgets** | Restrict `rvs_dynamic_trace` to 15–30 steps and `rvs_dynamic_emulate` to 50–100 steps. Use `until` to halt at specific gates. | Prevents runaway trace dumps |
| **5. Stripped Terminal Formatting** | Environment isolation enforces `TERM=dumb` and strips all ANSI codes. Never pipe through unstripped terminal wrappers. | Eliminates terminal pollution |
| **6. Parameterless Tool Calling** | Parameterless tools (`rvs_debug_sessions`, `rvs_frida_env_check`) accept empty arguments `{}` or omitted parameters. | Avoids redundant parameter overhead |

---

## 🚨 Standardized Exit Code Taxonomy

All commands and MCP tools map runtime results to standard exit codes (0–6):

| Exit Code | Identifier | Category | Meaning | Actionable Agent Recovery Strategy |
|:---:|---|---|---|---|
| **0** | `SUCCESS` | Execution | Operation completed successfully. | Proceed to next operational phase. |
| **1** | `INVALID_ARGUMENT` | Validation | Malformed input, invalid hex address prefix, unsupported enum value, or negative step count. | Ensure hex addresses use `0x` prefix (e.g. `0x401140`). Verify assembly syntax matches target CPU architecture. |
| **2** | `FILE_ERROR` | Filesystem | Target binary missing, unreadable, inaccessible, or target process PID non-existent. | Verify absolute file path and permissions (`chmod +rx`). Confirm target PID is active using `ps aux`. |
| **3** | `ANALYSIS_ERROR` | Analysis / RE | Emulation engine failed, function symbol not found, address not in executable section, or gate instruction unrecognized. | Run `rvs_functions` or `rvs_symbols` to verify function names. Confirm address falls within executable sections (`.text`). |
| **4** | `PATCH_ERROR` | Mutation | Assembly instruction failed to assemble, replacement string exceeds original length under `strict_length=True`, or byte length mismatch. | Shorten replacement string or disable `strict_length`. Verify assembly instruction size matches original opcode space (or pad with NOPs). |
| **5** | `TIMEOUT_ERROR` | Watchdog | Subprocess execution exceeded configured deadline (default: 30s). | Increase timeout parameter or decrease `steps` budget on emulation/tracing. Scope down function target. |
| **6** | `INTERNAL_ERROR` | System | Radare2 crash, UDS socket daemon failure, or unexpected OS signal. | Check UDS daemon status with `rvs dynamic debug daemon --status`. Kill dangling sessions with `rvs_debug_kill`. |

---

## 🛠️ Complete 44-Tool Canonical MCP Catalog

### Phase 1: Static Reconnaissance & Triage
*Initial binary profiling, architecture classification, security mitigations, symbols, strings, and automated triage.*

#### `rvs_info`
Inspect binary file metadata, architecture, bitness, endianness, OS, entry point, sections, and security mitigations (canary, NX, PIE, RELRO, stripped).

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_functions`
List analyzed functions in the binary with memory offsets, sizes, signatures, and cyclomatic complexity.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `filter` (`string`, optional): Optional substring or regex filter on function name (e.g. 'main', 'sym.imp').
- `detail` (`boolean`, optional): Include full details (stack frame size, local variables, argument counts). Defaults to false.
- `limit` (`integer`, optional): Maximum number of functions to return (for token budget management).
- `offset` (`integer`, optional): Pagination offset index into the function list.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_disasm`
Extract basic blocks and disassembled machine instructions for a specific function or address, including jump/fail control flow targets.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `target` (`string`, **required**): Function name (e.g. 'main', 'sym.check_key') or virtual memory address (e.g. '0x11e0').
- `disasm` (`boolean`, optional): Include disassembled instructions inside each basic block. Defaults to true.
- `max_instructions` (`integer`, optional): Maximum number of instructions to disassemble (truncation limit).
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_decompile`
Generate high-level pseudo-C decompilation for a function, along with call graph targets, referenced strings, and structural metrics.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `function` (`string`, **required**): Target function name (e.g. 'main') or virtual address (e.g. '0x11e0').
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_flow`
Analyze control flow decision gates, condition/branch instructions (e.g. jz, jne, cmp), jump/fail targets, and loop back-edges for a function.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `function` (`string`, **required**): Target function name or virtual memory address.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_xrefs`
Extract cross-references (callers, callees, code references, data references, string references) to and/or from a symbol or address.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `target` (`string`, **required**): Target symbol name, function name, string address, or memory address (e.g. 'sym.imp.puts', 'main', '0x2004').
- `direction` (`string`, optional): Reference direction: 'all' (bidirectional), 'to' (incoming references/callers), 'from' (outgoing callees/data refs). Defaults to 'all'. (allowed: `['all', 'to', 'from']`)
- `kind` (`string`, optional): Optional filter by reference kind. (allowed: `['call', 'code', 'data', 'string', 'read', 'write']`)
- `limit` (`integer`, optional): Maximum number of cross-references to return.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_strings`
Extract ASCII and UTF-8 strings from binary data and text sections with virtual memory addresses.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `min_len` (`integer`, optional): Minimum string character length. Defaults to 4.
- `filter` (`string`, optional): Optional substring filter to match specific strings (e.g. 'flag', 'pass', 'key').
- `limit` (`integer`, optional): Maximum number of strings to return.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_symbols`
List binary symbols, PLT imports, exported symbols, bindings, and virtual addresses.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `filter` (`string`, optional): Optional substring filter on symbol names.
- `limit` (`integer`, optional): Maximum number of symbols to return. Defaults to 50.
- `offset` (`integer`, optional): Starting index offset for pagination. Defaults to 0.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_agent_triage`
Perform full autonomous binary reconnaissance: security mitigations, top complex functions, interesting strings, and actionable RE next steps.

**Parameters:**
- `file` (`string`, **required**): Path to the binary file to triage.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

---

### Phase 2: Dynamic Emulation & ESIL Tracing
*Safe user-space CPU instruction emulation via radare2 ESIL without executing native code or requiring root privileges.*

#### `rvs_dynamic_emulate`
Safely emulate binary execution via radare2 ESIL (Evaluable Strings Intermediate Language). Emulates function logic, steps until target address, traces register deltas, and inspects memory changes without OS execution permissions.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `target` (`string`, **required**): Function name (e.g. 'main', 'sym.check_key') or virtual memory address (e.g. '0x11e0').
- `steps` (`integer`, optional): Maximum number of ESIL steps to emulate (defaults to 100).
- `until` (`string`, optional): Stop emulation when instruction pointer reaches this virtual address (hex or symbol).
- `reg_set` (`array`, optional): Preset CPU registers before emulation (e.g. ['rax=1', 'rdi=0x1000']).
- `read_mem` (`string`, optional): Memory address to inspect before and after emulation.
- `mem_len` (`integer`, optional): Number of memory bytes to inspect (default: 32).
- `compact` (`boolean`, optional): Emit token-optimized compact output with register diffs. Defaults to true.

#### `rvs_dynamic_trace`
Instruction-by-instruction dynamic execution trace recording opcodes and register deltas. Ideal for cryptanalytic loops, key checking, and decryptors.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `target` (`string`, **required**): Function name or start virtual address.
- `steps` (`integer`, optional): Number of instruction steps to trace (default: 20, max: 100).
- `reg_set` (`array`, optional): Preset CPU registers before trace (e.g. ['rax=0x42']).
- `compact` (`boolean`, optional): Emit token-optimized compact trace. Defaults to true.

#### `rvs_dynamic_step`
Single-step (or small N-step) execution advancing the instruction pointer and reporting register changes.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `target` (`string`, **required**): Function name or virtual address.
- `count` (`integer`, optional): Number of instructions to step (default: 1).
- `reg_set` (`array`, optional): Preset registers before step.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

---

### Phase 3: Interactive Dynamic Debugging (UDS Daemon)
*Live process debugging via native ptrace daemon over Unix Domain Socket with persistent sessions, breakpoints, stepping, and memory/register modification.*

#### `rvs_debug_spawn`
Spawn target executable under native ptrace debugger with ASLR control and stdin injection. Returns session ID for subsequent debug operations.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `args` (`array`, optional): Command line arguments passed to the debugged process.
- `stdin` (`string`, optional): String or file path to feed into target stdin.
- `no_aslr` (`boolean`, optional): Disable ASLR for reproducible memory addresses. Defaults to true.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_attach`
Attach native ptrace debugger to an existing running process by PID. Returns session ID.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable (for symbol resolution).
- `pid` (`integer`, **required**): Process ID to attach to.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_continue`
Continue debugged process execution until breakpoint hit, signal, or process exit. Returns halt event with register state.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `session` (`string`, optional): Debug session ID (uses most recent if omitted).
- `until` (`string`, optional): Continue until reaching this address or symbol (e.g. '0x1146', 'main+42').
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_step`
Single-step or step-over instructions in the debugged process. Returns register diff after stepping.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `session` (`string`, optional): Debug session ID (uses most recent if omitted).
- `step_type` (`string`, optional): Step type: 'instruction' (single step), 'over' (step over calls), 'out' (run to return), 'line' (step source line). Defaults to 'instruction'. (allowed: `['instruction', 'over', 'out', 'line']`)
- `count` (`integer`, optional): Number of steps to execute. Defaults to 1.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_breakpoint`
Manage software and hardware breakpoints: add, remove, list, or clear breakpoints in the debug session.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `session` (`string`, optional): Debug session ID (uses most recent if omitted).
- `action` (`string`, optional): Breakpoint action. Defaults to 'list'. (allowed: `['add', 'remove', 'list', 'clear']`)
- `addr` (`string`, optional): Target address or symbol for add/remove (e.g. '0x1146', 'main', 'entry0+4').
- `hw` (`boolean`, optional): Use hardware breakpoint (DR0-DR3) instead of software INT3.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_registers`
Inspect or modify CPU registers in the debug session. Supports register diffs to track changes across halts.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `session` (`string`, optional): Debug session ID (uses most recent if omitted).
- `reg_set` (`array`, optional): Modify registers (format: 'reg=val', e.g. ['rax=0x1337', 'rdi=0']).
- `diff` (`boolean`, optional): Return only registers that changed since previous halt.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_memory`
Inspect virtual memory maps, read or write live process memory in the debug session.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `session` (`string`, optional): Debug session ID (uses most recent if omitted).
- `action` (`string`, optional): Memory action: 'maps' (list memory regions), 'read' (read bytes), 'write' (write bytes). Defaults to 'read'. (allowed: `['maps', 'read', 'write']`)
- `addr` (`string`, optional): Target memory address or symbol.
- `len` (`integer`, optional): Number of bytes to read. Defaults to 32.
- `data` (`string`, optional): Hexadecimal byte string to write (for 'write' action, e.g. '90909090').
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_kill`
Terminate a debug session and kill or detach from the debugged process.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `session` (`string`, optional): Debug session ID to terminate.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_debug_sessions`
List all active native debug sessions with their PIDs, states, and session IDs.

**Parameters:**
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

---

### Phase 4: Live Runtime Instrumentation via Frida (r2frida)
*Dynamic runtime instrumentation, function hooking, argument tracing, return value replacement, and JavaScript injection via r2frida.*

#### `rvs_frida_env_check`
Check r2frida plugin installation status and runtime capabilities.

**Parameters:**
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_attach`
Attach r2frida to a running process by PID, process name, or full Frida URI for live dynamic instrumentation.

**Parameters:**
- `target` (`string`, **required**): Target PID (e.g. '1234'), process name (e.g. 'firefox'), or frida URI.
- `device` (`string`, optional): Device type: 'local', 'usb', or remote 'IP:port'. Defaults to 'local'.
- `timeout` (`integer`, optional): Timeout in seconds for attach operation.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_spawn`
Spawn a new target executable under r2frida dynamic instrumentation with optional arguments.

**Parameters:**
- `path` (`string`, **required**): Path to the executable to spawn under Frida.
- `args` (`array`, optional): Command line arguments for the spawned process.
- `device` (`string`, optional): Device type: 'local', 'usb', or remote. Defaults to 'local'.
- `timeout` (`integer`, optional): Timeout in seconds for spawn operation.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_modules`
List loaded modules and shared libraries in target process memory space via r2frida (:il).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `filter` (`string`, optional): Filter module names by substring.
- `limit` (`integer`, optional): Maximum number of modules to return. Defaults to 30.
- `offset` (`integer`, optional): Starting index offset for pagination. Defaults to 0.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_symbols`
Enumerate symbols, exports, and functions in target process or specific module via r2frida (:is).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `module` (`string`, optional): Specific module to inspect (e.g. 'libc.so.6').
- `filter` (`string`, optional): Filter symbol names by substring.
- `limit` (`integer`, optional): Maximum number of symbols to return. Defaults to 50.
- `offset` (`integer`, optional): Starting index offset for pagination. Defaults to 0.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_classes`
Enumerate Objective-C, Swift, or Java classes in target process via r2frida (:ic).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `filter` (`string`, optional): Filter class names by substring.
- `limit` (`integer`, optional): Maximum number of classes to return. Defaults to 50.
- `offset` (`integer`, optional): Starting index offset for pagination. Defaults to 0.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_hook`
Register a dynamic function hook to trace arguments and inspect execution at a target address via r2frida (:dtf).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `addr` (`string`, **required**): Target function address or symbol name to hook.
- `format` (`string`, optional): Argument format specifier (e.g. 'i' int, 'x' hex, 'z' string, 'h' hexdump).
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_trace_regs`
Trace CPU register values at function entry/exit via r2frida (:dtr).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `addr` (`string`, **required**): Target function address or symbol name.
- `regs` (`string`, **required**): Comma-separated register names to trace (e.g. 'rax,rdi,rsi').
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_hook_return`
Install return value replacement hook on target function to override its return value dynamically.

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `addr` (`string`, **required**): Target function address or symbol name.
- `retval` (`string`, **required**): Replacement return value in hex or decimal (e.g. '0x1', '0').
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_hooks_list`
List all currently active hooks registered in the target process via r2frida (:dtj).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_hook_remove`
Remove a registered dynamic hook by its ID from the target process (:dt-).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `id` (`string`, **required**): Hook identifier to remove.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_script`
Inject and evaluate custom JavaScript snippet or load external script file via r2frida (:eval / :.).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `code` (`string`, optional): JavaScript code snippet to evaluate inline (mutually exclusive with script_file).
- `script_file` (`string`, optional): Path to external JavaScript file to load (mutually exclusive with code).
- `timeout` (`integer`, optional): Execution timeout in seconds for script evaluation.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_rpc`
Invoke an exported Frida RPC method (rpc.exports.<method>) on the target process.

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `method` (`string`, **required**): Exported RPC method name to invoke.
- `args` (`string`, optional): Arguments as JSON array string or comma-separated values.
- `timeout` (`integer`, optional): Execution timeout in seconds.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_mem_read`
Read raw memory bytes from live target process memory space via r2frida (:x).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `addr` (`string`, **required**): Virtual memory address (hex string or symbol).
- `len` (`integer`, optional): Number of bytes to read. Defaults to 32.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_frida_mem_write`
Write and patch raw memory bytes directly in live target process memory space via r2frida (:w).

**Parameters:**
- `target` (`string`, **required**): Target PID, process name, or frida URI.
- `addr` (`string`, **required**): Virtual memory address (hex string or symbol).
- `data` (`string`, **required**): Hexadecimal byte string to write (e.g. '9090' or '31c0c3').
- `protect` (`boolean`, optional): Ensure memory page is writable before writing. Defaults to true.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

---

### Phase 5: High-Level Composite Triage & Dynamic Workflows
*Automated multi-turn reverse engineering workflows for crash triage, decision gate bypassing, decryptor payload dumping, and anti-debug detection.*

#### `rvs_triage_crash`
Automated dynamic crash triaging and root-cause classification (SIGSEGV, NULL deref, etc.).

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `args` (`array`, optional): Optional command line arguments to trigger crash.
- `timeout` (`number`, optional): Execution timeout in seconds. Defaults to 5.0.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_bypass_decision_gate`
Control-flow analysis and dynamic bypass workflow for authentication/decision gates.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `gate_addr` (`string`, **required**): Gate function name or memory address to bypass.
- `timeout` (`number`, optional): Execution timeout in seconds. Defaults to 10.0.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_dump_decrypted_buffer`
Dynamic decryptor buffer dump workflow: breaks after decryption loop and extracts memory plaintext.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `function` (`string`, optional): Optional decryption function name.
- `buffer_addr` (`string`, optional): Optional virtual memory address of the decrypted buffer.
- `buffer_len` (`integer`, optional): Number of bytes to dump. Defaults to 64.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

#### `rvs_detect_anti_debug`
Static and dynamic anti-debugging detection workflow with tailored Frida bypass generation.

**Parameters:**
- `file` (`string`, **required**): Path to the target binary executable.
- `compact` (`boolean`, optional): Emit token-optimized compact output. Defaults to true.

---

### Phase 6: Binary Patching & Verification
*Deterministic binary modification with automatic backup creation, dry-run validation, instruction rewriting, string patching, and raw byte editing.*

#### `rvs_patch_instruction`
Assemble and patch an assembly instruction or insert a NOP sled at a target memory address or symbol offset with automatic backup.

**Parameters:**
- `file` (`string`, **required**): Path to the binary file to modify.
- `addr` (`string`, **required**): Target memory address (e.g. '0x13d2') or symbol+offset (e.g. 'main+242').
- `assembly` (`string`, optional): Assembly instruction text to assemble and write (e.g. 'mov eax, 1', 'jmp 0x1400').
- `nop_bytes` (`integer`, optional): Number of NOP bytes (0x90) to write (mutually exclusive with assembly).
- `backup` (`boolean`, optional): Create a timestamped .bak backup file before modifying. Defaults to true.

#### `rvs_patch_string`
Patch or overwrite a string literal in the binary data/rodata section by memory address or old text search.

**Parameters:**
- `file` (`string`, **required**): Path to the binary file to modify.
- `new_string` (`string`, **required**): New replacement string text.
- `addr` (`string`, optional): Target memory address of the string (e.g. '0x2004').
- `old_string` (`string`, optional): Old string text to search and replace (used if addr is omitted).
- `pad_null` (`boolean`, optional): Zero-pad remaining bytes if new string is shorter than original. Defaults to true.
- `strict_length` (`boolean`, optional): Prevent writes exceeding original string length. Defaults to true.
- `backup` (`boolean`, optional): Create backup file before modifying. Defaults to true.

#### `rvs_patch_bytes`
Write raw hexadecimal byte sequence to a target memory address with write verification and backup.

**Parameters:**
- `file` (`string`, **required**): Path to the binary file to modify.
- `addr` (`string`, **required**): Target memory address in hex (e.g. '0x13d2') or symbol offset.
- `hex_bytes` (`string`, **required**): Hexadecimal byte string without spaces (e.g. 'e9a200000090' or '9090').
- `backup` (`boolean`, optional): Create backup file before modifying. Defaults to true.

#### `rvs_agent_patch_plan`
Validate, dry-run simulate, or atomically apply a multi-step patch plan to the target binary.

**Parameters:**
- `file` (`string`, **required**): Path to the binary file to patch.
- `plan` (`object`, **required**): Patch plan object specifying name, dry_run, and list of steps (instruction, bytes, nop, string).
- `dry_run` (`boolean`, optional): Override dry_run flag in the plan. Defaults to false.

---


---

## 💡 Practical Crackme Bypass Recipes & Workflows

### Recipe 1: Authentication & License Gate Bypass
**Goal**: Bypass a password/license validation check function (e.g. `sym.check_auth` or `check_master_password`).

```python
# 1. Autonomous Triage: find candidate check function
triage = rvs_agent_triage(file="auth_gate")

# 2. Control Flow Analysis: locate the exact branch decision gate
flow = rvs_flow(file="auth_gate", function="sym.check_auth")
# Returns decision node: e.g. addr "0x40117a", cond "test eax, eax", branch "jne 0x401183", fail "0x40117c"

# 3. Interactive Debugging: Spawn under debugger with ASLR disabled
spawn = rvs_debug_spawn(file="auth_gate", args=["invalid_password"], no_aslr=True)
sess = spawn["data"]["session_id"]

# 4. Set Breakpoint at the decision gate
rvs_debug_breakpoint(file="auth_gate", session=sess, action="add", addr="0x40117a")

# 5. Continue execution until the gate is reached
rvs_debug_continue(file="auth_gate", session=sess, until="0x40117a")

# 6. Invert Zero Flag (ZF) in rflags or set RAX=1 to force success branch
regs = rvs_debug_registers(file="auth_gate", session=sess, diff=True)
# Toggle ZF (bit 6) or force RAX
rvs_debug_registers(file="auth_gate", session=sess, reg_set=["rax=1", "rflags=0x246"])

# 7. Single step to verify the success path is taken
rvs_debug_step(file="auth_gate", session=sess, step_type="instruction", count=1)

# 8. Clean up debugger session
rvs_debug_kill(file="auth_gate", session=sess)

# 9. Permanent Binary Patch: Invert branch (or NOP out check)
# Either invert instruction:
rvs_patch_instruction(file="auth_gate", addr="0x40117a", assembly="je 0x401183")
# Or use the composite one-shot bypass workflow:
# rvs_bypass_decision_gate(file="auth_gate", gate_addr="sym.check_auth")
```

---

### Recipe 2: Encrypted String & Decryptor Buffer Dumping
**Goal**: Extract plaintext flag/string decrypted in memory by a routine before program exit.

```python
# Option A: One-Shot Composite Workflow
result = rvs_dump_decrypted_buffer(file="decryptor_target")
# Returns:
#   buffer: "FLAG{rvs_dynamic_decryptor_buffer_extracted_2026}"
#   buffer_addr: "0x404060"
#   hex: "464c41477b7276735f..."

# Option B: ESIL Emulation with Memory Inspection
# 1. Find decryption function and buffer address
funcs = rvs_functions(file="decryptor_target", filter="decrypt")
# 2. Emulate through the decryption loop and read memory
emu = rvs_dynamic_emulate(
    file="decryptor_target",
    target="sym.decrypt_payload",
    steps=150,
    read_mem="0x404060",
    mem_len=64
)
# Inspect emu["data"]["read_mem_hex"] or decoded ASCII text
```

---

### Recipe 3: Anti-Debugging Detection & Live Frida Neutralization
**Goal**: Detect anti-analysis protections (`ptrace`, `TracerPid`) and neutralize them dynamically.

```python
# 1. Detect anti-debugging mechanisms
detection = rvs_detect_anti_debug(file="antidebug_target")
# Returns:
#   anti_debug_detected: True
#   techniques: ["ptrace", "proc_status_tracerpid"]
#   details: {"ptrace_symbol": "imp.ptrace", "proc_status_string": "TracerPid:"}
#   bypass_hook: "// Frida script neutralizing ptrace and TracerPid..."

# 2. Spawn process under Frida and inject the bypass script
rvs_frida_spawn(path="antidebug_target")
rvs_frida_script(
    target="antidebug_target",
    code='''
    Interceptor.attach(Module.findExportByName(null, "ptrace"), {
        onEnter: function(args) {
            if (args[0].toInt32() === 0) { this.is_traceme = true; }
        },
        onLeave: function(retval) {
            if (this.is_traceme) { retval.replace(ptr(0)); }
        }
    });
    '''
)
```

---

### Recipe 4: Dynamic Crash Triage & Exception Root-Cause Analysis
**Goal**: Automatically diagnose an unexpected crash, segfault, or exception input.

```python
# Call composite crash triage workflow with crash-triggering input
crash_report = rvs_triage_crash(file="crash_target", args=["trigger_crash"])
# Returns:
#   crashed: True
#   signal: 11 (SIGSEGV)
#   cause: "NULL_POINTER_DEREFERENCE"
#   fault_addr: "0x0"
#   rip: "0x4011aa"
#   instruction: "mov dword [rax], 0xdeadbeef"
#   register_diff: [{"r": "rax", "a": "0x0"}, {"r": "rip", "a": "0x4011aa"}, ...]

# Immediate diagnosis: RAX was 0x0 when dereferenced by instruction 'mov dword [rax], ...'
```

---

## 🎯 Verification Checklist for Agents

Before completing any reverse engineering assignment:
1. **Schema Compliance**: Verify all tool calls use exact parameter names (`file` vs `target` vs `path`).
2. **Session Cleanup**: Ensure all debug sessions created with `rvs_debug_spawn` / `rvs_debug_attach` are terminated via `rvs_debug_kill`. Check with `rvs_debug_sessions()` (must show 0 active sessions).
3. **Backup Verification**: Ensure `.bak` files are created whenever modifying binaries.
4. **Token Budgeting**: Always pass `compact=True` (or omit to accept default `True`). Limit symbol and string queries.
