---
name: rvs-reverse-engineering
description: Autonomous binary reverse engineering, ESIL dynamic emulation, execution tracing, control-flow gate analysis, and deterministic binary patching using rvs and its MCP agent harness.
compatibility: Antigravity CLI, Claude Code, Google Gemini CLI, GitHub Copilot CLI, Cursor
version: 2.0.0
---

# `rvs` Autonomous Reverse Engineering Agent Skill

This skill guides AI agents (Antigravity CLI, Claude Code, Gemini CLI, Copilot CLI) in performing end-to-end static and dynamic reverse engineering, control flow analysis, instruction-level tracing, and binary patching using `rvs` via Model Context Protocol (MCP) or direct CLI.

---

## 🧠 Core Mental Model

`rvs` provides a deterministic, token-optimized abstraction over `radare2`. Unlike raw RE tools which emit verbose terminal streams, `rvs` guarantees:
1. **Zero Terminal Pollution**: Stripped ANSI codes, `TERM=dumb`, isolated subcommands.
2. **Deterministic Response Envelopes**: Structured JSON (`ApiResponseDict`) with 7-level standardized exit codes (`0` = Success, `1` = Invalid Arg, `2` = File Error, `3` = Analysis/Emu Error, `4` = Patch Error, `5` = Timeout, `6` = Internal Error).
3. **Adaptive Token Compression**: Compact mode eliminates 60%–90% of redundant JSON fields while retaining critical register diffs, disassembly opcodes, and control-flow edges.
4. **Safe Dynamic Analysis (ESIL)**: Emulates instructions, tracks register deltas, and inspects memory without requiring root, OS ptrace permissions, or executing foreign binary code natively.

---

## 🔄 5-Phase Reverse Engineering Operational Playbook

```
┌────────────────────────────────────────────────────────┐
│  Phase 1: Reconnaissance & Triage                      │
│  rvs_agent_triage ──> rvs_info ──> rvs_strings         │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 2: Static Flow & Decompilation                  │
│  rvs_functions ──> rvs_flow ──> rvs_decompile          │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 3: Dynamic Emulation & Tracing (ESIL)           │
│  rvs_dynamic_emulate ──> rvs_dynamic_trace ──> step    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 4: Patch Strategy & Dry-Run Simulation          │
│  rvs_agent_patch_plan (dry_run=True)                   │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  Phase 5: Patch Application & Dynamic Verification     │
│  rvs_agent_patch_plan (dry_run=False) ──> rvs_emulate  │
└────────────────────────────────────────────────────────┘
```

### Phase 1: Reconnaissance & Triage
Always begin by establishing the binary profile:
1. **Run `rvs_agent_triage`** first.
   - Extracts architecture, bitness, endianness, and security mitigations (PIE, Canary, NX, RELRO, stripped).
   - Identifies candidate functions ranked by cyclomatic complexity.
   - Scans for high-interest strings (passwords, URLs, auth tokens, success/failure banners).
2. **Targeted String Search**: If looking for specific banners or flags:
   - Call `rvs_strings(file=..., min_len=5, filter="...")` to avoid massive string dumps.
3. **Cross-Reference String to Code**:
   - Call `rvs_xrefs(file=..., target="<string_addr_or_flag>")` to identify the exact functions and call sites referencing the string.

### Phase 2: Static Analysis & Control-Flow Exploration
1. **Locate Target Function**:
   - Use `rvs_functions(file=..., filter="check")` to narrow down auth or validation routines.
2. **Decompile Logic**:
   - Use `rvs_decompile(file=..., function="<name_or_addr>")` to inspect the high-level C pseudocode representation.
3. **Identify Decision Gates & Conditional Branches**:
   - Use `rvs_flow(file=..., function="<name_or_addr>")`.
   - Returns all decision nodes (`cmp`, `test`), condition instructions, branch types (`je`, `jne`, `jz`), jump targets (taken), and fail targets (fallthrough).
   - Identifies loop back-edges.

### Phase 3: Dynamic Reverse Engineering & ESIL Emulation
Use dynamic emulation to verify how the binary behaves under specific inputs without executing unsafe binaries:
1. **Emulate Function with Custom Inputs**:
   - Tool: `rvs_dynamic_emulate`
   - Preset registers using `reg_set`: e.g. `reg_set=["rdi=0x1000", "rax=0x42"]`.
   - Set execution step budget: `steps=100` (prevents infinite loops in obfuscated code).
   - Set break/until address: `until="0x11f4"` to stop exactly at a key decision gate.
   - Inspect memory: `read_mem="0x4020"`, `mem_len=16` to observe decryptor buffers.
   - **Key Return Data**:
     - `diff`: Only the registers that changed during emulation (e.g. `rax`, `rip`, `rflags`).
     - `ret`: Architecture return register (`RAX`/`EAX` on x86, `R0`/`X0` on ARM).
     - `stop`: `until_reached` or `step_limit_completed`.
2. **Instruction-Level Tracing**:
   - Tool: `rvs_dynamic_trace`
   - Steps through the instruction sequence step-by-step (e.g. `steps=20`).
   - Yields an array of `{ step, addr, asm, diff }`.
   - Reveals loop counters, decryption math, or key XOR schedules.
3. **Single Stepping**:
   - Tool: `rvs_dynamic_step`
   - Executes 1 (or N) instruction(s) from target address to check flag setting (e.g., zero flag `ZF` after a `test eax, eax`).

### Phase 4: Patch Strategy & Dry-Run Simulation
1. **Formulate Patch Plan**:
   - Use `rvs_agent_patch_plan` with `dry_run=True`.
   - Define steps:
     - Invert conditional branch: change `je 0x11f5` to `jne 0x11f5` or `jmp 0x11f5`.
     - NOP sled: replace check logic with `type="nop"`, `count=N`.
     - Force return value: patch `mov eax, 1; ret`.
   - Dry-run inspects the exact original bytes and proposed replacement bytes without altering the binary on disk.

### Phase 5: Patch Application & Verification
1. **Apply Patch**:
   - Run `rvs_agent_patch_plan` with `dry_run=False` (automatically generates `.bak` backup).
2. **Verify Execution**:
   - Run `rvs_dynamic_emulate` on the patched binary to confirm that the execution path now reaches the success node or returns the desired status register.

---

## ⚡ Token Optimization & Budget Conservation Guidelines

As an AI agent, conserving context tokens is critical. Follow these mandatory heuristics:

| Rule | Action | Impact |
|------|--------|--------|
| **1. Default to Compact** | Keep `compact=True` (default in all tools). | **60%–90% token reduction** |
| **2. Scoped Queries** | Never run unfiltered `rvs_strings` or `rvs_symbols` without `filter` or `limit`. | Prevents dumping 10k+ rows |
| **3. Step Budgets** | Set `steps` on `dynamic_emulate` (default 50-100) and `dynamic_trace` (default 15-30). | Prevents runaway trace output |
| **4. Leverage Register Diffs** | Read `data.diff` instead of full register dumps; 95% of registers remain unchanged. | Massive token savings |
| **5. Session Awareness** | Subsequent commands on the same binary reuse cached architecture/bitness automatically. | Instant execution |

---

## 🛠️ Complete MCP Tool Catalog

### 1. Reconnaissance & Metadata
- **`rvs_info`**: Basic format, architecture, bitness, entry point, security flags.
  - `file` (str, req), `compact` (bool, default: True).
- **`rvs_strings`**: Extract ASCII/UTF strings.
  - `file` (str, req), `min_len` (int, default: 4), `filter` (str, opt), `limit` (int, opt), `compact` (bool).
- **`rvs_symbols`**: Enumerate exported/imported symbols and PLT functions.
  - `file` (str, req), `filter` (str, opt), `limit` (int, opt), `compact` (bool).
- **`rvs_agent_triage`**: Complete autonomous reconnaissance and top complex functions.
  - `file` (str, req), `compact` (bool, default: True).

### 2. Static Analysis & Flow
- **`rvs_functions`**: List functions with offsets, sizes, cyclomatic complexity.
  - `file` (str, req), `filter` (str, opt), `detail` (bool), `limit` (int), `compact` (bool).
- **`rvs_disasm`**: Basic blocks & instruction disassembly.
  - `file` (str, req), `target` (str, req), `disasm` (bool, default: True), `max_instructions` (int), `compact` (bool).
- **`rvs_decompile`**: Pseudo-C decompilation with string refs and calls.
  - `file` (str, req), `function` (str, req), `compact` (bool).
- **`rvs_flow`**: Decision gate nodes, condition/branch instructions, and jump/fail targets.
  - `file` (str, req), `function` (str, req), `compact` (bool).
- **`rvs_xrefs`**: Cross-references to/from symbol, address, or string.
  - `file` (str, req), `target` (str, req), `direction` ("all"|"to"|"from"), `kind` (str, opt), `compact` (bool).
- **`rvs_graph`**: Call graph or function CFG.
  - `file` (str, req), `target` (str, opt), `graph_type` ("callgraph"|"cfg"), `compact` (bool).
- **`rvs_prologue_epilogue`**: Function frame boundaries and stack adjustments.
  - `file` (str, req), `target` (str, opt), `compact` (bool).

### 3. Dynamic Analysis & Emulation (ESIL)
- **`rvs_dynamic_emulate`**: Safe ESIL function/address emulation with register diffs and memory checks.
  - `file` (str, req), `target` (str, req - func or hex addr), `steps` (int, default: 100), `until` (str, opt - stop hex addr), `reg_set` (list[str], opt - e.g. `["rax=1", "rdi=0x1000"]`), `read_mem` (str, opt), `mem_len` (int, default: 32), `compact` (bool).
- **`rvs_dynamic_trace`**: Instruction execution trace with register deltas at each step.
  - `file` (str, req), `target` (str, req), `steps` (int, default: 20, max: 100), `reg_set` (list[str], opt), `compact` (bool).
- **`rvs_dynamic_step`**: Single-step (or N-step) execution advancing program counter.
  - `file` (str, req), `target` (str, req), `count` (int, default: 1), `reg_set` (list[str], opt), `compact` (bool).

### 4. Binary Patching & Mutation
- **`rvs_patch_instruction`**: Patch assembly instruction or write NOP sled.
  - `file` (str, req), `addr` (str, req), `assembly` (str, opt), `nop_bytes` (int, opt), `backup` (bool, default: True).
- **`rvs_patch_string`**: Overwrite ASCII string literal with boundary overflow protection.
  - `file` (str, req), `new_string` (str, req), `addr` (str, opt), `old_string` (str, opt), `pad_null` (bool), `strict_length` (bool), `backup` (bool).
- **`rvs_patch_bytes`**: Write raw hex bytes at specified address.
  - `file` (str, req), `addr` (str, req), `hex_bytes` (str, req), `backup` (bool).
- **`rvs_agent_patch_plan`**: Multi-step patch plan with dry-run simulation.
  - `file` (str, req), `plan` (dict, req), `dry_run` (bool, default: False).

---

## 🚨 Troubleshooting & Actionable Error Handling

| Error Code | Meaning | Agent Action |
|------------|---------|--------------|
| `INVALID_ARGUMENT` (1) | Bad parameter or unparseable value | Verify hex address prefix (`0x`), ensure assembly mnemonic is valid architecture syntax. |
| `FILE_ERROR` (2) | Target binary missing or unreadable | Check absolute file path, verify permissions (`chmod +r` / `chmod +w`). |
| `ANALYSIS_ERROR` (3) | Emulation or flow failure | Function symbol not found or address not in executable section. Use `rvs_symbols` or `rvs_info` to find valid code addresses. |
| `PATCH_ERROR` (4) | Assembly failed or string overflow | Shorten replacement string or disable `strict_length`. Verify instruction operands match CPU bitness (e.g. `eax` vs `rax`). |
| `TIMEOUT_ERROR` (5) | Subprocess exceeded deadline | Lower `steps` budget on emulation or pass `timeout=60.0`. |

---

## 💡 Quick Recipes

### Recipe 1: Crackme / License Key Reverse Engineering
```python
# 1. Triage binary
rvs_agent_triage(file="crackme")

# 2. Look for validation strings
rvs_strings(file="crackme", filter="license")

# 3. Find xref to the string
rvs_xrefs(file="crackme", target="0x2004")

# 4. Analyze decision gates in the check function
rvs_flow(file="crackme", function="sym.check_key")

# 5. Emulate with sample input to observe branch outcome
rvs_dynamic_emulate(file="crackme", target="sym.check_key", steps=50, reg_set=["rax=0x1234"])

# 6. Formulate patch to invert branch gate
rvs_agent_patch_plan(file="crackme", plan={
    "name": "bypass_license_check",
    "dry_run": False,
    "steps": [{"type": "instruction", "addr": "0x1146", "assembly": "jmp 0x1180"}]
})
```

### Recipe 2: Algorithm Decryption Tracing
```python
# Trace execution inside decryption loop for 25 steps
rvs_dynamic_trace(file="malware_sample", target="0x1400", steps=25)

# Inspect memory buffer after 100 emulation steps
rvs_dynamic_emulate(file="malware_sample", target="0x1400", steps=100, read_mem="0x4080", mem_len=32)
```
