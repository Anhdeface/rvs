# rvs: High-Performance Binary Analysis, Dynamic RE, Debugging & Instrumentation Engine

[![Version](https://img.shields.io/badge/version-v0.4.2-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-2021_edition-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)
[![MCP](https://img.shields.io/badge/protocol-MCP_Compliant-purple.svg)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/license-GPL--3.0-green.svg)](LICENSE)

`rvs` (Reverse Visual Static/Dynamic Engine) is a systems-level binary analysis, instruction-level dynamic emulation, native interactive debugging, live runtime instrumentation (`r2frida`), Android APK reverse engineering, and deterministic binary patching engine. It is engineered as high-throughput, machine-readable infrastructure for autonomous AI coding agents (Google Antigravity, Claude Code, Cursor, Gemini CLI) and security researchers.

---

## Quick Installation

### 1. Automated Setup
Clone the repository and run the automated installer:
```bash
git clone https://github.com/Anhdeface/rvs.git
cd rvs
./install.sh
```
The installer checks prerequisites, compiles the `rvs` binary, sets up shell symlinks (`~/.local/bin/rvs`), extracts MCP tool schemas, and registers the server with detected AI agent environments.

### 2. AI Agent MCP Configuration

#### Google Antigravity
The installer automatically configures `~/.gemini/config/mcp_config.json` and copies schemas. Manual entry:
```json
{
  "mcpServers": {
    "rvs": {
      "command": "python3",
      "args": ["/absolute/path/to/rvs/rvs_agent_harness.py", "--mcp"]
    }
  }
}
```

#### Claude Desktop & Claude Code CLI
```bash
claude mcp add rvs -- python3 /absolute/path/to/rvs/rvs_agent_harness.py --mcp
```

#### Cursor IDE (`~/.cursor/mcp.json` or project `.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "rvs": {
      "command": "python3",
      "args": ["/absolute/path/to/rvs/rvs_agent_harness.py", "--mcp"]
    }
  }
}
```

#### OpenCode (`~/.config/opencode/opencode.json`)
```json
{
  "mcp": {
    "servers": {
      "rvs": {
        "command": "python3",
        "args": ["/absolute/path/to/rvs/rvs_agent_harness.py", "--mcp"]
      }
    }
  }
}
```

---

## Supported Tooling Catalog (50 Canonical Tools)

The engine provides 50 canonical tools accessible via MCP JSON-RPC 2.0 stdio and the `rvs` CLI:

### 1. Reconnaissance & Static Metadata (4 tools)
| Tool Name | Parameters | Description | CLI Equivalent |
|:---|:---|:---|:---|
| `rvs_info` | `file, compact` | Extract binary format, architecture, bitness, and security mitigations (PIE, Canary, NX, RELRO). | `rvs -f <file> info` |
| `rvs_strings` | `file, min_len, filter, limit, compact` | Extract printable strings with byte offsets. | `rvs -f <file> strings` |
| `rvs_symbols` | `file, filter, limit, compact` | Resolve imported, exported, and internal symbols. | `rvs -f <file> symbols` |
| `rvs_agent_triage` | `file, compact` | Profile binary and rank functions by cyclomatic complexity. | `rvs -f <file> agent triage` |

### 2. Static Flow & Decompilation (5 tools)
| Tool Name | Parameters | Description | CLI Equivalent |
|:---|:---|:---|:---|
| `rvs_functions` | `file, filter, limit, compact` | Enumerate function offsets, sizes, and complexity. | `rvs -f <file> analyze functions` |
| `rvs_disasm` | `file, target, max_instructions, compact` | Disassemble function blocks or address ranges. | `rvs -f <file> analyze blocks <target>` |
| `rvs_decompile` | `file, function, compact` | Decompile target function into annotated pseudo-C. | `rvs -f <file> agent decompile <func>` |
| `rvs_flow` | `file, function, compact` | Analyze decision gates, branch conditions, and jump targets. | `rvs -f <file> agent flow <func>` |
| `rvs_xrefs` | `file, target, direction, compact` | Trace cross-references to/from symbols, addresses, or strings. | `rvs -f <file> agent xrefs <target>` |

### 3. Dynamic Analysis & ESIL Emulation (3 tools)
| Tool Name | Parameters | Description | CLI Equivalent |
|:---|:---|:---|:---|
| `rvs_dynamic_emulate` | `file, target, steps, until, reg_set, read_mem, mem_len, compact` | User-space VM emulation capturing registers, stop reasons, and memory buffers. | `rvs -f <file> dynamic emulate <target>` |
| `rvs_dynamic_trace` | `file, target, steps, reg_set, compact` | Instruction execution trace emitting modified register diffs. | `rvs -f <file> dynamic trace <target>` |
| `rvs_dynamic_step` | `file, target, count, reg_set, compact` | Single-step N instructions advancing the program counter. | `rvs -f <file> dynamic step <target>` |

### 4. Native Interactive Debugging (ptrace) (9 tools)
| Tool Name | Parameters | Description | CLI Equivalent |
|:---|:---|:---|:---|
| `rvs_debug_spawn` | `file, args, stdin, no_aslr, compact` | Spawn executable under managed debugger session. | `rvs dynamic debug spawn <file>` |
| `rvs_debug_attach` | `file, pid, compact` | Attach debugger to running process by PID. | `rvs dynamic debug attach <pid>` |
| `rvs_debug_continue` | `file, session, until, compact` | Continue execution until breakpoint or termination. | `rvs dynamic debug continue <session>` |
| `rvs_debug_step` | `file, session, step_type, count, compact` | Single-step N native instructions under debugger. | `rvs dynamic debug step <session>` |
| `rvs_debug_breakpoint` | `file, session, action, addr, hw, compact` | Set, list, or clear software/hardware breakpoints. | `rvs dynamic debug bp <session> <action>` |
| `rvs_debug_registers` | `file, session, reg_set, diff, compact` | Read or mutate architectural CPU registers. | `rvs dynamic debug registers <session>` |
| `rvs_debug_memory` | `file, session, action, addr, len, data, compact` | Read or write raw memory bytes in live process space. | `rvs dynamic debug memory <session> <addr>` |
| `rvs_debug_kill` | `file, session, compact` | Terminate debuggee process and release resources. | `rvs dynamic debug kill <session>` |
| `rvs_debug_sessions` | `compact` | List active debugger sessions. | `rvs dynamic debug list-sessions` |

### 5. Live Runtime Instrumentation (r2frida) (15 tools)
| Tool Name | Parameters | Description | CLI Equivalent |
|:---|:---|:---|:---|
| `rvs_frida_env_check` | `compact` | Verify r2frida installation and host capabilities. | `rvs frida env-check` |
| `rvs_frida_attach` | `target, package, device, timeout, compact` | Attach Frida to process by PID, name, or URI. | `rvs frida attach <target>` |
| `rvs_frida_spawn` | `path, package, args, device, timeout, compact` | Spawn executable under dynamic Frida instrumentation. | `rvs frida spawn <path>` |
| `rvs_frida_modules` | `target, filter, limit, offset, compact` | Enumerate loaded shared libraries and memory bases. | `rvs frida modules -t <target>` |
| `rvs_frida_symbols` | `target, module, filter, limit, offset, compact` | Enumerate exported symbols in target process/module. | `rvs frida symbols -t <target>` |
| `rvs_frida_classes` | `target, filter, limit, offset, compact` | Enumerate Objective-C, Swift, or Java classes in memory. | `rvs frida classes -t <target>` |
| `rvs_frida_hook` | `target, addr, format, compact` | Hook function entry/exit to log parameters and return. | `rvs frida hook -t <target> -A <addr>` |
| `rvs_frida_trace_regs` | `target, addr, regs, compact` | Trace CPU register values at function entry/exit. | `rvs frida trace-regs -t <target> -A <addr> -r <regs>` |
| `rvs_frida_hook_return` | `target, addr, retval, compact` | Dynamically intercept and force function return values. | `rvs frida hook-return -t <target> -A <addr> --retval <val>` |
| `rvs_frida_hooks_list` | `target, compact` | List all active dynamic hooks. | `rvs frida hooks-list -t <target>` |
| `rvs_frida_hook_remove` | `target, id, compact` | Remove active dynamic hook by ID. | `rvs frida hook-remove -t <target> --id <id>` |
| `rvs_frida_script` | `target, code, script_file, timeout, compact` | Inject and evaluate custom JavaScript snippet or file. | `rvs frida script -t <target> --code <code>` |
| `rvs_frida_rpc` | `target, method, args, timeout, compact` | Invoke exported Frida RPC method (`rpc.exports`). | `rvs frida rpc -t <target> -m <method>` |
| `rvs_frida_mem_read` | `target, addr, len, compact` | Read raw bytes from live process memory. | `rvs frida mem-read -t <target> -A <addr>` |
| `rvs_frida_mem_write` | `target, addr, data, protect, compact` | Live patch memory bytes in running process. | `rvs frida mem-write -t <target> -A <addr> -d <data>` |

### 6. Binary Patching & Composite Agent Workflows (8 tools)
| Tool Name | Parameters | Description | CLI Equivalent |
|:---|:---|:---|:---|
| `rvs_patch_instruction` | `file, addr, assembly, nop_bytes, backup` | Patch assembly instruction or write NOP sled with backup. | `rvs -f <file> patch instruction --addr <addr> --assembly <asm>` |
| `rvs_patch_string` | `file, new_string, addr, backup` | Overwrite string literal with overflow protection. | `rvs -f <file> patch string --addr <addr> --new <str>` |
| `rvs_patch_bytes` | `file, addr, hex_bytes, backup` | Write raw hex bytes at specified binary offset. | `rvs -f <file> patch bytes --addr <addr> --hex <hex>` |
| `rvs_agent_patch_plan` | `file, plan, dry_run` | Execute multi-step patch plan with dry-run verification. | `rvs -f <file> agent patch-plan --plan <plan>` |
| `rvs_triage_crash` | `file, args, timeout, compact` | Autonomous crash triage, fault address, and registers. | *(composite workflow)* |
| `rvs_bypass_decision_gate` | `file, gate_addr, timeout, compact` | Analyze gate and synthesize bypass patch. | *(composite workflow)* |
| `rvs_dump_decrypted_buffer` | `file, function, buffer_addr, buffer_len, compact` | Dump decrypted memory buffer at runtime breakpoint. | *(composite workflow)* |
| `rvs_detect_anti_debug` | `file, compact` | Detect ptrace anti-debugging and anti-analysis gates. | *(composite workflow)* |

### 7. Android APK & Multi-Language Analysis (6 tools)
| Tool Name | Parameters | Description | CLI Equivalent |
|:---|:---|:---|:---|
| `rvs_apk_info` | `file, compact` | Package metadata, manifest summary, DEX/SO inventory, multi-language detection. | `rvs apk inspect <file>` |
| `rvs_apk_manifest` | `file, compact` | Permissions, activities, services, receivers, SDK bounds, debuggable flag. | `rvs apk manifest <file>` |
| `rvs_apk_dex` | `file, dex_file, class, method, disasm, decompile, compact` | Dalvik DEX analysis, method disassembly, Smali formatting, pseudo-Java decompilation. | `rvs apk dex <file>` |
| `rvs_apk_native` | `file, abi, library, symbol, xrefs, compact` | Native `.so` libraries, JNI exports, dynamic `RegisterNatives`, cross-references. | `rvs apk so <file>` |
| `rvs_apk_resources` | `file, type, name, dump, compact` | Inspect and dump resources, ARSC string tables, layouts, assets. | `rvs apk resources <file>` |
| `rvs_apk_signature` | `file, verify, compact` | Extract and verify v1 JAR signatures, v2/v3 signing blocks, X.509 certs. | `rvs apk signature <file>` |

---

## Practical CLI Usage Guide

### 1. Native Binary Analysis
```bash
# General triage of binary mitigations and complexity
rvs -f ./crackme -c agent triage

# Decompile key validation routine
rvs -f ./crackme -c agent decompile sym.validate_key

# Trace decision gate branching
rvs -f ./crackme -c agent flow sym.validate_key

# Emulate execution with ESIL VM
rvs -f ./crackme -c dynamic emulate sym.validate_key --steps 50 --reg rdi=0x1337

# Apply instruction patch with automated backup (.bak)
rvs -f ./crackme patch instruction --addr 0x1180 --assembly "jmp 0x1195" --backup
```

### 2. Android APK Analysis
```bash
# Package overview & multi-language detection (Java, C/C++, Flutter, React Native)
rvs apk inspect app.apk -c

# Unpack APK into structured directory (manifest, resources, smali, assets, lib)
rvs apk unpack app.apk --output ./unpacked_app
rvs apk unpack app.apk -o ./unpacked_app --force
rvs apk unpack app.apk -o ./unpacked_app --no-java

# Extract permissions, components, and SDK limits from AndroidManifest.xml
rvs apk manifest app.apk -c

# Search classes, disassemble Dalvik bytecode, and format Smali
rvs apk dex app.apk --class "MainActivity" --disasm --smali -c

# Analyze native libraries and JNI entry points for arm64-v8a
rvs apk so app.apk --abi arm64-v8a --xrefs -c

# List resources and extract specific assets
rvs apk resources app.apk --list
rvs apk resources app.apk --extract "assets/app_config.json"

# Verify APK signing block and certificate fingerprints
rvs apk signature app.apk --verify -c
```

### 3. Native Debugging & Live Instrumentation
```bash
# Spawn binary under managed ptrace debugger
rvs dynamic debug spawn ./crackme
rvs dynamic debug bp <SESSION_ID> 0x1180 --action add
rvs dynamic debug continue <SESSION_ID>
rvs dynamic debug registers <SESSION_ID>
rvs dynamic debug kill <SESSION_ID>

# Live Frida hook on running process
rvs frida hook -t 1234 -A 0x1140 --format "iz"
rvs frida hook-return -t 1234 -A 0x1140 --retval 1
```

---

## Exit Code Taxonomy

All commands and MCP responses adhere to a deterministic machine-readable exit hierarchy:

| Exit Code | Identifier | Meaning | Remediation Action |
|:---:|:---|:---|:---|
| `0` | `SUCCESS` | Operation finished successfully. | None required. |
| `1` | `INVALID_ARGUMENT` | Malformed CLI arguments, invalid hex syntax, or missing arguments. | Verify `0x` hex prefixes, instruction syntax, or required flags. |
| `2` | `FILE_ERROR` | File not found, permission denied, or zero-byte target. | Check file path and filesystem permissions (`chmod +rx`). |
| `3` | `ANALYSIS_ERROR` | Symbol not found, disassembly failure, or emulation fault. | Verify symbol names with `rvs_symbols` or valid code offsets. |
| `4` | `PATCH_ERROR` | Assembly error, string length overflow, or patch verification failure. | Check replacement length against original or instruction size. |
| `5` | `TIMEOUT_ERROR` | Execution exceeded specified timeout deadline. | Reduce instruction count / step budget or increase `--timeout`. |
| `6` | `INTERNAL_ERROR` | Subprocess pipe error, crash, or driver fault. | Check system dependencies (`r2`, `frida`) and host capabilities. |

---

## License

This project is licensed under the GNU General Public License v3.0 ([GPL-3.0](LICENSE)).
