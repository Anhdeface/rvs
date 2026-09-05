#!/usr/bin/env python3
"""
rvs_agent_harness.py - Standard Python AI Agent CLI Harness & MCP Protocol Layer for `rvs`.

Provides:
1. Complete Subprocess Environment Isolation (TERM=dumb, NO_COLOR=1, R2_NOPLUGINS=1, RADARE2_RCFILE=/dev/null)
2. Process Watchdog with Timeout Management (Graceful SIGTERM -> SIGKILL)
3. Token-Optimized Response Filtering & Compaction Engine (compact, summary, full modes)
4. LLM Function Calling Schema Exporter (OpenAI, Anthropic, Gemini, MCP formats for 16 commands including Dynamic RE)
5. Native Model Context Protocol (MCP) Stdio JSON-RPC 2.0 Server
6. Ergonomic Typed Python API (`RvsHarness` & `RvsAgentHarness`) with Normalized Error Envelopes
7. Standardized 7-Level Exit Code Taxonomy & Actionable Error Suggestions
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, TypedDict, Union

# =============================================================================
# Constants & Exit Code Taxonomy
# =============================================================================

EXIT_SUCCESS: int = 0
EXIT_INVALID_ARGUMENT: int = 1
EXIT_FILE_ERROR: int = 2
EXIT_ANALYSIS_ERROR: int = 3
EXIT_PATCH_ERROR: int = 4
EXIT_TIMEOUT_ERROR: int = 5
EXIT_INTERNAL_ERROR: int = 6

DEFAULT_TIMEOUT_SECONDS: float = 30.0

MCP_PROTOCOL_VERSION: str = "2024-11-05"
SERVER_NAME: str = "rvs-mcp-server"
SERVER_VERSION: str = "0.2.0"

# Regex for stripping ANSI escape codes
ANSI_ESCAPE_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

OutputMode = Literal["compact", "summary", "full"]
SchemaFormat = Literal["openai", "anthropic", "gemini", "mcp"]


# =============================================================================
# Type Definitions & Response Envelopes
# =============================================================================

class ApiErrorDict(TypedDict, total=False):
    code: str
    message: str
    category: Optional[str]
    exit_code: Optional[int]
    details: Optional[Any]
    suggestion: Optional[str]


class ApiResponseDict(TypedDict, total=False):
    success: bool
    command: str
    target: str
    timestamp: Optional[str]
    format_version: Optional[str]
    summary: Optional[str]
    mode: Optional[str]
    data: Optional[Any]
    warnings: List[str]
    error: Optional[ApiErrorDict]
    execution_time_seconds: Optional[float]
    token_estimate: Optional[int]


# =============================================================================
# Environment & Subprocess Management
# =============================================================================

def find_rvs_binary(custom_path: Optional[Union[str, Path]] = None) -> Path:
    """Locate the `rvs` executable across custom path, environment, target builds, and PATH."""
    if custom_path:
        p = Path(custom_path)
        if p.exists() and os.access(p, os.X_OK):
            return p.resolve()

    # 1. Check RVS_BIN environment variable
    if "RVS_BIN" in os.environ:
        p = Path(os.environ["RVS_BIN"])
        if p.exists() and os.access(p, os.X_OK):
            return p.resolve()

    # 2. Check CARGO_BIN_EXE_rvs
    if "CARGO_BIN_EXE_rvs" in os.environ:
        p = Path(os.environ["CARGO_BIN_EXE_rvs"])
        if p.exists() and os.access(p, os.X_OK):
            return p.resolve()

    # 3. Check workspace target directory relative to this script or CWD
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "target" / "release" / "rvs",
        script_dir / "target" / "debug" / "rvs",
        Path.cwd() / "target" / "release" / "rvs",
        Path.cwd() / "target" / "debug" / "rvs",
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c.resolve()

    # 4. Check system PATH
    which_rvs = shutil.which("rvs")
    if which_rvs:
        return Path(which_rvs).resolve()

    # Default fallback
    return script_dir / "target" / "debug" / "rvs"


def sanitize_terminal_output(text: Union[str, bytes]) -> str:
    """Strips ANSI escape codes, terminal cursor controls, and unprintable characters."""
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    # Strip ANSI sequences
    cleaned = ANSI_ESCAPE_RE.sub("", text)
    # Strip control characters except standard whitespace (\n, \r, \t)
    sanitized = "".join(
        c for c in cleaned if c in ("\n", "\r", "\t") or (ord(c) >= 32 and ord(c) != 127)
    )
    return sanitized


def get_isolated_environment() -> Dict[str, str]:
    """Constructs a strictly sanitized subprocess environment."""
    env = dict(os.environ)
    env["TERM"] = "dumb"
    env["NO_COLOR"] = "1"
    env["R2_NOPLUGINS"] = "1"
    env["RADARE2_RCFILE"] = "/dev/null"
    env["R2_RCFILE"] = "/dev/null"
    env["CLICOLOR"] = "0"
    return env


def format_hex_addr(addr: Any) -> Optional[str]:
    """Formats an integer or hex string into canonical '0x...' hex format."""
    if addr is None:
        return None
    if isinstance(addr, int):
        return f"0x{addr:x}"
    if isinstance(addr, str):
        if addr.startswith("0x") or addr.startswith("0X"):
            return addr.lower()
        try:
            val = int(addr, 16 if any(c in "abcdefABCDEF" for c in addr) else 10)
            return f"0x{val:x}"
        except ValueError:
            return addr
    return str(addr)


def make_error_envelope(
    command_str: str,
    target_str: str,
    code: str,
    message: str,
    category: str = "EXECUTION_ERROR",
    exit_code: int = EXIT_INTERNAL_ERROR,
    suggestion: Optional[str] = None,
    details: Optional[Any] = None,
) -> ApiResponseDict:
    """Constructs a standard ApiResponse error envelope with actionable suggestions."""
    return {
        "success": False,
        "command": command_str,
        "target": target_str,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "data": None,
        "warnings": [],
        "error": {
            "code": code,
            "message": message,
            "category": category,
            "exit_code": exit_code,
            "details": details,
            "suggestion": suggestion,
        },
    }


def make_timeout_error_envelope(
    command_str: str,
    target_str: str,
    timeout_sec: float,
) -> ApiResponseDict:
    """Constructs a standard ApiResponse error envelope for timeouts."""
    return make_error_envelope(
        command_str=command_str,
        target_str=target_str,
        code="TIMEOUT_EXPIRED",
        message=f"Command timed out after {timeout_sec} seconds",
        category="TIMEOUT_ERROR",
        exit_code=EXIT_TIMEOUT_ERROR,
        suggestion="Increase timeout using --timeout flag or scope down target function/query.",
    )


def execute_rvs_subprocess(
    rvs_args: List[str],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    rvs_bin: Optional[Path] = None,
    cwd: Optional[Path] = None,
) -> Tuple[int, str, str, float]:
    """
    Executes `rvs` with timeout watchdog enforcement and strict environment isolation.
    Returns: (exit_code, sanitized_stdout, sanitized_stderr, execution_time_seconds)
    """
    if rvs_bin is None:
        rvs_bin = find_rvs_binary()

    cmd = [str(rvs_bin)] + rvs_args
    env = get_isolated_environment()
    start_time = time.time()

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=str(cwd) if cwd else None,
            text=True,
            errors="replace",
        )

        try:
            stdout_raw, stderr_raw = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Graceful termination first (SIGTERM)
            try:
                proc.terminate()
                stdout_raw, stderr_raw = proc.communicate(timeout=0.5)
            except (subprocess.TimeoutExpired, Exception):
                # Force kill if unresponsive (SIGKILL)
                try:
                    proc.kill()
                    stdout_raw, stderr_raw = proc.communicate(timeout=0.5)
                except Exception:
                    stdout_raw, stderr_raw = "", ""

            duration = time.time() - start_time
            stdout = sanitize_terminal_output(stdout_raw)
            stderr = sanitize_terminal_output(stderr_raw)
            return EXIT_TIMEOUT_ERROR, stdout, stderr, duration

        duration = time.time() - start_time
        stdout = sanitize_terminal_output(stdout_raw)
        stderr = sanitize_terminal_output(stderr_raw)
        return proc.returncode, stdout, stderr, duration

    except FileNotFoundError:
        duration = time.time() - start_time
        err_msg = f"rvs binary not found at '{rvs_bin}'"
        return EXIT_FILE_ERROR, "", err_msg, duration
    except Exception as e:
        duration = time.time() - start_time
        return EXIT_INTERNAL_ERROR, "", str(e), duration


# =============================================================================
# Token-Optimized Response Filtering & Compaction Engine (R1)
# =============================================================================

def prune_info(data: Dict[str, Any], mode: OutputMode) -> Dict[str, Any]:
    """Prune binary metadata according to selected mode."""
    if mode == "full":
        return data

    sec = data.get("security", {})
    sec_compact: Any
    if isinstance(sec, dict):
        sec_compact = [
            k for k, v in sec.items()
            if v is True or (isinstance(v, str) and v.lower() not in ("none", "false", "no"))
        ]
    else:
        sec_compact = sec

    entry_hex = data.get("entry_point_hex") or format_hex_addr(data.get("entry_point"))

    if mode == "summary":
        return {
            "format": f"{data.get('format')}-{data.get('arch')}-{data.get('bits')}",
            "entry": entry_hex,
            "security": sec_compact,
        }

    res: Dict[str, Any] = {
        "format": data.get("format"),
        "arch": data.get("arch"),
        "bits": data.get("bits"),
        "entry": entry_hex,
        "security": sec_compact,
    }
    if data.get("endian") and data.get("endian") != "little":
        res["endian"] = data.get("endian")
    if data.get("os") and data.get("os") != "linux":
        res["os"] = data.get("os")
    if data.get("sections_count") is not None:
        res["sections"] = data.get("sections_count")
    return res


def prune_functions(
    data: Dict[str, Any],
    mode: OutputMode,
    limit: Optional[int] = None,
    offset: int = 0,
) -> Dict[str, Any]:
    """Prune and paginate function list."""
    if mode == "full":
        return data

    funcs = data.get("functions", [])
    total = len(funcs)

    if mode == "summary":
        top = sorted(
            funcs,
            key=lambda f: (f.get("cyclomatic_complexity") or 0, f.get("size") or 0),
            reverse=True,
        )[:5]
        top_list = [
            {
                "name": f.get("name"),
                "addr": f.get("offset_hex") or format_hex_addr(f.get("offset")),
                "size": f.get("size"),
                "cc": f.get("cyclomatic_complexity"),
            }
            for f in top
        ]
        return {
            "total_functions": total,
            "total": total,
            "top_complex": top_list,
            "top": top_list,
        }

    try:
        effective_limit = int(limit) if limit is not None else 50
    except (ValueError, TypeError):
        effective_limit = 50
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0

    sliced = funcs[effective_offset : effective_offset + effective_limit]
    compact_funcs = []
    for f in sliced:
        item: Dict[str, Any] = {
            "name": f.get("name"),
            "addr": f.get("offset_hex") or format_hex_addr(f.get("offset")),
            "size": f.get("size"),
        }
        if f.get("cyclomatic_complexity") is not None:
            item["cc"] = f.get("cyclomatic_complexity")
        if f.get("num_basic_blocks") is not None:
            item["blocks"] = f.get("num_basic_blocks")
        if f.get("num_instructions") is not None:
            item["instrs"] = f.get("num_instructions")
        compact_funcs.append(item)

    is_truncated = (total > len(compact_funcs)) or effective_offset > 0 or limit is not None
    if not is_truncated and effective_offset == 0:
        return {
            "total": total,
            "functions": compact_funcs,
        }

    res: Dict[str, Any] = {
        "total": total,
        "displayed": len(compact_funcs),
        "remaining": max(0, total - (effective_offset + len(compact_funcs))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_funcs)),
        "has_more": total > (effective_offset + len(compact_funcs)),
        "functions": compact_funcs,
    }
    if total > (effective_offset + len(compact_funcs)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_funcs)} to retrieve next slice."
        )
    return res


def prune_blocks(
    data: Dict[str, Any],
    mode: OutputMode,
    limit: Optional[int] = None,
    offset: int = 0,
    max_instructions: Optional[int] = None,
) -> Dict[str, Any]:
    """Prune and paginate basic blocks and instructions."""
    if mode == "full":
        return data

    blocks = data.get("blocks", [])
    total = len(blocks)
    fn_name = data.get("function_name")
    fn_addr = data.get("function_addr_hex") or format_hex_addr(data.get("function_addr"))

    if mode == "summary":
        entry_b = blocks[0] if blocks else {}
        return {
            "function": fn_name,
            "addr": fn_addr,
            "total_blocks": total,
            "entry": entry_b.get("addr_hex") or format_hex_addr(entry_b.get("addr")),
        }

    try:
        effective_limit = int(limit) if limit is not None else 30
    except (ValueError, TypeError):
        effective_limit = 30
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0
    if max_instructions is not None:
        try:
            max_instructions = int(max_instructions)
        except (ValueError, TypeError):
            max_instructions = None

    sliced = blocks[effective_offset : effective_offset + effective_limit]
    compact_blocks = []

    for b in sliced:
        insts = b.get("instructions", [])
        if max_instructions is not None:
            insts = insts[:max_instructions]

        compact_insts = [
            {
                "addr": i.get("addr_hex") or format_hex_addr(i.get("addr")),
                "asm": i.get("disasm") or i.get("opcode") or i.get("asm"),
                "size": i.get("size"),
            }
            for i in insts
        ]

        b_dict: Dict[str, Any] = {
            "addr": b.get("addr_hex") or format_hex_addr(b.get("addr")),
            "size": b.get("size"),
            "instructions": compact_insts,
        }
        jump_addr = b.get("jump_hex") or format_hex_addr(b.get("jump"))
        fail_addr = b.get("fail_hex") or format_hex_addr(b.get("fail"))
        if jump_addr:
            b_dict["jump"] = jump_addr
        if fail_addr:
            b_dict["fail"] = fail_addr

        compact_blocks.append(b_dict)

    is_truncated = (total > len(compact_blocks)) or effective_offset > 0 or limit is not None
    if not is_truncated and effective_offset == 0:
        return {
            "function": fn_name,
            "addr": fn_addr,
            "total": total,
            "blocks": compact_blocks,
        }

    res: Dict[str, Any] = {
        "function": fn_name,
        "addr": fn_addr,
        "total": total,
        "displayed": len(compact_blocks),
        "remaining": max(0, total - (effective_offset + len(compact_blocks))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_blocks)),
        "has_more": total > (effective_offset + len(compact_blocks)),
        "blocks": compact_blocks,
    }
    if total > (effective_offset + len(compact_blocks)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_blocks)} to retrieve next slice."
        )
    return res


def prune_strings(
    data: Dict[str, Any],
    mode: OutputMode,
    limit: Optional[int] = None,
    offset: int = 0,
) -> Dict[str, Any]:
    """Prune and paginate string discovery tables."""
    if mode == "full":
        return data

    raw_strings = data.get("strings", [])
    total = len(raw_strings)

    if mode == "summary":
        return {
            "total": total,
            "sample": [s.get("string") for s in raw_strings[:10]],
        }

    try:
        effective_limit = int(limit) if limit is not None else 50
    except (ValueError, TypeError):
        effective_limit = 50
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0

    sliced = raw_strings[effective_offset : effective_offset + effective_limit]
    compact_strings = [
        {
            "addr": s.get("vaddr_hex") or format_hex_addr(s.get("vaddr")) or s.get("addr"),
            "string": s.get("string"),
        }
        for s in sliced
    ]

    is_truncated = (total > len(compact_strings)) or effective_offset > 0 or limit is not None
    if not is_truncated and effective_offset == 0:
        return {
            "total": total,
            "strings": compact_strings,
        }

    res: Dict[str, Any] = {
        "total": total,
        "displayed": len(compact_strings),
        "remaining": max(0, total - (effective_offset + len(compact_strings))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_strings)),
        "has_more": total > (effective_offset + len(compact_strings)),
        "strings": compact_strings,
    }
    if total > (effective_offset + len(compact_strings)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_strings)} to retrieve next slice."
        )
    return res


def prune_symbols(
    data: Dict[str, Any],
    mode: OutputMode,
    limit: Optional[int] = None,
    offset: int = 0,
) -> Dict[str, Any]:
    """Prune and paginate symbol tables."""
    if mode == "full":
        return data

    raw_symbols = data.get("symbols", [])
    total = len(raw_symbols)

    if mode == "summary":
        return {
            "total": total,
            "sample": [s.get("name") for s in raw_symbols[:10]],
        }

    try:
        effective_limit = int(limit) if limit is not None else 50
    except (ValueError, TypeError):
        effective_limit = 50
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0

    sliced = raw_symbols[effective_offset : effective_offset + effective_limit]
    compact_symbols = []
    for s in sliced:
        sym_dict: Dict[str, Any] = {
            "name": s.get("name"),
            "addr": s.get("vaddr_hex") or format_hex_addr(s.get("vaddr")) or s.get("addr"),
            "type": s.get("sym_type") or s.get("type"),
        }
        if s.get("bind"):
            sym_dict["bind"] = s.get("bind")
        compact_symbols.append(sym_dict)

    is_truncated = (total > len(compact_symbols)) or effective_offset > 0 or limit is not None
    if not is_truncated and effective_offset == 0:
        return {
            "total": total,
            "symbols": compact_symbols,
        }

    res: Dict[str, Any] = {
        "total": total,
        "displayed": len(compact_symbols),
        "remaining": max(0, total - (effective_offset + len(compact_symbols))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_symbols)),
        "has_more": total > (effective_offset + len(compact_symbols)),
        "symbols": compact_symbols,
    }
    if total > (effective_offset + len(compact_symbols)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_symbols)} to retrieve next slice."
        )
    return res


def prune_xrefs(
    data: Dict[str, Any],
    mode: OutputMode,
    limit: Optional[int] = None,
    offset: int = 0,
) -> Dict[str, Any]:
    """Prune and consolidate cross-reference lists."""
    if mode == "full":
        return data

    # Schema variant A: Agent xrefs format (callers, callees, data_refs)
    if "callers" in data or "callees" in data or "data_refs" in data:
        callers = [
            {
                "fn": c.get("function"),
                "at": c.get("call_site_hex") or format_hex_addr(c.get("call_site")),
            }
            for c in data.get("callers", [])
        ]
        callees = [
            {
                "fn": c.get("function"),
                "at": c.get("call_site_hex") or format_hex_addr(c.get("call_site")),
            }
            for c in data.get("callees", [])
        ]
        data_refs = [
            {
                "addr": d.get("addr_hex") or format_hex_addr(d.get("addr")),
                "type": d.get("ref_type"),
                "preview": d.get("value_preview"),
            }
            for d in data.get("data_refs", [])
        ]

        if mode == "summary":
            return {
                "target": data.get("target"),
                "callers_count": len(callers),
                "callees_count": len(callees),
                "data_refs_count": len(data_refs),
            }

        try:
            effective_limit = int(limit) if limit is not None else 30
        except (ValueError, TypeError):
            effective_limit = 30
        return {
            "target": data.get("target"),
            "addr": data.get("target_addr_hex") or format_hex_addr(data.get("target_addr")),
            "callers": callers[:effective_limit],
            "callees": callees[:effective_limit],
            "data_refs": data_refs[:effective_limit],
        }

    # Schema variant B: Core analyze xrefs format (xrefs, xrefs_to, xrefs_from)
    raw_xrefs = data.get("xrefs") or data.get("xrefs_to", []) + data.get("xrefs_from", [])
    total = len(raw_xrefs)

    if mode == "summary":
        return {
            "target": data.get("target"),
            "total": total,
            "direction": data.get("direction", "all"),
        }

    try:
        effective_limit = int(limit) if limit is not None else 30
    except (ValueError, TypeError):
        effective_limit = 30
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0

    sliced = raw_xrefs[effective_offset : effective_offset + effective_limit]
    compact_xrefs = []
    for x in sliced:
        compact_xrefs.append({
            "from": x.get("from_addr_hex") or format_hex_addr(x.get("from_addr")) or x.get("from"),
            "from_fn": x.get("from_function") or x.get("from_name"),
            "to": x.get("to_addr_hex") or format_hex_addr(x.get("to_addr")) or x.get("to"),
            "to_fn": x.get("to_function") or x.get("to_name"),
            "type": x.get("xref_type") or x.get("type"),
            "op": x.get("opcode"),
        })

    is_truncated = (total > len(compact_xrefs)) or effective_offset > 0 or limit is not None
    if not is_truncated and effective_offset == 0:
        return {
            "target": data.get("target"),
            "addr": data.get("target_addr_hex") or format_hex_addr(data.get("target_addr")),
            "total": total,
            "xrefs": compact_xrefs,
        }

    res: Dict[str, Any] = {
        "target": data.get("target"),
        "addr": data.get("target_addr_hex") or format_hex_addr(data.get("target_addr")),
        "total": total,
        "displayed": len(compact_xrefs),
        "remaining": max(0, total - (effective_offset + len(compact_xrefs))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_xrefs)),
        "has_more": total > (effective_offset + len(compact_xrefs)),
        "xrefs": compact_xrefs,
    }
    if total > (effective_offset + len(compact_xrefs)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_xrefs)} to retrieve next slice."
        )
    return res


def prune_flow(data: Dict[str, Any], mode: OutputMode) -> Dict[str, Any]:
    """Prune control-flow branch gates and loop structures."""
    if mode == "full":
        return data

    nodes = data.get("decision_nodes", [])
    fn_name = data.get("function_name")
    fn_addr = data.get("function_addr_hex") or format_hex_addr(data.get("function_addr"))

    if mode == "summary":
        return {
            "function": fn_name,
            "addr": fn_addr,
            "total_blocks": data.get("total_blocks"),
            "decision_gates_count": len(nodes),
            "loops": data.get("loop_count", 0),
        }

    compact_nodes = []
    for n in nodes:
        compact_nodes.append({
            "addr": n.get("addr_hex") or format_hex_addr(n.get("addr")),
            "cond": n.get("condition_instruction"),
            "branch": n.get("branch_instruction"),
            "jump": n.get("jump_target_hex") or format_hex_addr(n.get("jump_target")),
            "fail": n.get("fail_target_hex") or format_hex_addr(n.get("fail_target")),
            "type": n.get("gate_type"),
        })

    exits = [
        format_hex_addr(e) if isinstance(e, int) else str(e)
        for e in data.get("exit_nodes", [])
    ]

    return {
        "function": fn_name,
        "addr": fn_addr,
        "total_blocks": data.get("total_blocks"),
        "loops": data.get("loop_count", 0),
        "decision_nodes": compact_nodes,
        "exits": exits,
    }


def prune_decompile(
    data: Dict[str, Any],
    mode: OutputMode,
    max_lines: int = 120,
) -> Dict[str, Any]:
    """Prune pseudo-C decompilation output."""
    if mode == "full":
        return data

    fn_name = data.get("function_name")
    fn_addr = data.get("function_addr_hex") or format_hex_addr(data.get("function_addr"))

    if mode == "summary":
        return {
            "function": fn_name,
            "addr": fn_addr,
            "size": data.get("size"),
            "blocks": data.get("blocks_count"),
            "calls": data.get("calls", []),
            "strings": data.get("strings_referenced", []),
        }

    code = data.get("pseudo_c", "")
    lines = code.splitlines()
    truncated_code = code
    if len(lines) > max_lines:
        truncated_code = "\n".join(lines[:max_lines]) + f"\n// ... [{len(lines) - max_lines} lines truncated] ..."

    return {
        "function": fn_name,
        "addr": fn_addr,
        "size": data.get("size"),
        "blocks": data.get("blocks_count"),
        "calls": data.get("calls", []),
        "strings": data.get("strings_referenced", []),
        "pseudo_c": truncated_code,
    }


def prune_triage(data: Dict[str, Any], mode: OutputMode) -> Dict[str, Any]:
    """Prune high-level reconnaissance and triage summary."""
    if mode == "full":
        return data

    entry_hex = data.get("entry_point_hex") or format_hex_addr(data.get("entry_point"))
    sec = data.get("security", {})
    sec_compact = [
        k for k, v in (sec if isinstance(sec, dict) else {}).items()
        if v is True or (isinstance(v, str) and v.lower() not in ("none", "false", "no"))
    ]

    if mode == "summary":
        return {
            "format": f"{data.get('format')}-{data.get('arch')}-{data.get('bits')}",
            "entry": entry_hex,
            "security": sec_compact,
            "total_functions": data.get("total_functions"),
            "total_strings": data.get("total_strings"),
        }

    top_funcs = [
        {
            "name": f.get("name"),
            "addr": f.get("addr_hex") or format_hex_addr(f.get("addr")),
            "size": f.get("size"),
            "cc": f.get("complexity"),
            "blocks": f.get("num_blocks"),
        }
        for f in data.get("top_functions", [])[:5]
    ]

    return {
        "format": data.get("format"),
        "arch": data.get("arch"),
        "bits": data.get("bits"),
        "entry": entry_hex,
        "security": sec_compact,
        "total_functions": data.get("total_functions"),
        "total_strings": data.get("total_strings"),
        "top_functions": top_funcs,
        "interesting_strings": data.get("interesting_strings", []),
        "recommendations": data.get("recommendations", [])[:2],
    }


def prune_patch_result(data: Dict[str, Any], mode: OutputMode) -> Dict[str, Any]:
    """Prune patch operation and patch plan results."""
    if mode == "full":
        return data

    # Schema variant A: Single patch operation result
    if "original_bytes" in data or "patched_bytes" in data or "address_hex" in data or "address" in data:
        addr = data.get("address_hex") or format_hex_addr(data.get("address")) or data.get("addr")
        if mode == "summary":
            return {
                "addr": addr,
                "type": data.get("patch_type") or data.get("step_type"),
                "verified": data.get("verified", True),
            }

        res: Dict[str, Any] = {
            "addr": addr,
            "type": data.get("patch_type") or data.get("step_type"),
            "orig": data.get("original_bytes"),
            "new": data.get("patched_bytes"),
            "before": data.get("disasm_before"),
            "after": data.get("disasm_after"),
            "bytes": data.get("bytes_modified"),
            "verified": data.get("verified", True),
        }
        if data.get("backup_path"):
            res["backup"] = data.get("backup_path")
        return res

    # Schema variant B: Composite patch plan result
    if "step_results" in data:
        steps = [
            {
                "idx": s.get("step_index"),
                "type": s.get("step_type"),
                "addr": s.get("addr_hex") or format_hex_addr(s.get("addr")),
                "success": s.get("success"),
                "orig": s.get("original_bytes"),
                "new": s.get("patched_bytes"),
            }
            for s in data.get("step_results", [])
        ]
        return {
            "plan": data.get("plan_name"),
            "applied": data.get("applied"),
            "dry_run": data.get("dry_run"),
            "total_steps": data.get("total_steps"),
            "executed": data.get("steps_executed"),
            "backup": data.get("backup_path"),
            "steps": steps,
        }

    return data


def prune_emulate(data: Dict[str, Any], mode: OutputMode) -> Dict[str, Any]:
    """Prune dynamic emulation response."""
    if mode == "full":
        return data

    if mode == "summary":
        res: Dict[str, Any] = {
            "target": data.get("target") or data.get("function_name"),
            "start": data.get("start_addr_hex") or data.get("start"),
            "final": data.get("final_addr_hex") or data.get("final"),
            "steps": data.get("steps_executed") or data.get("steps"),
            "stop_reason": data.get("stop_reason") or data.get("stop"),
        }
        if data.get("return_value"):
            res["return_value"] = data.get("return_value")
        elif data.get("ret"):
            res["return_value"] = data.get("ret")
        if data.get("agent_summary"):
            res["summary"] = data.get("agent_summary")
        return res

    # Compact mode: preserve register diff, return value, stop reason, omit full reg dump
    res = {
        "target": data.get("target") or data.get("function_name"),
        "start": data.get("start_addr_hex") or data.get("start"),
        "final": data.get("final_addr_hex") or data.get("final"),
        "steps": data.get("steps_executed") or data.get("steps"),
        "stop": data.get("stop_reason") or data.get("stop"),
    }
    if data.get("return_value"):
        res["ret"] = data.get("return_value")
    elif data.get("ret"):
        res["ret"] = data.get("ret")

    diff = data.get("register_diff") or data.get("diff") or data.get("key_registers_changed") or []
    res["diff"] = diff

    if data.get("branches_encountered"):
        res["branches"] = data.get("branches_encountered")
    if data.get("agent_summary"):
        res["summary"] = data.get("agent_summary")
    if data.get("memory_after"):
        res["mem_after"] = data.get("memory_after")
    return res


def prune_trace(data: Dict[str, Any], mode: OutputMode, limit: Optional[int] = None) -> Dict[str, Any]:
    """Prune instruction-level trace response."""
    if mode == "full":
        return data

    steps = data.get("trace", [])
    total = len(steps)
    if mode == "summary":
        return {
            "target": data.get("target"),
            "start": data.get("start_addr_hex") or data.get("start"),
            "total_steps": total,
            "first_step": steps[0] if steps else None,
            "last_step": steps[-1] if steps else None,
        }

    try:
        effective_limit = int(limit) if limit is not None else 30
    except (ValueError, TypeError):
        effective_limit = 30
    compact_steps = []
    for s in steps[:effective_limit]:
        compact_steps.append({
            "step": s.get("step"),
            "addr": s.get("addr_hex") or s.get("addr"),
            "asm": s.get("disasm") or s.get("asm"),
            "diff": s.get("reg_changes") or s.get("diff") or [],
        })

    res: Dict[str, Any] = {
        "target": data.get("target"),
        "start": data.get("start_addr_hex") or data.get("start"),
        "total_steps": total,
        "displayed": len(compact_steps),
        "trace": compact_steps,
    }
    if total > len(compact_steps):
        res["truncated"] = True
        res["remaining"] = total - len(compact_steps)
    return res


def prune_step(data: Dict[str, Any], mode: OutputMode) -> Dict[str, Any]:
    """Prune single-step emulation response."""
    if mode == "full":
        return data

    return {
        "curr": data.get("curr") or data.get("current_addr_hex") or data.get("current_addr"),
        "next": data.get("next") or data.get("next_addr_hex") or data.get("next_addr"),
        "instruction": data.get("instruction") or data.get("asm"),
        "diff": data.get("diff") or data.get("reg_changes") or [],
    }


def transform_response(
    resp_envelope: Dict[str, Any],
    mode: OutputMode = "compact",
    limit: Optional[int] = None,
    offset: int = 0,
    max_lines: int = 120,
    max_instructions: Optional[int] = None,
) -> ApiResponseDict:
    """Applies pruning rules and budget truncation based on command type and selected mode."""
    if mode == "full" or not resp_envelope.get("success") or "data" not in resp_envelope:
        return resp_envelope  # type: ignore

    cmd = resp_envelope.get("command", "").lower()
    raw_data = resp_envelope.get("data")
    if not isinstance(raw_data, dict):
        return resp_envelope  # type: ignore

    transformed_data: Dict[str, Any]

    if "info" in cmd:
        transformed_data = prune_info(raw_data, mode)
    elif "functions" in cmd or "funcs" in cmd:
        transformed_data = prune_functions(raw_data, mode, limit=limit, offset=offset)
    elif "blocks" in cmd or "disasm" in cmd:
        transformed_data = prune_blocks(
            raw_data, mode, limit=limit, offset=offset, max_instructions=max_instructions
        )
    elif "strings" in cmd:
        transformed_data = prune_strings(raw_data, mode, limit=limit, offset=offset)
    elif "symbols" in cmd:
        transformed_data = prune_symbols(raw_data, mode, limit=limit, offset=offset)
    elif "flow" in cmd:
        transformed_data = prune_flow(raw_data, mode)
    elif "xrefs" in cmd:
        transformed_data = prune_xrefs(raw_data, mode, limit=limit, offset=offset)
    elif "decompile" in cmd:
        transformed_data = prune_decompile(raw_data, mode, max_lines=max_lines)
    elif "triage" in cmd:
        transformed_data = prune_triage(raw_data, mode)
    elif "patch" in cmd:
        transformed_data = prune_patch_result(raw_data, mode)
    elif "emulate" in cmd:
        transformed_data = prune_emulate(raw_data, mode)
    elif "trace" in cmd:
        transformed_data = prune_trace(raw_data, mode, limit=limit)
    elif "step" in cmd:
        transformed_data = prune_step(raw_data, mode)
    else:
        transformed_data = raw_data

    # Calculate token estimate heuristic (~4 characters per token)
    serialized = json.dumps(transformed_data)
    token_est = max(1, len(serialized) // 4)

    return {
        "success": True,
        "command": resp_envelope.get("command", ""),
        "target": resp_envelope.get("target", ""),
        "mode": mode,
        "data": transformed_data,
        "warnings": resp_envelope.get("warnings", []),
        "execution_time_seconds": resp_envelope.get("execution_time_seconds", 0.0),
        "token_estimate": token_est,
    }


# =============================================================================
# Canonical Tool Catalog & Schema Exporter (R2)
# =============================================================================

CANONICAL_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "rvs_info",
        "description": "Inspect binary file metadata, architecture, bitness, endianness, OS, entry point, sections, and security mitigations (canary, NX, PIE, RELRO, stripped).",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_functions",
        "description": "List analyzed functions in the binary with memory offsets, sizes, signatures, and cyclomatic complexity.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "filter": {
                "type": "string",
                "description": "Optional substring or regex filter on function name (e.g. 'main', 'sym.imp').",
            },
            "detail": {
                "type": "boolean",
                "description": "Include full details (stack frame size, local variables, argument counts). Defaults to false.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of functions to return (for token budget management).",
            },
            "offset": {
                "type": "integer",
                "description": "Pagination offset index into the function list.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_disasm",
        "description": "Extract basic blocks and disassembled machine instructions for a specific function or address, including jump/fail control flow targets.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "target": {
                "type": "string",
                "description": "Function name (e.g. 'main', 'sym.check_key') or virtual memory address (e.g. '0x11e0').",
            },
            "disasm": {
                "type": "boolean",
                "description": "Include disassembled instructions inside each basic block. Defaults to true.",
            },
            "max_instructions": {
                "type": "integer",
                "description": "Maximum number of instructions to disassemble (truncation limit).",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file", "target"],
    },
    {
        "name": "rvs_decompile",
        "description": "Generate high-level pseudo-C decompilation for a function, along with call graph targets, referenced strings, and structural metrics.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "function": {
                "type": "string",
                "description": "Target function name (e.g. 'main') or virtual address (e.g. '0x11e0').",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file", "function"],
    },
    {
        "name": "rvs_flow",
        "description": "Analyze control flow decision gates, condition/branch instructions (e.g. jz, jne, cmp), jump/fail targets, and loop back-edges for a function.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "function": {
                "type": "string",
                "description": "Target function name or virtual memory address.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file", "function"],
    },
    {
        "name": "rvs_xrefs",
        "description": "Extract cross-references (callers, callees, code references, data references, string references) to and/or from a symbol or address.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "target": {
                "type": "string",
                "description": "Target symbol name, function name, string address, or memory address (e.g. 'sym.imp.puts', 'main', '0x2004').",
            },
            "direction": {
                "type": "string",
                "enum": ["all", "to", "from"],
                "description": "Reference direction: 'all' (bidirectional), 'to' (incoming references/callers), 'from' (outgoing callees/data refs). Defaults to 'all'.",
            },
            "kind": {
                "type": "string",
                "enum": ["call", "code", "data", "string", "read", "write"],
                "description": "Optional filter by reference kind.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of cross-references to return.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file", "target"],
    },
    {
        "name": "rvs_strings",
        "description": "Extract ASCII and UTF-8 strings from binary data and text sections with virtual memory addresses.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "min_len": {
                "type": "integer",
                "description": "Minimum string character length. Defaults to 4.",
            },
            "filter": {
                "type": "string",
                "description": "Optional substring filter to match specific strings (e.g. 'flag', 'pass', 'key').",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of strings to return.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_symbols",
        "description": "List binary symbols, PLT imports, exported symbols, bindings, and virtual addresses.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "filter": {
                "type": "string",
                "description": "Optional substring filter on symbol names.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of symbols to return.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_patch_instruction",
        "description": "Assemble and patch an assembly instruction or insert a NOP sled at a target memory address or symbol offset with automatic backup.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the binary file to modify.",
            },
            "addr": {
                "type": "string",
                "description": "Target memory address (e.g. '0x13d2') or symbol+offset (e.g. 'main+242').",
            },
            "assembly": {
                "type": "string",
                "description": "Assembly instruction text to assemble and write (e.g. 'mov eax, 1', 'jmp 0x1400').",
            },
            "nop_bytes": {
                "type": "integer",
                "description": "Number of NOP bytes (0x90) to write (mutually exclusive with assembly).",
            },
            "backup": {
                "type": "boolean",
                "description": "Create a timestamped .bak backup file before modifying. Defaults to true.",
            },
        },
        "required": ["file", "addr"],
    },
    {
        "name": "rvs_patch_string",
        "description": "Patch or overwrite a string literal in the binary data/rodata section by memory address or old text search.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the binary file to modify.",
            },
            "new_string": {
                "type": "string",
                "description": "New replacement string text.",
            },
            "addr": {
                "type": "string",
                "description": "Target memory address of the string (e.g. '0x2004').",
            },
            "old_string": {
                "type": "string",
                "description": "Old string text to search and replace (used if addr is omitted).",
            },
            "pad_null": {
                "type": "boolean",
                "description": "Zero-pad remaining bytes if new string is shorter than original. Defaults to true.",
            },
            "strict_length": {
                "type": "boolean",
                "description": "Prevent writes exceeding original string length. Defaults to true.",
            },
            "backup": {
                "type": "boolean",
                "description": "Create backup file before modifying. Defaults to true.",
            },
        },
        "required": ["file", "new_string"],
    },
    {
        "name": "rvs_patch_bytes",
        "description": "Write raw hexadecimal byte sequence to a target memory address with write verification and backup.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the binary file to modify.",
            },
            "addr": {
                "type": "string",
                "description": "Target memory address in hex (e.g. '0x13d2') or symbol offset.",
            },
            "hex_bytes": {
                "type": "string",
                "description": "Hexadecimal byte string without spaces (e.g. 'e9a200000090' or '9090').",
            },
            "backup": {
                "type": "boolean",
                "description": "Create backup file before modifying. Defaults to true.",
            },
        },
        "required": ["file", "addr", "hex_bytes"],
    },
    {
        "name": "rvs_agent_triage",
        "description": "Perform full autonomous binary reconnaissance: security mitigations, top complex functions, interesting strings, and actionable RE next steps.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the binary file to triage.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_agent_patch_plan",
        "description": "Validate, dry-run simulate, or atomically apply a multi-step patch plan to the target binary.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the binary file to patch.",
            },
            "plan": {
                "type": "object",
                "description": "Patch plan object specifying name, dry_run, and list of steps (instruction, bytes, nop, string).",
                "properties": {
                    "name": {"type": "string", "description": "Descriptive name for the patch plan."},
                    "dry_run": {"type": "boolean", "description": "Simulate patching without modifying binary."},
                    "steps": {
                        "type": "array",
                        "description": "List of patch step operations.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["instruction", "bytes", "nop", "string"]},
                                "addr": {"type": "string", "description": "Target address (hex or symbol)."},
                                "assembly": {"type": "string", "description": "Assembly for 'instruction' step."},
                                "hex": {"type": "string", "description": "Hex bytes for 'bytes' step."},
                                "new_string": {"type": "string", "description": "New string for 'string' step."},
                                "count": {"type": "integer", "description": "NOP count for 'nop' step."},
                            },
                            "required": ["type", "addr"],
                        },
                    },
                },
                "required": ["name", "steps"],
            },
            "dry_run": {
                "type": "boolean",
                "description": "Override dry_run flag in the plan. Defaults to false.",
            },
        },
        "required": ["file", "plan"],
    },
    {
        "name": "rvs_dynamic_emulate",
        "description": "Safely emulate binary execution via radare2 ESIL (Evaluable Strings Intermediate Language). Emulates function logic, steps until target address, traces register deltas, and inspects memory changes without OS execution permissions.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "target": {
                "type": "string",
                "description": "Function name (e.g. 'main', 'sym.check_key') or virtual memory address (e.g. '0x11e0').",
            },
            "steps": {
                "type": "integer",
                "description": "Maximum number of ESIL steps to emulate (defaults to 100).",
            },
            "until": {
                "type": "string",
                "description": "Stop emulation when instruction pointer reaches this virtual address (hex or symbol).",
            },
            "reg_set": {
                "type": "array",
                "description": "Preset CPU registers before emulation (e.g. ['rax=1', 'rdi=0x1000']).",
                "items": {"type": "string"},
            },
            "read_mem": {
                "type": "string",
                "description": "Memory address to inspect before and after emulation.",
            },
            "mem_len": {
                "type": "integer",
                "description": "Number of memory bytes to inspect (default: 32).",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output with register diffs. Defaults to true.",
            },
        },
        "required": ["file", "target"],
    },
    {
        "name": "rvs_dynamic_trace",
        "description": "Instruction-by-instruction dynamic execution trace recording opcodes and register deltas. Ideal for cryptanalytic loops, key checking, and decryptors.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "target": {
                "type": "string",
                "description": "Function name or start virtual address.",
            },
            "steps": {
                "type": "integer",
                "description": "Number of instruction steps to trace (default: 20, max: 100).",
            },
            "reg_set": {
                "type": "array",
                "description": "Preset CPU registers before trace (e.g. ['rax=0x42']).",
                "items": {"type": "string"},
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact trace. Defaults to true.",
            },
        },
        "required": ["file", "target"],
    },
    {
        "name": "rvs_dynamic_step",
        "description": "Single-step (or small N-step) execution advancing the instruction pointer and reporting register changes.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "target": {
                "type": "string",
                "description": "Function name or virtual address.",
            },
            "count": {
                "type": "integer",
                "description": "Number of instructions to step (default: 1).",
            },
            "reg_set": {
                "type": "array",
                "description": "Preset registers before step.",
                "items": {"type": "string"},
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file", "target"],
    },
]


def _convert_schema_to_gemini(prop_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively converts standard JSON Schema type strings to Gemini uppercase types."""
    type_map = {
        "string": "STRING",
        "integer": "INTEGER",
        "number": "NUMBER",
        "boolean": "BOOLEAN",
        "object": "OBJECT",
        "array": "ARRAY",
    }
    converted: Dict[str, Any] = {}
    for k, v in prop_dict.items():
        if k == "type" and isinstance(v, str):
            converted[k] = type_map.get(v.lower(), v.upper())
        elif k == "properties" and isinstance(v, dict):
            converted[k] = {
                prop_name: _convert_schema_to_gemini(prop_val)
                for prop_name, prop_val in v.items()
            }
        elif k == "items" and isinstance(v, dict):
            converted[k] = _convert_schema_to_gemini(v)
        else:
            converted[k] = v
    return converted


def get_tool_schemas(format: SchemaFormat = "openai") -> Union[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Exports tool calling schemas for the specified LLM convention:
    - 'openai': Function calling tools list (`type: "function"`)
    - 'anthropic': Tools list (`name`, `description`, `input_schema`)
    - 'gemini': Function declarations with uppercase type names (`OBJECT`, `STRING`, etc.)
    - 'mcp': Model Context Protocol tool definitions (`name`, `description`, `inputSchema`)
    """
    fmt = format.lower()
    if fmt == "openai":
        return [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": {
                        "type": "object",
                        "properties": tool["properties"],
                        "required": tool["required"],
                        "additionalProperties": False,
                    },
                },
            }
            for tool in CANONICAL_TOOLS
        ]

    elif fmt == "anthropic":
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "input_schema": {
                    "type": "object",
                    "properties": tool["properties"],
                    "required": tool["required"],
                    "additionalProperties": False,
                },
            }
            for tool in CANONICAL_TOOLS
        ]

    elif fmt == "gemini":
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        prop_name: _convert_schema_to_gemini(prop_val)
                        for prop_name, prop_val in tool["properties"].items()
                    },
                    "required": tool["required"],
                },
            }
            for tool in CANONICAL_TOOLS
        ]

    elif fmt == "mcp":
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "inputSchema": {
                    "type": "object",
                    "properties": tool["properties"],
                    "required": tool["required"],
                },
            }
            for tool in CANONICAL_TOOLS
        ]

    else:
        raise ValueError(
            f"Unsupported schema format: '{format}'. Supported formats: openai, anthropic, gemini, mcp."
        )


def coerce_bool_param(val: Any, default: bool, param_name: str) -> bool:
    """Coerce boolean parameter from bool or string representation ('true'/'false'/'1'/'0')."""
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        v = val.strip().lower()
        if v in ("true", "1", "yes", "t"):
            return True
        if v in ("false", "0", "no", "f", ""):
            return False
    raise ValueError(f"Invalid boolean value for parameter '{param_name}': {val!r}")


def coerce_int_param(
    val: Any,
    default: Optional[int],
    param_name: str,
    allow_negative: bool = False,
    min_val: Optional[int] = None,
) -> Optional[int]:
    """Coerce integer parameter from int or string representation. Validates sign."""
    if val is None:
        return default
    if isinstance(val, bool):
        raise ValueError(f"Invalid integer value for parameter '{param_name}': boolean {val!r}")
    parsed: int
    if isinstance(val, int):
        parsed = val
    elif isinstance(val, float):
        parsed = int(val)
    elif isinstance(val, str):
        s = val.strip()
        try:
            if s.startswith("0x") or s.startswith("0X"):
                parsed = int(s, 16)
            else:
                parsed = int(s, 10)
        except ValueError:
            raise ValueError(f"Invalid integer value for parameter '{param_name}': {val!r}")
    else:
        raise ValueError(f"Invalid type for parameter '{param_name}': {type(val).__name__}")

    if not allow_negative and parsed < 0:
        raise ValueError(f"Parameter '{param_name}' cannot be negative: {parsed}")
    if min_val is not None and parsed < min_val:
        raise ValueError(f"Parameter '{param_name}' must be >= {min_val}: {parsed}")
    return parsed


def coerce_reg_set_param(val: Any) -> Optional[List[str]]:
    """Coerce reg_set parameter: if string (e.g. 'rax=1'), wrap in list ['rax=1']."""
    if val is None:
        return None
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        return [s]
    if isinstance(val, (list, tuple)):
        return [str(item) for item in val]
    return [str(val)]


# =============================================================================
# Ergonomic Python API: RvsHarness & RvsAgentHarness (R2 & R3)
# =============================================================================

class RvsHarness:
    """
    Modern, typed Python interface for rvs binary analysis and patching engine.
    Provides direct programmatic execution, normalized error envelopes,
    token-optimized compaction, and automatic environment isolation.
    """

    def __init__(
        self,
        rvs_bin: Optional[Union[str, Path]] = None,
        default_timeout: float = DEFAULT_TIMEOUT_SECONDS,
        default_mode: OutputMode = "compact",
    ) -> None:
        self.rvs_bin = find_rvs_binary(custom_path=rvs_bin)
        self.default_timeout = default_timeout
        self.default_mode = default_mode
        self._session_cache: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _normalize_target(target: Optional[Union[str, Path]]) -> str:
        """Normalize binary path to absolute real path for unified session caching."""
        if not target:
            return ""
        try:
            return os.path.abspath(os.path.realpath(str(target)))
        except Exception:
            return str(target)

    def get_session(self, target: Union[str, Path]) -> Dict[str, Any]:
        """Retrieve cached analysis session properties for target binary."""
        return self._session_cache.get(self._normalize_target(target), {})

    def clear_session(self, target: Optional[Union[str, Path]] = None) -> None:
        """Clear cached session data for a specific binary or all binaries."""
        if target:
            self._session_cache.pop(self._normalize_target(target), None)
        else:
            self._session_cache.clear()

    def run(
        self,
        args: List[str],
        timeout: Optional[float] = None,
        target_file: Optional[Union[str, Path]] = None,
        mode: Optional[OutputMode] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> ApiResponseDict:
        """
        Executes an `rvs` command and returns structured ApiResponseDict envelope.
        """
        t = timeout if timeout is not None else self.default_timeout
        cmd_args = list(args)
        if target_file and "-f" not in cmd_args and "--file" not in cmd_args:
            cmd_args = ["-f", str(target_file)] + cmd_args

        # Extract target file from args if not provided
        target_str = str(target_file) if target_file else ""
        if not target_str:
            for i, a in enumerate(cmd_args):
                if a in ("-f", "--file") and i + 1 < len(cmd_args):
                    target_str = cmd_args[i + 1]
                    break

        norm_target = self._normalize_target(target_str) if target_str else ""

        # Check session cache to accelerate repeated agent operations
        if norm_target and norm_target in self._session_cache:
            cache = self._session_cache[norm_target]
            if "-a" not in cmd_args and "--arch" not in cmd_args and cache.get("arch"):
                cmd_args.extend(["-a", cache["arch"]])
            if "-b" not in cmd_args and "--bits" not in cmd_args and cache.get("bits"):
                cmd_args.extend(["-b", str(cache["bits"])])

        code, stdout, stderr, duration = execute_rvs_subprocess(
            cmd_args, timeout=t, rvs_bin=self.rvs_bin
        )

        if code == EXIT_TIMEOUT_ERROR:
            return make_timeout_error_envelope(" ".join(cmd_args), target_str, t)

        # Parse JSON envelope from stdout
        resp: Optional[ApiResponseDict] = None
        if stdout.strip():
            try:
                data = json.loads(stdout)
                if isinstance(data, dict):
                    data["execution_time_seconds"] = round(duration, 3)
                    resp = data  # type: ignore
                    # Populate session cache from successful discovery
                    if norm_target and data.get("success") and isinstance(data.get("data"), dict):
                        d = data["data"]
                        if norm_target not in self._session_cache:
                            self._session_cache[norm_target] = {}
                        if d.get("arch"):
                            self._session_cache[norm_target]["arch"] = d["arch"]
                        if d.get("bits"):
                            self._session_cache[norm_target]["bits"] = d["bits"]
            except json.JSONDecodeError:
                pass

        if resp is None:
            # Construct synthetic envelope for non-JSON or error stream
            success = (code == EXIT_SUCCESS)
            resp = {
                "success": success,
                "command": " ".join(cmd_args),
                "target": target_str,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "execution_time_seconds": round(duration, 3),
                "data": stdout if success else None,
                "warnings": [],
                "error": None if success else {
                    "code": "EXECUTION_ERROR",
                    "message": stderr or stdout or f"Command failed with exit code {code}",
                    "exit_code": code,
                    "suggestion": "Verify binary file path and argument syntax.",
                },
            }

        # Apply compaction transformation if mode is requested or set
        eff_mode = mode if mode is not None else self.default_mode
        if eff_mode and eff_mode != "full" and resp.get("success"):
            resp = transform_response(resp, mode=eff_mode, limit=limit, offset=offset)

        return resp

    # -------------------------------------------------------------------------
    # Core Analysis Methods
    # -------------------------------------------------------------------------

    def info(
        self,
        target: Union[str, Path],
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Inspect binary metadata, architecture, format, and security mitigations."""
        mode: OutputMode = "compact" if compact else "full"
        return self.run(["-f", str(target), "info"], timeout=timeout, mode=mode)

    def functions(
        self,
        target: Union[str, Path],
        filter: Optional[str] = None,
        detail: bool = False,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Enumerate functions with addresses, sizes, signatures, and cyclomatic complexity."""
        args = ["-f", str(target), "analyze", "functions"]
        if filter:
            args.extend(["--filter", filter])
        if detail:
            args.append("--detail")
        mode: OutputMode = "compact" if compact else "full"
        return self.run(
            args, timeout=timeout, mode=mode, limit=limit, offset=offset or 0
        )

    def disasm(
        self,
        target: Union[str, Path],
        function_or_addr: str,
        disasm: bool = True,
        max_instructions: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Disassemble basic blocks and instructions for target function or address."""
        args = ["-f", str(target), "analyze", "blocks", str(function_or_addr)]
        if not disasm:
            args.append("--disasm=false")
        mode: OutputMode = "compact" if compact else "full"
        resp = self.run(args, timeout=timeout, mode=mode)
        if max_instructions is not None and resp.get("success") and isinstance(resp.get("data"), dict):
            # Enforce max_instructions truncation
            blocks = resp["data"].get("blocks", [])
            for b in blocks:
                if "instructions" in b and len(b["instructions"]) > max_instructions:
                    b["instructions"] = b["instructions"][:max_instructions]
        return resp

    def decompile(
        self,
        target: Union[str, Path],
        function: str,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Generate pseudo-C decompilation, call graph, and referenced strings."""
        mode: OutputMode = "compact" if compact else "full"
        return self.run(
            ["-f", str(target), "--format", "json", "agent", "decompile", str(function)],
            timeout=timeout,
            mode=mode,
        )

    def flow(
        self,
        target: Union[str, Path],
        function: str,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Analyze control-flow branch gates, conditional checks, and loop back-edges."""
        mode: OutputMode = "compact" if compact else "full"
        return self.run(
            ["-f", str(target), "--format", "json", "agent", "flow", str(function)],
            timeout=timeout,
            mode=mode,
        )

    def xrefs(
        self,
        target: Union[str, Path],
        symbol_or_addr: str,
        direction: Literal["all", "to", "from"] = "all",
        kind: Optional[Literal["call", "code", "data", "string", "read", "write"]] = None,
        limit: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Extract cross-references to and/or from a symbol or address."""
        args = ["-f", str(target), "analyze", "xrefs", str(symbol_or_addr), "--type", direction]
        if kind:
            args.extend(["--kind", kind])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(args, timeout=timeout, mode=mode, limit=limit)

    def strings(
        self,
        target: Union[str, Path],
        min_len: int = 4,
        filter: Optional[str] = None,
        limit: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Scan binary data sections for ASCII/UTF-8 strings."""
        args = ["-f", str(target), "strings", "--min-len", str(min_len)]
        mode: OutputMode = "compact" if compact else "full"
        resp = self.run(args, timeout=timeout, mode=mode, limit=limit)
        if filter and resp.get("success") and isinstance(resp.get("data"), dict):
            # Apply filter substring
            raw_strs = resp["data"].get("strings", [])
            filtered = [s for s in raw_strs if filter.lower() in s.get("string", "").lower()]
            resp["data"]["strings"] = filtered
            resp["data"]["displayed"] = len(filtered)
        return resp

    def symbols(
        self,
        target: Union[str, Path],
        filter: Optional[str] = None,
        limit: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """List binary symbols, PLT imports, and virtual addresses."""
        args = ["-f", str(target), "symbols"]
        if filter:
            args.extend(["--filter", filter])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(args, timeout=timeout, mode=mode, limit=limit)

    # -------------------------------------------------------------------------
    # Binary Patching Methods
    # -------------------------------------------------------------------------

    def patch_instruction(
        self,
        target: Union[str, Path],
        addr: str,
        assembly: Optional[str] = None,
        nop_bytes: Optional[int] = None,
        backup: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Assemble and patch an assembly instruction or insert NOP sled."""
        if assembly is not None and nop_bytes is not None:
            return make_error_envelope(
                command_str=f"patch instruction --addr {addr}",
                target_str=str(target),
                code="INVALID_ARGUMENT",
                message="Cannot specify both 'assembly' and 'nop_bytes' simultaneously.",
                category="INVALID_ARGUMENT",
                exit_code=EXIT_INVALID_ARGUMENT,
                suggestion="Specify either an assembly instruction string or nop_bytes count.",
            )

        args = ["-f", str(target), "patch", "instruction", "--addr", str(addr)]
        if assembly is not None:
            args.extend(["--assembly", str(assembly)])
        elif nop_bytes is not None:
            args.extend(["--nop", str(nop_bytes)])
        else:
            return make_error_envelope(
                command_str=f"patch instruction --addr {addr}",
                target_str=str(target),
                code="INVALID_ARGUMENT",
                message="Must specify either 'assembly' or 'nop_bytes'.",
                category="INVALID_ARGUMENT",
                exit_code=EXIT_INVALID_ARGUMENT,
                suggestion="Provide --assembly <ASM> or --nop <COUNT>.",
            )

        if not backup:
            args.append("--backup=false")

        return self.run(args, timeout=timeout, mode="compact")

    def patch_string(
        self,
        target: Union[str, Path],
        new_string: str,
        addr: Optional[str] = None,
        old_string: Optional[str] = None,
        pad_null: bool = True,
        strict_length: bool = True,
        backup: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Patch or overwrite a string literal in binary data section."""
        args = ["-f", str(target), "patch", "string", "--new", str(new_string)]
        if addr:
            args.extend(["--addr", str(addr)])
        if old_string:
            args.extend(["--old", str(old_string)])
        if not pad_null:
            args.append("--pad-null=false")
        if not strict_length:
            args.append("--strict-length=false")
        if not backup:
            args.append("--backup=false")

        return self.run(args, timeout=timeout, mode="compact")

    def patch_bytes(
        self,
        target: Union[str, Path],
        addr: str,
        hex_bytes: str,
        backup: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Write raw hex bytes to target address with verification."""
        clean_hex = hex_bytes.replace(" ", "").replace("0x", "")
        if len(clean_hex) % 2 != 0:
            return make_error_envelope(
                command_str=f"patch bytes --addr {addr} --hex {hex_bytes}",
                target_str=str(target),
                code="INVALID_HEX_STRING",
                message=f"Hex byte string must have an even number of characters (got {len(clean_hex)})",
                category="PATCH_ERROR",
                exit_code=EXIT_PATCH_ERROR,
                suggestion="Ensure hex string contains complete bytes (e.g. '9090' or 'e9a200000090').",
            )

        args = ["-f", str(target), "patch", "bytes", "--addr", str(addr), "--hex", clean_hex]
        if not backup:
            args.append("--backup=false")

        return self.run(args, timeout=timeout, mode="compact")

    # -------------------------------------------------------------------------
    # Composite Agent Methods
    # -------------------------------------------------------------------------

    def triage(
        self,
        target: Union[str, Path],
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Autonomous binary triage, security evaluation, and RE next steps."""
        mode: OutputMode = "compact" if compact else "full"
        return self.run(
            ["-f", str(target), "--format", "json", "agent", "triage"],
            timeout=timeout,
            mode=mode,
        )

    def patch_plan(
        self,
        target: Union[str, Path],
        plan: Union[str, Path, Dict[str, Any]],
        dry_run: bool = False,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Validate, dry-run simulate, or atomically apply multi-step patch plan."""
        plan_str: str
        if isinstance(plan, dict):
            plan_dict = dict(plan)
            if dry_run:
                plan_dict["dry_run"] = True
            elif "dry_run" not in plan_dict:
                plan_dict["dry_run"] = False
            plan_str = json.dumps(plan_dict)
        elif isinstance(plan, (Path, str)):
            # Check if it's a file path
            plan_path = Path(plan)
            is_file = False
            try:
                is_file = plan_path.is_file()
            except Exception:
                is_file = False

            if is_file:
                try:
                    with open(plan_path, "r", encoding="utf-8") as f:
                        file_content = f.read()
                    plan_dict = json.loads(file_content)
                    if isinstance(plan_dict, dict):
                        if dry_run:
                            plan_dict["dry_run"] = True
                        elif "dry_run" not in plan_dict:
                            plan_dict["dry_run"] = False
                        plan_str = json.dumps(plan_dict)
                    else:
                        plan_str = file_content
                except Exception:
                    plan_str = str(plan)
            else:
                # String - could be JSON or plain string
                try:
                    plan_dict = json.loads(str(plan))
                    if isinstance(plan_dict, dict):
                        if dry_run:
                            plan_dict["dry_run"] = True
                        elif "dry_run" not in plan_dict:
                            plan_dict["dry_run"] = False
                        plan_str = json.dumps(plan_dict)
                    else:
                        plan_str = str(plan)
                except Exception:
                    plan_str = str(plan)
        else:
            plan_str = str(plan)

        args = ["-f", str(target), "agent", "patch-plan", "--plan", plan_str]
        return self.run(args, timeout=timeout, mode="compact")

    # -------------------------------------------------------------------------
    # Dynamic RE & ESIL Emulation Methods
    # -------------------------------------------------------------------------

    def dynamic_emulate(
        self,
        target: Union[str, Path],
        function_or_addr: str,
        steps: int = 100,
        until: Optional[str] = None,
        reg_set: Optional[List[str]] = None,
        read_mem: Optional[str] = None,
        mem_len: int = 32,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Safely emulate execution of a function or address range with radare2 ESIL."""
        args = ["-f", str(target), "dynamic", "emulate", str(function_or_addr), "--steps", str(steps)]
        if until:
            args.extend(["--until", str(until)])
        if reg_set:
            regs = [reg_set] if isinstance(reg_set, str) else reg_set
            for r in regs:
                args.extend(["--reg", str(r)])
        if read_mem:
            args.extend(["--read-mem", str(read_mem), "--mem-len", str(mem_len)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(args, timeout=timeout, mode=mode)

    def dynamic_trace(
        self,
        target: Union[str, Path],
        function_or_addr: str,
        steps: int = 20,
        reg_set: Optional[Union[str, List[str]]] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Trace instruction-by-instruction execution with register deltas."""
        args = ["-f", str(target), "dynamic", "trace", str(function_or_addr), "--steps", str(steps)]
        if reg_set:
            regs = [reg_set] if isinstance(reg_set, str) else reg_set
            for r in regs:
                args.extend(["--reg", str(r)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(args, timeout=timeout, mode=mode)

    def dynamic_step(
        self,
        target: Union[str, Path],
        function_or_addr: str,
        count: int = 1,
        reg_set: Optional[Union[str, List[str]]] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Single-step (or N steps) execution advancing instruction pointer."""
        args = ["-f", str(target), "dynamic", "step", str(function_or_addr), "--count", str(count)]
        if reg_set:
            regs = [reg_set] if isinstance(reg_set, str) else reg_set
            for r in regs:
                args.extend(["--reg", str(r)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(args, timeout=timeout, mode=mode)

    def agent_emulate(
        self,
        target: Union[str, Path],
        function_or_addr: str,
        steps: int = 100,
        until: Optional[str] = None,
        reg_set: Optional[Union[str, List[str]]] = None,
        read_mem: Optional[str] = None,
        mem_len: int = 32,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Autonomous AI agent emulation: evaluates decision gates and synthesizes natural summary."""
        args = ["-f", str(target), "agent", "emulate", str(function_or_addr), "--steps", str(steps)]
        if until:
            args.extend(["--until", str(until)])
        if reg_set:
            regs = [reg_set] if isinstance(reg_set, str) else reg_set
            for r in regs:
                args.extend(["--reg", str(r)])
        if read_mem:
            args.extend(["--read-mem", str(read_mem), "--mem-len", str(mem_len)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(args, timeout=timeout, mode=mode)

    # -------------------------------------------------------------------------
    # Schema & MCP Execution
    # -------------------------------------------------------------------------

    def get_tool_schemas(
        self,
        format: SchemaFormat = "openai",
    ) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
        """Export tool calling schemas for specified LLM format convention."""
        return get_tool_schemas(format=format)

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> ApiResponseDict:
        """Dispatches an MCP or LLM tool call to the appropriate programmatic method."""
        if not isinstance(arguments, dict):
            return make_error_envelope(
                command_str=f"{tool_name}",
                target_str="",
                code="INVALID_ARGUMENT",
                message="Tool arguments must be a dictionary object",
                category="INVALID_ARGUMENT",
                exit_code=EXIT_INVALID_ARGUMENT,
                suggestion="Pass tool arguments as a key-value JSON object.",
            )

        file = arguments.get("file")
        if not file:
            return make_error_envelope(
                command_str=f"{tool_name}",
                target_str="",
                code="INVALID_ARGUMENT",
                message=f"Missing required parameter 'file' for tool '{tool_name}'",
                category="INVALID_ARGUMENT",
                exit_code=EXIT_INVALID_ARGUMENT,
                suggestion="Specify the path to the target binary in the 'file' argument.",
            )

        try:
            compact = coerce_bool_param(arguments.get("compact"), True, "compact")

            if tool_name == "rvs_info":
                return self.info(file, compact=compact)

            elif tool_name == "rvs_functions":
                detail = coerce_bool_param(arguments.get("detail"), False, "detail")
                limit = coerce_int_param(arguments.get("limit"), None, "limit", allow_negative=False)
                offset = coerce_int_param(arguments.get("offset"), None, "offset", allow_negative=False)
                return self.functions(
                    file,
                    filter=arguments.get("filter"),
                    detail=detail,
                    limit=limit,
                    offset=offset,
                    compact=compact,
                )

            elif tool_name == "rvs_disasm":
                target = arguments.get("target")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target' (function name or address)",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass target='main' or target='0x11e0'.",
                    )
                disasm = coerce_bool_param(arguments.get("disasm"), True, "disasm")
                max_instructions = coerce_int_param(
                    arguments.get("max_instructions"), None, "max_instructions", allow_negative=False
                )
                return self.disasm(
                    file,
                    function_or_addr=str(target),
                    disasm=disasm,
                    max_instructions=max_instructions,
                    compact=compact,
                )

            elif tool_name == "rvs_decompile":
                function = arguments.get("function")
                if not function:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'function'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass function='main' or function address.",
                    )
                return self.decompile(file, function=str(function), compact=compact)

            elif tool_name == "rvs_flow":
                function = arguments.get("function")
                if not function:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'function'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass function='main' or function address.",
                    )
                return self.flow(file, function=str(function), compact=compact)

            elif tool_name == "rvs_xrefs":
                target = arguments.get("target")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass target symbol or address to xrefs query.",
                    )
                limit = coerce_int_param(arguments.get("limit"), None, "limit", allow_negative=False)
                return self.xrefs(
                    file,
                    symbol_or_addr=str(target),
                    direction=arguments.get("direction", "all"),
                    kind=arguments.get("kind"),
                    limit=limit,
                    compact=compact,
                )

            elif tool_name == "rvs_strings":
                min_len = coerce_int_param(arguments.get("min_len"), 4, "min_len", allow_negative=False)
                if min_len is None:
                    min_len = 4
                limit = coerce_int_param(arguments.get("limit"), None, "limit", allow_negative=False)
                return self.strings(
                    file,
                    min_len=min_len,
                    filter=arguments.get("filter"),
                    limit=limit,
                    compact=compact,
                )

            elif tool_name == "rvs_symbols":
                limit = coerce_int_param(arguments.get("limit"), None, "limit", allow_negative=False)
                return self.symbols(
                    file,
                    filter=arguments.get("filter"),
                    limit=limit,
                    compact=compact,
                )

            elif tool_name == "rvs_patch_instruction":
                addr = arguments.get("addr")
                if not addr:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'addr'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                nop_bytes = coerce_int_param(arguments.get("nop_bytes"), None, "nop_bytes", allow_negative=False)
                backup = coerce_bool_param(arguments.get("backup"), True, "backup")
                return self.patch_instruction(
                    file,
                    addr=addr,
                    assembly=arguments.get("assembly"),
                    nop_bytes=nop_bytes,
                    backup=backup,
                )

            elif tool_name == "rvs_patch_string":
                new_str = arguments.get("new_string")
                if new_str is None:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'new_string'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                pad_null = coerce_bool_param(arguments.get("pad_null"), True, "pad_null")
                strict_length = coerce_bool_param(arguments.get("strict_length"), True, "strict_length")
                backup = coerce_bool_param(arguments.get("backup"), True, "backup")
                return self.patch_string(
                    file,
                    new_string=new_str,
                    addr=arguments.get("addr"),
                    old_string=arguments.get("old_string"),
                    pad_null=pad_null,
                    strict_length=strict_length,
                    backup=backup,
                )

            elif tool_name == "rvs_patch_bytes":
                addr = arguments.get("addr")
                hex_bytes = arguments.get("hex_bytes")
                if not addr or not hex_bytes:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'addr' or 'hex_bytes'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                backup = coerce_bool_param(arguments.get("backup"), True, "backup")
                return self.patch_bytes(
                    file,
                    addr=addr,
                    hex_bytes=hex_bytes,
                    backup=backup,
                )

            elif tool_name == "rvs_agent_triage":
                return self.triage(file, compact=compact)

            elif tool_name == "rvs_agent_patch_plan":
                plan = arguments.get("plan")
                if not plan:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'plan'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                dry_run = coerce_bool_param(arguments.get("dry_run"), False, "dry_run")
                return self.patch_plan(
                    file,
                    plan=plan,
                    dry_run=dry_run,
                )

            elif tool_name in ("rvs_dynamic_emulate", "dynamic_emulate", "rvs_emulate", "emulate", "rvs_agent_emulate", "agent_emulate"):
                target = arguments.get("target")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target' (function or address)",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass target='main' or target='0x11e0'.",
                    )
                steps = coerce_int_param(arguments.get("steps"), 100, "steps", allow_negative=False)
                if steps is None:
                    steps = 100
                mem_len = coerce_int_param(arguments.get("mem_len"), 32, "mem_len", allow_negative=False)
                if mem_len is None:
                    mem_len = 32
                reg_set = coerce_reg_set_param(arguments.get("reg_set"))
                return self.dynamic_emulate(
                    file,
                    function_or_addr=str(target),
                    steps=steps,
                    until=arguments.get("until"),
                    reg_set=reg_set,
                    read_mem=arguments.get("read_mem"),
                    mem_len=mem_len,
                    compact=compact,
                )

            elif tool_name in ("rvs_dynamic_trace", "dynamic_trace", "rvs_trace", "trace", "rvs_agent_trace", "agent_trace"):
                target = arguments.get("target")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target' (function or address)",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass target='main' or target='0x11e0'.",
                    )
                steps = coerce_int_param(arguments.get("steps"), 20, "steps", allow_negative=False)
                if steps is None:
                    steps = 20
                reg_set = coerce_reg_set_param(arguments.get("reg_set"))
                return self.dynamic_trace(
                    file,
                    function_or_addr=str(target),
                    steps=steps,
                    reg_set=reg_set,
                    compact=compact,
                )

            elif tool_name in ("rvs_dynamic_step", "dynamic_step", "rvs_step", "step"):
                target = arguments.get("target")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target' (function or address)",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass target='main' or target='0x11e0'.",
                    )
                count = coerce_int_param(arguments.get("count"), 1, "count", allow_negative=False)
                if count is None:
                    count = 1
                reg_set = coerce_reg_set_param(arguments.get("reg_set"))
                return self.dynamic_step(
                    file,
                    function_or_addr=str(target),
                    count=count,
                    reg_set=reg_set,
                    compact=compact,
                )

            else:
                return make_error_envelope(
                    command_str=f"{tool_name}",
                    target_str=str(file),
                    code="TOOL_NOT_FOUND",
                    message=f"Tool '{tool_name}' is not recognized.",
                    category="INVALID_ARGUMENT",
                    exit_code=EXIT_INVALID_ARGUMENT,
                    suggestion="Use get_tool_schemas() or tools/list to see available tool definitions.",
                )

        except ValueError as e:
            return make_error_envelope(
                command_str=f"{tool_name}",
                target_str=str(file) if file else "",
                code="INVALID_ARGUMENT",
                message=str(e),
                category="INVALID_ARGUMENT",
                exit_code=EXIT_INVALID_ARGUMENT,
                suggestion="Check parameter types and provide valid arguments.",
            )
        except Exception as e:
            return make_error_envelope(
                command_str=f"{tool_name}",
                target_str=str(file) if file else "",
                code="INTERNAL_ERROR",
                message=str(e),
                exit_code=EXIT_INTERNAL_ERROR,
            )

    # -------------------------------------------------------------------------
    # Native Stdio MCP Server Loop (R2.2)
    # -------------------------------------------------------------------------

    def serve_mcp(
        self,
        stdin_stream: Optional[io.TextIOBase] = None,
        stdout_stream: Optional[io.TextIOBase] = None,
    ) -> None:
        """Runs the standard stdio Model Context Protocol (MCP) JSON-RPC 2.0 server loop."""
        in_stream = stdin_stream if stdin_stream is not None else sys.stdin
        out_stream = stdout_stream if stdout_stream is not None else sys.stdout

        def _send_response(payload: Dict[str, Any]) -> bool:
            try:
                out_stream.write(json.dumps(payload) + "\n")
                out_stream.flush()
                return True
            except (BrokenPipeError, IOError, OSError):
                return False

        try:
            for line in in_stream:
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    req = json.loads(line_str)
                except json.JSONDecodeError:
                    err_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error: Invalid JSON payload"},
                    }
                    if not _send_response(err_response):
                        break
                    continue

                try:
                    if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
                        err_response = {
                            "jsonrpc": "2.0",
                            "id": req.get("id") if isinstance(req, dict) else None,
                            "error": {"code": -32600, "message": "Invalid Request: Expected JSON-RPC 2.0 object"},
                        }
                        if not _send_response(err_response):
                            break
                        continue

                    msg_id = req.get("id")
                    method = req.get("method")
                    params = req.get("params")

                    # 1. Notification (no id)
                    if msg_id is None:
                        # Handle client notification (e.g. notifications/initialized)
                        continue

                    if not isinstance(method, str):
                        resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32600,
                                "message": "Invalid Request: 'method' must be a string",
                            },
                        }
                    # 2. initialize
                    elif method == "initialize":
                        if params is not None and not isinstance(params, dict):
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32602,
                                    "message": "Invalid params: params must be an object",
                                },
                            }
                        else:
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "result": {
                                    "protocolVersion": MCP_PROTOCOL_VERSION,
                                    "capabilities": {
                                        "tools": {"listChanged": False},
                                    },
                                    "serverInfo": {
                                        "name": SERVER_NAME,
                                        "version": SERVER_VERSION,
                                    },
                                },
                            }

                    # 3. ping
                    elif method == "ping":
                        if params is not None and not isinstance(params, dict):
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32602,
                                    "message": "Invalid params: params must be an object",
                                },
                            }
                        else:
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "result": {},
                            }

                    # 4. tools/list
                    elif method == "tools/list":
                        if params is not None and not isinstance(params, dict):
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32602,
                                    "message": "Invalid params: params must be an object",
                                },
                            }
                        else:
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "result": {
                                    "tools": self.get_tool_schemas("mcp"),
                                },
                            }

                    # 5. tools/call
                    elif method == "tools/call":
                        if not isinstance(params, dict):
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "error": {
                                    "code": -32602,
                                    "message": "Invalid params: params must be an object",
                                },
                            }
                        else:
                            tool_name = params.get("name", "")
                            tool_args = params.get("arguments", {})
                            tool_result = self.execute_tool(tool_name, tool_args)
                            is_error = not tool_result.get("success", False)
                            resp = {
                                "jsonrpc": "2.0",
                                "id": msg_id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": json.dumps(tool_result),
                                        }
                                    ],
                                    "isError": is_error,
                                },
                            }

                    # 6. Unknown method
                    else:
                        resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32601,
                                "message": f"Method not found: '{method}'",
                            },
                        }

                    if not _send_response(resp):
                        break

                except (BrokenPipeError, IOError, OSError):
                    break
                except Exception as e:
                    try:
                        sys.stderr.write(f"[MCP Server Error] {type(e).__name__}: {e}\n")
                        sys.stderr.flush()
                    except (BrokenPipeError, IOError, OSError):
                        break
                    req_id = req.get("id") if isinstance(req, dict) else None
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32603,
                            "message": f"Internal error: {str(e)}",
                        },
                    }
                    if not _send_response(err_resp):
                        break
        except (BrokenPipeError, IOError, OSError):
            pass


# =============================================================================
# Backward Compatibility Alias (R3)
# =============================================================================

class RvsAgentHarness(RvsHarness):
    """
    Legacy alias for RvsHarness, maintaining complete backward compatibility
    with all existing tests and external agent frameworks.
    """
    pass


# =============================================================================
# CLI Main Entrypoint
# =============================================================================

def main() -> None:
    args = sys.argv[1:]

    # Check for MCP server invocation
    if "--mcp" in args or "--serve-mcp" in args or (len(args) > 0 and args[0] == "mcp"):
        harness = RvsHarness()
        harness.serve_mcp()
        sys.exit(EXIT_SUCCESS)

    # Check for Tool Schemas export flag
    for i, a in enumerate(args):
        if a in ("--export-tools", "--tools") and i + 1 < len(args):
            fmt = args[i + 1]
            try:
                schemas = get_tool_schemas(fmt)  # type: ignore
                print(json.dumps(schemas, indent=2))
                sys.exit(EXIT_SUCCESS)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                sys.exit(EXIT_INVALID_ARGUMENT)
        elif a.startswith("--export-tools=") or a.startswith("--tools="):
            fmt = a.split("=", 1)[1]
            try:
                schemas = get_tool_schemas(fmt)  # type: ignore
                print(json.dumps(schemas, indent=2))
                sys.exit(EXIT_SUCCESS)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                sys.exit(EXIT_INVALID_ARGUMENT)

    # Extract harness-specific flags
    timeout = DEFAULT_TIMEOUT_SECONDS
    custom_rvs = None
    explicit_mode: Optional[OutputMode] = None
    limit_val: Optional[int] = None
    offset_val: int = 0
    cleaned_args: List[str] = []

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--timeout" and idx + 1 < len(args):
            try:
                timeout = float(args[idx + 1])
            except ValueError:
                timeout = DEFAULT_TIMEOUT_SECONDS
            idx += 2
        elif arg.startswith("--timeout="):
            try:
                timeout = float(arg.split("=", 1)[1])
            except ValueError:
                timeout = DEFAULT_TIMEOUT_SECONDS
            idx += 1
        elif arg == "--rvs-bin" and idx + 1 < len(args):
            custom_rvs = args[idx + 1]
            idx += 2
        elif arg.startswith("--rvs-bin="):
            custom_rvs = arg.split("=", 1)[1]
            idx += 1
        elif arg == "--mode" and idx + 1 < len(args):
            mode_str = args[idx + 1].lower()
            if mode_str in ("compact", "summary", "full"):
                explicit_mode = mode_str  # type: ignore
            idx += 2
        elif arg.startswith("--mode="):
            mode_str = arg.split("=", 1)[1].lower()
            if mode_str in ("compact", "summary", "full"):
                explicit_mode = mode_str  # type: ignore
            idx += 1
        elif arg in ("--max-items", "--limit") and idx + 1 < len(args):
            try:
                limit_val = int(args[idx + 1])
            except ValueError:
                pass
            idx += 2
        elif arg.startswith("--max-items=") or arg.startswith("--limit="):
            try:
                limit_val = int(arg.split("=", 1)[1])
            except ValueError:
                pass
            idx += 1
        elif arg == "--offset" and idx + 1 < len(args):
            try:
                offset_val = int(args[idx + 1])
            except ValueError:
                pass
            idx += 2
        elif arg.startswith("--offset="):
            try:
                offset_val = int(arg.split("=", 1)[1])
            except ValueError:
                pass
            idx += 1
        else:
            cleaned_args.append(arg)
            idx += 1

    rvs_bin = find_rvs_binary(custom_rvs)

    # Extract target file for error reporting if present
    target_str = ""
    for i, a in enumerate(cleaned_args):
        if a in ("-f", "--file") and i + 1 < len(cleaned_args):
            target_str = cleaned_args[i + 1]
            break

    code, stdout, stderr, duration = execute_rvs_subprocess(
        cleaned_args,
        timeout=timeout,
        rvs_bin=rvs_bin,
    )

    if code == EXIT_TIMEOUT_ERROR:
        err_envelope = make_timeout_error_envelope(" ".join(cleaned_args), target_str, timeout)
        print(json.dumps(err_envelope))
        sys.exit(EXIT_TIMEOUT_ERROR)

    # If stdout contains JSON, parse and attach metadata / compaction if requested
    if stdout.strip():
        try:
            parsed = json.loads(stdout)
            if isinstance(parsed, dict):
                if "execution_time_seconds" not in parsed:
                    parsed["execution_time_seconds"] = round(duration, 3)

                # If an explicit mode or limit was specified on the CLI, transform the response
                if explicit_mode is not None or limit_val is not None or offset_val > 0:
                    mode_to_use = explicit_mode or "compact"
                    parsed = transform_response(
                        parsed, mode=mode_to_use, limit=limit_val, offset=offset_val
                    )

                print(json.dumps(parsed))
            else:
                print(stdout, end="")
        except json.JSONDecodeError:
            # Non-JSON or streaming output (e.g. jsonl, markdown, raw text)
            print(stdout, end="")
    elif stderr.strip():
        print(stderr, file=sys.stderr, end="")

    sys.exit(code)


if __name__ == "__main__":
    main()
