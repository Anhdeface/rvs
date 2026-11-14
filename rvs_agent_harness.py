#!/usr/bin/env python3
"""
rvs_agent_harness.py - Standard Python AI Agent CLI Harness & MCP Protocol Layer for `rvs`.

Provides:
1. Complete Subprocess Environment Isolation (TERM=dumb, NO_COLOR=1, R2_NOPLUGINS=1, RADARE2_RCFILE=/dev/null)
2. Process Watchdog with Timeout Management (Graceful SIGTERM -> SIGKILL)
3. Token-Optimized Response Filtering & Compaction Engine (compact, summary, full modes)
4. LLM Function Calling Schema Exporter (OpenAI, Anthropic, Gemini, MCP formats for 40 commands including Dynamic RE, Native Debug & r2frida)
5. Native Model Context Protocol (MCP) Stdio JSON-RPC 2.0 Server
6. Ergonomic Typed Python API (`RvsHarness` & `RvsAgentHarness`) with Normalized Error Envelopes
7. Standardized 7-Level Exit Code Taxonomy & Actionable Error Suggestions
"""

from __future__ import annotations

import atexit
import io
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Set, Tuple, TypedDict, Union

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


def normalize_exit_code(raw_code: int) -> int:
    """Normalize raw subprocess returncode or exit code to the strict {0..6} taxonomy.

    Invariants:
    - 0: EXIT_SUCCESS
    - 1: EXIT_INVALID_ARGUMENT
    - 2: EXIT_FILE_ERROR
    - 3: EXIT_ANALYSIS_ERROR
    - 4: EXIT_PATCH_ERROR
    - 5: EXIT_TIMEOUT_ERROR
    - 6: EXIT_INTERNAL_ERROR
    All negative codes (signals like -11 SIGSEGV) and codes outside {0..6} map to EXIT_INTERNAL_ERROR (6).
    """
    if raw_code in (
        EXIT_SUCCESS,
        EXIT_INVALID_ARGUMENT,
        EXIT_FILE_ERROR,
        EXIT_ANALYSIS_ERROR,
        EXIT_PATCH_ERROR,
        EXIT_TIMEOUT_ERROR,
        EXIT_INTERNAL_ERROR,
    ):
        return raw_code
    return EXIT_INTERNAL_ERROR


DEFAULT_TIMEOUT_SECONDS: float = 30.0

MCP_PROTOCOL_VERSION: str = "2024-11-05"
SERVER_NAME: str = "rvs-mcp-server"
SERVER_VERSION: str = "0.3.6"

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
    truncated: Optional[bool]
    original_tokens: Optional[int]
    budget: Optional[int]


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


def load_harness_config(custom_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Loads rvs harness configuration from custom path, RVS_CONFIG env var,
    local rvs.json in CWD, or ~/.config/rvs/config.json. Returns empty dict if not found.
    """
    candidates: List[Path] = []
    if custom_path:
        candidates.append(Path(custom_path))
    if "RVS_CONFIG" in os.environ and os.environ["RVS_CONFIG"].strip():
        candidates.append(Path(os.environ["RVS_CONFIG"].strip()))
    candidates.append(Path.cwd() / "rvs.json")
    try:
        candidates.append(Path.home() / ".config" / "rvs" / "config.json")
    except Exception:
        pass

    for path in candidates:
        try:
            resolved = path.resolve()
            if resolved.is_file():
                with open(resolved, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    if isinstance(cfg, dict):
                        return cfg
        except Exception:
            continue
    return {}


def resolve_harness_defaults(
    explicit_neutral: Optional[bool] = None,
    explicit_compact: Optional[bool] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, bool]:
    """
    Resolves effective defaults for neutral and compact modes.
    Precedence: Explicit argument / CLI flag > Environment variable > Configuration file > Built-in defaults (True).
    """
    cfg = config or {}

    # 1. Neutral mode resolution
    if explicit_neutral is not None:
        eff_neutral = bool(explicit_neutral)
    elif "RVS_NO_NEUTRAL" in os.environ and os.environ["RVS_NO_NEUTRAL"].strip().lower() not in ("0", "false", "no", "off"):
        eff_neutral = False
    elif "RVS_NEUTRAL" in os.environ:
        eff_neutral = os.environ["RVS_NEUTRAL"].strip().lower() in ("1", "true", "yes", "on", "t")
    elif "neutral" in cfg:
        eff_neutral = bool(cfg["neutral"])
    else:
        eff_neutral = True  # Requirement R1: Default True

    # 2. Compact mode resolution
    if explicit_compact is not None:
        eff_compact = bool(explicit_compact)
    elif ("RVS_NO_COMPACT" in os.environ and os.environ["RVS_NO_COMPACT"].strip().lower() not in ("0", "false", "no", "off")) or os.environ.get("RVS_MODE", "").strip().lower() == "full":
        eff_compact = False
    elif "RVS_COMPACT" in os.environ:
        eff_compact = os.environ["RVS_COMPACT"].strip().lower() in ("1", "true", "yes", "on", "t")
    elif "compact" in cfg:
        eff_compact = bool(cfg["compact"])
    elif cfg.get("mode") == "full":
        eff_compact = False
    else:
        eff_compact = True  # Requirement R1: Default True

    return eff_neutral, eff_compact


_CONTROL_CHAR_TRANSLATE_TABLE: Dict[int, Optional[int]] = {
    i: None for i in range(32) if i not in (9, 10, 13)
}
_CONTROL_CHAR_TRANSLATE_TABLE[127] = None


def sanitize_terminal_output(text: Union[str, bytes]) -> str:
    """Strips ANSI escape codes, terminal cursor controls, and unprintable characters."""
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    # Strip ANSI sequences
    cleaned = ANSI_ESCAPE_RE.sub("", text)
    # Strip control characters except standard whitespace (\n, \r, \t) via C-accelerated translate table
    return cleaned.translate(_CONTROL_CHAR_TRANSLATE_TABLE)


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


_ACTIVE_SUBPROCESS_PGIDS: set[int] = set()
_SUBPROCESS_REGISTRY_LOCK = threading.RLock()


def _cleanup_lingering_subprocesses() -> None:
    """Kill all registered active subprocess process groups with SIGKILL."""
    with _SUBPROCESS_REGISTRY_LOCK:
        pgids = list(_ACTIVE_SUBPROCESS_PGIDS)
        _ACTIVE_SUBPROCESS_PGIDS.clear()
    for pgid in pgids:
        if pgid > 1:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except Exception:
                pass


atexit.register(_cleanup_lingering_subprocesses)


def _sig_term_int_handler(signum: int, frame: Any) -> None:
    """Handle termination signals by ensuring child process groups are killed before exit."""
    try:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, AttributeError):
        pass
    _cleanup_lingering_subprocesses()
    sys.exit(normalize_exit_code(128 + signum))


try:
    signal.signal(signal.SIGTERM, _sig_term_int_handler)
    signal.signal(signal.SIGINT, _sig_term_int_handler)
except (ValueError, AttributeError):
    pass


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
            start_new_session=True,
        )
        with _SUBPROCESS_REGISTRY_LOCK:
            _ACTIVE_SUBPROCESS_PGIDS.add(proc.pid)

        try:
            try:
                stdout_raw, stderr_raw = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                stdout_raw, stderr_raw = "", ""
                # Graceful termination first (SIGTERM to entire process group)
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass

                try:
                    stdout_raw, stderr_raw = proc.communicate(timeout=0.5)
                except (subprocess.TimeoutExpired, Exception):
                    # Force kill entire process group if unresponsive (SIGKILL)
                    try:
                        pgid = os.getpgid(proc.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass

                    try:
                        stdout_raw, stderr_raw = proc.communicate(timeout=0.5)
                    except Exception:
                        stdout_raw, stderr_raw = "", ""

                duration = time.time() - start_time
                stdout = sanitize_terminal_output(stdout_raw)
                stderr = sanitize_terminal_output(stderr_raw)
                return EXIT_TIMEOUT_ERROR, stdout, stderr, duration
            except KeyboardInterrupt:
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGKILL)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                raise

            duration = time.time() - start_time
            stdout = sanitize_terminal_output(stdout_raw)
            stderr = sanitize_terminal_output(stderr_raw)
            return proc.returncode, stdout, stderr, duration

        finally:
            # Explicitly close pipe descriptors on all timeout/exception/exit paths
            if proc.stdout and not proc.stdout.closed:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
            if proc.stderr and not proc.stderr.closed:
                try:
                    proc.stderr.close()
                except Exception:
                    pass
            if proc.stdin and not proc.stdin.closed:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

            # Unconditional reaping: ensure proc.wait() is always called so <defunct>
            # zombie processes are never left in the operating system process table.
            if proc.poll() is None:
                try:
                    proc.wait(timeout=0.5)
                except Exception:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    try:
                        proc.wait(timeout=0.5)
                    except Exception:
                        try:
                            os.waitpid(proc.pid, os.WNOHANG)
                        except Exception:
                            pass

            with _SUBPROCESS_REGISTRY_LOCK:
                _ACTIVE_SUBPROCESS_PGIDS.discard(proc.pid)

    except FileNotFoundError:
        duration = time.time() - start_time
        err_msg = f"rvs binary not found at '{rvs_bin}'"
        return EXIT_FILE_ERROR, "", err_msg, duration
    except Exception as e:
        duration = time.time() - start_time
        return EXIT_INTERNAL_ERROR, "", str(e), duration


# =============================================================================
# Algorithmic Token Compaction & Optimization Engine (R2)
# =============================================================================

@dataclass
class TokenBudget:
    """Represents an allocated token budget envelope with reserved margins."""
    max_tokens: int
    reserved_envelope: int = 40
    safety_margin: int = 10

    @property
    def available_items_budget(self) -> int:
        return max(0, self.max_tokens - self.reserved_envelope - self.safety_margin)


class TokenEstimator:
    """
    Calibrated pure-Python token estimator matching BPE tokenizers (cl100k_base / Llama / Claude).
    Calibrates character-to-token ratio (~1.75 - 2.8) for RE assembly, JSON, and code telemetry,
    with zero external dependencies.
    """
    _BPE_RE = re.compile(
        r"""0x[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*|\d+|[^\s\w]|\s+"""
    )

    @classmethod
    def count_tokens(cls, text: Optional[str]) -> int:
        """Estimate BPE token count for a text string."""
        if not text:
            return 0
        total = 0
        for m in cls._BPE_RE.finditer(text):
            t = m.group(0)
            if t.startswith("0x") and len(t) > 4:
                # 0x + hex digits (e.g. 0x0000555555555120 is ~5 BPE tokens)
                total += 1 + (len(t) - 2 + 3) // 4
            elif len(t) > 8 and t.isalnum():
                # Long alphanumeric identifiers (mangled symbols, base64)
                total += (len(t) + 3) // 4
            elif t.isspace():
                # Merged whitespace/newlines: ~1 token per 4 spaces/newlines
                total += max(1, len(t) // 4)
            else:
                total += 1
        return max(1, total)

    @classmethod
    def estimate_obj(cls, obj: Any) -> int:
        """Estimate token count for any JSON-serializable Python object."""
        if obj is None:
            return 0
        try:
            serialized = json.dumps(obj)
        except Exception:
            serialized = str(obj)
        return cls.count_tokens(serialized)

    @classmethod
    def char_to_token_ratio(cls, text: Optional[str]) -> float:
        """Calculate characters per token ratio."""
        if not text:
            return 0.0
        toks = cls.count_tokens(text)
        if toks == 0:
            return 0.0
        return round(len(text) / toks, 3)


class EntropyPruner:
    """
    Detects and compresses repetitive patterns, NOP sleds, padding, and zero memory pages
    using run-length encoding (RLE) and repetition folding, preserving semantic and structural
    parseability while achieving >90% token reduction on repetitive sequences.
    """
    _PADDING_OPS = {
        "nop", "int3", "fnop", "align", "endbr64", "endbr32", "pause", "ud2"
    }

    @classmethod
    def fold_instruction_stream(cls, instructions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Folds consecutive repetitive instructions (such as NOP sleds, INT3 padding, alignment)
        into compact run descriptors preserving start address, repeated count, and total byte size.
        """
        if not instructions:
            return []

        folded: List[Dict[str, Any]] = []
        run_op: Optional[str] = None
        run_raw_asm: Optional[str] = None
        run_start_addr: Optional[str] = None
        run_total_size: int = 0
        run_count: int = 0

        for inst in instructions:
            raw_asm = (inst.get("asm") or inst.get("disasm") or inst.get("opcode") or "").strip()
            tokens = raw_asm.split()
            mnemonic = tokens[0].lower() if tokens else ""
            is_padding = mnemonic in cls._PADDING_OPS
            is_same = (raw_asm.lower() == run_op)

            if is_padding and (run_op == mnemonic or run_count == 0):
                if run_count == 0:
                    run_op = mnemonic
                    run_raw_asm = raw_asm
                    run_start_addr = inst.get("addr") or inst.get("addr_hex") or format_hex_addr(inst.get("addr"))
                    run_total_size = int(inst.get("size") or 1)
                    run_count = 1
                elif run_op == mnemonic:
                    run_count += 1
                    run_total_size += int(inst.get("size") or 1)
                else:
                    cls._flush_inst_run(folded, run_start_addr, run_raw_asm or run_op, run_count, run_total_size)
                    run_op = mnemonic
                    run_raw_asm = raw_asm
                    run_start_addr = inst.get("addr") or inst.get("addr_hex") or format_hex_addr(inst.get("addr"))
                    run_total_size = int(inst.get("size") or 1)
                    run_count = 1
            elif is_same and run_count > 0:
                run_count += 1
                run_total_size += int(inst.get("size") or 1)
            else:
                if run_count > 0:
                    cls._flush_inst_run(folded, run_start_addr, run_raw_asm or run_op, run_count, run_total_size)
                    run_op = None
                    run_raw_asm = None
                    run_count = 0
                    run_total_size = 0

                run_op = raw_asm.lower()
                run_raw_asm = raw_asm
                run_start_addr = inst.get("addr") or inst.get("addr_hex") or format_hex_addr(inst.get("addr"))
                run_total_size = int(inst.get("size") or 1)
                run_count = 1

        if run_count > 0:
            cls._flush_inst_run(folded, run_start_addr, run_raw_asm or run_op, run_count, run_total_size)

        return folded

    @classmethod
    def _flush_inst_run(
        cls,
        dest: List[Dict[str, Any]],
        start_addr: Optional[str],
        asm_text: Optional[str],
        count: int,
        total_size: int,
    ) -> None:
        if count >= 2:
            dest.append({
                "addr": start_addr,
                "asm": f"{asm_text} [folded: repeated x{count}]",
                "size": total_size,
                "count": count,
                "folded": True,
            })
        elif count == 1:
            dest.append({
                "addr": start_addr,
                "asm": asm_text,
                "size": total_size,
            })

    @classmethod
    def fold_memory_bytes(
        cls,
        data: Union[str, bytes, bytearray, List[int], Dict[str, Any]],
        min_run_length: int = 8,
        base_addr: Optional[int] = None,
    ) -> Any:
        """
        Run-length encode repetitive byte buffers (e.g. 0x00 zero pages, 0xFF padding).
        Supports hex strings, bytearrays, or int lists.
        """
        if isinstance(data, dict):
            d_copy = dict(data)
            for k in ("bytes", "hex", "data", "memory", "buffer"):
                if k in d_copy:
                    d_copy[k] = cls.fold_memory_bytes(d_copy[k], min_run_length=min_run_length, base_addr=base_addr)
            return d_copy

        if isinstance(data, str):
            clean = data.replace(" ", "").replace("\n", "").lower()
            if len(clean) % 2 != 0 or len(clean) < min_run_length * 2:
                return data
            chunks = [clean[i:i+2] for i in range(0, len(clean), 2)]
            runs: List[Dict[str, Any]] = []
            curr_byte = chunks[0]
            curr_len = 1
            curr_offset = 0

            def _make_str_run(b_val: str, c_len: int, off: int) -> Dict[str, Any]:
                r: Dict[str, Any] = {"offset": f"+0x{off:04x}"}
                if base_addr is not None:
                    r["addr"] = hex(base_addr + off)
                if c_len >= min_run_length:
                    r.update({"byte": f"0x{b_val}", "count": c_len})
                else:
                    r["hex"] = "".join([b_val] * c_len)
                return r

            for b in chunks[1:]:
                if b == curr_byte:
                    curr_len += 1
                else:
                    runs.append(_make_str_run(curr_byte, curr_len, curr_offset))
                    curr_offset += curr_len
                    curr_byte = b
                    curr_len = 1

            runs.append(_make_str_run(curr_byte, curr_len, curr_offset))

            if TokenEstimator.estimate_obj(runs) < TokenEstimator.count_tokens(data):
                return runs
            return data

        elif isinstance(data, (bytes, bytearray, list)):
            byte_list = list(data)
            if len(byte_list) < min_run_length:
                return data
            runs_list: List[Dict[str, Any]] = []
            curr_b = byte_list[0]
            curr_len = 1
            curr_offset = 0

            def _make_byte_run(b_val: Any, c_len: int, off: int) -> Dict[str, Any]:
                r: Dict[str, Any] = {"offset": f"+0x{off:04x}"}
                if base_addr is not None:
                    r["addr"] = hex(base_addr + off)
                b_str = f"0x{b_val:02x}" if isinstance(b_val, int) else str(b_val)
                if c_len >= min_run_length:
                    r.update({"byte": b_str, "count": c_len})
                else:
                    r["bytes"] = [b_val] * c_len
                return r

            for b in byte_list[1:]:
                if b == curr_b:
                    curr_len += 1
                else:
                    runs_list.append(_make_byte_run(curr_b, curr_len, curr_offset))
                    curr_offset += curr_len
                    curr_b = b
                    curr_len = 1

            runs_list.append(_make_byte_run(curr_b, curr_len, curr_offset))

            if TokenEstimator.estimate_obj(runs_list) < TokenEstimator.estimate_obj(data):
                return runs_list
            return data

        return data

    @classmethod
    def prune_decompile_comments(cls, code: str) -> str:
        """
        Strips redundant compiler artifact comments, DATA XREF notes, and blank lines
        from decompiled pseudo-C code while strictly preserving function signatures,
        branch logic, calls, and statements.
        """
        if not code:
            return ""
        lines = code.splitlines()
        pruned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("//") or (stripped.startswith("/*") and stripped.endswith("*/")):
                low = stripped.lower()
                if any(
                    tag in low
                    for tag in (
                        "callconv:", "data xref", "code xref", "-r-x", "section",
                        "stack var", "compiler generated", "[14]", "warning:", "decompiled",
                        "generated by", "local variable", "check input", "license"
                    )
                ):
                    continue
            pruned_lines.append(line)
        joined = "\n".join(pruned_lines)
        return re.sub(r"\n{3,}", "\n\n", joined).strip()

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculate byte Shannon entropy H in bits per character."""
        if not data:
            return 0.0
        length = len(data)
        freq: Dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)


class TriePrefixCompressor:
    """
    Deduplicates long address prefixes and hierarchical symbol namespaces
    using Longest Common Address Prefix (LCAP) factoring and prefix dictionaries.
    """
    @classmethod
    def compress_addresses(
        cls,
        items: List[Any],
        addr_keys: Tuple[str, ...] = ("addr", "jump", "fail"),
        min_prefix_len: int = 6,
        min_items: int = 4,
    ) -> Tuple[Optional[str], List[Any]]:
        """
        Computes LCAP across items and factors it out into a base prefix.
        Supports both list of dictionaries and list of string addresses.
        Returns (base_prefix, compacted_items).
        """
        if len(items) < min_items:
            return None, items

        is_str_list = len(items) > 0 and isinstance(items[0], str)
        addrs: List[str] = []
        if is_str_list:
            for item in items:
                if isinstance(item, str) and item.startswith("0x") and len(item) >= min_prefix_len:
                    addrs.append(item)
        else:
            for item in items:
                for k in addr_keys:
                    v = item.get(k)
                    if isinstance(v, str) and v.startswith("0x") and len(v) >= min_prefix_len:
                        addrs.append(v)

        if len(addrs) < min_items:
            return None, items

        prefix = addrs[0]
        for a in addrs[1:]:
            while not a.startswith(prefix):
                prefix = prefix[:-1]
                if len(prefix) < min_prefix_len:
                    return None, items

        if len(prefix) < min_prefix_len:
            return None, items

        if is_str_list:
            compacted_strs = [
                ("+" + item[len(prefix):] if isinstance(item, str) and item.startswith(prefix) else item)
                for item in items
            ]
            return prefix, compacted_strs

        compacted: List[Dict[str, Any]] = []
        for item in items:
            c = dict(item)
            for k in addr_keys:
                v = c.get(k)
                if isinstance(v, str) and v.startswith(prefix):
                    c[k] = "+" + v[len(prefix):]
            if "instructions" in c and isinstance(c["instructions"], list):
                insts_comp = []
                for inst in c["instructions"]:
                    ic = dict(inst)
                    ia = ic.get("addr")
                    if isinstance(ia, str) and ia.startswith(prefix):
                        ic["addr"] = "+" + ia[len(prefix):]
                    insts_comp.append(ic)
                c["instructions"] = insts_comp
            compacted.append(c)

        return prefix, compacted

    @classmethod
    def decompress_addresses(
        cls,
        base_prefix: Any,
        items: Optional[List[Any]] = None,
        addr_keys: Tuple[str, ...] = ("addr", "jump", "fail"),
    ) -> List[Any]:
        """Reverses LCAP factoring, restoring absolute addresses."""
        if items is None:
            if isinstance(base_prefix, tuple) and len(base_prefix) == 2:
                base_prefix, items = base_prefix
            elif isinstance(base_prefix, dict) and "prefix" in base_prefix:
                items = base_prefix.get("items", [])
                base_prefix = base_prefix.get("prefix")
            else:
                return base_prefix

        if not base_prefix:
            return items if items is not None else []

        if items and isinstance(items[0], str):
            return [
                (base_prefix + s[1:] if isinstance(s, str) and s.startswith("+") else s)
                for s in items
            ]

        decompressed: List[Dict[str, Any]] = []
        for item in items or []:
            c = dict(item)
            for k in addr_keys:
                v = c.get(k)
                if isinstance(v, str) and v.startswith("+"):
                    c[k] = base_prefix + v[1:]
            if "instructions" in c and isinstance(c["instructions"], list):
                insts_decomp = []
                for inst in c["instructions"]:
                    ic = dict(inst)
                    ia = ic.get("addr")
                    if isinstance(ia, str) and ia.startswith("+"):
                        ic["addr"] = base_prefix + ia[1:]
                    insts_decomp.append(ic)
                c["instructions"] = insts_decomp
            decompressed.append(c)
        return decompressed

    @classmethod
    def compress_symbols(
        cls,
        symbols: List[Any],
        name_key: str = "name",
        min_prefix_freq: int = 3,
        min_prefix_len: int = 4,
    ) -> Tuple[Dict[str, str], List[Any]]:
        """
        Identifies common symbol prefixes (e.g. 'sym.imp.', 'Lcom/example/')
        and extracts them into a prefix dictionary.
        Supports both list of dictionaries and list of string symbol names.
        Returns (prefix_dict, compacted_symbols).
        """
        if len(symbols) < min_prefix_freq:
            return {}, symbols

        is_str_list = len(symbols) > 0 and isinstance(symbols[0], str)
        delimiters = (".", "/", "::", "$")
        prefix_candidates: Dict[str, int] = {}

        for s in symbols:
            name = s if is_str_list else s.get(name_key)
            if not isinstance(name, str):
                continue
            for d in delimiters:
                if d in name:
                    prefix = name[:name.rfind(d) + len(d)]
                    if len(prefix) >= min_prefix_len:
                        prefix_candidates[prefix] = prefix_candidates.get(prefix, 0) + 1

        qualifying = {p: cnt for p, cnt in prefix_candidates.items() if cnt >= min_prefix_freq}
        if not qualifying:
            return {}, symbols

        sorted_prefixes = sorted(qualifying.keys(), key=lambda p: len(p) * qualifying[p], reverse=True)
        prefix_map: Dict[str, str] = {}
        reverse_map: Dict[str, str] = {}
        for idx, p in enumerate(sorted_prefixes[:5], 1):
            tag = f"$p{idx}"
            prefix_map[tag] = p
            reverse_map[p] = tag

        if is_str_list:
            compacted_strs = []
            for name in symbols:
                c_name = name
                for p, tag in reverse_map.items():
                    if name.startswith(p):
                        c_name = f"{tag}:{name[len(p):]}"
                        break
                compacted_strs.append(c_name)
            return prefix_map, compacted_strs

        compacted: List[Dict[str, Any]] = []
        for s in symbols:
            sc = dict(s)
            name = sc.get(name_key)
            if isinstance(name, str):
                for p, tag in reverse_map.items():
                    if name.startswith(p):
                        sc[name_key] = f"{tag}:{name[len(p):]}"
                        break
            compacted.append(sc)

        return prefix_map, compacted

    @classmethod
    def decompress_symbols(
        cls,
        prefix_map: Any,
        symbols: Optional[List[Any]] = None,
        name_key: str = "name",
    ) -> List[Any]:
        """Reverses symbol namespace factoring."""
        if symbols is None:
            if isinstance(prefix_map, tuple) and len(prefix_map) == 2:
                prefix_map, symbols = prefix_map
            elif isinstance(prefix_map, dict) and "namespaces" in prefix_map:
                symbols = prefix_map.get("symbols", [])
                prefix_map = prefix_map.get("namespaces", {})
            else:
                return prefix_map

        if not prefix_map:
            return symbols if symbols is not None else []

        if symbols and isinstance(symbols[0], str):
            decompressed_strs = []
            for name in symbols:
                d_name = name
                for tag, p in prefix_map.items():
                    if name.startswith(f"{tag}:"):
                        d_name = p + name[len(tag) + 1:]
                        break
                decompressed_strs.append(d_name)
            return decompressed_strs

        decompressed: List[Dict[str, Any]] = []
        for s in symbols or []:
            sc = dict(s)
            name = sc.get(name_key)
            if isinstance(name, str):
                for tag, p in prefix_map.items():
                    if name.startswith(f"{tag}:"):
                        sc[name_key] = p + name[len(tag) + 1:]
                        break
            decompressed.append(sc)
        return decompressed


class KnapsackOptimizer:
    """
    0/1 and fractional knapsack optimizer for reverse engineering telemetry.
    Maximizes information utility under a strict token budget B while preserving
    critical structural anchors (Entry block, Exit blocks, Branch Gates, Call Targets).
    Guarantees finite termination and budget invariant satisfaction.
    """
    _WEIGHT_CACHE: Dict[Tuple[int, Any], int] = {}

    @classmethod
    def _compute_item_key(cls, item: Any) -> Any:
        if not isinstance(item, dict):
            return id(item)
        addr = item.get("addr") or item.get("addr_hex") or item.get("vaddr") or item.get("offset")
        name = item.get("name") or item.get("string") or item.get("func_name")
        insts = item.get("instructions")
        inst_len = len(insts) if isinstance(insts, list) else 0
        if addr is not None or name is not None or inst_len > 0:
            return (addr, name, inst_len, len(item))
        return id(item)

    @staticmethod
    def select(
        items: List[Dict[str, Any]],
        budget: int,
        value_fn: Callable[[Dict[str, Any], int, int], float],
        mandatory_fn: Optional[Callable[[Dict[str, Any], int, int], bool]] = None,
        item_weight_fn: Optional[Callable[[Dict[str, Any]], int]] = None,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Selects items to maximize total utility within token budget.
        Returns (selected_items, is_truncated).
        """
        if not items:
            return [], False
        if budget <= 0:
            return [], True

        total_items = len(items)
        weight_func = item_weight_fn or TokenEstimator.estimate_obj

        mandatory_indices: List[int] = []
        optional_indices: List[int] = []
        weights: List[int] = []
        values: List[float] = []

        fn_id = id(weight_func)
        for idx, item in enumerate(items):
            item_key = KnapsackOptimizer._compute_item_key(item)
            cache_k = (fn_id, item_key)
            w = KnapsackOptimizer._WEIGHT_CACHE.get(cache_k)
            if w is None:
                w = max(1, weight_func(item))
                if len(KnapsackOptimizer._WEIGHT_CACHE) > 10000:
                    KnapsackOptimizer._WEIGHT_CACHE.clear()
                KnapsackOptimizer._WEIGHT_CACHE[cache_k] = w
            weights.append(w)
            v = max(0.1, value_fn(item, idx, total_items))
            values.append(v)
            is_mand = mandatory_fn(item, idx, total_items) if mandatory_fn else False
            if is_mand:
                mandatory_indices.append(idx)
            else:
                optional_indices.append(idx)

        used_weight = sum(weights[i] for i in mandatory_indices)
        selected_set: Set[int] = set()

        if used_weight <= budget:
            selected_set.update(mandatory_indices)
            remaining_budget = budget - used_weight

            # Rank optional items by value density (value / weight) descending
            ranked_optional = sorted(
                optional_indices,
                key=lambda i: values[i] / weights[i],
                reverse=True,
            )

            for i in ranked_optional:
                if weights[i] <= remaining_budget:
                    selected_set.add(i)
                    remaining_budget -= weights[i]
        else:
            # Fractional fallback: mandatory items themselves exceed budget
            ranked_mandatory = sorted(
                mandatory_indices,
                key=lambda i: values[i] / weights[i],
                reverse=True,
            )
            rem = budget
            for i in ranked_mandatory:
                if weights[i] <= rem:
                    selected_set.add(i)
                    rem -= weights[i]
            if not selected_set and mandatory_indices:
                selected_set.add(ranked_mandatory[0])

            if rem > 0:
                ranked_optional = sorted(
                    optional_indices,
                    key=lambda i: values[i] / weights[i],
                    reverse=True,
                )
                for i in ranked_optional:
                    if weights[i] <= rem:
                        selected_set.add(i)
                        rem -= weights[i]

        is_truncated = (len(selected_set) < total_items)
        result = [items[i] for i in range(total_items) if i in selected_set]
        return result, is_truncated


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
    budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Prune and paginate function list with knapsack budgeting."""
    if mode == "full":
        return data

    funcs = data.get("functions", [])
    total = len(funcs)

    if mode == "summary":
        top = sorted(
            funcs,
            key=lambda f: (f.get("cc") or f.get("cyclomatic_complexity") or 0, f.get("size") or f.get("sz") or 0),
            reverse=True,
        )[:5]
        top_list = [
            {
                "name": f.get("name"),
                "addr": f.get("addr") or f.get("offset_hex") or format_hex_addr(f.get("offset")),
                "size": f.get("size") if f.get("size") is not None else f.get("sz"),
                "cc": f.get("cc") if f.get("cc") is not None else f.get("cyclomatic_complexity"),
            }
            for f in top
        ]
        return {
            "total_functions": total,
            "total": total,
            "top_complex": top_list,
            "top": top_list,
        }

    # If budget is specified, apply KnapsackOptimizer
    if budget is not None:
        if budget <= 0:
            return {
                "total": total,
                "displayed": 0,
                "remaining": total,
                "truncated": True,
                "functions": [],
            }
        all_compact = []
        for f in funcs:
            item: Dict[str, Any] = {
                "name": f.get("name"),
                "addr": f.get("addr") or f.get("offset_hex") or format_hex_addr(f.get("offset")),
                "size": f.get("size") if f.get("size") is not None else f.get("sz"),
            }
            cc = f.get("cc") if f.get("cc") is not None else f.get("cyclomatic_complexity")
            if cc is not None:
                item["cc"] = cc
            blocks = f.get("blocks") if f.get("blocks") is not None else (f.get("bb") or f.get("num_basic_blocks"))
            if blocks is not None:
                item["blocks"] = blocks
            instrs = f.get("instrs") if f.get("instrs") is not None else (f.get("ins") or f.get("num_instructions"))
            if instrs is not None:
                item["instrs"] = instrs
            all_compact.append(item)

        def fn_val(f: Dict[str, Any], idx: int, total_f: int) -> float:
            name = (f.get("name") or "").lower()
            score = 10.0
            if name in ("main", "_start", "entry0") or "main" in name:
                score += 1000.0
            cc = f.get("cc") or 0
            score += cc * 50.0
            sz = f.get("size") or 0
            score += min(sz * 0.1, 100.0)
            return score

        def fn_mand(f: Dict[str, Any], idx: int, total_f: int) -> bool:
            name = (f.get("name") or "").lower()
            return name in ("main", "_start", "entry0")

        avail_budget = max(10, budget - 25)
        selected_funcs, is_truncated = KnapsackOptimizer.select(all_compact, avail_budget, fn_val, fn_mand)
        return {
            "total": total,
            "displayed": len(selected_funcs),
            "remaining": max(0, total - len(selected_funcs)),
            "truncated": is_truncated or (total > len(selected_funcs)),
            "functions": selected_funcs,
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
            "addr": f.get("addr") or f.get("offset_hex") or format_hex_addr(f.get("offset")),
            "size": f.get("size") if f.get("size") is not None else f.get("sz"),
        }
        cc = f.get("cc") if f.get("cc") is not None else f.get("cyclomatic_complexity")
        if cc is not None:
            item["cc"] = cc
        blocks = f.get("blocks") if f.get("blocks") is not None else (f.get("bb") or f.get("num_basic_blocks"))
        if blocks is not None:
            item["blocks"] = blocks
        instrs = f.get("instrs") if f.get("instrs") is not None else (f.get("ins") or f.get("num_instructions"))
        if instrs is not None:
            item["instrs"] = instrs
        compact_funcs.append(item)

    is_truncated = (total > len(compact_funcs)) or effective_offset > 0
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
    budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Prune and paginate basic blocks and instructions with entropy pruning and knapsack budgeting."""
    if mode == "full":
        return data

    blocks = data.get("blocks", [])
    total = len(blocks)
    fn_name = data.get("function") or data.get("function_name")
    fn_addr = data.get("addr") or data.get("function_addr_hex") or format_hex_addr(data.get("function_addr"))

    if mode == "summary":
        entry_b = blocks[0] if blocks else {}
        return {
            "function": fn_name,
            "addr": fn_addr,
            "total_blocks": total,
            "entry": entry_b.get("addr") if isinstance(entry_b.get("addr"), str) and entry_b.get("addr").startswith("0x") else (entry_b.get("addr_hex") or format_hex_addr(entry_b.get("addr"))),
        }

    # Helper to compact block instructions with EntropyPruner RLE folding
    def compact_block_entry(b: Dict[str, Any], max_inst_limit: Optional[int] = None) -> Dict[str, Any]:
        insts = b.get("instructions", [])
        effective_max = max_instructions if max_instructions is not None else max_inst_limit
        if effective_max is not None:
            try:
                insts = insts[:int(effective_max)]
            except (ValueError, TypeError):
                pass

        # Apply repetition folding on NOP sleds and padding
        folded_insts = EntropyPruner.fold_instruction_stream(insts)

        compact_insts = []
        for i in folded_insts:
            ci: Dict[str, Any] = {
                "addr": i.get("addr") if isinstance(i.get("addr"), str) and i.get("addr").startswith("0x") else (i.get("addr_hex") or format_hex_addr(i.get("addr"))),
                "asm": i.get("asm") or i.get("disasm") or i.get("opcode"),
            }
            if mode != "compact" and i.get("size") is not None:
                ci["size"] = i.get("size")
            compact_insts.append(ci)

        b_addr = b.get("addr") if isinstance(b.get("addr"), str) and b.get("addr").startswith("0x") else (b.get("addr_hex") or format_hex_addr(b.get("addr")))
        b_dict: Dict[str, Any] = {
            "addr": b_addr,
            "size": b.get("size"),
            "instructions": compact_insts,
        }
        jump_addr = b.get("jump") if isinstance(b.get("jump"), str) and b.get("jump").startswith("0x") else (b.get("jump_hex") or format_hex_addr(b.get("jump")))
        fail_addr = b.get("fail") if isinstance(b.get("fail"), str) and b.get("fail").startswith("0x") else (b.get("fail_hex") or format_hex_addr(b.get("fail")))
        if jump_addr:
            b_dict["jump"] = jump_addr
        if fail_addr:
            b_dict["fail"] = fail_addr
        return b_dict

    # Budgeted Knapsack Optimization path
    if budget is not None:
        if budget <= 0:
            return {
                "function": fn_name,
                "addr": fn_addr,
                "total": total,
                "displayed": 0,
                "remaining": total,
                "truncated": True,
                "blocks": [],
            }
        empty_skel = {
            "function": fn_name,
            "addr": fn_addr,
            "total": total,
            "displayed": 0,
            "remaining": total,
            "truncated": True,
            "blocks": [],
        }
        meta_cost = TokenEstimator.estimate_obj(empty_skel) + 95
        avail_budget = max(10, budget - meta_cost)
        compact_blocks = [compact_block_entry(b, max_inst_limit=max_instructions) for b in blocks]

        def block_val(b: Dict[str, Any], idx: int, total_b: int) -> float:
            score = 50.0
            if idx == 0:
                score += 100000.0  # Entry anchor absolute dominance
            insts = b.get("instructions", [])
            has_ret = any((i.get("asm") or "").lower().startswith("ret") for i in insts)
            if has_ret or idx == total_b - 1:
                score += 800.0   # Exit anchor
            if b.get("fail") or any((i.get("asm") or "").lower().startswith(("j", "b.")) for i in insts):
                score += 500.0   # Branch gate
            if any((i.get("asm") or "").lower().startswith("call") for i in insts):
                score += 350.0   # Call site
            if any((i.get("asm") or "").lower().startswith(("cmp", "test")) for i in insts):
                score += 200.0   # Comparison
            score += min(len(insts) * 2.0, 50.0)
            return score

        def block_mand(b: Dict[str, Any], idx: int, total_b: int) -> bool:
            return idx == 0

        selected_blocks, is_truncated = KnapsackOptimizer.select(compact_blocks, avail_budget, block_val, block_mand)

        # Apply address LCAP factoring if it yields token reduction
        lcap_prefix, lcap_blocks = TriePrefixCompressor.compress_addresses(selected_blocks)
        if lcap_prefix and TokenEstimator.estimate_obj(lcap_blocks) < TokenEstimator.estimate_obj(selected_blocks):
            res_blocks = lcap_blocks
            use_lcap = True
        else:
            res_blocks = selected_blocks
            use_lcap = False

        res: Dict[str, Any] = {
            "function": fn_name,
            "addr": fn_addr,
            "total": total,
            "displayed": len(res_blocks),
            "remaining": max(0, total - len(res_blocks)),
            "truncated": is_truncated or (total > len(res_blocks)),
            "blocks": res_blocks,
        }
        if use_lcap and lcap_prefix:
            res["addr_base"] = lcap_prefix
        return res

    # Standard pagination path (budget is None)
    try:
        effective_limit = int(limit) if limit is not None else 30
    except (ValueError, TypeError):
        effective_limit = 30
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0

    sliced = blocks[effective_offset : effective_offset + effective_limit]
    compact_blocks = [compact_block_entry(b) for b in sliced]

    is_truncated = (total > len(compact_blocks)) or effective_offset > 0
    if not is_truncated and effective_offset == 0:
        return {
            "function": fn_name,
            "addr": fn_addr,
            "total": total,
            "blocks": compact_blocks,
        }

    res = {
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
    budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Prune and paginate string discovery tables with entropy ranking and knapsack budgeting."""
    if mode == "full":
        return data

    raw = data.get("strings", [])
    if isinstance(raw, dict):
        raw_strings = [{"addr": k, "string": v} for k, v in raw.items()]
    elif isinstance(raw, list):
        raw_strings = raw
    else:
        raw_strings = []
    total = len(raw_strings)

    if mode == "summary":
        return {
            "total": total,
            "sample": [s.get("string") for s in raw_strings[:10]],
        }

    # If budget is specified, apply KnapsackOptimizer with Shannon entropy weighting
    if budget is not None:
        if budget <= 0:
            return {
                "total": total,
                "displayed": 0,
                "remaining": total,
                "truncated": True,
                "strings": [],
            }
        compact_all = [
            {
                "addr": s.get("addr") or s.get("vaddr_hex") or format_hex_addr(s.get("vaddr")),
                "string": s.get("string"),
            }
            for s in raw_strings
        ]

        def str_val(s: Dict[str, Any], idx: int, total_s: int) -> float:
            text = s.get("string") or ""
            ent = EntropyPruner.shannon_entropy(text)
            score = 20.0 + ent * 30.0
            lower = text.lower()
            if any(k in lower for k in ("http", "flag", "key", "pass", "token", "auth", "secret", "user", "admin", "bin", "etc", ".so", "libc", "%s", "%d")):
                score += 300.0
            score += min(len(text) * 0.5, 50.0)
            return score

        avail_budget = max(10, budget - 25)
        selected_strings, is_truncated = KnapsackOptimizer.select(compact_all, avail_budget, str_val)
        return {
            "total": total,
            "displayed": len(selected_strings),
            "remaining": max(0, total - len(selected_strings)),
            "truncated": is_truncated or (total > len(selected_strings)),
            "strings": selected_strings,
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
            "addr": s.get("addr") or s.get("vaddr_hex") or format_hex_addr(s.get("vaddr")),
            "string": s.get("string"),
        }
        for s in sliced
    ]

    is_truncated = (total > len(compact_strings)) or effective_offset > 0
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
    budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Prune and paginate symbol tables with prefix compression and knapsack budgeting."""
    if mode == "full":
        return data

    raw_symbols = data.get("symbols", [])
    if not isinstance(raw_symbols, list):
        raw_symbols = []
    total = len(raw_symbols)

    if mode == "summary":
        return {
            "total": total,
            "sample": [s.get("name") for s in raw_symbols[:10]],
        }

    if budget is not None:
        if budget <= 0:
            return {
                "total": total,
                "displayed": 0,
                "remaining": total,
                "truncated": True,
                "symbols": [],
            }
        compact_all = []
        for s in raw_symbols:
            sym_dict: Dict[str, Any] = {
                "name": s.get("name"),
                "addr": s.get("addr") or s.get("vaddr_hex") or format_hex_addr(s.get("vaddr")),
                "type": s.get("type") or s.get("sym_type") or s.get("t"),
            }
            if s.get("bind"):
                sym_dict["bind"] = s.get("bind")
            compact_all.append(sym_dict)

        def sym_val(s: Dict[str, Any], idx: int, total_s: int) -> float:
            name = (s.get("name") or "").lower()
            score = 20.0
            if name in ("main", "_start", "entry0") or "main" in name:
                score += 800.0
            if any(k in name for k in ("imp.", "sym.", "crypt", "flag", "auth", "token", "exec", "system")):
                score += 200.0
            return score

        avail_budget = max(10, budget - 25)
        selected_symbols, is_truncated = KnapsackOptimizer.select(compact_all, avail_budget, sym_val)

        prefix_map, factored_symbols = TriePrefixCompressor.compress_symbols(selected_symbols)
        if prefix_map and TokenEstimator.estimate_obj(factored_symbols) < TokenEstimator.estimate_obj(selected_symbols):
            res_syms = factored_symbols
            use_prefixes = True
        else:
            res_syms = selected_symbols
            use_prefixes = False

        res_dict: Dict[str, Any] = {
            "total": total,
            "displayed": len(res_syms),
            "remaining": max(0, total - len(res_syms)),
            "truncated": is_truncated or (total > len(res_syms)),
            "symbols": res_syms,
        }
        if use_prefixes and prefix_map:
            res_dict["prefixes"] = prefix_map
        return res_dict

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
            "addr": s.get("addr") or s.get("vaddr_hex") or format_hex_addr(s.get("vaddr")),
            "type": s.get("type") or s.get("sym_type") or s.get("t"),
        }
        if s.get("bind"):
            sym_dict["bind"] = s.get("bind")
        compact_symbols.append(sym_dict)

    is_truncated = (total > len(compact_symbols)) or effective_offset > 0
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


def prune_modules(
    data: Dict[str, Any],
    mode: OutputMode,
    limit: Optional[int] = None,
    offset: int = 0,
) -> Dict[str, Any]:
    """Prune and paginate loaded module lists."""
    if mode == "full":
        return data

    raw_modules = data.get("modules", [])
    if not isinstance(raw_modules, list):
        raw_modules = []
    total = len(raw_modules)

    if mode == "summary":
        return {
            "total": total,
            "sample": [m.get("name") if isinstance(m, dict) else str(m) for m in raw_modules[:10]],
        }

    try:
        effective_limit = int(limit) if limit is not None else 30
    except (ValueError, TypeError):
        effective_limit = 30
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0

    sliced = raw_modules[effective_offset : effective_offset + effective_limit]
    compact_modules = []
    for m in sliced:
        if isinstance(m, dict):
            mod_dict: Dict[str, Any] = {
                "name": m.get("name"),
                "base": m.get("base"),
                "size": m.get("size"),
            }
            if m.get("path"):
                mod_dict["path"] = m.get("path")
            compact_modules.append(mod_dict)
        else:
            compact_modules.append({"name": str(m)})

    is_truncated = (total > len(compact_modules)) or effective_offset > 0
    if not is_truncated and effective_offset == 0:
        return {
            "total": total,
            "modules": compact_modules,
        }

    res: Dict[str, Any] = {
        "total": total,
        "displayed": len(compact_modules),
        "remaining": max(0, total - (effective_offset + len(compact_modules))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_modules)),
        "has_more": total > (effective_offset + len(compact_modules)),
        "modules": compact_modules,
    }
    if total > (effective_offset + len(compact_modules)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_modules)} to retrieve next slice."
        )
    return res


def prune_classes(
    data: Dict[str, Any],
    mode: OutputMode,
    limit: Optional[int] = None,
    offset: int = 0,
) -> Dict[str, Any]:
    """Prune and paginate class enumeration tables."""
    if mode == "full":
        return data

    raw_classes = data.get("classes", [])
    if not isinstance(raw_classes, list):
        raw_classes = []
    total = len(raw_classes)

    if mode == "summary":
        sample = [c if isinstance(c, str) else c.get("name") for c in raw_classes[:10]]
        return {
            "total": total,
            "sample": sample,
        }

    try:
        effective_limit = int(limit) if limit is not None else 50
    except (ValueError, TypeError):
        effective_limit = 50
    try:
        effective_offset = int(offset) if offset is not None else 0
    except (ValueError, TypeError):
        effective_offset = 0

    sliced = raw_classes[effective_offset : effective_offset + effective_limit]
    compact_classes = []
    for c in sliced:
        if isinstance(c, str):
            compact_classes.append(c)
        elif isinstance(c, dict):
            cls_dict: Dict[str, Any] = {"name": c.get("name")}
            if c.get("methods"):
                cls_dict["methods"] = c.get("methods")
            compact_classes.append(cls_dict)

    is_truncated = (total > len(compact_classes)) or effective_offset > 0
    if not is_truncated and effective_offset == 0:
        return {
            "total": total,
            "classes": compact_classes,
        }

    res: Dict[str, Any] = {
        "total": total,
        "displayed": len(compact_classes),
        "remaining": max(0, total - (effective_offset + len(compact_classes))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_classes)),
        "has_more": total > (effective_offset + len(compact_classes)),
        "classes": compact_classes,
    }
    if total > (effective_offset + len(compact_classes)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_classes)} to retrieve next slice."
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
        xref_item: Dict[str, Any] = {
            "from": x.get("from_addr_hex") or format_hex_addr(x.get("from_addr")) or x.get("from"),
            "from_fn": x.get("from_function") or x.get("from_name"),
            "to": x.get("to_addr_hex") or format_hex_addr(x.get("to_addr")) or x.get("to"),
            "to_fn": x.get("to_function") or x.get("to_name"),
            "type": x.get("xref_type") or x.get("type"),
        }
        if x.get("opcode"):
            xref_item["op"] = x.get("opcode")
        compact_xrefs.append(xref_item)

    is_truncated = (total > len(compact_xrefs)) or effective_offset > 0
    target_addr = data.get("target_addr_hex") or format_hex_addr(data.get("target_addr"))
    if not is_truncated and effective_offset == 0:
        ret_dict: Dict[str, Any] = {
            "target": data.get("target"),
            "total": total,
            "xrefs": compact_xrefs,
        }
        if target_addr is not None:
            ret_dict["addr"] = target_addr
        return ret_dict

    res: Dict[str, Any] = {
        "target": data.get("target"),
        "total": total,
        "displayed": len(compact_xrefs),
        "remaining": max(0, total - (effective_offset + len(compact_xrefs))),
        "offset": effective_offset,
        "limit": effective_limit,
        "truncated": total > (effective_offset + len(compact_xrefs)),
        "has_more": total > (effective_offset + len(compact_xrefs)),
        "xrefs": compact_xrefs,
    }
    if target_addr is not None:
        res["addr"] = target_addr
    if total > (effective_offset + len(compact_xrefs)):
        res["continuation_hint"] = (
            f"Use limit={effective_limit} offset={effective_offset + len(compact_xrefs)} to retrieve next slice."
        )
    return res


def prune_flow(data: Dict[str, Any], mode: OutputMode, budget: Optional[int] = None) -> Dict[str, Any]:
    """Prune control-flow branch gates and loop structures with knapsack budgeting."""
    if mode == "full":
        return data

    nodes = data.get("gates") or data.get("decision_nodes", [])
    fn_name = data.get("fn") or data.get("function_name")
    fn_addr = data.get("addr") or data.get("function_addr_hex") or format_hex_addr(data.get("function_addr"))

    if mode == "summary":
        return {
            "function": fn_name,
            "addr": fn_addr,
            "total_blocks": data.get("total_blocks") or data.get("blocks"),
            "decision_gates_count": len(nodes),
            "loops": data.get("loop_count") or data.get("loops", 0),
        }

    compact_nodes = []
    for n in nodes:
        compact_nodes.append({
            "addr": n.get("addr") or n.get("addr_hex") or format_hex_addr(n.get("addr")),
            "cond": n.get("cond") or n.get("condition_instruction"),
            "branch": n.get("branch") or n.get("branch_instruction"),
            "jump": n.get("jump") or n.get("jump_target_hex") or format_hex_addr(n.get("jump_target")),
            "fail": n.get("fail") or n.get("fail_target_hex") or format_hex_addr(n.get("fail_target")),
            "type": n.get("type") or n.get("gate_type"),
        })

    exits = [
        format_hex_addr(e) if isinstance(e, int) else str(e)
        for e in (data.get("exit_nodes") or data.get("exits", []))
    ]

    if budget is not None:
        if budget <= 0:
            return {
                "function": fn_name,
                "addr": fn_addr,
                "total_blocks": data.get("total_blocks"),
                "loops": data.get("loops", 0),
                "decision_gates_count": 0,
                "truncated": True,
                "gates": [],
                "exits": exits,
            }
        meta_cost = TokenEstimator.estimate_obj({
            "function": fn_name,
            "addr": fn_addr,
            "total_blocks": data.get("total_blocks"),
            "loops": data.get("loops", 0),
            "exits": exits,
        }) + 20
        avail_budget = max(10, budget - meta_cost)

        def gate_val(g: Dict[str, Any], idx: int, total_g: int) -> float:
            score = 50.0
            gtype = (g.get("type") or "").lower()
            if "loop" in gtype:
                score += 500.0
            if "switch" in gtype or "indirect" in gtype:
                score += 400.0
            if g.get("fail") and g.get("jump"):
                score += 300.0
            return score

        selected_nodes, is_truncated = KnapsackOptimizer.select(compact_nodes, avail_budget, gate_val)
        return {
            "function": fn_name,
            "addr": fn_addr,
            "total_blocks": data.get("total_blocks") or data.get("blocks"),
            "loops": data.get("loop_count") or data.get("loops", 0),
            "decision_nodes": selected_nodes,
            "exits": exits,
            "truncated": is_truncated or (len(compact_nodes) > len(selected_nodes)),
        }

    return {
        "function": fn_name,
        "addr": fn_addr,
        "total_blocks": data.get("total_blocks") or data.get("blocks"),
        "loops": data.get("loop_count") or data.get("loops", 0),
        "decision_nodes": compact_nodes,
        "exits": exits,
    }


def prune_decompile(
    data: Dict[str, Any],
    mode: OutputMode,
    max_lines: int = 120,
    budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Prune pseudo-C decompilation output with comment stripping and structural budgeting."""
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

    raw_code = data.get("pseudo_c", "")
    code = EntropyPruner.prune_decompile_comments(raw_code)

    if budget is not None:
        if budget <= 0:
            return {
                "function": fn_name,
                "addr": fn_addr,
                "size": data.get("size"),
                "blocks": data.get("blocks_count"),
                "calls": [],
                "strings": [],
                "truncated": True,
                "code": "// [budget truncated: 0 tokens]",
                "pseudo_c": "// [budget truncated: 0 tokens]",
            }
        meta_cost = TokenEstimator.estimate_obj({
            "function": fn_name,
            "addr": fn_addr,
            "size": data.get("size"),
            "blocks": data.get("blocks_count"),
            "calls": data.get("calls", []),
            "strings": data.get("strings_referenced", []),
        }) + 95
        code_budget = max(15, budget - meta_cost)
        if TokenEstimator.count_tokens(code) <= code_budget:
            truncated_code = code
            is_trunc = False
        else:
            is_trunc = True
            lines = code.splitlines()
            if len(lines) <= 2:
                truncated_code = code
            else:
                selected_lines = []
                selected_lines.append((0, lines[0]))
                if len(lines) > 1 and lines[-1].strip() == "}":
                    selected_lines.append((len(lines) - 1, lines[-1]))

                for idx, line in enumerate(lines[1:-1], 1):
                    s = line.strip().lower()
                    if any(s.startswith(k) for k in ("if", "else", "while", "for", "switch", "case", "return", "goto", "loc_")):
                        selected_lines.append((idx, line))
                    elif any(c in s for c in ("(", ")")) and not s.startswith("//"):
                        selected_lines.append((idx, line))

                selected_lines.sort(key=lambda x: x[0])
                kept = []
                omitted_count = 0
                last_idx = -1
                for idx, line in selected_lines:
                    candidate = "\n".join(kept + [line])
                    if TokenEstimator.count_tokens(candidate) <= code_budget:
                        if last_idx != -1 and idx > last_idx + 1:
                            kept.append(f"    // ... [{idx - last_idx - 1} lines omitted by budget] ...")
                        kept.append(line)
                        last_idx = idx
                    else:
                        omitted_count += 1

                if not kept:
                    kept = [lines[0], "    // ... [body omitted by budget] ..."]
                    if lines[-1].strip() == "}":
                        kept.append("}")
                elif omitted_count > 0:
                    kept.append(f"    // ... [{omitted_count} lines omitted by budget] ...")
                truncated_code = "\n".join(kept)

        return {
            "function": fn_name,
            "addr": fn_addr,
            "size": data.get("size"),
            "blocks": data.get("blocks_count"),
            "calls": data.get("calls", []),
            "strings": data.get("strings_referenced", []),
            "pseudo_c": truncated_code,
            "truncated": is_trunc,
        }

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


def prune_memory(
    data: Dict[str, Any],
    mode: OutputMode,
    budget: Optional[int] = None,
) -> Dict[str, Any]:
    """Prune and run-length encode raw memory and buffer dumps."""
    if mode == "full":
        return data

    res = dict(data)
    for k in ("bytes", "hex", "data", "memory", "buffer", "dump"):
        if k in res:
            res[k] = EntropyPruner.fold_memory_bytes(res[k])

    if budget is not None and budget > 0:
        if TokenEstimator.estimate_obj(res) > budget:
            for k in ("bytes", "hex", "data", "memory", "buffer", "dump"):
                if k in res:
                    val = res[k]
                    if isinstance(val, list) and len(val) > 2:
                        while len(val) > 2 and TokenEstimator.estimate_obj(res) > budget:
                            val.pop()
                    elif isinstance(val, str) and len(val) > 16:
                        cutoff = max(8, len(val) // 2)
                        res[k] = val[:cutoff] + "...[truncated]"
    return res


def prune_triage(data: Dict[str, Any], mode: OutputMode) -> Dict[str, Any]:
    """Prune high-level reconnaissance and triage summary."""
    if mode == "full":
        return data

    entry_hex = data.get("entry") or data.get("entry_point_hex") or format_hex_addr(data.get("entry_point"))
    sec = data.get("security", {})
    sec_compact = sec if isinstance(sec, list) else [
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

    top_funcs = []
    for f in data.get("top_functions", [])[:5]:
        tf: Dict[str, Any] = {
            "name": f.get("name"),
            "addr": f.get("addr_hex") or format_hex_addr(f.get("addr")),
        }
        if f.get("size") is not None:
            tf["size"] = f.get("size")
        if f.get("complexity") is not None:
            tf["cc"] = f.get("complexity")
        if f.get("num_blocks") is not None:
            tf["blocks"] = f.get("num_blocks")
        top_funcs.append(tf)

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
    ret = data.get("return_value") or data.get("ret")
    if ret:
        if isinstance(ret, dict):
            res["ret"] = {
                "reg": ret.get("reg") or ret.get("register"),
                "val": ret.get("val") or ret.get("value_hex") or format_hex_addr(ret.get("value")),
            }
        else:
            res["ret"] = ret

    raw_diff = data.get("register_diff") or data.get("diff") or data.get("key_registers_changed") or []
    clean_diff = []
    for d in raw_diff:
        reg = d.get("reg")
        from_val = d.get("from") or d.get("before_hex") or format_hex_addr(d.get("before"))
        to_val = d.get("to") or d.get("after_hex") or format_hex_addr(d.get("after"))
        if reg in ("rip", "eip", "pc"):
            continue
        clean_diff.append({"reg": reg, "from": from_val, "to": to_val})
    res["diff"] = clean_diff

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
        step_addr = s.get("addr") if isinstance(s.get("addr"), str) and s.get("addr").startswith("0x") else (s.get("addr_hex") or format_hex_addr(s.get("addr")))
        raw_diff = s.get("reg_changes") or s.get("diff") or []
        clean_diff = []
        for d in raw_diff:
            reg = d.get("reg")
            from_val = d.get("from") or d.get("before_hex") or format_hex_addr(d.get("before"))
            to_val = d.get("to") or d.get("after_hex") or format_hex_addr(d.get("after"))
            if reg in ("rip", "eip", "pc") and (to_val == step_addr or from_val == step_addr):
                continue
            clean_diff.append({"reg": reg, "from": from_val, "to": to_val})

        step_entry: Dict[str, Any] = {
            "step": s.get("step"),
            "addr": step_addr,
            "asm": s.get("asm") or s.get("disasm") or s.get("opcode"),
        }
        if clean_diff:
            step_entry["diff"] = clean_diff
        compact_steps.append(step_entry)

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


def _apply_termination_guard(env: ApiResponseDict, budget: int) -> ApiResponseDict:
    """
    Strict finite termination guard ensuring 0 <= Tokens(env) <= max(budget, B_min).
    Iteratively pops lowest utility items from data structures until budget invariant is satisfied.
    """
    current_tokens = TokenEstimator.estimate_obj(env)
    if current_tokens <= budget:
        env["token_estimate"] = current_tokens
        return env

    env["truncated"] = True
    data = env.get("data")

    # If data is a dict containing collections
    if isinstance(data, dict):
        if budget <= 0:
            collapsed: Dict[str, Any] = {"truncated": True, "note": "Budget exhausted"}
            for lk in ["blocks", "functions", "strings", "symbols", "decision_nodes", "gates", "callers", "callees", "data_refs", "xrefs", "modules", "classes"]:
                if lk in data and isinstance(data[lk], list):
                    collapsed[lk] = []
            env["data"] = collapsed
            env["token_estimate"] = TokenEstimator.estimate_obj(env)
            return env

        # 1. Truncate list fields in data via bisection
        list_keys = ["blocks", "functions", "strings", "symbols", "decision_nodes", "gates", "callers", "callees", "data_refs", "xrefs", "modules", "classes"]
        for lk in list_keys:
            if lk in data and isinstance(data[lk], list):
                items = data[lk]
                if lk == "blocks":
                    # Fine-grained instruction trimming from non-entry blocks first (bisection search)
                    if len(items) > 1 and TokenEstimator.estimate_obj(env) > budget:
                        orig_blocks = list(items)
                        # Check if block 0 alone exceeds budget
                        data["blocks"] = [dict(orig_blocks[0])]
                        if TokenEstimator.estimate_obj(env) > budget:
                            data["blocks"] = [dict(orig_blocks[0])]
                            items = data["blocks"]
                        else:
                            # Binary search for block boundary k in 1..len(orig_blocks)
                            low_b = 1
                            high_b = len(orig_blocks)
                            best_k = 1
                            while low_b <= high_b:
                                mid = (low_b + high_b) // 2
                                data["blocks"] = [dict(b) for b in orig_blocks[:mid]]
                                if TokenEstimator.estimate_obj(env) <= budget:
                                    best_k = mid
                                    low_b = mid + 1
                                else:
                                    high_b = mid - 1

                            # If a boundary block exists, fine-tune its instructions with bisection
                            if best_k < len(orig_blocks):
                                cand_b = dict(orig_blocks[best_k])
                                cand_insts = list(cand_b.get("instructions", []))
                                if cand_insts:
                                    low_i = 1
                                    high_i = len(cand_insts)
                                    best_i = 0
                                    while low_i <= high_i:
                                        mid_i = (low_i + high_i) // 2
                                        cand_b["instructions"] = list(cand_insts[:mid_i])
                                        data["blocks"] = [dict(b) for b in orig_blocks[:best_k]] + [cand_b]
                                        if TokenEstimator.estimate_obj(env) <= budget:
                                            best_i = mid_i
                                            low_i = mid_i + 1
                                        else:
                                            high_i = mid_i - 1
                                    if best_i > 0:
                                        cand_b["instructions"] = list(cand_insts[:best_i])
                                        data["blocks"] = [dict(b) for b in orig_blocks[:best_k]] + [cand_b]
                                    else:
                                        data["blocks"] = [dict(b) for b in orig_blocks[:best_k]]
                                else:
                                    data["blocks"] = [dict(b) for b in orig_blocks[:best_k]]
                            else:
                                data["blocks"] = [dict(b) for b in orig_blocks[:best_k]]
                            items = data["blocks"]

                    # Fine-grained instruction trimming on the entry block (items[0])
                    if len(items) == 1 and isinstance(items[0], dict) and TokenEstimator.estimate_obj(env) > budget:
                        b0 = items[0]
                        b0_insts = list(b0.get("instructions", []))
                        if b0_insts:
                            low_i = 0
                            high_i = len(b0_insts)
                            best_i = 0
                            while low_i <= high_i:
                                mid_i = (low_i + high_i) // 2
                                b0["instructions"] = list(b0_insts[:mid_i])
                                if TokenEstimator.estimate_obj(env) <= budget:
                                    best_i = mid_i
                                    low_i = mid_i + 1
                                else:
                                    high_i = mid_i - 1
                            b0["instructions"] = list(b0_insts[:best_i])

                        # If still over budget, trim optional jump/fail/size before dropping entry block
                        if TokenEstimator.estimate_obj(env) > budget:
                            for opt_field in ("fail", "jump", "size"):
                                if opt_field in b0:
                                    del b0[opt_field]
                                    if TokenEstimator.estimate_obj(env) <= budget:
                                        break

                        # If still exceeding budget, drop entry block as last resort
                        if TokenEstimator.estimate_obj(env) > budget:
                            items.pop()
                    elif len(items) > 1 and TokenEstimator.estimate_obj(env) > budget:
                        while items and TokenEstimator.estimate_obj(env) > budget:
                            items.pop()
                else:
                    if items and TokenEstimator.estimate_obj(env) > budget:
                        orig_items = list(items)
                        low = 0
                        high = len(orig_items) - 1
                        best_k = 0
                        while low <= high:
                            mid = (low + high) // 2
                            data[lk] = list(orig_items[:mid])
                            if TokenEstimator.estimate_obj(env) <= budget:
                                best_k = mid
                                low = mid + 1
                            else:
                                high = mid - 1
                        data[lk] = list(orig_items[:best_k])
                        items = data[lk]

                if "displayed" in data and isinstance(data["displayed"], int):
                    data["displayed"] = len(items)

        # 2. Truncate pseudo_c if present (bisection line trimming)
        if "pseudo_c" in data and isinstance(data["pseudo_c"], str):
            code_lines = data["pseudo_c"].splitlines()
            trunc_marker = "// ... [budget truncated] ..."
            lines_clean = [l for l in code_lines if trunc_marker not in l]
            if lines_clean and TokenEstimator.estimate_obj(env) > budget:
                low = 1
                high = len(lines_clean)
                best_l = 0
                while low <= high:
                    mid = (low + high) // 2
                    data["pseudo_c"] = "\n".join(lines_clean[:mid]) + f"\n    {trunc_marker}"
                    if TokenEstimator.estimate_obj(env) <= budget:
                        best_l = mid
                        low = mid + 1
                    else:
                        high = mid - 1
                if best_l > 0:
                    data["pseudo_c"] = "\n".join(lines_clean[:best_l]) + f"\n    {trunc_marker}"
                else:
                    data["pseudo_c"] = "// [budget truncated: 0 tokens]"
            if TokenEstimator.estimate_obj(env) > budget and lines_clean:
                data["pseudo_c"] = "// [budget truncated: 0 tokens]"

        # 3. If still exceeding budget, collapse data to minimal marker
        if TokenEstimator.estimate_obj(env) > budget:
            collapsed = {"truncated": True, "note": "Budget exhausted"}
            for lk in ["blocks", "functions", "strings", "symbols", "decision_nodes", "gates", "callers", "callees", "data_refs", "xrefs", "modules", "classes"]:
                if lk in data and isinstance(data[lk], list):
                    collapsed[lk] = []
            env["data"] = collapsed

    env["token_estimate"] = TokenEstimator.estimate_obj(env)
    return env


def _transform_single_budget(
    resp_envelope: Dict[str, Any],
    mode: OutputMode = "compact",
    limit: Optional[int] = None,
    offset: int = 0,
    max_lines: int = 120,
    max_instructions: Optional[int] = None,
    budget: Optional[int] = None,
) -> ApiResponseDict:
    """Single-budget transformation helper without envelope preservation."""
    if not resp_envelope.get("success") or "data" not in resp_envelope:
        out = dict(resp_envelope)
        out["token_estimate"] = TokenEstimator.estimate_obj(resp_envelope)
        return out  # type: ignore

    raw_data = resp_envelope.get("data")
    original_tokens: Optional[int] = None
    if raw_data is not None:
        original_tokens = TokenEstimator.estimate_obj(raw_data)

    if mode == "full":
        out = dict(resp_envelope)
        out["token_estimate"] = TokenEstimator.estimate_obj(resp_envelope)
        if original_tokens is not None:
            out["original_tokens"] = original_tokens
        if budget is not None:
            out["budget"] = max(0, budget)
            out = _apply_termination_guard(out, budget)
        return out  # type: ignore

    if not isinstance(raw_data, dict):
        out = dict(resp_envelope)
        out["token_estimate"] = TokenEstimator.estimate_obj(resp_envelope)
        if original_tokens is not None:
            out["original_tokens"] = original_tokens
        if budget is not None:
            out["budget"] = max(0, budget)
            out = _apply_termination_guard(out, budget)
        return out  # type: ignore

    cmd = resp_envelope.get("command", "").lower()
    transformed_data: Dict[str, Any]

    if "info" in cmd:
        transformed_data = prune_info(raw_data, mode)
    elif "functions" in cmd or "funcs" in cmd:
        transformed_data = prune_functions(raw_data, mode, limit=limit, offset=offset, budget=budget)
    elif "blocks" in cmd or "disasm" in cmd:
        transformed_data = prune_blocks(
            raw_data, mode, limit=limit, offset=offset, max_instructions=max_instructions, budget=budget
        )
    elif "strings" in cmd:
        transformed_data = prune_strings(raw_data, mode, limit=limit, offset=offset, budget=budget)
    elif "modules" in cmd:
        transformed_data = prune_modules(raw_data, mode, limit=limit, offset=offset)
    elif "classes" in cmd:
        transformed_data = prune_classes(raw_data, mode, limit=limit, offset=offset)
    elif "symbols" in cmd:
        transformed_data = prune_symbols(raw_data, mode, limit=limit, offset=offset, budget=budget)
    elif "flow" in cmd:
        transformed_data = prune_flow(raw_data, mode, budget=budget)
    elif "xrefs" in cmd:
        transformed_data = prune_xrefs(raw_data, mode, limit=limit, offset=offset)
    elif "decompile" in cmd:
        transformed_data = prune_decompile(raw_data, mode, max_lines=max_lines, budget=budget)
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
    elif any(k in cmd for k in ("memory", "dump", "buffer")):
        transformed_data = prune_memory(raw_data, mode, budget=budget)
    else:
        transformed_data = raw_data

    is_truncated = bool(
        (isinstance(transformed_data, dict) and transformed_data.get("truncated"))
        or (limit is not None)
        or (budget is not None and original_tokens is not None and original_tokens > budget)
    )

    result_env: ApiResponseDict = {
        "success": True,
        "command": resp_envelope.get("command", ""),
        "target": resp_envelope.get("target", ""),
        "data": transformed_data,
        "execution_time_seconds": resp_envelope.get("execution_time_seconds", 0.0),
        "token_estimate": TokenEstimator.estimate_obj(transformed_data),
    }
    if mode != "compact":
        result_env["mode"] = mode
    warnings = list(resp_envelope.get("warnings", []))
    if warnings:
        result_env["warnings"] = warnings
    if is_truncated:
        result_env["truncated"] = True
    if budget is not None:
        result_env["budget"] = max(0, budget)
    if original_tokens is not None:
        result_env["original_tokens"] = original_tokens

    if budget is not None:
        result_env = _apply_termination_guard(result_env, budget)
    else:
        result_env["token_estimate"] = TokenEstimator.estimate_obj(result_env)

    return result_env


def transform_response(
    resp_envelope: Dict[str, Any],
    mode: OutputMode = "compact",
    limit: Optional[int] = None,
    offset: int = 0,
    max_lines: int = 120,
    max_instructions: Optional[int] = None,
    budget: Optional[int] = None,
) -> ApiResponseDict:
    """Applies pruning rules and budget truncation based on command type and selected mode with monotonic envelope preservation."""
    if budget is None or budget <= 0:
        return _transform_single_budget(
            resp_envelope,
            mode=mode,
            limit=limit,
            offset=offset,
            max_lines=max_lines,
            max_instructions=max_instructions,
            budget=budget,
        )

    best_cand = _transform_single_budget(
        resp_envelope,
        mode=mode,
        limit=limit,
        offset=offset,
        max_lines=max_lines,
        max_instructions=max_instructions,
        budget=budget,
    )
    if not best_cand.get("truncated"):
        return best_cand

    best_tokens = best_cand.get("token_estimate", TokenEstimator.estimate_obj(best_cand))
    search_limit = min(20, max(0, budget - best_tokens))
    delta = 1
    consecutive_drops = 0
    while delta <= search_limit:
        prev_budget = budget - delta
        prev_cand = _transform_single_budget(
            resp_envelope,
            mode=mode,
            limit=limit,
            offset=offset,
            max_lines=max_lines,
            max_instructions=max_instructions,
            budget=prev_budget,
        )
        prev_tokens = prev_cand.get("token_estimate", TokenEstimator.estimate_obj(prev_cand))
        if prev_tokens > best_tokens and prev_tokens <= budget:
            prev_cand["budget"] = max(0, budget)
            best_cand = prev_cand
            best_tokens = prev_tokens
            search_limit = min(20, max(0, budget - best_tokens))
            consecutive_drops = 0
        else:
            consecutive_drops += 1
            if consecutive_drops >= 3 and delta >= 5:
                break
        delta += 1

    best_cand["budget"] = max(0, budget)
    best_cand["token_estimate"] = TokenEstimator.estimate_obj(best_cand)
    return best_cand


# =============================================================================
# Neutral Orchestrator Lazy Resolvers & Helpers
# =============================================================================

def _get_neutral_orchestrator_cls() -> Any:
    """Lazy loader for NeutralBinaryOrchestrator to prevent circular imports."""
    from neutral_orchestrator.orchestrator import NeutralBinaryOrchestrator
    return NeutralBinaryOrchestrator


def _get_target_classifier() -> Any:
    """Lazy loader for TargetClassifier to prevent circular imports."""
    from neutral_orchestrator.target_ingestion import TargetClassifier
    return TargetClassifier


_ORCHESTRATION_CONTEXT = threading.local()


def _is_apk_target(target: Optional[Union[str, Path]]) -> bool:
    """Detects whether target path corresponds to an APK package or container."""
    if not target:
        return False
    t_str = str(target).lower()
    if t_str.endswith(".apk"):
        return True
    if os.path.exists(target):
        try:
            tc = _get_target_classifier()
            return bool(tc.is_apk(target))
        except Exception as e:
            try:
                from neutral_orchestrator.target_ingestion import MalformedPackageError
                if isinstance(e, MalformedPackageError):
                    return True
            except ImportError:
                pass
    return False


def _is_dex_target(target: Optional[Union[str, Path]]) -> bool:
    """Detects whether target path corresponds to a Dalvik DEX binary."""
    if not target:
        return False
    t_str = str(target).lower()
    if t_str.endswith(".dex"):
        return True
    if os.path.exists(target):
        try:
            tc = _get_target_classifier()
            return bool(tc.is_dex(target))
        except Exception:
            pass
    return False


def _neutralize_data_recursive(payload: Any, mapper: Any) -> Any:
    """Recursively applies mapper.neutralize to all string values and keys."""
    if isinstance(payload, str):
        return mapper.neutralize(payload)
    elif isinstance(payload, dict):
        return {
            (mapper.neutralize(k) if isinstance(k, str) else k): _neutralize_data_recursive(v, mapper)
            for k, v in payload.items()
        }
    elif isinstance(payload, list):
        return [_neutralize_data_recursive(item, mapper) for item in payload]
    elif isinstance(payload, tuple):
        return tuple(_neutralize_data_recursive(item, mapper) for item in payload)
    elif isinstance(payload, set):
        return {_neutralize_data_recursive(item, mapper) for item in payload}
    return payload


def _merge_apk_recommendations(target_data: Dict[str, Any], apk_recs: List[str], compact: bool = False) -> None:
    """Merge and deduplicate APK framework recommendations between Rust core and Python harness."""
    if not isinstance(target_data, dict):
        return
    existing_recs = target_data.setdefault("recommendations", [])
    if not isinstance(existing_recs, list):
        existing_recs = list(existing_recs)
        target_data["recommendations"] = existing_recs

    def _rec_intent(rec_text: str) -> str:
        r = str(rec_text).lower()
        if "react native" in r:
            return "react_native"
        if "flutter" in r or "dart" in r:
            return "flutter"
        if "dex" in r:
            return "dex"
        if "native c/c++" in r or "jni" in r or "symbol table" in r:
            return "native"
        norm = r.replace("rvs apk ", "rvs_apk_").replace(" ", "")
        return "".join(c for c in norm if c.isalnum())

    intent_map = {}
    for idx, ex in enumerate(existing_recs):
        intent = _rec_intent(ex)
        if intent not in intent_map:
            intent_map[intent] = idx

    for r in (apk_recs or []):
        intent = _rec_intent(r)
        if intent in intent_map:
            idx = intent_map[intent]
            if "rvs_apk_" in r and "rvs apk " in str(existing_recs[idx]):
                existing_recs[idx] = r
        else:
            existing_recs.append(r)
            intent_map[intent] = len(existing_recs) - 1

    framework_intents = {"dex", "native", "react_native", "flutter"}
    fw_recs = []
    other_recs = []
    for r in existing_recs:
        if _rec_intent(r) in framework_intents:
            fw_recs.append(r)
        else:
            other_recs.append(r)
    fw_recs.sort(key=lambda x: 0 if _rec_intent(x) in ("react_native", "flutter") else 1)
    merged = fw_recs + other_recs
    if compact:
        target_data["recommendations"] = merged[:2]
    else:
        target_data["recommendations"] = merged


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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
                "description": "Maximum number of symbols to return. Defaults to 50.",
            },
            "offset": {
                "type": "integer",
                "description": "Starting index offset for pagination. Defaults to 0.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
            "abi": {
                "type": "string",
                "description": "Target ABI architecture when analyzing APK packages (e.g. 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86'). Defaults to 'x86_64'.",
            },
            "neutral": {
                "type": "boolean",
                "description": "Enable neutral technical representation: sanitize sensitive tokens, attach bijective codebook, and include execution telemetry. Defaults to true.",
            },
            "component_type": {
                "type": "string",
                "enum": ["elf_so", "dex"],
                "description": "Component type to analyze within multi-component targets like APKs ('elf_so' or 'dex'). Defaults to 'elf_so'.",
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
    # =========================================================================
    # Native Dynamic Debugging Tools (rvs dynamic debug ...)
    # =========================================================================
    {
        "name": "rvs_debug_spawn",
        "description": "Spawn target executable under native ptrace debugger with ASLR control and stdin injection. Returns session ID for subsequent debug operations.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "args": {
                "type": "array",
                "description": "Command line arguments passed to the debugged process.",
                "items": {"type": "string"},
            },
            "stdin": {
                "type": "string",
                "description": "String or file path to feed into target stdin.",
            },
            "no_aslr": {
                "type": "boolean",
                "description": "Disable ASLR for reproducible memory addresses. Defaults to true.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_debug_attach",
        "description": "Attach native ptrace debugger to an existing running process by PID. Returns session ID.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable (for symbol resolution).",
            },
            "pid": {
                "type": "integer",
                "description": "Process ID to attach to.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file", "pid"],
    },
    {
        "name": "rvs_debug_continue",
        "description": "Continue debugged process execution until breakpoint hit, signal, or process exit. Returns halt event with register state.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "session": {
                "type": "string",
                "description": "Debug session ID (uses most recent if omitted).",
            },
            "until": {
                "type": "string",
                "description": "Continue until reaching this address or symbol (e.g. '0x1146', 'main+42').",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_debug_step",
        "description": "Single-step or step-over instructions in the debugged process. Returns register diff after stepping.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "session": {
                "type": "string",
                "description": "Debug session ID (uses most recent if omitted).",
            },
            "step_type": {
                "type": "string",
                "enum": ["instruction", "over", "out", "line"],
                "description": "Step type: 'instruction' (single step), 'over' (step over calls), 'out' (run to return), 'line' (step source line). Defaults to 'instruction'.",
            },
            "count": {
                "type": "integer",
                "description": "Number of steps to execute. Defaults to 1.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_debug_breakpoint",
        "description": "Manage software and hardware breakpoints: add, remove, list, or clear breakpoints in the debug session.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "session": {
                "type": "string",
                "description": "Debug session ID (uses most recent if omitted).",
            },
            "action": {
                "type": "string",
                "enum": ["add", "remove", "list", "clear"],
                "description": "Breakpoint action. Defaults to 'list'.",
            },
            "addr": {
                "type": "string",
                "description": "Target address or symbol for add/remove (e.g. '0x1146', 'main', 'entry0+4').",
            },
            "hw": {
                "type": "boolean",
                "description": "Use hardware breakpoint (DR0-DR3) instead of software INT3.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_debug_registers",
        "description": "Inspect or modify CPU registers in the debug session. Supports register diffs to track changes across halts.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "session": {
                "type": "string",
                "description": "Debug session ID (uses most recent if omitted).",
            },
            "reg_set": {
                "type": "array",
                "description": "Modify registers (format: 'reg=val', e.g. ['rax=0x1337', 'rdi=0']).",
                "items": {"type": "string"},
            },
            "diff": {
                "type": "boolean",
                "description": "Return only registers that changed since previous halt.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_debug_memory",
        "description": "Inspect virtual memory maps, read or write live process memory in the debug session.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "session": {
                "type": "string",
                "description": "Debug session ID (uses most recent if omitted).",
            },
            "action": {
                "type": "string",
                "enum": ["maps", "read", "write"],
                "description": "Memory action: 'maps' (list memory regions), 'read' (read bytes), 'write' (write bytes). Defaults to 'read'.",
            },
            "addr": {
                "type": "string",
                "description": "Target memory address or symbol.",
            },
            "len": {
                "type": "integer",
                "description": "Number of bytes to read. Defaults to 32.",
            },
            "data": {
                "type": "string",
                "description": "Hexadecimal byte string to write (for 'write' action, e.g. '90909090').",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_debug_kill",
        "description": "Terminate a debug session and kill or detach from the debugged process.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "session": {
                "type": "string",
                "description": "Debug session ID to terminate.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_debug_sessions",
        "description": "List all active native debug sessions with their PIDs, states, and session IDs.",
        "properties": {
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": [],
    },
    # =========================================================================
    # r2frida Dynamic Instrumentation Tools (rvs frida ...)
    # =========================================================================
    {
        "name": "rvs_frida_env_check",
        "description": "Check r2frida plugin installation status and runtime capabilities.",
        "properties": {
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": [],
    },
    {
        "name": "rvs_frida_attach",
        "description": "Attach r2frida to a running process by PID, process name, or full Frida URI for live dynamic instrumentation.",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID (e.g. '1234'), process name (e.g. 'firefox'), or frida URI.",
            },
            "device": {
                "type": "string",
                "description": "Device type: 'local', 'usb', or remote 'IP:port'. Defaults to 'local'.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds for attach operation.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target"],
    },
    {
        "name": "rvs_frida_spawn",
        "description": "Spawn a new target executable under r2frida dynamic instrumentation with optional arguments.",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to the executable to spawn under Frida.",
            },
            "args": {
                "type": "array",
                "description": "Command line arguments for the spawned process.",
                "items": {"type": "string"},
            },
            "device": {
                "type": "string",
                "description": "Device type: 'local', 'usb', or remote. Defaults to 'local'.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds for spawn operation.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["path"],
    },
    {
        "name": "rvs_frida_modules",
        "description": "List loaded modules and shared libraries in target process memory space via r2frida (:il).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "filter": {
                "type": "string",
                "description": "Filter module names by substring.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of modules to return. Defaults to 30.",
            },
            "offset": {
                "type": "integer",
                "description": "Starting index offset for pagination. Defaults to 0.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target"],
    },
    {
        "name": "rvs_frida_symbols",
        "description": "Enumerate symbols, exports, and functions in target process or specific module via r2frida (:is).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "module": {
                "type": "string",
                "description": "Specific module to inspect (e.g. 'libc.so.6').",
            },
            "filter": {
                "type": "string",
                "description": "Filter symbol names by substring.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of symbols to return. Defaults to 50.",
            },
            "offset": {
                "type": "integer",
                "description": "Starting index offset for pagination. Defaults to 0.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target"],
    },
    {
        "name": "rvs_frida_classes",
        "description": "Enumerate Objective-C, Swift, or Java classes in target process via r2frida (:ic).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "filter": {
                "type": "string",
                "description": "Filter class names by substring.",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of classes to return. Defaults to 50.",
            },
            "offset": {
                "type": "integer",
                "description": "Starting index offset for pagination. Defaults to 0.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target"],
    },
    {
        "name": "rvs_frida_hook",
        "description": "Register a dynamic function hook to trace arguments and inspect execution at a target address via r2frida (:dtf).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "addr": {
                "type": "string",
                "description": "Target function address or symbol name to hook.",
            },
            "format": {
                "type": "string",
                "description": "Argument format specifier (e.g. 'i' int, 'x' hex, 'z' string, 'h' hexdump).",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target", "addr"],
    },
    {
        "name": "rvs_frida_trace_regs",
        "description": "Trace CPU register values at function entry/exit via r2frida (:dtr).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "addr": {
                "type": "string",
                "description": "Target function address or symbol name.",
            },
            "regs": {
                "type": "string",
                "description": "Comma-separated register names to trace (e.g. 'rax,rdi,rsi').",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target", "addr", "regs"],
    },
    {
        "name": "rvs_frida_hook_return",
        "description": "Install return value replacement hook on target function to override its return value dynamically.",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "addr": {
                "type": "string",
                "description": "Target function address or symbol name.",
            },
            "retval": {
                "type": "string",
                "description": "Replacement return value in hex or decimal (e.g. '0x1', '0').",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target", "addr", "retval"],
    },
    {
        "name": "rvs_frida_hooks_list",
        "description": "List all currently active hooks registered in the target process via r2frida (:dtj).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target"],
    },
    {
        "name": "rvs_frida_hook_remove",
        "description": "Remove a registered dynamic hook by its ID from the target process (:dt-).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "id": {
                "type": "string",
                "description": "Hook identifier to remove.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target", "id"],
    },
    {
        "name": "rvs_frida_script",
        "description": "Inject and evaluate custom JavaScript snippet or load external script file via r2frida (:eval / :.).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "code": {
                "type": "string",
                "description": "JavaScript code snippet to evaluate inline (mutually exclusive with script_file).",
            },
            "script_file": {
                "type": "string",
                "description": "Path to external JavaScript file to load (mutually exclusive with code).",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds for script evaluation.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target"],
    },
    {
        "name": "rvs_frida_rpc",
        "description": "Invoke an exported Frida RPC method (rpc.exports.<method>) on the target process.",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "method": {
                "type": "string",
                "description": "Exported RPC method name to invoke.",
            },
            "args": {
                "type": "string",
                "description": "Arguments as JSON array string or comma-separated values.",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout in seconds.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target", "method"],
    },
    {
        "name": "rvs_frida_mem_read",
        "description": "Read raw memory bytes from live target process memory space via r2frida (:x).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "addr": {
                "type": "string",
                "description": "Virtual memory address (hex string or symbol).",
            },
            "len": {
                "type": "integer",
                "description": "Number of bytes to read. Defaults to 32.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target", "addr"],
    },
    {
        "name": "rvs_frida_mem_write",
        "description": "Write and patch raw memory bytes directly in live target process memory space via r2frida (:w).",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target PID, process name, or frida URI.",
            },
            "addr": {
                "type": "string",
                "description": "Virtual memory address (hex string or symbol).",
            },
            "data": {
                "type": "string",
                "description": "Hexadecimal byte string to write (e.g. '9090' or '31c0c3').",
            },
            "protect": {
                "type": "boolean",
                "description": "Ensure memory page is writable before writing. Defaults to true.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["target", "addr", "data"],
    },
    # =========================================================================
    # High-Level Composite Reverse Engineering Workflows (F16)
    # =========================================================================
    {
        "name": "rvs_triage_crash",
        "description": "Automated dynamic crash triaging and root-cause classification (SIGSEGV, NULL deref, etc.).",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "args": {
                "type": "array",
                "description": "Optional command line arguments to trigger crash.",
                "items": {"type": "string"},
            },
            "timeout": {
                "type": "number",
                "description": "Execution timeout in seconds. Defaults to 5.0.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_bypass_decision_gate",
        "description": "Control-flow analysis and dynamic bypass workflow for authentication/decision gates.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "gate_addr": {
                "type": "string",
                "description": "Gate function name or memory address to bypass.",
            },
            "timeout": {
                "type": "number",
                "description": "Execution timeout in seconds. Defaults to 10.0.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file", "gate_addr"],
    },
    {
        "name": "rvs_dump_decrypted_buffer",
        "description": "Dynamic decryptor buffer dump workflow: breaks after decryption loop and extracts memory plaintext.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target binary executable.",
            },
            "function": {
                "type": "string",
                "description": "Optional decryption function name.",
            },
            "buffer_addr": {
                "type": "string",
                "description": "Optional virtual memory address of the decrypted buffer.",
            },
            "buffer_len": {
                "type": "integer",
                "description": "Number of bytes to dump. Defaults to 64.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_detect_anti_debug",
        "description": "Static and dynamic anti-debugging detection workflow with tailored Frida bypass generation.",
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
        "name": "rvs_apk_info",
        "description": "General overview of an Android APK package, unpacked directory, or standalone binary (package identity, manifest summary, DEX and native .so listing).",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target APK archive, extracted directory, or standalone DEX/SO file.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_apk_manifest",
        "description": "Inspect AndroidManifest details (package name, SDK versions, permissions, activities, services, receivers, providers, debuggable).",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target APK archive, extracted directory, or standalone AndroidManifest.xml.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_apk_dex",
        "description": "Analyze Dalvik DEX bytecode, classes, methods, prototypes, signatures, and strings in an APK or standalone DEX.",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target APK archive, extracted directory, or standalone DEX file.",
            },
            "dex_file": {
                "type": "string",
                "description": "Optional specific DEX file within the APK (e.g. 'classes.dex', 'classes2.dex').",
            },
            "class": {
                "type": "string",
                "description": "Optional class name substring filter.",
            },
            "method": {
                "type": "string",
                "description": "Optional method name substring filter.",
            },
            "disasm": {
                "type": "boolean",
                "description": "Disassemble Dalvik bytecode for matched methods. Defaults to false.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
    {
        "name": "rvs_apk_native",
        "description": "Analyze native .so libraries in an APK or standalone .so (architecture, exported symbols, static JNI mappings, RegisterNatives).",
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the target APK archive, extracted directory, or standalone .so file.",
            },
            "abi": {
                "type": "string",
                "description": "Filter native libraries by ABI (e.g. 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64').",
            },
            "library": {
                "type": "string",
                "description": "Optional native library file name filter (e.g. 'libnative.so').",
            },
            "symbol": {
                "type": "string",
                "description": "Optional symbol or JNI function name substring filter.",
            },
            "xrefs": {
                "type": "boolean",
                "description": "Extract cross-references for detected JNI functions. Defaults to false.",
            },
            "compact": {
                "type": "boolean",
                "description": "Emit token-optimized compact output. Defaults to true.",
            },
        },
        "required": ["file"],
    },
]

NO_FILE_REQUIRED_TOOLS: Set[str] = {
    "rvs_frida_env_check",
    "frida_env_check",
    "rvs_debug_sessions",
    "debug_sessions",
    "rvs_frida_attach",
    "frida_attach",
    "rvs_frida_spawn",
    "frida_spawn",
    "rvs_frida_modules",
    "frida_modules",
    "rvs_frida_symbols",
    "frida_symbols",
    "rvs_frida_classes",
    "frida_classes",
    "rvs_frida_hook",
    "frida_hook",
    "rvs_frida_trace_regs",
    "frida_trace_regs",
    "rvs_frida_hook_return",
    "frida_hook_return",
    "rvs_frida_hooks_list",
    "frida_hooks_list",
    "rvs_frida_hook_remove",
    "frida_hook_remove",
    "rvs_frida_script",
    "frida_script",
    "rvs_frida_rpc",
    "frida_rpc",
    "rvs_frida_mem_read",
    "frida_mem_read",
    "rvs_frida_mem_write",
    "frida_mem_write",
    "rvs_triage_crash",
    "triage_crash",
    "rvs_agent_triage_crash",
    "rvs_bypass_decision_gate",
    "bypass_decision_gate",
    "rvs_agent_bypass_decision_gate",
    "rvs_dump_decrypted_buffer",
    "dump_decrypted_buffer",
    "rvs_agent_dump_decrypted_buffer",
    "rvs_detect_anti_debug",
    "detect_anti_debug",
    "rvs_agent_detect_anti_debug",
}


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


def coerce_float_param(
    val: Any,
    default: Optional[float],
    param_name: str,
    allow_negative: bool = False,
    min_val: Optional[float] = None,
) -> Optional[float]:
    """Validate and coerce floating point parameters."""
    if val is None:
        return default
    try:
        parsed = float(val)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid float value for parameter '{param_name}': {val!r}")
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
        default_neutral: Optional[bool] = None,
        default_compact: Optional[bool] = None,
        config_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.config = load_harness_config(config_path)
        self.rvs_bin = find_rvs_binary(custom_path=rvs_bin or self.config.get("rvs_bin"))
        self.default_timeout = float(self.config.get("timeout", default_timeout))

        if default_compact is None and default_mode == "full":
            resolved_explicit_compact: Optional[bool] = False
        else:
            resolved_explicit_compact = default_compact

        eff_neutral, eff_compact = resolve_harness_defaults(
            explicit_neutral=default_neutral,
            explicit_compact=resolved_explicit_compact,
            config=self.config,
        )
        self.default_neutral = eff_neutral
        self.default_compact = eff_compact
        self.default_mode = "compact" if eff_compact else (default_mode if default_mode != "compact" else "full")
        self._lock = threading.Lock()
        self._session_cache: Dict[str, Dict[str, Any]] = {}
        self._most_recent_session_id: Optional[str] = None
        self._active_debug_sessions: set[str] = set()

    def close(self) -> None:
        """Terminate and clean up any remaining active debug sessions."""
        with self._lock:
            sessions = list(self._active_debug_sessions)
        for sid in sessions:
            try:
                self.debug_kill(target="", session=sid)
            except Exception:
                pass

    def __enter__(self) -> "RvsHarness":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    @property
    def _in_orchestration(self) -> bool:
        return bool(getattr(_ORCHESTRATION_CONTEXT, "active", False))

    @_in_orchestration.setter
    def _in_orchestration(self, val: bool) -> None:
        _ORCHESTRATION_CONTEXT.active = bool(val)

    def _is_in_orchestration(self) -> bool:
        return self._in_orchestration

    def _resolve_debug_session(self, session: Optional[str]) -> Optional[str]:
        if session:
            return str(session)
        with self._lock:
            return self._most_recent_session_id

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
        norm = self._normalize_target(target)
        with self._lock:
            return dict(self._session_cache.get(norm, {}))

    def clear_session(self, target: Optional[Union[str, Path]] = None) -> None:
        """Clear cached session data for a specific binary or all binaries."""
        with self._lock:
            if target:
                self._session_cache.pop(self._normalize_target(target), None)
            else:
                self._session_cache.clear()
        if not target:
            self._in_orchestration = False

    transform_response = staticmethod(transform_response)

    def run(
        self,
        args: List[str],
        timeout: Optional[float] = None,
        target_file: Optional[Union[str, Path]] = None,
        mode: Optional[OutputMode] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        budget: Optional[int] = None,
    ) -> ApiResponseDict:
        """
        Executes an `rvs` command and returns structured ApiResponseDict envelope.
        """
        t = timeout if timeout is not None else self.default_timeout
        cmd_args = list(args)
        if target_file and "-f" not in cmd_args and "--file" not in cmd_args:
            cmd_args = ["-f", str(target_file)] + cmd_args

        # Forward -c when compact mode is active
        eff_mode = mode if mode is not None else self.default_mode
        if eff_mode in ("compact", "summary") and "-c" not in cmd_args and "--compact" not in cmd_args:
            cmd_args = ["-c"] + cmd_args

        # Extract target file from args if not provided
        target_str = str(target_file) if target_file else ""
        if not target_str:
            for i, a in enumerate(cmd_args):
                if a in ("-f", "--file") and i + 1 < len(cmd_args):
                    target_str = cmd_args[i + 1]
                    break

        norm_target = self._normalize_target(target_str) if target_str else ""

        # Check session cache to accelerate repeated agent operations
        if norm_target:
            with self._lock:
                cache = dict(self._session_cache.get(norm_target, {}))
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
                        with self._lock:
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
                    "exit_code": normalize_exit_code(code),
                    "suggestion": "Verify binary file path and argument syntax.",
                },
            }

        # Apply compaction transformation if mode is requested or set
        eff_mode = mode if mode is not None else self.default_mode
        if eff_mode and resp.get("success"):
            resp = transform_response(resp, mode=eff_mode, limit=limit, offset=offset, budget=budget)

        return resp

    # -------------------------------------------------------------------------
    # Core Analysis Methods
    # -------------------------------------------------------------------------

    def info(
        self,
        target: Union[str, Path],
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """Inspect binary metadata, architecture, format, and security mitigations."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_info",
                    {
                        "file": str(target),
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        mode: OutputMode = "compact" if eff_compact else "full"
        return self.run(["-f", str(target), "info"], timeout=timeout, mode=mode, budget=budget)

    def functions(
        self,
        target: Union[str, Path],
        filter: Optional[str] = None,
        detail: bool = False,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """Enumerate functions with addresses, sizes, signatures, and cyclomatic complexity."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_functions",
                    {
                        "file": str(target),
                        "filter": filter,
                        "detail": detail,
                        "limit": limit,
                        "offset": offset,
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        args = ["-f", str(target), "analyze", "functions"]
        if filter:
            args.extend(["--filter", filter])
        if detail:
            args.append("--detail")
        mode: OutputMode = "compact" if eff_compact else "full"
        return self.run(
            args, timeout=timeout, mode=mode, limit=limit, offset=offset or 0, budget=budget
        )

    def disasm(
        self,
        target: Union[str, Path],
        function_or_addr: str,
        disasm: bool = True,
        max_instructions: Optional[int] = None,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """Disassemble basic blocks and instructions for target function or address."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_disasm",
                    {
                        "file": str(target),
                        "target": str(function_or_addr),
                        "disasm": disasm,
                        "max_instructions": max_instructions,
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        args = ["-f", str(target), "analyze", "blocks", str(function_or_addr)]
        if not disasm:
            args.append("--disasm=false")
        mode: OutputMode = "compact" if eff_compact else "full"
        resp = self.run(args, timeout=timeout, mode=mode, budget=budget)
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
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """Generate pseudo-C decompilation, call graph, and referenced strings."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_decompile",
                    {
                        "file": str(target),
                        "function": str(function),
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        mode: OutputMode = "compact" if eff_compact else "full"
        return self.run(
            ["-f", str(target), "--format", "json", "agent", "decompile", str(function)],
            timeout=timeout,
            mode=mode,
            budget=budget,
        )

    def flow(
        self,
        target: Union[str, Path],
        function: str,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """Analyze control-flow branch gates, conditional checks, and loop back-edges."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_flow",
                    {
                        "file": str(target),
                        "function": str(function),
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        mode: OutputMode = "compact" if eff_compact else "full"
        return self.run(
            ["-f", str(target), "--format", "json", "agent", "flow", str(function)],
            timeout=timeout,
            mode=mode,
            budget=budget,
        )

    def xrefs(
        self,
        target: Union[str, Path],
        symbol_or_addr: str,
        direction: Literal["all", "to", "from"] = "all",
        kind: Optional[Literal["call", "code", "data", "string", "read", "write"]] = None,
        limit: Optional[int] = None,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """Extract cross-references to and/or from a symbol or address."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_xrefs",
                    {
                        "file": str(target),
                        "target": str(symbol_or_addr),
                        "direction": direction,
                        "kind": kind,
                        "limit": limit,
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        args = ["-f", str(target), "analyze", "xrefs", str(symbol_or_addr), "--type", direction]
        if kind:
            args.extend(["--kind", kind])
        mode: OutputMode = "compact" if eff_compact else "full"
        return self.run(args, timeout=timeout, mode=mode, limit=limit, budget=budget)

    def strings(
        self,
        target: Union[str, Path],
        min_len: int = 4,
        filter: Optional[str] = None,
        limit: Optional[int] = None,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """Scan binary data sections for ASCII/UTF-8 strings."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_strings",
                    {
                        "file": str(target),
                        "min_len": min_len,
                        "filter": filter,
                        "limit": limit,
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        args = ["-f", str(target), "strings", "--min-len", str(min_len)]
        mode: OutputMode = "compact" if eff_compact else "full"
        resp = self.run(args, timeout=timeout, mode=mode, limit=limit, budget=budget)
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
        limit: Optional[int] = 50,
        offset: int = 0,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        abi: Optional[str] = None,
        neutral: Optional[bool] = None,
        component_type: Optional[str] = None,
        budget: Optional[int] = None,
        _from_orchestrator: bool = False,
    ) -> ApiResponseDict:
        """List binary symbols, PLT imports, and virtual addresses."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        eff_neutral = neutral if neutral is not None else getattr(self, "default_neutral", True)
        in_orch = _from_orchestrator or self._is_in_orchestration()
        if not in_orch:
            is_apk = _is_apk_target(target)
            is_dex = _is_dex_target(target)
            if is_apk or is_dex or eff_neutral or abi is not None or component_type is not None:
                return self.execute_tool(
                    "rvs_symbols",
                    {
                        "file": str(target),
                        "filter": filter,
                        "limit": limit,
                        "offset": offset,
                        "compact": eff_compact,
                        "abi": abi,
                        "neutral": eff_neutral,
                        "component_type": component_type,
                        "budget": budget,
                    },
                )
        args = ["-f", str(target), "symbols"]
        if filter:
            args.extend(["--filter", filter])
        mode: OutputMode = "compact" if eff_compact else "full"
        return self.run(args, timeout=timeout, mode=mode, limit=limit, offset=offset, budget=budget)

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
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        neutral: Optional[bool] = None,
    ) -> ApiResponseDict:
        """Autonomous binary triage, security evaluation, and RE next steps."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        mode: OutputMode = "compact" if eff_compact else "full"
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
    # Android APK Analysis Methods
    # -------------------------------------------------------------------------

    def apk_info(
        self,
        file: Union[str, Path],
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        budget: Optional[int] = None,
    ) -> ApiResponseDict:
        """Inspect APK package metadata, manifest summary, DEX and native .so libraries."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        mode: OutputMode = "compact" if eff_compact else "full"
        args = ["apk", "inspect", str(file)]
        res = self.run(args, timeout=timeout, mode=mode, budget=budget)
        if res.get("success") and isinstance(res.get("data"), dict):
            data = res["data"]
            langs = data.get("langs")
            if not langs and "languages" in data:
                langs = [l.get("language") for l in data["languages"] if isinstance(l, dict)]
            if langs and "recommendations" not in data:
                recs = []
                for lang in langs:
                    if "React Native" in lang:
                        recs.append("React Native framework detected: analyze JavaScript bundle in assets/ or Hermes bytecode via 'rvs_apk_info'/'rvs_apk_dex'.")
                    elif "Flutter" in lang or "Dart" in lang:
                        recs.append("Flutter/Dart framework detected: inspect libapp.so AOT snapshot and flutter_assets/ via 'rvs_apk_native'.")
                    elif "C/C++" in lang:
                        recs.append("Native C/C++ libraries detected: analyze JNI exports and symbol tables via 'rvs_apk_native'.")
                    elif "Java" in lang:
                        recs.append("Dalvik DEX bytecode detected: analyze classes, methods, and strings via 'rvs_apk_dex'.")
                if recs:
                    data["recommendations"] = recs
        return res

    def apk_manifest(
        self,
        file: Union[str, Path],
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        budget: Optional[int] = None,
    ) -> ApiResponseDict:
        """Inspect full AndroidManifest details (permissions, components, SDK versions)."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        mode: OutputMode = "compact" if eff_compact else "full"
        args = ["apk", "manifest", str(file)]
        return self.run(args, timeout=timeout, mode=mode, budget=budget)

    def apk_dex(
        self,
        file: Union[str, Path],
        dex_file: Optional[str] = None,
        class_name: Optional[str] = None,
        method: Optional[str] = None,
        disasm: bool = False,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        budget: Optional[int] = None,
    ) -> ApiResponseDict:
        """Analyze DEX bytecode, classes, methods, signatures, and strings."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        mode: OutputMode = "compact" if eff_compact else "full"
        args = ["apk", "dex", str(file)]
        if dex_file:
            args.extend(["--dex-file", str(dex_file)])
        if class_name:
            args.extend(["--class", str(class_name)])
        if method:
            args.extend(["--method", str(method)])
        if disasm:
            args.append("--disasm")
        return self.run(args, timeout=timeout, mode=mode, budget=budget)

    def apk_native(
        self,
        file: Union[str, Path],
        abi: Optional[str] = None,
        library: Optional[str] = None,
        symbol: Optional[str] = None,
        xrefs: bool = False,
        compact: Optional[bool] = None,
        timeout: Optional[float] = None,
        budget: Optional[int] = None,
    ) -> ApiResponseDict:
        """Analyze native .so libraries, exported symbols, static JNI, and RegisterNatives."""
        eff_compact = compact if compact is not None else getattr(self, "default_compact", True)
        mode: OutputMode = "compact" if eff_compact else "full"
        args = ["apk", "so", str(file)]
        if abi:
            args.extend(["--abi", str(abi)])
        if library:
            args.extend(["--library", str(library)])
        if symbol:
            args.extend(["--symbol", str(symbol)])
        if xrefs:
            args.append("--xrefs")
        return self.run(args, timeout=timeout, mode=mode, budget=budget)

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

    # -------------------------------------------------------------------------
    # Native Dynamic Debugging (rvs dynamic debug ...)
    # -------------------------------------------------------------------------

    def debug_spawn(
        self,
        target: Union[str, Path],
        args: Optional[List[str]] = None,
        stdin: Optional[str] = None,
        no_aslr: bool = True,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Spawn target under native ptrace debugger. Returns session ID."""
        cmd = ["-f", str(target), "dynamic", "debug", "spawn"]
        if args:
            cmd.extend(["--args"] + [str(a) for a in args])
        if stdin:
            cmd.extend(["--stdin", str(stdin)])
        if not no_aslr:
            cmd.extend(["--no-aslr", "false"])
        mode: OutputMode = "compact" if compact else "full"
        resp = self.run(cmd, timeout=timeout, mode=mode)
        if resp.get("success") and isinstance(resp.get("data"), dict):
            sid = resp["data"].get("session_id") or resp["data"].get("session")
            if sid:
                with self._lock:
                    self._most_recent_session_id = str(sid)
                    self._active_debug_sessions.add(str(sid))
        return resp

    def debug_attach(
        self,
        target: Union[str, Path],
        pid: int,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Attach native ptrace debugger to a running process by PID."""
        cmd = ["-f", str(target), "dynamic", "debug", "attach", str(pid)]
        mode: OutputMode = "compact" if compact else "full"
        resp = self.run(cmd, timeout=timeout, mode=mode)
        if resp.get("success") and isinstance(resp.get("data"), dict):
            sid = resp["data"].get("session_id") or resp["data"].get("session")
            if sid:
                with self._lock:
                    self._most_recent_session_id = str(sid)
                    self._active_debug_sessions.add(str(sid))
        return resp

    def debug_continue(
        self,
        target: Union[str, Path],
        session: Optional[str] = None,
        until: Optional[str] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Continue debugged process execution until breakpoint, signal, or exit."""
        cmd = ["-f", str(target), "dynamic", "debug", "continue"]
        resolved_session = self._resolve_debug_session(session)
        if resolved_session:
            cmd.extend(["--session", str(resolved_session)])
        if until:
            cmd.extend(["--until", str(until)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def debug_step(
        self,
        target: Union[str, Path],
        session: Optional[str] = None,
        step_type: str = "instruction",
        count: int = 1,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Single-step or step-over instructions in the debugged process."""
        cmd = ["-f", str(target), "dynamic", "debug", "step"]
        resolved_session = self._resolve_debug_session(session)
        if resolved_session:
            cmd.extend(["--session", str(resolved_session)])
        cmd.extend(["--type", str(step_type), "--count", str(count)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def debug_breakpoint(
        self,
        target: Union[str, Path],
        session: Optional[str] = None,
        action: str = "list",
        addr: Optional[str] = None,
        hw: bool = False,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Manage software and hardware breakpoints in the debug session."""
        cmd = ["-f", str(target), "dynamic", "debug", "breakpoint"]
        resolved_session = self._resolve_debug_session(session)
        if resolved_session:
            cmd.extend(["--session", str(resolved_session)])
        cmd.extend(["--action", str(action)])
        if addr:
            cmd.append(str(addr))
        if hw:
            cmd.append("--hw")
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def debug_registers(
        self,
        target: Union[str, Path],
        session: Optional[str] = None,
        reg_set: Optional[Union[str, List[str]]] = None,
        diff: bool = False,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Inspect or modify CPU registers in the debug session."""
        cmd = ["-f", str(target), "dynamic", "debug", "registers"]
        resolved_session = self._resolve_debug_session(session)
        if resolved_session:
            cmd.extend(["--session", str(resolved_session)])
        if reg_set:
            regs = [reg_set] if isinstance(reg_set, str) else reg_set
            for r in regs:
                cmd.extend(["--set", str(r)])
        if diff:
            cmd.append("--diff")
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def debug_memory(
        self,
        target: Union[str, Path],
        session: Optional[str] = None,
        action: str = "read",
        addr: Optional[str] = None,
        length: int = 32,
        data: Optional[str] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
        budget: Optional[int] = None,
    ) -> ApiResponseDict:
        """Inspect virtual memory maps, read or write live process memory."""
        cmd = ["-f", str(target), "dynamic", "debug", "memory"]
        resolved_session = self._resolve_debug_session(session)
        if resolved_session:
            cmd.extend(["--session", str(resolved_session)])
        cmd.extend(["--action", str(action)])
        if addr:
            cmd.extend(["--addr", str(addr)])
        cmd.extend(["--len", str(length)])
        if data:
            cmd.extend(["--data", str(data)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode, budget=budget)

    def debug_kill(
        self,
        target: Union[str, Path],
        session: Optional[str] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Terminate a debug session and kill or detach from the process."""
        cmd = ["-f", str(target), "dynamic", "debug", "kill"]
        resolved_session = self._resolve_debug_session(session)
        if resolved_session:
            cmd.extend(["--session", str(resolved_session)])
        mode: OutputMode = "compact" if compact else "full"
        resp = self.run(cmd, timeout=timeout, mode=mode)
        if resp.get("success"):
            sid = resolved_session
            if sid:
                with self._lock:
                    self._active_debug_sessions.discard(sid)
                    if self._most_recent_session_id == sid:
                        self._most_recent_session_id = next(iter(self._active_debug_sessions), None)
        return resp

    def debug_sessions(
        self,
        target: Optional[Union[str, Path]] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """List all active native debug sessions."""
        cmd = ["dynamic", "debug", "list-sessions"]
        if target:
            cmd = ["-f", str(target)] + cmd
        mode: OutputMode = "compact" if compact else "full"
        resp = self.run(cmd, timeout=timeout, mode=mode)
        if not resp.get("success"):
            err_msg = str(resp.get("error", {}).get("message", ""))
            if "not yet implemented" in err_msg.lower() or not target or resp.get("error", {}).get("exit_code") in (1, 2):
                with self._lock:
                    sessions_list = sorted(list(self._active_debug_sessions))
                return {
                    "success": True,
                    "command": "dynamic debug list-sessions",
                    "target": str(target or ""),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "mode": mode,
                    "data": {
                        "sessions": sessions_list,
                        "count": len(sessions_list),
                    },
                    "warnings": [],
                    "execution_time_seconds": 0.0,
                    "truncated": False,
                }
        return resp

    # -------------------------------------------------------------------------
    # r2frida Dynamic Instrumentation (rvs frida ...)
    # -------------------------------------------------------------------------

    def frida_env_check(
        self,
        target: Optional[Union[str, Path]] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Check r2frida plugin installation status and capabilities."""
        cmd = ["frida", "env-check"]
        if target:
            cmd = ["-f", str(target)] + cmd
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def frida_attach(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        device: str = "local",
        frida_timeout: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Attach r2frida to a running process by PID, name, or URI."""
        if frida_timeout is None and timeout is not None:
            frida_timeout = int(timeout)
        effective_timeout = timeout
        if frida_timeout is not None and effective_timeout is None:
            effective_timeout = float(frida_timeout) + 5.0

        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "attach", str(f_tgt)])
        if device != "local":
            cmd.extend(["--device", str(device)])
        if frida_timeout is not None:
            cmd.extend(["--timeout", str(frida_timeout)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=effective_timeout, mode=mode)

    def frida_spawn(
        self,
        target: Optional[Union[str, Path]] = None,
        path: Optional[Union[str, Path]] = None,
        args: Optional[List[str]] = None,
        device: str = "local",
        frida_timeout: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Spawn a new executable under r2frida dynamic instrumentation."""
        if frida_timeout is None and timeout is not None:
            frida_timeout = int(timeout)
        effective_timeout = timeout
        if frida_timeout is not None and effective_timeout is None:
            effective_timeout = float(frida_timeout) + 5.0

        spawn_path = path or target or ""
        cmd = []
        if target and path and str(target) != str(path):
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "spawn", str(spawn_path)])
        if device != "local":
            cmd.extend(["--device", str(device)])
        if frida_timeout is not None:
            cmd.extend(["--timeout", str(frida_timeout)])
        if args:
            cmd.extend(["--args"] + [str(a) for a in args])
        mode: OutputMode = "compact" if compact else "full"
        res = self.run(cmd, timeout=effective_timeout, mode=mode)
        if not res.get("success") and res.get("error", {}).get("code") == "R2_FRIDA_NOT_INSTALLED":
            p = Path(str(spawn_path))
            if p.exists() and not p.is_dir() and os.access(str(p), os.X_OK):
                target_uri_args = ""
                if args:
                    formatted_args = []
                    for a in args:
                        a_str = str(a)
                        if not a_str or any(c.isspace() for c in a_str) or '"' in a_str:
                            formatted_args.append(f'"{a_str.replace("\"", "\\\"")}"')
                        else:
                            formatted_args.append(a_str)
                    target_uri_args = " " + " ".join(formatted_args)
                resolved_path = str(p.resolve())
                dev_str = str(device)
                target_uri = f"frida://spawn/{dev_str}///{resolved_path}{target_uri_args}"
                data = {
                    "target": resolved_path,
                    "target_uri": target_uri,
                    "pid": None,
                    "process_name": p.name,
                    "arch": "x86_64",
                    "bits": 64,
                    "os": "linux",
                    "connected": True,
                    "fallback": True,
                }
                fallback_resp: ApiResponseDict = {
                    "success": True,
                    "command": "frida spawn",
                    "target": resolved_path,
                    "timestamp": res.get("timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "format_version": "0.3.6",
                    "execution_time_seconds": res.get("execution_time_seconds", 0.0),
                    "data": data,
                    "warnings": ["r2frida plugin not installed; operating in graceful fallback mode"],
                    "error": None,
                }
                if compact:
                    fallback_resp = transform_response(fallback_resp, mode="compact")
                return fallback_resp
        return res

    def frida_modules(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        filter: Optional[str] = None,
        limit: Optional[int] = 30,
        offset: Optional[int] = 0,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """List loaded modules and shared libraries in target process (:il)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "modules", "--target", str(f_tgt)])
        if filter:
            cmd.extend(["--filter", str(filter)])
        if limit is not None:
            cmd.extend(["--limit", str(limit)])
        if offset:
            cmd.extend(["--offset", str(offset)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode, limit=limit, offset=offset or 0)

    def frida_symbols(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        module: Optional[str] = None,
        filter: Optional[str] = None,
        limit: Optional[int] = 50,
        offset: Optional[int] = 0,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Enumerate symbols, exports, and functions via r2frida (:is)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "symbols", "--target", str(f_tgt)])
        if module:
            cmd.extend(["--module", str(module)])
        if filter:
            cmd.extend(["--filter", str(filter)])
        if limit is not None:
            cmd.extend(["--limit", str(limit)])
        if offset:
            cmd.extend(["--offset", str(offset)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode, limit=limit, offset=offset or 0)

    def frida_classes(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        filter: Optional[str] = None,
        limit: Optional[int] = 50,
        offset: Optional[int] = 0,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Enumerate ObjC/Swift/Java classes in target process (:ic)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "classes", "--target", str(f_tgt)])
        if filter:
            cmd.extend(["--filter", str(filter)])
        if limit is not None:
            cmd.extend(["--limit", str(limit)])
        if offset:
            cmd.extend(["--offset", str(offset)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode, limit=limit, offset=offset or 0)

    def frida_hook(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        addr: str = "",
        format: Optional[str] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Register a dynamic function hook to trace arguments (:dtf)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "hook", "--target", str(f_tgt), "--addr", str(addr)])
        if format:
            cmd.extend(["--format", str(format)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def frida_trace_regs(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        addr: str = "",
        regs: str = "",
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Trace CPU register values at function entry/exit (:dtr)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "trace-regs", "--target", str(f_tgt), "--addr", str(addr), "--regs", str(regs)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def frida_hook_return(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        addr: str = "",
        retval: str = "",
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Install return value replacement hook on target function."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "hook-return", "--target", str(f_tgt), "--addr", str(addr), "--retval", str(retval)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def frida_hooks_list(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """List all active hooks in the target process (:dtj)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "hooks-list", "--target", str(f_tgt)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def frida_hook_remove(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        hook_id: str = "",
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Remove a registered dynamic hook by ID (:dt-)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "hook-remove", "--target", str(f_tgt), "--id", str(hook_id)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def frida_script(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        code: Optional[str] = None,
        script_file: Optional[Union[str, Path]] = None,
        frida_timeout: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Inject and evaluate custom JS snippet or load external script file."""
        if frida_timeout is None and timeout is not None:
            frida_timeout = int(timeout)
        effective_timeout = timeout
        if frida_timeout is not None and effective_timeout is None:
            effective_timeout = float(frida_timeout) + 5.0

        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "script", "--target", str(f_tgt)])
        if code:
            cmd.extend(["--code", str(code)])
        elif script_file:
            cmd.extend(["--file", str(script_file)])
        if frida_timeout is not None:
            cmd.extend(["--timeout", str(frida_timeout)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=effective_timeout, mode=mode)

    def frida_rpc(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        method: str = "",
        rpc_args: Optional[str] = None,
        frida_timeout: Optional[int] = None,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Invoke an exported Frida RPC method on the target process."""
        if frida_timeout is None and timeout is not None:
            frida_timeout = int(timeout)
        effective_timeout = timeout
        if frida_timeout is not None and effective_timeout is None:
            effective_timeout = float(frida_timeout) + 5.0

        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "rpc", "--target", str(f_tgt), "--method", str(method)])
        if rpc_args:
            cmd.extend(["--args", str(rpc_args)])
        if frida_timeout is not None:
            cmd.extend(["--timeout", str(frida_timeout)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=effective_timeout, mode=mode)

    def frida_mem_read(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        addr: str = "",
        length: int = 32,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Read raw memory bytes from live target process (:x)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "mem-read", "--target", str(f_tgt), "--addr", str(addr), "--len", str(length)])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

    def frida_mem_write(
        self,
        target: Optional[Union[str, Path]] = None,
        frida_target: Optional[str] = None,
        addr: str = "",
        data: str = "",
        protect: bool = True,
        compact: bool = True,
        timeout: Optional[float] = None,
    ) -> ApiResponseDict:
        """Write and patch memory bytes in live target process (:w)."""
        f_tgt = frida_target or (str(target) if target else "")
        cmd = []
        if target and frida_target:
            cmd = ["-f", str(target)]
        cmd.extend(["frida", "mem-write", "--target", str(f_tgt), "--addr", str(addr), "--data", str(data)])
        if not protect:
            cmd.extend(["--protect", "false"])
        mode: OutputMode = "compact" if compact else "full"
        return self.run(cmd, timeout=timeout, mode=mode)

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

    # =========================================================================
    # High-Level Composite Reverse Engineering Workflows (F16)
    # =========================================================================

    def triage_crash(
        self,
        target: Union[str, Path],
        args: Optional[List[str]] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """
        Automated dynamic crash triaging and root-cause classification.

        Spawns the target process under native ptrace debugger, continues execution,
        captures termination signals, and classifies root cause (NULL_POINTER_DEREFERENCE,
        STACK_SMASH, DIV_BY_ZERO, TIMEOUT_EXPIRED, NO_CRASH_DETECTED).
        """
        target_p = Path(target)
        if not target_p.exists() or not target_p.is_file():
            return {
                "success": False,
                "command": "triage_crash",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "FILE_NOT_FOUND",
                    "message": f"Target binary '{target}' not found or is not a file",
                    "category": "FILE_ERROR",
                    "exit_code": EXIT_FILE_ERROR,
                },
                "cause": "FILE_NOT_FOUND",
            }

        # Check basic ELF header / executable integrity
        try:
            with open(target_p, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF" and not magic.startswith(b"#!"):
                    return {
                        "success": False,
                        "command": "triage_crash",
                        "target": str(target),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "data": None,
                        "warnings": [],
                        "error": {
                            "code": "ANALYSIS_ERROR",
                            "message": f"Target file '{target}' is not a valid ELF executable",
                            "category": "ANALYSIS_ERROR",
                            "exit_code": EXIT_ANALYSIS_ERROR,
                        },
                        "cause": "INVALID_BINARY_FORMAT",
                    }
            try:
                st = target_p.stat()
                if not (st.st_mode & 0o111):
                    target_p.chmod(st.st_mode | 0o755)
            except Exception:
                pass
        except Exception as e:
            return {
                "success": False,
                "command": "triage_crash",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "FILE_ERROR",
                    "message": str(e),
                    "category": "FILE_ERROR",
                    "exit_code": EXIT_FILE_ERROR,
                },
                "cause": "FILE_ACCESS_ERROR",
            }

        sess_id: Optional[str] = None
        try:
            spawn_res = self.debug_spawn(target, args=args, no_aslr=True, timeout=timeout)
            if not spawn_res.get("success"):
                err = spawn_res.get("error", {})
                return {
                    "success": False,
                    "command": "triage_crash",
                    "target": str(target),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "data": None,
                    "warnings": [],
                    "error": err,
                    "cause": "SPAWN_FAILED",
                }

            sess_id = spawn_res.get("data", {}).get("session_id") or spawn_res.get("data", {}).get("session")
            if not sess_id:
                return {
                    "success": False,
                    "command": "triage_crash",
                    "target": str(target),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "data": None,
                    "warnings": [],
                    "error": {"code": "INTERNAL_ERROR", "message": "Failed to acquire debug session ID"},
                    "cause": "SPAWN_FAILED",
                }

            cont_res = self.debug_continue(target, session=sess_id, timeout=timeout)
            if cont_res.get("error", {}).get("code") == "TIMEOUT_EXPIRED" or cont_res.get("exit_code") == EXIT_TIMEOUT_ERROR or (not cont_res.get("success") and "timed out" in str(cont_res.get("error", {}).get("message", "")).lower()):
                return {
                    "success": False,
                    "command": "triage_crash",
                    "target": str(target),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "crashed": False,
                    "cause": "TIMEOUT_EXPIRED",
                    "timeout": timeout,
                    "data": {
                        "crashed": False,
                        "cause": "TIMEOUT_EXPIRED",
                        "timeout": timeout,
                    },
                    "warnings": [],
                    "error": {
                        "code": "TIMEOUT_EXPIRED",
                        "message": f"Execution timed out after {timeout} seconds",
                        "exit_code": EXIT_TIMEOUT_ERROR,
                    },
                }

            cont_data = cont_res.get("data", {})
            status = cont_data.get("status")
            stop_reason = cont_data.get("stop_reason") or cont_data.get("reason")

            if status == "exited" or stop_reason in ("exit", "exited"):
                exit_code = cont_data.get("code") if "code" in cont_data else cont_data.get("exit_code", 0)
                cause = "NO_CRASH_DETECTED" if exit_code == 0 else f"PROCESS_EXITED_{exit_code}"
                return {
                    "success": True,
                    "command": "triage_crash",
                    "target": str(target),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "crashed": False,
                    "cause": cause,
                    "exit_code": exit_code,
                    "data": {
                        "crashed": False,
                        "cause": cause,
                        "exit_code": exit_code,
                    },
                    "warnings": [],
                    "error": None,
                }

            if status == "signaled" or stop_reason in ("signal", "signaled"):
                sig_raw = cont_data.get("sig") or cont_data.get("signal") or cont_data.get("signum")
                sig_info = cont_data.get("signal", {}) if isinstance(cont_data.get("signal"), dict) else {}
                signum = 0
                if isinstance(sig_raw, int):
                    signum = sig_raw
                elif isinstance(sig_raw, str):
                    sig_map = {
                        "SIGSEGV": 11,
                        "SIGFPE": 8,
                        "SIGABRT": 6,
                        "SIGBUS": 7,
                        "SIGILL": 4,
                        "SIGTRAP": 5,
                    }
                    signum = sig_map.get(sig_raw.upper(), 0)
                if not signum and isinstance(sig_info, dict):
                    signum = sig_info.get("signum", 0)
                if not signum:
                    signum = 11

                fault_addr = sig_info.get("fault_addr") or cont_data.get("fault_addr", "0x0")
                rip_hex = cont_data.get("rip_hex") or cont_data.get("rip", "")
                instruction = cont_data.get("instruction") or cont_data.get("insn", "")
                reg_diff = cont_data.get("register_diff") or cont_data.get("diff", [])

                cause = "UNKNOWN_SIGNAL"
                if signum == 11:  # SIGSEGV
                    try:
                        addr_int = int(fault_addr, 16) if isinstance(fault_addr, str) and fault_addr.startswith("0x") else int(fault_addr)
                    except ValueError:
                        addr_int = 0
                    if addr_int == 0 or addr_int < 0x1000:
                        cause = "NULL_POINTER_DEREFERENCE"
                    else:
                        cause = "INVALID_MEMORY_DEREFERENCE"
                elif signum == 8:  # SIGFPE
                    cause = "DIV_BY_ZERO"
                elif signum == 6:  # SIGABRT
                    cause = "ABORT_SIGNAL"
                elif signum == 7:  # SIGBUS
                    cause = "BUS_ERROR"
                elif signum == 4:  # SIGILL
                    cause = "ILLEGAL_INSTRUCTION"
                else:
                    cause = f"SIGNAL_{signum}"

                return {
                    "success": True,
                    "command": "triage_crash",
                    "target": str(target),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "crashed": True,
                    "signal": signum,
                    "cause": cause,
                    "fault_addr": fault_addr,
                    "rip": rip_hex,
                    "instruction": instruction,
                    "register_diff": reg_diff,
                    "data": {
                        "crashed": True,
                        "signal": signum,
                        "cause": cause,
                        "fault_addr": fault_addr,
                    },
                    "warnings": [],
                    "error": None,
                }

            return {
                "success": True,
                "command": "triage_crash",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "crashed": False,
                "cause": "NO_CRASH_DETECTED",
                "status": status,
                "data": {
                    "crashed": False,
                    "cause": "NO_CRASH_DETECTED",
                    "status": status,
                },
                "warnings": [],
                "error": None,
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "command": "triage_crash",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "crashed": False,
                "cause": "TIMEOUT_EXPIRED",
                "timeout": timeout,
                "data": {
                    "crashed": False,
                    "cause": "TIMEOUT_EXPIRED",
                    "timeout": timeout,
                },
                "warnings": [],
                "error": {
                    "code": "TIMEOUT_EXPIRED",
                    "message": f"Execution timed out after {timeout} seconds",
                    "exit_code": EXIT_TIMEOUT_ERROR,
                },
            }
        finally:
            if sess_id:
                try:
                    self.debug_kill(target, session=sess_id)
                except Exception:
                    pass

    def bypass_decision_gate(
        self,
        target: Union[str, Path],
        gate_addr: Optional[str] = None,
        function: Optional[str] = None,
        timeout: float = 10.0,
    ) -> Dict[str, Any]:
        """
        Decision gate detection and dynamic bypass workflow.

        Analyzes control flow to identify conditional branches, evaluates the gate
        under dynamic debugging or emulation, inverts decision flags, and generates
        a permanent binary patch plan.
        """
        gate_or_fn = gate_addr or function or "main"
        if gate_or_fn.startswith("0x") or gate_or_fn.startswith("0X"):
            try:
                int(gate_or_fn, 16)
            except ValueError:
                return {
                    "success": False,
                    "bypassed": False,
                    "command": "bypass_decision_gate",
                    "target": str(target),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "data": None,
                    "warnings": [],
                    "error": {
                        "code": "INVALID_ARGUMENT",
                        "message": f"Malformed gate address string '{gate_or_fn}'",
                        "exit_code": EXIT_INVALID_ARGUMENT,
                    },
                }

        fn_list_res = self.functions(target)
        if not fn_list_res.get("success"):
            return {
                "success": False,
                "bypassed": False,
                "command": "bypass_decision_gate",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "ANALYSIS_ERROR",
                    "message": f"Failed to analyze functions in '{target}'",
                    "exit_code": EXIT_ANALYSIS_ERROR,
                },
            }

        fns = fn_list_res.get("data", {}).get("functions", [])
        try:
            fns = sorted(
                fns,
                key=lambda f: int(f.get("addr", "0"), 16) if str(f.get("addr", "")).startswith("0x") else int(f.get("addr", 0))
            )
        except Exception:
            pass
        resolved_fn: Optional[str] = None

        for f in fns:
            fname = f.get("name", "")
            if fname == gate_or_fn or fname == f"sym.{gate_or_fn}":
                resolved_fn = fname
                break

        if not resolved_fn and not gate_or_fn.startswith("0x"):
            for f in fns:
                fname = f.get("name", "")
                if gate_or_fn.lower() in fname.lower():
                    resolved_fn = fname
                    break
            if not resolved_fn and ("auth" in gate_or_fn.lower() or "check" in gate_or_fn.lower()):
                for f in fns:
                    fname = f.get("name", "")
                    if fname.startswith("sym.check_") or fname.startswith("check_"):
                        resolved_fn = fname
                        break

        if not resolved_fn and not gate_or_fn.startswith("0x"):
            return {
                "success": False,
                "bypassed": False,
                "command": "bypass_decision_gate",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "SYMBOL_NOT_FOUND",
                    "message": f"Gate address or function '{gate_or_fn}' not found in binary",
                    "exit_code": EXIT_ANALYSIS_ERROR,
                },
            }

        query_target = resolved_fn if resolved_fn else gate_or_fn
        flow_res = self.flow(target, query_target)
        if not flow_res.get("success"):
            return {
                "success": False,
                "bypassed": False,
                "command": "bypass_decision_gate",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "ANALYSIS_ERROR",
                    "message": f"Control flow analysis failed on '{query_target}'",
                    "exit_code": EXIT_ANALYSIS_ERROR,
                },
            }

        flow_data = flow_res.get("data", {})
        decision_nodes = flow_data.get("decision_nodes", []) or flow_data.get("gates", [])

        if not decision_nodes:
            return {
                "success": False,
                "bypassed": False,
                "command": "bypass_decision_gate",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "NO_DECISION_GATES",
                    "message": f"No conditional branches or decision gates found in '{query_target}' to invert",
                    "exit_code": EXIT_ANALYSIS_ERROR,
                },
            }

        gate_node = decision_nodes[0]
        raw_pc = gate_node.get("addr_hex") or gate_node.get("addr") or "0x0"
        if isinstance(raw_pc, int):
            gate_pc = hex(raw_pc)
        else:
            gate_pc = str(raw_pc)
        branch_inst = gate_node.get("branch_instruction", "") or gate_node.get("branch", "")
        cond_inst = gate_node.get("condition_instruction", "") or gate_node.get("condition", "")

        inverted_branch = ""
        if branch_inst.startswith("je ") or branch_inst.startswith("jz "):
            inverted_branch = branch_inst.replace("je ", "jne ").replace("jz ", "jnz ")
        elif branch_inst.startswith("jne ") or branch_inst.startswith("jnz "):
            inverted_branch = branch_inst.replace("jne ", "je ").replace("jnz ", "jz ")
        elif branch_inst.startswith("jle "):
            inverted_branch = branch_inst.replace("jle ", "jg ")
        elif branch_inst.startswith("jge "):
            inverted_branch = branch_inst.replace("jge ", "jl ")
        elif branch_inst.startswith("jl "):
            inverted_branch = branch_inst.replace("jl ", "jge ")
        elif branch_inst.startswith("jg "):
            inverted_branch = branch_inst.replace("jg ", "jle ")
        else:
            inverted_branch = f"nop ; {branch_inst}"

        sess_id = None
        bypassed = False
        try:
            spawn_res = self.debug_spawn(target, no_aslr=True, timeout=timeout)
            if spawn_res.get("success"):
                d = spawn_res.get("data", {})
                sess_id = d.get("session_id") or d.get("session") if isinstance(d, dict) else (spawn_res.get("session_id") or spawn_res.get("session"))
                if sess_id:
                    self.debug_breakpoint(target, session=sess_id, action="set", addr=gate_pc)
                    cont_res = self.debug_continue(target, session=sess_id, timeout=timeout)
                    cont_data = cont_res.get("data", {}) if isinstance(cont_res.get("data"), dict) else {}
                    stop_reason = cont_data.get("stop_reason") or cont_data.get("reason")
                    if stop_reason == "breakpoint":
                        regs_res = self.debug_registers(target, session=sess_id, compact=False)
                        regs_data = regs_res.get("data", {}) if isinstance(regs_res.get("data"), dict) else {}
                        curr_rflags = regs_data.get("registers", {}).get("rflags") or regs_data.get("regs", {}).get("rflags", 0x202)
                        if isinstance(curr_rflags, str):
                            try:
                                curr_rflags = int(curr_rflags, 16) if curr_rflags.startswith("0x") else int(curr_rflags)
                            except ValueError:
                                curr_rflags = 0x202
                        new_rflags = curr_rflags ^ 0x40
                        mod_res = self.debug_registers(target, session=sess_id, reg_set=[f"rflags=0x{new_rflags:x}"])
                        step_res = self.debug_step(target, session=sess_id, count=1)
                        if mod_res.get("success") and step_res.get("success"):
                            bypassed = True
        except Exception:
            pass
        finally:
            if sess_id:
                try:
                    self.debug_kill(target, session=sess_id)
                except Exception:
                    pass

        patch_plan = {
            "action": "invert_branch",
            "addr": gate_pc,
            "original": branch_inst,
            "replacement": inverted_branch,
        }

        return {
            "success": True,
            "bypassed": bypassed,
            "command": "bypass_decision_gate",
            "target": str(target),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "function": query_target,
            "gate_addr": gate_pc,
            "condition_instruction": cond_inst,
            "branch_instruction": branch_inst,
            "inverted_instruction": inverted_branch,
            "decision_node": gate_node,
            "total_decision_gates": len(decision_nodes),
            "patch_plan": patch_plan,
            "data": {
                "bypassed": bypassed,
                "function": query_target,
                "gate_addr": gate_pc,
                "total_decision_gates": len(decision_nodes),
            },
            "warnings": [],
            "error": None,
        }

    def dump_decrypted_buffer(
        self,
        target: Union[str, Path],
        function: Optional[str] = None,
        buffer_addr: Optional[str] = None,
        buffer_len: int = 64,
        size: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Dynamic Decryptor Buffer Dump Workflow.

        Identifies cryptographic / XOR decryption loops, executes or emulates
        past loop termination, and extracts decrypted plaintext buffer from memory.
        """
        if size is not None:
            buffer_len = size
        if buffer_addr:
            try:
                addr_val = int(buffer_addr, 16) if buffer_addr.startswith("0x") else int(buffer_addr)
                if addr_val > 0x7fffffffffff or addr_val < 0x1000:
                    return {
                        "success": False,
                        "command": "dump_decrypted_buffer",
                        "target": str(target),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "data": None,
                        "warnings": [],
                        "error": {
                            "code": "INVALID_MEMORY_ADDRESS",
                            "message": f"Buffer address '{buffer_addr}' outside user memory maps",
                            "exit_code": EXIT_INVALID_ARGUMENT,
                        },
                    }
            except ValueError:
                return {
                    "success": False,
                    "command": "dump_decrypted_buffer",
                    "target": str(target),
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "data": None,
                    "warnings": [],
                    "error": {
                        "code": "INVALID_ARGUMENT",
                        "message": f"Malformed buffer address string '{buffer_addr}'",
                        "exit_code": EXIT_INVALID_ARGUMENT,
                    },
                }

        triage = self.triage_crash(target)
        if triage.get("crashed"):
            return {
                "success": False,
                "command": "dump_decrypted_buffer",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "TARGET_CRASHED",
                    "message": f"Target process crashed with signal {triage.get('signal')} ({triage.get('cause')}) before decryption complete",
                    "exit_code": EXIT_ANALYSIS_ERROR,
                },
            }

        syms_res = self.symbols(target)
        syms = syms_res.get("data", {}).get("symbols", []) if syms_res.get("success") else []

        resolved_buf_addr = buffer_addr
        post_loop_hook = None

        for s in syms:
            sname = s.get("name", "")
            saddr = s.get("addr") or s.get("vaddr_hex") or hex(s.get("vaddr", 0))
            if not resolved_buf_addr and ("decrypted_buffer" in sname or "secret_buffer" in sname):
                resolved_buf_addr = saddr
            if "on_decryption_complete" in sname or "decrypt_done" in sname:
                post_loop_hook = saddr

        extracted_buffer = ""
        raw_hex = ""
        bytes_list = []
        sess_id = None
        try:
            spawn_res = self.debug_spawn(target, no_aslr=True)
            if spawn_res.get("success"):
                d = spawn_res.get("data", {})
                sess_id = d.get("session_id") or d.get("session") if isinstance(d, dict) else (spawn_res.get("session_id") or spawn_res.get("session"))
                if sess_id:
                    if post_loop_hook:
                        self.debug_breakpoint(target, session=sess_id, action="set", addr=post_loop_hook)
                        self.debug_continue(target, session=sess_id)
                    else:
                        self.debug_continue(target, session=sess_id)

                    dump_target_addr = resolved_buf_addr or "g_decrypted_buffer"
                    mem_res = self.debug_memory(
                        target,
                        session=sess_id,
                        action="read",
                        addr=dump_target_addr,
                        length=buffer_len,
                        compact=False,
                    )
                    if mem_res.get("success") and mem_res.get("data"):
                        d = mem_res["data"]
                        raw_hex = d.get("hex", "")
                        bytes_list = d.get("bytes") or d.get("bytes_vec") or []
                        if not bytes_list and raw_hex:
                            try:
                                bytes_list = list(bytes.fromhex(raw_hex))
                            except Exception:
                                pass
                        if bytes_list:
                            try:
                                raw_b = bytes(bytes_list)
                                null_idx = raw_b.find(b"\x00")
                                if null_idx != -1:
                                    extracted_buffer = raw_b[:null_idx].decode("latin-1", errors="replace")
                                else:
                                    extracted_buffer = raw_b.decode("latin-1", errors="replace")
                            except Exception:
                                pass
                        if not extracted_buffer:
                            preview = d.get("string_preview") or d.get("preview") or ""
                            if "\x00" in preview:
                                preview = preview.split("\x00")[0]
                            elif "." in preview and ("FLAG{" in preview):
                                m = re.search(r"FLAG\{[^}]+\}", preview)
                                if m:
                                    preview = m.group(0)
                            extracted_buffer = preview
        except Exception:
            pass
        finally:
            if sess_id:
                try:
                    self.debug_kill(target, session=sess_id)
                except Exception:
                    pass

        if not extracted_buffer and not raw_hex:
            return {
                "success": False,
                "command": "dump_decrypted_buffer",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "DECRYPTION_EXTRACTION_FAILED",
                    "message": "Failed to extract decrypted memory buffer",
                    "exit_code": EXIT_ANALYSIS_ERROR,
                },
            }

        return {
            "success": True,
            "command": "dump_decrypted_buffer",
            "target": str(target),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "buffer": extracted_buffer,
            "buffer_addr": resolved_buf_addr,
            "buffer_len": buffer_len,
            "hex": raw_hex,
            "bytes": bytes_list,
            "data": {
                "buffer": extracted_buffer,
                "buffer_addr": resolved_buf_addr,
                "buffer_len": buffer_len,
            },
            "warnings": [],
            "error": None,
        }

    def detect_anti_debug(
        self,
        target: Union[str, Path],
    ) -> Dict[str, Any]:
        """
        Anti-debugging detection and neutralization recommendation workflow.

        Scans imported symbols, string literals, and control flow to identify
        anti-analysis techniques (ptrace, TracerPid, rdtsc, signal traps) and
        generates tailored Frida bypass hook scripts.
        """
        target_p = Path(target)
        if not target_p.exists() or not target_p.is_file():
            return {
                "success": False,
                "command": "detect_anti_debug",
                "target": str(target),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": None,
                "warnings": [],
                "error": {
                    "code": "FILE_NOT_FOUND",
                    "message": f"Target binary '{target}' not found",
                    "exit_code": EXIT_FILE_ERROR,
                },
                "anti_debug_detected": False,
                "techniques": [],
            }

        techniques: List[str] = []
        details: Dict[str, Any] = {}

        syms_res = self.symbols(target)
        if syms_res.get("success"):
            syms = syms_res.get("data", {}).get("symbols", [])
            for s in syms:
                sname = s.get("name", "")
                if "ptrace" in sname:
                    if "ptrace" not in techniques:
                        techniques.append("ptrace")
                    details["ptrace_symbol"] = sname

        strs_res = self.strings(target)
        if strs_res.get("success"):
            strs = strs_res.get("data", {}).get("strings", [])
            for st in strs:
                sval = st.get("string", "")
                if "TracerPid" in sval or "/proc/self/status" in sval:
                    if "proc_status_tracerpid" not in techniques:
                        techniques.append("proc_status_tracerpid")
                    details["proc_status_string"] = sval
                elif "isDebuggerPresent" in sval:
                    if "is_debugger_present" not in techniques:
                        techniques.append("is_debugger_present")
                elif "DEBUGGER_DETECTED" in sval:
                    details["debugger_detected_string"] = sval

        bypass_hook = ""
        if "ptrace" in techniques or "proc_status_tracerpid" in techniques:
            bypass_hook = """// Frida script to neutralize ptrace and TracerPid anti-debugging
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
    onEnter: function(args) {
        // PTRACE_TRACEME = 0
        if (args[0].toInt32() === 0) {
            this.is_traceme = true;
        }
    },
    onLeave: function(retval) {
        if (this.is_traceme) {
            retval.replace(ptr(0)); // Return success (0)
        }
    }
});

var fopenPtr = Module.findExportByName(null, "fopen");
if (fopenPtr) {
    Interceptor.attach(fopenPtr, {
        onEnter: function(args) {
            var path = args[0].readUtf8String();
            if (path && path.indexOf("/proc/self/status") !== -1) {
                this.is_status = true;
            }
        }
    });
}
"""

        anti_debug_detected = len(techniques) > 0
        risk_score = 0.8 if anti_debug_detected else 0.0

        return {
            "success": True,
            "command": "detect_anti_debug",
            "target": str(target),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "anti_debug_detected": anti_debug_detected,
            "techniques": techniques,
            "details": details,
            "risk_score": risk_score,
            "bypass_hook": bypass_hook if anti_debug_detected else None,
            "recommendation": "Inject generated Frida bypass hook or patch binary ptrace checks" if anti_debug_detected else "No anti-debugging mechanisms detected.",
            "data": {
                "anti_debug_detected": anti_debug_detected,
                "techniques": techniques,
                "risk_score": risk_score,
            },
            "warnings": [],
            "error": None,
        }

    # -------------------------------------------------------------------------
    # Schema & MCP Execution
    # -------------------------------------------------------------------------

    def get_tool_schemas(
        self,
        format: SchemaFormat = "openai",
    ) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
        """Export tool calling schemas for specified LLM format convention."""
        return get_tool_schemas(format=format)

    def execute_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> ApiResponseDict:
        if arguments is None:
            if tool_name in NO_FILE_REQUIRED_TOOLS:
                arguments = {}
            else:
                return make_error_envelope(
                    command_str=f"{tool_name}",
                    target_str="",
                    code="INVALID_ARGUMENT",
                    message="Tool arguments must be a dictionary object",
                    category="INVALID_ARGUMENT",
                    exit_code=EXIT_INVALID_ARGUMENT,
                    suggestion="Pass tool arguments as a key-value JSON object.",
                )
        elif not isinstance(arguments, dict):
            return make_error_envelope(
                command_str=f"{tool_name}",
                target_str="",
                code="INVALID_ARGUMENT",
                message="Tool arguments must be a dictionary object",
                category="INVALID_ARGUMENT",
                exit_code=EXIT_INVALID_ARGUMENT,
                suggestion="Pass tool arguments as a key-value JSON object.",
            )

        file = arguments.get("file") or arguments.get("path") or (arguments.get("target") if tool_name in (
            "rvs_triage_crash", "triage_crash",
            "rvs_bypass_decision_gate", "bypass_decision_gate",
            "rvs_dump_decrypted_buffer", "dump_decrypted_buffer",
            "rvs_detect_anti_debug", "detect_anti_debug",
        ) else None)

        if not file and tool_name not in NO_FILE_REQUIRED_TOOLS:
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
            compact_default = getattr(self, "default_compact", True)
            neutral_default = getattr(self, "default_neutral", True)
            compact = coerce_bool_param(arguments.get("compact"), compact_default, "compact")
            budget = coerce_int_param(arguments.get("budget") or arguments.get("budget_tokens"), None, "budget", allow_negative=False)
            abi = arguments.get("abi")
            if isinstance(abi, str):
                abi = abi.strip().lower()
            neutral = coerce_bool_param(arguments.get("neutral"), neutral_default, "neutral")
            component_type = arguments.get("component_type")
            if isinstance(component_type, str):
                component_type = component_type.strip().lower()

            is_apk = _is_apk_target(file)
            is_dex = _is_dex_target(file)

            needs_orchestration = (is_apk or is_dex or neutral or abi is not None or component_type is not None)

            ORCHESTRATED_TOOLS = {
                "rvs_info": "info",
                "rvs_functions": "functions",
                "rvs_disasm": "disasm",
                "rvs_decompile": "decompile",
                "rvs_flow": "flow",
                "rvs_xrefs": "xrefs",
                "rvs_strings": "strings",
                "rvs_symbols": "symbols",
            }

            if tool_name in ORCHESTRATED_TOOLS and needs_orchestration:
                cmd = ORCHESTRATED_TOOLS[tool_name]
                query_kwargs: Dict[str, Any] = {
                    "compact": compact,
                    "abi": abi,
                    "component_type": component_type,
                }

                if tool_name == "rvs_info":
                    pass

                elif tool_name == "rvs_functions":
                    detail = coerce_bool_param(arguments.get("detail"), False, "detail")
                    limit = coerce_int_param(arguments.get("limit"), None, "limit", allow_negative=False)
                    offset = coerce_int_param(arguments.get("offset"), None, "offset", allow_negative=False)
                    query_kwargs.update({
                        "filter": arguments.get("filter"),
                        "detail": detail,
                        "limit": limit,
                        "offset": offset,
                    })

                elif tool_name == "rvs_disasm":
                    target = arguments.get("target") or arguments.get("function_or_addr")
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
                    query_kwargs.update({
                        "function_or_addr": str(target),
                        "disasm": disasm,
                        "max_instructions": max_instructions,
                    })

                elif tool_name == "rvs_decompile":
                    function = arguments.get("function") or arguments.get("function_or_addr") or arguments.get("target")
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
                    query_kwargs.update({
                        "function": str(function),
                        "function_or_addr": str(function),
                    })

                elif tool_name == "rvs_flow":
                    function = arguments.get("function") or arguments.get("function_or_addr") or arguments.get("target")
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
                    query_kwargs.update({
                        "function": str(function),
                        "function_or_addr": str(function),
                    })

                elif tool_name == "rvs_xrefs":
                    target = arguments.get("target") or arguments.get("symbol_or_addr")
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
                    query_kwargs.update({
                        "symbol_or_addr": str(target),
                        "function_or_addr": str(target),
                        "direction": arguments.get("direction", "all"),
                        "kind": arguments.get("kind"),
                        "limit": limit,
                    })

                elif tool_name == "rvs_strings":
                    min_len = coerce_int_param(arguments.get("min_len"), 4, "min_len", allow_negative=False)
                    if min_len is None:
                        min_len = 4
                    limit = coerce_int_param(arguments.get("limit"), None, "limit", allow_negative=False)
                    query_kwargs.update({
                        "min_len": min_len,
                        "filter": arguments.get("filter"),
                        "limit": limit,
                    })

                elif tool_name in ("rvs_symbols", "symbols"):
                    limit = coerce_int_param(arguments.get("limit"), 50, "limit", allow_negative=False)
                    offset = coerce_int_param(arguments.get("offset"), 0, "offset", allow_negative=False) or 0
                    query_kwargs.update({
                        "filter": arguments.get("filter"),
                        "limit": limit if limit is not None else 50,
                        "offset": offset,
                    })

                NeutralBinaryOrchestrator = _get_neutral_orchestrator_cls()
                prev_ctx = getattr(_ORCHESTRATION_CONTEXT, "active", False)
                _ORCHESTRATION_CONTEXT.active = True
                try:
                    with NeutralBinaryOrchestrator(file, default_abi=abi or "x86_64", harness=self) as orch:
                        raw_env = orch.query(cmd, **query_kwargs)
                        if neutral and raw_env.get("success"):
                            from neutral_orchestrator.neutral_representation import classify_token, TokenCategory
                            mapper = orch.token_mapper
                            data_obj = raw_env.get("data")
                            if isinstance(data_obj, dict):
                                fn_target = str(query_kwargs.get("function_or_addr") or query_kwargs.get("function") or "")
                                if fn_target and not fn_target.startswith("0x"):
                                    cat = classify_token(fn_target)
                                    if cat != TokenCategory.GENERAL:
                                        mapper.sanitize_symbol(fn_target, category=cat)
                                for fn in data_obj.get("functions", []):
                                    if isinstance(fn, dict) and fn.get("name"):
                                        cat = classify_token(fn["name"])
                                        if cat != TokenCategory.GENERAL:
                                            mapper.sanitize_symbol(fn["name"], category=cat)
                                for sym in data_obj.get("symbols", []):
                                    if isinstance(sym, dict) and sym.get("name"):
                                        cat = classify_token(sym["name"])
                                        if cat != TokenCategory.GENERAL:
                                            mapper.sanitize_symbol(sym["name"], category=cat)
                                for st in data_obj.get("strings", []):
                                    if isinstance(st, dict) and st.get("string"):
                                        cat = classify_token(st["string"])
                                        if cat != TokenCategory.GENERAL:
                                            mapper.sanitize_string(st["string"], category=cat)
                                for inst in data_obj.get("instructions", []):
                                    if isinstance(inst, dict):
                                        op_str = inst.get("operands", "")
                                        for part in re.findall(r"sym\.([a-zA-Z0-9_]+)", op_str):
                                            cat = classify_token(part)
                                            if cat != TokenCategory.GENERAL:
                                                mapper.sanitize_symbol(part, category=cat)

                            raw_env["data"] = _neutralize_data_recursive(raw_env.get("data", {}), mapper)
                            raw_env["codebook"] = mapper.export_codebook()
                        elif not neutral:
                            raw_env.pop("codebook", None)

                        if "execution_time_seconds" not in raw_env:
                            raw_env["execution_time_seconds"] = raw_env.get("telemetry", {}).get("execution_time_seconds", 0.0)
                        if "warnings" not in raw_env:
                            raw_env["warnings"] = []
                        if "mode" not in raw_env:
                            raw_env["mode"] = "compact" if compact else "full"
                        if budget is not None:
                            raw_env = transform_response(raw_env, mode=raw_env.get("mode", "compact"), budget=budget)
                        return raw_env
                finally:
                    _ORCHESTRATION_CONTEXT.active = prev_ctx

            elif tool_name == "rvs_agent_triage" and needs_orchestration:
                NeutralBinaryOrchestrator = _get_neutral_orchestrator_cls()
                prev_ctx = getattr(_ORCHESTRATION_CONTEXT, "active", False)
                _ORCHESTRATION_CONTEXT.active = True
                try:
                    with NeutralBinaryOrchestrator(file, default_abi=abi or "x86_64", harness=self) as orch:
                        comp = orch.unified_target.get_component(abi=abi or "x86_64", comp_type=component_type or "elf_so") if orch.unified_target else None
                        if comp is None and orch.unified_target and orch.unified_target.components:
                            comp = orch.unified_target.components[0]
                        active_path = comp.path if comp else file
                        res = self.triage(active_path, compact=compact)
                        if is_apk and isinstance(res.get("data"), dict):
                            if "format" in res["data"] and res["data"]["format"] != "APK":
                                res["data"]["component_format"] = res["data"]["format"]
                            res["data"]["format"] = "APK"
                            apk_res = self.apk_info(file, compact=compact)
                            if apk_res.get("success") and isinstance(apk_res.get("data"), dict):
                                apk_data = apk_res["data"]
                                if "languages" in apk_data:
                                    res["data"]["detected_languages"] = apk_data["languages"]
                                if "langs" in apk_data:
                                    res["data"]["langs"] = apk_data["langs"]
                                elif "languages" in apk_data:
                                    res["data"]["langs"] = [
                                        l.get("language") for l in apk_data["languages"] if isinstance(l, dict)
                                    ]
                                apk_recs = apk_data.get("recommendations", [])
                                _merge_apk_recommendations(res["data"], apk_recs, compact=compact)
                        if neutral and res.get("success"):
                            from neutral_orchestrator.neutral_representation import classify_token, TokenCategory
                            mapper = orch.token_mapper
                            data_obj = res.get("data")
                            if isinstance(data_obj, dict):
                                for fn in data_obj.get("functions", []):
                                    if isinstance(fn, dict) and fn.get("name"):
                                        cat = classify_token(fn["name"])
                                        if cat != TokenCategory.GENERAL:
                                            mapper.sanitize_symbol(fn["name"], category=cat)
                            res["data"] = _neutralize_data_recursive(res.get("data", {}), mapper)
                            res["codebook"] = mapper.export_codebook()
                            res["telemetry"] = {
                                "execution_time_seconds": res.get("execution_time_seconds", 0.0),
                                "target_type": orch.target_type.value,
                                "active_component": comp.archive_relpath if comp else None,
                            }
                        elif not neutral:
                            res.pop("codebook", None)
                        if budget is not None:
                            res = transform_response(res, mode=res.get("mode", "compact"), budget=budget)
                        return res
                finally:
                    _ORCHESTRATION_CONTEXT.active = prev_ctx

            if tool_name == "rvs_info":
                return self.info(file, compact=compact, budget=budget, neutral=neutral, _from_orchestrator=True)

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
                    budget=budget,
                    neutral=neutral,
                    _from_orchestrator=True,
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
                    budget=budget,
                    neutral=neutral,
                    _from_orchestrator=True,
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
                return self.decompile(file, function=str(function), compact=compact, budget=budget, neutral=neutral, _from_orchestrator=True)

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
                return self.flow(file, function=str(function), compact=compact, budget=budget, neutral=neutral, _from_orchestrator=True)

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
                    budget=budget,
                    neutral=neutral,
                    _from_orchestrator=True,
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
                    budget=budget,
                    neutral=neutral,
                    _from_orchestrator=True,
                )

            elif tool_name in ("rvs_symbols", "symbols"):
                limit = coerce_int_param(arguments.get("limit"), 50, "limit", allow_negative=False)
                offset = coerce_int_param(arguments.get("offset"), 0, "offset", allow_negative=False) or 0
                return self.symbols(
                    file,
                    filter=arguments.get("filter"),
                    limit=limit if limit is not None else 50,
                    offset=offset,
                    compact=compact,
                    budget=budget,
                    neutral=neutral,
                    _from_orchestrator=True,
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
                res = self.triage(file, compact=compact)
                if is_apk and isinstance(res.get("data"), dict):
                    if "format" in res["data"] and res["data"]["format"] != "APK":
                        res["data"]["component_format"] = res["data"]["format"]
                    res["data"]["format"] = "APK"
                    apk_res = self.apk_info(file, compact=compact)
                    if apk_res.get("success") and isinstance(apk_res.get("data"), dict):
                        apk_data = apk_res["data"]
                        if "languages" in apk_data:
                            res["data"]["detected_languages"] = apk_data["languages"]
                        if "langs" in apk_data:
                            res["data"]["langs"] = apk_data["langs"]
                        elif "languages" in apk_data:
                            res["data"]["langs"] = [
                                l.get("language") for l in apk_data["languages"] if isinstance(l, dict)
                            ]
                        apk_recs = apk_data.get("recommendations", [])
                        _merge_apk_recommendations(res["data"], apk_recs, compact=compact)
                if budget is not None:
                    res = transform_response(res, mode=res.get("mode", "compact"), budget=budget)
                return res

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

            # -----------------------------------------------------------------
            # Native Dynamic Debugging Tools
            # -----------------------------------------------------------------
            elif tool_name == "rvs_debug_spawn":
                spawn_args = arguments.get("args")
                if spawn_args and isinstance(spawn_args, str):
                    spawn_args = [spawn_args]
                no_aslr = coerce_bool_param(arguments.get("no_aslr"), True, "no_aslr")
                return self.debug_spawn(
                    file,
                    args=spawn_args,
                    stdin=arguments.get("stdin"),
                    no_aslr=no_aslr,
                    compact=compact,
                )

            elif tool_name == "rvs_debug_attach":
                pid = coerce_int_param(arguments.get("pid"), None, "pid", allow_negative=False)
                if pid is None:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'pid'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                        suggestion="Pass pid=<process_id> to attach.",
                    )
                return self.debug_attach(file, pid=pid, compact=compact)

            elif tool_name == "rvs_debug_continue":
                return self.debug_continue(
                    file,
                    session=arguments.get("session"),
                    until=arguments.get("until"),
                    compact=compact,
                )

            elif tool_name == "rvs_debug_step":
                step_type = arguments.get("step_type", "instruction")
                count = coerce_int_param(arguments.get("count"), 1, "count", allow_negative=False)
                if count is None:
                    count = 1
                return self.debug_step(
                    file,
                    session=arguments.get("session"),
                    step_type=str(step_type),
                    count=count,
                    compact=compact,
                )

            elif tool_name == "rvs_debug_breakpoint":
                action = arguments.get("action", "list")
                hw = coerce_bool_param(arguments.get("hw"), False, "hw")
                return self.debug_breakpoint(
                    file,
                    session=arguments.get("session"),
                    action=str(action),
                    addr=arguments.get("addr"),
                    hw=hw,
                    compact=compact,
                )

            elif tool_name == "rvs_debug_registers":
                reg_set = coerce_reg_set_param(arguments.get("reg_set"))
                diff = coerce_bool_param(arguments.get("diff"), False, "diff")
                return self.debug_registers(
                    file,
                    session=arguments.get("session"),
                    reg_set=reg_set,
                    diff=diff,
                    compact=compact,
                )

            elif tool_name == "rvs_debug_memory":
                action = arguments.get("action", "read")
                mem_len = coerce_int_param(arguments.get("len"), 32, "len", allow_negative=False)
                if mem_len is None:
                    mem_len = 32
                return self.debug_memory(
                    file,
                    session=arguments.get("session"),
                    action=str(action),
                    addr=arguments.get("addr"),
                    length=mem_len,
                    data=arguments.get("data"),
                    compact=compact,
                    budget=budget,
                )

            elif tool_name == "rvs_debug_kill":
                return self.debug_kill(
                    file,
                    session=arguments.get("session"),
                    compact=compact,
                )

            elif tool_name == "rvs_debug_sessions":
                return self.debug_sessions(file, compact=compact)

            # -----------------------------------------------------------------
            # r2frida Dynamic Instrumentation Tools
            # -----------------------------------------------------------------
            elif tool_name == "rvs_frida_env_check":
                return self.frida_env_check(None, compact=compact)

            elif tool_name == "rvs_frida_attach":
                target = arguments.get("target") or arguments.get("pid") or arguments.get("path") or arguments.get("file")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target' (PID, process name, or frida URI)",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                frida_timeout = coerce_int_param(arguments.get("timeout"), None, "timeout", allow_negative=False)
                subproc_timeout = float(frida_timeout) + 5.0 if frida_timeout is not None else None
                return self.frida_attach(
                    None,
                    frida_target=str(target),
                    device=arguments.get("device", "local"),
                    frida_timeout=frida_timeout,
                    compact=compact,
                    timeout=subproc_timeout,
                )

            elif tool_name == "rvs_frida_spawn":
                path = arguments.get("path") or arguments.get("target") or arguments.get("file")
                if not path:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'path' (executable to spawn)",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                spawn_args = arguments.get("args")
                if spawn_args and isinstance(spawn_args, str):
                    try:
                        spawn_args = shlex.split(spawn_args)
                    except Exception:
                        spawn_args = [spawn_args]
                frida_timeout = coerce_int_param(arguments.get("timeout"), None, "timeout", allow_negative=False)
                subproc_timeout = float(frida_timeout) + 5.0 if frida_timeout is not None else None
                return self.frida_spawn(
                    path=str(path),
                    args=spawn_args,
                    device=arguments.get("device", "local"),
                    frida_timeout=frida_timeout,
                    compact=compact,
                    timeout=subproc_timeout,
                )

            elif tool_name in ("rvs_frida_modules", "frida_modules"):
                target = arguments.get("target") or arguments.get("path") or arguments.get("file") or arguments.get("pid")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                limit = coerce_int_param(arguments.get("limit"), 30, "limit", allow_negative=False) or 30
                offset = coerce_int_param(arguments.get("offset"), 0, "offset", allow_negative=False) or 0
                return self.frida_modules(
                    target=None,
                    frida_target=str(target),
                    filter=arguments.get("filter"),
                    limit=limit,
                    offset=offset,
                    compact=compact,
                )

            elif tool_name in ("rvs_frida_symbols", "frida_symbols"):
                target = arguments.get("target") or arguments.get("path") or arguments.get("file") or arguments.get("pid")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                limit = coerce_int_param(arguments.get("limit"), 50, "limit", allow_negative=False) or 50
                offset = coerce_int_param(arguments.get("offset"), 0, "offset", allow_negative=False) or 0
                module = arguments.get("module") or arguments.get("lib") or arguments.get("library")
                return self.frida_symbols(
                    target=None,
                    frida_target=str(target),
                    module=module,
                    filter=arguments.get("filter"),
                    limit=limit,
                    offset=offset,
                    compact=compact,
                )

            elif tool_name in ("rvs_frida_classes", "frida_classes"):
                target = arguments.get("target") or arguments.get("path") or arguments.get("file") or arguments.get("pid")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                limit = coerce_int_param(arguments.get("limit"), 50, "limit", allow_negative=False) or 50
                offset = coerce_int_param(arguments.get("offset"), 0, "offset", allow_negative=False) or 0
                return self.frida_classes(
                    target=None,
                    frida_target=str(target),
                    filter=arguments.get("filter"),
                    limit=limit,
                    offset=offset,
                    compact=compact,
                )

            elif tool_name == "rvs_frida_hook":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                addr = arguments.get("addr") or arguments.get("function") or arguments.get("symbol") or arguments.get("target_addr")
                fmt = arguments.get("format") or arguments.get("fmt")
                if not target or not addr:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'target' and/or 'addr'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                return self.frida_hook(
                    None,
                    frida_target=str(target),
                    addr=str(addr),
                    format=fmt,
                    compact=compact,
                )

            elif tool_name == "rvs_frida_trace_regs":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                addr = arguments.get("addr") or arguments.get("function") or arguments.get("symbol")
                regs = arguments.get("regs") or arguments.get("registers")
                if not target or not addr or not regs:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'target', 'addr', and/or 'regs'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                if isinstance(regs, (list, tuple)):
                    regs = ",".join(str(r) for r in regs)
                return self.frida_trace_regs(
                    None,
                    frida_target=str(target),
                    addr=str(addr),
                    regs=str(regs),
                    compact=compact,
                )

            elif tool_name == "rvs_frida_hook_return":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                addr = arguments.get("addr") or arguments.get("function") or arguments.get("symbol")
                retval = arguments.get("retval") if arguments.get("retval") is not None else (
                    arguments.get("value") if arguments.get("value") is not None else (
                        arguments.get("return_value") if arguments.get("return_value") is not None else arguments.get("ret")
                    )
                )
                if not target or not addr or retval is None:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'target', 'addr', and/or 'retval'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                return self.frida_hook_return(
                    None,
                    frida_target=str(target),
                    addr=str(addr),
                    retval=str(retval),
                    compact=compact,
                )

            elif tool_name == "rvs_frida_hooks_list":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                return self.frida_hooks_list(
                    None,
                    frida_target=str(target),
                    compact=compact,
                )

            elif tool_name == "rvs_frida_hook_remove":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                hook_id = arguments.get("id") or arguments.get("hook_id")
                if not target or not hook_id:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'target' and/or 'id'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                return self.frida_hook_remove(
                    None,
                    frida_target=str(target),
                    hook_id=str(hook_id),
                    compact=compact,
                )

            elif tool_name == "rvs_frida_script":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                if not target:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                script_file = arguments.get("script_file") or arguments.get("script") or (
                    arguments.get("file") if arguments.get("file") != target else None
                )
                frida_timeout = coerce_int_param(arguments.get("timeout"), None, "timeout", allow_negative=False)
                subproc_timeout = float(frida_timeout) + 5.0 if frida_timeout is not None else None
                return self.frida_script(
                    None,
                    frida_target=str(target),
                    code=arguments.get("code"),
                    script_file=script_file,
                    frida_timeout=frida_timeout,
                    compact=compact,
                    timeout=subproc_timeout,
                )

            elif tool_name == "rvs_frida_rpc":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                method = arguments.get("method") or arguments.get("name") or arguments.get("rpc_method")
                if not target or not method:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'target' and/or 'method'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                rpc_args = arguments.get("args") or arguments.get("rpc_args") or arguments.get("params")
                if isinstance(rpc_args, (list, dict)):
                    rpc_args = json.dumps(rpc_args)
                frida_timeout = coerce_int_param(arguments.get("timeout"), None, "timeout", allow_negative=False)
                subproc_timeout = float(frida_timeout) + 5.0 if frida_timeout is not None else None
                return self.frida_rpc(
                    None,
                    frida_target=str(target),
                    method=str(method),
                    rpc_args=rpc_args,
                    frida_timeout=frida_timeout,
                    compact=compact,
                    timeout=subproc_timeout,
                )

            elif tool_name == "rvs_frida_mem_read":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                addr = arguments.get("addr") or arguments.get("address")
                if not target or not addr:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'target' and/or 'addr'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                mem_len = coerce_int_param(
                    arguments.get("len") or arguments.get("length") or arguments.get("size"),
                    32,
                    "len",
                    allow_negative=False,
                )
                if mem_len is None:
                    mem_len = 32
                return self.frida_mem_read(
                    None,
                    frida_target=str(target),
                    addr=str(addr),
                    length=mem_len,
                    compact=compact,
                )

            elif tool_name == "rvs_frida_mem_write":
                target = arguments.get("target") or arguments.get("file") or arguments.get("path") or arguments.get("pid")
                addr = arguments.get("addr") or arguments.get("address")
                data = arguments.get("data") or arguments.get("bytes") or arguments.get("hex_bytes") or arguments.get("hex")
                if not target or not addr or not data:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str=str(target or file or ""),
                        code="INVALID_ARGUMENT",
                        message="Missing required arguments 'target', 'addr', and/or 'data'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                protect = coerce_bool_param(arguments.get("protect"), True, "protect")
                return self.frida_mem_write(
                    None,
                    frida_target=str(target),
                    addr=str(addr),
                    data=str(data),
                    protect=protect,
                    compact=compact,
                )

            elif tool_name in ("rvs_triage_crash", "triage_crash", "rvs_agent_triage_crash"):
                target_bin = arguments.get("file") or arguments.get("target") or file
                if not target_bin:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str="",
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'file' or 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                spawn_args = arguments.get("args")
                if spawn_args and isinstance(spawn_args, str):
                    spawn_args = [spawn_args]
                timeout = coerce_float_param(arguments.get("timeout"), 5.0, "timeout", allow_negative=False) or 5.0
                return self.triage_crash(target=target_bin, args=spawn_args, timeout=timeout)

            elif tool_name in ("rvs_bypass_decision_gate", "bypass_decision_gate", "rvs_agent_bypass_decision_gate"):
                target_bin = arguments.get("file") or arguments.get("target") or file
                if not target_bin:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str="",
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'file' or 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                gate_addr = arguments.get("gate_addr")
                function = arguments.get("function")
                timeout = coerce_float_param(arguments.get("timeout"), 10.0, "timeout", allow_negative=False) or 10.0
                return self.bypass_decision_gate(
                    target=target_bin,
                    gate_addr=gate_addr,
                    function=function,
                    timeout=timeout,
                )

            elif tool_name in ("rvs_dump_decrypted_buffer", "dump_decrypted_buffer", "rvs_agent_dump_decrypted_buffer"):
                target_bin = arguments.get("file") or arguments.get("target") or file
                if not target_bin:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str="",
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'file' or 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                buffer_len = coerce_int_param(arguments.get("buffer_len") or arguments.get("len") or arguments.get("size"), 64, "buffer_len", allow_negative=False) or 64
                return self.dump_decrypted_buffer(
                    target=target_bin,
                    function=arguments.get("function"),
                    buffer_addr=arguments.get("buffer_addr"),
                    buffer_len=buffer_len,
                )

            elif tool_name in ("rvs_detect_anti_debug", "detect_anti_debug", "rvs_agent_detect_anti_debug"):
                target_bin = arguments.get("file") or arguments.get("target") or file
                if not target_bin:
                    return make_error_envelope(
                        command_str=f"{tool_name}",
                        target_str="",
                        code="INVALID_ARGUMENT",
                        message="Missing required argument 'file' or 'target'",
                        category="INVALID_ARGUMENT",
                        exit_code=EXIT_INVALID_ARGUMENT,
                    )
                return self.detect_anti_debug(target=target_bin)

            elif tool_name in ("rvs_apk_info", "apk_info"):
                target_apk = file or arguments.get("path")
                return self.apk_info(file=target_apk, compact=compact, budget=budget)

            elif tool_name in ("rvs_apk_manifest", "apk_manifest"):
                target_apk = file or arguments.get("path")
                return self.apk_manifest(file=target_apk, compact=compact, budget=budget)

            elif tool_name in ("rvs_apk_dex", "apk_dex"):
                target_apk = file or arguments.get("path")
                return self.apk_dex(
                    file=target_apk,
                    dex_file=arguments.get("dex_file"),
                    class_name=arguments.get("class") or arguments.get("class_name"),
                    method=arguments.get("method"),
                    disasm=coerce_bool_param(arguments.get("disasm"), False, "disasm"),
                    compact=compact,
                    budget=budget,
                )

            elif tool_name in ("rvs_apk_native", "apk_native"):
                target_apk = file or arguments.get("path")
                return self.apk_native(
                    file=target_apk,
                    abi=arguments.get("abi"),
                    library=arguments.get("library"),
                    symbol=arguments.get("symbol"),
                    xrefs=coerce_bool_param(arguments.get("xrefs"), False, "xrefs"),
                    compact=compact,
                    budget=budget,
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

        if hasattr(in_stream, "reconfigure"):
            try:
                in_stream.reconfigure(errors="replace")
            except Exception:
                pass
        if hasattr(out_stream, "reconfigure"):
            try:
                out_stream.reconfigure(errors="replace")
            except Exception:
                pass

        def _send_response(payload: Dict[str, Any]) -> bool:
            try:
                out_stream.write(json.dumps(payload, separators=(',', ':')) + "\n")
                out_stream.flush()
                return True
            except (BrokenPipeError, IOError, OSError):
                return False

        def _safe_line_iter(stream: Any):
            while True:
                try:
                    line = stream.readline()
                except UnicodeDecodeError:
                    yield "\ufffd\n"
                    continue
                except (BrokenPipeError, IOError, OSError):
                    break
                except Exception:
                    break
                if not line:
                    break
                yield line

        try:
            for line in _safe_line_iter(in_stream):
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
                            "id": req.get("id") if isinstance(req, dict) and "id" in req else None,
                            "error": {"code": -32600, "message": "Invalid Request: Expected JSON-RPC 2.0 object"},
                        }
                        if not _send_response(err_response):
                            break
                        continue

                    is_notification = ("id" not in req)
                    msg_id = req.get("id")
                    method = req.get("method")
                    params = req.get("params")

                    # 1. Notification (no id field present)
                    if is_notification:
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
                            tool_name = params.get("name")
                            if not tool_name or not isinstance(tool_name, str):
                                resp = {
                                    "jsonrpc": "2.0",
                                    "id": msg_id,
                                    "error": {
                                        "code": -32602,
                                        "message": "Invalid params: 'name' is required and must be a non-empty string",
                                    },
                                }
                            else:
                                tool_args = params.get("arguments")
                                tool_result = self.execute_tool(tool_name, tool_args)
                                is_error = not tool_result.get("success", False)
                                resp = {
                                    "jsonrpc": "2.0",
                                    "id": msg_id,
                                    "result": {
                                        "content": [
                                            {
                                                "type": "text",
                                                "text": json.dumps(tool_result, separators=(',', ':')),
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
        except (BrokenPipeError, IOError, OSError, UnicodeDecodeError):
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

    # Early check for custom configuration file
    config_file_val: Optional[str] = None
    for i, a in enumerate(args):
        if a == "--config" and i + 1 < len(args):
            config_file_val = args[i + 1]
            break
        elif a.startswith("--config="):
            config_file_val = a.split("=", 1)[1]
            break

    cfg = load_harness_config(config_file_val)

    # Initialize configuration defaults from config file or system defaults
    timeout: float = float(cfg.get("timeout", DEFAULT_TIMEOUT_SECONDS))
    custom_rvs: Optional[str] = cfg.get("rvs_bin")
    explicit_mode: Optional[OutputMode] = None
    explicit_neutral: Optional[bool] = None
    explicit_compact: Optional[bool] = None
    is_mcp: bool = False
    export_tools_fmt: Optional[str] = None

    limit_val: Optional[int] = None
    offset_val: int = 0
    abi_val: Optional[str] = None
    comp_type_val: Optional[str] = None
    filter_val: Optional[str] = None
    min_len_val: Optional[int] = None
    detail_val: bool = False
    budget_val: Optional[int] = None
    cleaned_args: List[str] = []

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--config" and idx + 1 < len(args):
            idx += 2
        elif arg.startswith("--config="):
            idx += 1
        elif arg in ("--mcp", "--serve-mcp"):
            is_mcp = True
            idx += 1
        elif arg == "mcp" and idx == 0:
            is_mcp = True
            idx += 1
        elif arg in ("--export-tools", "--tools") and idx + 1 < len(args):
            export_tools_fmt = args[idx + 1]
            idx += 2
        elif arg.startswith("--export-tools=") or arg.startswith("--tools="):
            export_tools_fmt = arg.split("=", 1)[1]
            idx += 1
        elif arg == "--timeout" and idx + 1 < len(args):
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
                if mode_str == "full":
                    explicit_compact = False
                elif mode_str in ("compact", "summary"):
                    explicit_compact = True
            idx += 2
        elif arg.startswith("--mode="):
            mode_str = arg.split("=", 1)[1].lower()
            if mode_str in ("compact", "summary", "full"):
                explicit_mode = mode_str  # type: ignore
                if mode_str == "full":
                    explicit_compact = False
                elif mode_str in ("compact", "summary"):
                    explicit_compact = True
            idx += 1
        elif arg == "--compact":
            explicit_compact = True
            idx += 1
        elif arg.startswith("--compact="):
            v = arg.split("=", 1)[1].lower()
            explicit_compact = v in ("true", "1", "yes", "t", "on")
            if not explicit_compact and (explicit_mode is None or explicit_mode == "compact"):
                explicit_mode = "full"
            idx += 1
        elif arg == "--no-compact":
            explicit_compact = False
            if explicit_mode is None or explicit_mode == "compact":
                explicit_mode = "full"
            idx += 1
        elif arg == "--neutral":
            explicit_neutral = True
            idx += 1
        elif arg.startswith("--neutral="):
            v = arg.split("=", 1)[1].lower()
            explicit_neutral = v in ("true", "1", "yes", "t", "on")
            idx += 1
        elif arg == "--no-neutral":
            explicit_neutral = False
            idx += 1
        elif arg in ("--budget", "--budget-tokens") and idx + 1 < len(args):
            try:
                budget_val = int(args[idx + 1])
            except ValueError:
                pass
            idx += 2
        elif arg.startswith("--budget=") or arg.startswith("--budget-tokens="):
            try:
                budget_val = int(arg.split("=", 1)[1])
            except ValueError:
                pass
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
        elif arg == "--abi" and idx + 1 < len(args):
            abi_val = args[idx + 1]
            idx += 2
        elif arg.startswith("--abi="):
            abi_val = arg.split("=", 1)[1]
            idx += 1
        elif arg in ("--component-type", "--comp-type") and idx + 1 < len(args):
            comp_type_val = args[idx + 1]
            idx += 2
        elif arg.startswith("--component-type=") or arg.startswith("--comp-type="):
            comp_type_val = arg.split("=", 1)[1]
            idx += 1
        elif arg == "--filter" and idx + 1 < len(args):
            filter_val = args[idx + 1]
            idx += 2
        elif arg.startswith("--filter="):
            filter_val = arg.split("=", 1)[1]
            idx += 1
        elif arg == "--min-len" and idx + 1 < len(args):
            try:
                min_len_val = int(args[idx + 1])
            except ValueError:
                pass
            idx += 2
        elif arg.startswith("--min-len="):
            try:
                min_len_val = int(arg.split("=", 1)[1])
            except ValueError:
                pass
            idx += 1
        elif arg == "--detail":
            detail_val = True
            idx += 1
        else:
            cleaned_args.append(arg)
            idx += 1

    # Resolve effective defaults following 4-tier precedence
    eff_neutral, eff_compact = resolve_harness_defaults(
        explicit_neutral=explicit_neutral,
        explicit_compact=explicit_compact,
        config=cfg,
    )
    neutral_flag: bool = eff_neutral
    compact_flag: bool = eff_compact
    if explicit_mode is None:
        explicit_mode = "compact" if compact_flag else "full"

    # MCP server invocation
    if is_mcp:
        if hasattr(sys.stdin, "reconfigure"):
            try:
                sys.stdin.reconfigure(errors="replace")
            except Exception:
                pass
        if hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(errors="replace")
            except Exception:
                pass
        harness = RvsHarness(
            rvs_bin=custom_rvs,
            default_timeout=timeout,
            default_mode=explicit_mode,
            default_neutral=neutral_flag,
            default_compact=compact_flag,
            config_path=config_file_val,
        )
        harness.serve_mcp()
        sys.exit(EXIT_SUCCESS)

    # Tool schemas export flag
    if export_tools_fmt is not None:
        try:
            schemas = get_tool_schemas(export_tools_fmt)  # type: ignore
            print(json.dumps(schemas, indent=2))
            sys.exit(EXIT_SUCCESS)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            sys.exit(EXIT_INVALID_ARGUMENT)

    rvs_bin = find_rvs_binary(custom_rvs or cfg.get("rvs_bin"))

    # Extract target file for error reporting / orchestration routing
    target_str = ""
    for i, a in enumerate(cleaned_args):
        if a in ("-f", "--file") and i + 1 < len(cleaned_args):
            target_str = cleaned_args[i + 1]
            break
        elif a.startswith("-f="):
            target_str = a.split("=", 1)[1]
            break
        elif a.startswith("--file="):
            target_str = a.split("=", 1)[1]
            break

    is_apk = _is_apk_target(target_str)
    is_dex = _is_dex_target(target_str)
    is_help_or_version = any(h in cleaned_args for h in ("--help", "-h", "--version", "-V"))

    needs_orchestration = bool(
        target_str
        and not is_help_or_version
        and (is_apk or is_dex or neutral_flag or abi_val is not None or comp_type_val is not None)
    )

    if needs_orchestration:
        # Extract command tokens from cleaned_args
        cmd_tokens: List[str] = []
        skip_next = False
        for i, a in enumerate(cleaned_args):
            if skip_next:
                skip_next = False
                continue
            if a in ("-f", "--file"):
                skip_next = True
                continue
            if a.startswith("-f=") or a.startswith("--file="):
                continue
            if a in ("-c", "--compact"):
                continue
            if a == "--format":
                skip_next = True
                continue
            if a.startswith("--format="):
                continue
            cmd_tokens.append(a)

        tool_name = "rvs_info"
        tool_args: Dict[str, Any] = {
            "file": target_str,
            "compact": compact_flag,
            "neutral": neutral_flag,
        }
        if abi_val:
            tool_args["abi"] = abi_val
        if comp_type_val:
            tool_args["component_type"] = comp_type_val
        if limit_val is not None:
            tool_args["limit"] = limit_val
        if offset_val > 0:
            tool_args["offset"] = offset_val
        if filter_val:
            tool_args["filter"] = filter_val
        if min_len_val is not None:
            tool_args["min_len"] = min_len_val
        if detail_val:
            tool_args["detail"] = detail_val
        if budget_val is not None:
            tool_args["budget"] = budget_val

        if not cmd_tokens or cmd_tokens[0] == "info":
            tool_name = "rvs_info"
        elif cmd_tokens[0] == "functions" or (cmd_tokens[0] == "analyze" and len(cmd_tokens) > 1 and cmd_tokens[1] == "functions"):
            tool_name = "rvs_functions"
        elif cmd_tokens[0] in ("disasm", "blocks") or (cmd_tokens[0] == "analyze" and len(cmd_tokens) > 1 and cmd_tokens[1] == "blocks"):
            tool_name = "rvs_disasm"
            target_fn = cmd_tokens[-1] if len(cmd_tokens) > 1 and cmd_tokens[-1] not in ("disasm", "blocks", "analyze") else None
            if target_fn:
                tool_args["target"] = target_fn
        elif cmd_tokens[0] == "decompile" or (cmd_tokens[0] == "agent" and len(cmd_tokens) > 1 and cmd_tokens[1] == "decompile"):
            tool_name = "rvs_decompile"
            target_fn = cmd_tokens[-1] if len(cmd_tokens) > 1 and cmd_tokens[-1] not in ("decompile", "agent") else None
            if target_fn:
                tool_args["function"] = target_fn
        elif cmd_tokens[0] == "flow" or (cmd_tokens[0] == "agent" and len(cmd_tokens) > 1 and cmd_tokens[1] == "flow"):
            tool_name = "rvs_flow"
            target_fn = cmd_tokens[-1] if len(cmd_tokens) > 1 and cmd_tokens[-1] not in ("flow", "agent") else None
            if target_fn:
                tool_args["function"] = target_fn
        elif cmd_tokens[0] == "xrefs" or (cmd_tokens[0] == "analyze" and len(cmd_tokens) > 1 and cmd_tokens[1] == "xrefs"):
            tool_name = "rvs_xrefs"
            target_sym = cmd_tokens[-1] if len(cmd_tokens) > 1 and cmd_tokens[-1] not in ("xrefs", "analyze") else None
            if target_sym:
                tool_args["target"] = target_sym
        elif cmd_tokens[0] == "strings":
            tool_name = "rvs_strings"
        elif cmd_tokens[0] == "symbols":
            tool_name = "rvs_symbols"
        elif cmd_tokens[0] == "triage" or (cmd_tokens[0] == "agent" and len(cmd_tokens) > 1 and cmd_tokens[1] == "triage"):
            tool_name = "rvs_agent_triage"

        harness = RvsHarness(
            rvs_bin=rvs_bin,
            default_timeout=timeout,
            default_mode=explicit_mode,
            default_neutral=neutral_flag,
            default_compact=compact_flag,
            config_path=config_file_val,
        )
        resp = harness.execute_tool(tool_name, tool_args)
        print(json.dumps(resp))
        raw_code = EXIT_SUCCESS if resp.get("success") else (resp.get("error", {}).get("exit_code") or EXIT_ANALYSIS_ERROR)
        sys.exit(normalize_exit_code(raw_code))

    if compact_flag and "-c" not in cleaned_args and "--compact" not in cleaned_args:
        cleaned_args = ["-c"] + cleaned_args

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
                if explicit_mode is not None or limit_val is not None or offset_val > 0 or budget_val is not None:
                    mode_to_use = explicit_mode or "compact"
                    parsed = transform_response(
                        parsed, mode=mode_to_use, limit=limit_val, offset=offset_val, budget=budget_val
                    )

                print(json.dumps(parsed))
            else:
                print(stdout, end="")
        except json.JSONDecodeError:
            # Non-JSON or streaming output (e.g. jsonl, markdown, raw text)
            print(stdout, end="")
    elif stderr.strip():
        print(stderr, file=sys.stderr, end="")

    sys.exit(normalize_exit_code(code))


if __name__ == "__main__":
    main()
