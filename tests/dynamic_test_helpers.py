#!/usr/bin/env python3
"""
tests/dynamic_test_helpers.py - Shared Test Utilities & Probes for Dynamic E2E Tests.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import (
    ANSI_ESCAPE_RE,
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    CANONICAL_TOOLS,
    RvsHarness,
    find_rvs_binary,
    get_tool_schemas,
)

FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"

CRASH_TARGET_BIN = FIXTURES_DIR / "crash_target_elf64"
DECRYPTOR_TARGET_BIN = FIXTURES_DIR / "decryptor_target_elf64"
ANTIDEBUG_TARGET_BIN = FIXTURES_DIR / "antidebug_target_elf64"
AUTH_GATE_BIN = FIXTURES_DIR / "auth_gate_elf64"
FLOW_CALC_BIN = FIXTURES_DIR / "flow_calc_elf64"
TEST_TARGET_BIN = FIXTURES_DIR / "test_target_elf64"
CRACKME_CASE_BIN = FIXTURES_DIR / "crackme_case"


def get_target_binary() -> Path:
    """Finds the rvs executable."""
    bin_path = find_rvs_binary()
    if not bin_path or not bin_path.exists():
        fallback = WORKSPACE_DIR / "target" / "debug" / "rvs"
        if fallback.exists():
            return fallback
        raise RuntimeError("rvs binary not found. Build target/debug/rvs first.")
    return bin_path


def run_rvs_cmd(
    args: List[str],
    timeout: float = 25.0,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
) -> Tuple[int, Optional[Dict[str, Any]], str, str]:
    """Executes rvs CLI subprocess and returns (returncode, parsed_json, stdout, stderr)."""
    bin_path = get_target_binary()
    cmd = [str(bin_path)] + args
    proc_env = os.environ.copy()
    proc_env["TERM"] = "dumb"
    proc_env["NO_COLOR"] = "1"
    if env:
        proc_env.update(env)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=proc_env,
            cwd=str(cwd or WORKSPACE_DIR),
        )
    except subprocess.TimeoutExpired as e:
        return EXIT_TIMEOUT_ERROR, None, "", f"TimeoutExpired: {e}"

    parsed_json = None
    stdout_clean = proc.stdout.strip()
    if stdout_clean:
        try:
            parsed_json = json.loads(stdout_clean)
        except Exception:
            pass

    return proc.returncode, parsed_json, proc.stdout, proc.stderr


def run_harness_cli(
    args: List[str],
    timeout: float = 25.0,
) -> Tuple[int, Optional[Dict[str, Any]], str, str]:
    """Executes rvs_agent_harness.py as a CLI subprocess."""
    cmd = [sys.executable, str(WORKSPACE_DIR / "rvs_agent_harness.py")] + args
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(WORKSPACE_DIR),
        )
    except subprocess.TimeoutExpired as e:
        return EXIT_TIMEOUT_ERROR, None, "", f"TimeoutExpired: {e}"

    parsed_json = None
    stdout_clean = proc.stdout.strip()
    if stdout_clean:
        try:
            parsed_json = json.loads(stdout_clean)
        except Exception:
            pass

    return proc.returncode, parsed_json, proc.stdout, proc.stderr


def send_mcp_request(
    req: Dict[str, Any],
    harness: Optional[RvsHarness] = None,
) -> Dict[str, Any]:
    """Sends a JSON-RPC request to RvsHarness.serve_mcp and returns the response."""
    h = harness or RvsHarness(rvs_bin=get_target_binary())
    sin = io.StringIO(json.dumps(req) + "\n")
    sout = io.StringIO()
    h.serve_mcp(stdin_stream=sin, stdout_stream=sout)
    sout.seek(0)
    output_str = sout.read().strip()
    if not output_str:
        return {}
    return json.loads(output_str)


# =============================================================================
# Capability Probes (Progressive Testability)
# =============================================================================

def is_debug_cli_available() -> bool:
    """Checks if 'rvs dynamic debug' subcommand is compiled into rvs CLI."""
    rc, json_data, stdout, stderr = run_rvs_cmd(["dynamic", "--help"], timeout=5.0)
    if rc != 0:
        return False
    # Check if 'debug' is listed as a subcommand under dynamic
    lines = stdout.splitlines()
    in_commands = False
    for line in lines:
        if line.strip().startswith("Commands:"):
            in_commands = True
            continue
        if in_commands:
            if line.strip().startswith("debug"):
                return True
            if line.strip().startswith("Options:"):
                break
    return False


def is_frida_cli_available() -> bool:
    """Checks if 'rvs frida' subcommand is compiled into rvs CLI."""
    rc, json_data, stdout, stderr = run_rvs_cmd(["--help"], timeout=5.0)
    if rc != 0:
        return False
    # Check if 'frida' is listed as a top-level subcommand
    lines = stdout.splitlines()
    in_commands = False
    for line in lines:
        if line.strip().startswith("Commands:"):
            in_commands = True
            continue
        if in_commands:
            if line.strip().startswith("frida"):
                return True
            if line.strip().startswith("Options:"):
                break
    return False


def is_canonical_tools_expanded() -> bool:
    """Checks if CANONICAL_TOOLS in rvs_agent_harness has been expanded to 26 tools."""
    return len(CANONICAL_TOOLS) >= 26


def is_crash_triage_available() -> bool:
    """Checks if RvsHarness has triage_crash method."""
    return hasattr(RvsHarness, "triage_crash")


def is_gate_bypass_available() -> bool:
    """Checks if RvsHarness has bypass_decision_gate method."""
    return hasattr(RvsHarness, "bypass_decision_gate")


def is_buffer_dump_available() -> bool:
    """Checks if RvsHarness has dump_decrypted_buffer method."""
    return hasattr(RvsHarness, "dump_decrypted_buffer")


def is_anti_debug_available() -> bool:
    """Checks if RvsHarness has detect_anti_debug method."""
    return hasattr(RvsHarness, "detect_anti_debug")


def is_r2frida_installed() -> bool:
    """Checks if radare2 has the io_frida plugin loaded via Loj."""
    try:
        proc = subprocess.run(
            ["radare2", "-qc", "Loj", "-"],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            plugins = json.loads(proc.stdout.strip())
            for p in plugins:
                if p.get("name") == "frida" or "frida://" in p.get("uris", []):
                    return True
    except Exception:
        pass
    return False


# =============================================================================
# Validation & Assertion Helpers
# =============================================================================

def assert_no_ansi(text: str) -> bool:
    """Returns True if string is free from ANSI escape sequences."""
    return not bool(ANSI_ESCAPE_RE.search(text))


def assert_valid_envelope(data: Optional[Dict[str, Any]], expected_cmd: Optional[str] = None) -> bool:
    """Validates that a dictionary adheres to the canonical ApiResponse structure."""
    if not isinstance(data, dict):
        return False
    if "success" not in data:
        return False
    if "command" not in data:
        return False
    if expected_cmd and data.get("command") != expected_cmd:
        return False
    return True


def assert_valid_error_envelope(data: Optional[Dict[str, Any]], expected_exit_code: Optional[int] = None) -> bool:
    """Validates that a response dictionary represents a valid error envelope."""
    if not isinstance(data, dict):
        return False
    if data.get("success") is not False:
        return False
    err = data.get("error")
    if not isinstance(err, dict):
        return False
    if "code" not in err or "message" not in err:
        return False
    if expected_exit_code is not None and err.get("exit_code") != expected_exit_code:
        return False
    return True
