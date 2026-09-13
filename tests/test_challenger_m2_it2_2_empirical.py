#!/usr/bin/env python3
"""
tests/test_challenger_m2_it2_2_empirical.py - Empirical Adversarial Challenger Test Suite (Iteration 2)
Milestone 2: rvs frida Dynamic Instrumentation Subsystem

Stress-tests:
1. Target probe parsing & session info extraction (JSON :ij, Key-Value :i, edge cases, fallbacks)
2. FridaDriver timeout watchdog under artificial subprocess delays and hanging processes
3. Subprocess buffer-flood & pipe handling under timeout enforcement
4. Process attachment & organic permission denied detection
5. High-concurrency thread & process stress testing
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
RVS_RELEASE_BIN = WORKSPACE_DIR / "target" / "release" / "rvs"
RVS_DEBUG_BIN = WORKSPACE_DIR / "target" / "debug" / "rvs"

FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"
AUTH_GATE = FIXTURES_DIR / "auth_gate"

# Strict ANSI escape sequence regex
ANSI_REGEX = re.compile(r"(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])")

# Standard exit codes
EXIT_SUCCESS = 0
EXIT_INVALID_ARGUMENT = 1
EXIT_FILE_ERROR = 2
EXIT_ANALYSIS_ERROR = 3
EXIT_PATCH_ERROR = 4
EXIT_TIMEOUT_ERROR = 5
EXIT_INTERNAL_ERROR = 6


def get_rvs_bin() -> Path:
    if RVS_RELEASE_BIN.exists():
        return RVS_RELEASE_BIN
    if RVS_DEBUG_BIN.exists():
        return RVS_DEBUG_BIN
    raise RuntimeError("No rvs binary found in target/release/rvs or target/debug/rvs")


def run_rvs_cmd(
    args: List[str],
    env: Optional[Dict[str, str]] = None,
    timeout: float = 15.0,
) -> Tuple[int, Optional[Dict[str, Any]], str, str]:
    """Runs rvs binary with isolated environment and returns (rc, parsed_json, stdout, stderr)."""
    bin_path = get_rvs_bin()
    cmd = [str(bin_path)] + args
    effective_env = os.environ.copy()
    if env:
        effective_env.update(env)

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=effective_env,
        timeout=timeout,
    )

    stdout = proc.stdout
    stderr = proc.stderr
    rc = proc.returncode

    parsed_json: Optional[Dict[str, Any]] = None
    if stdout.strip():
        try:
            parsed_json = json.loads(stdout)
        except Exception:
            pass

    return rc, parsed_json, stdout, stderr


class TestTargetProbeAndSessionInfo(unittest.TestCase):
    """Stress tests target probe parsing and session info extraction via rvs CLI."""

    def setUp(self):
        self.temp_bin_dir = tempfile.mkdtemp(prefix="rvs_probe_r2_")
        self.mock_r2 = Path(self.temp_bin_dir) / "radare2"
        self.custom_env = os.environ.copy()
        self.custom_env["PATH"] = f"{self.temp_bin_dir}:{self.custom_env.get('PATH', '')}"

    def tearDown(self):
        shutil.rmtree(self.temp_bin_dir, ignore_errors=True)

    def _create_mock_r2(self, probe_output: str, exit_code: int = 0):
        content = f"""#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{{"name":"frida","uris":["frida://"]}}]'
        exit 0
    fi
    if [ "$arg" = ":i" ]; then
        cat << 'EOF'
{probe_output}
EOF
        exit {exit_code}
    fi
done
exit 0
"""
        self.mock_r2.write_text(content)
        self.mock_r2.chmod(0o755)

    def test_01_attach_probe_key_value_success(self):
        """Test attaching to target when :i returns standard key-value output."""
        probe_kv = """arch: arm64
bits: 64
os: linux
pid: 4321
"""
        self._create_mock_r2(probe_kv)
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "4321"], env=self.custom_env)

        self.assertEqual(rc, EXIT_SUCCESS, f"Expected 0, got {rc}. Output: {stdout}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        session = data.get("data", {})
        self.assertEqual(session.get("arch"), "arm64")
        self.assertEqual(session.get("bits"), 64)
        self.assertEqual(session.get("os"), "linux")
        self.assertEqual(session.get("pid"), 4321)
        self.assertTrue(session.get("connected"))

    def test_02_attach_probe_json_format_success(self):
        """Test attaching to target when probe returns JSON format."""
        probe_json = '{"arch": "riscv64", "bits": 64, "os": "freebsd", "pid": 9876}'
        self._create_mock_r2(probe_json)
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "target_proc"], env=self.custom_env)

        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIsNotNone(data)
        session = data.get("data", {})
        self.assertEqual(session.get("arch"), "riscv64")
        self.assertEqual(session.get("bits"), 64)
        self.assertEqual(session.get("os"), "freebsd")
        self.assertEqual(session.get("pid"), 9876)
        self.assertEqual(session.get("target"), "target_proc")

    def test_03_attach_probe_empty_or_corrupt_falls_back_gracefully(self):
        """Test attaching to target when :i returns garbage/corrupt data; falls back to host platform without panicking."""
        self._create_mock_r2("{corrupt json without closing brace, bits: 999")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "1000"], env=self.custom_env)

        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIsNotNone(data)
        session = data.get("data", {})
        # PID retained from parsed_target
        self.assertEqual(session.get("pid"), 1000)
        # Arch, bits, os fallback to host defaults
        self.assertIsNotNone(session.get("arch"))
        self.assertIn(session.get("bits"), [32, 64])
        self.assertIsNotNone(session.get("os"))

    def test_04_spawn_probe_populates_session(self):
        """Test spawning a binary with mock driver extracting genuine PID from probe."""
        probe_spawn = """arch: x86_64
bits: 64
os: linux
pid: 6543
"""
        self._create_mock_r2(probe_spawn)
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "spawn", str(AUTH_GATE)], env=self.custom_env)

        self.assertEqual(rc, EXIT_SUCCESS)
        self.assertIsNotNone(data)
        session = data.get("data", {})
        self.assertEqual(session.get("pid"), 6543)
        self.assertEqual(session.get("arch"), "x86_64")
        self.assertEqual(session.get("bits"), 64)


class TestTimeoutWatchdogUnderDelays(unittest.TestCase):
    """Stress tests FridaDriver timeout watchdog under artificial delays and buffer pressure."""

    def setUp(self):
        self.temp_bin_dir = tempfile.mkdtemp(prefix="rvs_timeout_r2_")
        self.mock_r2 = Path(self.temp_bin_dir) / "radare2"
        self.custom_env = os.environ.copy()
        self.custom_env["PATH"] = f"{self.temp_bin_dir}:{self.custom_env.get('PATH', '')}"

    def tearDown(self):
        shutil.rmtree(self.temp_bin_dir, ignore_errors=True)

    def _create_hanging_mock_r2(self, pre_output: str = "", sleep_seconds: int = 20):
        content = f"""#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{{"name":"frida","uris":["frida://"]}}]'
        exit 0
    fi
done
{pre_output}
exec sleep {sleep_seconds}
"""
        self.mock_r2.write_text(content)
        self.mock_r2.chmod(0o755)

    def test_01_attach_timeout_watchdog(self):
        """Verify `rvs frida attach ... --timeout 1` terminates hanging subprocess promptly."""
        self._create_hanging_mock_r2()
        t0 = time.time()
        rc, data, stdout, stderr = run_rvs_cmd(
            ["frida", "attach", "1234", "--timeout", "1"],
            env=self.custom_env,
            timeout=10.0,
        )
        elapsed = time.time() - t0

        self.assertLess(elapsed, 4.0, f"Watchdog took {elapsed:.2f}s; deadline not enforced promptly")
        self.assertEqual(rc, EXIT_TIMEOUT_ERROR)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("code"), "TIMEOUT_EXPIRED")
        self.assertEqual(data.get("error", {}).get("exit_code"), EXIT_TIMEOUT_ERROR)
        self.assertEqual(data.get("error", {}).get("category"), "TIMEOUT_ERROR")

    def test_02_spawn_timeout_watchdog(self):
        """Verify `rvs frida spawn ... --timeout 1` terminates hanging subprocess promptly."""
        self._create_hanging_mock_r2()
        t0 = time.time()
        rc, data, stdout, stderr = run_rvs_cmd(
            ["frida", "spawn", str(AUTH_GATE), "--timeout", "1"],
            env=self.custom_env,
            timeout=10.0,
        )
        elapsed = time.time() - t0

        self.assertLess(elapsed, 4.0)
        self.assertEqual(rc, EXIT_TIMEOUT_ERROR)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("code"), "TIMEOUT_EXPIRED")

    def test_03_script_timeout_watchdog(self):
        """Verify `rvs frida script ... --timeout 1` terminates hanging subprocess promptly."""
        self._create_hanging_mock_r2()
        t0 = time.time()
        rc, data, stdout, stderr = run_rvs_cmd(
            ["frida", "script", "--target", "0", "--code", "1+1", "--timeout", "1"],
            env=self.custom_env,
            timeout=10.0,
        )
        elapsed = time.time() - t0

        self.assertLess(elapsed, 4.0)
        self.assertEqual(rc, EXIT_TIMEOUT_ERROR)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("code"), "TIMEOUT_EXPIRED")

    def test_04_buffer_flooding_before_hang_unblocks_cleanly(self):
        """Verify watchdog does not deadlock on full pipe buffer when child floods output before hanging."""
        flood_script = """python3 -c "import sys; sys.stdout.write('X'*65536); sys.stderr.write('Y'*65536); sys.stdout.flush(); sys.stderr.flush()" """
        self._create_hanging_mock_r2(pre_output=flood_script)

        t0 = time.time()
        rc, data, stdout, stderr = run_rvs_cmd(
            ["frida", "attach", "1234", "--timeout", "1"],
            env=self.custom_env,
            timeout=10.0,
        )
        elapsed = time.time() - t0

        self.assertLess(elapsed, 4.0)
        self.assertEqual(rc, EXIT_TIMEOUT_ERROR)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("code"), "TIMEOUT_EXPIRED")


class TestProcessAttachmentAndPermissions(unittest.TestCase):
    """Stress tests organic permission detection and attach failure handling."""

    def setUp(self):
        self.temp_bin_dir = tempfile.mkdtemp(prefix="rvs_perm_r2_")
        self.mock_r2 = Path(self.temp_bin_dir) / "radare2"
        self.custom_env = os.environ.copy()
        self.custom_env["PATH"] = f"{self.temp_bin_dir}:{self.custom_env.get('PATH', '')}"

    def tearDown(self):
        shutil.rmtree(self.temp_bin_dir, ignore_errors=True)

    def _create_mock_r2_with_error(self, err_message: str, exit_code: int = 1):
        content = f"""#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{{"name":"frida","uris":["frida://"]}}]'
        exit 0
    fi
done
echo "{err_message}" >&2
exit {exit_code}
"""
        self.mock_r2.write_text(content)
        self.mock_r2.chmod(0o755)

    def test_01_permission_denied_operation_not_permitted(self):
        """Verify 'Operation not permitted' in stderr maps to exit code 2 (PERMISSION_DENIED)."""
        self._create_mock_r2_with_error("ptrace(PTRACE_ATTACH, 1) failed: Operation not permitted")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "1"], env=self.custom_env)

        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIsNotNone(data)
        self.assertFalse(data.get("success"))
        err = data.get("error", {})
        self.assertEqual(err.get("code"), "PERMISSION_DENIED")
        self.assertEqual(err.get("category"), "FILE_ERROR")
        self.assertEqual(err.get("exit_code"), EXIT_FILE_ERROR)
        self.assertIn("Permission denied", err.get("message", ""))

    def test_02_permission_denied_cap_sys_ptrace(self):
        """Verify 'CAP_SYS_PTRACE' in stderr maps to exit code 2 (PERMISSION_DENIED)."""
        self._create_mock_r2_with_error("frida: attach requires CAP_SYS_PTRACE or root")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "1"], env=self.custom_env)

        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIsNotNone(data)
        err = data.get("error", {})
        self.assertEqual(err.get("code"), "PERMISSION_DENIED")

    def test_03_frida_attach_failed_generic_error(self):
        """Verify generic attach error maps to exit code 3 (ANALYSIS_ERROR)."""
        self._create_mock_r2_with_error("Cannot find target process by name 'ghost_proc'")
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "ghost_proc"], env=self.custom_env)

        self.assertEqual(rc, EXIT_ANALYSIS_ERROR)
        self.assertIsNotNone(data)
        err = data.get("error", {})
        self.assertEqual(err.get("code"), "FRIDA_ATTACH_FAILED")
        self.assertEqual(err.get("category"), "ANALYSIS_ERROR")
        self.assertEqual(err.get("exit_code"), EXIT_ANALYSIS_ERROR)


class TestConcurrencyAndParallelStress(unittest.TestCase):
    """Stress tests concurrent rvs frida commands across threads and processes."""

    def test_01_multithreaded_concurrency_stress(self):
        """Execute 60 concurrent mixed frida subcommands across 16 worker threads."""
        cmds = [
            ["frida", "env-check"],
            ["frida", "attach", "1234", "--timeout", "1"],
            ["frida", "modules", "-t", "0"],
            ["frida", "symbols", "-t", "0"],
            ["frida", "classes", "-t", "0"],
            ["frida", "hooks-list", "-t", "0"],
            ["frida", "hook", "-t", "0", "-A", "0x401000", "--format", "x"],
            ["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", "rax"],
            ["frida", "trace-regs", "-t", "0", "-A", "0x401000", "--regs", ",,,"],
            ["frida", "script", "-t", "0", "--code", "1+1"],
            ["frida", "script", "-t", "0", "--code", "1+1", "--file", "/nonexistent.js"],
        ]

        def invoke(i: int):
            cmd = cmds[i % len(cmds)]
            return i, cmd, run_rvs_cmd(cmd)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(invoke, range(60)))

        for i, cmd, (rc, data, stdout, stderr) in results:
            self.assertIsNotNone(data, f"Run {i} ({cmd}) failed JSON parsing: {stdout}")
            self.assertIn("command", data)
            self.assertIn("timestamp", data)
            self.assertFalse(ANSI_REGEX.search(stdout))
            self.assertNotIn("\r", stdout)

            # Check pre-flight validation on empty regs
            if ",,," in cmd:
                self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
                self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

            # Check mutual exclusion on script
            if "--code" in cmd and "--file" in cmd:
                self.assertEqual(rc, EXIT_INVALID_ARGUMENT)

    def test_02_multiprocess_concurrency_stress(self):
        """Execute 20 concurrent invocations across separate OS worker processes."""
        cmds = [
            ["frida", "env-check"],
            ["frida", "attach", "9999", "--timeout", "1"],
            ["frida", "spawn", str(AUTH_GATE)],
            ["frida", "modules", "-t", "0"],
        ] * 5

        with concurrent.futures.ProcessPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run_rvs_cmd, cmds))

        for rc, data, stdout, stderr in results:
            self.assertIsNotNone(data)
            self.assertIn("format_version", data)
            self.assertFalse(ANSI_REGEX.search(stdout))


if __name__ == "__main__":
    unittest.main()
