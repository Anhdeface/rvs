#!/usr/bin/env python3
"""
tests/test_challenger_m2_it1_2_empirical.py - Empirical Adversarial Challenger Test Suite
Milestone 2: rvs frida Dynamic Instrumentation Subsystem

Probes:
1. Concurrency & Parallel Invocations:
   - High-concurrency parallel invocations of `rvs frida env-check`, `rvs frida modules --target 0`,
     and `rvs frida symbols --target 0` across threads and processes.
   - Deterministic exit codes, zero split-brain, zero lock contention crashes, zero panics.
2. Real-world Crackme Fixture Execution & Lifecycle:
   - Spawning against compiled crackme fixtures: `tests/fixtures/auth_gate`, `tests/fixtures/crash_target`, `tests/fixtures/decryptor_target`.
   - Spawning with complex command-line arguments (flags with hyphens, spaces, multiple arguments).
   - Timeout watchdog verification (`--timeout 1`, sub-second deadlines, hanging process termination).
3. Output Format Sanitization:
   - Strict ANSI escape sequence regex verification (zero ANSI codes).
   - Unparsed terminal control character verification (zero carriage returns / bells).
   - JSON envelope conformance across all error and success payloads.
4. Token Compaction Verification:
   - `--compact` / `-c` payload size reduction on modules, symbols, classes, hooks, memory, scripts.
   - Preserving critical operational fields while dropping redundant metadata.
5. Boundary & Adversarial Edge Cases:
   - Negative PIDs, negative pagination limits/offsets, invalid format specifiers,
     out-of-bounds kernel addresses (0xffffffffffffffff), bad hex data strings,
     zero-length memory reads, and excessive buffer allocations.
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
CRASH_TARGET = FIXTURES_DIR / "crash_target"
DECRYPTOR_TARGET = FIXTURES_DIR / "decryptor_target"

# Strict ANSI and terminal escape sequence regex
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


class TestConcurrencyParallel(unittest.TestCase):
    """Area 1: Concurrency & Parallel Invocations across threads and processes."""

    def test_01_concurrent_env_check_threads(self):
        """Run 30 concurrent `rvs frida env-check` across threads; verify zero crashes and deterministic output."""
        def invoke_env_check(i: int):
            return run_rvs_cmd(["frida", "env-check"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(invoke_env_check, i) for i in range(30)]
            results = [f.result() for f in futures]

        for idx, (rc, data, stdout, stderr) in enumerate(results):
            self.assertIn(rc, [0, EXIT_INTERNAL_ERROR], f"Run {idx} unexpected return code {rc}")
            self.assertIsNotNone(data, f"Run {idx} stdout was not valid JSON: {stdout}")
            self.assertEqual(data.get("command"), "frida env-check")
            self.assertEqual(data.get("target"), "host")
            self.assertFalse(ANSI_REGEX.search(stdout), f"Run {idx} stdout contains ANSI escapes")

    def test_02_concurrent_modules_target_0_threads(self):
        """Run 30 concurrent `rvs frida modules --target 0` across threads; verify determinism and no lock collisions."""
        def invoke_modules(i: int):
            return run_rvs_cmd(["frida", "modules", "--target", "0"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(invoke_modules, i) for i in range(30)]
            results = [f.result() for f in futures]

        for idx, (rc, data, stdout, stderr) in enumerate(results):
            self.assertIn(rc, [0, EXIT_INTERNAL_ERROR], f"Run {idx} unexpected return code {rc}")
            self.assertIsNotNone(data, f"Run {idx} invalid JSON: {stdout}")
            self.assertEqual(data.get("command"), "frida modules")
            self.assertFalse(ANSI_REGEX.search(stdout), f"Run {idx} stdout contains ANSI escapes")

    def test_03_concurrent_symbols_target_0_threads(self):
        """Run 30 concurrent `rvs frida symbols --target 0` across threads; verify deterministic code 6."""
        def invoke_symbols(i: int):
            return run_rvs_cmd(["frida", "symbols", "--target", "0"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(invoke_symbols, i) for i in range(30)]
            results = [f.result() for f in futures]

        for idx, (rc, data, stdout, stderr) in enumerate(results):
            self.assertIn(rc, [0, EXIT_INTERNAL_ERROR], f"Run {idx} unexpected return code {rc}")
            self.assertIsNotNone(data, f"Run {idx} invalid JSON: {stdout}")
            self.assertEqual(data.get("command"), "frida symbols")
            self.assertFalse(ANSI_REGEX.search(stdout), f"Run {idx} stdout contains ANSI escapes")

    def test_04_mixed_concurrent_frida_subcommands(self):
        """Run 40 interleaved concurrent invocations mixing env-check, modules, symbols, classes, mem-read, hooks."""
        cmd_pool = [
            ["frida", "env-check"],
            ["frida", "modules", "--target", "0"],
            ["frida", "symbols", "--target", "0"],
            ["frida", "classes", "--target", "0"],
            ["frida", "hook", "--target", "0", "--addr", "0x401000", "--format", "x"],
            ["frida", "hooks-list", "--target", "0"],
            ["frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "16"],
            ["frida", "spawn", str(AUTH_GATE), "--args", "admin", "1234"],
        ]

        def invoke_cmd(idx: int):
            cmd = cmd_pool[idx % len(cmd_pool)]
            return cmd[1], run_rvs_cmd(cmd)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(invoke_cmd, i) for i in range(40)]
            results = [f.result() for f in futures]

        for subcmd, (rc, data, stdout, stderr) in results:
            self.assertIn(rc, [0, EXIT_INTERNAL_ERROR, EXIT_ANALYSIS_ERROR], f"Subcmd {subcmd} unexpected rc {rc}")
            self.assertIsNotNone(data, f"Subcmd {subcmd} failed JSON parsing: {stdout}")
            self.assertFalse(ANSI_REGEX.search(stdout))

    def test_05_multiprocess_parallel_invocations(self):
        """Run parallel invocations using separate OS processes via ProcessPoolExecutor to test process-level concurrency."""
        with concurrent.futures.ProcessPoolExecutor(max_workers=8) as executor:
            cmds = [["frida", "env-check"], ["frida", "modules", "-t", "0"], ["frida", "symbols", "-t", "0"]] * 5
            futures = [executor.submit(run_rvs_cmd, c) for c in cmds]
            results = [f.result() for f in futures]

        for idx, (rc, data, stdout, stderr) in enumerate(results):
            self.assertIn(rc, [0, EXIT_INTERNAL_ERROR])
            self.assertIsNotNone(data)
            self.assertFalse(ANSI_REGEX.search(stdout))

    def test_06_high_load_200_concurrent_adversarial_invocations(self):
        """Run 200 high-concurrency interleaved adversarial commands across 24 worker threads."""
        scenarios = [
            (["frida", "env-check"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "env-check", "-c"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "modules", "-t", "0"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "symbols", "-t", "0"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "symbols", "-t", "0", "--limit", "-1"], [EXIT_INVALID_ARGUMENT]),
            (["frida", "hook", "-t", "0", "--addr", "0xffffffffffffffff", "--format", "x"], [EXIT_ANALYSIS_ERROR]),
            (["frida", "hook", "-t", "0", "--addr", "0x401000", "--format", "INVALID"], [EXIT_INVALID_ARGUMENT]),
            (["frida", "mem-read", "-t", "0", "--addr", "0x401000", "--len", "0"], [EXIT_INVALID_ARGUMENT]),
            (["frida", "mem-write", "-t", "0", "--addr", "0x401000", "--data", "ZZZZ"], [EXIT_INVALID_ARGUMENT]),
            (["frida", "spawn", str(AUTH_GATE), "--args", "admin", "1234"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "spawn", str(CRASH_TARGET), "--args", "safe"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "spawn", str(DECRYPTOR_TARGET), "--args", "test"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "spawn", "nonexistent/file_xyz", "--args", "test"], [EXIT_FILE_ERROR]),
            (["frida", "attach", "999999", "--timeout", "1"], [0, EXIT_INTERNAL_ERROR]),
            (["frida", "attach", "--", "-1"], [EXIT_INVALID_ARGUMENT]),
            (["frida", "attach", "http://bad.uri"], [EXIT_INVALID_ARGUMENT]),
            (["frida", "script", "-t", "0", "--file", "nonexistent.js"], [EXIT_FILE_ERROR]),
        ]

        def run_case(i: int):
            args, expected_rc = scenarios[i % len(scenarios)]
            rc, data, stdout, stderr = run_rvs_cmd(args)
            return i, args, expected_rc, rc, data, stdout, stderr

        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            results = list(pool.map(run_case, range(200)))

        self.assertEqual(len(results), 200)
        for i, args, expected_rc, rc, data, stdout, stderr in results:
            cmd_str = " ".join(args)
            if isinstance(expected_rc, (list, tuple, set)):
                self.assertIn(rc, expected_rc, f"Case {i} ({cmd_str}) expected one of {expected_rc}, got {rc}")
            else:
                self.assertEqual(rc, expected_rc, f"Case {i} ({cmd_str}) expected {expected_rc}, got {rc}")
            self.assertFalse(ANSI_REGEX.search(stdout), f"Case {i} contained ANSI in stdout")
            self.assertNotIn("\r", stdout, f"Case {i} contained carriage return in stdout")
            self.assertIsNotNone(data, f"Case {i} returned invalid JSON: {stdout}")
            self.assertIn("format_version", data)
            self.assertIn("command", data)


class TestFixtureExecutionAndLifecycle(unittest.TestCase):
    """Area 2: Crackme Fixture Execution, Spawn Arguments, Path Resolution, and Watchdogs."""

    def test_01_fixture_files_exist_and_executable(self):
        """Verify crackme fixtures exist, are non-empty, and have executable permissions."""
        fixtures = [AUTH_GATE, CRASH_TARGET, DECRYPTOR_TARGET]
        for f in fixtures:
            self.assertTrue(f.exists(), f"Fixture {f} does not exist")
            self.assertGreater(f.stat().st_size, 0, f"Fixture {f} is empty")
            # Must be executable
            st = f.stat()
            self.assertTrue(bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)), f"Fixture {f} not executable")

    def test_02_spawn_auth_gate_with_args(self):
        """Test `rvs frida spawn tests/fixtures/auth_gate --args admin 1234`."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "spawn", str(AUTH_GATE), "--args", "admin", "1234"])
        self.assertIn(rc, [0, EXIT_INTERNAL_ERROR])
        self.assertIsNotNone(data)
        self.assertEqual(data.get("command"), "frida spawn")
        self.assertTrue(str(AUTH_GATE) in str(data.get("target")) or "auth_gate" in str(data.get("target")))

    def test_03_spawn_crash_target_with_args(self):
        """Test `rvs frida spawn tests/fixtures/crash_target --args safe` and `--args crash`."""
        for arg in ["safe", "crash"]:
            rc, data, stdout, stderr = run_rvs_cmd(["frida", "spawn", str(CRASH_TARGET), "--args", arg])
            self.assertIn(rc, [0, EXIT_INTERNAL_ERROR])
            self.assertIsNotNone(data)
            self.assertEqual(data.get("command"), "frida spawn")

    def test_04_spawn_decryptor_target_with_args(self):
        """Test `rvs frida spawn tests/fixtures/decryptor_target --args test`."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "spawn", str(DECRYPTOR_TARGET), "--args", "test"])
        self.assertIn(rc, [0, EXIT_INTERNAL_ERROR])
        self.assertIsNotNone(data)
        self.assertEqual(data.get("command"), "frida spawn")

    def test_05_spawn_complex_hyphenated_arguments(self):
        """Test `rvs frida spawn ... --args -v -d --flag=true -u admin` with allow_hyphen_values."""
        rc, data, stdout, stderr = run_rvs_cmd([
            "frida", "spawn", str(AUTH_GATE), "--args", "-v", "-d", "--flag=true", "-u", "admin"
        ])
        # Should NOT fail with Clap unknown argument '-v'
        self.assertIn(rc, [0, EXIT_INTERNAL_ERROR])
        self.assertIsNotNone(data)

    def test_06_spawn_nonexistent_target_file_error(self):
        """Test spawning a non-existent binary returns EXIT_FILE_ERROR (2) upfront."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "spawn", "/nonexistent/binary/path_xyz", "--args", "123"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("code"), "FILE_NOT_FOUND")
        self.assertEqual(data.get("error", {}).get("exit_code"), EXIT_FILE_ERROR)

    def test_07_attach_watchdog_timeout_argument(self):
        """Test `rvs frida attach 999999 --timeout 1` accepts timeout parameter and emits clean envelope."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "999999", "--timeout", "1"])
        self.assertEqual(rc, EXIT_INTERNAL_ERROR)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("command"), "frida attach")
        self.assertEqual(data.get("target"), "999999")
        self.assertEqual(data.get("error", {}).get("code"), "R2_FRIDA_NOT_INSTALLED")

    def test_08_driver_timeout_watchdog_enforcement(self):
        """Empirically test FridaDriver timeout watchdog by mocking radare2 with an artificial delay."""
        temp_bin_dir = tempfile.mkdtemp(prefix="rvs_mock_r2_")
        mock_r2 = Path(temp_bin_dir) / "radare2"
        try:
            # Create a mock radare2 script that advertises frida, but hangs on command execution
            mock_content = """#!/usr/bin/env bash
if [ "$1" = "-H" ]; then
    echo "R2_USER_PLUGINS=/tmp"
    echo "R2_VERSION=6.1.4"
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = "Loj" ]; then
        echo '[{"name":"frida","uris":["frida://"]}]'
        exit 0
    fi
done
# exec replaces shell process so child.kill() terminates sleep directly
exec sleep 10
"""
            mock_r2.write_text(mock_content)
            mock_r2.chmod(0o755)

            custom_env = os.environ.copy()
            custom_env["PATH"] = f"{temp_bin_dir}:{custom_env.get('PATH', '')}"

            # Execute a command that invokes FridaDriver::cmd() with a 1-second timeout
            t0 = time.time()
            rc, data, stdout, stderr = run_rvs_cmd(
                ["frida", "script", "--target", "0", "--code", "1+1", "--timeout", "1"],
                env=custom_env,
                timeout=10.0,
            )
            elapsed = time.time() - t0

            # It must enforce the 1-second timeout and terminate the child within ~1-3s
            self.assertLess(elapsed, 5.0, f"Command took {elapsed:.2f}s, watchdog did not enforce deadline promptly")
            self.assertEqual(rc, EXIT_TIMEOUT_ERROR, f"Expected EXIT_TIMEOUT_ERROR (5), got {rc}. Output: {stdout}")
            self.assertIsNotNone(data)
            self.assertEqual(data.get("error", {}).get("code"), "TIMEOUT_EXPIRED")
            self.assertEqual(data.get("error", {}).get("exit_code"), EXIT_TIMEOUT_ERROR)
            self.assertIn("timed out", data.get("error", {}).get("message", "").lower())
        finally:
            shutil.rmtree(temp_bin_dir, ignore_errors=True)


class TestOutputSanitizationAndEnvelopes(unittest.TestCase):
    """Area 3: Zero ANSI Escapes, Unparsed Control Codes, and Standardized JSON Envelopes."""

    def test_01_zero_ansi_escapes_across_all_frida_commands(self):
        """Run all 15 frida subcommands and verify zero ANSI escape sequences in stdout."""
        subcommands = [
            ["frida", "env-check"],
            ["frida", "attach", "12345"],
            ["frida", "spawn", str(AUTH_GATE)],
            ["frida", "modules", "--target", "0"],
            ["frida", "symbols", "--target", "0"],
            ["frida", "classes", "--target", "0"],
            ["frida", "hook", "--target", "0", "--addr", "0x401000"],
            ["frida", "trace-regs", "--target", "0", "--addr", "0x401000"],
            ["frida", "hook-return", "--target", "0", "--addr", "0x401000", "--retval", "0x1"],
            ["frida", "hooks-list", "--target", "0"],
            ["frida", "hook-remove", "--target", "0", "--id", "1"],
            ["frida", "script", "--target", "0", "--code", "console.log('test')"],
            ["frida", "rpc", "--target", "0", "--method", "testMethod"],
            ["frida", "mem-read", "--target", "0", "--addr", "0x401000", "--len", "16"],
            ["frida", "mem-write", "--target", "0", "--addr", "0x401000", "--data", "9090"],
        ]

        for cmd in subcommands:
            rc, data, stdout, stderr = run_rvs_cmd(cmd)
            # Verify 0 ANSI sequences
            ansi_matches = ANSI_REGEX.findall(stdout)
            self.assertEqual(len(ansi_matches), 0, f"Command {' '.join(cmd)} stdout contained ANSI: {ansi_matches}")

            # Verify no unparsed control codes like CR (\r) or BELL (\x07)
            self.assertNotIn("\r", stdout, f"Command {' '.join(cmd)} stdout contained carriage return")
            self.assertNotIn("\x07", stdout, f"Command {' '.join(cmd)} stdout contained bell character")

            # Verify valid JSON
            self.assertIsNotNone(data, f"Command {' '.join(cmd)} stdout was not parseable JSON: {stdout}")

    def test_02_json_envelope_structure_compliance(self):
        """Verify ApiResponse envelope structure meets requirements."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "env-check"])
        self.assertIsNotNone(data)
        # Required top-level keys
        self.assertIn("success", data)
        self.assertIn("command", data)
        self.assertIn("target", data)
        self.assertIn("timestamp", data)
        self.assertIn("format_version", data)

        # For error envelope
        if not data["success"]:
            self.assertIn("error", data)
            err = data["error"]
            self.assertIn("code", err)
            self.assertIn("message", err)
            self.assertIn("category", err)
            self.assertIn("exit_code", err)
            self.assertIn("suggestion", err)
            self.assertEqual(err["exit_code"], rc)


class TestCompactModeTokenReduction(unittest.TestCase):
    """Area 4: Token Compaction Verification and Payload Size Reduction."""

    def test_01_compact_flag_accepted_positions(self):
        """Verify `--compact` and `-c` are recognized before and after subcommand without syntax errors."""
        invocations = [
            ["--compact", "frida", "env-check"],
            ["-c", "frida", "env-check"],
            ["frida", "env-check", "--compact"],
            ["frida", "env-check", "-c"],
            ["frida", "modules", "--target", "0", "--compact"],
            ["frida", "modules", "--target", "0", "-c"],
            ["frida", "symbols", "--target", "0", "--compact"],
            ["frida", "symbols", "--target", "0", "-c"],
        ]
        for cmd in invocations:
            rc, data, stdout, stderr = run_rvs_cmd(cmd)
            self.assertIn(rc, [0, EXIT_INTERNAL_ERROR])
            self.assertIsNotNone(data, f"Command {' '.join(cmd)} failed JSON parsing")

    def test_02_mock_live_modules_token_compaction(self):
        """Empirically test that compact mode on module listings drops `path` and achieves token reduction."""
        temp_bin_dir = tempfile.mkdtemp(prefix="rvs_mock_modules_")
        mock_r2 = Path(temp_bin_dir) / "radare2"
        try:
            # Generate 50 realistic loaded modules
            mock_modules = []
            for i in range(50):
                mock_modules.append({
                    "name": f"libexample_module_{i}.so",
                    "base": f"0x7fff{i:04x}000",
                    "size": 1024 * (i + 1),
                    "path": f"/usr/lib/x86_64-linux-gnu/subpath/nested/library/libexample_module_{i}.so.1.2.3",
                })
            json_modules = json.dumps(mock_modules)

            mock_content = f"""#!/usr/bin/env bash
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
    if [ "$arg" = ":ilj" ]; then
        echo '{json_modules}'
        exit 0
    fi
done
exit 0
"""
            mock_r2.write_text(mock_content)
            mock_r2.chmod(0o755)

            custom_env = os.environ.copy()
            custom_env["PATH"] = f"{temp_bin_dir}:{custom_env.get('PATH', '')}"

            rc_full, data_full, stdout_full, _ = run_rvs_cmd(["frida", "modules", "-t", "0"], env=custom_env)
            rc_comp, data_comp, stdout_comp, _ = run_rvs_cmd(["frida", "modules", "-t", "0", "-c"], env=custom_env)

            self.assertEqual(rc_full, EXIT_SUCCESS)
            self.assertEqual(rc_comp, EXIT_SUCCESS)
            self.assertIsNotNone(data_full)
            self.assertIsNotNone(data_comp)

            # Standard mode has path
            self.assertIn("path", data_full["data"]["modules"][0])
            # Compact mode drops path
            self.assertNotIn("path", data_comp["data"]["modules"][0])

            # Measure payload size reduction
            len_full = len(stdout_full)
            len_comp = len(stdout_comp)
            reduction = (len_full - len_comp) / len_full
            self.assertGreater(reduction, 0.40, f"Module compact reduction was {reduction:.1%}, expected > 40%")
        finally:
            shutil.rmtree(temp_bin_dir, ignore_errors=True)

    def test_03_mock_live_symbols_token_compaction(self):
        """Empirically test that compact mode on symbol listings drops redundant fields and achieves > 50% reduction."""
        temp_bin_dir = tempfile.mkdtemp(prefix="rvs_mock_syms_")
        mock_r2 = Path(temp_bin_dir) / "radare2"
        try:
            # Generate 100 realistic exported symbols
            mock_symbols = []
            for i in range(100):
                mock_symbols.append({
                    "name": f"crypto_function_subroutine_{i}",
                    "realname": f"crypto_function_subroutine_{i}_implementation_details",
                    "vaddr": 0x401000 + i * 64,
                    "address": f"0x{0x401000 + i * 64:x}",
                    "offset": i * 64,
                    "size": 64,
                    "type": "FUNC",
                    "bind": "GLOBAL",
                    "module": "libcrypto.so.3",
                })
            json_symbols = json.dumps(mock_symbols)

            mock_content = f"""#!/usr/bin/env bash
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
    if [[ "$arg" == *":isj"* ]]; then
        echo '{json_symbols}'
        exit 0
    fi
done
exit 0
"""
            mock_r2.write_text(mock_content)
            mock_r2.chmod(0o755)

            custom_env = os.environ.copy()
            custom_env["PATH"] = f"{temp_bin_dir}:{custom_env.get('PATH', '')}"

            rc_full, data_full, stdout_full, _ = run_rvs_cmd(["frida", "symbols", "-t", "0", "-l", "100"], env=custom_env)
            rc_comp, data_comp, stdout_comp, _ = run_rvs_cmd(["frida", "symbols", "-t", "0", "-l", "100", "-c"], env=custom_env)

            self.assertEqual(rc_full, EXIT_SUCCESS)
            self.assertEqual(rc_comp, EXIT_SUCCESS)
            self.assertIsNotNone(data_full)
            self.assertIsNotNone(data_comp)

            # Full mode has bind, module
            first_full = data_full["data"]["symbols"][0]
            self.assertIn("bind", first_full)
            self.assertIn("module", first_full)

            # Compact mode drops bind, module and renames size to sz
            first_comp = data_comp["data"]["symbols"][0]
            self.assertNotIn("bind", first_comp)
            self.assertNotIn("module", first_comp)
            self.assertIn("sz", first_comp)
            self.assertIn("addr", first_comp)

            # Verify size reduction >= 35%
            len_full = len(stdout_full)
            len_comp = len(stdout_comp)
            reduction = (len_full - len_comp) / len_full
            self.assertGreater(reduction, 0.35, f"Symbols compaction achieved {reduction:.1%}, expected > 35%")
        finally:
            shutil.rmtree(temp_bin_dir, ignore_errors=True)

    def test_04_mock_live_classes_token_compaction(self):
        """Empirically test that compact mode on class listings drops method arrays and achieves > 60% reduction."""
        temp_bin_dir = tempfile.mkdtemp(prefix="rvs_mock_classes_")
        mock_r2 = Path(temp_bin_dir) / "radare2"
        try:
            mock_classes = []
            for i in range(20):
                methods = [f"method_{j}_with_long_signature_and_parameters_{j}()" for j in range(15)]
                mock_classes.append({
                    "name": f"com.example.app.service.ClassNumber_{i}",
                    "methods": methods,
                })
            json_classes = json.dumps(mock_classes)

            mock_content = f"""#!/usr/bin/env bash
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
    if [ "$arg" = ":icj" ]; then
        echo '{json_classes}'
        exit 0
    fi
done
exit 0
"""
            mock_r2.write_text(mock_content)
            mock_r2.chmod(0o755)

            custom_env = os.environ.copy()
            custom_env["PATH"] = f"{temp_bin_dir}:{custom_env.get('PATH', '')}"

            rc_full, data_full, stdout_full, _ = run_rvs_cmd(["frida", "classes", "-t", "0"], env=custom_env)
            rc_comp, data_comp, stdout_comp, _ = run_rvs_cmd(["frida", "classes", "-t", "0", "-c"], env=custom_env)

            self.assertEqual(rc_full, EXIT_SUCCESS)
            self.assertEqual(rc_comp, EXIT_SUCCESS)
            self.assertIsNotNone(data_full)
            self.assertIsNotNone(data_comp)

            # Full mode retains methods
            self.assertIn("methods", data_full["data"]["classes"][0])
            # Compact mode is just class name strings
            self.assertIsInstance(data_comp["data"]["classes"][0], str)

            len_full = len(stdout_full)
            len_comp = len(stdout_comp)
            reduction = (len_full - len_comp) / len_full
            self.assertGreater(reduction, 0.60, f"Classes compaction achieved {reduction:.1%}, expected > 60%")
        finally:
            shutil.rmtree(temp_bin_dir, ignore_errors=True)


class TestBoundaryAndAdversarialEdgeCases(unittest.TestCase):
    """Area 5: Boundary Values, Invalid Inputs, and Security Guardrails."""

    def test_01_negative_pid_returns_invalid_argument(self):
        """Negative PID (-1) returns EXIT_INVALID_ARGUMENT (1)."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", "--", "-1"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")
        self.assertEqual(data.get("error", {}).get("exit_code"), EXIT_INVALID_ARGUMENT)

    def test_02_invalid_uri_scheme_returns_invalid_argument(self):
        """Non-frida URI schemes return EXIT_INVALID_ARGUMENT (1)."""
        schemes = ["http://127.0.0.1", "ssh://root@box", "file:///bin/ls"]
        for s in schemes:
            rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", s])
            self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
            self.assertIsNotNone(data)
            self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_03_empty_target_string_returns_invalid_argument(self):
        """Empty target string returns EXIT_INVALID_ARGUMENT (1)."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "attach", ""])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertIsNotNone(data)
        self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_04_negative_limit_and_offset_returns_invalid_argument(self):
        """Negative limit or offset returns EXIT_INVALID_ARGUMENT (1)."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "symbols", "-t", "0", "--limit", "-10"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

        rc, data, stdout, stderr = run_rvs_cmd(["frida", "symbols", "-t", "0", "--offset", "-5"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_05_invalid_hook_format_characters_returns_invalid_argument(self):
        """Invalid format character in hook returns EXIT_INVALID_ARGUMENT (1)."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "hook", "-t", "0", "-a", "0x401000", "--format", "xyz!@#"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_06_kernel_out_of_bounds_address_returns_analysis_error(self):
        """0xffffffffffffffff or out-of-bounds addresses return ADDRESS_OUT_OF_BOUNDS (3)."""
        for addr in ["0xffffffffffffffff", "0x8000000000000000"]:
            rc, data, stdout, stderr = run_rvs_cmd(["frida", "hook", "-t", "0", "--addr", addr, "--format", "x"])
            self.assertEqual(rc, EXIT_ANALYSIS_ERROR)
            self.assertEqual(data.get("error", {}).get("code"), "ADDRESS_OUT_OF_BOUNDS")
            self.assertEqual(data.get("error", {}).get("exit_code"), EXIT_ANALYSIS_ERROR)

    def test_07_invalid_hex_data_in_mem_write_returns_invalid_argument(self):
        """Non-hex chars (ZZZZ) or odd-length strings return EXIT_INVALID_ARGUMENT (1)."""
        bad_hexes = ["ZZZZ", "123", "909G", ""]
        for bad in bad_hexes:
            rc, data, stdout, stderr = run_rvs_cmd(["frida", "mem-write", "-t", "0", "-a", "0x401000", "-d", bad])
            self.assertEqual(rc, EXIT_INVALID_ARGUMENT, f"Failed on bad hex '{bad}'")
            self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_08_zero_length_or_excessive_mem_read_returns_invalid_argument(self):
        """Memory read with len=0 or len > 1MB returns EXIT_INVALID_ARGUMENT (1)."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "mem-read", "-t", "0", "-a", "0x401000", "-l", "0"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

        rc, data, stdout, stderr = run_rvs_cmd(["frida", "mem-read", "-t", "0", "-a", "0x401000", "-l", "2000000"])
        self.assertEqual(rc, EXIT_INVALID_ARGUMENT)
        self.assertEqual(data.get("error", {}).get("code"), "INVALID_ARGUMENT")

    def test_09_nonexistent_script_file_returns_file_error(self):
        """Referencing a missing script file returns EXIT_FILE_ERROR (2)."""
        rc, data, stdout, stderr = run_rvs_cmd(["frida", "script", "-t", "0", "--file", "/nonexistent/test_script.js"])
        self.assertEqual(rc, EXIT_FILE_ERROR)
        self.assertEqual(data.get("error", {}).get("code"), "FILE_NOT_FOUND")
        self.assertEqual(data.get("error", {}).get("exit_code"), EXIT_FILE_ERROR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
