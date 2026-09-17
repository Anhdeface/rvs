#!/usr/bin/env python3
"""
Adversarial Challenger Test Suite (Round 2, Instance 2)
Empirical verification of:
1. Ambient file isolation in rvs_frida_attach, rvs_frida_spawn, and all Frida tools.
2. Target aliasing in rvs_frida_attach (including {"file": "1234"}).
3. Parameter aliasing across Frida hook tools (target, pid, addr, registers, regs, retval, value, bytes, data).
4. CLI dispatcher argument handling.
"""

import os
import sys
import unittest
import subprocess
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rvs_agent_harness import RvsHarness, EXIT_INVALID_ARGUMENT


class TestFridaAmbientFileIsolation(unittest.TestCase):
    """Stress tests verifying that ambient file never prepends -f to Frida commands."""

    def setUp(self):
        self.harness = RvsHarness()
        self.captured_cmds = []

        def mock_run(cmd, *args, **kwargs):
            self.captured_cmds.append(list(cmd))
            return {"status": "ok", "command": " ".join(cmd), "data": {}}

        self.harness.run = mock_run

    def test_ambient_file_isolation_attach(self):
        """Verify rvs_frida_attach with ambient file never injects -f."""
        # Case 1: Explicit target + ambient file
        res = self.harness.execute_tool(
            "rvs_frida_attach",
            {"target": "1234", "file": "/usr/bin/some_ambient_binary"},
        )
        cmd = self.captured_cmds[-1]
        self.assertNotIn("-f", cmd, f"Expected no -f in attach, got: {cmd}")
        self.assertEqual(cmd, ["frida", "attach", "1234"])

        # Case 2: PID + ambient file
        res = self.harness.execute_tool(
            "rvs_frida_attach",
            {"pid": 4321, "file": "/tmp/ambient_target"},
        )
        cmd = self.captured_cmds[-1]
        self.assertNotIn("-f", cmd, f"Expected no -f in attach with pid+file, got: {cmd}")
        self.assertEqual(cmd, ["frida", "attach", "4321"])

        # Case 3: Process name + ambient file
        res = self.harness.execute_tool(
            "rvs_frida_attach",
            {"path": "target_daemon", "file": "/etc/ambient_cfg"},
        )
        cmd = self.captured_cmds[-1]
        self.assertNotIn("-f", cmd, f"Expected no -f in attach with path+file, got: {cmd}")
        self.assertEqual(cmd, ["frida", "attach", "target_daemon"])

    def test_ambient_file_isolation_spawn(self):
        """Verify rvs_frida_spawn with ambient file never injects -f."""
        # Case 1: Explicit path + ambient file
        self.harness.execute_tool(
            "rvs_frida_spawn",
            {"path": "/bin/target_app", "file": "/tmp/ambient_session_binary"},
        )
        cmd = self.captured_cmds[-1]
        self.assertNotIn("-f", cmd, f"Expected no -f in spawn, got: {cmd}")
        self.assertEqual(cmd, ["frida", "spawn", "/bin/target_app"])

        # Case 2: Target + ambient file
        self.harness.execute_tool(
            "rvs_frida_spawn",
            {"target": "/bin/target_app", "file": "/tmp/ambient_session_binary"},
        )
        cmd = self.captured_cmds[-1]
        self.assertNotIn("-f", cmd, f"Expected no -f in spawn with target+file, got: {cmd}")
        self.assertEqual(cmd, ["frida", "spawn", "/bin/target_app"])

        # Case 3: Spawn with args and ambient file
        self.harness.execute_tool(
            "rvs_frida_spawn",
            {"path": "/bin/target_app", "args": ["--foo", "bar"], "file": "/ambient/file"},
        )
        cmd = self.captured_cmds[-1]
        self.assertNotIn("-f", cmd, f"Expected no -f in spawn with args, got: {cmd}")
        self.assertEqual(cmd, ["frida", "spawn", "/bin/target_app", "--args", "--foo", "bar"])

    def test_ambient_file_isolation_all_frida_tools(self):
        """Verify ALL other Frida tools isolate ambient file from command invocation."""
        ambient_file = "/ambient/path/to/session.bin"

        tools_and_args = [
            ("rvs_frida_env_check", {"file": ambient_file}),
            ("rvs_frida_modules", {"target": "1234", "file": ambient_file}),
            ("rvs_frida_symbols", {"target": "1234", "file": ambient_file}),
            ("rvs_frida_classes", {"target": "1234", "file": ambient_file}),
            ("rvs_frida_hook", {"target": "1234", "addr": "0x401000", "file": ambient_file}),
            ("rvs_frida_trace_regs", {"target": "1234", "addr": "0x401000", "regs": "rax", "file": ambient_file}),
            ("rvs_frida_hook_return", {"target": "1234", "addr": "0x401000", "retval": "0", "file": ambient_file}),
            ("rvs_frida_hooks_list", {"target": "1234", "file": ambient_file}),
            ("rvs_frida_hook_remove", {"target": "1234", "id": "hook_1", "file": ambient_file}),
            ("rvs_frida_script", {"target": "1234", "code": "console.log('hi');", "file": ambient_file}),
            ("rvs_frida_rpc", {"target": "1234", "method": "testMethod", "file": ambient_file}),
            ("rvs_frida_mem_read", {"target": "1234", "addr": "0x401000", "len": 16, "file": ambient_file}),
            ("rvs_frida_mem_write", {"target": "1234", "addr": "0x401000", "data": "9090", "file": ambient_file}),
        ]

        for tool_name, args in tools_and_args:
            self.captured_cmds.clear()
            res = self.harness.execute_tool(tool_name, args)
            self.assertNotIn("error", res if res.get("status") == "error" else {})
            self.assertTrue(len(self.captured_cmds) > 0, f"Tool {tool_name} did not execute a command")
            cmd = self.captured_cmds[-1]
            self.assertNotIn("-f", cmd, f"Tool {tool_name} injected -f with ambient file: {cmd}")
            self.assertNotIn(ambient_file, cmd, f"Tool {tool_name} leaked ambient file into command: {cmd}")


class TestFridaTargetAliasing(unittest.TestCase):
    """Stress tests verifying target aliasing across tools, especially rvs_frida_attach."""

    def setUp(self):
        self.harness = RvsHarness()
        self.captured_cmds = []

        def mock_run(cmd, *args, **kwargs):
            self.captured_cmds.append(list(cmd))
            return {"status": "ok", "command": " ".join(cmd), "data": {}}

        self.harness.run = mock_run

    def test_attach_file_target_aliasing(self):
        """Test calling rvs_frida_attach with {'file': '1234'} as target alias."""
        self.harness.execute_tool("rvs_frida_attach", {"file": "1234"})
        cmd = self.captured_cmds[-1]
        self.assertEqual(cmd, ["frida", "attach", "1234"], f"Expected ['frida', 'attach', '1234'], got {cmd}")
        self.assertNotIn("-f", cmd)

        # PID as integer
        self.harness.execute_tool("rvs_frida_attach", {"file": 5678})
        cmd = self.captured_cmds[-1]
        self.assertEqual(cmd, ["frida", "attach", "5678"])

    def test_attach_all_target_aliases(self):
        """Verify precedence and alias support for target, pid, path, file in attach."""
        # 1. target
        self.harness.execute_tool("rvs_frida_attach", {"target": "proc_tgt"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "attach", "proc_tgt"])

        # 2. pid
        self.harness.execute_tool("rvs_frida_attach", {"pid": 9999})
        self.assertEqual(self.captured_cmds[-1], ["frida", "attach", "9999"])

        # 3. path
        self.harness.execute_tool("rvs_frida_attach", {"path": "/opt/daemon"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "attach", "/opt/daemon"])

        # 4. file
        self.harness.execute_tool("rvs_frida_attach", {"file": "proc_alias"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "attach", "proc_alias"])

        # Precedence: target > pid > path > file
        self.harness.execute_tool("rvs_frida_attach", {"target": "t", "pid": "p", "path": "pa", "file": "f"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "attach", "t"])

        self.harness.execute_tool("rvs_frida_attach", {"pid": "p", "path": "pa", "file": "f"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "attach", "p"])

        self.harness.execute_tool("rvs_frida_attach", {"path": "pa", "file": "f"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "attach", "pa"])

    def test_spawn_target_aliasing(self):
        """Verify spawn aliases: path, target, file."""
        self.harness.execute_tool("rvs_frida_spawn", {"path": "/bin/app1"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "spawn", "/bin/app1"])

        self.harness.execute_tool("rvs_frida_spawn", {"target": "/bin/app2"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "spawn", "/bin/app2"])

        self.harness.execute_tool("rvs_frida_spawn", {"file": "/bin/app3"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "spawn", "/bin/app3"])


class TestFridaParameterAliasing(unittest.TestCase):
    """Test parameter aliasing across all Frida hook tools:
    addr, registers/regs, retval/value, bytes/data, etc.
    """

    def setUp(self):
        self.harness = RvsHarness()
        self.captured_cmds = []

        def mock_run(cmd, *args, **kwargs):
            self.captured_cmds.append(list(cmd))
            return {"status": "ok", "command": " ".join(cmd), "data": {}}

        self.harness.run = mock_run

    def test_hook_aliases(self):
        """Test rvs_frida_hook aliases: target/pid/file/path, addr/function/symbol/target_addr, format/fmt."""
        # addr aliases
        for addr_key in ["addr", "function", "symbol", "target_addr"]:
            self.harness.execute_tool("rvs_frida_hook", {"target": "1234", addr_key: "sym.auth_check"})
            cmd = self.captured_cmds[-1]
            self.assertEqual(cmd, ["frida", "hook", "--target", "1234", "--addr", "sym.auth_check"])

        # format aliases
        self.harness.execute_tool("rvs_frida_hook", {"target": "1234", "addr": "0x1000", "format": "sz"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "hook", "--target", "1234", "--addr", "0x1000", "--format", "sz"])

        self.harness.execute_tool("rvs_frida_hook", {"target": "1234", "addr": "0x1000", "fmt": "zi"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "hook", "--target", "1234", "--addr", "0x1000", "--format", "zi"])

    def test_trace_regs_aliases(self):
        """Test rvs_frida_trace_regs: regs/registers (str and list), addr/function/symbol."""
        # regs as string
        self.harness.execute_tool("rvs_frida_trace_regs", {"target": "1234", "addr": "0x1000", "regs": "rax,rbx"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "trace-regs", "--target", "1234", "--addr", "0x1000", "--regs", "rax,rbx"])

        # registers as string
        self.harness.execute_tool("rvs_frida_trace_regs", {"target": "1234", "addr": "0x1000", "registers": "rdi,rsi"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "trace-regs", "--target", "1234", "--addr", "0x1000", "--regs", "rdi,rsi"])

        # regs as list
        self.harness.execute_tool("rvs_frida_trace_regs", {"target": "1234", "addr": "0x1000", "regs": ["eax", "edx"]})
        self.assertEqual(self.captured_cmds[-1], ["frida", "trace-regs", "--target", "1234", "--addr", "0x1000", "--regs", "eax,edx"])

        # registers as list
        self.harness.execute_tool("rvs_frida_trace_regs", {"target": "1234", "addr": "0x1000", "registers": ["r8", "r9", "r10"]})
        self.assertEqual(self.captured_cmds[-1], ["frida", "trace-regs", "--target", "1234", "--addr", "0x1000", "--regs", "r8,r9,r10"])

        # function/symbol aliases for addr
        self.harness.execute_tool("rvs_frida_trace_regs", {"pid": 555, "function": "sym.crypto", "regs": "rax"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "trace-regs", "--target", "555", "--addr", "sym.crypto", "--regs", "rax"])

        self.harness.execute_tool("rvs_frida_trace_regs", {"file": 555, "symbol": "sym.verify", "regs": "rax"})
        self.assertEqual(self.captured_cmds[-1], ["frida", "trace-regs", "--target", "555", "--addr", "sym.verify", "--regs", "rax"])

    def test_hook_return_aliases(self):
        """Test rvs_frida_hook_return: retval, value, return_value, ret (with 0, negative, string)."""
        aliases = ["retval", "value", "return_value", "ret"]
        test_values = [0, 1, -1, "0", "0x1", "true"]

        for alias in aliases:
            for val in test_values:
                self.harness.execute_tool(
                    "rvs_frida_hook_return",
                    {"target": "1234", "addr": "sym.is_admin", alias: val},
                )
                cmd = self.captured_cmds[-1]
                expected = ["frida", "hook-return", "--target", "1234", "--addr", "sym.is_admin", "--retval", str(val)]
                self.assertEqual(cmd, expected, f"Failed for alias '{alias}' with value '{val}'")

    def test_mem_read_and_write_aliases(self):
        """Test rvs_frida_mem_read and mem_write: address/addr, data/bytes/hex_bytes/hex, len/length/size."""
        # mem_read
        for addr_key in ["addr", "address"]:
            for len_key in ["len", "length", "size"]:
                self.harness.execute_tool(
                    "rvs_frida_mem_read",
                    {"target": "1234", addr_key: "0x7fff0000", len_key: 64},
                )
                self.assertEqual(
                    self.captured_cmds[-1],
                    ["frida", "mem-read", "--target", "1234", "--addr", "0x7fff0000", "--len", "64"],
                )

        # mem_write: data, bytes, hex_bytes, hex
        for data_key in ["data", "bytes", "hex_bytes", "hex"]:
            for addr_key in ["addr", "address"]:
                self.harness.execute_tool(
                    "rvs_frida_mem_write",
                    {"target": "1234", addr_key: "0x401000", data_key: "4883c408c3"},
                )
                self.assertEqual(
                    self.captured_cmds[-1],
                    ["frida", "mem-write", "--target", "1234", "--addr", "0x401000", "--data", "4883c408c3"],
                )

        # mem_write with protect=False
        self.harness.execute_tool(
            "rvs_frida_mem_write",
            {"target": "1234", "addr": "0x401000", "bytes": "9090", "protect": False},
        )
        self.assertEqual(
            self.captured_cmds[-1],
            ["frida", "mem-write", "--target", "1234", "--addr", "0x401000", "--data", "9090", "--protect", "false"],
        )


class TestFridaMissingParamsErrorEnvelopes(unittest.TestCase):
    """Verify standard error envelopes when required parameters are omitted."""

    def setUp(self):
        self.harness = RvsHarness()

    def test_missing_required_params_return_error_envelopes(self):
        # rvs_frida_attach missing target
        res = self.harness.execute_tool("rvs_frida_attach", {})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # rvs_frida_spawn missing path
        res = self.harness.execute_tool("rvs_frida_spawn", {})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # rvs_frida_hook missing addr
        res = self.harness.execute_tool("rvs_frida_hook", {"target": "1234"})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # rvs_frida_hook missing target
        res = self.harness.execute_tool("rvs_frida_hook", {"addr": "0x401000"})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # rvs_frida_trace_regs missing regs
        res = self.harness.execute_tool("rvs_frida_trace_regs", {"target": "1234", "addr": "0x401000"})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # rvs_frida_hook_return missing retval
        res = self.harness.execute_tool("rvs_frida_hook_return", {"target": "1234", "addr": "0x401000"})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # rvs_frida_mem_read missing addr
        res = self.harness.execute_tool("rvs_frida_mem_read", {"target": "1234"})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")

        # rvs_frida_mem_write missing data
        res = self.harness.execute_tool("rvs_frida_mem_write", {"target": "1234", "addr": "0x401000"})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error", {}).get("code"), "INVALID_ARGUMENT")


class TestFridaCliDispatcherDirect(unittest.TestCase):
    """Test calling rvs_agent_harness CLI entrypoint via subprocess to ensure CLI dispatching works."""

    def test_cli_export_tools_json(self):
        """CLI --export-tools returns valid JSON schemas."""
        cmd = [sys.executable, str(PROJECT_ROOT / "rvs_agent_harness.py"), "--export-tools", "gemini"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)
        import json
        data = json.loads(res.stdout)
        self.assertIsInstance(data, list)
        tool_names = [t.get("name") for t in data]
        self.assertIn("rvs_frida_attach", tool_names)
        self.assertIn("rvs_frida_spawn", tool_names)
        self.assertIn("rvs_frida_hook", tool_names)

    def test_cli_frida_attach_dispatch(self):
        """CLI invocation of frida attach passes command to rvs binary without injected -f."""
        cmd = [sys.executable, str(PROJECT_ROOT / "rvs_agent_harness.py"), "frida", "attach", "--help"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Usage: rvs frida attach", res.stdout)
        self.assertIn("<TARGET>", res.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
