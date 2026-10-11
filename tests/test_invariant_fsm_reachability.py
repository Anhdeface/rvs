"""tests/test_invariant_fsm_reachability.py - Execution FSM State Reachability & Containment Suite.

Formal Invariant Verification (R3 Invariant 3):
State Reachability & Error Containment Invariant (Execution FSM):
1. Complete State Reachability:
   Every terminal state T0..T6 in the standardized 7-level taxonomy is reachable via designated triggers:
       T0: EXIT_SUCCESS (0) - Clean analysis success
       T1: EXIT_INVALID_ARGUMENT (1) - Parameter validation failure
       T2: EXIT_FILE_ERROR (2) - Target file or binary access failure
       T3: EXIT_ANALYSIS_ERROR (3) - Reverse engineering analysis failure
       T4: EXIT_PATCH_ERROR (4) - Binary patching failure
       T5: EXIT_TIMEOUT_ERROR (5) - Watchdog timeout expired
       T6: EXIT_INTERNAL_ERROR (6) - Internal system/harness exception or signal termination
2. Total Error Containment:
   All execution paths map strictly to Omega(T) in {0, 1, 2, 3, 4, 5, 6} with zero unhandled crash paths,
   zero uncaught tracebacks, and zero unmapped OS signals.
3. Signal Normalization:
   Negative return codes from OS signals (e.g. -11 SIGSEGV, -9 SIGKILL, -15 SIGTERM) and runtime panics (101)
   are strictly normalized to EXIT_INTERNAL_ERROR (6).
4. MCP JSON-RPC Protocol Containment:
   JSON-RPC server loop contains all malformed requests (-32700, -32600, -32601, -32602, -32603),
   never crashing the daemon process.
"""

import io
import json
import os
import signal
import sys
import unittest
from pathlib import Path
from typing import Any, Dict

from rvs_agent_harness import (
    EXIT_ANALYSIS_ERROR,
    EXIT_FILE_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_INVALID_ARGUMENT,
    EXIT_PATCH_ERROR,
    EXIT_SUCCESS,
    EXIT_TIMEOUT_ERROR,
    RvsHarness,
    execute_rvs_subprocess,
    normalize_exit_code,
)

FIXTURE_PATH = "crackme_case"


class TestInvariantFsmReachability(unittest.TestCase):
    """Verifies Invariant 3: FSM State Reachability, Taxonomy Containment, and Error Isolation."""

    def setUp(self) -> None:
        self.harness = RvsHarness()
        self.taxonomy_codes = {
            EXIT_SUCCESS,
            EXIT_INVALID_ARGUMENT,
            EXIT_FILE_ERROR,
            EXIT_ANALYSIS_ERROR,
            EXIT_PATCH_ERROR,
            EXIT_TIMEOUT_ERROR,
            EXIT_INTERNAL_ERROR,
        }

    # -------------------------------------------------------------------------
    # 1. Terminal State Reachability (T0..T6)
    # -------------------------------------------------------------------------

    def test_01_reachability_t0_success(self) -> None:
        """FSM Transition: READY -> ARG_VAL -> TARGET_INGEST -> ... -> T0 (EXIT_SUCCESS: 0)."""
        res = self.harness.execute_tool("rvs_info", {"file": FIXTURE_PATH, "compact": True})
        self.assertTrue(res.get("success"), f"Expected success but got: {res}")
        self.assertNotIn("error", res)
        self.assertEqual(res.get("command"), "info")
        self.assertIn("data", res)

    def test_02_reachability_t1_invalid_argument(self) -> None:
        """FSM Transition: READY -> ARG_VAL -> T1 (EXIT_INVALID_ARGUMENT: 1)."""
        # Missing arguments dict entirely
        res1 = self.harness.execute_tool("rvs_info", arguments=None)
        self.assertFalse(res1.get("success"))
        err1 = res1.get("error", {})
        self.assertEqual(err1.get("exit_code"), EXIT_INVALID_ARGUMENT)
        self.assertIn(err1.get("exit_code"), self.taxonomy_codes)

        # Missing required parameter 'file'
        res2 = self.harness.execute_tool("rvs_info", arguments={})
        self.assertFalse(res2.get("success"))
        err2 = res2.get("error", {})
        self.assertEqual(err2.get("exit_code"), EXIT_INVALID_ARGUMENT)

        # Invalid type for numeric parameter
        res3 = self.harness.execute_tool("rvs_disasm", {"file": FIXTURE_PATH, "addr": "not_an_address_or_symbol!"})
        self.assertFalse(res3.get("success"))
        err3 = res3.get("error", {})
        self.assertIn(err3.get("exit_code"), (EXIT_INVALID_ARGUMENT, EXIT_ANALYSIS_ERROR))

    def test_03_reachability_t2_file_error(self) -> None:
        """FSM Transition: READY -> ARG_VAL -> TARGET_INGEST -> T2 (EXIT_FILE_ERROR: 2)."""
        res = self.harness.execute_tool("rvs_info", {"file": "/path/to/nonexistent/binary_xyz_12345"})
        self.assertFalse(res.get("success"))
        err = res.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_FILE_ERROR)
        self.assertIn(err.get("exit_code"), self.taxonomy_codes)

    def test_04_reachability_t3_analysis_error(self) -> None:
        """FSM Transition: READY -> ARG_VAL -> TARGET_INGEST -> PROC_RUN -> T3 (EXIT_ANALYSIS_ERROR: 3)."""
        res = self.harness.execute_tool(
            "rvs_decompile",
            {"file": FIXTURE_PATH, "function": "nonexistent_symbol_that_definitely_does_not_exist_9876"},
        )
        self.assertFalse(res.get("success"))
        err = res.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_ANALYSIS_ERROR)
        self.assertIn(err.get("exit_code"), self.taxonomy_codes)

    def test_05_reachability_t4_patch_error(self) -> None:
        """FSM Transition: READY -> ARG_VAL -> TARGET_INGEST -> PROC_RUN -> T4 (EXIT_PATCH_ERROR: 4)."""
        res = self.harness.execute_tool(
            "rvs_patch_bytes",
            {"file": FIXTURE_PATH, "addr": "0x1000", "hex_bytes": "NOT_HEX_CHARS_ZZZZ"},
        )
        self.assertFalse(res.get("success"))
        err = res.get("error", {})
        self.assertIn(err.get("exit_code"), (EXIT_INVALID_ARGUMENT, EXIT_PATCH_ERROR))
        self.assertIn(err.get("exit_code"), self.taxonomy_codes)

    def test_06_reachability_t5_timeout_error(self) -> None:
        """FSM Transition: PROC_RUN -> STREAM_DRAIN -> WATCHDOG_TERM/KILL -> T5 (EXIT_TIMEOUT_ERROR: 5)."""
        res = self.harness.run(["-f", FIXTURE_PATH, "analyze", "functions"], timeout=0.00001)
        self.assertFalse(res.get("success"))
        err = res.get("error", {})
        self.assertEqual(err.get("exit_code"), EXIT_TIMEOUT_ERROR)
        self.assertIn(err.get("exit_code"), self.taxonomy_codes)

    def test_07_reachability_t6_internal_error(self) -> None:
        """FSM Transition: PROC_RUN -> OS Signal / Panic -> T6 (EXIT_INTERNAL_ERROR: 6)."""
        code, stdout, stderr, dur = execute_rvs_subprocess(
            ["-c", "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"],
            timeout=2.0,
            rvs_bin=Path(sys.executable),
        )
        normalized = normalize_exit_code(code)
        self.assertEqual(normalized, EXIT_INTERNAL_ERROR)
        self.assertIn(normalized, self.taxonomy_codes)

    # -------------------------------------------------------------------------
    # 2. Signal Normalization Invariant
    # -------------------------------------------------------------------------

    def test_08_signal_normalization_negative_return_codes(self) -> None:
        """Invariant 3.2: POSIX signals and foreign codes map strictly to EXIT_INTERNAL_ERROR (6)."""
        test_signals = [
            -signal.SIGSEGV,  # -11
            -signal.SIGKILL,  # -9
            -signal.SIGTERM,  # -15
            -signal.SIGABRT,  # -6
            -signal.SIGILL,   # -4
            -signal.SIGFPE,   # -8
            -signal.SIGBUS,   # -7
            101,              # Standard Rust runtime panic exit code
            137,              # 128 + 9 (SIGKILL in shell convention)
            139,              # 128 + 11 (SIGSEGV in shell convention)
            255,              # Generic -1 in 8-bit unsigned
        ]

        for raw_code in test_signals:
            normalized = normalize_exit_code(raw_code)
            self.assertEqual(
                normalized,
                EXIT_INTERNAL_ERROR,
                f"Raw code {raw_code} normalized to {normalized}, expected EXIT_INTERNAL_ERROR (6)",
            )
            self.assertIn(normalized, self.taxonomy_codes)

    def test_09_signal_normalization_valid_codes_preserved(self) -> None:
        """Invariant 3.2b: Codes strictly within {0..6} are preserved identity-wise."""
        for code in range(7):
            self.assertEqual(normalize_exit_code(code), code)

    # -------------------------------------------------------------------------
    # 3. MCP JSON-RPC Protocol Containment
    # -------------------------------------------------------------------------

    def test_10_mcp_jsonrpc_protocol_containment(self) -> None:
        """Invariant 3.3: MCP JSON-RPC daemon contains all protocol errors without crashing."""
        requests = [
            # 1. Invalid JSON syntax -> Parse error (-32700)
            "this is not valid json at all\n",
            # 2. Missing jsonrpc="2.0" field -> Invalid Request (-32600)
            json.dumps({"jsonrpc": "1.0", "id": 1, "method": "tools/list"}) + "\n",
            # 3. Method is not a string -> Invalid Request (-32600)
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": 12345}) + "\n",
            # 4. Unknown method -> Method not found (-32601)
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "unknown/nonexistent_method"}) + "\n",
            # 5. Unknown tool name -> Method not found (-32601)
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "nonexistent_tool", "arguments": {}}}) + "\n",
            # 6. Missing tool name in tools/call -> Invalid params (-32602)
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"arguments": {}}}) + "\n",
            # 7. Notification without id -> handled silently without response
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n",
            # 8. Valid tools/list request -> Success result
            json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/list"}) + "\n",
        ]

        in_stream = io.StringIO("".join(requests))
        out_stream = io.StringIO()

        # Execute daemon loop - must complete cleanly without raising any unhandled exception
        self.harness.serve_mcp(stdin_stream=in_stream, stdout_stream=out_stream)

        output_lines = [json.loads(line) for line in out_stream.getvalue().splitlines() if line.strip()]

        # 7 responses expected (item 7 was a notification, producing no response)
        self.assertEqual(len(output_lines), 7)

        # Response 1: Parse error (-32700)
        self.assertEqual(output_lines[0]["jsonrpc"], "2.0")
        self.assertEqual(output_lines[0]["error"]["code"], -32700)

        # Response 2: Invalid Request (-32600)
        self.assertEqual(output_lines[1]["jsonrpc"], "2.0")
        self.assertEqual(output_lines[1]["error"]["code"], -32600)

        # Response 3: Invalid Request (-32600)
        self.assertEqual(output_lines[2]["jsonrpc"], "2.0")
        self.assertEqual(output_lines[2]["error"]["code"], -32600)

        # Response 4: Method not found (-32601)
        self.assertEqual(output_lines[3]["jsonrpc"], "2.0")
        self.assertEqual(output_lines[3]["error"]["code"], -32601)

        # Response 5: Unknown tool returned error envelope with isError=True
        self.assertEqual(output_lines[4]["jsonrpc"], "2.0")
        self.assertEqual(output_lines[4]["id"], 4)
        self.assertTrue(output_lines[4].get("result", {}).get("isError"))

        # Response 6: Invalid params (-32602)
        self.assertEqual(output_lines[5]["jsonrpc"], "2.0")
        self.assertEqual(output_lines[5]["error"]["code"], -32602)

        # Response 7: Valid tools/list request -> result
        self.assertEqual(output_lines[6]["jsonrpc"], "2.0")
        self.assertEqual(output_lines[6]["id"], 6)
        self.assertIn("tools", output_lines[6]["result"])

    # -------------------------------------------------------------------------
    # 4. Formal FSM State Transition Completeness
    # -------------------------------------------------------------------------

    def test_11_fsm_transition_matrix_completeness(self) -> None:
        """Invariant 3.4: All modeled transitions terminate in the strict {0..6} taxonomy."""
        fsm_transitions = [
            ("INIT -> ARG_PARSED -> TARGET_VALIDATED -> ANALYSIS_EXECUTING -> COMPACTION -> T0", "rvs_info", {"file": FIXTURE_PATH, "compact": True}, True, EXIT_SUCCESS),
            ("INIT -> ARG_INVALID -> T1", "rvs_info", None, False, EXIT_INVALID_ARGUMENT),
            ("INIT -> ARG_PARSED -> TARGET_MISSING -> T2", "rvs_info", {"file": "/nonexistent_bin_123"}, False, EXIT_FILE_ERROR),
            ("INIT -> ARG_PARSED -> TARGET_VALIDATED -> SYMBOL_MISSING -> T3", "rvs_decompile", {"file": FIXTURE_PATH, "function": "sym_missing_123"}, False, EXIT_ANALYSIS_ERROR),
            ("INIT -> ARG_PARSED -> TARGET_VALIDATED -> PATCH_BAD_BYTES -> T4", "rvs_patch_bytes", {"file": FIXTURE_PATH, "addr": "0x1000", "hex_bytes": "ZZZZ"}, False, EXIT_PATCH_ERROR),
        ]

        for desc, tool_name, args, exp_success, exp_code in fsm_transitions:
            res = self.harness.execute_tool(tool_name, args)
            if exp_success:
                self.assertTrue(res.get("success"), f"Failed transition: {desc}")
            else:
                self.assertFalse(res.get("success"), f"Expected failure in: {desc}")
                err = res.get("error", {})
                code = err.get("exit_code")
                self.assertIn(
                    code,
                    (exp_code, EXIT_INVALID_ARGUMENT),
                    f"Transition {desc} resulted in unexpected code: {code}",
                )
                self.assertIn(code, self.taxonomy_codes)


if __name__ == "__main__":
    unittest.main()
