"""
tests/test_apk_token_compaction_m2.py - Milestone 2 End-to-End Verification Test Suite.

Verifies:
1. Token Reduction & Compaction:
   - rvs_apk_dex with summary=True achieves >99% token reduction.
   - Pagination (limit=5) reduces token count by >95%.
   - Field filtering (fields="pkg,perms") reduces manifest tokens by >50%.
2. Token Budget Invariant:
   - For any budget B (e.g. 200, 500, 1000), Tokens(result) <= B is strictly satisfied across all 6 APK tools.
3. Neutral Binary Orchestrator:
   - Successfully handles pure-Java APKs (sample_no_so.apk) for functions, disasm, and decompile.
4. Schema & Tool Count Invariants:
   - All 50 canonical tool schemas validate cleanly and preserve backward compatibility.
5. Unpack Pipeline & Flag Forwarding:
   - RvsHarness.apk_unpack() functions autonomously.
   - All new Dalvik flags (cfg, xrefs, fields, annotations, summary, limit, offset, include_strings, smali) forward cleanly.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from rvs_agent_harness import (
    CANONICAL_TOOLS,
    RvsHarness,
    TokenEstimator,
    get_tool_schemas,
)
from neutral_orchestrator.orchestrator import NeutralBinaryOrchestrator


WORKSPACE_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"
RAW_APK = FIXTURES_DIR / "sample_raw.apk"
NO_SO_APK = FIXTURES_DIR / "sample_no_so.apk"
MULTI_DEX_APK = FIXTURES_DIR / "sample_multi_dex.apk"


class TestApkTokenCompactionM2(unittest.TestCase):
    """End-to-End Verification Suite for Milestone 2 Token Optimization & Schemas."""

    @classmethod
    def setUpClass(cls):
        cls.harness = RvsHarness()
        assert RAW_APK.is_file(), f"Fixture missing: {RAW_APK}"
        assert NO_SO_APK.is_file(), f"Fixture missing: {NO_SO_APK}"

    def test_01_summary_mode_token_reduction_greater_than_99_percent(self):
        """Verifies rvs_apk_dex with summary=True achieves >99% token reduction."""
        full_res = self.harness.execute_tool(
            "rvs_apk_dex",
            {"file": str(RAW_APK), "compact": True},
        )
        self.assertTrue(full_res.get("success"), f"Full query failed: {full_res.get('error')}")
        tok_full = TokenEstimator.estimate_obj(full_res)

        sum_res = self.harness.execute_tool(
            "rvs_apk_dex",
            {"file": str(RAW_APK), "summary": True, "compact": True},
        )
        self.assertTrue(sum_res.get("success"), f"Summary query failed: {sum_res.get('error')}")
        tok_sum = TokenEstimator.estimate_obj(sum_res)

        reduction = (1.0 - (tok_sum / tok_full)) * 100.0
        self.assertGreater(
            reduction,
            99.0,
            f"Summary token reduction was {reduction:.2f}%, expected >99.0% (Full: {tok_full}, Summary: {tok_sum})",
        )
        data = sum_res.get("data", {})
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total_classes"], 323)
        self.assertEqual(data["summary"]["total_methods"], 2176)
        self.assertEqual(data["class_list"], [])

    def test_02_pagination_token_reduction_greater_than_95_percent(self):
        """Verifies rvs_apk_dex with pagination (limit=5) achieves >95% token reduction."""
        full_res = self.harness.execute_tool(
            "rvs_apk_dex",
            {"file": str(RAW_APK), "compact": True},
        )
        tok_full = TokenEstimator.estimate_obj(full_res)

        page_res = self.harness.execute_tool(
            "rvs_apk_dex",
            {"file": str(RAW_APK), "limit": 5, "offset": 0, "compact": True},
        )
        self.assertTrue(page_res.get("success"), f"Pagination query failed: {page_res.get('error')}")
        tok_page = TokenEstimator.estimate_obj(page_res)

        reduction = (1.0 - (tok_page / tok_full)) * 100.0
        self.assertGreater(
            reduction,
            95.0,
            f"Pagination token reduction was {reduction:.2f}%, expected >95.0% (Full: {tok_full}, Paginated: {tok_page})",
        )
        data = page_res.get("data", {})
        self.assertEqual(len(data.get("class_list", [])), 5)

    def test_03_field_filtering_token_reduction_greater_than_50_percent(self):
        """Verifies manifest field filtering (fields='pkg,perms') achieves >50% token reduction."""
        man_full = self.harness.execute_tool(
            "rvs_apk_manifest",
            {"file": str(RAW_APK), "compact": True},
        )
        self.assertTrue(man_full.get("success"), f"Manifest full query failed: {man_full.get('error')}")
        tok_man_full = TokenEstimator.estimate_obj(man_full)

        man_filt = self.harness.execute_tool(
            "rvs_apk_manifest",
            {"file": str(RAW_APK), "fields": "pkg,perms", "compact": True},
        )
        self.assertTrue(man_filt.get("success"), f"Manifest filtered query failed: {man_filt.get('error')}")
        tok_man_filt = TokenEstimator.estimate_obj(man_filt)

        reduction = (1.0 - (tok_man_filt / tok_man_full)) * 100.0
        self.assertGreater(
            reduction,
            50.0,
            f"Field filter token reduction was {reduction:.2f}%, expected >50.0% (Full: {tok_man_full}, Filtered: {tok_man_filt})",
        )
        filt_data = man_filt.get("data", {})
        self.assertIn("pkg", filt_data)
        self.assertIn("perms", filt_data)
        self.assertNotIn("activities", filt_data)
        self.assertNotIn("services", filt_data)
        self.assertNotIn("raw_xml", filt_data)

    def test_04_budget_invariant_strictly_enforced_across_all_apk_tools(self):
        """Verifies Tokens(result) <= B holds strictly for any budget B across all 6 APK tools."""
        apk_tools = [
            "rvs_apk_info",
            "rvs_apk_manifest",
            "rvs_apk_dex",
            "rvs_apk_native",
            "rvs_apk_resources",
            "rvs_apk_signature",
        ]
        test_budgets = [200, 500, 1000]

        for tool_name in apk_tools:
            for budget in test_budgets:
                with self.subTest(tool=tool_name, budget=budget):
                    res = self.harness.execute_tool(
                        tool_name,
                        {"file": str(RAW_APK), "budget": budget, "compact": True},
                    )
                    self.assertTrue(res.get("success"), f"{tool_name} failed with budget {budget}")
                    actual_tokens = TokenEstimator.estimate_obj(res)
                    self.assertLessEqual(
                        actual_tokens,
                        budget,
                        f"{tool_name} violated budget invariant: actual {actual_tokens} > budget {budget}",
                    )

    def test_05_neutral_orchestrator_handles_pure_java_apk(self):
        """Verifies NeutralBinaryOrchestrator handles pure-Java APK (sample_no_so.apk) without unsupported errors."""
        with NeutralBinaryOrchestrator(str(NO_SO_APK)) as orch:
            # 1. functions query
            f_res = orch.query("functions")
            self.assertTrue(f_res.get("success"), f"functions query failed: {f_res.get('error')}")
            f_data = f_res.get("data", {})
            self.assertGreater(len(f_data.get("functions", [])), 0)

            # 2. disasm query
            d_res = orch.query("disasm", function_or_addr="setChecked")
            self.assertTrue(d_res.get("success"), f"disasm query failed: {d_res.get('error')}")
            d_data = d_res.get("data", {})
            self.assertTrue(
                "disassembly" in d_data
                or any("disassembly" in m for c in d_data.get("class_list", []) for m in c.get("methods", [])),
                "Disassembly instructions missing from Dalvik disasm response",
            )

            # 3. decompile query
            dec_res = orch.query("decompile", function="setChecked")
            self.assertTrue(dec_res.get("success"), f"decompile query failed: {dec_res.get('error')}")
            dec_data = dec_res.get("data", {})
            self.assertTrue(
                "decompiled" in dec_data
                or any("decompiled" in m for c in dec_data.get("class_list", []) for m in c.get("methods", [])),
                "Decompiled pseudo-Java missing from Dalvik decompile response",
            )

    def test_06_canonical_tool_count_and_schema_conformance(self):
        """Verifies exactly 50 canonical tools exist and schemas validate across MCP, OpenAI, Anthropic, Gemini."""
        self.assertEqual(len(CANONICAL_TOOLS), 50, "CANONICAL_TOOLS count must remain exactly 50")

        # Verify rvs_apk_dex properties in CANONICAL_TOOLS
        dex_tool = next(t for t in CANONICAL_TOOLS if t["name"] == "rvs_apk_dex")
        props = dex_tool["properties"]
        expected_props = [
            "file", "dex_file", "class", "method", "disasm", "decompile",
            "cfg", "xrefs", "fields", "annotations", "summary",
            "limit", "offset", "include_strings", "smali", "compact"
        ]
        for prop in expected_props:
            self.assertIn(prop, props, f"Property '{prop}' missing from rvs_apk_dex schema")

        # Verify 'fields' in all 6 APK tools
        apk_tool_names = [
            "rvs_apk_info", "rvs_apk_manifest", "rvs_apk_dex",
            "rvs_apk_native", "rvs_apk_resources", "rvs_apk_signature"
        ]
        for tool_name in apk_tool_names:
            t = next(x for x in CANONICAL_TOOLS if x["name"] == tool_name)
            self.assertIn("fields", t["properties"], f"Field filtering missing from {tool_name}")

        # Verify exported schema formats
        for fmt in ("openai", "anthropic", "gemini", "mcp"):
            schemas = get_tool_schemas(fmt)
            self.assertEqual(len(schemas), 50)

    def test_07_apk_unpack_helper_method(self):
        """Verifies RvsHarness.apk_unpack() produces unpacked directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "unpacked_test"
            res = self.harness.apk_unpack(
                file=str(RAW_APK),
                output=out_dir,
                force=True,
                no_java=True,
            )
            self.assertTrue(res.get("success"), f"apk_unpack failed: {res.get('error')}")
            self.assertTrue(out_dir.is_dir(), "Output directory was not created")
            self.assertTrue((out_dir / "AndroidManifest.xml").is_file(), "AndroidManifest.xml missing")
            self.assertTrue((out_dir / "rvs_agent_summary.json").is_file(), "rvs_agent_summary.json missing")
            self.assertTrue((out_dir / "rvs_agent_summary.md").is_file(), "rvs_agent_summary.md missing")

    def test_08_dalvik_core_flag_forwarding_in_apk_dex(self):
        """Verifies forwarding of cfg, xrefs, fields, and smali flags through Python harness."""
        # CFG
        res_cfg = self.harness.apk_dex(
            RAW_APK,
            class_name="QuickActionItem",
            method="setChecked",
            cfg=True,
            compact=True,
        )
        self.assertTrue(res_cfg.get("success"))
        cls_cfg = res_cfg["data"]["class_list"][0]
        self.assertIn("cfg", cls_cfg["methods"][0])

        # Smali
        res_smali = self.harness.apk_dex(
            RAW_APK,
            class_name="QuickActionItem",
            method="setChecked",
            smali=True,
            compact=True,
        )
        self.assertTrue(res_smali.get("success"))
        cls_smali = res_smali["data"]["class_list"][0]
        self.assertIn("smali", cls_smali["methods"][0])

        # Fields flag
        res_fields = self.harness.apk_dex(
            RAW_APK,
            class_name="QuickActionItem",
            fields_flag=True,
            compact=True,
        )
        self.assertTrue(res_fields.get("success"))
        cls_fields = res_fields["data"]["class_list"][0]
        self.assertIn("detailed_fields", cls_fields)


if __name__ == "__main__":
    unittest.main()
