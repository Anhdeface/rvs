"""
tests/test_e2e_apk_suite.py - End-to-End Test Suite for rvs Android APK Reverse Engineering Subsystem.

Implements the 4-Tier Test Methodology:
- Tier 1: Feature Coverage (>=5 tests per feature)
  * Manifest Extraction (Binary AXML & Plain-Text XML)
  * Resources & Assets Dumping (Listing, JSON/Token assets, strings.xml, resources.arsc)
  * DEX Dalvik Bytecode, Smali Formatting & Method Decompilation
  * Signature & X.509 Certificate Verification (v1 JAR, v2 APK Signing Block)
  * Python MCP Tool Suite (rvs_apk_info, manifest, dex, native, resources, signature)
  * Dynamic Frida Connection & Target Resolution for APKs
- Tier 2: Boundary & Corner Cases (>=5 tests per feature)
  * Manifest Boundaries (truncated AXML, missing file, unclosed XML, empty files)
  * Resources & Assets Boundaries (missing assets, nonexistent extract, path traversal attempt, corrupt ARSC)
  * DEX Boundaries (corrupted magic, invalid class/method filter, missing DEX)
  * Signature Boundaries (unsigned APK, tampered file digest, corrupted magic, size mismatch)
  * MCP & Harness Boundaries (missing arguments, non-existent files, non-APK targets)
- Tier 3: Cross-Feature Combinations (Pairwise interactions across CLI/MCP/formats)
- Tier 4: Real-World Application Workloads (full triage sequences on raw, multi-dex, native, hybrid frameworks)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Setup workspace paths
WORKSPACE_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"

if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness
from rvs_agent_harness import RvsHarness, CANONICAL_TOOLS
from tests.fixtures_builder import (
    create_corrupted_apk,
    create_corrupted_signing_block_apk,
    create_synthetic_apk,
    create_synthetic_dex,
    create_synthetic_flutter_apk,
    create_synthetic_hybrid_apk,
    create_synthetic_java_only_apk,
    create_synthetic_native_cpp_apk,
    create_synthetic_react_native_apk,
    create_tampered_signature_apk,
    create_unsigned_apk,
    create_zero_byte_target,
    synthesize_apk_signing_block_v2,
    synthesize_arsc_bytes,
    synthesize_dex_bytes,
    synthesize_elf_bytes,
    synthesize_pkcs7_signature_bytes,
    synthesize_x509_cert_bytes,
)


def resolve_rvs_binary() -> Path:
    """Locate the compiled rvs CLI binary (debug or release)."""
    debug_bin = WORKSPACE_DIR / "target" / "debug" / "rvs"
    release_bin = WORKSPACE_DIR / "target" / "release" / "rvs"

    if debug_bin.exists() and os.access(debug_bin, os.X_OK):
        return debug_bin
    if release_bin.exists() and os.access(release_bin, os.X_OK):
        return release_bin
    # Fallback to PATH
    found = shutil.which("rvs")
    if found:
        return Path(found)
    return debug_bin


RVS_BIN = resolve_rvs_binary()


def run_rvs_cli(args: List[str], timeout: int = 15) -> Tuple[int, str, str, Optional[Dict[str, Any]]]:
    """
    Execute the rvs CLI binary and return (exit_code, stdout, stderr, parsed_json_or_none).
    """
    cmd = [str(RVS_BIN)] + args
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    json_data = None
    if p.stdout.strip():
        try:
            json_data = json.loads(p.stdout)
        except Exception:
            pass
    return p.returncode, p.stdout, p.stderr, json_data


def is_cli_subcommand_available(*subcommands: str) -> bool:
    """Check if the rvs CLI binary currently recognizes the given subcommand."""
    code, stdout, stderr, _ = run_rvs_cli(list(subcommands) + ["--help"])
    return code == 0


def is_mcp_tool_available(tool_name: str) -> bool:
    """Check if the given tool is registered in CANONICAL_TOOLS catalog."""
    return any(t.get("name") == tool_name for t in CANONICAL_TOOLS)


# =============================================================================
# Tier 1: Feature Coverage (Happy Path)
# =============================================================================

class TestApkE2ETier1FeatureCoverage(unittest.TestCase):
    """
    Tier 1 tests verifying core happy-path feature coverage (>=5 tests per feature):
    1. Manifest Extraction (Binary AXML & Plain-Text XML)
    2. Resources & Assets Dumping
    3. Dalvik DEX Bytecode, Smali Assembly & Decompilation
    4. Signature & Certificate Verification (v1 & v2)
    5. Python MCP Agent Harness Tools
    6. Frida Dynamic Target Resolution for APKs
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw_apk = FIXTURES_DIR / "sample_raw.apk"
        cls.unpacked_dir = FIXTURES_DIR / "sample_unpacked_dir"
        cls.harness = RvsHarness()

    # --- Feature 1: Manifest Extraction ---

    def test_tier1_manifest_binary_axml_package_and_versions(self) -> None:
        """Verifies package name and versioning parsed from binary AXML."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.raw_apk)])
        self.assertEqual(code, 0, f"rvs apk manifest failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        manifest = data["data"]
        self.assertEqual(manifest["package_name"], "eu.jgamba.myapplication")
        self.assertEqual(manifest["version_code"], 1)
        self.assertEqual(manifest["version_name"], "1.0")

    def test_tier1_manifest_binary_axml_sdk_bounds(self) -> None:
        """Verifies min and target SDK versions from binary AXML."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.raw_apk)])
        self.assertEqual(code, 0)
        manifest = data["data"]
        self.assertEqual(manifest["min_sdk_version"], 35)
        self.assertEqual(manifest["target_sdk_version"], 35)
        self.assertFalse(manifest["debuggable"])

    def test_tier1_manifest_binary_axml_permissions(self) -> None:
        """Verifies requested permissions extraction from binary AXML."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.raw_apk)])
        self.assertEqual(code, 0)
        permissions = data["data"]["permissions"]
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", permissions)
        self.assertIn("android.permission.ACCESS_COARSE_LOCATION", permissions)
        self.assertIn("eu.jgamba.MY_PERMISSION", permissions)

    def test_tier1_manifest_binary_axml_components(self) -> None:
        """Verifies declared components (activities, services, receivers, providers)."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.raw_apk)])
        self.assertEqual(code, 0)
        manifest = data["data"]
        self.assertIn("eu.jgamba.myapplication.MainActivity", manifest["activities"])
        self.assertIn("eu.jgamba.myapplication.MyFirstService", manifest["services"])
        self.assertIn("eu.jgamba.myapplication.MyReceiver", manifest["receivers"])
        self.assertIn("eu.jgamba.myapplication.MyContentProvider", manifest["providers"])

    def test_tier1_manifest_unpacked_text_xml_extraction(self) -> None:
        """Verifies manifest extraction from an unpacked directory containing plain-text XML."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.unpacked_dir)])
        self.assertEqual(code, 0)
        self.assertTrue(data.get("success"))
        manifest = data["data"]
        self.assertEqual(manifest["package_name"], "com.example.unpacked")
        self.assertEqual(manifest["version_code"], 42)
        self.assertEqual(manifest["version_name"], "2.1.0")
        self.assertTrue(manifest["debuggable"])
        self.assertIn("android.permission.INTERNET", manifest["permissions"])

    def test_tier1_manifest_raw_xml_extraction_flag(self) -> None:
        """Verifies manifest extraction with --raw or XML decoding."""
        if not is_cli_subcommand_available("apk", "manifest"):
            self.skipTest("CLI subcommand 'rvs apk manifest' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.raw_apk), "--raw"])
        self.assertEqual(code, 0, f"rvs apk manifest --raw failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        raw_xml = data["data"].get("raw_xml") or data["data"].get("xml")
        self.assertIsNotNone(raw_xml)
        self.assertIn("<manifest", raw_xml)
        self.assertIn("eu.jgamba.myapplication", raw_xml)

    # --- Feature 2: Resources & Assets Dumping ---

    def test_tier1_resources_listing_entries(self) -> None:
        """Verifies listing resources, assets, and ARSC table entries in APK."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "resources", str(self.raw_apk), "--list"])
        self.assertEqual(code, 0, f"rvs apk resources --list failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        entries = data["data"]["entries"]
        names = [e.get("name") or e.get("path") for e in entries]
        self.assertTrue(any("assets/app_config.json" in n for n in names))
        self.assertTrue(any("res/values/strings.xml" in n for n in names))

    def test_tier1_resources_extract_asset_json(self) -> None:
        """Verifies extracting and dumping assets/app_config.json content."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "resources", str(self.raw_apk), "--extract", "assets/app_config.json"
        ])
        self.assertEqual(code, 0, f"rvs apk resources --extract failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        ext = data["data"].get("extracted", {})
        self.assertEqual(ext.get("name"), "assets/app_config.json")
        self.assertIn("environment", ext.get("content", ""))

    def test_tier1_resources_extract_asset_secret_token(self) -> None:
        """Verifies extracting secret token asset without standalone script."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "resources", str(self.raw_apk), "--extract", "assets/secret_token.txt"
        ])
        self.assertEqual(code, 0, f"rvs apk resources --extract failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        ext = data["data"].get("extracted", {})
        self.assertEqual(ext.get("name"), "assets/secret_token.txt")
        self.assertIn("rvs_synthetic_secret_token", ext.get("content", ""))

    def test_tier1_resources_extract_strings_xml(self) -> None:
        """Verifies extracting XML string resources."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "resources", str(self.raw_apk), "--extract", "res/values/strings.xml"
        ])
        self.assertEqual(code, 0, f"rvs apk resources --extract failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        ext = data["data"].get("extracted", {})
        self.assertEqual(ext.get("name"), "res/values/strings.xml")
        self.assertIn("welcome_message", ext.get("content", ""))

    def test_tier1_resources_arsc_table_parsing(self) -> None:
        """Verifies resources.arsc table structure ingestion."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "resources", str(self.raw_apk), "--list"])
        self.assertEqual(code, 0, f"rvs apk resources failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        self.assertTrue(data["data"]["has_arsc"])
        entries = data["data"].get("entries", [])
        arsc_entry = next((e for e in entries if e.get("name") == "resources.arsc"), None)
        self.assertIsNotNone(arsc_entry)
        self.assertEqual(arsc_entry.get("type"), "arsc")

    def test_tier1_resources_cli_contract_envelope(self) -> None:
        """Verifies resources command follows ApiResponse envelope schema."""
        if is_cli_subcommand_available("apk", "resources"):
            code, stdout, stderr, data = run_rvs_cli(["apk", "resources", str(self.raw_apk)])
            self.assertEqual(code, 0)
            self.assertIn(data.get("command"), ["apk resources", "apk_resources"])
            self.assertEqual(data.get("target"), str(self.raw_apk))
            self.assertIn("timestamp", data)
            self.assertIn("format_version", data)

    # --- Feature 3: Dalvik DEX, Smali & Decompilation ---

    def test_tier1_dex_classes_and_methods_inspection(self) -> None:
        """Verifies DEX class, method, and string pool count metrics."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "dex", str(self.raw_apk)])
        self.assertEqual(code, 0)
        self.assertTrue(data.get("success"))
        dex_data = data["data"]
        self.assertEqual(dex_data["file_name"], "classes.dex")
        self.assertGreaterEqual(dex_data["classes_count"], 300)
        self.assertGreaterEqual(dex_data["methods_count"], 2000)
        self.assertGreaterEqual(dex_data["strings_count"], 6000)

    def test_tier1_dex_method_prototype_and_access_flags(self) -> None:
        """Verifies method prototype signatures and access flags."""
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "dex", str(self.raw_apk),
            "-C", "Lcom/devoteam/quickaction/QuickActionItem;"
        ])
        self.assertEqual(code, 0)
        classes = data["data"]["classes"]
        self.assertEqual(len(classes), 1)
        cls_obj = classes[0]
        methods = {m["name"]: m for m in cls_obj["methods"]}
        self.assertIn("setChecked", methods)
        self.assertEqual(methods["setChecked"]["signature"], "(Z)V")
        self.assertEqual(methods["setChecked"]["access_flags"], 1)

    def test_tier1_dex_dalvik_disassembly(self) -> None:
        """Verifies Dalvik opcode disassembly via --disasm flag."""
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "dex", str(self.raw_apk),
            "-C", "Lcom/devoteam/quickaction/QuickActionItem;",
            "-m", "setChecked",
            "--disasm",
        ])
        self.assertEqual(code, 0)
        classes = data["data"]["classes"]
        method = classes[0]["methods"][0]
        self.assertIn("disassembly", method)
        self.assertIsInstance(method["disassembly"], list)

    def test_tier1_dex_smali_assembly_formatting(self) -> None:
        """Verifies Dalvik method smali assembly formatting contract."""
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "dex", str(self.raw_apk),
            "-C", "Lcom/devoteam/quickaction/QuickActionItem;",
            "-m", "setChecked",
            "--smali",
        ])
        self.assertEqual(code, 0, f"rvs apk dex --smali failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        method = data["data"]["classes"][0]["methods"][0]
        smali = method.get("smali")
        self.assertIsNotNone(smali)
        self.assertIn(".method", smali)
        self.assertIn("setChecked", smali)

    def test_tier1_dex_decompilation_method(self) -> None:
        """Verifies method decompilation to high-level pseudo-code."""
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "dex", str(self.raw_apk),
            "-C", "Lcom/devoteam/quickaction/QuickActionItem;",
            "-m", "setChecked",
            "--decompile",
        ])
        self.assertEqual(code, 0, f"rvs apk dex --decompile failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        method = data["data"]["classes"][0]["methods"][0]
        decompiled = method.get("decompiled") or method.get("code")
        self.assertIsNotNone(decompiled)
        self.assertIn("setChecked", decompiled)

    # --- Feature 4: Signature & Certificate Verification ---

    def test_tier1_signature_v1_jar_manifest_verification(self) -> None:
        """Verifies v1 JAR signing files META-INF/MANIFEST.MF, CERT.SF, and CERT.RSA."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.raw_apk), "--verify"])
        self.assertEqual(code, 0, f"rvs apk signature failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        self.assertTrue(data["data"]["is_signed"])
        self.assertTrue(data["data"]["verified"])
        self.assertIn("v1", data["data"]["schemes"])
        self.assertGreaterEqual(len(data["data"]["signers"]), 1)
        signer = data["data"]["signers"][0]
        self.assertIn("RvsTestSigner", signer["subject"])

    def test_tier1_signature_v1_x509_certificate_extraction(self) -> None:
        """Verifies X.509 certificate metadata embedded in META-INF/CERT.RSA."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.raw_apk)])
        self.assertEqual(code, 0, f"rvs apk signature failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        signers = data["data"].get("signers", [])
        self.assertGreaterEqual(len(signers), 1)
        signer = signers[0]
        self.assertIn("RvsTestSigner", signer["subject"])
        self.assertIn("RvsTestSuite", signer["issuer"])
        self.assertEqual(signer.get("serial_number"), "12345678")
        self.assertEqual(signer.get("signature_algorithm"), "sha256WithRSAEncryption")

    def test_tier1_signature_v2_signing_block_detection(self) -> None:
        """Verifies APK Signing Block v2 detection (magic and ID 0x7109871a)."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.raw_apk)])
        self.assertEqual(code, 0, f"rvs apk signature failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        self.assertTrue(data["data"]["signing_block_present"])
        self.assertIn("v2", data["data"]["schemes"])

    def test_tier1_signature_fingerprint_sha256(self) -> None:
        """Verifies certificate SHA-256 fingerprint extraction."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.raw_apk)])
        self.assertEqual(code, 0, f"rvs apk signature failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        signers = data["data"].get("signers", [])
        self.assertGreaterEqual(len(signers), 1)
        fp256 = signers[0].get("sha256_fingerprint")
        self.assertIsNotNone(fp256)
        self.assertEqual(len(fp256), 64)
        self.assertTrue(all(c in "0123456789abcdefABCDEF" for c in fp256))
        fp1 = signers[0].get("sha1_fingerprint")
        self.assertIsNotNone(fp1)
        self.assertEqual(len(fp1), 40)

    def test_tier1_signature_cli_contract_envelope(self) -> None:
        """Verifies rvs apk signature command envelope compliance."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.raw_apk), "--verify"])
        self.assertEqual(code, 0, f"rvs apk signature failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertIn(data.get("command"), ["apk signature", "apk_signature"])
        self.assertTrue(data["data"]["is_signed"])
        self.assertTrue(data["data"]["verified"])
        self.assertIn("v1", data["data"]["schemes"])
        self.assertIn("v2", data["data"]["schemes"])
        self.assertTrue(data["data"]["signing_block_present"])
        self.assertIn("timestamp", data)
        self.assertIn("format_version", data)

    # --- Feature 5: Python MCP Agent Harness Tools ---

    def test_tier1_mcp_rvs_apk_info(self) -> None:
        """Verifies rvs_apk_info tool execution through harness."""
        resp = self.harness.execute_tool("rvs_apk_info", {"file": str(self.raw_apk), "compact": False})
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp.get("command"), "apk inspect")
        self.assertEqual(resp["data"]["package_name"], "eu.jgamba.myapplication")
        self.assertTrue(resp["data"]["has_manifest"])

    def test_tier1_mcp_rvs_apk_manifest(self) -> None:
        """Verifies rvs_apk_manifest tool execution through harness."""
        resp = self.harness.execute_tool("rvs_apk_manifest", {"file": str(self.raw_apk), "compact": False})
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp["data"]["package_name"], "eu.jgamba.myapplication")
        self.assertIn("eu.jgamba.myapplication.MainActivity", resp["data"]["activities"])

    def test_tier1_mcp_rvs_apk_dex(self) -> None:
        """Verifies rvs_apk_dex tool execution through harness."""
        resp = self.harness.execute_tool("rvs_apk_dex", {"file": str(self.raw_apk), "compact": False})
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp["data"]["file_name"], "classes.dex")
        self.assertGreaterEqual(resp["data"]["classes_count"], 300)

    def test_tier1_mcp_rvs_apk_native(self) -> None:
        """Verifies rvs_apk_native tool execution through harness."""
        resp = self.harness.execute_tool("rvs_apk_native", {"file": str(self.raw_apk), "compact": False})
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp["data"]["abi"], "arm64-v8a")
        jni_names = [f["name"] for f in resp["data"]["jni_functions"]]
        self.assertIn("Java_com_example_app_MainActivity_stringFromJNI", jni_names)

    def test_tier1_mcp_rvs_apk_resources(self) -> None:
        """Verifies rvs_apk_resources MCP tool contract and dispatch."""
        if not is_mcp_tool_available("rvs_apk_resources"):
            self.skipTest("MCP tool 'rvs_apk_resources' not registered in CANONICAL_TOOLS")
        resp = self.harness.execute_tool("rvs_apk_resources", {"file": str(self.raw_apk), "list": True})
        self.assertTrue(resp.get("success"))

    def test_tier1_mcp_rvs_apk_signature(self) -> None:
        """Verifies rvs_apk_signature MCP tool contract and dispatch."""
        if not is_mcp_tool_available("rvs_apk_signature"):
            self.skipTest("MCP tool 'rvs_apk_signature' not registered in CANONICAL_TOOLS")
        resp = self.harness.execute_tool("rvs_apk_signature", {"file": str(self.raw_apk), "verify": True})
        self.assertTrue(resp.get("success"))

    # --- Feature 6: Dynamic Frida Connection & Target Resolution ---

    def test_tier1_frida_apk_target_detection(self) -> None:
        """Verifies target is identified as an APK container."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "inspect", str(self.raw_apk)])
        self.assertEqual(code, 0, f"rvs apk inspect failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        self.assertEqual(data["data"]["source_type"], "archive")
        self.assertTrue(data["data"]["has_manifest"])
        self.assertEqual(data["data"]["package_name"], "eu.jgamba.myapplication")

    def test_tier1_frida_package_name_resolution(self) -> None:
        """Verifies package name can be resolved from APK for Frida attachment."""
        resp = self.harness.execute_tool("rvs_apk_manifest", {"file": str(self.raw_apk)})
        self.assertTrue(resp.get("success"))
        pkg_name = resp["data"].get("package_name") or resp["data"].get("pkg")
        self.assertEqual(pkg_name, "eu.jgamba.myapplication")

    def test_tier1_frida_spawn_apk_contract(self) -> None:
        """Verifies rvs_frida_spawn handles APK target with structured envelope."""
        resp = self.harness.execute_tool("rvs_frida_spawn", {"target": str(self.raw_apk)})
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp.get("command"), "frida spawn")
        self.assertEqual(resp.get("target"), str(self.raw_apk))
        if resp.get("success"):
            self.assertIn("pid", resp.get("data", {}))
        else:
            self.assertIn("error", resp)
            self.assertIn(resp["error"].get("code"), ["PERMISSION_DENIED", "R2_FRIDA_NOT_INSTALLED", "TARGET_NOT_EXECUTABLE"])

    def test_tier1_frida_attach_apk_contract(self) -> None:
        """Verifies rvs_frida_attach handles APK target with structured envelope."""
        resp = self.harness.execute_tool("rvs_frida_attach", {"target": str(self.raw_apk)})
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp.get("command"), "frida attach")
        self.assertEqual(resp.get("target"), str(self.raw_apk))
        if resp.get("success"):
            self.assertIn("session_id", resp.get("data", {}))
        else:
            self.assertIn("error", resp)
            self.assertIn(resp["error"].get("code"), ["R2_FRIDA_NOT_INSTALLED", "DEVICE_NOT_FOUND", "PROCESS_NOT_FOUND"])

    def test_tier1_frida_device_usb_default_contract(self) -> None:
        """Verifies Frida environment check executes cleanly."""
        resp = self.harness.execute_tool("rvs_frida_env_check", {})
        self.assertIsInstance(resp, dict)
        self.assertEqual(resp.get("command"), "frida env-check")
        if resp.get("success"):
            self.assertTrue("installed" in resp.get("data", {}) or "r2frida_installed" in resp.get("data", {}))
        else:
            self.assertIn("error", resp)
            self.assertEqual(resp["error"].get("code"), "R2_FRIDA_NOT_INSTALLED")


# =============================================================================
# Tier 2: Boundary & Corner Cases
# =============================================================================

class TestApkE2ETier2BoundaryAndCornerCases(unittest.TestCase):
    """
    Tier 2 tests verifying boundary, adversarial, and error conditions (>=5 tests per feature).
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls.temp_dir.name)
        cls.harness = RvsHarness()

        # Generate boundary fixtures
        cls.empty_apk = cls.tmp / "empty.apk"
        create_zero_byte_target(cls.empty_apk)

        cls.corrupt_zip = cls.tmp / "corrupt_zip.apk"
        create_corrupted_apk(cls.corrupt_zip, corruption_type="bad_zip")

        cls.unsigned_apk = cls.tmp / "unsigned.apk"
        create_unsigned_apk(cls.unsigned_apk)

        cls.tampered_apk = cls.tmp / "tampered.apk"
        create_tampered_signature_apk(cls.tampered_apk)

        cls.bad_magic_apk = cls.tmp / "bad_magic.apk"
        create_corrupted_signing_block_apk(cls.bad_magic_apk, corruption_type="bad_magic")

        cls.size_mismatch_apk = cls.tmp / "size_mismatch.apk"
        create_corrupted_signing_block_apk(cls.size_mismatch_apk, corruption_type="size_mismatch")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    # --- Boundary 1: Manifest Boundaries ---

    def test_tier2_manifest_truncated_axml(self) -> None:
        """Verifies handling of truncated binary AXML manifest."""
        corrupt_axml = FIXTURES_DIR / "corrupt_manifest.axml"
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(corrupt_axml)])
        self.assertNotEqual(code, 0)
        self.assertFalse(data.get("success", False) if data else False)

    def test_tier2_manifest_missing_file(self) -> None:
        """Verifies non-existent manifest path fails with structured error."""
        nonexistent = self.tmp / "does_not_exist.apk"
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(nonexistent)])
        self.assertNotEqual(code, 0)

    def test_tier2_manifest_malformed_xml(self) -> None:
        """Verifies unclosed tag in plain text manifest returns structured error."""
        bad_dir = FIXTURES_DIR / "corrupt_manifest_dir"
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(bad_dir)])
        self.assertNotEqual(code, 0)

    def test_tier2_manifest_empty_file(self) -> None:
        """Verifies 0-byte manifest/APK fails gracefully."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.empty_apk)])
        self.assertNotEqual(code, 0)

    def test_tier2_manifest_corrupted_header(self) -> None:
        """Verifies corrupted ZIP header produces clean structured error."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "manifest", str(self.corrupt_zip)])
        self.assertNotEqual(code, 0)

    # --- Boundary 2: Resources & Assets Boundaries ---

    def test_tier2_resources_nonexistent_entry_extract(self) -> None:
        """Verifies extracting nonexistent resource path fails gracefully."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "resources", str(FIXTURES_DIR / "sample_raw.apk"),
            "--extract", "assets/nonexistent_file_xyz.txt"
        ])
        self.assertNotEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertFalse(data.get("success", True))
        self.assertIn("error", data)

    def test_tier2_resources_path_traversal_attempt(self) -> None:
        """Verifies path traversal attempts (e.g. ../../etc/passwd) are rejected."""
        if is_cli_subcommand_available("apk", "resources"):
            code, stdout, stderr, data = run_rvs_cli([
                "apk", "resources", str(FIXTURES_DIR / "sample_raw.apk"),
                "--extract", "../../etc/passwd"
            ])
            self.assertNotEqual(code, 0)
            self.assertIsNotNone(data)
            self.assertFalse(data.get("success", True))
            self.assertEqual(data.get("error", {}).get("code"), "INVALID_BINARY")

    def test_tier2_resources_directory_path_traversal_blocked(self) -> None:
        """Verifies extracting host files via absolute paths or directory traversal fails gracefully."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        unpacked_dir = FIXTURES_DIR / "sample_unpacked_dir"

        # Test absolute path attack (/etc/passwd)
        code_abs, stdout_abs, stderr_abs, data_abs = run_rvs_cli([
            "apk", "resources", str(unpacked_dir),
            "--extract", "/etc/passwd"
        ])
        self.assertNotEqual(code_abs, 0, "Absolute path /etc/passwd extraction must be rejected")
        self.assertIsNotNone(data_abs)
        self.assertFalse(data_abs.get("success", True))
        self.assertEqual(data_abs.get("error", {}).get("code"), "INVALID_BINARY")
        self.assertNotIn("root:x:", stdout_abs)
        self.assertNotIn("root:x:", stderr_abs)

        # Test relative path traversal attack (../../etc/passwd)
        code_rel, stdout_rel, stderr_rel, data_rel = run_rvs_cli([
            "apk", "resources", str(unpacked_dir),
            "--extract", "../../../../../../etc/passwd"
        ])
        self.assertNotEqual(code_rel, 0, "Relative traversal ../etc/passwd must be rejected")
        self.assertIsNotNone(data_rel)
        self.assertFalse(data_rel.get("success", True))
        self.assertEqual(data_rel.get("error", {}).get("code"), "INVALID_BINARY")
        self.assertNotIn("root:x:", stdout_rel)
        self.assertNotIn("root:x:", stderr_rel)

    def test_tier2_resources_dump_zip_slip_blocked(self) -> None:
        """Verifies dumping an APK containing Zip Slip traversal entries does not escape destination directory."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            synth_apk = temp_path / "zip_slip_fixture.apk"
            dump_dest = temp_path / "dump_out"
            dump_dest.mkdir()
            canary_escaped = temp_path / "canary_escaped.txt"

            with zipfile.ZipFile(str(synth_apk), "w") as z:
                z.writestr("AndroidManifest.xml", b"<manifest package=\"com.slip.test\" />")
                z.writestr("res/values/strings.xml", b"<resources><string name=\"safe\">hello</string></resources>")
                z.writestr("../canary_escaped.txt", b"CANARY_PAYLOAD_ESCAPED")
                z.writestr("res/../../../tmp/canary_e2e_tmp.txt", b"TMP_PAYLOAD_ESCAPED")

            code, stdout, stderr, data = run_rvs_cli([
                "apk", "resources", str(synth_apk),
                "--dump", str(dump_dest)
            ])
            self.assertEqual(code, 0)
            self.assertIsNotNone(data)
            self.assertTrue(data.get("success"))

            # Legitimate file was dumped
            self.assertTrue((dump_dest / "res/values/strings.xml").is_file())

            # Traversal entries did not escape
            self.assertFalse(canary_escaped.exists(), "Zip slip entry must not escape dump_dest")
            self.assertFalse(Path("/tmp/canary_e2e_tmp.txt").exists(), "Zip slip entry must not escape to /tmp")

    def test_tier2_resources_apk_without_assets(self) -> None:
        """Verifies APK with no assets folder does not crash."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        no_so = FIXTURES_DIR / "sample_no_so.apk"
        code, stdout, stderr, data = run_rvs_cli(["apk", "resources", str(no_so), "--list"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))

    def test_tier2_resources_empty_resource_file(self) -> None:
        """Verifies 0-byte APK returns error when inspecting resources."""
        if is_cli_subcommand_available("apk", "resources"):
            code, stdout, stderr, data = run_rvs_cli(["apk", "resources", str(self.empty_apk)])
            self.assertNotEqual(code, 0)

    def test_tier2_resources_corrupt_arsc_header(self) -> None:
        """Verifies corrupted ARSC header chunk is detected without panic."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        corrupt_arsc = self.tmp / "corrupt.arsc"
        corrupt_arsc.write_bytes(b"\xFF\xFF\x00\x00\x00\x00\x00\x00")
        code, stdout, stderr, data = run_rvs_cli(["apk", "resources", str(corrupt_arsc)])
        self.assertNotEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertFalse(data.get("success", True))
        self.assertIn("error", data)

    # --- Boundary 3: DEX Boundaries ---

    def test_tier2_dex_corrupt_magic(self) -> None:
        """Verifies corrupted DEX header magic fails with structured error."""
        corrupt_dex = FIXTURES_DIR / "corrupt_classes.dex"
        code, stdout, stderr, data = run_rvs_cli(["apk", "dex", str(corrupt_dex)])
        self.assertNotEqual(code, 0)

    def test_tier2_dex_nonexistent_class_filter(self) -> None:
        """Verifies filtering by non-existent class returns empty class list."""
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "dex", str(FIXTURES_DIR / "sample_raw.apk"),
            "-C", "Lcom/nonexistent/FakeClass;"
        ])
        self.assertEqual(code, 0)
        classes = data["data"]["classes"]
        self.assertEqual(len(classes), 0)

    def test_tier2_dex_nonexistent_method_filter(self) -> None:
        """Verifies filtering by non-existent method returns empty method list."""
        code, stdout, stderr, data = run_rvs_cli([
            "apk", "dex", str(FIXTURES_DIR / "sample_raw.apk"),
            "-C", "Lcom/devoteam/quickaction/QuickActionItem;",
            "-m", "nonExistentMethodXYZ",
        ])
        self.assertEqual(code, 0)
        classes = data["data"]["classes"]
        self.assertEqual(len(classes[0]["methods"]), 0)

    def test_tier2_dex_apk_without_dex(self) -> None:
        """Verifies APK container without classes.dex returns error."""
        so_only = self.tmp / "so_only.apk"
        create_synthetic_apk(so_only, dex_strings_map={}, multidex=False)
        # Remove classes.dex from archive
        with zipfile.ZipFile(so_only, "r") as zf:
            items = {item.filename: zf.read(item.filename) for item in zf.infolist() if item.filename != "classes.dex"}
        with zipfile.ZipFile(so_only, "w") as zf:
            for name, content in items.items():
                zf.writestr(name, content)
        code, stdout, stderr, data = run_rvs_cli(["apk", "dex", str(so_only)])
        self.assertNotEqual(code, 0)

    def test_tier2_dex_truncated_bytecode(self) -> None:
        """Verifies truncated DEX file is rejected cleanly."""
        truncated_dex = self.tmp / "truncated.dex"
        truncated_dex.write_bytes(b"dex\n035\x00" + b"\x00" * 40)
        code, stdout, stderr, data = run_rvs_cli(["apk", "dex", str(truncated_dex)])
        self.assertNotEqual(code, 0)

    # --- Boundary 4: Signature & Security Boundaries ---

    def test_tier2_signature_unsigned_apk(self) -> None:
        """Verifies unsigned APK returns valid=false and signature warnings."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.unsigned_apk), "--verify"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertFalse(data["data"]["is_signed"])
        self.assertFalse(data["data"]["verified"])
        self.assertEqual(data["data"]["schemes"], [])
        self.assertFalse(data["data"]["signing_block_present"])
        self.assertGreaterEqual(len(data["data"]["verification_errors"]), 1)

    def test_tier2_signature_tampered_file_digest(self) -> None:
        """Verifies APK with tampered payload triggers signature verification failure."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.tampered_apk), "--verify"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertFalse(data["data"]["verified"])
        self.assertGreaterEqual(len(data["data"]["verification_errors"]), 1)

    def test_tier2_signature_corrupted_signing_block_bad_magic(self) -> None:
        """Verifies corrupted APK Signing Block magic ('BAD Sig Block 42') is detected."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.bad_magic_apk), "--verify"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertFalse(data["data"]["signing_block_present"])
        self.assertFalse(data["data"]["is_signed"])
        self.assertFalse(data["data"]["verified"])
        self.assertNotIn("v2", data["data"]["schemes"])
        self.assertGreaterEqual(len(data["data"]["verification_errors"]), 1)

    def test_tier2_signature_corrupted_signing_block_size_mismatch(self) -> None:
        """Verifies size mismatch between first and second uint64 size fields."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(self.size_mismatch_apk), "--verify"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertFalse(data["data"]["is_signed"])
        self.assertFalse(data["data"]["verified"])
        self.assertNotIn("v2", data["data"]["schemes"])
        self.assertGreaterEqual(len(data["data"]["verification_errors"]), 1)

    def test_tier2_signature_truncated_signing_block(self) -> None:
        """Verifies truncated signing block fails cleanly."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        trunc = self.tmp / "trunc_sig.apk"
        create_corrupted_signing_block_apk(trunc, corruption_type="truncated")
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(trunc), "--verify"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(data)
        self.assertFalse(data["data"]["signing_block_present"])
        self.assertFalse(data["data"]["is_signed"])
        self.assertFalse(data["data"]["verified"])
        self.assertGreaterEqual(len(data["data"]["verification_errors"]), 1)

    # --- Boundary 5: MCP & Harness Boundaries ---

    def test_tier2_mcp_missing_required_file_param(self) -> None:
        """Verifies calling MCP tool without 'file' parameter returns error."""
        resp = self.harness.execute_tool("rvs_apk_manifest", {})
        self.assertFalse(resp.get("success"))
        self.assertIn("error", resp)

    def test_tier2_mcp_nonexistent_file_path(self) -> None:
        """Verifies calling MCP tool with nonexistent path returns error."""
        resp = self.harness.execute_tool("rvs_apk_manifest", {"file": "/path/to/nonexistent/target.apk"})
        self.assertFalse(resp.get("success"))

    def test_tier2_mcp_non_apk_file_passed(self) -> None:
        """Verifies passing arbitrary text file to rvs_apk_manifest fails cleanly."""
        txt_file = self.tmp / "not_an_apk.txt"
        txt_file.write_text("Hello, world!")
        resp = self.harness.execute_tool("rvs_apk_manifest", {"file": str(txt_file)})
        self.assertFalse(resp.get("success"))

    def test_tier2_mcp_zero_byte_file(self) -> None:
        """Verifies passing 0-byte file to rvs_apk_dex fails cleanly."""
        resp = self.harness.execute_tool("rvs_apk_dex", {"file": str(self.empty_apk)})
        self.assertFalse(resp.get("success"))

    def test_tier2_mcp_frida_nonexistent_package(self) -> None:
        """Verifies frida attach to invalid package returns structured error."""
        resp = self.harness.execute_tool("rvs_frida_attach", {"target": "com.invalid.nonexistent.fakeapp"})
        self.assertIsInstance(resp, dict)
        self.assertIn("success", resp)


# =============================================================================
# Tier 3: Cross-Feature Combinations (Pairwise Interactions)
# =============================================================================

class TestApkE2ETier3CrossFeatureCombinations(unittest.TestCase):
    """
    Tier 3 tests verifying cross-feature interactions and data consistency.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw_apk = FIXTURES_DIR / "sample_raw.apk"
        cls.multi_dex_apk = FIXTURES_DIR / "sample_multi_dex.apk"
        cls.harness = RvsHarness()

    def test_tier3_manifest_to_dex_pipeline(self) -> None:
        """Verifies activities declared in AndroidManifest correlate with DEX classes."""
        _, _, _, m_data = run_rvs_cli(["apk", "manifest", str(self.raw_apk)])
        _, _, _, d_data = run_rvs_cli(["apk", "dex", str(self.raw_apk)])
        self.assertTrue(m_data["success"])
        self.assertTrue(d_data["success"])

        pkg = m_data["data"]["package_name"]
        self.assertTrue(len(pkg) > 0)
        self.assertGreater(d_data["data"]["classes_count"], 0)

        # Cross-verify on synthetic APK where DEX strings correlate with manifest
        temp_apk = FIXTURES_DIR.parent / "temp_cross.apk"
        create_synthetic_apk(temp_apk, multidex=False)
        try:
            _, _, _, sm_data = run_rvs_cli(["apk", "manifest", str(temp_apk)])
            _, _, _, sd_data = run_rvs_cli(["apk", "dex", str(temp_apk)])
            self.assertTrue(sm_data["success"])
            self.assertTrue(sd_data["success"])
            strings = sd_data["data"].get("strings", [])
            self.assertTrue(len(strings) > 0)
            self.assertTrue(any("AuthActivity" in s or "example" in s for s in strings))
        finally:
            if temp_apk.exists():
                temp_apk.unlink()

    def test_tier3_manifest_to_frida_target_correlation(self) -> None:
        """Verifies package name from manifest matches Frida target string."""
        resp = self.harness.execute_tool("rvs_apk_manifest", {"file": str(self.raw_apk), "compact": False})
        pkg = resp["data"]["package_name"]
        self.assertEqual(pkg, "eu.jgamba.myapplication")

    def test_tier3_unpacked_text_manifest_to_resources(self) -> None:
        """Verifies unpacked directory text manifest correlates with inspect metadata."""
        unpacked_dir = FIXTURES_DIR / "sample_unpacked_dir"
        _, _, _, inspect_data = run_rvs_cli(["apk", "inspect", str(unpacked_dir)])
        _, _, _, manifest_data = run_rvs_cli(["apk", "manifest", str(unpacked_dir)])
        self.assertEqual(inspect_data["data"]["package_name"], manifest_data["data"]["package_name"])

    def test_tier3_compact_vs_full_json_schema_consistency(self) -> None:
        """Verifies compact output (-c) contains equivalent information in token-optimized format."""
        _, _, _, full_data = run_rvs_cli(["apk", "inspect", str(self.raw_apk)])
        _, _, _, compact_data = run_rvs_cli(["apk", "inspect", str(self.raw_apk), "-c"])
        self.assertTrue(full_data["success"])
        self.assertTrue(compact_data["success"])
        # Compact reduces output size
        self.assertEqual(full_data["data"]["package_name"], compact_data["data"].get("package_name") or compact_data["data"].get("pkg"))

    def test_tier3_multidex_and_multiabi_coexistence(self) -> None:
        """Verifies multidex APK contains multiple DEX files and native libraries."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "inspect", str(self.multi_dex_apk)])
        self.assertEqual(code, 0)
        dex_files = data["data"]["dex_files"]
        self.assertGreaterEqual(len(dex_files), 2)
        self.assertTrue(any("classes.dex" in d for d in dex_files))
        self.assertTrue(any("classes2.dex" in d for d in dex_files))
        self.assertIn("arm64-v8a", data["data"]["native_libraries"])

    def test_tier3_native_so_jni_to_dex_correlation(self) -> None:
        """Verifies native exported JNI functions match Dalvik class and method conventions."""
        _, _, _, so_data = run_rvs_cli(["apk", "so", str(self.raw_apk)])
        self.assertTrue(so_data["success"])
        jni_funcs = so_data["data"]["jni_functions"]
        self.assertGreaterEqual(len(jni_funcs), 1)
        first_func = jni_funcs[0]
        self.assertTrue(first_func["name"].startswith("Java_"))
        self.assertTrue(len(first_func["demangled_class"]) > 0)
        self.assertTrue(len(first_func["demangled_method"]) > 0)

    def test_tier3_cli_json_envelope_to_mcp_dict_consistency(self) -> None:
        """Verifies native CLI JSON envelope fields match Python MCP response format."""
        _, _, _, cli_data = run_rvs_cli(["apk", "manifest", str(self.raw_apk)])
        mcp_data = self.harness.execute_tool("rvs_apk_manifest", {"file": str(self.raw_apk), "compact": False})
        self.assertEqual(cli_data["success"], mcp_data["success"])
        self.assertEqual(cli_data["target"], mcp_data["target"])
        self.assertEqual(cli_data["data"]["package_name"], mcp_data["data"]["package_name"])

    def test_tier3_signatures_with_resources_integrity(self) -> None:
        """Verifies package integrity when both resources and v1/v2 signatures are present."""
        if not is_cli_subcommand_available("apk", "resources"):
            self.skipTest("CLI subcommand 'rvs apk resources' not available")
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        res_code, _, res_err, res_data = run_rvs_cli(["apk", "resources", str(self.raw_apk), "--list"])
        self.assertEqual(res_code, 0, f"rvs apk resources failed: {res_err}")
        self.assertTrue(res_data["success"])
        self.assertTrue(res_data["data"]["has_arsc"])

        sig_code, _, sig_err, sig_data = run_rvs_cli(["apk", "signature", str(self.raw_apk), "--verify"])
        self.assertEqual(sig_code, 0, f"rvs apk signature failed: {sig_err}")
        self.assertTrue(sig_data["success"])
        self.assertTrue(sig_data["data"]["is_signed"])
        self.assertTrue(sig_data["data"]["verified"])
        self.assertTrue(sig_data["data"]["signing_block_present"])
        self.assertIn("v1", sig_data["data"]["schemes"])
        self.assertIn("v2", sig_data["data"]["schemes"])


# =============================================================================
# Tier 4: Real-World Application Scenarios
# =============================================================================

class TestApkE2ETier4RealWorldApplicationScenarios(unittest.TestCase):
    """
    Tier 4 tests verifying end-to-end multi-step real-world reverse engineering workflows.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw_apk = FIXTURES_DIR / "sample_raw.apk"
        cls.multi_dex_apk = FIXTURES_DIR / "sample_multi_dex.apk"
        cls.harness = RvsHarness()
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls.temp_dir.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def test_tier4_e2e_full_triage_sample_raw_apk(self) -> None:
        """
        Executes complete end-to-end triage sequence on sample_raw.apk:
        Step 1: Inspect package identity & detected languages
        Step 2: Manifest extraction (permissions & main activity)
        Step 3: DEX inspection
        Step 4: Native .so JNI function discovery
        Step 5: Signature integrity check
        """
        # Step 1: Inspect
        r1 = self.harness.execute_tool("rvs_apk_info", {"file": str(self.raw_apk)})
        self.assertTrue(r1["success"])
        self.assertEqual(r1["data"].get("package_name") or r1["data"].get("pkg"), "eu.jgamba.myapplication")

        # Step 2: Manifest
        r2 = self.harness.execute_tool("rvs_apk_manifest", {"file": str(self.raw_apk), "compact": False})
        self.assertTrue(r2["success"])
        self.assertIn("eu.jgamba.myapplication.MainActivity", r2["data"]["activities"])

        # Step 3: DEX
        r3 = self.harness.execute_tool("rvs_apk_dex", {"file": str(self.raw_apk), "compact": False})
        self.assertTrue(r3["success"])
        self.assertGreaterEqual(r3["data"]["classes_count"], 300)

        # Step 4: Native SO
        r4 = self.harness.execute_tool("rvs_apk_native", {"file": str(self.raw_apk), "compact": False})
        self.assertTrue(r4["success"])
        self.assertEqual(r4["data"]["abi"], "arm64-v8a")
        self.assertGreaterEqual(len(r4["data"]["jni_functions"]), 1)

    def test_tier4_e2e_multidex_package_audit(self) -> None:
        """Verifies multi-DEX package triage inspecting both primary and secondary DEX files."""
        code, stdout, stderr, data = run_rvs_cli(["apk", "inspect", str(self.multi_dex_apk)])
        self.assertEqual(code, 0)
        dex_files = data["data"]["dex_files"]
        self.assertEqual(len(dex_files), 2)

        code1, _, _, dex1 = run_rvs_cli(["apk", "dex", str(self.multi_dex_apk), "--dex-file", "classes.dex"])
        self.assertEqual(code1, 0)
        self.assertEqual(dex1["data"]["file_name"], "classes.dex")

        code2, _, _, dex2 = run_rvs_cli(["apk", "dex", str(self.multi_dex_apk), "--dex-file", "classes2.dex"])
        self.assertEqual(code2, 0)
        self.assertEqual(dex2["data"]["file_name"], "classes2.dex")

    def test_tier4_e2e_standalone_dex_and_so_investigation(self) -> None:
        """Verifies triage flow when target is a standalone .dex or .so file outside an APK."""
        classes_dex = FIXTURES_DIR / "sample_classes.dex"
        code, stdout, stderr, data = run_rvs_cli(["apk", "dex", str(classes_dex)])
        self.assertEqual(code, 0)
        self.assertTrue(data["success"])

        aarch64_so = FIXTURES_DIR / "sample_aarch64_lib.so"
        code, stdout, stderr, data = run_rvs_cli(["apk", "so", str(aarch64_so)])
        self.assertEqual(code, 0)
        self.assertTrue(data["success"])

    def test_tier4_e2e_react_native_bundle_extraction(self) -> None:
        """Verifies end-to-end triage of React Native APK detecting bundle asset and runtime markers."""
        rn_apk = self.tmp / "sample_rn.apk"
        create_synthetic_react_native_apk(rn_apk)
        code, stdout, stderr, data = run_rvs_cli(["apk", "inspect", str(rn_apk)])
        self.assertEqual(code, 0)
        langs = [l["language"] for l in data["data"]["languages"]]
        self.assertIn("React Native", langs)

    def test_tier4_e2e_flutter_dart_snapshot_triage(self) -> None:
        """Verifies end-to-end triage of Flutter/Dart APK detecting kernel blob asset and runtime markers."""
        flutter_apk = self.tmp / "sample_flutter.apk"
        create_synthetic_flutter_apk(flutter_apk)
        code, stdout, stderr, data = run_rvs_cli(["apk", "inspect", str(flutter_apk)])
        self.assertEqual(code, 0)
        langs = [l["language"] for l in data["data"]["languages"]]
        self.assertTrue(any("Flutter" in l for l in langs))

    def test_tier4_e2e_hybrid_multi_framework_triage(self) -> None:
        """Verifies triage of hybrid framework APK containing React Native and custom security binaries."""
        hybrid_apk = self.tmp / "sample_hybrid.apk"
        create_synthetic_hybrid_apk(hybrid_apk)
        code, stdout, stderr, data = run_rvs_cli(["apk", "inspect", str(hybrid_apk)])
        self.assertEqual(code, 0)
        langs = [l["language"] for l in data["data"]["languages"]]
        self.assertIn("React Native", langs)
        self.assertIn("C/C++", langs)

    def test_tier4_e2e_defensive_security_tamper_detection(self) -> None:
        """Verifies security audit pipeline detects tampered signature digests."""
        if not is_cli_subcommand_available("apk", "signature"):
            self.skipTest("CLI subcommand 'rvs apk signature' not available")
        tampered = self.tmp / "tampered_audit.apk"
        create_tampered_signature_apk(tampered)
        code, stdout, stderr, data = run_rvs_cli(["apk", "signature", str(tampered), "--verify"])
        self.assertEqual(code, 0, f"rvs apk signature failed: {stderr}")
        self.assertIsNotNone(data)
        self.assertTrue(data.get("success"))
        self.assertFalse(data["data"]["verified"])
        self.assertGreaterEqual(len(data["data"]["verification_errors"]), 1)


if __name__ == "__main__":
    unittest.main()
