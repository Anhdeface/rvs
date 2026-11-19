#!/usr/bin/env python3
"""
tests/test_e2e_install_unpack.py - End-to-End Test Suite for rvs:
1. install.sh Multi-Distro Linux Environment Diagnostics & Java Check (M1 / R2)
2. Autonomous APK Unpack CLI & Structured Extraction (M2 / R1)
3. Smali Directory Recognition in Container Ingestion (M2 / R1)
4. User-Focused README Verification & 50 Canonical Tool Sync (M3 / R4)
5. Cross-Feature Workflows & Roundtrip Pipelines (M4 / R3)

Adheres strictly to the 4-tier test architecture, opaque-box methodology,
and hermetic temporary directory isolation.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

WORKSPACE_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = WORKSPACE_DIR / "tests" / "fixtures"
INSTALL_SH = WORKSPACE_DIR / "install.sh"
README_MD = WORKSPACE_DIR / "README.md"

if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import rvs_agent_harness as h
from rvs_agent_harness import CANONICAL_TOOLS


def resolve_rvs_binary() -> Path:
    """Locate the compiled rvs CLI binary (debug or release)."""
    debug_bin = WORKSPACE_DIR / "target" / "debug" / "rvs"
    release_bin = WORKSPACE_DIR / "target" / "release" / "rvs"

    if debug_bin.exists() and os.access(debug_bin, os.X_OK):
        return debug_bin
    if release_bin.exists() and os.access(release_bin, os.X_OK):
        return release_bin
    found = shutil.which("rvs")
    if found:
        return Path(found)
    return debug_bin


RVS_BIN = resolve_rvs_binary()


def run_rvs_cli(
    args: List[str], timeout: int = 30
) -> Tuple[int, str, str, Optional[Dict[str, Any]]]:
    """Execute the rvs CLI binary and return (exit_code, stdout, stderr, parsed_json_or_none)."""
    cmd = [str(RVS_BIN)] + args
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    json_data = None
    if p.stdout.strip():
        try:
            json_data = json.loads(p.stdout)
        except Exception:
            pass
    return p.returncode, p.stdout, p.stderr, json_data


def run_install_sh(
    args: List[str],
    extra_env: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    stdin_input: Optional[str] = None,
) -> Tuple[int, str, str]:
    """Execute install.sh with custom environment and return (exit_code, stdout, stderr)."""
    env = dict(os.environ)
    if extra_env:
        for k, v in extra_env.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v

    cmd = ["bash", str(INSTALL_SH)] + args
    p = subprocess.run(
        cmd,
        cwd=str(WORKSPACE_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        input=stdin_input,
        env=env,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


class TestInstallScriptEnvironmentDiagnostics(unittest.TestCase):
    """
    Validation of Requirement R2 and Milestone 1:
    - Multi-distro Linux environment diagnostics
    - Dynamic Java runtime check (OpenJDK >= 8, JRE vs JDK)
    - 14-character column alignment formatting
    - Strictly ZERO auto-install commands and ZERO package manager suggestions
    """

    def test_01_install_sh_syntax_validity(self):
        """Verify install.sh has valid Bash syntax with zero parse errors."""
        res = subprocess.run(
            ["bash", "-n", str(INSTALL_SH)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"Bash syntax error in install.sh: {res.stderr}")

    def test_02_install_sh_diagnostics_flag(self):
        """Verify ./install.sh --diagnostics executes cleanly non-interactively and exits 0."""
        code, stdout, stderr = run_install_sh(["--diagnostics"])
        self.assertEqual(code, 0, f"install.sh --diagnostics failed with code {code}: {stderr}")
        self.assertIn("Environment", stdout)
        self.assertIn("Java", stdout)
        self.assertIn("Python 3", stdout)
        self.assertIn("radare2", stdout)
        self.assertIn("Git", stdout)
        self.assertIn("jq", stdout)

    def test_03_install_sh_check_flag_alias(self):
        """Verify ./install.sh --check works as an alias to --diagnostics."""
        code, stdout, stderr = run_install_sh(["--check"])
        self.assertEqual(code, 0, f"install.sh --check failed with code {code}: {stderr}")
        self.assertIn("Environment", stdout)
        self.assertIn("Java", stdout)

    def test_04_install_sh_java_detection_standard_env(self):
        """Verify install.sh detects Java runtime in standard environment and formats OK."""
        code, stdout, stderr = run_install_sh(["--diagnostics"])
        self.assertEqual(code, 0)
        # Check that Java line contains OK
        java_line = None
        for line in stdout.splitlines():
            if "Java" in line and ":" in line:
                java_line = line
                break
        self.assertIsNotNone(java_line, "Java status line not found in output")
        self.assertIn("OK", java_line, f"Expected Java status OK, got: {java_line}")

    def test_05_install_sh_14_char_column_format(self):
        """
        Verify exact 14-character column alignment for all Environment diagnostic rows:
        Prefix up to colon must match: '  <Name><spaces>: ' exactly 14 characters.
        """
        code, stdout, stderr = run_install_sh(["--diagnostics"])
        self.assertEqual(code, 0)

        expected_labels = [
            "User",
            "Repo",
            "rvs CLI",
            "Python 3",
            "Java",
            "Apktool",
            "radare2",
            "Git",
            "jq",
            "Cargo",
        ]

        found_labels = []
        for line in stdout.splitlines():
            clean_line = re.sub(r"\x1b\[[0-9;]*[mK]", "", line)
            m = re.match(r"^(  [A-Za-z0-9 ]+?)\s*:\s+(.*)$", clean_line)
            if m:
                label_part = clean_line.split(":")[0] + ":"
                col_width = len(label_part)
                label_name = m.group(1).strip()
                if label_name in expected_labels:
                    found_labels.append(label_name)
                    # '  <Label>   :' is exactly 13 characters, followed by a space = column 14
                    self.assertEqual(
                        col_width,
                        13,
                        f"Label '{label_name}' column width up to colon is {col_width}, expected 13 ('{label_part}')",
                    )
                    self.assertTrue(
                        clean_line.startswith(label_part + " "),
                        f"Label line must have space after colon: '{clean_line}'",
                    )

        self.assertIn("Java", found_labels, "Java row was not found in Environment diagnostic table")
        self.assertIn("Apktool", found_labels, "Apktool row was not found in Environment diagnostic table")
        self.assertIn("Python 3", found_labels)
        self.assertIn("Git", found_labels)

    def test_06_install_sh_missing_java_clean_warning_not_fatal(self):
        """
        Verify that when Java is missing, install.sh:
        1. Reports 'Java          : missing'
        2. Emits a non-fatal warning '[!] Java is missing...'
        3. Exits with return code 0 (does NOT abort installation)
        """
        # Strip all directories containing java or jdk from PATH
        clean_path_dirs = [
            d for d in os.environ.get("PATH", "").split(":")
            if d and not (Path(d) / "java").exists() and "jdk" not in d
        ]
        env_override = {
            "PATH": ":".join(clean_path_dirs),
            "JAVA_HOME": "",
        }

        code, stdout, stderr = run_install_sh(["--diagnostics"], extra_env=env_override)
        self.assertEqual(code, 0, f"Missing Java must be non-fatal, but exited with {code}: {stderr}")

        clean_out = re.sub(r"\x1b\[[0-9;]*[mK]", "", stdout)
        self.assertIn("Java", clean_out)
        self.assertIn("missing", clean_out)
        self.assertIn("Java is missing", clean_out)

    def test_07_strictly_no_package_manager_suggestions_on_missing_java(self):
        """
        STRICT REQUIREMENT R2:
        Assert NO auto-install commands and NO package manager suggestions:
        'apt', 'yum', 'dnf', 'pacman', 'zypper', 'brew', 'try running', 'please install'.
        """
        clean_path_dirs = [
            d for d in os.environ.get("PATH", "").split(":")
            if d and not (Path(d) / "java").exists() and "jdk" not in d
        ]
        env_override = {
            "PATH": ":".join(clean_path_dirs),
            "JAVA_HOME": "",
        }

        code, stdout, stderr = run_install_sh(["--diagnostics"], extra_env=env_override)
        combined = (stdout + "\n" + stderr).lower()

        forbidden_keywords = [
            "apt",
            "yum",
            "dnf",
            "pacman",
            "zypper",
            "brew",
            "try running",
            "please install",
            "install them with your package manager",
            "sudo apt install",
            "brew install",
            "pacman -s",
        ]

        for kw in forbidden_keywords:
            self.assertNotIn(
                kw,
                combined,
                f"Violation of R2: Package manager command or suggestion '{kw}' found in installer output:\n{combined}",
            )

    def test_08_strictly_no_package_manager_suggestions_on_missing_required(self):
        """
        Verify that even when a required tool (like jq) is missing:
        1. Script reports missing error and exits code 1.
        2. STRICTLY NO package manager suggestions (apt/yum/dnf/pacman/brew) are printed.
        """
        with tempfile.TemporaryDirectory() as fake_bin:
            # Mirror all directories in PATH, but mask jq with a non-executable entry
            # or recreate /usr/bin without jq
            for p in os.environ.get("PATH", "").split(":"):
                if p and (Path(p) / "jq").is_file():
                    for f in os.listdir(p):
                        if f != "jq":
                            src_file = Path(p) / f
                            dest_file = Path(fake_bin) / f
                            if not dest_file.exists():
                                try:
                                    os.symlink(src_file, dest_file)
                                except OSError:
                                    pass

            other_dirs = [
                d for d in os.environ.get("PATH", "").split(":")
                if d and not (Path(d) / "jq").is_file()
            ]
            new_path = f"{fake_bin}:" + ":".join(other_dirs)

            env_override = {
                "PATH": new_path,
                "JAVA_HOME": "",
            }

            code, stdout, stderr = run_install_sh(["--diagnostics"], extra_env=env_override)
            self.assertNotEqual(code, 0, "Missing required tool jq must return non-zero exit code")

            clean_out = re.sub(r"\x1b\[[0-9;]*[mK]", "", stdout + "\n" + stderr).lower()
            self.assertIn("missing required dependencies", clean_out)

            forbidden_keywords = [
                "sudo apt install",
                "brew install",
                "sudo pacman -s",
                "install them with your package manager",
                "debian/ubuntu :",
                "arch linux    :",
                "macos         :",
                "try running",
                "please install",
            ]

            for kw in forbidden_keywords:
                self.assertNotIn(
                    kw,
                    clean_out,
                    f"Violation of R2: Package manager suggestion '{kw}' printed on missing required dependency",
                )

    def test_09_install_sh_outdated_java_warning(self):
        """
        Verify that when Java is older than 8 (e.g. mock Java 1.7.0):
        1. Status is marked 'outdated'
        2. Warning is added
        3. Script does NOT abort (exit code 0)
        """
        with tempfile.TemporaryDirectory() as mock_dir:
            mock_java = Path(mock_dir) / "java"
            mock_java.write_text(
                '#!/bin/bash\necho \'java version "1.7.0_80"\' >&2\necho \'Java(TM) SE Runtime Environment (build 1.7.0_80-b15)\' >&2\n'
            )
            mock_java.chmod(mock_java.stat().st_mode | stat.S_IEXEC)

            # Prepend mock_dir to current PATH
            env_override = {
                "PATH": f"{mock_dir}:{os.environ.get('PATH', '')}",
                "JAVA_HOME": "",
            }

            code, stdout, stderr = run_install_sh(["--diagnostics"], extra_env=env_override)
            self.assertEqual(code, 0, f"Outdated Java must be non-fatal (code 0), got {code}: {stderr}")
            clean_out = re.sub(r"\x1b\[[0-9;]*[mK]", "", stdout)
            self.assertIn("outdated", clean_out)
            self.assertIn("need >= 8", clean_out)

    def test_10_install_sh_jre_vs_jdk_differentiation(self):
        """
        Verify that when Java is present without javac:
        Status indicates 'JRE' instead of 'JDK'.
        """
        with tempfile.TemporaryDirectory() as mock_dir:
            mock_java = Path(mock_dir) / "java"
            mock_java.write_text(
                '#!/bin/bash\necho \'openjdk version "17.0.2" 2022-01-18\' >&2\n'
            )
            mock_java.chmod(mock_java.stat().st_mode | stat.S_IEXEC)

            # Remove JDK dirs from PATH so javac is not found
            clean_path_dirs = [
                d for d in os.environ.get("PATH", "").split(":")
                if d and not (Path(d) / "javac").exists() and "jdk" not in d
            ]

            env_override = {
                "PATH": f"{mock_dir}:" + ":".join(clean_path_dirs),
                "JAVA_HOME": "",
            }

            code, stdout, stderr = run_install_sh(["--diagnostics"], extra_env=env_override)
            self.assertEqual(code, 0, f"Mock JRE check failed: {stderr}")
            clean_out = re.sub(r"\x1b\[[0-9;]*[mK]", "", stdout)
            self.assertIn("JRE", clean_out)

    def test_11_install_sh_apktool_check_optional_and_non_fatal(self):
        """
        Verify that install.sh reports Apktool status:
        - 'Apktool   : OK (v...)' or 'Apktool   : not found (optional)'
        - Non-fatal (exit code 0) even if apktool is missing
        """
        code, stdout, stderr = run_install_sh(["--diagnostics"])
        self.assertEqual(code, 0, f"Diagnostics exited with {code}: {stderr}")
        clean_out = re.sub(r"\x1b\[[0-9;]*[mK]", "", stdout)
        self.assertIn("Apktool", clean_out)
        self.assertTrue("OK" in clean_out or "not found (optional)" in clean_out)

    def test_12_install_sh_strictly_no_package_manager_suggestions_on_missing_apktool(self):
        """
        STRICT REQUIREMENT:
        When apktool is missing from PATH and jar locations:
        - Reports 'not found (optional)'
        - Strictly NO package manager suggestions (apt, dnf, yum, pacman, brew, etc.)
        - Non-fatal (exit code 0)
        """
        clean_path_dirs = [
            d for d in os.environ.get("PATH", "").split(":")
            if d and not (Path(d) / "apktool").exists()
        ]
        env_override = {
            "PATH": ":".join(clean_path_dirs),
            "APKTOOL_PATH": "/nonexistent/apktool",
            "APKTOOL_JAR": "/nonexistent/apktool.jar",
        }
        code, stdout, stderr = run_install_sh(["--diagnostics"], extra_env=env_override)
        self.assertEqual(code, 0, f"Diagnostics must be non-fatal on missing apktool: {stderr}")

        clean_out = re.sub(r"\x1b\[[0-9;]*[mK]", "", stdout)
        self.assertIn("Apktool", clean_out)
        self.assertIn("not found (optional)", clean_out)

        combined = (stdout + "\n" + stderr).lower()
        forbidden_keywords = [
            "sudo apt install",
            "apt install",
            "brew install",
            "pacman -s",
            "dnf install",
            "yum install",
            "try running",
            "please install apktool",
        ]
        for kw in forbidden_keywords:
            self.assertNotIn(kw, combined, f"Forbidden package manager hint '{kw}' found in installer output")

    def test_11_install_sh_execution_via_sh(self):
        """Verify install.sh executes cleanly when invoked via 'sh' (POSIX re-exec to bash)."""
        res = subprocess.run(
            ["sh", str(INSTALL_SH), "--diagnostics"],
            cwd=str(WORKSPACE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, f"sh install.sh --diagnostics failed: {res.stderr}")
        self.assertIn("Environment", res.stdout)
        self.assertIn("Java", res.stdout)

    def test_12_install_sh_execution_via_dash(self):
        """Verify install.sh executes cleanly when invoked via 'dash' if available."""
        if not shutil.which("dash"):
            self.skipTest("dash not installed on host")
        res = subprocess.run(
            ["dash", str(INSTALL_SH), "--diagnostics"],
            cwd=str(WORKSPACE_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, f"dash install.sh --diagnostics failed: {res.stderr}")
        self.assertIn("Environment", res.stdout)
        self.assertIn("Java", res.stdout)

    def test_13_install_sh_java_version_modern_ga_and_update_indicators(self):
        """
        Verify install.sh correctly detects and parses modern Java GA versions (with '+')
        and update indicators ('u') without flagging them as missing or outdated.
        """
        cases = [
            ("21+35", "openjdk version \"21+35\" 2023-09-19 LTS\n"),
            ("17+35-2724", "openjdk version \"17+35-2724\" 2021-09-14\n"),
            ("8u382-b05", "openjdk version \"8u382-b05\" (build 1.8.0_382-b05)\n"),
        ]

        for ver_tag, banner in cases:
            with tempfile.TemporaryDirectory() as mock_dir:
                mock_java = Path(mock_dir) / "java"
                mock_java.write_text(f'#!/bin/bash\necho \'{banner.strip()}\' >&2\n')
                mock_java.chmod(mock_java.stat().st_mode | stat.S_IEXEC)

                env_override = {
                    "PATH": f"{mock_dir}:{os.environ.get('PATH', '')}",
                    "JAVA_HOME": "",
                }

                code, stdout, stderr = run_install_sh(["--diagnostics"], extra_env=env_override)
                self.assertEqual(code, 0, f"Failed for Java version {ver_tag}: {stderr}")
                clean_out = re.sub(r"\x1b\[[0-9;]*[mK]", "", stdout)
                self.assertIn("Java", clean_out)
                self.assertIn("OK", clean_out, f"Expected Java OK for {ver_tag}, got:\n{clean_out}")
                self.assertIn(ver_tag, clean_out, f"Expected version {ver_tag} in output, got:\n{clean_out}")


class TestRvsApkUnpackCli(unittest.TestCase):
    """
    Validation of Requirement R1 and Milestone 2:
    - Autonomous 'rvs apk unpack' CLI command
    - Default/Java mode and '--no-java' pure-Rust fallback mode
    - Structured extraction (manifest, resources, smali/dex, assets)
    - Error handling (missing file, existing dir without --force, corrupt archives)
    """

    def setUp(self):
        self.sample_apk = FIXTURES_DIR / "sample_raw.apk"
        self.multi_dex_apk = FIXTURES_DIR / "sample_multi_dex.apk"
        self.corrupt_apk = FIXTURES_DIR / "corrupt_header.apk"
        self.empty_apk = FIXTURES_DIR / "empty_file.apk"

        self.assertTrue(self.sample_apk.is_file(), f"Fixture missing: {self.sample_apk}")
        self.assertTrue(self.multi_dex_apk.is_file(), f"Fixture missing: {self.multi_dex_apk}")

    def test_01_unpack_cli_help(self):
        """Verify 'rvs apk unpack --help' displays usage, options, and descriptions."""
        code, stdout, stderr, _ = run_rvs_cli(["apk", "unpack", "--help"])
        self.assertEqual(code, 0, f"Help command failed: {stderr}")
        self.assertIn("rvs apk unpack", stdout)
        self.assertIn("--output", stdout)
        self.assertIn("--force", stdout)
        self.assertIn("--no-java", stdout)

    def test_02_unpack_sample_apk_pure_rust_mode(self):
        """
        Verify 'rvs apk unpack <apk> -o <out_dir> --no-java' executes pure-Rust extraction:
        1. Returns exit code 0
        2. Emits JSON summary with engine='rust-native'
        3. Creates structured destination directory
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_rust"
            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0, f"Unpack failed: {stderr}")
            self.assertIsNotNone(json_data, f"Unpack should return JSON: {stdout}")
            self.assertTrue(json_data.get("success"), "Expected success: true")

            data = json_data.get("data", {})
            self.assertEqual(data.get("engine"), "rust-native")
            self.assertTrue(data.get("manifest_extracted"))
            self.assertTrue(data.get("resources_extracted"))
            self.assertTrue(data.get("smali_generated"))

            self.assertTrue(out_dest.is_dir(), "Destination directory was not created")
            self.assertTrue((out_dest / "AndroidManifest.xml").is_file())
            self.assertTrue((out_dest / "res").is_dir())
            self.assertTrue((out_dest / "smali").is_dir())
            self.assertTrue((out_dest / "assets").is_dir())

    def test_03_unpack_sample_apk_default_mode(self):
        """
        Verify 'rvs apk unpack <apk> -o <out_dir>' executes in default mode
        (Java-accelerated if available, or pure-Rust fallback).
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_default"
            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(out_dest)]
            )
            self.assertEqual(code, 0, f"Default unpack failed: {stderr}")
            self.assertIsNotNone(json_data)
            self.assertTrue(json_data.get("success"))

            data = json_data.get("data", {})
            self.assertIn(data.get("engine"), ["java-apktool", "rust-native"])
            self.assertTrue(data.get("manifest_extracted"))
            self.assertTrue(data.get("resources_extracted"))
            self.assertTrue(data.get("smali_generated"))

    def test_04_unpack_structured_manifest_is_readable_xml(self):
        """Verify extracted AndroidManifest.xml is human-readable XML containing package identity."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_manifest"
            code, stdout, stderr, _ = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0)

            manifest_path = out_dest / "AndroidManifest.xml"
            self.assertTrue(manifest_path.is_file(), "AndroidManifest.xml missing from unpack output")
            content = manifest_path.read_text(encoding="utf-8", errors="replace")
            self.assertIn("<manifest", content)
            self.assertIn("eu.jgamba.myapplication", content)

    def test_05_unpack_structured_resources_and_strings(self):
        """Verify res/ directory is extracted and contains valid XML/string values."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_res"
            code, stdout, stderr, _ = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0)

            res_dir = out_dest / "res"
            self.assertTrue(res_dir.is_dir(), "res/ directory missing from unpack output")

            strings_xml = res_dir / "values" / "strings.xml"
            self.assertTrue(strings_xml.is_file(), "res/values/strings.xml missing from unpack output")
            content = strings_xml.read_text(encoding="utf-8", errors="replace")
            self.assertIn("<resources>", content)
            self.assertIn("<string name=", content)
            self.assertIn("</resources>", content)

    def test_06_unpack_structured_smali_directory(self):
        """Verify smali/ directory is extracted and contains disassembled .smali files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_smali"
            code, stdout, stderr, _ = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0)

            smali_dir = out_dest / "smali"
            self.assertTrue(smali_dir.is_dir(), "smali/ directory missing from unpack output")

            smali_files = list(smali_dir.rglob("*.smali"))
            self.assertGreater(len(smali_files), 0, "No .smali files found in smali/ directory")

            # Check that smali file has valid directives (.class, .super, .method)
            first_smali = smali_files[0].read_text(encoding="utf-8", errors="replace")
            self.assertIn(".class", first_smali)

    def test_07_unpack_structured_assets(self):
        """Verify assets/ directory is preserved with original files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_assets"
            code, stdout, stderr, _ = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0)

            assets_dir = out_dest / "assets"
            self.assertTrue(assets_dir.is_dir(), "assets/ directory missing from unpack output")
            self.assertTrue(
                (assets_dir / "app_config.json").is_file(), "assets/app_config.json missing"
            )
            self.assertTrue(
                (assets_dir / "secret_token.txt").is_file(), "assets/secret_token.txt missing"
            )

    def test_08_unpack_multi_dex_apk(self):
        """Verify unpack on multi-DEX APK extracts all classes across DEX files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_multidex"
            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(self.multi_dex_apk), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0, f"Multi-dex unpack failed: {stderr}")
            self.assertTrue(out_dest.is_dir())
            self.assertTrue((out_dest / "smali").is_dir())
            smali_count = len(list(out_dest.rglob("*.smali")))
            self.assertGreater(smali_count, 10, "Expected multiple smali classes in multi-DEX package")

    def test_09_unpack_error_missing_file(self):
        """Verify unpack on non-existent file returns error code 2 (FILE_ERROR) without panic."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "out"
            nonexistent = Path(tmp_dir) / "does_not_exist.apk"
            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(nonexistent), "-o", str(out_dest)]
            )
            self.assertEqual(code, 2, f"Expected FILE_ERROR (2) on missing file, got {code}")
            if json_data:
                self.assertFalse(json_data.get("success"))

    def test_10_unpack_error_existing_dir_without_force(self):
        """Verify unpack targeting an existing non-empty directory without --force fails cleanly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            existing_dir = Path(tmp_dir) / "existing_out"
            existing_dir.mkdir()
            (existing_dir / "canary.txt").write_text("do not overwrite")

            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(existing_dir)]
            )
            self.assertNotEqual(code, 0, "Unpack without --force must not overwrite existing non-empty directory")
            self.assertTrue(
                (existing_dir / "canary.txt").is_file(), "Canary file must remain intact"
            )

    def test_11_unpack_with_force_overwrites_existing_dir(self):
        """Verify unpack targeting an existing directory WITH --force overwrites cleanly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            existing_dir = Path(tmp_dir) / "existing_out"
            existing_dir.mkdir()
            (existing_dir / "old_canary.txt").write_text("old content")

            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(existing_dir), "--force", "--no-java"]
            )
            self.assertEqual(code, 0, f"Unpack with --force failed: {stderr}")
            self.assertTrue((existing_dir / "AndroidManifest.xml").is_file())
            self.assertFalse((existing_dir / "old_canary.txt").exists())

    def test_12_unpack_error_corrupt_archive(self):
        """Verify unpack on corrupt archive terminates gracefully with error, zero panics."""
        if self.corrupt_apk.is_file():
            with tempfile.TemporaryDirectory() as tmp_dir:
                out_dest = Path(tmp_dir) / "corrupt_out"
                code, stdout, stderr, json_data = run_rvs_cli(
                    ["apk", "unpack", str(self.corrupt_apk), "-o", str(out_dest)]
                )
                self.assertNotEqual(code, 0)
                self.assertNotIn("panicked at", stderr + stdout)

    def test_13_unpack_error_empty_file(self):
        """Verify unpack on zero-byte file terminates gracefully with error."""
        if self.empty_apk.is_file():
            with tempfile.TemporaryDirectory() as tmp_dir:
                out_dest = Path(tmp_dir) / "empty_out"
                code, stdout, stderr, json_data = run_rvs_cli(
                    ["apk", "unpack", str(self.empty_apk), "-o", str(out_dest)]
                )
                self.assertNotEqual(code, 0)

    def test_14_unpack_generates_agent_summary_json_and_md(self):
        """
        Automatic Agent Augmentation:
        Verify that unpack automatically generates 'rvs_agent_summary.json' and 'rvs_agent_summary.md'
        containing attack surface, dangerous permissions, class/method metrics, and JNI cross-references.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "unpacked_agent_artifacts"
            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(self.sample_apk), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0, f"Unpack failed: {stderr}")

            # Verify rvs_agent_summary.json exists and is valid
            summary_json_path = out_dest / "rvs_agent_summary.json"
            self.assertTrue(summary_json_path.is_file(), "rvs_agent_summary.json was not generated")
            summary_data = json.loads(summary_json_path.read_text(encoding="utf-8"))

            self.assertIn("package_name", summary_data)
            self.assertIn("total_classes", summary_data)
            self.assertIn("total_methods", summary_data)
            self.assertIn("exported_activities", summary_data)
            self.assertIn("dangerous_permissions", summary_data)
            self.assertIn("jni_cross_references", summary_data)

            # Verify rvs_agent_summary.md exists and has markdown content
            summary_md_path = out_dest / "rvs_agent_summary.md"
            self.assertTrue(summary_md_path.is_file(), "rvs_agent_summary.md was not generated")
            md_text = summary_md_path.read_text(encoding="utf-8")
            self.assertIn("# RVS APK Agent Reconnaissance Summary", md_text)
            self.assertIn("Attack Surface", md_text)
            self.assertIn("JNI Native Method Cross-References", md_text)

            # Verify agent_summary is attached to CLI JSON envelope
            self.assertIsNotNone(json_data)
            data = json_data.get("data", {})
            self.assertIn("agent_summary", data)
            agent_summary = data["agent_summary"]
            self.assertIsNotNone(agent_summary)
            self.assertGreater(agent_summary.get("total_classes", 0), 0)


class TestUnpackedDirectoryIngestionSmali(unittest.TestCase):
    """
    Validation of Requirement R1:
    - Ingestion of unpacked directories containing 'smali/' structure
    - Identification of classes, methods, and language 'Java'
    - Multi-smali support ('smali_classes2/')
    - Direct querying via 'rvs apk inspect' and 'rvs apk dex'
    """

    def test_01_ingest_smali_directory_detects_java_language(self):
        """
        Verify that an unpacked directory with smali/ (and NO .dex file):
        1. Successfully ingests via 'rvs apk inspect <dir>'
        2. Detects 'Java' language with high confidence
        3. Identifies 'smali' in dex_files listing
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            pkg_dir = Path(tmp_dir) / "test_smali_pkg"
            pkg_dir.mkdir()

            # Create mock text manifest
            (pkg_dir / "AndroidManifest.xml").write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="com.example.smalitest">\n<application android:label="TestApp" />\n</manifest>'
            )

            # Create smali hierarchy
            class_dir = pkg_dir / "smali" / "com" / "example"
            class_dir.mkdir(parents=True)
            smali_file = class_dir / "MainActivity.smali"
            smali_file.write_text(
                """.class public Lcom/example/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

# direct methods
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method public calculateScore(I)I
    .registers 3
    const/16 v0, 100
    return v0
.end method
"""
            )

            code, stdout, stderr, json_data = run_rvs_cli(["apk", "inspect", str(pkg_dir)])
            self.assertEqual(code, 0, f"Inspect failed on smali directory: {stderr}")
            self.assertIsNotNone(json_data)
            self.assertTrue(json_data.get("success"))

            data = json_data.get("data", {})
            self.assertEqual(data.get("source_type"), "directory")
            self.assertEqual(data.get("package_name"), "com.example.smalitest")
            self.assertIn("smali", data.get("dex_files", []))

            # Verify Java language detection
            langs = data.get("languages", [])
            lang_names = [l.get("language") for l in langs]
            self.assertIn("Java", lang_names, f"Expected Java language detected from smali, found: {langs}")

    def test_02_ingest_multi_smali_classes2(self):
        """
        Verify ingestion of multi-smali structure:
        - smali/ (com.example.First)
        - smali_classes2/ (com.example.Second)
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            pkg_dir = Path(tmp_dir) / "test_multismali_pkg"
            pkg_dir.mkdir()

            (pkg_dir / "AndroidManifest.xml").write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n<manifest package="com.example.multismali" />'
            )

            # smali 1
            c1_dir = pkg_dir / "smali" / "com" / "example"
            c1_dir.mkdir(parents=True)
            (c1_dir / "First.smali").write_text(
                """.class public Lcom/example/First;
.super Ljava/lang/Object;
.method public run()V
    return-void
.end method
"""
            )

            # smali 2
            c2_dir = pkg_dir / "smali_classes2" / "com" / "example"
            c2_dir.mkdir(parents=True)
            (c2_dir / "Second.smali").write_text(
                """.class public Lcom/example/Second;
.super Ljava/lang/Object;
.method public execute()V
    return-void
.end method
"""
            )

            code, stdout, stderr, json_data = run_rvs_cli(["apk", "inspect", str(pkg_dir)])
            self.assertEqual(code, 0)
            data = json_data.get("data", {})
            dex_files = data.get("dex_files", [])
            self.assertTrue(
                "smali" in dex_files and "smali_classes2" in dex_files,
                f"Expected both smali and smali_classes2 in dex_files: {dex_files}",
            )

    def test_03_rvs_apk_dex_on_smali_directory(self):
        """
        Verify 'rvs apk dex <dir>' on smali-only directory:
        Must query classes and methods without requiring a .dex file.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            pkg_dir = Path(tmp_dir) / "test_dex_smali"
            pkg_dir.mkdir()

            (pkg_dir / "AndroidManifest.xml").write_text(
                '<manifest package="com.example.dexsmali" />'
            )

            c_dir = pkg_dir / "smali" / "com" / "example"
            c_dir.mkdir(parents=True)
            (c_dir / "AuthHelper.smali").write_text(
                """.class public Lcom/example/AuthHelper;
.super Ljava/lang/Object;

.method public static checkPin(Ljava/lang/String;)Z
    .registers 2
    const/4 v0, 1
    return v0
.end method
"""
            )

            code, stdout, stderr, json_data = run_rvs_cli(["apk", "dex", str(pkg_dir), "-c"])
            self.assertEqual(code, 0, f"apk dex failed on smali directory: {stderr}")
            self.assertIsNotNone(json_data)
            self.assertTrue(json_data.get("success"))

            data = json_data.get("data", {})
            self.assertGreaterEqual(data.get("classes", 0), 1)
            self.assertGreaterEqual(data.get("methods", 0), 1)

            class_list = data.get("class_list", [])
            class_names = [c.get("name") for c in class_list]
            self.assertTrue(
                any("AuthHelper" in name for name in class_names),
                f"AuthHelper class not found in class_list: {class_names}",
            )

    def test_04_ingest_empty_smali_directory_graceful(self):
        """Verify an unpacked directory with an empty smali/ directory handles cleanly."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            pkg_dir = Path(tmp_dir) / "empty_smali_pkg"
            pkg_dir.mkdir()
            (pkg_dir / "AndroidManifest.xml").write_text('<manifest package="com.empty" />')
            (pkg_dir / "smali").mkdir()

            code, stdout, stderr, json_data = run_rvs_cli(["apk", "inspect", str(pkg_dir)])
            self.assertEqual(code, 0)
            self.assertIsNotNone(json_data)

    def test_05_ingest_smali_directory_with_non_smali_files(self):
        """Verify non-smali files inside smali/ (.txt, .bak, .DS_Store) are cleanly ignored."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            pkg_dir = Path(tmp_dir) / "mixed_smali_pkg"
            pkg_dir.mkdir()
            (pkg_dir / "AndroidManifest.xml").write_text('<manifest package="com.mixed" />')

            c_dir = pkg_dir / "smali" / "com" / "mixed"
            c_dir.mkdir(parents=True)
            (c_dir / "RealClass.smali").write_text(
                ".class public Lcom/mixed/RealClass;\n.super Ljava/lang/Object;\n"
            )
            # Extraneous files
            (c_dir / "notes.txt").write_text("random notes")
            (c_dir / "backup.smali.bak").write_text("old backup")

            code, stdout, stderr, json_data = run_rvs_cli(["apk", "dex", str(pkg_dir), "-c"])
            self.assertEqual(code, 0)
            data = json_data.get("data", {})
            self.assertEqual(data.get("classes"), 1)


class TestReadmeUserFocusedVerification(unittest.TestCase):
    """
    Validation of Requirement R4 and Milestone 3:
    - Written concisely (< 400 lines)
    - Strictly user-focused: Quick Installation, AI MCP configuration, CLI usage
    - Supported Tooling Catalog listing all 50 canonical tools
    - Strictly ZERO internal architecture / system design explanations
    """

    @classmethod
    def setUpClass(cls):
        cls.assertTrue(README_MD.is_file(), f"README.md not found at {README_MD}")
        cls.content = README_MD.read_text(encoding="utf-8")
        cls.lines = cls.content.splitlines()

    def test_01_readme_no_internal_architecture_sections(self):
        """
        STRICT REQUIREMENT R4:
        Assert README.md contains NO internal architecture sections:
        - '## Architecture'
        - 'Component Breakdown'
        - 'Token Compaction Engine'
        - 'Core Design Principles'
        """
        forbidden_headers = [
            "## Architecture",
            "### Architecture",
            "Component Breakdown",
            "Token Compaction Engine",
            "Core Design Principles",
            "Technical Overview",
        ]

        for section in forbidden_headers:
            self.assertNotIn(
                section,
                self.content,
                f"Violation of R4: Internal architecture section '{section}' found in README.md",
            )

    def test_02_readme_contains_all_50_canonical_tools(self):
        """
        Verify README.md Supported Tooling Catalog documents all 50 canonical tools by name.
        """
        self.assertEqual(len(CANONICAL_TOOLS), 50, "Pre-condition: CANONICAL_TOOLS must have 50 tools")

        missing_tools = []
        for tool in CANONICAL_TOOLS:
            tool_name = tool["name"]
            # Look for tool name enclosed in backticks or as table entry
            if f"`{tool_name}`" not in self.content and tool_name not in self.content:
                missing_tools.append(tool_name)

        self.assertEqual(
            missing_tools,
            [],
            f"README.md is missing documentation for {len(missing_tools)} canonical tools: {missing_tools}",
        )

    def test_03_readme_quick_installation_section(self):
        """Verify README.md contains Quick Installation instructions and AI MCP client configs."""
        self.assertIn("Quick Installation", self.content)
        self.assertIn("./install.sh", self.content)
        self.assertIn("Antigravity", self.content)
        self.assertIn("Claude", self.content)
        self.assertIn("Cursor", self.content)

    def test_04_readme_cli_usage_examples(self):
        """Verify README.md contains CLI usage examples for both ELF and Android APK reversing."""
        self.assertIn("rvs apk inspect", self.content)
        self.assertIn("rvs apk unpack", self.content)
        self.assertIn("--output", self.content)
        self.assertIn("--force", self.content)
        self.assertIn("--no-java", self.content)
        self.assertIn("rvs apk manifest", self.content)
        self.assertIn("rvs apk dex", self.content)

    def test_05_readme_exit_code_taxonomy(self):
        """Verify README.md documents the exit code taxonomy (Codes 0 through 6)."""
        self.assertIn("Exit Code", self.content)
        self.assertIn("SUCCESS", self.content)
        self.assertIn("FILE_ERROR", self.content)

    def test_06_readme_concise_length(self):
        """Verify README.md is concise (strictly under 400 lines)."""
        line_count = len(self.lines)
        self.assertLess(
            line_count,
            400,
            f"README.md must be concise (< 400 lines), but has {line_count} lines",
        )


class TestCrossFeatureWorkflows(unittest.TestCase):
    """
    Tier 3 / Tier 4 Cross-Feature Integration:
    - Roundtrip: Unpack APK -> Ingest Unpacked Directory -> Query Components
    - Pure-Rust vs Java Mode Parity
    - Diagnostics -> CLI Execution Workflow
    """

    def test_01_unpack_then_reinspect_roundtrip(self):
        """
        Full roundtrip verification:
        1. 'rvs apk unpack <sample_apk> -o <dir> --no-java'
        2. 'rvs apk inspect <dir>'
        3. 'rvs apk manifest <dir>'
        4. 'rvs apk dex <dir>'
        5. 'rvs apk resources <dir>'
        All commands must succeed and match original package characteristics.
        """
        sample_apk = FIXTURES_DIR / "sample_raw.apk"
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "roundtrip_out"

            # 1. Unpack
            code, _, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(sample_apk), "-o", str(out_dir), "--no-java"]
            )
            self.assertEqual(code, 0, f"Unpack step failed: {stderr}")

            # 2. Inspect
            code, _, stderr, insp_data = run_rvs_cli(["apk", "inspect", str(out_dir)])
            self.assertEqual(code, 0, f"Inspect on unpacked dir failed: {stderr}")
            self.assertEqual(
                insp_data.get("data", {}).get("package_name"), "eu.jgamba.myapplication"
            )

            # 3. Manifest
            code, _, stderr, man_data = run_rvs_cli(["apk", "manifest", str(out_dir), "-c"])
            self.assertEqual(code, 0, f"Manifest on unpacked dir failed: {stderr}")
            self.assertEqual(
                man_data.get("data", {}).get("pkg"), "eu.jgamba.myapplication"
            )

            # 4. Dex
            code, _, stderr, dex_data = run_rvs_cli(["apk", "dex", str(out_dir), "-c"])
            self.assertEqual(code, 0, f"Dex on unpacked dir failed: {stderr}")
            self.assertGreater(dex_data.get("data", {}).get("classes", 0), 0)

            # 5. Resources
            code, _, stderr, res_data = run_rvs_cli(["apk", "resources", str(out_dir), "-c"])
            self.assertEqual(code, 0, f"Resources on unpacked dir failed: {stderr}")

    def test_02_pure_rust_vs_java_parity(self):
        """Verify pure-Rust mode and default mode both extract readable manifest and resources."""
        sample_apk = FIXTURES_DIR / "sample_raw.apk"
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_rust = Path(tmp_dir) / "rust_mode"
            out_java = Path(tmp_dir) / "java_mode"

            code1, _, _, _ = run_rvs_cli(
                ["apk", "unpack", str(sample_apk), "-o", str(out_rust), "--no-java"]
            )
            code2, _, _, _ = run_rvs_cli(
                ["apk", "unpack", str(sample_apk), "-o", str(out_java)]
            )

            self.assertEqual(code1, 0)
            self.assertEqual(code2, 0)

            self.assertTrue((out_rust / "AndroidManifest.xml").is_file())
            self.assertTrue((out_java / "AndroidManifest.xml").is_file())

            self.assertTrue((out_rust / "res").is_dir())
            self.assertTrue((out_java / "res").is_dir())

    def test_03_diagnostics_and_cli_pipeline(self):
        """Verify running install diagnostics followed by APK unpack in sequence."""
        code, stdout, stderr = run_install_sh(["--diagnostics"])
        self.assertEqual(code, 0)

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dest = Path(tmp_dir) / "pipeline_out"
            code, stdout, stderr, json_data = run_rvs_cli(
                ["apk", "unpack", str(FIXTURES_DIR / "sample_raw.apk"), "-o", str(out_dest), "--no-java"]
            )
            self.assertEqual(code, 0)
            self.assertTrue(json_data.get("success"))


if __name__ == "__main__":
    unittest.main()
