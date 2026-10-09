"""
tests/fixtures_builder.py - Pure-Python Synthetic Fixture Generator for Binary Orchestration.

Provides:
1. Pure-Python minimal valid Dalvik DEX synthesizer (`synthesize_dex_bytes`, `create_synthetic_dex`).
   Produces spec-compliant Dalvik DEX (version 035) with valid Adler32 checksums, SHA-1 signatures,
   string tables, and map lists without external Android SDK or build tools.
2. Pure-Python multi-ABI, multidex APK fixture builder (`create_synthetic_apk`).
   Packages compiled ELF binaries from `tests/fixtures/*_elf64` into valid APK zip containers
   with `classes.dex`, `classes2.dex`, `lib/x86_64/libauth.so`, `lib/arm64-v8a/libauth.so`.
3. Boundary & adversarial fixture generators (`create_corrupted_apk`, `create_zero_byte_target`).
4. Embedded `unittest.TestCase` suite guaranteeing testability and regression safety.
"""

from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Union

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _encode_uleb128(val: int) -> bytes:
    """Encode an integer as Dalvik unsigned LEB128."""
    result = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val > 0:
            result.append(b | 0x80)
        else:
            result.append(b)
            break
    return bytes(result)


def synthesize_dex_bytes(
    strings: Optional[List[str]] = None,
    version: str = "035",
) -> bytes:
    """
    Synthesizes a minimal valid Dalvik DEX bytecode file in pure Python.
    
    Adheres to the Dalvik Executable format specification:
    - 112-byte (0x70) Header
    - Magic: 'dex\\n' + version (3 ASCII digits) + '\\0'
    - Adler32 checksum at offset 0x08
    - SHA-1 signature at offset 0x0C
    - Valid endian tag (0x12345678)
    - String ID table and String Data table (if strings provided)
    - Map List table at end of file
    """
    if strings is None:
        strings = ["Lcom/example/synthetic/EntryPoint;", "synthetic_main"]

    # Deduplicate and sort strings per DEX spec
    unique_strings = sorted(list(set(strings)))
    
    header_size = 0x70
    string_ids_size = len(unique_strings)
    string_ids_off = header_size

    # Build string data items
    string_data_bytes = bytearray()
    string_data_offsets: List[int] = []
    current_data_off = string_ids_off + (string_ids_size * 4)

    for s in unique_strings:
        s_bytes = s.encode("utf-8")
        encoded = _encode_uleb128(len(s)) + s_bytes + b"\x00"
        string_data_offsets.append(current_data_off + len(string_data_bytes))
        string_data_bytes += encoded

    # Pad string data to 4-byte boundary
    while len(string_data_bytes) % 4 != 0:
        string_data_bytes += b"\x00"

    map_off = current_data_off + len(string_data_bytes)

    # Build Map List
    map_items = [
        (0x0000, 1, 0),                            # TYPE_HEADER_ITEM
        (0x0001, string_ids_size, string_ids_off), # TYPE_STRING_ID_ITEM
        (0x2002, string_ids_size, current_data_off), # TYPE_STRING_DATA_ITEM
        (0x1000, 1, map_off),                      # TYPE_MAP_LIST
    ]

    map_data = bytearray()
    map_data += struct.pack("<I", len(map_items))
    for itype, isize, ioff in map_items:
        map_data += struct.pack("<HHII", itype, 0, isize, ioff)

    file_size = map_off + len(map_data)

    # Construct Header (112 bytes)
    header = bytearray(header_size)
    # Magic bytes (8 bytes)
    magic = f"dex\n{version}\x00".encode("ascii")
    header[0:8] = magic
    # file_size
    struct.pack_into("<I", header, 0x20, file_size)
    # header_size
    struct.pack_into("<I", header, 0x24, header_size)
    # endian_tag (0x12345678)
    struct.pack_into("<I", header, 0x28, 0x12345678)
    # map_off
    struct.pack_into("<I", header, 0x34, map_off)
    # string_ids_size & string_ids_off
    struct.pack_into("<I", header, 0x38, string_ids_size)
    struct.pack_into("<I", header, 0x3C, string_ids_off)

    # Construct string_ids table (array of uint32 offsets)
    string_ids_table = bytearray()
    for soff in string_data_offsets:
        string_ids_table += struct.pack("<I", soff)

    full_payload = bytearray(header + string_ids_table + string_data_bytes + map_data)

    # Compute SHA-1 signature (bytes 32 to EOF)
    sha1 = hashlib.sha1(bytes(full_payload[32:])).digest()
    full_payload[12:32] = sha1

    # Compute Adler-32 checksum (bytes 12 to EOF)
    adler = zlib.adler32(bytes(full_payload[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", full_payload, 8, adler)

    return bytes(full_payload)


def create_synthetic_dex(
    output_path: Union[str, Path],
    strings: Optional[List[str]] = None,
    version: str = "035",
) -> Path:
    """Writes a synthesized minimal Dalvik DEX file to output_path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    dex_bytes = synthesize_dex_bytes(strings=strings, version=version)
    out.write_bytes(dex_bytes)
    return out


def create_synthetic_apk(
    output_path: Union[str, Path],
    elf_fixtures: Optional[Dict[str, Union[str, Path, bytes]]] = None,
    multidex: bool = True,
    dex_strings_map: Optional[Dict[str, List[str]]] = None,
    include_manifest: bool = True,
) -> Path:
    """
    Creates a valid synthetic Android APK package archive with multi-ABI native libraries
    and Dalvik DEX bytecode components.
    
    Default layout:
    - AndroidManifest.xml
    - META-INF/MANIFEST.MF
    - classes.dex (valid Dalvik DEX)
    - classes2.dex (if multidex is True)
    - lib/x86_64/libauth.so (copied from tests/fixtures/auth_gate_elf64)
    - lib/arm64-v8a/libauth.so (copied from tests/fixtures/auth_gate_elf64 or custom)
    - lib/x86_64/libflow.so (copied from tests/fixtures/flow_calc_elf64)
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if dex_strings_map is None:
        dex_strings_map = {
            "classes.dex": [
                "Lcom/example/auth/AuthActivity;",
                "check_master_password",
                "AUTH_TOKEN_ACTIVE",
            ],
            "classes2.dex": [
                "Lcom/example/flow/FlowCalculator;",
                "calc_dispatch",
                "calc_collatz_steps",
            ],
        }

    # Resolve default ELF fixtures from tests/fixtures if not supplied
    if elf_fixtures is None:
        auth_elf = FIXTURES_DIR / "auth_gate_elf64"
        flow_elf = FIXTURES_DIR / "flow_calc_elf64"
        
        # Verify fallback fixtures exist
        auth_bytes = auth_elf.read_bytes() if auth_elf.exists() else b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
        flow_bytes = flow_elf.read_bytes() if flow_elf.exists() else b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56

        elf_fixtures = {
            "lib/x86_64/libauth.so": auth_bytes,
            "lib/arm64-v8a/libauth.so": auth_bytes,
            "lib/x86_64/libflow.so": flow_bytes,
        }

    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 1. AndroidManifest.xml
        if include_manifest:
            manifest_xml = (
                b'<?xml version="1.0" encoding="utf-8"?>\n'
                b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
                b'    package="com.example.synthetic.target"\n'
                b'    android:versionCode="1"\n'
                b'    android:versionName="1.0">\n'
                b'    <application android:hasCode="true" android:label="SyntheticTarget">\n'
                b'        <activity android:name=".MainActivity"/>\n'
                b'    </application>\n'
                b'</manifest>\n'
            )
            zf.writestr("AndroidManifest.xml", manifest_xml)

        # 2. META-INF/MANIFEST.MF
        manifest_mf = (
            b"Manifest-Version: 1.0\n"
            b"Created-By: 1.0 (Synthetic APK Fixture Builder)\n"
        )
        zf.writestr("META-INF/MANIFEST.MF", manifest_mf)

        # 3. classes.dex
        dex1_strings = dex_strings_map.get("classes.dex", ["Lcom/example/Main;"])
        dex1_bytes = synthesize_dex_bytes(strings=dex1_strings)
        zf.writestr("classes.dex", dex1_bytes)

        # 4. classes2.dex (if multidex)
        if multidex:
            dex2_strings = dex_strings_map.get("classes2.dex", ["Lcom/example/Secondary;"])
            dex2_bytes = synthesize_dex_bytes(strings=dex2_strings)
            zf.writestr("classes2.dex", dex2_bytes)

        # 5. Native libraries (ELF .so files)
        for archive_path, content in elf_fixtures.items():
            if isinstance(content, (str, Path)):
                content_bytes = Path(content).read_bytes()
            elif isinstance(content, bytes):
                content_bytes = content
            else:
                raise TypeError(f"Invalid fixture content type for {archive_path}: {type(content)}")
            zf.writestr(archive_path, content_bytes)

    return out


def create_corrupted_apk(
    output_path: Union[str, Path],
    corruption_type: str = "bad_zip",
) -> Path:
    """
    Creates an intentionally corrupted APK/ZIP container for boundary and error handling tests.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if corruption_type == "bad_zip":
        # ZIP magic with random invalid bytes
        out.write_bytes(b"PK\x03\x04\x00\x00\x00\x00\xde\xad\xbe\xef\x00\x00\x00\x00corrupted_payload")
    elif corruption_type == "truncated":
        # Truncated in the middle of local header
        out.write_bytes(b"PK\x03\x04\x14\x00\x00\x00\x08\x00")
    else:
        out.write_bytes(b"\x00\xff\x00\xffNOT_A_ZIP_HEADER")
    return out


def create_zero_byte_target(output_path: Union[str, Path]) -> Path:
    """Creates a zero-byte file for boundary testing."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"")
    return out


# =============================================================================
# Self-Verification Test Suite
# =============================================================================

class TestFixturesBuilder(unittest.TestCase):
    """
    Unit tests ensuring the synthetic DEX and APK builders produce valid structures
    and satisfy all contractual specifications.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_synthesize_dex_magic_and_header(self) -> None:
        """Validates that synthesized DEX begins with 'dex\\n035\\x00' and has 112-byte header."""
        dex_bytes = synthesize_dex_bytes()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))
        self.assertGreaterEqual(len(dex_bytes), 112)
        
        # Verify header_size at 0x24 is 112 (0x70)
        header_size = struct.unpack_from("<I", dex_bytes, 0x24)[0]
        self.assertEqual(header_size, 0x70)

        # Verify endian tag at 0x28 is 0x12345678
        endian_tag = struct.unpack_from("<I", dex_bytes, 0x28)[0]
        self.assertEqual(endian_tag, 0x12345678)

        # Verify file size matches actual length
        file_size = struct.unpack_from("<I", dex_bytes, 0x20)[0]
        self.assertEqual(file_size, len(dex_bytes))

    def test_synthesize_dex_checksum_and_signature(self) -> None:
        """Validates Adler32 checksum and SHA-1 signature calculations."""
        dex_bytes = synthesize_dex_bytes(strings=["Lcom/test/Auth;", "validate_token"])
        
        # SHA-1 verification (offset 32 to end)
        expected_sha1 = hashlib.sha1(dex_bytes[32:]).digest()
        actual_sha1 = dex_bytes[12:32]
        self.assertEqual(actual_sha1, expected_sha1)

        # Adler32 verification (offset 12 to end)
        expected_adler = zlib.adler32(dex_bytes[12:]) & 0xFFFFFFFF
        actual_adler = struct.unpack_from("<I", dex_bytes, 8)[0]
        self.assertEqual(actual_adler, expected_adler)

    def test_synthesize_dex_string_preservation(self) -> None:
        """Validates strings are encoded within the synthetic DEX."""
        target_strings = ["Lcom/example/Gate;", "super_secret_func", "TOKEN_XYZ"]
        dex_bytes = synthesize_dex_bytes(strings=target_strings)
        for s in target_strings:
            self.assertIn(s.encode("utf-8"), dex_bytes)

    def test_create_synthetic_dex_file(self) -> None:
        """Validates file-based DEX generation."""
        dex_path = self.tmp / "test.dex"
        res = create_synthetic_dex(dex_path, strings=["Lcom/file/Test;"])
        self.assertTrue(res.exists())
        self.assertEqual(res, dex_path)
        data = dex_path.read_bytes()
        self.assertTrue(data.startswith(b"dex\n035\x00"))

    def test_create_synthetic_apk_multidex_and_multiabi(self) -> None:
        """Validates synthetic APK packages both multidex and multi-ABI libraries."""
        apk_path = self.tmp / "sample.apk"
        create_synthetic_apk(apk_path, multidex=True)
        
        self.assertTrue(apk_path.exists())
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("AndroidManifest.xml", namelist)
            self.assertIn("classes.dex", namelist)
            self.assertIn("classes2.dex", namelist)
            self.assertIn("lib/x86_64/libauth.so", namelist)
            self.assertIn("lib/arm64-v8a/libauth.so", namelist)
            self.assertIn("lib/x86_64/libflow.so", namelist)

            # Check that extracted classes.dex is valid DEX
            classes_dex = zf.read("classes.dex")
            self.assertTrue(classes_dex.startswith(b"dex\n035\x00"))

            # Check that extracted libauth.so is valid ELF
            auth_so = zf.read("lib/x86_64/libauth.so")
            self.assertTrue(auth_so.startswith(b"\x7fELF"))

    def test_create_corrupted_apk(self) -> None:
        """Validates corrupted APK generation produces unparseable zip."""
        corrupt_path = self.tmp / "corrupt.apk"
        create_corrupted_apk(corrupt_path, corruption_type="bad_zip")
        self.assertTrue(corrupt_path.exists())
        with self.assertRaises(zipfile.BadZipFile):
            with zipfile.ZipFile(corrupt_path, "r") as zf:
                zf.testzip()

    def test_create_zero_byte_target(self) -> None:
        """Validates zero-byte target utility."""
        zero_path = self.tmp / "empty.bin"
        create_zero_byte_target(zero_path)
        self.assertTrue(zero_path.exists())
        self.assertEqual(zero_path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
