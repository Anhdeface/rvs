#!/usr/bin/env python3
"""
Test fixture generation script for rvs Android and AArch64 upgrades.
Generates:
1. sample_aarch64_lib.so & sample_aarch64_stripped.so
2. sample_manifest.axml & sample_unpacked_dir/
3. sample_classes.dex
4. sample_raw.apk & sample_multi_dex.apk & sample_no_so.apk
5. Corrupted / adversarial fixtures
"""

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent

def compile_aarch64():
    rs_source = FIXTURES_DIR / "sample_aarch64_lib.rs"
    out_so = FIXTURES_DIR / "sample_aarch64_lib.so"
    out_stripped = FIXTURES_DIR / "sample_aarch64_stripped.so"

    print(f"[*] Compiling {rs_source} to {out_so}...")
    subprocess.run([
        "rustc",
        "--target", "aarch64-unknown-linux-gnu",
        "-C", "panic=abort",
        "-C", "linker=rust-lld",
        "--crate-type", "cdylib",
        str(rs_source),
        "-o", str(out_so)
    ], check=True)

    print(f"[*] Compiling stripped {out_stripped}...")
    subprocess.run([
        "rustc",
        "--target", "aarch64-unknown-linux-gnu",
        "-C", "panic=abort",
        "-C", "linker=rust-lld",
        "-C", "strip=symbols",
        "--crate-type", "cdylib",
        str(rs_source),
        "-o", str(out_stripped)
    ], check=True)

def setup_dex():
    dex_source = Path("/home/quanh/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/dex-0.5.0/resources/classes.dex")
    target_dex = FIXTURES_DIR / "sample_classes.dex"
    print(f"[*] Copying {dex_source} to {target_dex}...")
    shutil.copyfile(dex_source, target_dex)

def setup_manifest():
    app_apk = Path("/home/quanh/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rusty-axml-0.2.1/tests/assets/app.apk")
    target_axml = FIXTURES_DIR / "sample_manifest.axml"
    print(f"[*] Extracting binary AndroidManifest.xml to {target_axml}...")
    with zipfile.ZipFile(app_apk, 'r') as z:
        with open(target_axml, 'wb') as f:
            f.write(z.read("AndroidManifest.xml"))

def setup_unpacked_dirs():
    # 1. Plain text XML unpacked dir
    unpacked_dir = FIXTURES_DIR / "sample_unpacked_dir"
    unpacked_dir.mkdir(parents=True, exist_ok=True)
    manifest_xml = unpacked_dir / "AndroidManifest.xml"
    manifest_xml.write_text("""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.unpacked"
    android:versionCode="42"
    android:versionName="2.1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <application
        android:debuggable="true"
        android:label="UnpackedApp">
        <activity android:name="com.example.unpacked.MainActivity" />
        <activity android:name="com.example.unpacked.DetailActivity" />
        <service android:name="com.example.unpacked.SyncService" />
        <receiver android:name="com.example.unpacked.BootReceiver" />
        <provider android:name="com.example.unpacked.DataProvider" />
    </application>
</manifest>
""")

    shutil.copyfile(FIXTURES_DIR / "sample_classes.dex", unpacked_dir / "classes.dex")
    lib_abi_dir = unpacked_dir / "lib" / "arm64-v8a"
    lib_abi_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES_DIR / "sample_aarch64_lib.so", lib_abi_dir / "libnative.so")

    # 2. Binary AXML unpacked dir
    unpacked_axml_dir = FIXTURES_DIR / "sample_unpacked_axml_dir"
    unpacked_axml_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES_DIR / "sample_manifest.axml", unpacked_axml_dir / "AndroidManifest.xml")
    shutil.copyfile(FIXTURES_DIR / "sample_classes.dex", unpacked_axml_dir / "classes.dex")
    lib_abi_dir2 = unpacked_axml_dir / "lib" / "arm64-v8a"
    lib_abi_dir2.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES_DIR / "sample_aarch64_lib.so", lib_abi_dir2 / "libnative.so")

def setup_apk_archives():
    # 1. sample_raw.apk (Full valid APK with binary AXML, DEX, and arm64-v8a .so)
    raw_apk = FIXTURES_DIR / "sample_raw.apk"
    print(f"[*] Building {raw_apk}...")
    with zipfile.ZipFile(raw_apk, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.write(FIXTURES_DIR / "sample_manifest.axml", "AndroidManifest.xml")
        z.write(FIXTURES_DIR / "sample_classes.dex", "classes.dex")
        z.write(FIXTURES_DIR / "sample_aarch64_lib.so", "lib/arm64-v8a/libnative.so")
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: rvs-test-suite\n")
        z.writestr("assets/app_config.json", '{"environment": "production", "debug": false}')

    # 2. sample_no_so.apk (APK with DEX but no native libs)
    no_so_apk = FIXTURES_DIR / "sample_no_so.apk"
    print(f"[*] Building {no_so_apk}...")
    with zipfile.ZipFile(no_so_apk, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.write(FIXTURES_DIR / "sample_manifest.axml", "AndroidManifest.xml")
        z.write(FIXTURES_DIR / "sample_classes.dex", "classes.dex")

    # 3. sample_multi_dex.apk (APK with multiple DEX files)
    multi_dex_apk = FIXTURES_DIR / "sample_multi_dex.apk"
    print(f"[*] Building {multi_dex_apk}...")
    with zipfile.ZipFile(multi_dex_apk, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.write(FIXTURES_DIR / "sample_manifest.axml", "AndroidManifest.xml")
        z.write(FIXTURES_DIR / "sample_classes.dex", "classes.dex")
        z.write(FIXTURES_DIR / "sample_classes.dex", "classes2.dex")
        z.write(FIXTURES_DIR / "sample_aarch64_lib.so", "lib/arm64-v8a/libnative.so")

def setup_adversarial_fixtures():
    print("[*] Creating adversarial and boundary fixtures...")
    # Empty 0-byte file
    (FIXTURES_DIR / "empty_file.apk").write_bytes(b"")
    # Corrupt zip (header truncated / random noise)
    (FIXTURES_DIR / "corrupt_header.apk").write_bytes(b"PK\x03\x04\x00\x00corrupted_zip_bytes_random_junk_1234567890")
    # Corrupt AXML (bad magic)
    (FIXTURES_DIR / "corrupt_manifest.axml").write_bytes(b"\x00\x00\x00\x00\xff\xff\xff\xff_invalid_axml_chunk_header")
    # Corrupt DEX (bad magic)
    (FIXTURES_DIR / "corrupt_classes.dex").write_bytes(b"dex\n999\x00_invalid_dex_header_and_checksum_payload_bytes")
    # Directory with no manifest or dex
    empty_dir = FIXTURES_DIR / "empty_dir"
    empty_dir.mkdir(parents=True, exist_ok=True)
    # Directory with corrupt manifest
    bad_manifest_dir = FIXTURES_DIR / "corrupt_manifest_dir"
    bad_manifest_dir.mkdir(parents=True, exist_ok=True)
    (bad_manifest_dir / "AndroidManifest.xml").write_bytes(b"<invalid xml < unclosed tag")

if __name__ == "__main__":
    compile_aarch64()
    setup_dex()
    setup_manifest()
    setup_unpacked_dirs()
    setup_apk_archives()
    setup_adversarial_fixtures()
    print("[+] All fixtures created successfully in", FIXTURES_DIR)
