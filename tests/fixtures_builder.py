"""
tests/fixtures_builder.py - Pure-Python Synthetic Fixture Generator for Binary Orchestration.

Provides:
1. Pure-Python minimal valid Dalvik DEX synthesizer (`synthesize_dex_bytes`, `create_synthetic_dex`).
   Produces spec-compliant Dalvik DEX (version 035) with valid Adler32 checksums, SHA-1 signatures,
   string tables, and map lists without external Android SDK or build tools.
2. Pure-Python minimal valid ELF shared object synthesizer (`synthesize_elf_bytes`).
   Produces spec-compliant ELF32/ELF64 binaries parseable by goblin, supporting AArch64 (arm64),
   x86_64, ARM (armeabi-v7a), and x86, with dynamic tags (DT_SONAME, DT_NEEDED, DT_STRTAB, DT_SYMTAB),
   static JNI functions, symbols, and RegisterNatives detection.
3. Turnkey multi-language mock APK fixture generators:
   - `create_synthetic_apk`: Multi-ABI multidex generic APK.
   - `create_synthetic_react_native_apk`: React Native framework APK.
   - `create_synthetic_flutter_apk`: Flutter / Dart framework APK.
   - `create_synthetic_native_cpp_apk`: C/C++ native library APK.
   - `create_synthetic_java_only_apk`: Pure Java APK with zero native libraries.
   - `create_synthetic_hybrid_apk`: Hybrid multi-framework APK.
4. Boundary & adversarial fixture generators (`create_corrupted_apk`, `create_zero_byte_target`).
5. Embedded `unittest.TestCase` suite guaranteeing testability and regression safety.
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
from typing import Dict, List, Optional, Tuple, Union

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
        (0x0000, 1, 0),                              # TYPE_HEADER_ITEM
        (0x0001, string_ids_size, string_ids_off),   # TYPE_STRING_ID_ITEM
        (0x2002, string_ids_size, current_data_off), # TYPE_STRING_DATA_ITEM
        (0x1000, 1, map_off),                        # TYPE_MAP_LIST
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


def synthesize_elf_bytes(
    arch: str = "arm64",  # "arm64", "x86_64", "arm", "x86"
    soname: Optional[str] = None,
    needed: Optional[List[str]] = None,
    exports: Optional[List[Tuple[str, int, int]]] = None,  # (name, vaddr, size)
    imports: Optional[List[str]] = None,
    has_register_natives: bool = False,
) -> bytes:
    """
    Synthesizes a minimal valid ELF shared object (.so) in pure Python.

    Adheres to the ELF32 and ELF64 specifications:
    - Supports arm64 (AArch64, EM_AARCH64=183), x86_64 (EM_X86_64=62),
      arm (ARM, EM_ARM=40), and x86 (i386, EM_386=3).
    - Identity-mapped virtual addresses (p_vaddr == p_offset) allowing Goblin
      to translate string table and symbol table virtual addresses without boundary errors.
    - Program headers: PT_LOAD covering all contents and PT_DYNAMIC referencing the dynamic segment.
    - Dynamic section: DT_SONAME, DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_NULL.
    - Static and dynamic symbol tables (.symtab and .dynsym) with demanglable JNI exports.
    """
    if needed is None:
        needed = ["libc.so", "libm.so"]
    if exports is None:
        exports = [("Java_com_example_MainActivity_stringFromJNI", 0x1000, 32)]
    if imports is None:
        imports = ["__android_log_print"]
    if soname is None:
        soname = f"lib{arch}.so"

    if has_register_natives:
        if "RegisterNatives" not in imports:
            imports.append("RegisterNatives")

    is_64 = arch in ("arm64", "x86_64")
    machine_map = {
        "arm64": 0xB7,   # EM_AARCH64 (183)
        "x86_64": 0x3E,  # EM_X86_64 (62)
        "arm": 40,       # EM_ARM (40)
        "x86": 3,        # EM_386 (3)
    }
    if arch not in machine_map:
        raise ValueError(f"Unsupported architecture for ELF synthesis: {arch}")
    e_machine = machine_map[arch]

    # 1. Build .dynstr table
    dynstr = bytearray(b"\x00")
    soname_off = len(dynstr)
    dynstr.extend(soname.encode("utf-8") + b"\x00")

    needed_offs: List[int] = []
    for n in needed:
        needed_offs.append(len(dynstr))
        dynstr.extend(n.encode("utf-8") + b"\x00")

    export_sym_info: List[Tuple[int, int, int]] = []
    for name, addr, sz in exports:
        export_sym_info.append((len(dynstr), addr, sz))
        dynstr.extend(name.encode("utf-8") + b"\x00")

    import_sym_info: List[int] = []
    for name in imports:
        import_sym_info.append(len(dynstr))
        dynstr.extend(name.encode("utf-8") + b"\x00")

    # 2. Build .dynsym table
    sym_size = 24 if is_64 else 16
    dynsym = bytearray(sym_size)  # Symbol 0: NULL symbol

    # Imports: st_shndx = 0 (SHN_UNDEF), binding=GLOBAL, type=FUNC
    for str_off in import_sym_info:
        if is_64:
            dynsym.extend(struct.pack("<IBBHQQ", str_off, 0x12, 0, 0, 0, 0))
        else:
            dynsym.extend(struct.pack("<IIIBBH", str_off, 0, 0, 0x12, 0, 0))

    # Exports: st_shndx = 1 (.text), binding=GLOBAL, type=FUNC
    for str_off, addr, sz in export_sym_info:
        if is_64:
            dynsym.extend(struct.pack("<IBBHQQ", str_off, 0x12, 0, 1, addr, sz))
        else:
            dynsym.extend(struct.pack("<IIIBBH", str_off, addr, sz, 0x12, 0, 1))

    # Static tables mirror dynamic tables for full symbol resolution
    strtab = bytearray(dynstr)
    symtab = bytearray(dynsym)

    # Executable code stub
    text_bytes = bytearray(b"\x00" * 32)
    if has_register_natives:
        text_bytes.extend(b"RegisterNatives\x00")

    # Layout calculation
    ehdr_size = 64 if is_64 else 52
    phentsize = 56 if is_64 else 32
    align = 16 if is_64 else 8
    phnum = 2

    phoff = ehdr_size
    cur_off = phoff + (phnum * phentsize)
    if cur_off % align != 0:
        cur_off += (align - (cur_off % align))

    text_off = cur_off
    text_addr = cur_off
    text_size = len(text_bytes)
    cur_off += text_size

    dynsym_off = cur_off
    dynsym_addr = cur_off
    dynsym_size = len(dynsym)
    cur_off += dynsym_size

    dynstr_off = cur_off
    dynstr_addr = cur_off
    dynstr_size = len(dynstr)
    cur_off += dynstr_size

    # .dynamic section
    dynamic_off = cur_off
    dynamic_addr = cur_off
    dynamic = bytearray()
    dyn_fmt = "<QQ" if is_64 else "<II"
    if soname:
        dynamic.extend(struct.pack(dyn_fmt, 14, soname_off))  # DT_SONAME
    for noff in needed_offs:
        dynamic.extend(struct.pack(dyn_fmt, 1, noff))         # DT_NEEDED
    dynamic.extend(struct.pack(dyn_fmt, 5, dynstr_addr))      # DT_STRTAB
    dynamic.extend(struct.pack(dyn_fmt, 6, dynsym_addr))      # DT_SYMTAB
    dynamic.extend(struct.pack(dyn_fmt, 10, dynstr_size))     # DT_STRSZ
    dynamic.extend(struct.pack(dyn_fmt, 11, sym_size))        # DT_SYMENT
    dynamic.extend(struct.pack(dyn_fmt, 0, 0))                # DT_NULL
    dynamic_size = len(dynamic)
    cur_off += dynamic_size

    # .shstrtab section
    shstrtab = bytearray(b"\x00")
    def add_shstr(name: str) -> int:
        off = len(shstrtab)
        shstrtab.extend(name.encode("ascii") + b"\x00")
        return off

    text_shname = add_shstr(".text")
    dynsym_shname = add_shstr(".dynsym")
    dynstr_shname = add_shstr(".dynstr")
    dynamic_shname = add_shstr(".dynamic")
    shstrtab_shname = add_shstr(".shstrtab")
    symtab_shname = add_shstr(".symtab")
    strtab_shname = add_shstr(".strtab")

    shstrtab_off = cur_off
    shstrtab_size = len(shstrtab)
    cur_off += shstrtab_size

    symtab_off = cur_off
    symtab_size = len(symtab)
    cur_off += symtab_size

    strtab_off = cur_off
    strtab_size = len(strtab)
    cur_off += strtab_size

    sh_align = 8 if is_64 else 4
    if cur_off % sh_align != 0:
        cur_off += (sh_align - (cur_off % sh_align))
    shoff = cur_off

    # Program Headers: PT_LOAD (type 1) and PT_DYNAMIC (type 2)
    phdrs = bytearray()
    if is_64:
        # PT_LOAD: type=1, flags=7 (RWX), offset=0, vaddr=0, paddr=0, filesz=cur_off, memsz=cur_off, align=0x1000
        phdrs.extend(struct.pack("<IIQQQQQQ", 1, 7, 0, 0, 0, cur_off, cur_off, 0x1000))
        # PT_DYNAMIC: type=2, flags=6 (RW), offset=dynamic_off, vaddr=dynamic_addr, paddr=dynamic_addr, filesz=dynamic_size, memsz=dynamic_size, align=8
        phdrs.extend(struct.pack("<IIQQQQQQ", 2, 6, dynamic_off, dynamic_addr, dynamic_addr, dynamic_size, dynamic_size, 8))
    else:
        # PT_LOAD: type=1, offset=0, vaddr=0, paddr=0, filesz=cur_off, memsz=cur_off, flags=7, align=0x1000
        phdrs.extend(struct.pack("<IIIIIIII", 1, 0, 0, 0, cur_off, cur_off, 7, 0x1000))
        # PT_DYNAMIC: type=2, offset=dynamic_off, vaddr=dynamic_addr, paddr=dynamic_addr, filesz=dynamic_size, memsz=dynamic_size, flags=6, align=4
        phdrs.extend(struct.pack("<IIIIIIII", 2, dynamic_off, dynamic_addr, dynamic_addr, dynamic_size, dynamic_size, 6, 4))

    # Section Headers (8 headers: 0=NULL, 1=.text, 2=.dynsym, 3=.dynstr, 4=.dynamic, 5=.shstrtab, 6=.symtab, 7=.strtab)
    shdrs = bytearray()
    num_imports = len(import_sym_info)
    if is_64:
        shdrs.extend(b"\x00" * 64)  # 0: NULL
        shdrs.extend(struct.pack("<IIQQQQIIQQ", text_shname, 1, 6, text_addr, text_off, text_size, 0, 0, 16, 0))
        shdrs.extend(struct.pack("<IIQQQQIIQQ", dynsym_shname, 11, 2, dynsym_addr, dynsym_off, dynsym_size, 3, 1 + num_imports, 8, 24))
        shdrs.extend(struct.pack("<IIQQQQIIQQ", dynstr_shname, 3, 2, dynstr_addr, dynstr_off, dynstr_size, 0, 0, 1, 0))
        shdrs.extend(struct.pack("<IIQQQQIIQQ", dynamic_shname, 6, 3, dynamic_addr, dynamic_off, dynamic_size, 3, 0, 8, 16))
        shdrs.extend(struct.pack("<IIQQQQIIQQ", shstrtab_shname, 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0))
        shdrs.extend(struct.pack("<IIQQQQIIQQ", symtab_shname, 2, 0, 0, symtab_off, symtab_size, 7, 1 + num_imports, 8, 24))
        shdrs.extend(struct.pack("<IIQQQQIIQQ", strtab_shname, 3, 0, 0, strtab_off, strtab_size, 0, 0, 1, 0))
    else:
        shdrs.extend(b"\x00" * 40)  # 0: NULL
        shdrs.extend(struct.pack("<IIIIIIIIII", text_shname, 1, 6, text_addr, text_off, text_size, 0, 0, 4, 0))
        shdrs.extend(struct.pack("<IIIIIIIIII", dynsym_shname, 11, 2, dynsym_addr, dynsym_off, dynsym_size, 3, 1 + num_imports, 4, 16))
        shdrs.extend(struct.pack("<IIIIIIIIII", dynstr_shname, 3, 2, dynstr_addr, dynstr_off, dynstr_size, 0, 0, 1, 0))
        shdrs.extend(struct.pack("<IIIIIIIIII", dynamic_shname, 6, 3, dynamic_addr, dynamic_off, dynamic_size, 3, 0, 4, 8))
        shdrs.extend(struct.pack("<IIIIIIIIII", shstrtab_shname, 3, 0, 0, shstrtab_off, shstrtab_size, 0, 0, 1, 0))
        shdrs.extend(struct.pack("<IIIIIIIIII", symtab_shname, 2, 0, 0, symtab_off, symtab_size, 7, 1 + num_imports, 4, 16))
        shdrs.extend(struct.pack("<IIIIIIIIII", strtab_shname, 3, 0, 0, strtab_off, strtab_size, 0, 0, 1, 0))

    shnum = 8
    shstrndx = 5

    ident = b"\x7fELF" + (b"\x02" if is_64 else b"\x01") + b"\x01\x01\x00" + b"\x00" * 8
    if is_64:
        ehdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, e_machine, 1, text_addr, phoff, shoff, 0, 64, 56, phnum, 64, shnum, shstrndx)
    else:
        ehdr = struct.pack("<16sHHIIIIIHHHHHH", ident, 3, e_machine, 1, text_addr, phoff, shoff, 0, 52, 32, phnum, 40, shnum, shstrndx)

    data = bytearray(ehdr)
    data.extend(phdrs)
    if len(data) < text_off:
        data.extend(b"\x00" * (text_off - len(data)))
    data.extend(text_bytes)
    data.extend(dynsym)
    data.extend(dynstr)
    data.extend(dynamic)
    data.extend(shstrtab)
    data.extend(symtab)
    data.extend(strtab)
    if len(data) < shoff:
        data.extend(b"\x00" * (shoff - len(data)))
    data.extend(shdrs)
    return bytes(data)


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
    - lib/x86_64/libauth.so (synthesized x86_64 ELF)
    - lib/arm64-v8a/libauth.so (synthesized arm64 ELF)
    - lib/x86_64/libflow.so (synthesized x86_64 ELF)
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

    # Resolve default ELF fixtures: prefer compiled disk fixtures with machine code for disasm/functions,
    # falling back to synthesized ELFs if absent.
    if elf_fixtures is None:
        auth_elf = FIXTURES_DIR / "auth_gate_elf64"
        flow_elf = FIXTURES_DIR / "flow_calc_elf64"
        auth_bytes = (
            auth_elf.read_bytes()
            if auth_elf.exists()
            else synthesize_elf_bytes(
                arch="x86_64",
                soname="libauth.so",
                exports=[("check_master_password", 0x11E0, 32), ("main", 0x1140, 64)],
            )
        )
        flow_bytes = (
            flow_elf.read_bytes()
            if flow_elf.exists()
            else synthesize_elf_bytes(
                arch="x86_64",
                soname="libflow.so",
                exports=[("calc_dispatch", 0x1200, 64)],
            )
        )
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


def create_synthetic_react_native_apk(output_path: Union[str, Path]) -> Path:
    """
    Creates a synthetic React Native Android APK containing:
    - AndroidManifest.xml with React Native package
    - classes.dex with React Native DEX class references ('com.facebook.react.')
    - assets/index.android.bundle JavaScript bundle marker
    - lib/arm64-v8a/libreactnativejni.so and libhermes.so native runtime markers
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    rn_dex = synthesize_dex_bytes([
        "Lcom/facebook/react/ReactActivity;",
        "Lcom/facebook/react/ReactPackage;",
        "com.facebook.react.bridge.NativeModule",
    ])
    rn_so = synthesize_elf_bytes(
        arch="arm64",
        soname="libreactnativejni.so",
        needed=["libc.so", "libfolly_runtime.so"],
        exports=[("Java_com_facebook_react_bridge_ReactBridge_init", 0x1000, 64)],
    )
    hermes_so = synthesize_elf_bytes(
        arch="arm64",
        soname="libhermes.so",
        needed=["libc.so"],
        exports=[],
    )

    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            b'    package="com.example.reactnative.sample">\n'
            b'    <application android:name=".MainApplication">\n'
            b'        <activity android:name=".MainActivity"/>\n'
            b'    </application>\n'
            b'</manifest>\n'
        )
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", rn_dex)
        zf.writestr("assets/index.android.bundle", b"var __BUNDLE_START_TIME__ = Date.now();")
        zf.writestr("lib/arm64-v8a/libreactnativejni.so", rn_so)
        zf.writestr("lib/arm64-v8a/libhermes.so", hermes_so)

    return out


def create_synthetic_flutter_apk(output_path: Union[str, Path]) -> Path:
    """
    Creates a synthetic Flutter / Dart Android APK containing:
    - AndroidManifest.xml with Flutter package
    - classes.dex with Flutter embedding class references ('io.flutter.')
    - assets/flutter_assets/kernel_blob.bin Flutter snapshot marker
    - lib/arm64-v8a/libflutter.so and libapp.so native engine & snapshot markers
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    flutter_dex = synthesize_dex_bytes([
        "Lio/flutter/embedding/android/FlutterActivity;",
        "Lio/flutter/embedding/engine/FlutterEngine;",
        "io.flutter.plugin.common.MethodChannel",
    ])
    flutter_engine_so = synthesize_elf_bytes(
        arch="arm64",
        soname="libflutter.so",
        needed=["libc.so", "libm.so"],
        exports=[("Java_io_flutter_embedding_engine_FlutterJNI_nativeInit", 0x1000, 64)],
    )
    dart_app_so = synthesize_elf_bytes(
        arch="arm64",
        soname="libapp.so",
        needed=["libc.so"],
        exports=[("_kDartIsolateSnapshotInstructions", 0x2000, 128)],
    )

    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            b'    package="com.example.flutter.sample">\n'
            b'    <application android:name="io.flutter.app.FlutterApplication">\n'
            b'        <activity android:name=".MainActivity"/>\n'
            b'    </application>\n'
            b'</manifest>\n'
        )
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", flutter_dex)
        zf.writestr("assets/flutter_assets/kernel_blob.bin", b"FLUTTER_SNAPSHOT_KERNEL_BLOB")
        zf.writestr("lib/arm64-v8a/libflutter.so", flutter_engine_so)
        zf.writestr("lib/arm64-v8a/libapp.so", dart_app_so)

    return out


def create_synthetic_native_cpp_apk(output_path: Union[str, Path]) -> Path:
    """
    Creates a synthetic C/C++ native Android APK containing:
    - AndroidManifest.xml
    - classes.dex with JNI caller declarations
    - Multi-ABI native libraries (arm64-v8a, x86_64, armeabi-v7a) with C/C++ runtime deps and JNI exports
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    dex_bytes = synthesize_dex_bytes([
        "Lcom/example/nativecpp/MainActivity;",
        "stringFromJNI",
        "calculateAuthGate",
    ])

    exports = [
        ("Java_com_example_nativecpp_MainActivity_stringFromJNI", 0x1000, 32),
        ("Java_com_example_nativecpp_MainActivity_calculateAuthGate", 0x1040, 64),
    ]

    so_arm64 = synthesize_elf_bytes(
        arch="arm64",
        soname="libnative.so",
        needed=["libc.so", "libm.so", "libstdc++.so"],
        exports=exports,
    )
    so_x86_64 = synthesize_elf_bytes(
        arch="x86_64",
        soname="libnative.so",
        needed=["libc.so", "libm.so", "libstdc++.so"],
        exports=exports,
    )
    so_arm = synthesize_elf_bytes(
        arch="arm",
        soname="libnative.so",
        needed=["libc.so", "libm.so", "libstdc++.so"],
        exports=exports,
    )

    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            b'    package="com.example.nativecpp.sample">\n'
            b'    <application>\n'
            b'        <activity android:name=".MainActivity"/>\n'
            b'    </application>\n'
            b'</manifest>\n'
        )
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("lib/arm64-v8a/libnative.so", so_arm64)
        zf.writestr("lib/x86_64/libnative.so", so_x86_64)
        zf.writestr("lib/armeabi-v7a/libnative.so", so_arm)

    return out


def create_synthetic_java_only_apk(output_path: Union[str, Path]) -> Path:
    """
    Creates a synthetic pure-Java Android APK containing:
    - AndroidManifest.xml
    - classes.dex and classes2.dex
    - No native libraries (lib/ directory is absent)
    - No framework markers
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    dex1_bytes = synthesize_dex_bytes([
        "Lcom/example/purejava/MainActivity;",
        "onCreate",
        "calculateLocalHash",
    ])
    dex2_bytes = synthesize_dex_bytes([
        "Lcom/example/purejava/DataService;",
        "onBind",
        "fetchLocalRecords",
    ])

    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            b'    package="com.example.purejava.sample">\n'
            b'    <application>\n'
            b'        <activity android:name=".MainActivity"/>\n'
            b'        <service android:name=".DataService"/>\n'
            b'    </application>\n'
            b'</manifest>\n'
        )
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex1_bytes)
        zf.writestr("classes2.dex", dex2_bytes)

    return out


def create_synthetic_hybrid_apk(output_path: Union[str, Path]) -> Path:
    """
    Creates a synthetic hybrid multi-language Android APK containing:
    - AndroidManifest.xml
    - classes.dex with React Native and custom Java logic
    - React Native bundle marker ('assets/index.android.bundle')
    - React Native runtime ('lib/arm64-v8a/libreactnativejni.so')
    - Custom native security library with JNI exports and RegisterNatives detection ('lib/arm64-v8a/libcustom_sec.so')
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    dex_bytes = synthesize_dex_bytes([
        "Lcom/facebook/react/ReactActivity;",
        "Lcom/example/hybrid/SecurityBridge;",
        "decryptToken",
    ])
    rn_so = synthesize_elf_bytes(
        arch="arm64",
        soname="libreactnativejni.so",
        needed=["libc.so", "libfolly_runtime.so"],
        exports=[],
    )
    custom_so = synthesize_elf_bytes(
        arch="arm64",
        soname="libcustom_sec.so",
        needed=["libc.so", "libcrypto.so"],
        exports=[("Java_com_example_hybrid_SecurityBridge_decryptToken", 0x1000, 48)],
        has_register_natives=True,
    )

    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = (
            b'<?xml version="1.0" encoding="utf-8"?>\n'
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
            b'    package="com.example.hybrid.sample">\n'
            b'    <application>\n'
            b'        <activity android:name=".MainActivity"/>\n'
            b'    </application>\n'
            b'</manifest>\n'
        )
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex_bytes)
        zf.writestr("assets/index.android.bundle", b"var __BUNDLE_HYBRID__ = true;")
        zf.writestr("lib/arm64-v8a/libreactnativejni.so", rn_so)
        zf.writestr("lib/arm64-v8a/libcustom_sec.so", custom_so)

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
    Unit tests ensuring the synthetic DEX, ELF, and APK builders produce valid structures
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

    def test_synthesize_elf_architectures(self) -> None:
        """Validates pure-Python ELF synthesis across arm64, x86_64, arm, and x86."""
        for arch, expected_class, expected_machine in [
            ("arm64", 2, 0xB7),
            ("x86_64", 2, 0x3E),
            ("arm", 1, 40),
            ("x86", 1, 3),
        ]:
            elf_bytes = synthesize_elf_bytes(arch=arch, soname=f"lib{arch}.so")
            self.assertTrue(elf_bytes.startswith(b"\x7fELF"))
            self.assertEqual(elf_bytes[4], expected_class)  # EI_CLASS: 1=32bit, 2=64bit
            self.assertEqual(elf_bytes[5], 1)               # EI_DATA: 1=little-endian
            e_machine = struct.unpack_from("<H", elf_bytes, 0x12)[0]
            self.assertEqual(e_machine, expected_machine)
            self.assertIn(f"lib{arch}.so".encode("utf-8"), elf_bytes)

    def test_synthesize_elf_symbols_and_registration(self) -> None:
        """Validates ELF exports, imports, and RegisterNatives detection byte patterns."""
        elf_bytes = synthesize_elf_bytes(
            arch="arm64",
            soname="libcustom.so",
            exports=[("Java_com_example_Custom_nativeFunc", 0x1000, 32)],
            imports=["custom_import_func"],
            has_register_natives=True,
        )
        self.assertIn(b"Java_com_example_Custom_nativeFunc\x00", elf_bytes)
        self.assertIn(b"custom_import_func\x00", elf_bytes)
        self.assertIn(b"RegisterNatives\x00", elf_bytes)

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

    def test_create_synthetic_react_native_apk(self) -> None:
        """Validates React Native synthetic APK generation and markers."""
        rn_path = self.tmp / "sample_rn.apk"
        create_synthetic_react_native_apk(rn_path)
        self.assertTrue(rn_path.exists())
        with zipfile.ZipFile(rn_path, "r") as zf:
            names = zf.namelist()
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn("classes.dex", names)
            self.assertIn("assets/index.android.bundle", names)
            self.assertIn("lib/arm64-v8a/libreactnativejni.so", names)
            self.assertIn("lib/arm64-v8a/libhermes.so", names)
            dex_content = zf.read("classes.dex")
            self.assertIn(b"com/facebook/react", dex_content)

    def test_create_synthetic_flutter_apk(self) -> None:
        """Validates Flutter synthetic APK generation and markers."""
        flutter_path = self.tmp / "sample_flutter.apk"
        create_synthetic_flutter_apk(flutter_path)
        self.assertTrue(flutter_path.exists())
        with zipfile.ZipFile(flutter_path, "r") as zf:
            names = zf.namelist()
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn("classes.dex", names)
            self.assertIn("assets/flutter_assets/kernel_blob.bin", names)
            self.assertIn("lib/arm64-v8a/libflutter.so", names)
            self.assertIn("lib/arm64-v8a/libapp.so", names)
            dex_content = zf.read("classes.dex")
            self.assertIn(b"io/flutter", dex_content)

    def test_create_synthetic_native_cpp_apk(self) -> None:
        """Validates C/C++ native synthetic APK with multi-ABI libraries."""
        cpp_path = self.tmp / "sample_cpp.apk"
        create_synthetic_native_cpp_apk(cpp_path)
        self.assertTrue(cpp_path.exists())
        with zipfile.ZipFile(cpp_path, "r") as zf:
            names = zf.namelist()
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn("classes.dex", names)
            self.assertIn("lib/arm64-v8a/libnative.so", names)
            self.assertIn("lib/x86_64/libnative.so", names)
            self.assertIn("lib/armeabi-v7a/libnative.so", names)

    def test_create_synthetic_java_only_apk(self) -> None:
        """Validates pure Java synthetic APK contains multidex and zero native libraries."""
        java_path = self.tmp / "sample_java.apk"
        create_synthetic_java_only_apk(java_path)
        self.assertTrue(java_path.exists())
        with zipfile.ZipFile(java_path, "r") as zf:
            names = zf.namelist()
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn("classes.dex", names)
            self.assertIn("classes2.dex", names)
            self.assertFalse(any(n.startswith("lib/") for n in names))

    def test_create_synthetic_hybrid_apk(self) -> None:
        """Validates hybrid synthetic APK contains both framework assets and custom native libraries."""
        hybrid_path = self.tmp / "sample_hybrid.apk"
        create_synthetic_hybrid_apk(hybrid_path)
        self.assertTrue(hybrid_path.exists())
        with zipfile.ZipFile(hybrid_path, "r") as zf:
            names = zf.namelist()
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn("assets/index.android.bundle", names)
            self.assertIn("lib/arm64-v8a/libreactnativejni.so", names)
            self.assertIn("lib/arm64-v8a/libcustom_sec.so", names)

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
