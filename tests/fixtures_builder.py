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

import base64
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
    data_off = current_data_off
    data_size = file_size - current_data_off

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
    # data_size & data_off
    struct.pack_into("<I", header, 0x68, data_size)
    struct.pack_into("<I", header, 0x6C, data_off)

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


# =============================================================================
# ASN.1 DER & APK Signature Synthesizers
# =============================================================================

DEFAULT_RSA_MODULUS_HEX = (
    "c4a45a33b006934c56832db740ca38596001099e2ff9bdfdbbd9b0391ab1a120"
    "5f93e36e65561a32a68a5c689d14ec9f02fe045fb9633e68dfd058ad116ff1a3"
    "bc8c8d2d9bb4e637a3b3dc5d820464f9bf51a2f6fb39f60b43f1190bc1ef0452"
    "3c942eeed3be04f46f4142f9b8893707cb67ca2b6e50e82c5f1c9c43d2c77d"
)


def _der_len(length: int) -> bytes:
    """Encode ASN.1 length in DER format."""
    if length < 0x80:
        return bytes([length])
    lb = bytearray()
    t = length
    while t > 0:
        lb.insert(0, t & 0xFF)
        t >>= 8
    return bytes([0x80 | len(lb)]) + bytes(lb)


def _der_tlv(tag: int, val: bytes) -> bytes:
    """Construct a DER Tag-Length-Value."""
    return bytes([tag]) + _der_len(len(val)) + val


def _der_seq(val: bytes) -> bytes:
    """Construct an ASN.1 SEQUENCE."""
    return _der_tlv(0x30, val)


def _der_set(val: bytes) -> bytes:
    """Construct an ASN.1 SET."""
    return _der_tlv(0x31, val)


def _der_int(val: int) -> bytes:
    """Construct an ASN.1 INTEGER."""
    if val == 0:
        return _der_tlv(0x02, b"\x00")
    b = bytearray()
    t = val
    while t > 0:
        b.insert(0, t & 0xFF)
        t >>= 8
    if b[0] & 0x80:
        b.insert(0, 0x00)
    return _der_tlv(0x02, bytes(b))


def _der_oid(oid_str: str) -> bytes:
    """Encode an OID string into DER."""
    parts = [int(p) for p in oid_str.split(".")]
    res = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        p_bytes = bytearray()
        v = part
        while True:
            p_bytes.insert(0, (v & 0x7F) | (0x80 if len(p_bytes) > 0 else 0x00))
            v >>= 7
            if v == 0:
                break
        res.extend(p_bytes)
    return _der_tlv(0x06, bytes(res))


def _der_bit_str(val: bytes, unused: int = 0) -> bytes:
    """Construct an ASN.1 BIT STRING."""
    return _der_tlv(0x03, bytes([unused]) + val)


def _der_octet_str(val: bytes) -> bytes:
    """Construct an ASN.1 OCTET STRING."""
    return _der_tlv(0x04, val)


def _der_null() -> bytes:
    """Construct an ASN.1 NULL."""
    return b"\x05\x00"


def _der_printable(s: str) -> bytes:
    """Construct an ASN.1 PrintableString."""
    return _der_tlv(0x13, s.encode("ascii"))


def _der_utf8(s: str) -> bytes:
    """Construct an ASN.1 UTF8String."""
    return _der_tlv(0x0C, s.encode("utf-8"))


def _der_utc(s: str) -> bytes:
    """Construct an ASN.1 UTCTime."""
    return _der_tlv(0x17, s.encode("ascii"))


def _parse_dn(dn_str: str) -> bytes:
    """Parse a Distinguished Name (e.g. 'CN=Signer, O=Org, C=US') into DER RDN sequence."""
    oid_map = {
        "C": "2.5.4.6",
        "O": "2.5.4.10",
        "OU": "2.5.4.11",
        "CN": "2.5.4.3",
    }
    rdns = bytearray()
    for part in dn_str.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().upper()
            v = v.strip()
            oid = oid_map.get(k, "2.5.4.3")
            s_der = _der_printable(v) if k == "C" else _der_utf8(v)
            rdns.extend(_der_set(_der_seq(_der_oid(oid) + s_der)))
    if not rdns:
        rdns.extend(_der_set(_der_seq(_der_oid("2.5.4.3") + _der_utf8("RvsTestSigner"))))
    return _der_seq(bytes(rdns))


def synthesize_x509_cert_bytes(
    cert_subject: str = "CN=RvsTestSigner, O=RvsTestSuite, C=US",
    cert_issuer: Optional[str] = None,
    serial_number: int = 0x12345678,
    not_before: str = "240101000000Z",
    not_after: str = "440101000000Z",
) -> Tuple[bytes, bytes]:
    """
    Synthesizes a deterministic DER-encoded X.509 v3 self-signed certificate
    and SubjectPublicKeyInfo structure.
    
    Returns:
        (cert_der, spki_der)
    """
    subject_der = _parse_dn(cert_subject)
    issuer_der = _parse_dn(cert_issuer or cert_subject)

    rsa_pub_der = _der_seq(_der_int(int(DEFAULT_RSA_MODULUS_HEX, 16)) + _der_int(65537))
    alg_rsa = _der_seq(_der_oid("1.2.840.113549.1.1.1") + _der_null())
    spki = _der_seq(alg_rsa + _der_bit_str(rsa_pub_der))

    alg_rsa_sha256 = _der_seq(_der_oid("1.2.840.113549.1.1.11") + _der_null())
    validity = _der_seq(_der_utc(not_before) + _der_utc(not_after))

    tbs = _der_seq(
        _der_tlv(0xA0, _der_int(2))  # v3
        + _der_int(serial_number)
        + alg_rsa_sha256
        + issuer_der
        + validity
        + subject_der
        + spki
    )
    sig_val = (hashlib.sha256(tbs).digest() * 4)[:128]
    cert_der = _der_seq(tbs + alg_rsa_sha256 + _der_bit_str(sig_val))
    return cert_der, spki


def synthesize_pkcs7_signature_bytes(
    cert_subject: str = "CN=RvsTestSigner, O=RvsTestSuite, C=US",
    cert_issuer: Optional[str] = None,
    serial_number: int = 0x12345678,
) -> bytes:
    """
    Synthesizes a deterministic DER-encoded PKCS#7 SignedData structure
    containing the X.509 signer certificate for META-INF/*.RSA.
    """
    cert_der, _ = synthesize_x509_cert_bytes(
        cert_subject=cert_subject,
        cert_issuer=cert_issuer,
        serial_number=serial_number,
    )
    issuer_der = _parse_dn(cert_issuer or cert_subject)
    alg_rsa = _der_seq(_der_oid("1.2.840.113549.1.1.1") + _der_null())
    alg_sha256 = _der_seq(_der_oid("2.16.840.1.101.3.4.2.1") + _der_null())
    encap_content = _der_seq(_der_oid("1.2.840.113549.1.7.1"))
    issuer_and_serial = _der_seq(issuer_der + _der_int(serial_number))
    dummy_sig = b"\x42" * 128

    signer_info = _der_seq(
        _der_int(1)
        + issuer_and_serial
        + alg_sha256
        + alg_rsa
        + _der_octet_str(dummy_sig)
    )
    signed_data = _der_seq(
        _der_int(1)
        + _der_set(alg_sha256)
        + encap_content
        + _der_tlv(0xA0, cert_der)
        + _der_set(signer_info)
    )
    return _der_seq(_der_oid("1.2.840.113549.1.7.2") + _der_tlv(0xA0, signed_data))


def synthesize_arsc_bytes(
    pkg_name: str = "com.example.synthetic.target",
    strings: Optional[List[str]] = None,
) -> bytes:
    """
    Synthesizes a minimal valid spec-compliant Android binary resources.arsc table
    containing a global string pool, package chunk, type string pool, and key string pool.
    """
    if strings is None:
        strings = ["app_name", "SyntheticTarget", "res/values/strings.xml"]

    def _build_pool(strs: List[str]) -> bytes:
        offsets = []
        str_data = bytearray()
        for s in strs:
            offsets.append(len(str_data))
            encoded = s.encode("utf-8")
            str_data.append(len(s) & 0x7F)
            str_data.append(len(encoded) & 0x7F)
            str_data.extend(encoded)
            str_data.append(0)
        while len(str_data) % 4 != 0:
            str_data.append(0)
        h_size = 28
        count = len(strs)
        start = h_size + (count * 4)
        total = start + len(str_data)
        h = bytearray()
        h.extend(struct.pack("<HHI", 0x0001, h_size, total))
        h.extend(struct.pack("<IIIII", count, 0, 0x00000100, start, 0))
        for off in offsets:
            h.extend(struct.pack("<I", off))
        return bytes(h) + bytes(str_data)

    global_pool = _build_pool(strings)
    type_pool = _build_pool(["attr", "string", "xml"])
    key_pool = _build_pool(["app_name", "welcome_message", "api_endpoint"])

    pkg_h_size = 288
    type_off = pkg_h_size
    key_off = type_off + len(type_pool)
    pkg_total = key_off + len(key_pool)

    pkg_name_utf16 = pkg_name.encode("utf-16le")
    pkg_name_padded = pkg_name_utf16.ljust(256, b"\x00")[:256]

    pkg_chunk = bytearray()
    pkg_chunk.extend(struct.pack("<HHI", 0x0200, pkg_h_size, pkg_total))
    pkg_chunk.extend(struct.pack("<I", 0x7F))
    pkg_chunk.extend(pkg_name_padded)
    pkg_chunk.extend(struct.pack("<IIIII", type_off, 0, key_off, 0, 0))
    pkg_chunk.extend(type_pool)
    pkg_chunk.extend(key_pool)

    table_h_size = 12
    table_total = table_h_size + len(global_pool) + len(pkg_chunk)
    table_header = struct.pack("<HHII", 0x0002, table_h_size, table_total, 1)

    return table_header + global_pool + bytes(pkg_chunk)


def synthesize_apk_signing_block_v2(
    pairs: Optional[List[Tuple[int, bytes]]] = None,
    cert_der: Optional[bytes] = None,
    spki_der: Optional[bytes] = None,
    apk_digest_sha256: Optional[bytes] = None,
) -> bytes:
    """
    Synthesizes an Android APK Signing Block with ID 0x7109871a (v2 scheme)
    and 16-byte magic 'APK Sig Block 42'.
    """
    if pairs is None:
        if cert_der is None or spki_der is None:
            cert_der, spki_der = synthesize_x509_cert_bytes()
        if apk_digest_sha256 is None:
            apk_digest_sha256 = hashlib.sha256(b"rvs_apk_signing_block_v2_digest").digest()

        def _pfx(data: bytes) -> bytes:
            return struct.pack("<I", len(data)) + data

        algo_id = 0x0101  # RSA-PKCS1-v1_5 with SHA256
        digest_entry = struct.pack("<I", algo_id) + _pfx(apk_digest_sha256)
        digests_seq = _pfx(_pfx(digest_entry))
        certs_seq = _pfx(_pfx(cert_der))
        attrs_seq = _pfx(b"")
        signed_data = digests_seq + certs_seq + attrs_seq

        sig_entry = struct.pack("<I", algo_id) + _pfx(b"\x5a" * 128)
        sigs_seq = _pfx(_pfx(sig_entry))
        signer = _pfx(signed_data) + sigs_seq + _pfx(spki_der)
        signers_seq = _pfx(_pfx(signer))
        pairs = [(0x7109871A, signers_seq)]

    pairs_bytes = bytearray()
    for pair_id, pair_val in pairs:
        pair_len = 4 + len(pair_val)
        pairs_bytes.extend(struct.pack("<Q", pair_len))
        pairs_bytes.extend(struct.pack("<I", pair_id))
        pairs_bytes.extend(pair_val)

    # APK Signing Block format:
    # uint64 size_of_block (excluding this field)
    # pairs...
    # uint64 size_of_block (same as first field)
    # 16-byte magic: 'APK Sig Block 42'
    block_size = len(pairs_bytes) + 24
    block = bytearray()
    block.extend(struct.pack("<Q", block_size))
    block.extend(pairs_bytes)
    block.extend(struct.pack("<Q", block_size))
    block.extend(b"APK Sig Block 42")
    return bytes(block)


def inject_apk_signing_block(apk_path: Union[str, Path], block_bytes: bytes) -> None:
    """
    Injects an APK Signing Block immediately before the Central Directory
    in a valid ZIP archive and shifts the Central Directory offset in the EOCD record.
    """
    apk = Path(apk_path)
    zip_data = apk.read_bytes()
    eocd_idx = zip_data.rfind(b"PK\x05\x06")
    if eocd_idx == -1:
        raise ValueError(f"Target {apk} is not a valid ZIP archive (no EOCD found)")
    cd_offset = struct.unpack("<I", zip_data[eocd_idx + 16 : eocd_idx + 20])[0]

    new_data = bytearray()
    new_data.extend(zip_data[:cd_offset])
    new_data.extend(block_bytes)
    new_data.extend(zip_data[cd_offset:eocd_idx])

    new_cd_offset = cd_offset + len(block_bytes)
    new_eocd = bytearray(zip_data[eocd_idx:])
    new_eocd[16:20] = struct.pack("<I", new_cd_offset)
    new_data.extend(new_eocd)

    apk.write_bytes(bytes(new_data))


def synthesize_v1_manifest_and_sf(
    entries: Dict[str, bytes],
) -> Tuple[bytes, bytes, bytes]:
    """
    Synthesizes META-INF/MANIFEST.MF, META-INF/CERT.SF, and META-INF/CERT.RSA
    for standard v1 JAR signing.
    """
    mf_lines = [
        "Manifest-Version: 1.0",
        "Created-By: 1.0 (Synthetic APK Fixture Builder)",
    ]
    for name, data in sorted(entries.items()):
        if name.startswith("META-INF/"):
            continue
        digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        mf_lines.append("")
        mf_lines.append(f"Name: {name}")
        mf_lines.append(f"SHA-256-Digest: {digest}")
    mf_lines.append("")
    mf_bytes = "\r\n".join(mf_lines).encode("utf-8")

    mf_digest = base64.b64encode(hashlib.sha256(mf_bytes).digest()).decode("ascii")
    sf_lines = [
        "Signature-Version: 1.0",
        "Created-By: 1.0 (Synthetic APK Fixture Builder)",
        f"SHA-256-Digest-Manifest: {mf_digest}",
    ]
    for name, data in sorted(entries.items()):
        if name.startswith("META-INF/"):
            continue
        digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        sf_lines.append("")
        sf_lines.append(f"Name: {name}")
        sf_lines.append(f"SHA-256-Digest: {digest}")
    sf_lines.append("")
    sf_bytes = "\r\n".join(sf_lines).encode("utf-8")

    rsa_bytes = synthesize_pkcs7_signature_bytes()
    return mf_bytes, sf_bytes, rsa_bytes


def create_synthetic_apk(
    output_path: Union[str, Path],
    elf_fixtures: Optional[Dict[str, Union[str, Path, bytes]]] = None,
    multidex: bool = True,
    dex_strings_map: Optional[Dict[str, List[str]]] = None,
    include_manifest: bool = True,
    sign_v1: bool = True,
    sign_v2: bool = True,
    assets: Optional[Dict[str, Union[str, bytes]]] = None,
    resources: Optional[Dict[str, Union[str, bytes]]] = None,
    tamper_entry: Optional[Tuple[str, bytes]] = None,
) -> Path:
    """
    Creates a valid synthetic Android APK package archive with multi-ABI native libraries,
    Dalvik DEX bytecode components, embedded resources, assets, and v1/v2 signatures.
    
    Default layout:
    - AndroidManifest.xml
    - classes.dex (valid Dalvik DEX)
    - classes2.dex (if multidex is True)
    - lib/x86_64/libauth.so, lib/arm64-v8a/libauth.so, lib/x86_64/libflow.so
    - assets/app_config.json, assets/secret_token.txt
    - res/values/strings.xml, resources.arsc
    - META-INF/MANIFEST.MF, META-INF/CERT.SF, META-INF/CERT.RSA (if sign_v1 is True)
    - APK Signing Block v2 (if sign_v2 is True)
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

    # Resolve default ELF fixtures
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

    # Prepare archive entries dictionary
    entries: Dict[str, bytes] = {}

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
        entries["AndroidManifest.xml"] = manifest_xml

    # 2. classes.dex
    dex1_strings = dex_strings_map.get("classes.dex", ["Lcom/example/Main;"])
    entries["classes.dex"] = synthesize_dex_bytes(strings=dex1_strings)

    # 3. classes2.dex (if multidex)
    if multidex:
        dex2_strings = dex_strings_map.get("classes2.dex", ["Lcom/example/Secondary;"])
        entries["classes2.dex"] = synthesize_dex_bytes(strings=dex2_strings)

    # 4. Native libraries (ELF .so files)
    for archive_path, content in elf_fixtures.items():
        if isinstance(content, (str, Path)):
            content_bytes = Path(content).read_bytes()
        elif isinstance(content, bytes):
            content_bytes = content
        else:
            raise TypeError(f"Invalid fixture content type for {archive_path}: {type(content)}")
        entries[archive_path] = content_bytes

    # 5. Assets
    if assets is None:
        assets = {
            "assets/app_config.json": b'{"environment": "production", "debug": false, "app_id": "com.example.synthetic.target"}\n',
            "assets/secret_token.txt": b"rvs_synthetic_secret_token_alpha_numeric_key_99\n",
        }
    for asset_path, asset_content in assets.items():
        if isinstance(asset_content, str):
            entries[asset_path] = asset_content.encode("utf-8")
        else:
            entries[asset_path] = bytes(asset_content)

    # 6. Resources
    if resources is None:
        resources = {
            "res/values/strings.xml": (
                b'<?xml version="1.0" encoding="utf-8"?>\n'
                b'<resources>\n'
                b'    <string name="app_name">SyntheticTarget</string>\n'
                b'    <string name="welcome_message">Welcome to rvs reverse engineering suite</string>\n'
                b'    <string name="api_endpoint">https://api.example.com/v1</string>\n'
                b'</resources>\n'
            ),
            "resources.arsc": synthesize_arsc_bytes(),
        }
    for res_path, res_content in resources.items():
        if isinstance(res_content, str):
            entries[res_path] = res_content.encode("utf-8")
        else:
            entries[res_path] = bytes(res_content)

    # 7. v1 JAR Signatures
    if sign_v1:
        mf_bytes, sf_bytes, rsa_bytes = synthesize_v1_manifest_and_sf(entries)
        entries["META-INF/MANIFEST.MF"] = mf_bytes
        entries["META-INF/CERT.SF"] = sf_bytes
        entries["META-INF/CERT.RSA"] = rsa_bytes
    else:
        # Minimal non-signature manifest header if requested
        entries["META-INF/MANIFEST.MF"] = (
            b"Manifest-Version: 1.0\n"
            b"Created-By: 1.0 (Synthetic APK Fixture Builder)\n"
        )

    # Mutate entry payload AFTER v1 signatures are computed to trigger signature mismatch
    if tamper_entry is not None:
        tamper_name, tamper_data = tamper_entry
        entries[tamper_name] = tamper_data

    # Write archive
    with zipfile.ZipFile(out, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zinfo = zipfile.ZipInfo(name)
            if name.startswith("assets/"):
                zinfo.compress_type = zipfile.ZIP_STORED
            else:
                zinfo.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zinfo, data)

    # 8. v2 APK Signing Block
    if sign_v2:
        block = synthesize_apk_signing_block_v2()
        inject_apk_signing_block(out, block)

    return out


def create_unsigned_apk(
    output_path: Union[str, Path],
    multidex: bool = False,
) -> Path:
    """Creates a synthetic APK without any signatures (no v1 META-INF signatures, no v2 block)."""
    return create_synthetic_apk(
        output_path=output_path,
        multidex=multidex,
        sign_v1=False,
        sign_v2=False,
    )


def create_tampered_signature_apk(
    output_path: Union[str, Path],
) -> Path:
    """
    Creates an APK with valid v1 & v2 signatures initially,
    then deliberately mutates the content of an entry without updating signatures,
    causing cryptographic digest verification to fail while preserving ZIP container integrity.
    """
    return create_synthetic_apk(
        output_path=output_path,
        sign_v1=True,
        sign_v2=True,
        tamper_entry=("assets/secret_token.txt", b"rvs_TAMPR_secret_token_alpha_numeric_key_99\n"),
    )


def create_corrupted_signing_block_apk(
    output_path: Union[str, Path],
    corruption_type: str = "bad_magic",
) -> Path:
    """
    Creates an APK with a corrupted APK Signing Block.
    Supported corruption types:
    - 'bad_magic': Mutates the 16-byte magic to 'BAD Sig Block 42'
    - 'size_mismatch': First uint64 size != second uint64 size
    - 'truncated': Truncates block bytes
    """
    apk_path = Path(output_path)
    create_synthetic_apk(apk_path, sign_v1=True, sign_v2=False)
    block = bytearray(synthesize_apk_signing_block_v2())
    if corruption_type == "bad_magic":
        block[-16:] = b"BAD Sig Block 42"
    elif corruption_type == "size_mismatch":
        struct.pack_into("<Q", block, len(block) - 24, 0xDEADBEEF)
    elif corruption_type == "truncated":
        block = block[: len(block) - 10]
    else:
        block[-16:] = b"\x00" * 16

    inject_apk_signing_block(apk_path, bytes(block))
    return apk_path


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

    def test_synthesize_x509_cert_and_pkcs7(self) -> None:
        """Validates pure-Python X.509 certificate and PKCS#7 SignedData synthesis."""
        cert_der, spki_der = synthesize_x509_cert_bytes(
            cert_subject="CN=CustomSigner, O=CustomOrg, C=US",
            serial_number=0xAABBCCDD,
        )
        self.assertTrue(cert_der.startswith(b"\x30"))
        self.assertIn(b"CustomSigner", cert_der)
        self.assertIn(b"CustomOrg", cert_der)
        self.assertTrue(spki_der.startswith(b"\x30"))

        pkcs7_der = synthesize_pkcs7_signature_bytes(
            cert_subject="CN=CustomSigner, O=CustomOrg, C=US",
            serial_number=0xAABBCCDD,
        )
        self.assertTrue(pkcs7_der.startswith(b"\x30"))
        # Must contain SignedData OID 1.2.840.113549.1.7.2
        self.assertIn(_der_oid("1.2.840.113549.1.7.2"), pkcs7_der)
        # Must contain embedded certificate
        self.assertIn(cert_der, pkcs7_der)

    def test_synthesize_arsc_bytes(self) -> None:
        """Validates pure-Python binary resources.arsc table structure."""
        arsc = synthesize_arsc_bytes(pkg_name="com.test.app", strings=["hello", "world"])
        self.assertGreaterEqual(len(arsc), 12)
        chunk_type, header_size, total_size, pkg_count = struct.unpack_from("<HHII", arsc, 0)
        self.assertEqual(chunk_type, 0x0002)  # RES_TABLE_TYPE
        self.assertEqual(header_size, 12)
        self.assertEqual(total_size, len(arsc))
        self.assertEqual(pkg_count, 1)
        self.assertIn(b"com.test.app".replace(b"", b"\x00")[1:-1], arsc)  # UTF-16LE package name

    def test_synthesize_apk_signing_block_v2(self) -> None:
        """Validates APK Signing Block v2 layout, magic, and size fields."""
        block = synthesize_apk_signing_block_v2()
        self.assertTrue(block.endswith(b"APK Sig Block 42"))
        size1 = struct.unpack_from("<Q", block, 0)[0]
        size2 = struct.unpack_from("<Q", block, len(block) - 24)[0]
        self.assertEqual(size1, size2)
        self.assertEqual(size1, len(block) - 8)
        # Verify v2 ID 0x7109871a is present
        self.assertIn(struct.pack("<I", 0x7109871A), block)

    def test_create_synthetic_apk_with_v1_v2_and_resources(self) -> None:
        """Validates that synthetic APK packaging includes v1 signatures, v2 signing block, resources, and assets."""
        apk_path = self.tmp / "sample_signed.apk"
        create_synthetic_apk(apk_path, multidex=True, sign_v1=True, sign_v2=True)
        self.assertTrue(apk_path.exists())

        # Verify ZIP structure
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("AndroidManifest.xml", namelist)
            self.assertIn("classes.dex", namelist)
            self.assertIn("classes2.dex", namelist)
            self.assertIn("assets/app_config.json", namelist)
            self.assertIn("assets/secret_token.txt", namelist)
            self.assertIn("res/values/strings.xml", namelist)
            self.assertIn("resources.arsc", namelist)
            self.assertIn("META-INF/MANIFEST.MF", namelist)
            self.assertIn("META-INF/CERT.SF", namelist)
            self.assertIn("META-INF/CERT.RSA", namelist)

            # Check that manifest contains digests
            mf_content = zf.read("META-INF/MANIFEST.MF").decode("utf-8")
            self.assertIn("Name: AndroidManifest.xml", mf_content)
            self.assertIn("SHA-256-Digest:", mf_content)

            # Check that CERT.SF contains manifest digest
            sf_content = zf.read("META-INF/CERT.SF").decode("utf-8")
            self.assertIn("SHA-256-Digest-Manifest:", sf_content)

            # Check CERT.RSA is valid PKCS#7
            rsa_bytes = zf.read("META-INF/CERT.RSA")
            self.assertTrue(rsa_bytes.startswith(b"\x30"))

        # Verify APK Signing Block exists in raw file before central directory
        raw_bytes = apk_path.read_bytes()
        self.assertIn(b"APK Sig Block 42", raw_bytes)
        self.assertIn(struct.pack("<I", 0x7109871A), raw_bytes)

    def test_create_unsigned_apk(self) -> None:
        """Validates unsigned APK fixture has no signatures."""
        apk_path = self.tmp / "sample_unsigned.apk"
        create_unsigned_apk(apk_path)
        self.assertTrue(apk_path.exists())
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()
            self.assertNotIn("META-INF/CERT.SF", namelist)
            self.assertNotIn("META-INF/CERT.RSA", namelist)
        raw_bytes = apk_path.read_bytes()
        self.assertNotIn(b"APK Sig Block 42", raw_bytes)

    def test_create_tampered_signature_apk(self) -> None:
        """Validates tampered signature APK fixture mutates file payload while preserving ZIP integrity."""
        apk_path = self.tmp / "sample_tampered.apk"
        create_tampered_signature_apk(apk_path)
        self.assertTrue(apk_path.exists())
        raw_bytes = apk_path.read_bytes()
        self.assertIn(b"APK Sig Block 42", raw_bytes)
        self.assertIn(b"TAMPR", raw_bytes)
        with zipfile.ZipFile(apk_path, "r") as zf:
            self.assertIsNone(zf.testzip())
            content = zf.read("assets/secret_token.txt")
            self.assertIn(b"TAMPR", content)

    def test_create_corrupted_signing_block_apk(self) -> None:
        """Validates corrupted signing block fixtures."""
        bad_magic_path = self.tmp / "bad_magic.apk"
        create_corrupted_signing_block_apk(bad_magic_path, corruption_type="bad_magic")
        self.assertTrue(bad_magic_path.exists())
        self.assertIn(b"BAD Sig Block 42", bad_magic_path.read_bytes())

        mismatch_path = self.tmp / "mismatch.apk"
        create_corrupted_signing_block_apk(mismatch_path, corruption_type="size_mismatch")
        self.assertTrue(mismatch_path.exists())
        self.assertIn(struct.pack("<Q", 0xDEADBEEF), mismatch_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
