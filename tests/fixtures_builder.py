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


# ---------------------------------------------------------------------------
# Pure-Python Dalvik DEX Bytecode Generator (DexBuilder)
# ---------------------------------------------------------------------------

ACC_PUBLIC = 0x0001
ACC_PRIVATE = 0x0002
ACC_PROTECTED = 0x0004
ACC_STATIC = 0x0008
ACC_FINAL = 0x0010
ACC_SYNCHRONIZED = 0x0020
ACC_VOLATILE = 0x0040
ACC_TRANSIENT = 0x0080
ACC_NATIVE = 0x0100
ACC_INTERFACE = 0x0200
ACC_ABSTRACT = 0x0400
ACC_STRICT = 0x0800
ACC_SYNTHETIC = 0x1000
ACC_ANNOTATION = 0x2000
ACC_ENUM = 0x4000

VISIBILITY_BUILD = 0
VISIBILITY_RUNTIME = 1
VISIBILITY_SYSTEM = 2


def _to_shorty_char(type_desc: str) -> str:
    """Returns the single-character shorty descriptor for a type descriptor."""
    if not type_desc:
        return "V"
    c = type_desc[0]
    if c in ("Z", "B", "S", "C", "I", "J", "F", "D", "V"):
        return c
    return "L"


def _make_shorty(return_type: str, params: List[str]) -> str:
    """Constructs the Dalvik shorty descriptor string for a method."""
    return _to_shorty_char(return_type) + "".join(_to_shorty_char(p) for p in params)


class DexAnnotation:
    """Represents a Dalvik annotation."""

    def __init__(
        self,
        type_descriptor: str,
        visibility: int = VISIBILITY_RUNTIME,
        elements: Optional[List[Tuple[str, Any]]] = None,
    ):
        self.type_descriptor = type_descriptor
        self.visibility = visibility
        self.elements = elements or []


class DexField:
    """Represents a Dalvik class field definition."""

    def __init__(
        self,
        class_type: str,
        name: str,
        field_type: str,
        access_flags: int = ACC_PUBLIC,
        is_static: bool = False,
        initial_value: Optional[Any] = None,
        annotations: Optional[List[DexAnnotation]] = None,
    ):
        self.class_type = class_type
        self.name = name
        self.field_type = field_type
        self.access_flags = access_flags
        if is_static:
            self.access_flags |= ACC_STATIC
        self.is_static = bool(self.access_flags & ACC_STATIC)
        self.initial_value = initial_value
        self.annotations = annotations or []

    def add_annotation(
        self,
        type_descriptor: str,
        visibility: int = VISIBILITY_RUNTIME,
        elements: Optional[List[Tuple[str, Any]]] = None,
    ) -> DexAnnotation:
        ann = DexAnnotation(type_descriptor, visibility, elements)
        self.annotations.append(ann)
        return ann


class _Label:
    def __init__(self, name: str):
        self.name = name


class _Instruction:
    def __init__(self, kind: str, **kwargs):
        self.kind = kind
        self.args = kwargs

    def size_words(self) -> int:
        k = self.kind
        if k in ("nop", "return_void", "return", "return_object", "goto", "const_4", "format_12x"):
            return 1
        elif k in (
            "const_16",
            "const_string",
            "goto_16",
            "if_test",
            "if_testz",
            "arith_23x",
            "arith_lit8",
            "iget_iput",
            "sget_sput",
        ):
            return 2
        elif k in ("const", "invoke", "switch"):
            return 3
        elif k == "raw_words":
            return len(self.args["words"])
        return 1


class DexMethod:
    """Represents a Dalvik class method with opcode assembling capabilities."""

    def __init__(
        self,
        class_type: str,
        name: str,
        return_type: str = "V",
        params: Optional[List[str]] = None,
        access_flags: int = ACC_PUBLIC,
        registers_size: int = 4,
        ins_size: Optional[int] = None,
        outs_size: int = 2,
        annotations: Optional[List[DexAnnotation]] = None,
    ):
        self.class_type = class_type
        self.name = name
        self.return_type = return_type
        self.params = params or []
        self.access_flags = access_flags
        self.registers_size = registers_size
        self.outs_size = outs_size
        self.annotations = annotations or []
        self.instructions: List[Union[_Label, _Instruction]] = []

        if (self.access_flags & (ACC_STATIC | ACC_PRIVATE)) != 0 or self.name in ("<init>", "<clinit>"):
            self.is_direct = True
        else:
            self.is_direct = False

        if ins_size is None:
            this_reg = 0 if (self.access_flags & ACC_STATIC) else 1
            param_regs = sum(2 if p in ("J", "D") else 1 for p in self.params)
            self.ins_size = this_reg + param_regs
        else:
            self.ins_size = ins_size

        if self.registers_size < self.ins_size:
            self.registers_size = self.ins_size + 2

    def emit_label(self, name: str) -> None:
        self.instructions.append(_Label(name))

    def emit_nop(self) -> None:
        self.instructions.append(_Instruction("nop"))

    def emit_const_4(self, vx: int, lit4: int) -> None:
        if not (-8 <= lit4 <= 7):
            raise ValueError(f"lit4 {lit4} out of signed 4-bit range [-8, 7]; use emit_const_16")
        self.instructions.append(_Instruction("const_4", vx=vx, lit4=lit4))

    def emit_const_16(self, vx: int, lit16: int) -> None:
        self.instructions.append(_Instruction("const_16", vx=vx, lit16=lit16))

    def emit_const(self, vx: int, lit32: int) -> None:
        self.instructions.append(_Instruction("const", vx=vx, lit32=lit32))

    def emit_const_string(self, vx: int, string_val: str) -> None:
        self.instructions.append(_Instruction("const_string", vx=vx, string_val=string_val))

    def emit_return_void(self) -> None:
        self.instructions.append(_Instruction("return_void"))

    def emit_return(self, vx: int) -> None:
        self.instructions.append(_Instruction("return", vx=vx))

    def emit_return_object(self, vx: int) -> None:
        self.instructions.append(_Instruction("return_object", vx=vx))

    def emit_move(self, va: int, vb: int) -> None:
        self.instructions.append(_Instruction("format_12x", op=0x01, va=va, vb=vb))

    def emit_move_object(self, va: int, vb: int) -> None:
        self.instructions.append(_Instruction("format_12x", op=0x07, va=va, vb=vb))

    def emit_array_length(self, va: int, vb: int) -> None:
        self.instructions.append(_Instruction("format_12x", op=0x21, va=va, vb=vb))

    def emit_goto(self, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("goto", target=target))

    def emit_goto_16(self, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("goto_16", target=target))

    def emit_if_eq(self, va: int, vb: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_test", op=0x32, va=va, vb=vb, target=target))

    def emit_if_ne(self, va: int, vb: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_test", op=0x33, va=va, vb=vb, target=target))

    def emit_if_lt(self, va: int, vb: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_test", op=0x34, va=va, vb=vb, target=target))

    def emit_if_ge(self, va: int, vb: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_test", op=0x35, va=va, vb=vb, target=target))

    def emit_if_gt(self, va: int, vb: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_test", op=0x36, va=va, vb=vb, target=target))

    def emit_if_le(self, va: int, vb: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_test", op=0x37, va=va, vb=vb, target=target))

    def emit_if_eqz(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_testz", op=0x38, va=va, target=target))

    def emit_if_nez(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_testz", op=0x39, va=va, target=target))

    def emit_if_ltz(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_testz", op=0x3a, va=va, target=target))

    def emit_if_gez(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_testz", op=0x3b, va=va, target=target))

    def emit_if_gtz(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_testz", op=0x3c, va=va, target=target))

    def emit_if_lez(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("if_testz", op=0x3d, va=va, target=target))

    def emit_add_int(self, va: int, vb: int, vc: int) -> None:
        self.instructions.append(_Instruction("arith_23x", op=0x90, va=va, vb=vb, vc=vc))

    def emit_sub_int(self, va: int, vb: int, vc: int) -> None:
        self.instructions.append(_Instruction("arith_23x", op=0x91, va=va, vb=vb, vc=vc))

    def emit_mul_int(self, va: int, vb: int, vc: int) -> None:
        self.instructions.append(_Instruction("arith_23x", op=0x92, va=va, vb=vb, vc=vc))

    def emit_and_int(self, va: int, vb: int, vc: int) -> None:
        self.instructions.append(_Instruction("arith_23x", op=0x95, va=va, vb=vb, vc=vc))

    def emit_or_int(self, va: int, vb: int, vc: int) -> None:
        self.instructions.append(_Instruction("arith_23x", op=0x96, va=va, vb=vb, vc=vc))

    def emit_xor_int(self, va: int, vb: int, vc: int) -> None:
        self.instructions.append(_Instruction("arith_23x", op=0x97, va=va, vb=vb, vc=vc))

    def emit_add_int_lit8(self, va: int, vb: int, lit8: int) -> None:
        self.instructions.append(_Instruction("arith_lit8", op=0xd8, va=va, vb=vb, lit8=lit8))

    def emit_iget(self, va: int, vb: int, field_class: str, field_name: str, field_type: str) -> None:
        self.instructions.append(
            _Instruction("iget_iput", op=0x52, va=va, vb=vb, field_class=field_class, field_name=field_name, field_type=field_type)
        )

    def emit_iput(self, va: int, vb: int, field_class: str, field_name: str, field_type: str) -> None:
        self.instructions.append(
            _Instruction("iget_iput", op=0x59, va=va, vb=vb, field_class=field_class, field_name=field_name, field_type=field_type)
        )

    def emit_sget(self, va: int, field_class: str, field_name: str, field_type: str) -> None:
        self.instructions.append(
            _Instruction("sget_sput", op=0x60, va=va, field_class=field_class, field_name=field_name, field_type=field_type)
        )

    def emit_sput(self, va: int, field_class: str, field_name: str, field_type: str) -> None:
        self.instructions.append(
            _Instruction("sget_sput", op=0x67, va=va, field_class=field_class, field_name=field_name, field_type=field_type)
        )

    def emit_invoke_virtual(
        self,
        method_class: str,
        method_name: str,
        return_type: str,
        params: Optional[List[str]] = None,
        args: Optional[List[int]] = None,
    ) -> None:
        self.instructions.append(
            _Instruction("invoke", op=0x6e, method_class=method_class, method_name=method_name, return_type=return_type, params=params or [], args=args or [])
        )

    def emit_invoke_direct(
        self,
        method_class: str,
        method_name: str,
        return_type: str,
        params: Optional[List[str]] = None,
        args: Optional[List[int]] = None,
    ) -> None:
        self.instructions.append(
            _Instruction("invoke", op=0x70, method_class=method_class, method_name=method_name, return_type=return_type, params=params or [], args=args or [])
        )

    def emit_invoke_static(
        self,
        method_class: str,
        method_name: str,
        return_type: str,
        params: Optional[List[str]] = None,
        args: Optional[List[int]] = None,
    ) -> None:
        self.instructions.append(
            _Instruction("invoke", op=0x71, method_class=method_class, method_name=method_name, return_type=return_type, params=params or [], args=args or [])
        )

    def emit_packed_switch(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("switch", op=0x2b, va=va, target=target))

    def emit_sparse_switch(self, va: int, target: Union[str, int]) -> None:
        self.instructions.append(_Instruction("switch", op=0x2c, va=va, target=target))

    def emit_packed_switch_payload(
        self,
        first_key: int,
        targets: List[Union[str, int]],
        switch_inst_label: Optional[str] = None,
    ) -> None:
        self.instructions.append(
            _Instruction("packed_switch_payload", first_key=first_key, targets=targets, switch_inst_label=switch_inst_label)
        )

    def emit_sparse_switch_payload(
        self,
        keys: List[int],
        targets: List[Union[str, int]],
        switch_inst_label: Optional[str] = None,
    ) -> None:
        if len(keys) != len(targets):
            raise ValueError(f"Keys length ({len(keys)}) does not match targets length ({len(targets)})")
        sorted_pairs = sorted(zip(keys, targets), key=lambda p: p[0])
        sorted_keys = [p[0] for p in sorted_pairs]
        sorted_targets = [p[1] for p in sorted_pairs]
        self.instructions.append(
            _Instruction("sparse_switch_payload", keys=sorted_keys, targets=sorted_targets, switch_inst_label=switch_inst_label)
        )

    def emit_raw_words(self, words: List[int]) -> None:
        self.instructions.append(_Instruction("raw_words", words=words))

    def add_annotation(
        self,
        type_descriptor: str,
        visibility: int = VISIBILITY_RUNTIME,
        elements: Optional[List[Tuple[str, Any]]] = None,
    ) -> DexAnnotation:
        ann = DexAnnotation(type_descriptor, visibility, elements)
        self.annotations.append(ann)
        return ann


class DexClass:
    """Represents a Dalvik class definition."""

    def __init__(
        self,
        name: str,
        super_class: Optional[str] = "Ljava/lang/Object;",
        access_flags: int = ACC_PUBLIC,
        interfaces: Optional[List[str]] = None,
        source_file: Optional[str] = None,
    ):
        self.name = name
        self.super_class = super_class
        self.access_flags = access_flags
        self.interfaces = interfaces or []
        self.source_file = source_file
        self.fields: List[DexField] = []
        self.methods: List[DexMethod] = []
        self.annotations: List[DexAnnotation] = []

    def add_field(
        self,
        name: str,
        field_type: str,
        access_flags: int = ACC_PUBLIC,
        is_static: bool = False,
        initial_value: Optional[Any] = None,
        annotations: Optional[List[DexAnnotation]] = None,
    ) -> DexField:
        field = DexField(
            class_type=self.name,
            name=name,
            field_type=field_type,
            access_flags=access_flags,
            is_static=is_static,
            initial_value=initial_value,
            annotations=annotations,
        )
        self.fields.append(field)
        return field

    def add_method(
        self,
        name: str,
        return_type: str = "V",
        params: Optional[List[str]] = None,
        access_flags: int = ACC_PUBLIC,
        registers_size: int = 4,
        ins_size: Optional[int] = None,
        outs_size: int = 2,
        annotations: Optional[List[DexAnnotation]] = None,
    ) -> DexMethod:
        method = DexMethod(
            class_type=self.name,
            name=name,
            return_type=return_type,
            params=params,
            access_flags=access_flags,
            registers_size=registers_size,
            ins_size=ins_size,
            outs_size=outs_size,
            annotations=annotations,
        )
        self.methods.append(method)
        return method

    def add_annotation(
        self,
        type_descriptor: str,
        visibility: int = VISIBILITY_RUNTIME,
        elements: Optional[List[Tuple[str, Any]]] = None,
    ) -> DexAnnotation:
        ann = DexAnnotation(type_descriptor, visibility, elements)
        self.annotations.append(ann)
        return ann


def _encode_value(val: Any, s2i: Dict[str, int], t2i: Dict[str, int]) -> bytes:
    """Encodes a Python primitive value into Dalvik encoded_value binary format."""
    if val is None:
        return bytes([(0 << 5) | 0x1E])
    elif isinstance(val, bool):
        arg = 1 if val else 0
        return bytes([(arg << 5) | 0x1F])
    elif isinstance(val, int):
        if -128 <= val <= 127:
            return bytes([(0 << 5) | 0x04]) + struct.pack("<b", val)
        elif -32768 <= val <= 32767:
            return bytes([(1 << 5) | 0x04]) + struct.pack("<h", val)
        else:
            return bytes([(3 << 5) | 0x04]) + struct.pack("<i", val)
    elif isinstance(val, str):
        idx = s2i[val]
        if idx < 256:
            return bytes([(0 << 5) | 0x17, idx])
        elif idx < 65536:
            return bytes([(1 << 5) | 0x17]) + struct.pack("<H", idx)
        else:
            return bytes([(3 << 5) | 0x17]) + struct.pack("<I", idx)
    elif isinstance(val, tuple) and len(val) == 2 and val[0] == "type":
        idx = t2i[val[1]]
        if idx < 256:
            return bytes([(0 << 5) | 0x18, idx])
        elif idx < 65536:
            return bytes([(1 << 5) | 0x18]) + struct.pack("<H", idx)
        else:
            return bytes([(3 << 5) | 0x18]) + struct.pack("<I", idx)
    elif isinstance(val, list):
        res = bytearray()
        res += _encode_uleb128(len(val))
        for item in val:
            res += _encode_value(item, s2i, t2i)
        return bytes([(0 << 5) | 0x1C]) + res
    else:
        s_val = str(val)
        idx = s2i[s_val]
        return bytes([(0 << 5) | 0x17, idx])


class DexBuilder:
    """
    Pure-Python Dalvik DEX (version 035) bytecode builder.
    Generates spec-compliant DEX binary files with classes, methods, fields,
    interfaces, annotations, and Dalvik instruction bytecodes.
    """

    def __init__(self, version: str = "035"):
        self.version = version
        self.classes: List[DexClass] = []
        self._extra_strings: List[str] = []
        self._extra_types: List[str] = []
        self._extra_protos: List[Tuple[str, str, Tuple[str, ...]]] = []
        self._extra_fields: List[Tuple[str, str, str]] = []
        self._extra_methods: List[Tuple[str, str, str, Tuple[str, ...]]] = []

    def add_string(self, s: str) -> int:
        """Ensures a string is included in the string pool."""
        if s not in self._extra_strings:
            self._extra_strings.append(s)
        return 0

    def add_type(self, descriptor: str) -> int:
        """Ensures a type descriptor is included in the type table."""
        self.add_string(descriptor)
        if descriptor not in self._extra_types:
            self._extra_types.append(descriptor)
        return 0

    def add_proto(self, return_type: str, params: Optional[List[str]] = None) -> int:
        """Ensures a method prototype is included in the proto table."""
        p_list = params or []
        shorty = _make_shorty(return_type, p_list)
        self.add_string(shorty)
        self.add_type(return_type)
        for p in p_list:
            self.add_type(p)
        key = (shorty, return_type, tuple(p_list))
        if key not in self._extra_protos:
            self._extra_protos.append(key)
        return 0

    def add_field_id(self, class_type: str, name: str, field_type: str) -> int:
        """Ensures a field reference is included in the field table."""
        self.add_type(class_type)
        self.add_string(name)
        self.add_type(field_type)
        key = (class_type, name, field_type)
        if key not in self._extra_fields:
            self._extra_fields.append(key)
        return 0

    def add_method_id(
        self,
        class_type: str,
        name: str,
        return_type: str,
        params: Optional[List[str]] = None,
    ) -> int:
        """Ensures a method reference is included in the method table."""
        p_list = params or []
        self.add_type(class_type)
        self.add_string(name)
        self.add_proto(return_type, p_list)
        key = (class_type, name, return_type, tuple(p_list))
        if key not in self._extra_methods:
            self._extra_methods.append(key)
        return 0

    def create_class(
        self,
        name: str,
        super_class: Optional[str] = "Ljava/lang/Object;",
        access_flags: int = ACC_PUBLIC,
        interfaces: Optional[List[str]] = None,
        source_file: Optional[str] = None,
    ) -> DexClass:
        """Creates and attaches a new Dalvik class to this builder."""
        cls = DexClass(
            name=name,
            super_class=super_class,
            access_flags=access_flags,
            interfaces=interfaces,
            source_file=source_file,
        )
        self.classes.append(cls)
        return cls

    def build(self) -> bytes:
        """
        Assembles and serializes the complete Dalvik DEX file bytes.
        Computes SHA-1 signature and Adler-32 checksum.
        """
        # Step 1: Collect all strings, types, protos, fields, methods
        strings_set = set(self._extra_strings)
        types_set = set(self._extra_types)
        protos_set = set(self._extra_protos)
        fields_set = set(self._extra_fields)
        methods_set = set(self._extra_methods)

        for cls in self.classes:
            types_set.add(cls.name)
            strings_set.add(cls.name)
            if cls.super_class:
                types_set.add(cls.super_class)
                strings_set.add(cls.super_class)
            if cls.source_file:
                strings_set.add(cls.source_file)
            for iface in cls.interfaces:
                types_set.add(iface)
                strings_set.add(iface)

            # Class annotations
            for ann in cls.annotations:
                types_set.add(ann.type_descriptor)
                strings_set.add(ann.type_descriptor)
                for el_name, el_val in ann.elements:
                    strings_set.add(el_name)
                    if isinstance(el_val, str):
                        strings_set.add(el_val)
                    elif isinstance(el_val, tuple) and el_val[0] == "type":
                        types_set.add(el_val[1])
                        strings_set.add(el_val[1])

            # Fields
            for f in cls.fields:
                types_set.add(f.class_type)
                types_set.add(f.field_type)
                strings_set.add(f.class_type)
                strings_set.add(f.name)
                strings_set.add(f.field_type)
                fields_set.add((f.class_type, f.name, f.field_type))
                if isinstance(f.initial_value, str):
                    strings_set.add(f.initial_value)
                for ann in f.annotations:
                    types_set.add(ann.type_descriptor)
                    strings_set.add(ann.type_descriptor)
                    for el_name, el_val in ann.elements:
                        strings_set.add(el_name)
                        if isinstance(el_val, str):
                            strings_set.add(el_val)
                        elif isinstance(el_val, tuple) and el_val[0] == "type":
                            types_set.add(el_val[1])
                            strings_set.add(el_val[1])

            # Methods
            for m in cls.methods:
                types_set.add(m.class_type)
                types_set.add(m.return_type)
                strings_set.add(m.class_type)
                strings_set.add(m.name)
                strings_set.add(m.return_type)
                for p in m.params:
                    types_set.add(p)
                    strings_set.add(p)
                shorty = _make_shorty(m.return_type, m.params)
                strings_set.add(shorty)
                protos_set.add((shorty, m.return_type, tuple(m.params)))
                methods_set.add((m.class_type, m.name, m.return_type, tuple(m.params)))

                for ann in m.annotations:
                    types_set.add(ann.type_descriptor)
                    strings_set.add(ann.type_descriptor)
                    for el_name, el_val in ann.elements:
                        strings_set.add(el_name)
                        if isinstance(el_val, str):
                            strings_set.add(el_val)
                        elif isinstance(el_val, tuple) and el_val[0] == "type":
                            types_set.add(el_val[1])
                            strings_set.add(el_val[1])

                for item in m.instructions:
                    if isinstance(item, _Instruction):
                        if item.kind == "const_string":
                            strings_set.add(item.args["string_val"])
                        elif item.kind in ("iget_iput", "sget_sput"):
                            fc = item.args["field_class"]
                            fn = item.args["field_name"]
                            ft = item.args["field_type"]
                            types_set.add(fc)
                            strings_set.add(fc)
                            strings_set.add(fn)
                            types_set.add(ft)
                            strings_set.add(ft)
                            fields_set.add((fc, fn, ft))
                        elif item.kind == "invoke":
                            mc = item.args["method_class"]
                            mn = item.args["method_name"]
                            rt = item.args["return_type"]
                            params = item.args["params"]
                            types_set.add(mc)
                            strings_set.add(mc)
                            strings_set.add(mn)
                            types_set.add(rt)
                            strings_set.add(rt)
                            for p in params:
                                types_set.add(p)
                                strings_set.add(p)
                            ishorty = _make_shorty(rt, params)
                            strings_set.add(ishorty)
                            protos_set.add((ishorty, rt, tuple(params)))
                            methods_set.add((mc, mn, rt, tuple(params)))

        # Step 2: Sorting according to DEX spec
        unique_strings = sorted(list(strings_set))
        s2i = {s: i for i, s in enumerate(unique_strings)}

        unique_types = sorted(list(types_set), key=lambda t: s2i[t])
        t2i = {t: i for i, t in enumerate(unique_types)}

        unique_protos = sorted(
            list(protos_set),
            key=lambda p: (t2i[p[1]], tuple(t2i[param] for param in p[2]))
        )
        p2i = {p: i for i, p in enumerate(unique_protos)}

        unique_fields = sorted(
            list(fields_set),
            key=lambda f: (t2i[f[0]], s2i[f[1]], t2i[f[2]])
        )
        f2i = {f: i for i, f in enumerate(unique_fields)}

        unique_methods = sorted(
            list(methods_set),
            key=lambda m: (t2i[m[0]], s2i[m[1]], p2i[(_make_shorty(m[2], list(m[3])), m[2], m[3])])
        )
        m2i = {m: i for i, m in enumerate(unique_methods)}

        sorted_classes = sorted(self.classes, key=lambda c: t2i[c.name])

        # Step 3: Compute Table Offsets
        header_size = 0x70
        s_ids_off = header_size
        s_ids_size = len(unique_strings)

        t_ids_off = s_ids_off + s_ids_size * 4
        t_ids_size = len(unique_types)

        p_ids_off = t_ids_off + t_ids_size * 4
        p_ids_size = len(unique_protos)

        f_ids_off = p_ids_off + p_ids_size * 12
        f_ids_size = len(unique_fields)

        m_ids_off = f_ids_off + f_ids_size * 8
        m_ids_size = len(unique_methods)

        c_defs_off = m_ids_off + m_ids_size * 8
        c_defs_size = len(sorted_classes)

        data_off = c_defs_off + c_defs_size * 32
        data_buf = bytearray()

        def cur_off() -> int:
            return data_off + len(data_buf)

        def align(n: int = 4) -> None:
            while cur_off() % n != 0:
                data_buf.append(0)

        # Step 4: Serialize Data Section
        # 1. String data
        s_data_offsets = []
        for s in unique_strings:
            s_data_offsets.append(cur_off())
            raw = s.encode("utf-8")
            data_buf += _encode_uleb128(len(s)) + raw + b"\x00"

        align(4)

        # 2. Type lists
        proto_param_offsets: Dict[Tuple[str, str, Tuple[str, ...]], int] = {}
        for p in unique_protos:
            params = p[2]
            if not params:
                proto_param_offsets[p] = 0
            else:
                align(4)
                poff = cur_off()
                proto_param_offsets[p] = poff
                data_buf += struct.pack("<I", len(params))
                for param in params:
                    data_buf += struct.pack("<H", t2i[param])
                align(4)

        class_interfaces_offsets: Dict[DexClass, int] = {}
        for cls in sorted_classes:
            if not cls.interfaces:
                class_interfaces_offsets[cls] = 0
            else:
                align(4)
                ioff = cur_off()
                class_interfaces_offsets[cls] = ioff
                data_buf += struct.pack("<I", len(cls.interfaces))
                for iface in cls.interfaces:
                    data_buf += struct.pack("<H", t2i[iface])
                align(4)

        # 3. Annotations
        ann_item_offsets: Dict[DexAnnotation, int] = {}
        all_annotations: List[DexAnnotation] = []
        for cls in sorted_classes:
            all_annotations.extend(cls.annotations)
            for f in cls.fields:
                all_annotations.extend(f.annotations)
            for m in cls.methods:
                all_annotations.extend(m.annotations)

        for ann in all_annotations:
            if ann in ann_item_offsets:
                continue
            align(4)
            a_off = cur_off()
            ann_item_offsets[ann] = a_off
            data_buf += bytes([ann.visibility])
            data_buf += _encode_uleb128(t2i[ann.type_descriptor])
            data_buf += _encode_uleb128(len(ann.elements))
            for el_name, el_val in ann.elements:
                data_buf += _encode_uleb128(s2i[el_name])
                data_buf += _encode_value(el_val, s2i, t2i)
            align(4)

        class_annotations_dir_offsets: Dict[DexClass, int] = {}
        for cls in sorted_classes:
            has_class_ann = bool(cls.annotations)
            fields_with_ann = [f for f in cls.fields if f.annotations]
            methods_with_ann = [m for m in cls.methods if m.annotations]

            if not has_class_ann and not fields_with_ann and not methods_with_ann:
                class_annotations_dir_offsets[cls] = 0
                continue

            class_set_off = 0
            if has_class_ann:
                align(4)
                class_set_off = cur_off()
                data_buf += struct.pack("<I", len(cls.annotations))
                for ann in cls.annotations:
                    data_buf += struct.pack("<I", ann_item_offsets[ann])

            field_entries = []
            for f in fields_with_ann:
                align(4)
                f_set_off = cur_off()
                data_buf += struct.pack("<I", len(f.annotations))
                for ann in f.annotations:
                    data_buf += struct.pack("<I", ann_item_offsets[ann])
                f_idx = f2i[(f.class_type, f.name, f.field_type)]
                field_entries.append((f_idx, f_set_off))
            field_entries.sort(key=lambda x: x[0])

            method_entries = []
            for m in methods_with_ann:
                align(4)
                m_set_off = cur_off()
                data_buf += struct.pack("<I", len(m.annotations))
                for ann in m.annotations:
                    data_buf += struct.pack("<I", ann_item_offsets[ann])
                m_idx = m2i[(m.class_type, m.name, m.return_type, tuple(m.params))]
                method_entries.append((m_idx, m_set_off))
            method_entries.sort(key=lambda x: x[0])

            align(4)
            dir_off = cur_off()
            class_annotations_dir_offsets[cls] = dir_off
            data_buf += struct.pack(
                "<IIII",
                class_set_off,
                len(field_entries),
                len(method_entries),
                0,
            )
            for f_idx, f_off in field_entries:
                data_buf += struct.pack("<II", f_idx, f_off)
            for m_idx, m_off in method_entries:
                data_buf += struct.pack("<II", m_idx, m_off)
            align(4)

        # 4. Static values
        class_static_values_offsets: Dict[DexClass, int] = {}
        for cls in sorted_classes:
            static_fields = [f for f in cls.fields if f.is_static]
            last_init_idx = -1
            for idx, f in enumerate(static_fields):
                if f.initial_value is not None:
                    last_init_idx = idx

            if last_init_idx == -1:
                class_static_values_offsets[cls] = 0
            else:
                align(4)
                sv_off = cur_off()
                class_static_values_offsets[cls] = sv_off
                vals = []
                for i in range(last_init_idx + 1):
                    vals.append(static_fields[i].initial_value)
                data_buf += _encode_uleb128(len(vals))
                for v in vals:
                    data_buf += _encode_value(v, s2i, t2i)
                align(4)

        # 5. Code items
        method_code_offsets: Dict[DexMethod, int] = {}
        for cls in sorted_classes:
            for m in cls.methods:
                if (m.access_flags & (ACC_NATIVE | ACC_ABSTRACT)) != 0:
                    method_code_offsets[m] = 0
                    continue

                cur_pc = 0
                label_pcs: Dict[str, int] = {}
                for idx, item in enumerate(m.instructions):
                    if isinstance(item, _Label):
                        next_inst = None
                        for future_item in m.instructions[idx + 1:]:
                            if isinstance(future_item, _Instruction):
                                next_inst = future_item
                                break
                        if next_inst and next_inst.kind in ("packed_switch_payload", "sparse_switch_payload"):
                            if cur_pc % 2 != 0:
                                cur_pc += 1
                        label_pcs[item.name] = cur_pc
                    elif isinstance(item, _Instruction):
                        if item.kind in ("packed_switch_payload", "sparse_switch_payload"):
                            if cur_pc % 2 != 0:
                                cur_pc += 1
                            if item.kind == "packed_switch_payload":
                                cur_pc += 4 + 2 * len(item.args["targets"])
                            else:
                                cur_pc += 2 + 4 * len(item.args["keys"])
                        else:
                            cur_pc += item.size_words()

                words: List[int] = []
                cur_pc = 0
                last_switch_pc = 0

                def _resolve_target(target: Union[str, int], current_pc: int) -> int:
                    if isinstance(target, int):
                        return target
                    if target not in label_pcs:
                        raise ValueError(f"Label '{target}' referenced in method '{m.name}' was never defined")
                    return label_pcs[target] - current_pc

                for item in m.instructions:
                    if isinstance(item, _Label):
                        continue
                    elif isinstance(item, _Instruction):
                        k = item.kind
                        if k == "nop":
                            words.append(0x0000)
                            cur_pc += 1
                        elif k == "format_12x":
                            op = item.args["op"]
                            va = item.args["va"]
                            vb = item.args["vb"]
                            words.append(((vb & 0x0F) << 12) | ((va & 0x0F) << 8) | op)
                            cur_pc += 1
                        elif k == "const_4":
                            vx = item.args["vx"]
                            lit4 = item.args["lit4"]
                            if not (-8 <= lit4 <= 7):
                                raise ValueError(f"lit4 {lit4} out of signed 4-bit range [-8, 7]; use emit_const_16")
                            lit4_val = lit4 & 0x0F
                            words.append((lit4_val << 12) | ((vx & 0x0F) << 8) | 0x12)
                            cur_pc += 1
                        elif k == "const_16":
                            vx = item.args["vx"]
                            lit16 = item.args["lit16"] & 0xFFFF
                            words.append(((vx & 0xFF) << 8) | 0x13)
                            words.append(lit16)
                            cur_pc += 2
                        elif k == "const":
                            vx = item.args["vx"]
                            lit32 = item.args["lit32"] & 0xFFFFFFFF
                            words.append(((vx & 0xFF) << 8) | 0x14)
                            words.append(lit32 & 0xFFFF)
                            words.append((lit32 >> 16) & 0xFFFF)
                            cur_pc += 3
                        elif k == "const_string":
                            vx = item.args["vx"]
                            str_idx = s2i[item.args["string_val"]]
                            words.append(((vx & 0xFF) << 8) | 0x1A)
                            words.append(str_idx & 0xFFFF)
                            cur_pc += 2
                        elif k == "return_void":
                            words.append(0x000E)
                            cur_pc += 1
                        elif k == "return":
                            vx = item.args["vx"]
                            words.append(((vx & 0xFF) << 8) | 0x0F)
                            cur_pc += 1
                        elif k == "return_object":
                            vx = item.args["vx"]
                            words.append(((vx & 0xFF) << 8) | 0x11)
                            cur_pc += 1
                        elif k == "goto":
                            t = item.args["target"]
                            t_offset = _resolve_target(t, cur_pc)
                            if not (-128 <= t_offset <= 127):
                                raise ValueError(f"goto branch offset {t_offset} in method '{m.name}' exceeds 8-bit range (-128..127); use goto_16")
                            words.append(((t_offset & 0xFF) << 8) | 0x28)
                            cur_pc += 1
                        elif k == "goto_16":
                            t = item.args["target"]
                            t_offset = _resolve_target(t, cur_pc)
                            if not (-32768 <= t_offset <= 32767):
                                raise ValueError(f"goto_16 branch offset {t_offset} in method '{m.name}' exceeds 16-bit range (-32768..32767)")
                            words.append(0x0029)
                            words.append(t_offset & 0xFFFF)
                            cur_pc += 2
                        elif k == "if_test":
                            op = item.args["op"]
                            va = item.args["va"]
                            vb = item.args["vb"]
                            t = item.args["target"]
                            t_offset = _resolve_target(t, cur_pc)
                            if not (-32768 <= t_offset <= 32767):
                                raise ValueError(f"Conditional branch offset {t_offset} in method '{m.name}' exceeds 16-bit range (-32768..32767)")
                            words.append(((vb & 0x0F) << 12) | ((va & 0x0F) << 8) | op)
                            words.append(t_offset & 0xFFFF)
                            cur_pc += 2
                        elif k == "if_testz":
                            op = item.args["op"]
                            va = item.args["va"]
                            t = item.args["target"]
                            t_offset = _resolve_target(t, cur_pc)
                            if not (-32768 <= t_offset <= 32767):
                                raise ValueError(f"Conditional branch offset {t_offset} in method '{m.name}' exceeds 16-bit range (-32768..32767)")
                            words.append(((va & 0xFF) << 8) | op)
                            words.append(t_offset & 0xFFFF)
                            cur_pc += 2
                        elif k == "arith_23x":
                            op = item.args["op"]
                            va = item.args["va"]
                            vb = item.args["vb"]
                            vc = item.args["vc"]
                            words.append(((va & 0xFF) << 8) | op)
                            words.append(((vc & 0xFF) << 8) | (vb & 0xFF))
                            cur_pc += 2
                        elif k == "arith_lit8":
                            op = item.args["op"]
                            va = item.args["va"]
                            vb = item.args["vb"]
                            lit8 = item.args["lit8"] & 0xFF
                            words.append(((va & 0xFF) << 8) | op)
                            words.append((lit8 << 8) | (vb & 0xFF))
                            cur_pc += 2
                        elif k == "iget_iput":
                            op = item.args["op"]
                            va = item.args["va"]
                            vb = item.args["vb"]
                            fc = item.args["field_class"]
                            fn = item.args["field_name"]
                            ft = item.args["field_type"]
                            f_idx = f2i[(fc, fn, ft)]
                            words.append(((vb & 0x0F) << 12) | ((va & 0x0F) << 8) | op)
                            words.append(f_idx & 0xFFFF)
                            cur_pc += 2
                        elif k == "sget_sput":
                            op = item.args["op"]
                            va = item.args["va"]
                            fc = item.args["field_class"]
                            fn = item.args["field_name"]
                            ft = item.args["field_type"]
                            f_idx = f2i[(fc, fn, ft)]
                            words.append(((va & 0xFF) << 8) | op)
                            words.append(f_idx & 0xFFFF)
                            cur_pc += 2
                        elif k == "invoke":
                            op = item.args["op"]
                            mc = item.args["method_class"]
                            mn = item.args["method_name"]
                            rt = item.args["return_type"]
                            params = item.args["params"]
                            args = item.args["args"]
                            m_idx = m2i[(mc, mn, rt, tuple(params))]
                            count_a = len(args)
                            reg_g = args[4] if count_a == 5 else 0
                            words.append((count_a << 12) | ((reg_g & 0x0F) << 8) | op)
                            words.append(m_idx & 0xFFFF)
                            c = args[0] if count_a >= 1 else 0
                            d = args[1] if count_a >= 2 else 0
                            e = args[2] if count_a >= 3 else 0
                            f = args[3] if count_a >= 4 else 0
                            words.append(((f & 0x0F) << 12) | ((e & 0x0F) << 8) | ((d & 0x0F) << 4) | (c & 0x0F))
                            cur_pc += 3
                        elif k == "switch":
                            last_switch_pc = cur_pc
                            op = item.args["op"]
                            va = item.args["va"]
                            t = item.args["target"]
                            t_offset = _resolve_target(t, cur_pc)
                            if not (-2147483648 <= t_offset <= 2147483647):
                                raise ValueError(f"Switch offset {t_offset} in method '{m.name}' exceeds 32-bit range")
                            words.append(((va & 0xFF) << 8) | op)
                            words.append(t_offset & 0xFFFF)
                            words.append((t_offset >> 16) & 0xFFFF)
                            cur_pc += 3
                        elif k == "packed_switch_payload":
                            if cur_pc % 2 != 0:
                                words.append(0x0000)
                                cur_pc += 1
                            sw_label = item.args["switch_inst_label"]
                            if sw_label:
                                if sw_label not in label_pcs:
                                    raise ValueError(f"Label '{sw_label}' referenced in method '{m.name}' was never defined")
                                sw_pc = label_pcs[sw_label]
                            else:
                                sw_pc = last_switch_pc
                            targets = item.args["targets"]
                            words.append(0x0100)
                            words.append(len(targets) & 0xFFFF)
                            fk = item.args["first_key"] & 0xFFFFFFFF
                            words.append(fk & 0xFFFF)
                            words.append((fk >> 16) & 0xFFFF)
                            for t in targets:
                                rel_target = _resolve_target(t, sw_pc)
                                rel_target &= 0xFFFFFFFF
                                words.append(rel_target & 0xFFFF)
                                words.append((rel_target >> 16) & 0xFFFF)
                            cur_pc += 4 + 2 * len(targets)
                        elif k == "sparse_switch_payload":
                            if cur_pc % 2 != 0:
                                words.append(0x0000)
                                cur_pc += 1
                            sw_label = item.args["switch_inst_label"]
                            if sw_label:
                                if sw_label not in label_pcs:
                                    raise ValueError(f"Label '{sw_label}' referenced in method '{m.name}' was never defined")
                                sw_pc = label_pcs[sw_label]
                            else:
                                sw_pc = last_switch_pc
                            keys = item.args["keys"]
                            targets = item.args["targets"]
                            sorted_pairs = sorted(zip(keys, targets), key=lambda p: p[0])
                            keys = [p[0] for p in sorted_pairs]
                            targets = [p[1] for p in sorted_pairs]
                            words.append(0x0200)
                            words.append(len(keys) & 0xFFFF)
                            for key in keys:
                                k32 = key & 0xFFFFFFFF
                                words.append(k32 & 0xFFFF)
                                words.append((k32 >> 16) & 0xFFFF)
                            for t in targets:
                                rel_target = _resolve_target(t, sw_pc)
                                rel_target &= 0xFFFFFFFF
                                words.append(rel_target & 0xFFFF)
                                words.append((rel_target >> 16) & 0xFFFF)
                            cur_pc += 2 + 4 * len(keys)
                        elif k == "raw_words":
                            for w in item.args["words"]:
                                words.append(w & 0xFFFF)
                                cur_pc += 1

                align(4)
                code_off = cur_off()
                method_code_offsets[m] = code_off
                insns_bytes = struct.pack(f"<{len(words)}H", *words)
                data_buf += struct.pack(
                    "<HHHHII",
                    m.registers_size,
                    m.ins_size,
                    m.outs_size,
                    0,
                    0,
                    len(words),
                )
                data_buf += insns_bytes

        # 6. Class data items
        class_data_offsets: Dict[DexClass, int] = {}
        for cls in sorted_classes:
            static_fields = sorted([f for f in cls.fields if f.is_static], key=lambda f: f2i[(f.class_type, f.name, f.field_type)])
            instance_fields = sorted([f for f in cls.fields if not f.is_static], key=lambda f: f2i[(f.class_type, f.name, f.field_type)])
            direct_methods = sorted([m for m in cls.methods if m.is_direct], key=lambda m: m2i[(m.class_type, m.name, m.return_type, tuple(m.params))])
            virtual_methods = sorted([m for m in cls.methods if not m.is_direct], key=lambda m: m2i[(m.class_type, m.name, m.return_type, tuple(m.params))])

            if not static_fields and not instance_fields and not direct_methods and not virtual_methods:
                class_data_offsets[cls] = 0
                continue

            align(1)
            cdata_off = cur_off()
            class_data_offsets[cls] = cdata_off

            cdata = bytearray()
            cdata += _encode_uleb128(len(static_fields))
            cdata += _encode_uleb128(len(instance_fields))
            cdata += _encode_uleb128(len(direct_methods))
            cdata += _encode_uleb128(len(virtual_methods))

            prev_idx = 0
            for f in static_fields:
                f_idx = f2i[(f.class_type, f.name, f.field_type)]
                cdata += _encode_uleb128(f_idx - prev_idx)
                cdata += _encode_uleb128(f.access_flags)
                prev_idx = f_idx

            prev_idx = 0
            for f in instance_fields:
                f_idx = f2i[(f.class_type, f.name, f.field_type)]
                cdata += _encode_uleb128(f_idx - prev_idx)
                cdata += _encode_uleb128(f.access_flags)
                prev_idx = f_idx

            prev_idx = 0
            for m in direct_methods:
                m_idx = m2i[(m.class_type, m.name, m.return_type, tuple(m.params))]
                cdata += _encode_uleb128(m_idx - prev_idx)
                cdata += _encode_uleb128(m.access_flags)
                cdata += _encode_uleb128(method_code_offsets.get(m, 0))
                prev_idx = m_idx

            prev_idx = 0
            for m in virtual_methods:
                m_idx = m2i[(m.class_type, m.name, m.return_type, tuple(m.params))]
                cdata += _encode_uleb128(m_idx - prev_idx)
                cdata += _encode_uleb128(m.access_flags)
                cdata += _encode_uleb128(method_code_offsets.get(m, 0))
                prev_idx = m_idx

            data_buf += cdata

        # 7. Map List
        align(4)
        map_off = cur_off()
        map_items = [
            (0x0000, 1, 0),
            (0x0001, s_ids_size, s_ids_off),
            (0x0002, t_ids_size, t_ids_off),
            (0x0003, p_ids_size, p_ids_off),
            (0x0004, f_ids_size, f_ids_off),
            (0x0005, m_ids_size, m_ids_off),
            (0x0006, c_defs_size, c_defs_off),
        ]

        if s_ids_size > 0:
            map_items.append((0x2002, s_ids_size, s_data_offsets[0]))

        tl_count = sum(1 for p in unique_protos if p[2]) + sum(1 for c in sorted_classes if c.interfaces)
        if tl_count > 0:
            first_tl_off = min(
                [proto_param_offsets[p] for p in unique_protos if proto_param_offsets[p] > 0] +
                [class_interfaces_offsets[c] for c in sorted_classes if class_interfaces_offsets[c] > 0]
            )
            map_items.append((0x1001, tl_count, first_tl_off))

        if all_annotations:
            first_ann_off = min(ann_item_offsets.values())
            map_items.append((0x2004, len(ann_item_offsets), first_ann_off))

        cd_count = len([c for c in sorted_classes if class_data_offsets.get(c, 0) > 0])
        if cd_count > 0:
            first_cd = min(class_data_offsets[c] for c in sorted_classes if class_data_offsets[c] > 0)
            map_items.append((0x2000, cd_count, first_cd))

        code_count = len([m for c in sorted_classes for m in c.methods if method_code_offsets.get(m, 0) > 0])
        if code_count > 0:
            first_code = min(method_code_offsets[m] for c in sorted_classes for m in c.methods if method_code_offsets[m] > 0)
            map_items.append((0x2001, code_count, first_code))

        map_items.append((0x1000, 1, map_off))
        map_items.sort(key=lambda x: x[2])

        data_buf += struct.pack("<I", len(map_items))
        for itype, isize, ioff in map_items:
            data_buf += struct.pack("<HHII", itype, 0, isize, ioff)

        file_size = data_off + len(data_buf)
        data_size = len(data_buf)

        # Step 5: Serialize Tables
        s_ids_table = bytearray()
        for soff in s_data_offsets:
            s_ids_table += struct.pack("<I", soff)

        t_ids_table = bytearray()
        for t in unique_types:
            t_ids_table += struct.pack("<I", s2i[t])

        p_ids_table = bytearray()
        for p in unique_protos:
            p_ids_table += struct.pack("<III", s2i[p[0]], t2i[p[1]], proto_param_offsets[p])

        f_ids_table = bytearray()
        for f in unique_fields:
            f_ids_table += struct.pack("<HHI", t2i[f[0]], t2i[f[2]], s2i[f[1]])

        m_ids_table = bytearray()
        for m in unique_methods:
            proto_key = (_make_shorty(m[2], list(m[3])), m[2], m[3])
            m_ids_table += struct.pack("<HHI", t2i[m[0]], p2i[proto_key], s2i[m[1]])

        c_defs_table = bytearray()
        for cls in sorted_classes:
            c_idx = t2i[cls.name]
            super_idx = t2i[cls.super_class] if cls.super_class else 0xFFFFFFFF
            ifaces_off = class_interfaces_offsets.get(cls, 0)
            src_idx = s2i[cls.source_file] if cls.source_file else 0xFFFFFFFF
            ann_off = class_annotations_dir_offsets.get(cls, 0)
            cdata_off = class_data_offsets.get(cls, 0)
            sv_off = class_static_values_offsets.get(cls, 0)

            c_defs_table += struct.pack(
                "<IIIIIIII",
                c_idx,
                cls.access_flags,
                super_idx,
                ifaces_off,
                src_idx,
                ann_off,
                cdata_off,
                sv_off,
            )

        header = bytearray(header_size)
        magic = f"dex\n{self.version}\x00".encode("ascii")
        header[0:8] = magic
        struct.pack_into("<I", header, 0x20, file_size)
        struct.pack_into("<I", header, 0x24, header_size)
        struct.pack_into("<I", header, 0x28, 0x12345678)
        struct.pack_into("<I", header, 0x34, map_off)
        struct.pack_into("<I", header, 0x38, s_ids_size)
        struct.pack_into("<I", header, 0x3C, s_ids_off)
        struct.pack_into("<I", header, 0x40, t_ids_size)
        struct.pack_into("<I", header, 0x44, t_ids_off)
        struct.pack_into("<I", header, 0x48, p_ids_size)
        struct.pack_into("<I", header, 0x4C, p_ids_off)
        struct.pack_into("<I", header, 0x50, f_ids_size)
        struct.pack_into("<I", header, 0x54, f_ids_off)
        struct.pack_into("<I", header, 0x58, m_ids_size)
        struct.pack_into("<I", header, 0x5C, m_ids_off)
        struct.pack_into("<I", header, 0x60, c_defs_size)
        struct.pack_into("<I", header, 0x64, c_defs_off)
        struct.pack_into("<I", header, 0x68, data_size)
        struct.pack_into("<I", header, 0x6C, data_off)

        full_payload = bytearray(
            header +
            s_ids_table +
            t_ids_table +
            p_ids_table +
            f_ids_table +
            m_ids_table +
            c_defs_table +
            data_buf
        )

        sha1 = hashlib.sha1(bytes(full_payload[32:])).digest()
        full_payload[12:32] = sha1

        adler = zlib.adler32(bytes(full_payload[12:])) & 0xFFFFFFFF
        struct.pack_into("<I", full_payload, 8, adler)

        return bytes(full_payload)


# ---------------------------------------------------------------------------
# High-Level Synthetic DEX and APK Fixture Generators
# ---------------------------------------------------------------------------

def synthesize_cfg_branch_dex() -> bytes:
    """
    Synthesizes a Dalvik DEX file containing diverse control flow structures:
    - branchGateSimple: conditional if-eq gate
    - branchAllConditions: cascaded if-ne, if-lt, if-ge, if-gt, if-le, if-eqz, if-nez
    - loopCounter: loop with backward jump back-edge
    - nestedLoops: two nested loops
    - switchDispatch: packed-switch with aligned payload table
    - sparseSwitchDispatch: sparse-switch with aligned payload table
    """
    b = DexBuilder()
    cls = b.create_class("Lcom/example/BranchGateTest;")

    # 1. branchGateSimple(II)I
    m = cls.add_method("branchGateSimple", return_type="I", params=["I", "I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m.emit_if_eq(va=2, vb=3, target="true_target")
    m.emit_const_4(vx=0, lit4=0)
    m.emit_return(vx=0)
    m.emit_label("true_target")
    m.emit_const_4(vx=0, lit4=1)
    m.emit_return(vx=0)

    # 2. branchAllConditions(II)I
    m = cls.add_method("branchAllConditions", return_type="I", params=["I", "I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m.emit_if_ne(va=2, vb=3, target="c1")
    m.emit_return(vx=2)
    m.emit_label("c1")
    m.emit_if_lt(va=2, vb=3, target="c2")
    m.emit_return(vx=3)
    m.emit_label("c2")
    m.emit_if_ge(va=2, vb=3, target="c3")
    m.emit_return(vx=2)
    m.emit_label("c3")
    m.emit_if_gt(va=2, vb=3, target="c4")
    m.emit_return(vx=3)
    m.emit_label("c4")
    m.emit_if_le(va=2, vb=3, target="c5")
    m.emit_return(vx=2)
    m.emit_label("c5")
    m.emit_if_eqz(va=2, target="c6")
    m.emit_return(vx=3)
    m.emit_label("c6")
    m.emit_if_nez(va=3, target="c_end")
    m.emit_return(vx=2)
    m.emit_label("c_end")
    m.emit_const_4(vx=0, lit4=0)
    m.emit_return(vx=0)

    # 3. loopCounter(I)I
    m = cls.add_method("loopCounter", return_type="I", params=["I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m.emit_const_4(vx=0, lit4=0)
    m.emit_label("loop_head")
    m.emit_if_lez(va=3, target="loop_exit")
    m.emit_add_int_lit8(va=0, vb=0, lit8=1)
    m.emit_add_int_lit8(va=3, vb=3, lit8=-1)
    m.emit_goto(target="loop_head")
    m.emit_label("loop_exit")
    m.emit_return(vx=0)

    # 4. nestedLoops(II)I
    m = cls.add_method("nestedLoops", return_type="I", params=["I", "I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m.emit_const_4(vx=0, lit4=0)
    m.emit_label("outer_loop")
    m.emit_if_lez(va=2, target="end_outer")
    m.emit_label("inner_loop")
    m.emit_if_lez(va=3, target="end_inner")
    m.emit_add_int_lit8(va=0, vb=0, lit8=1)
    m.emit_add_int_lit8(va=3, vb=3, lit8=-1)
    m.emit_goto(target="inner_loop")
    m.emit_label("end_inner")
    m.emit_add_int_lit8(va=2, vb=2, lit8=-1)
    m.emit_goto(target="outer_loop")
    m.emit_label("end_outer")
    m.emit_return(vx=0)

    # 5. switchDispatch(I)I
    m = cls.add_method("switchDispatch", return_type="I", params=["I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m.emit_packed_switch(va=3, target="payload")
    m.emit_label("def_case")
    m.emit_const_4(vx=0, lit4=0)
    m.emit_return(vx=0)
    m.emit_label("c_0")
    m.emit_const_16(vx=0, lit16=10)
    m.emit_return(vx=0)
    m.emit_label("c_1")
    m.emit_const_16(vx=0, lit16=20)
    m.emit_return(vx=0)
    m.emit_label("payload")
    m.emit_packed_switch_payload(first_key=0, targets=["c_0", "c_1"])

    # 6. sparseSwitchDispatch(I)I
    m = cls.add_method("sparseSwitchDispatch", return_type="I", params=["I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m.emit_sparse_switch(va=3, target="sparse_payload")
    m.emit_label("sparse_def")
    m.emit_const_4(vx=0, lit4=0)
    m.emit_return(vx=0)
    m.emit_label("sc_100")
    m.emit_const_4(vx=0, lit4=1)
    m.emit_return(vx=0)
    m.emit_label("sc_500")
    m.emit_const_4(vx=0, lit4=2)
    m.emit_return(vx=0)
    m.emit_label("sparse_payload")
    m.emit_sparse_switch_payload(keys=[100, 500], targets=["sc_100", "sc_500"])

    return b.build()


def create_cfg_branch_dex(output_path: Union[str, Path]) -> Path:
    """Writes synthesized CFG branch DEX file to output_path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(synthesize_cfg_branch_dex())
    return out


def synthesize_rich_class_dex() -> bytes:
    """
    Synthesizes a Dalvik DEX file containing a rich class definition:
    - Class: Lcom/example/rich/SecureModel;
    - Interfaces: Serializable, Comparable, Authenticatable
    - Fields:
      * mId: I (ACC_PRIVATE)
      * mName: Ljava/lang/String; (ACC_PRIVATE, @EncryptedField)
      * IS_ACTIVE: Z (ACC_PUBLIC | ACC_STATIC | ACC_FINAL, initial_value=True)
      * KEY_BYTES: [B (ACC_PROTECTED | ACC_STATIC)
    - Annotations:
      * Class annotation @Secured(level="HIGH")
      * Method annotation @NonNull on authenticate(Ljava/lang/String;)Z
    """
    b = DexBuilder()
    cls = b.create_class(
        name="Lcom/example/rich/SecureModel;",
        super_class="Ljava/lang/Object;",
        access_flags=ACC_PUBLIC,
        interfaces=[
            "Ljava/io/Serializable;",
            "Ljava/lang/Comparable;",
            "Lcom/example/rich/Authenticatable;",
        ],
        source_file="SecureModel.java",
    )
    cls.add_annotation("Lcom/example/rich/Secured;", visibility=VISIBILITY_RUNTIME, elements=[("level", "HIGH")])

    cls.add_field("mId", "I", access_flags=ACC_PRIVATE)
    f_name = cls.add_field("mName", "Ljava/lang/String;", access_flags=ACC_PRIVATE)
    f_name.add_annotation("Lcom/example/rich/EncryptedField;", visibility=VISIBILITY_RUNTIME)

    cls.add_field(
        "IS_ACTIVE",
        "Z",
        access_flags=ACC_PUBLIC | ACC_STATIC | ACC_FINAL,
        initial_value=True,
    )
    cls.add_field("KEY_BYTES", "[B", access_flags=ACC_PROTECTED | ACC_STATIC)

    m = cls.add_method("authenticate", return_type="Z", params=["Ljava/lang/String;"], access_flags=ACC_PUBLIC)
    m.add_annotation("Landroid/annotation/NonNull;", visibility=VISIBILITY_RUNTIME)
    m.emit_const_4(vx=0, lit4=1)
    m.emit_return(vx=0)

    return b.build()


def create_rich_class_dex(output_path: Union[str, Path]) -> Path:
    """Writes synthesized rich class DEX file to output_path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(synthesize_rich_class_dex())
    return out


def synthesize_decompile_test_dex() -> bytes:
    """
    Synthesizes a Dalvik DEX file with methods structured for pseudo-Java decompilation:
    - getter(): iget v0, p0, mId; return v0; -> "return this.mId;"
    - setter(int): iput p1, p0, mId; return-void; -> "this.mId = p1;"
    - max(int, int): if-le p0, p1, +2; return p0; return p1; -> "if (p0 > p1) return p0; return p1;"
    - add(int, int): add-int v0, p0, p1; return v0; -> "return p0 + p1;"
    """
    b = DexBuilder()
    cls = b.create_class("Lcom/example/decompile/DecompileTarget;")
    cls.add_field("mId", "I", access_flags=ACC_PRIVATE)

    # 1. getter
    m1 = cls.add_method("getter", return_type="I", access_flags=ACC_PUBLIC)
    m1.emit_iget(va=0, vb=1, field_class="Lcom/example/decompile/DecompileTarget;", field_name="mId", field_type="I")
    m1.emit_return(vx=0)

    # 2. setter
    m2 = cls.add_method("setter", return_type="V", params=["I"], access_flags=ACC_PUBLIC)
    m2.emit_iput(va=2, vb=1, field_class="Lcom/example/decompile/DecompileTarget;", field_name="mId", field_type="I")
    m2.emit_return_void()

    # 3. max
    m3 = cls.add_method("max", return_type="I", params=["I", "I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m3.emit_if_le(va=2, vb=3, target="else_lbl")
    m3.emit_return(vx=2)
    m3.emit_label("else_lbl")
    m3.emit_return(vx=3)

    # 4. add
    m4 = cls.add_method("add", return_type="I", params=["I", "I"], access_flags=ACC_PUBLIC | ACC_STATIC)
    m4.emit_add_int(va=0, vb=2, vc=3)
    m4.emit_return(vx=0)

    return b.build()


def create_decompile_test_dex(output_path: Union[str, Path]) -> Path:
    """Writes synthesized decompile test DEX file to output_path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(synthesize_decompile_test_dex())
    return out


def synthesize_corrupted_dex(corruption_type: str = "bad_magic") -> bytes:
    """
    Generates an invalid/corrupted Dalvik DEX buffer for boundary testing:
    - "bad_magic": magic is "dex\n999\0"
    - "bad_checksum": inverted Adler-32
    - "bad_signature": zeroed SHA-1 signature
    - "truncated": truncated to 64 bytes
    - "bad_endian": endian_tag = 0
    - "oob_map_off": map_off set to 0x7FFFFFFF
    """
    valid_dex = synthesize_empty_dex()
    corrupted = bytearray(valid_dex)

    if corruption_type == "bad_magic":
        corrupted[0:8] = b"BADMAGIC"
    elif corruption_type == "bad_checksum":
        orig_chk = struct.unpack_from("<I", corrupted, 8)[0]
        struct.pack_into("<I", corrupted, 8, orig_chk ^ 0xFFFFFFFF)
    elif corruption_type == "bad_signature":
        corrupted[12:32] = b"\x00" * 20
    elif corruption_type == "truncated":
        return bytes(corrupted[:64])
    elif corruption_type == "bad_endian":
        struct.pack_into("<I", corrupted, 0x28, 0x00000000)
    elif corruption_type == "oob_map_off":
        struct.pack_into("<I", corrupted, 0x34, 0x7FFFFFFF)
    else:
        raise ValueError(f"Unknown corruption_type: {corruption_type}")

    return bytes(corrupted)


def create_corrupted_dex(output_path: Union[str, Path], corruption_type: str = "bad_magic") -> Path:
    """Writes corrupted DEX fixture to output_path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(synthesize_corrupted_dex(corruption_type=corruption_type))
    return out


def synthesize_empty_dex() -> bytes:
    """Synthesizes a minimal valid Dalvik DEX file with 0 classes and 0 strings."""
    b = DexBuilder()
    return b.build()


def create_empty_dex(output_path: Union[str, Path]) -> Path:
    """Writes minimal empty DEX to output_path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(synthesize_empty_dex())
    return out


def synthesize_token_stress_dex(class_count: int = 150, string_count: int = 1000) -> bytes:
    """
    Synthesizes a large DEX with class_count classes and string_count strings
    to test token limits, truncation guards, and pagination (--limit/--offset).
    """
    b = DexBuilder()
    for i in range(class_count):
        cls = b.create_class(f"Lcom/example/stress/Class{i:03d};")
        cls.add_field(f"field_{i}", "I", access_flags=ACC_PUBLIC)
        m = cls.add_method("doOperation", return_type="I", access_flags=ACC_PUBLIC)
        m.emit_const_4(vx=0, lit4=i % 8)
        m.emit_return(vx=0)

    for s_idx in range(string_count):
        b.add_string(f"EXTRA_STRESS_STRING_{s_idx:04d}")

    return b.build()


def create_token_stress_dex(
    output_path: Union[str, Path],
    class_count: int = 150,
    string_count: int = 1000,
) -> Path:
    """Writes token stress DEX to output_path."""
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(synthesize_token_stress_dex(class_count=class_count, string_count=string_count))
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
    dex_bytes_map: Optional[Dict[str, bytes]] = None,
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
    if dex_bytes_map is not None and "classes.dex" in dex_bytes_map:
        entries["classes.dex"] = dex_bytes_map["classes.dex"]
    else:
        dex1_strings = dex_strings_map.get("classes.dex", ["Lcom/example/Main;"])
        entries["classes.dex"] = synthesize_dex_bytes(strings=dex1_strings)

    # 3. classes2.dex (if multidex)
    if multidex:
        if dex_bytes_map is not None and "classes2.dex" in dex_bytes_map:
            entries["classes2.dex"] = dex_bytes_map["classes2.dex"]
        else:
            dex2_strings = dex_strings_map.get("classes2.dex", ["Lcom/example/Secondary;"])
            entries["classes2.dex"] = synthesize_dex_bytes(strings=dex2_strings)

    # Any other DEX files from dex_bytes_map (e.g. classes3.dex)
    if dex_bytes_map is not None:
        for dex_name, dex_content in dex_bytes_map.items():
            if dex_name not in entries:
                entries[dex_name] = dex_content

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


def synthesize_multidex_cross_apk(
    output_path: Optional[Union[str, Path]] = None,
) -> Path:
    """
    Creates a multi-DEX APK containing:
    - classes.dex: CallerActivity with callRemote() invoking WorkerService.performTask(I)Ljava/lang/String;,
      static field SHARED_SECRET, and native method nativeCryptoInit()
    - classes2.dex: WorkerService with performTask() returning "TASK_OK"
    - lib/arm64-v8a/libmultidex_crypto.so: ELF shared object exporting Java_com_example_multidex_CallerActivity_nativeCryptoInit
    - AndroidManifest.xml, resources.arsc, and v1/v2 signatures.
    """
    if output_path is None:
        tmp_dir = tempfile.mkdtemp(prefix="rvs_multidex_")
        out = Path(tmp_dir) / "multidex_cross.apk"
    else:
        out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # 1. classes.dex
    b1 = DexBuilder()
    c1 = b1.create_class("Lcom/example/multidex/CallerActivity;")
    c1.add_field(
        "SHARED_SECRET",
        "Ljava/lang/String;",
        access_flags=ACC_PUBLIC | ACC_STATIC | ACC_FINAL,
        initial_value="s3cr3t_m4st3r_k3y",
    )
    m_call = c1.add_method("callRemote", return_type="V", access_flags=ACC_PUBLIC)
    m_call.emit_const_16(vx=0, lit16=42)
    m_call.emit_invoke_static(
        method_class="Lcom/example/multidex/WorkerService;",
        method_name="performTask",
        return_type="Ljava/lang/String;",
        params=["I"],
        args=[0],
    )
    m_call.emit_return_void()
    c1.add_method(
        "nativeCryptoInit",
        return_type="Z",
        params=["Ljava/lang/String;"],
        access_flags=ACC_PUBLIC | ACC_NATIVE,
    )
    dex1 = b1.build()

    # 2. classes2.dex
    b2 = DexBuilder()
    c2 = b2.create_class("Lcom/example/multidex/WorkerService;")
    m_task = c2.add_method(
        "performTask",
        return_type="Ljava/lang/String;",
        params=["I"],
        access_flags=ACC_PUBLIC | ACC_STATIC,
    )
    m_task.emit_const_string(vx=0, string_val="TASK_OK")
    m_task.emit_return_object(vx=0)
    dex2 = b2.build()

    # 3. Native JNI library
    elf_bytes = synthesize_elf_bytes(
        arch="arm64",
        exports=[("Java_com_example_multidex_CallerActivity_nativeCryptoInit", 0x1000, 32)],
    )

    elf_fixtures = {
        "lib/arm64-v8a/libmultidex_crypto.so": elf_bytes,
    }

    dex_bytes_map = {
        "classes.dex": dex1,
        "classes2.dex": dex2,
    }

    return create_synthetic_apk(
        output_path=out,
        elf_fixtures=elf_fixtures,
        multidex=True,
        dex_bytes_map=dex_bytes_map,
        include_manifest=True,
        sign_v1=True,
        sign_v2=True,
    )


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

    def test_dex_builder_basic_class(self) -> None:
        """Validates pure-Python DexBuilder constructs spec-compliant Dalvik DEX."""
        builder = DexBuilder()
        cls = builder.create_class("Lcom/example/TestBasic;")
        cls.add_field("mVal", "I", access_flags=ACC_PRIVATE)
        m = cls.add_method("getValue", return_type="I", access_flags=ACC_PUBLIC)
        m.emit_const_4(vx=0, lit4=7)
        m.emit_return(vx=0)

        dex_bytes = builder.build()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))
        self.assertGreaterEqual(len(dex_bytes), 112)

        # Check Adler-32 and SHA-1 consistency
        sha1_calc = hashlib.sha1(dex_bytes[32:]).digest()
        self.assertEqual(dex_bytes[12:32], sha1_calc)
        adler_calc = zlib.adler32(dex_bytes[12:]) & 0xFFFFFFFF
        header_adler = struct.unpack_from("<I", dex_bytes, 8)[0]
        self.assertEqual(header_adler, adler_calc)

    def test_synthesize_cfg_branch_dex(self) -> None:
        """Validates synthetic control-flow branch DEX contains branch gates, loops, and switches."""
        out_path = self.tmp / "cfg_branch.dex"
        create_cfg_branch_dex(out_path)
        self.assertTrue(out_path.exists())
        dex_bytes = out_path.read_bytes()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))

        # Verify rvs CLI disassembly if binary is built
        rvs_bin = Path("target/debug/rvs")
        if rvs_bin.exists():
            import subprocess
            res = subprocess.run(
                [str(rvs_bin), "apk", "dex", str(out_path), "--disasm"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"rvs apk dex failed: {res.stderr}")
            self.assertIn("branchGateSimple", res.stdout)
            self.assertIn("loopCounter", res.stdout)
            self.assertIn("switchDispatch", res.stdout)
            self.assertIn("sparseSwitchDispatch", res.stdout)

    def test_synthesize_multidex_cross_apk(self) -> None:
        """Validates multi-DEX cross-caller APK synthesis with classes.dex, classes2.dex, and JNI library."""
        apk_path = self.tmp / "multidex_cross.apk"
        synthesize_multidex_cross_apk(apk_path)
        self.assertTrue(apk_path.exists())

        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()
            self.assertIn("AndroidManifest.xml", namelist)
            self.assertIn("classes.dex", namelist)
            self.assertIn("classes2.dex", namelist)
            self.assertIn("lib/arm64-v8a/libmultidex_crypto.so", namelist)

            # Check that classes.dex has CallerActivity
            dex1 = zf.read("classes.dex")
            self.assertTrue(dex1.startswith(b"dex\n035\x00"))
            self.assertIn(b"CallerActivity", dex1)
            self.assertIn(b"callRemote", dex1)
            self.assertIn(b"nativeCryptoInit", dex1)

            # Check that classes2.dex has WorkerService
            dex2 = zf.read("classes2.dex")
            self.assertTrue(dex2.startswith(b"dex\n035\x00"))
            self.assertIn(b"WorkerService", dex2)
            self.assertIn(b"performTask", dex2)

    def test_synthesize_rich_class_dex(self) -> None:
        """Validates rich class synthesis with typed fields, interfaces, and annotations."""
        out_path = self.tmp / "rich_class.dex"
        create_rich_class_dex(out_path)
        self.assertTrue(out_path.exists())
        dex_bytes = out_path.read_bytes()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))
        self.assertIn(b"SecureModel", dex_bytes)
        self.assertIn(b"Serializable", dex_bytes)
        self.assertIn(b"Comparable", dex_bytes)
        self.assertIn(b"Authenticatable", dex_bytes)
        self.assertIn(b"EncryptedField", dex_bytes)
        self.assertIn(b"Secured", dex_bytes)
        self.assertIn(b"IS_ACTIVE", dex_bytes)

    def test_synthesize_decompile_test_dex(self) -> None:
        """Validates decompile test DEX with getter, setter, max, and add methods."""
        out_path = self.tmp / "decompile.dex"
        create_decompile_test_dex(out_path)
        self.assertTrue(out_path.exists())
        dex_bytes = out_path.read_bytes()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))
        self.assertIn(b"DecompileTarget", dex_bytes)
        self.assertIn(b"getter", dex_bytes)
        self.assertIn(b"setter", dex_bytes)
        self.assertIn(b"max", dex_bytes)
        self.assertIn(b"add", dex_bytes)

    def test_synthesize_corrupted_dex(self) -> None:
        """Validates corrupted DEX boundary fixtures."""
        corruptions = ["bad_magic", "bad_checksum", "bad_signature", "truncated", "bad_endian", "oob_map_off"]
        for ctype in corruptions:
            corrupted = synthesize_corrupted_dex(corruption_type=ctype)
            self.assertIsInstance(corrupted, bytes)
            if ctype == "bad_magic":
                self.assertTrue(corrupted.startswith(b"BADMAGIC"))
            elif ctype == "truncated":
                self.assertEqual(len(corrupted), 64)
            elif ctype == "bad_signature":
                self.assertEqual(corrupted[12:32], b"\x00" * 20)

    def test_synthesize_empty_dex(self) -> None:
        """Validates minimal empty DEX with 0 classes and 0 strings."""
        empty_bytes = synthesize_empty_dex()
        self.assertTrue(empty_bytes.startswith(b"dex\n035\x00"))
        classes_size = struct.unpack_from("<I", empty_bytes, 0x60)[0]
        self.assertEqual(classes_size, 0)
        strings_size = struct.unpack_from("<I", empty_bytes, 0x38)[0]
        self.assertEqual(strings_size, 0)

    def test_synthesize_token_stress_dex(self) -> None:
        """Validates token stress DEX with specified class and string counts."""
        stress_bytes = synthesize_token_stress_dex(class_count=15, string_count=40)
        self.assertTrue(stress_bytes.startswith(b"dex\n035\x00"))
        classes_size = struct.unpack_from("<I", stress_bytes, 0x60)[0]
        self.assertEqual(classes_size, 15)
        self.assertIn(b"Class000", stress_bytes)
        self.assertIn(b"EXTRA_STRESS_STRING_0000", stress_bytes)

    def test_dex_builder_all_opcodes(self) -> None:
        """Validates comprehensive Dalvik opcode assembling and emission."""
        builder = DexBuilder()
        cls = builder.create_class("Lcom/example/OpcodeTest;")
        cls.add_field("mVal", "I", access_flags=ACC_PUBLIC)
        cls.add_field("sVal", "I", access_flags=ACC_PUBLIC | ACC_STATIC)

        m = cls.add_method("testOpcodes", return_type="I", params=["I", "I"], access_flags=ACC_PUBLIC | ACC_STATIC)
        # Constants
        m.emit_const_4(vx=0, lit4=5)
        m.emit_const_16(vx=1, lit16=1000)
        m.emit_const(vx=2, lit32=0x12345678)
        m.emit_const_string(vx=3, string_val="HELLO_DEX")
        # Format 12x
        m.emit_move(va=0, vb=1)
        m.emit_move_object(va=2, vb=3)
        m.emit_array_length(va=0, vb=2)
        # Arithmetic
        m.emit_add_int(va=0, vb=1, vc=2)
        m.emit_sub_int(va=0, vb=2, vc=1)
        m.emit_mul_int(va=0, vb=1, vc=2)
        m.emit_and_int(va=0, vb=1, vc=2)
        m.emit_or_int(va=0, vb=1, vc=2)
        m.emit_xor_int(va=0, vb=1, vc=2)
        m.emit_add_int_lit8(va=0, vb=0, lit8=3)
        # Fields
        m.emit_sget(va=0, field_class="Lcom/example/OpcodeTest;", field_name="sVal", field_type="I")
        m.emit_sput(va=0, field_class="Lcom/example/OpcodeTest;", field_name="sVal", field_type="I")
        # Jumps and branches
        m.emit_goto_16(target="lbl_next")
        m.emit_label("lbl_next")
        m.emit_return(vx=0)

        dex_bytes = builder.build()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))

    def test_dex_builder_format_12x(self) -> None:
        """Validates Dalvik format 12x opcode encoding (move, move-object, array-length)."""
        builder = DexBuilder()
        cls = builder.create_class("Lcom/example/Test12x;")
        m = cls.add_method("test12x", return_type="V")
        m.emit_move(va=1, vb=2)
        m.emit_move_object(va=3, vb=4)
        m.emit_array_length(va=0, vb=3)
        m.emit_return_void()
        dex_bytes = builder.build()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))

        rvs_bin = Path("target/debug/rvs")
        if rvs_bin.exists():
            out_path = self.tmp / "test_12x.dex"
            out_path.write_bytes(dex_bytes)
            import subprocess
            res = subprocess.run([str(rvs_bin), "apk", "dex", str(out_path), "--disasm"], stdout=subprocess.PIPE, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("move v1, v2", res.stdout)
            self.assertIn("move-object v3, v4", res.stdout)
            self.assertIn("array-length v0, v3", res.stdout)

    def test_dex_builder_const_4_range(self) -> None:
        """Validates signed 4-bit range [-8, 7] enforcement on emit_const_4."""
        builder = DexBuilder()
        cls = builder.create_class("Lcom/example/RangeTest;")
        m = cls.add_method("validConst4", return_type="V")
        m.emit_const_4(vx=0, lit4=-8)
        m.emit_const_4(vx=1, lit4=7)
        m.emit_return_void()
        builder.build()

        with self.assertRaises(ValueError) as ctx_pos:
            m.emit_const_4(vx=0, lit4=8)
        self.assertIn("out of signed 4-bit range [-8, 7]", str(ctx_pos.exception))

        with self.assertRaises(ValueError) as ctx_neg:
            m.emit_const_4(vx=0, lit4=-9)
        self.assertIn("out of signed 4-bit range [-8, 7]", str(ctx_neg.exception))

    def test_dex_builder_missing_label(self) -> None:
        """Validates informative ValueError raised when referencing undefined labels."""
        builder = DexBuilder()
        cls = builder.create_class("Lcom/example/TestMissingLabel;")
        m = cls.add_method("badJump", return_type="V")
        m.emit_goto(target="nonexistent_lbl")
        with self.assertRaises(ValueError) as ctx:
            builder.build()
        self.assertIn("Label 'nonexistent_lbl' referenced in method 'badJump' was never defined", str(ctx.exception))

    def test_dex_builder_branch_range(self) -> None:
        """Validates signed 8-bit and 16-bit range enforcement on branch instructions."""
        b1 = DexBuilder()
        cls1 = b1.create_class("Lcom/example/TestBranchRange;")
        m1 = cls1.add_method("bigGoto", return_type="V")
        m1.emit_goto(target="far_lbl")
        for _ in range(200):
            m1.emit_nop()
        m1.emit_label("far_lbl")
        m1.emit_return_void()
        with self.assertRaises(ValueError) as ctx1:
            b1.build()
        self.assertIn("exceeds 8-bit range (-128..127)", str(ctx1.exception))

        b2 = DexBuilder()
        cls2 = b2.create_class("Lcom/example/TestBranchRange2;")
        m2 = cls2.add_method("hugeBranch", return_type="V")
        m2.emit_if_eq(va=0, vb=1, target="super_far")
        for _ in range(35000):
            m2.emit_nop()
        m2.emit_label("super_far")
        m2.emit_return_void()
        with self.assertRaises(ValueError) as ctx2:
            b2.build()
        self.assertIn("exceeds 16-bit range", str(ctx2.exception))

    def test_dex_builder_sparse_switch_key_sorting(self) -> None:
        """Validates that sparse-switch payload keys are strictly sorted in ascending order."""
        builder = DexBuilder()
        cls = builder.create_class("Lcom/example/SparseSortTest;")
        m = cls.add_method("testSparseSort", return_type="I", params=["I"], access_flags=ACC_PUBLIC | ACC_STATIC)
        m.emit_sparse_switch(va=0, target="payload")
        m.emit_label("def_case")
        m.emit_const_4(vx=0, lit4=0)
        m.emit_return(vx=0)
        m.emit_label("case_500")
        m.emit_const_4(vx=0, lit4=1)
        m.emit_return(vx=0)
        m.emit_label("case_100")
        m.emit_const_4(vx=0, lit4=2)
        m.emit_return(vx=0)
        m.emit_label("case_neg")
        m.emit_const_4(vx=0, lit4=3)
        m.emit_return(vx=0)
        m.emit_label("payload")
        m.emit_sparse_switch_payload(keys=[500, -10, 100], targets=["case_500", "case_neg", "case_100"])
        dex_bytes = builder.build()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))

        rvs_bin = Path("target/debug/rvs")
        if rvs_bin.exists():
            out_path = self.tmp / "test_sparse_sort.dex"
            out_path.write_bytes(dex_bytes)
            import subprocess
            res = subprocess.run([str(rvs_bin), "apk", "dex", str(out_path), "--disasm"], stdout=subprocess.PIPE, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("sparse-switch-payload (3)", res.stdout)

    def test_dex_builder_switch_payload_alignment(self) -> None:
        """Validates switch instruction target offset points directly to payload, not preceding NOP."""
        builder = DexBuilder()
        cls = builder.create_class("Lcom/example/SwitchAlignTest;")
        m = cls.add_method("oddPcSwitch", return_type="I", params=["I"], access_flags=ACC_PUBLIC | ACC_STATIC)
        m.emit_packed_switch(va=3, target="payload")
        m.emit_label("def_case")
        m.emit_const_4(vx=0, lit4=0)
        m.emit_return(vx=0)
        m.emit_label("c_0")
        m.emit_const_16(vx=0, lit16=10)
        m.emit_return(vx=0)
        m.emit_label("c_1")
        m.emit_const_16(vx=0, lit16=20)
        m.emit_return(vx=0)
        m.emit_label("payload")
        m.emit_packed_switch_payload(first_key=0, targets=["c_0", "c_1"])
        dex_bytes = builder.build()
        self.assertTrue(dex_bytes.startswith(b"dex\n035\x00"))

        rvs_bin = Path("target/debug/rvs")
        if rvs_bin.exists():
            out_path = self.tmp / "test_switch_align.dex"
            out_path.write_bytes(dex_bytes)
            import subprocess
            res = subprocess.run([str(rvs_bin), "apk", "dex", str(out_path), "--disasm"], stdout=subprocess.PIPE, text=True)
            self.assertEqual(res.returncode, 0)
            import json
            data = json.loads(res.stdout)["data"]["classes"][0]["methods"][0]["disassembly"]
            switch_inst = next(i for i in data if i["opcode"].startswith("packed-switch"))
            payload_inst = next(i for i in data if i["opcode"].startswith("packed-switch-payload"))
            switch_target_hex = switch_inst["disasm"].split(", ")[1]
            self.assertEqual(int(switch_target_hex, 16), payload_inst["addr"])



if __name__ == "__main__":
    unittest.main()
