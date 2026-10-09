"""
neutral_orchestrator/orchestrator.py - Neutral Technical Binary Orchestration Layer.

Milestone 3 Implementation:
- Standardized 10-key JSON telemetry envelope (NeutralResponseEnvelope).
- Pure-Python Dalvik DEX metadata extraction (DalvikMetadataExtractor).
- Context-managed NeutralBinaryOrchestrator wrapping UnifiedTarget, RvsHarness,
  and NeutralTokenMapper.
- Query routing across standalone ELFs, APK native .so components, and DEX executables.
- Invariant preservation, instruction flattening, and zero resource leak lifecycle.
"""

from __future__ import annotations

import enum
import json
import os
import struct
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict, Union

from rvs_agent_harness import RvsHarness
from neutral_orchestrator.target_ingestion import (
    TargetComponent,
    TargetType,
    UnifiedTarget,
    ingest_target,
)
from neutral_orchestrator.neutral_representation import (
    ControlFlowGraph,
    NeutralTokenMapper,
    TokenCategory,
    classify_token,
    verify_invariants,
)


# ==============================================================================
# Standardized JSON Telemetry Envelope
# ==============================================================================

class NeutralResponseEnvelope(TypedDict):
    """
    Standardized 10-key dictionary capturing query status, targeting,
    payload data, session codebook, execution telemetry, and error details.
    """
    success: bool
    command: str
    target: str
    target_type: str
    active_component: Optional[str]
    timestamp: str
    data: Dict[str, Any]
    codebook: Optional[Dict[str, Any]]
    telemetry: Dict[str, Any]
    error: Optional[Dict[str, Any]]


def _sanitize_for_json(obj: Any, seen: Optional[set] = None) -> Any:
    """
    Recursively normalizes Python objects into standard JSON primitives.
    Converts Path, Enum, set, bytes, and custom objects while preventing
    circular reference errors.
    """
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if isinstance(obj, (dict, list, tuple)):
        if obj_id in seen:
            return "<circular_reference>"
        seen.add(obj_id)

    try:
        if isinstance(obj, dict):
            return {str(k): _sanitize_for_json(v, seen) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [_sanitize_for_json(v, seen) for v in obj]
        elif isinstance(obj, set):
            return [_sanitize_for_json(v, seen) for v in sorted(list(obj), key=str)]
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, enum.Enum):
            return obj.value
        elif hasattr(obj, "value") and not isinstance(obj, (int, float, str, bool)):
            return obj.value
        elif isinstance(obj, bytes):
            try:
                return obj.decode("utf-8")
            except UnicodeDecodeError:
                return obj.hex()
        elif isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        elif hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
            return _sanitize_for_json(obj.to_dict(), seen)
        else:
            return str(obj)
    finally:
        if isinstance(obj, (dict, list, tuple)):
            seen.discard(obj_id)


# ==============================================================================
# Dalvik DEX Analysis Extractor
# ==============================================================================

class DalvikMetadataExtractor:
    """
    Pure-Python parser for Dalvik Executable (DEX) files (v035-v039).
    Parses the 112-byte header, Adler32 checksum, SHA-1 signature,
    endianness, and ULEB128-encoded string tables without external dependencies.
    """

    @staticmethod
    def extract_metadata(dex_path: Union[str, Path]) -> Dict[str, Any]:
        p = Path(dex_path)
        if not p.exists() or p.stat().st_size < 112:
            return {
                "format": "dex",
                "valid": False,
                "error": f"Invalid or truncated DEX file: {dex_path}",
            }

        data = p.read_bytes()
        if len(data) < 112 or not data.startswith(b"dex\n"):
            return {
                "format": "dex",
                "valid": False,
                "error": "Missing valid Dalvik DEX magic bytes",
            }

        magic = data[:8].decode("ascii", errors="replace").rstrip("\x00")
        version = data[4:7].decode("ascii", errors="replace") if len(data) >= 8 else "035"
        checksum, = struct.unpack_from("<I", data, 8)
        sha1 = data[12:32].hex()
        file_size, header_size, endian = struct.unpack_from("<III", data, 0x20)
        link_size, link_off = struct.unpack_from("<II", data, 0x2C)
        map_off, = struct.unpack_from("<I", data, 0x34)
        string_ids_size, string_ids_off = struct.unpack_from("<II", data, 0x38)
        type_ids_size, type_ids_off = struct.unpack_from("<II", data, 0x40)
        proto_ids_size, proto_ids_off = struct.unpack_from("<II", data, 0x48)
        field_ids_size, field_ids_off = struct.unpack_from("<II", data, 0x50)
        method_ids_size, method_ids_off = struct.unpack_from("<II", data, 0x58)
        class_defs_size, class_defs_off = struct.unpack_from("<II", data, 0x60)
        data_size, data_off = struct.unpack_from("<II", data, 0x68)

        # Parse string table
        strings: List[Dict[str, Any]] = []
        raw_strings: List[str] = []
        if 0 < string_ids_off < len(data) and string_ids_size > 0:
            for i in range(min(string_ids_size, 5000)):
                if string_ids_off + i * 4 + 4 > len(data):
                    break
                soff, = struct.unpack_from("<I", data, string_ids_off + i * 4)
                if not (0 <= soff < len(data)):
                    continue
                pos = soff
                length = 0
                shift = 0
                while pos < len(data):
                    b = data[pos]
                    pos += 1
                    length |= (b & 0x7F) << shift
                    if (b & 0x80) == 0:
                        break
                    shift += 7

                null_idx = data.find(b"\x00", pos)
                if null_idx != -1:
                    raw_bytes = data[pos:null_idx]
                elif pos + length <= len(data):
                    raw_bytes = data[pos:pos + length]
                else:
                    raw_bytes = data[pos:]

                try:
                    s = raw_bytes.decode("utf-8", errors="surrogatepass")
                    s = s.encode("utf-16", "surrogatepass").decode("utf-16")
                except Exception:
                    s = raw_bytes.decode("utf-8", errors="replace")
                raw_strings.append(s)
                strings.append({"string": s, "offset": soff, "length": length})

        return {
            "format": "dex",
            "arch": "dalvik",
            "bits": 32,
            "version": version,
            "magic": magic,
            "file_size": file_size,
            "header_size": header_size,
            "endian_tag": hex(endian),
            "checksum": hex(checksum),
            "signature": sha1,
            "string_count": string_ids_size,
            "type_count": type_ids_size,
            "proto_count": proto_ids_size,
            "field_count": field_ids_size,
            "method_count": method_ids_size,
            "class_count": class_defs_size,
            "strings": strings,
            "raw_strings": raw_strings,
            "valid": True,
        }


# ==============================================================================
# Neutral Binary Orchestrator
# ==============================================================================

class NeutralBinaryOrchestrator:
    """
    Context-managed Technical Binary Orchestrator.
    Wraps UnifiedTarget, RvsHarness, and NeutralTokenMapper.
    Routes queries to native RvsHarness or Dalvik analysis extractors,
    formats responses into standardized NeutralResponseEnvelope dictionaries,
    and guarantees zero ephemeral directory leaks upon exit.
    """

    SUPPORTED_OPERATIONS = {
        "info",
        "functions",
        "disasm",
        "flow",
        "xrefs",
        "decompile",
        "strings",
        "symbols",
        "cfg",
    }

    def __init__(
        self,
        target: Union[str, Path, UnifiedTarget],
        default_abi: str = "x86_64",
        token_mapper: Optional[NeutralTokenMapper] = None,
        harness: Optional[RvsHarness] = None,
        rvs_bin: Optional[Union[str, Path]] = None,
    ) -> None:
        self.default_abi = default_abi
        if isinstance(target, UnifiedTarget):
            self.unified_target: Optional[UnifiedTarget] = target
            self.target_path = str(target.primary_path)
            self._owns_target = False
        else:
            self.target_path = str(target)
            self.unified_target = ingest_target(self.target_path, default_abi=default_abi)
            self._owns_target = True

        self.token_mapper: NeutralTokenMapper = token_mapper or NeutralTokenMapper(session_id=str(uuid.uuid4()))
        if harness is not None:
            self.harness = harness
            self._owns_harness = False
        else:
            self.harness = RvsHarness(rvs_bin=rvs_bin)
            self._owns_harness = True
        if hasattr(self.harness, "_in_orchestration"):
            self.harness._in_orchestration = True

        self._closed = False

    @property
    def target(self) -> Optional[UnifiedTarget]:
        """Convenience property exposing underlying UnifiedTarget."""
        return self.unified_target

    @property
    def target_type(self) -> TargetType:
        """Exposes TargetType enum of ingested target."""
        if self.unified_target:
            return self.unified_target.target_type
        return TargetType.UNKNOWN

    @property
    def components(self) -> List[TargetComponent]:
        """List of analyzable components in target."""
        if self.unified_target:
            return self.unified_target.components
        return []

    def __enter__(self) -> "NeutralBinaryOrchestrator":
        if self._closed:
            raise RuntimeError("Cannot re-enter closed NeutralBinaryOrchestrator session")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """
        Idempotent teardown: cleans up extracted APK temporary directories
        and clears RvsHarness cached session data.
        """
        if not self._closed:
            self._closed = True
            if self.unified_target is not None:
                self.unified_target.cleanup()
            if self.harness is not None:
                self.harness.clear_session()

    def cleanup(self) -> None:
        """Alias for close()."""
        self.close()

    def query(self, command: str, **kwargs: Any) -> Dict[str, Any]:
        """
        Executes binary analysis command and returns structured NeutralResponseEnvelope.
        """
        if self._closed:
            raise RuntimeError("NeutralBinaryOrchestrator session has already been closed")

        start_time = time.perf_counter()
        normalized_cmd = command.strip().lower()
        active_comp_str: Optional[str] = None
        target_type_str = self.target_type.value

        try:
            # 1. Validate requested operation
            if normalized_cmd not in self.SUPPORTED_OPERATIONS:
                elapsed = max(0.0, round(time.perf_counter() - start_time, 4))
                return _sanitize_for_json({
                    "success": False,
                    "command": normalized_cmd,
                    "target": self.target_path,
                    "target_type": target_type_str,
                    "active_component": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {},
                    "codebook": self.token_mapper.export_codebook(),
                    "telemetry": {
                        "execution_time_seconds": elapsed,
                        "target_type": target_type_str,
                        "active_component": None,
                    },
                    "error": {
                        "code": "INVALID_COMMAND",
                        "message": f"Operation '{command}' is not supported by orchestrator.",
                        "category": "INVALID_ARGUMENT",
                        "exit_code": 1,
                    },
                })

            # 2. Resolve target component
            abi = kwargs.get("abi")
            comp_type = kwargs.get("component_type")
            comp: Optional[TargetComponent] = None

            if self.unified_target:
                if comp_type == "dex":
                    comp = self.unified_target.get_component(comp_type="dex")
                elif comp_type == "elf_so":
                    comp = self.unified_target.get_component(abi=abi, comp_type="elf_so")
                elif abi is not None:
                    comp = self.unified_target.get_component(abi=abi, comp_type=comp_type or "elf_so")
                elif self.target_type == TargetType.APK_PACKAGE:
                    comp = self.unified_target.get_component(abi=self.default_abi, comp_type="elf_so")
                    if comp is None:
                        comp = self.unified_target.get_component(comp_type="elf_so")
                    if comp is None:
                        comp = self.unified_target.get_component(comp_type="dex")
                elif self.target_type == TargetType.DEX_STANDALONE:
                    comp = self.unified_target.get_component(comp_type="dex")
                else:
                    comp = self.unified_target.get_component(comp_type="elf_so")
                    if comp is None and self.unified_target.components:
                        comp = self.unified_target.components[0]

            # If component could not be resolved (either explicit ABI/type not found,
            # or container has no analyzable components, or target is malformed/empty):
            if comp is None:
                elapsed = max(0.0, round(time.perf_counter() - start_time, 4))
                is_empty = False
                try:
                    is_empty = os.path.exists(self.target_path) and os.path.getsize(self.target_path) == 0
                except OSError:
                    is_empty = False

                if is_empty:
                    err_code = "ZERO_BYTE_FILE"
                    err_msg = f"File '{self.target_path}' is empty (0 bytes)"
                elif abi is not None or comp_type is not None:
                    err_code = "COMPONENT_NOT_FOUND"
                    err_msg = f"Component matching abi='{abi}' and comp_type='{comp_type}' not found."
                else:
                    err_code = "COMPONENT_NOT_FOUND"
                    err_msg = (
                        f"No analyzable executable components (native .so or Dalvik DEX) "
                        f"found in target '{self.target_path}'."
                    )

                return _sanitize_for_json({
                    "success": False,
                    "command": normalized_cmd,
                    "target": self.target_path,
                    "target_type": target_type_str,
                    "active_component": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": {},
                    "codebook": self.token_mapper.export_codebook(),
                    "telemetry": {
                        "execution_time_seconds": elapsed,
                        "target_type": target_type_str,
                        "active_component": None,
                    },
                    "error": {
                        "code": err_code,
                        "message": err_msg,
                        "category": "FILE_ERROR",
                        "exit_code": 2,
                    },
                })

            active_path = comp.path
            if comp.archive_relpath:
                active_comp_str = comp.archive_relpath
            elif self.target_type == TargetType.ELF_STANDALONE:
                active_comp_str = None
            else:
                active_comp_str = comp.name

            # 3. Determine if routing to DEX or native
            is_dex = (comp and comp.component_type == "dex") or (self.target_type == TargetType.DEX_STANDALONE)

            # 4. Dispatch query
            if is_dex:
                res_data, error, success = self._route_dex(normalized_cmd, active_path, **kwargs)
            else:
                res_data, error, success = self._route_native(normalized_cmd, active_path, **kwargs)

            elapsed = max(0.0, round(time.perf_counter() - start_time, 4))
            envelope = {
                "success": success,
                "command": normalized_cmd,
                "target": self.target_path,
                "target_type": target_type_str,
                "active_component": active_comp_str,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": res_data,
                "codebook": self.token_mapper.export_codebook(),
                "telemetry": {
                    "execution_time_seconds": elapsed,
                    "target_type": target_type_str,
                    "active_component": active_comp_str,
                },
                "error": error if not success else None,
            }
            return _sanitize_for_json(envelope)

        except Exception as e:
            elapsed = max(0.0, round(time.perf_counter() - start_time, 4))
            err_envelope = {
                "success": False,
                "command": normalized_cmd,
                "target": self.target_path,
                "target_type": target_type_str,
                "active_component": active_comp_str,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": {},
                "codebook": self.token_mapper.export_codebook() if hasattr(self, "token_mapper") else None,
                "telemetry": {
                    "execution_time_seconds": elapsed,
                    "target_type": target_type_str,
                    "active_component": active_comp_str,
                },
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": str(e),
                    "category": "INTERNAL_ERROR",
                    "exit_code": 6,
                },
            }
            return _sanitize_for_json(err_envelope)

    def _route_dex(
        self,
        command: str,
        dex_path: str,
        **kwargs: Any,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], bool]:
        """Routes DEX component queries to Dalvik metadata extractor."""
        meta = DalvikMetadataExtractor.extract_metadata(dex_path)
        if not meta.get("valid", True):
            return {}, {
                "code": "ANALYSIS_ERROR",
                "message": meta.get("error", "Failed to parse DEX metadata"),
                "category": "ANALYSIS_ERROR",
                "exit_code": 3,
            }, False

        if command == "info":
            info_data = dict(meta)
            info_data.pop("strings", None)
            info_data.pop("raw_strings", None)
            info_data["security"] = []
            return info_data, None, True

        elif command == "strings":
            min_len = kwargs.get("min_len", 4)
            filter_str = kwargs.get("filter")
            strs = meta.get("strings", [])
            if min_len > 0:
                strs = [s for s in strs if len(s.get("string", "")) >= min_len]
            if filter_str:
                fl = filter_str.lower()
                strs = [s for s in strs if fl in s.get("string", "").lower()]
            limit = kwargs.get("limit")
            if limit is not None and limit > 0:
                strs = strs[:limit]

            # Register sensitive strings in token mapper
            for item in strs:
                st = item.get("string", "")
                if st:
                    cat = classify_token(st)
                    if cat != TokenCategory.GENERAL:
                        self.token_mapper.sanitize_string(st, category=cat)

            return {"strings": strs, "total": len(strs)}, None, True

        else:
            return {}, {
                "code": "UNSUPPORTED_DEX_OPERATION",
                "message": f"Operation '{command}' is not supported on Dalvik DEX components.",
                "category": "ANALYSIS_ERROR",
                "exit_code": 3,
            }, False

    def _route_native(
        self,
        command: str,
        target_file: str,
        **kwargs: Any,
    ) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], bool]:
        """Routes native ELF and APK .so queries to RvsHarness."""
        fn_or_addr = (
            kwargs.get("function_or_addr")
            or kwargs.get("function")
            or kwargs.get("symbol_or_addr")
            or kwargs.get("symbol")
            or kwargs.get("addr")
        )

        if command == "info":
            resp = self.harness.info(
                target=target_file,
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "functions":
            resp = self.harness.functions(
                target=target_file,
                filter=kwargs.get("filter"),
                detail=kwargs.get("detail", False),
                limit=kwargs.get("limit"),
                offset=kwargs.get("offset"),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "disasm":
            if not fn_or_addr:
                return {}, {
                    "code": "MISSING_ARGUMENT",
                    "message": "Missing function_or_addr for disasm command",
                    "category": "INVALID_ARGUMENT",
                    "exit_code": 1,
                }, False
            resp = self.harness.disasm(
                target=target_file,
                function_or_addr=str(fn_or_addr),
                disasm=kwargs.get("disasm", True),
                max_instructions=kwargs.get("max_instructions"),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "flow":
            if not fn_or_addr:
                return {}, {
                    "code": "MISSING_ARGUMENT",
                    "message": "Missing function_or_addr for flow command",
                    "category": "INVALID_ARGUMENT",
                    "exit_code": 1,
                }, False
            resp = self.harness.flow(
                target=target_file,
                function=str(fn_or_addr),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "xrefs":
            if not fn_or_addr:
                return {}, {
                    "code": "MISSING_ARGUMENT",
                    "message": "Missing symbol_or_addr for xrefs command",
                    "category": "INVALID_ARGUMENT",
                    "exit_code": 1,
                }, False
            resp = self.harness.xrefs(
                target=target_file,
                symbol_or_addr=str(fn_or_addr),
                direction=kwargs.get("direction", "all"),
                kind=kwargs.get("kind"),
                limit=kwargs.get("limit"),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "decompile":
            if not fn_or_addr:
                return {}, {
                    "code": "MISSING_ARGUMENT",
                    "message": "Missing function for decompile command",
                    "category": "INVALID_ARGUMENT",
                    "exit_code": 1,
                }, False
            resp = self.harness.decompile(
                target=target_file,
                function=str(fn_or_addr),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "strings":
            resp = self.harness.strings(
                target=target_file,
                min_len=kwargs.get("min_len", 4),
                filter=kwargs.get("filter"),
                limit=kwargs.get("limit"),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "symbols":
            resp = self.harness.symbols(
                target=target_file,
                filter=kwargs.get("filter"),
                limit=kwargs.get("limit", 50),
                offset=kwargs.get("offset", 0),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )

        elif command == "cfg":
            if not fn_or_addr:
                return {}, {
                    "code": "MISSING_ARGUMENT",
                    "message": "Missing function_or_addr for cfg command",
                    "category": "INVALID_ARGUMENT",
                    "exit_code": 1,
                }, False
            flow_resp = self.harness.flow(
                target=target_file,
                function=str(fn_or_addr),
                compact=kwargs.get("compact", True),
                timeout=kwargs.get("timeout"),
                _from_orchestrator=True,
            )
            if not flow_resp.get("success"):
                return {}, flow_resp.get("error"), False

            flow_data = flow_resp.get("data") or {}
            blocks = flow_data.get("blocks", [])
            if not blocks:
                try:
                    dq = self.harness.disasm(
                        target=target_file,
                        function_or_addr=str(fn_or_addr),
                        disasm=False,
                        _from_orchestrator=True,
                    )
                    if dq.get("success") and isinstance(dq.get("data"), dict):
                        blocks = dq["data"].get("blocks", [])
                except Exception:
                    pass
            nodes = [{"id": f"BB_{b.get('addr')}", "start_addr": str(b.get("addr"))} for b in blocks]
            edges = []
            for b in blocks:
                b_addr = b.get("addr")
                b_jump = b.get("jump")
                b_fail = b.get("fail")
                if b_jump:
                    edges.append({
                        "source": f"BB_{b_addr}",
                        "target": f"BB_{b_jump}",
                        "edge_type": "CONDITIONAL_TAKEN" if b_fail else "UNCONDITIONAL",
                    })
                if b_fail:
                    edges.append({
                        "source": f"BB_{b_addr}",
                        "target": f"BB_{b_fail}",
                        "edge_type": "CONDITIONAL_NOT_TAKEN",
                    })
            cfg_obj = ControlFlowGraph(nodes=nodes, edges=edges)
            cfg_dict = cfg_obj.to_dict()
            return {"cfg": cfg_dict, "nodes": nodes, "edges": edges, "blocks": blocks}, None, True

        else:
            return {}, {
                "code": "UNREACHABLE",
                "message": f"Command '{command}' not dispatched.",
            }, False

        success = bool(resp.get("success", False))
        error = resp.get("error") if not success else None
        data = resp.get("data")
        if not isinstance(data, dict):
            data = {"result": data} if data is not None else {}

        # 5. Critical Invariant Post-Processing: Flatten instructions for disasm
        if command == "disasm" and success:
            instructions: List[Dict[str, Any]] = []
            blocks = data.get("blocks", [])
            if isinstance(blocks, list):
                for b in blocks:
                    if isinstance(b, dict):
                        instructions.extend(b.get("instructions", []))
            if not instructions and "instructions" in data and isinstance(data["instructions"], list):
                instructions = data["instructions"]
            data["instructions"] = instructions

        # 6. Critical Invariant Post-Processing: Populate blocks for flow
        if command == "flow" and success:
            blocks = data.get("blocks", [])
            if not blocks:
                try:
                    disasm_quick = self.harness.disasm(
                        target=target_file,
                        function_or_addr=str(fn_or_addr),
                        disasm=False,
                        _from_orchestrator=True,
                    )
                    if disasm_quick.get("success") and isinstance(disasm_quick.get("data"), dict):
                        d_blocks = disasm_quick["data"].get("blocks", [])
                        if d_blocks:
                            blocks = d_blocks
                except Exception:
                    pass

            if not blocks:
                synth_blocks = []
                for d in data.get("decision_nodes", []):
                    if isinstance(d, dict) and "addr" in d:
                        synth_blocks.append({"addr": d["addr"]})
                for e in (data.get("exits", []) or data.get("exit_nodes", [])):
                    synth_blocks.append({"addr": e if isinstance(e, str) else str(e)})
                blocks = synth_blocks
            data["blocks"] = blocks

        # 7. Auto-register discovered sensitive symbols and strings in session token mapper
        if success:
            if command == "functions":
                for fn in data.get("functions", []):
                    if isinstance(fn, dict):
                        name = fn.get("name", "")
                        if name:
                            cat = classify_token(name)
                            if cat != TokenCategory.GENERAL:
                                self.token_mapper.sanitize_symbol(name, category=cat)
            elif command == "strings":
                for s in data.get("strings", []):
                    if isinstance(s, dict):
                        text = s.get("string", "")
                        if text:
                            cat = classify_token(text)
                            if cat != TokenCategory.GENERAL:
                                self.token_mapper.sanitize_string(text, category=cat)

        return data, error, success

    # Ergonomic convenience methods
    def info(self, **kwargs: Any) -> Dict[str, Any]:
        """Inspect binary metadata, format, architecture, and mitigations."""
        return self.query("info", **kwargs)

    def functions(self, **kwargs: Any) -> Dict[str, Any]:
        """Discover functions, entry points, signatures, and addresses."""
        return self.query("functions", **kwargs)

    def disasm(self, function_or_addr: str, **kwargs: Any) -> Dict[str, Any]:
        """Disassemble function or address, returning flattened instructions and basic blocks."""
        return self.query("disasm", function_or_addr=function_or_addr, **kwargs)

    def flow(self, function_or_addr: str, **kwargs: Any) -> Dict[str, Any]:
        """Analyze control-flow branches, condition expressions, loops, and basic blocks."""
        return self.query("flow", function_or_addr=function_or_addr, **kwargs)

    def xrefs(self, symbol_or_addr: str, **kwargs: Any) -> Dict[str, Any]:
        """Extract cross-references to and from target symbol or address."""
        return self.query("xrefs", symbol_or_addr=symbol_or_addr, **kwargs)

    def decompile(self, function: str, **kwargs: Any) -> Dict[str, Any]:
        """Generate pseudo-C decompilation for target function."""
        return self.query("decompile", function=function, **kwargs)

    def strings(self, **kwargs: Any) -> Dict[str, Any]:
        """Extract strings from data sections or Dalvik string tables."""
        return self.query("strings", **kwargs)

    def symbols(self, **kwargs: Any) -> Dict[str, Any]:
        """Enumerate exported symbols, PLT imports, and virtual addresses."""
        return self.query("symbols", **kwargs)

    def cfg(self, function_or_addr: str, **kwargs: Any) -> Dict[str, Any]:
        """Extract formal Control Flow Graph representation."""
        return self.query("cfg", function_or_addr=function_or_addr, **kwargs)
