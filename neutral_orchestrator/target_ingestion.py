"""
neutral_orchestrator/target_ingestion.py - Multi-Format Target Ingestion & Unification.

Part of the Neutral Technical Binary Orchestration Layer.
Provides:
1. TargetType enum (ELF_STANDALONE, APK_PACKAGE, DEX_STANDALONE, UNKNOWN).
2. TargetComponent dataclass with full metadata, query helpers, and serialization.
3. TargetClassifier with pure-Python magic byte sniffing for ELF32/ELF64, PIE, DEX, and APK.
4. Standalone ELF zero-copy ingestion preserving canonical paths and filesystem state.
5. APK container unpacker with Zip Slip defense-in-depth, selective extraction, and natural multidex sorting.
6. 6-Tier Ephemeral Lifecycle Watchdog (Context Manager, Idempotent Cleanup, GC Finalizer,
   atexit Registry, Deadlock-Free Signal Handlers, and TTL Orphan Sweeper).
7. UnifiedTarget abstraction offering consistent querying and component selection.
8. Main entry point ingest_target().
"""

from __future__ import annotations

import atexit
import enum
import os
import platform
import re
import shutil
import signal
import stat
import struct
import sys
import tempfile
import threading
import time
import weakref
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# ==============================================================================
# Custom Exception Hierarchy
# ==============================================================================

class TargetIngestionError(Exception):
    """Base exception for all target ingestion, sniffing, and extraction failures."""

    def __init__(
        self,
        message: str,
        code: str = "INGESTION_ERROR",
        category: str = "FILE_ERROR",
        exit_code: int = 1,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.category = category
        self.exit_code = exit_code

    def to_error_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "category": self.category,
            "exit_code": self.exit_code,
        }


class TargetNotFoundError(TargetIngestionError, FileNotFoundError):
    """Raised when target file does not exist on filesystem or is not a regular file."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="FILE_NOT_FOUND", category="FILE_ERROR", exit_code=2)


class TargetPermissionError(TargetIngestionError, PermissionError):
    """Raised when target file cannot be opened due to filesystem permission restrictions."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="PERMISSION_DENIED", category="FILE_ERROR", exit_code=2)


class EmptyTargetError(TargetIngestionError, ValueError):
    """Raised when target file exists but has a file size of 0 bytes."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="EMPTY_FILE", category="FILE_ERROR", exit_code=2)


class UnparseableBinaryError(TargetIngestionError, ValueError):
    """Raised when target binary format cannot be recognized or is truncated/corrupt."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="UNPARSEABLE_FORMAT", category="ANALYSIS_ERROR", exit_code=3)


class SecurityViolationError(TargetIngestionError, ValueError):
    """Raised when an archive member violates security policies (e.g. Zip Slip directory traversal)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="SECURITY_VIOLATION", category="ANALYSIS_ERROR", exit_code=3)


class MalformedPackageError(UnparseableBinaryError, zipfile.BadZipFile):
    """Raised when package container is corrupted or malformed ZIP."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


# ==============================================================================
# Enumerations and Data Structures
# ==============================================================================

class TargetType(str, enum.Enum):
    """Enumeration of recognized binary target formats."""
    ELF_STANDALONE = "elf_standalone"
    APK_PACKAGE = "apk_package"
    DEX_STANDALONE = "dex_standalone"
    UNKNOWN = "unknown"


@dataclass
class TargetComponent:
    """Represents an individual analyzable component within a target."""
    path: str
    component_type: str        # 'elf_so', 'dex', 'elf'
    abi: Optional[str] = None  # 'x86_64', 'arm64-v8a', 'armeabi-v7a', 'x86', None
    archive_relpath: str = ""
    size_bytes: int = field(default=0)

    def __post_init__(self) -> None:
        if not self.size_bytes:
            try:
                self.size_bytes = Path(self.path).stat().st_size
            except OSError:
                self.size_bytes = 0

    @property
    def name(self) -> str:
        return Path(self.path).name

    @property
    def is_native(self) -> bool:
        return self.component_type in ("elf_so", "elf_standalone", "elf")

    @property
    def is_dex(self) -> bool:
        return self.component_type == "dex"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "component_type": self.component_type,
            "abi": self.abi,
            "archive_relpath": self.archive_relpath,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class TargetClassification:
    """Metadata record summarizing binary sniffing and architecture analysis."""
    target_type: TargetType
    format_name: str                     # "elf", "apk", "dex", "unknown"
    bits: Optional[int] = None           # 32, 64, or None
    endianness: Optional[str] = None     # "little", "big", or None
    e_type: Optional[int] = None         # 2 (ET_EXEC), 3 (ET_DYN), etc.
    is_pie: Optional[bool] = None        # True if e_type == 3
    machine: Optional[str] = None        # "x86", "x86_64", "arm", "arm64", etc.
    abi: Optional[str] = None            # "x86", "x86_64", "armeabi-v7a", "arm64-v8a"
    dex_version: Optional[str] = None    # "035", "037", etc.
    has_manifest: Optional[bool] = None  # True if AndroidManifest.xml present
    has_dex: Optional[bool] = None       # True if classes*.dex present


# ELF (e_machine, ei_class) to (machine_name, canonical_abi)
ELF_MACHINE_TO_ABI: Dict[Tuple[int, int], Tuple[str, str]] = {
    (62, 2): ("x86_64", "x86_64"),       # EM_X86_64, 64-bit -> ABI "x86_64"
    (3, 1): ("x86", "x86"),              # EM_386, 32-bit -> ABI "x86"
    (183, 2): ("arm64", "arm64-v8a"),    # EM_AARCH64, 64-bit -> ABI "arm64-v8a"
    (40, 1): ("arm", "armeabi-v7a"),     # EM_ARM, 32-bit -> ABI "armeabi-v7a"
    (243, 2): ("riscv64", "riscv64"),    # EM_RISCV, 64-bit -> ABI "riscv64"
    (8, 1): ("mips", "mips"),            # EM_MIPS, 32-bit -> ABI "mips"
    (8, 2): ("mips64", "mips64"),        # EM_MIPS, 64-bit -> ABI "mips64"
}

# Regex patterns for selective extraction
DEX_FILENAME_RE = re.compile(r"^classes(?:\d+)?\.dex$")
NATIVE_SO_RE = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")


def get_host_abi() -> str:
    """Determine normalized host architecture ABI."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    elif machine in ("aarch64", "arm64"):
        return "arm64-v8a"
    elif machine.startswith("arm"):
        return "armeabi-v7a"
    elif machine in ("i386", "i686", "x86"):
        return "x86"
    return "x86_64"


# ==============================================================================
# 6-Tier Ephemeral Lifecycle Watchdog Implementation
# ==============================================================================

EPHEMERAL_DIR_PREFIX = "rvs_target_"

_ACTIVE_EPHEMERAL_DIRS: Set[str] = set()
_REGISTRY_LOCK = threading.Lock()
_ATEXIT_REGISTERED = False
_SIGNALS_REGISTERED = False
_PREVIOUS_SIGINT_HANDLER: Any = None
_PREVIOUS_SIGTERM_HANDLER: Any = None
_OPPORTUNISTIC_SWEEP_DONE = False


def _shutil_rmtree_helper(path: Union[str, Path, None]) -> None:
    """
    Resilient recursive directory removal helper.
    Handles read-only files, restricted subdirectories (0o500/0o400),
    and permission quirks often encountered in extracted APK packages.
    """
    if not path:
        return
    path_str = str(path)
    if not os.path.exists(path_str):
        return

    # Fast-path attempt
    try:
        shutil.rmtree(path_str)
        return
    except Exception:
        pass

    # Resilient permission-correcting walk
    try:
        for root, dirs, files in os.walk(path_str, topdown=False):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    os.chmod(fpath, stat.S_IWUSR | stat.S_IRUSR)
                    os.unlink(fpath)
                except OSError:
                    pass
            for dname in dirs:
                dpath = os.path.join(root, dname)
                try:
                    os.chmod(dpath, stat.S_IRWXU)
                    os.rmdir(dpath)
                except OSError:
                    pass
        try:
            os.chmod(path_str, stat.S_IRWXU)
            os.rmdir(path_str)
        except OSError:
            pass
    except Exception:
        pass

    # Final best-effort fallback
    try:
        shutil.rmtree(path_str, ignore_errors=True)
    except Exception:
        pass


def _finalizer_cleanup(dir_path: str) -> None:
    """
    Pure module-level finalizer callback executed by weakref.finalize (Tier 3).
    MUST NOT reference any UnifiedTarget instance.
    """
    _unregister_ephemeral_dir(dir_path)
    _shutil_rmtree_helper(dir_path)


def _register_ephemeral_dir(path: str) -> None:
    """Register ephemeral directory in Tier 4 tracking set."""
    if not path:
        return
    resolved = os.path.abspath(path)
    with _REGISTRY_LOCK:
        _ACTIVE_EPHEMERAL_DIRS.add(resolved)


def _unregister_ephemeral_dir(path: str) -> None:
    """Remove ephemeral directory from Tier 4 tracking set."""
    if not path:
        return
    resolved = os.path.abspath(path)
    with _REGISTRY_LOCK:
        _ACTIVE_EPHEMERAL_DIRS.discard(resolved)


def _atexit_cleanup_all() -> None:
    """Tier 4: Global exit handler invoked automatically by Python atexit."""
    with _REGISTRY_LOCK:
        dirs_to_clean = list(_ACTIVE_EPHEMERAL_DIRS)
        _ACTIVE_EPHEMERAL_DIRS.clear()
    for d in dirs_to_clean:
        _shutil_rmtree_helper(d)


def _ensure_atexit_registered() -> None:
    global _ATEXIT_REGISTERED
    if not _ATEXIT_REGISTERED:
        with _REGISTRY_LOCK:
            if not _ATEXIT_REGISTERED:
                atexit.register(_atexit_cleanup_all)
                _ATEXIT_REGISTERED = True


def _signal_cleanup_all(signum: int, frame: Any) -> None:
    """
    Tier 5: Signal handler for SIGINT and SIGTERM:
    1. Reaps all active ephemeral directories using non-blocking lock acquisition.
    2. Forwards signal to previously installed handler or restores default POSIX exit.
    """
    acquired = _REGISTRY_LOCK.acquire(blocking=False)
    dirs_to_clean: List[str] = []
    try:
        dirs_to_clean = list(_ACTIVE_EPHEMERAL_DIRS)
        _ACTIVE_EPHEMERAL_DIRS.clear()
    finally:
        if acquired:
            _REGISTRY_LOCK.release()

    for d in dirs_to_clean:
        _shutil_rmtree_helper(d)

    prev_handler = (
        _PREVIOUS_SIGINT_HANDLER if signum == signal.SIGINT else _PREVIOUS_SIGTERM_HANDLER
    )
    if callable(prev_handler):
        prev_handler(signum, frame)
    elif prev_handler == signal.SIG_DFL:
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
    elif prev_handler == signal.SIG_IGN:
        pass
    else:
        sys.exit(128 + signum)


def _register_signal_handlers() -> None:
    global _SIGNALS_REGISTERED, _PREVIOUS_SIGINT_HANDLER, _PREVIOUS_SIGTERM_HANDLER
    if _SIGNALS_REGISTERED:
        return
    try:
        if threading.current_thread() is not threading.main_thread():
            return
        _PREVIOUS_SIGINT_HANDLER = signal.getsignal(signal.SIGINT)
        _PREVIOUS_SIGTERM_HANDLER = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGINT, _signal_cleanup_all)
        signal.signal(signal.SIGTERM, _signal_cleanup_all)
        _SIGNALS_REGISTERED = True
    except (ValueError, AttributeError, OSError):
        pass


def sweep_orphaned_target_dirs(
    base_dir: Optional[str] = None,
    ttl_seconds: float = 3600.0,
    prefix: str = EPHEMERAL_DIR_PREFIX,
    dry_run: bool = False,
) -> List[str]:
    """
    Tier 6: Scans base_dir (defaulting to tempfile.gettempdir()) for orphaned rvs_target_* dirs.
    Deletes directories older than ttl_seconds that are NOT actively tracked in _ACTIVE_EPHEMERAL_DIRS.
    Returns list of swept directory paths.
    """
    swept_dirs: List[str] = []
    search_root = base_dir or tempfile.gettempdir()
    if not os.path.isdir(search_root):
        return swept_dirs

    now = time.time()
    with _REGISTRY_LOCK:
        active_snapshot = set(_ACTIVE_EPHEMERAL_DIRS)

    try:
        with os.scandir(search_root) as it:
            for entry in it:
                try:
                    if not entry.name.startswith(prefix):
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue

                    entry_abs = os.path.abspath(entry.path)
                    if entry_abs in active_snapshot:
                        continue

                    mtime = entry.stat().st_mtime
                    age = now - mtime
                    if age >= ttl_seconds:
                        if not dry_run:
                            _shutil_rmtree_helper(entry_abs)
                        swept_dirs.append(entry_abs)
                except (OSError, PermissionError):
                    continue
    except (OSError, PermissionError):
        pass

    return swept_dirs


def _maybe_opportunistic_sweep() -> None:
    global _OPPORTUNISTIC_SWEEP_DONE
    if not _OPPORTUNISTIC_SWEEP_DONE:
        _OPPORTUNISTIC_SWEEP_DONE = True
        try:
            sweep_orphaned_target_dirs(ttl_seconds=86400.0)
        except Exception:
            pass


def create_ephemeral_dir(prefix: str = EPHEMERAL_DIR_PREFIX) -> str:
    """
    Allocates an ephemeral directory under tempfile.gettempdir(), registers it
    in the Tier 4 atexit registry, sets up signal traps, and performs opportunistic sweep.
    """
    _maybe_opportunistic_sweep()
    _ensure_atexit_registered()
    _register_signal_handlers()

    temp_path = tempfile.mkdtemp(prefix=prefix)
    _register_ephemeral_dir(temp_path)
    return temp_path


def cleanup_ephemeral_dir(path: Union[str, Path, None]) -> None:
    """Explicitly cleans up an ephemeral directory and de-registers it from tracking."""
    if not path:
        return
    path_str = str(path)
    _unregister_ephemeral_dir(path_str)
    _shutil_rmtree_helper(path_str)


# ==============================================================================
# Feature 1: Target Classifier
# ==============================================================================

class TargetClassifier:
    """Static classifier providing fast binary sniffing and architecture analysis."""

    @staticmethod
    def _validate_path(path: Union[str, Path]) -> Path:
        """Validates path existence, regular file status, and read permissions."""
        p = Path(path).resolve()
        if not p.exists() or not p.is_file():
            raise TargetNotFoundError(
                f"Target binary file does not exist or is not a regular file: {path}"
            )
        if not os.access(str(p), os.R_OK):
            raise TargetPermissionError(
                f"Permission denied reading target binary file: {path}"
            )
        return p

    @classmethod
    def sniff_type(cls, path: Union[str, Path]) -> TargetType:
        """Lightweight sniffer returning TargetType enum."""
        return cls.classify(path).target_type

    @classmethod
    def is_elf(cls, path: Union[str, Path]) -> bool:
        return cls.sniff_type(path) == TargetType.ELF_STANDALONE

    @classmethod
    def is_apk(cls, path: Union[str, Path]) -> bool:
        return cls.sniff_type(path) == TargetType.APK_PACKAGE

    @classmethod
    def is_dex(cls, path: Union[str, Path]) -> bool:
        return cls.sniff_type(path) == TargetType.DEX_STANDALONE

    @classmethod
    def classify(cls, path: Union[str, Path]) -> TargetClassification:
        """Inspects binary header (first 64 bytes) and returns comprehensive TargetClassification."""
        p = cls._validate_path(path)
        try:
            size = p.stat().st_size
        except OSError as e:
            raise TargetNotFoundError(f"Could not stat target file {path}: {e}")

        # Zero-byte file: return TargetType.UNKNOWN
        if size == 0:
            return TargetClassification(
                target_type=TargetType.UNKNOWN,
                format_name="empty",
            )

        with open(p, "rb") as f:
            header = f.read(64)

        if len(header) < 4:
            return TargetClassification(
                target_type=TargetType.UNKNOWN,
                format_name="unknown",
            )

        # 1. Inspect ELF Format
        if header.startswith(b"\x7fELF"):
            if len(header) < 20:
                raise UnparseableBinaryError(f"Truncated ELF identification header in {path}")
            ei_class = header[4]
            ei_data = header[5]

            bits = 32 if ei_class == 1 else (64 if ei_class == 2 else None)
            endian_prefix = "<" if ei_data == 1 else (">" if ei_data == 2 else None)
            endianness = "little" if ei_data == 1 else ("big" if ei_data == 2 else None)

            if bits is None or endian_prefix is None:
                raise UnparseableBinaryError(
                    f"Malformed ELF identification (class={ei_class}, data={ei_data})"
                )

            e_type = struct.unpack_from(endian_prefix + "H", header, 16)[0]
            e_machine = struct.unpack_from(endian_prefix + "H", header, 18)[0]
            is_pie = (e_type == 3)

            machine, abi = ELF_MACHINE_TO_ABI.get(
                (e_machine, ei_class),
                (f"unknown_{e_machine}", None)
            )

            return TargetClassification(
                target_type=TargetType.ELF_STANDALONE,
                format_name="elf",
                bits=bits,
                endianness=endianness,
                e_type=e_type,
                is_pie=is_pie,
                machine=machine,
                abi=abi,
            )

        # 2. Inspect Dalvik DEX Format
        if header.startswith(b"dex\n"):
            if len(header) >= 8 and header[7] == 0:
                ver_bytes = header[4:7]
                try:
                    ver_str = ver_bytes.decode("ascii")
                    if ver_str.isdigit() and 35 <= int(ver_str) <= 39:
                        return TargetClassification(
                            target_type=TargetType.DEX_STANDALONE,
                            format_name="dex",
                            dex_version=ver_str,
                        )
                except Exception:
                    pass
            raise UnparseableBinaryError(f"Malformed or unsupported DEX header in {path}")

        # 3. Inspect APK / ZIP Format
        if header.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(str(p), "r") as zf:
                    names = set(zf.namelist())
                    has_manifest = "AndroidManifest.xml" in names
                    has_dex = any(
                        n == "classes.dex" or (n.startswith("classes") and n.endswith(".dex"))
                        for n in names
                    )
                    if has_manifest or has_dex:
                        return TargetClassification(
                            target_type=TargetType.APK_PACKAGE,
                            format_name="apk",
                            has_manifest=has_manifest,
                            has_dex=has_dex,
                        )
            except zipfile.BadZipFile as e:
                raise MalformedPackageError(f"Corrupted ZIP container in {path}: {e}") from e

        # 4. Unrecognized Binary Format
        return TargetClassification(
            target_type=TargetType.UNKNOWN,
            format_name="unknown",
        )


# ==============================================================================
# Feature 3: Safe ZIP Extraction & Member Filtering
# ==============================================================================

def is_safe_archive_member(member_name: str, target_dir: Path) -> bool:
    """
    Validate that an archive member does not execute a Zip Slip directory traversal.
    Enforces slash normalization, rejection of leading slashes and drive letters,
    rejection of '..' components, and canonical boundary containment check.
    """
    clean_name = member_name.replace("\\", "/")

    # Reject leading slashes and absolute paths
    if clean_name.startswith("/") or os.path.isabs(clean_name):
        return False

    # Reject Windows drive letters (e.g. C:file)
    if len(clean_name) >= 2 and clean_name[1] == ":" and clean_name[0].isalpha():
        return False

    # Reject directory traversal components
    parts = clean_name.split("/")
    if any(p == ".." for p in parts):
        return False

    # Canonical containment check
    resolved_dest = (target_dir / clean_name).resolve()
    resolved_root = target_dir.resolve()
    try:
        return resolved_dest.is_relative_to(resolved_root)
    except AttributeError:
        return str(resolved_dest).startswith(str(resolved_root) + os.sep)


def extract_apk_container(
    apk_path: Union[str, Path],
    destination_dir: Union[str, Path],
) -> List[TargetComponent]:
    """
    Selectively and safely unpacks an APK container into an ephemeral directory.

    Extracts ONLY:
    - Dalvik executables (classes*.dex)
    - Native shared libraries (lib/<abi>/*.so)

    Applies strict Zip Slip containment validation and prunes non-executable container bloat.
    """
    dest_path = Path(destination_dir).resolve()
    dest_path.mkdir(parents=True, exist_ok=True)
    components: List[TargetComponent] = []

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                # Skip directory entries
                if info.is_dir() or info.filename.endswith("/"):
                    continue

                raw_name = info.filename
                clean_name = raw_name.replace("\\", "/")

                # Skip symbolic links (S_IFLNK = 0o120000)
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue

                # Zip Slip security check: validate ALL entries for containment!
                if not is_safe_archive_member(clean_name, dest_path):
                    raise SecurityViolationError(
                        f"Zip Slip path traversal attempt detected in archive entry: {raw_name}"
                    )

                # Selective filtering check
                is_dex = bool(DEX_FILENAME_RE.match(clean_name))
                so_match = NATIVE_SO_RE.match(clean_name)
                is_so = bool(so_match)

                if not (is_dex or is_so):
                    # Discard non-analyzable asset (res/, assets/, META-INF/, etc.)
                    continue

                # Safe streaming extraction
                target_file = (dest_path / clean_name).resolve()
                target_file.parent.mkdir(parents=True, exist_ok=True)

                with zf.open(info) as src, open(target_file, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                if is_dex:
                    components.append(
                        TargetComponent(
                            path=str(target_file),
                            component_type="dex",
                            abi=None,
                            archive_relpath=clean_name,
                        )
                    )
                elif is_so and so_match:
                    abi = so_match.group(1)
                    components.append(
                        TargetComponent(
                            path=str(target_file),
                            component_type="elf_so",
                            abi=abi,
                            archive_relpath=clean_name,
                        )
                    )

    except zipfile.BadZipFile as e:
        raise MalformedPackageError(f"Corrupted or invalid APK archive at '{apk_path}': {e}") from e

    # Deterministic sorting:
    # 1. Natural multidex sorting (classes.dex, classes2.dex, classes3.dex, ...)
    # 2. Native libraries sorted by (abi, name)
    dex_comps = [c for c in components if c.component_type == "dex"]
    so_comps = [c for c in components if c.component_type == "elf_so"]

    def _dex_key(c: TargetComponent) -> int:
        m = re.match(r"^classes(\d*)\.dex$", c.archive_relpath)
        if not m or not m.group(1):
            return 1
        return int(m.group(1))

    dex_comps.sort(key=_dex_key)
    so_comps.sort(key=lambda c: (c.abi or "", c.name))

    return dex_comps + so_comps


# ==============================================================================
# Unified Target Abstraction
# ==============================================================================

class UnifiedTarget:
    """
    Unified container representing an ingested binary target (standalone ELF or APK container).
    Equipped with 6-Tier Ephemeral Lifecycle Watchdog.
    """

    def __init__(
        self,
        primary_path: str,
        target_type: TargetType,
        components: List[TargetComponent],
        temp_dir: Optional[str] = None,
        is_ephemeral: bool = False,
        default_abi: str = "x86_64",
        original_path: Optional[str] = None,
    ) -> None:
        self.original_path = str(original_path or primary_path)
        self._primary_path = str(primary_path)
        self.target_type = target_type
        self.components = list(components)
        self.temp_dir = temp_dir
        self.is_ephemeral = is_ephemeral
        self.default_abi = default_abi
        self._selected_component: Optional[TargetComponent] = None
        self._cleaned_up = False
        self._lock = threading.Lock()

        # Resolve initial active component
        self._resolve_initial_component()

        # Tier 3: Attach weakref GC finalizer
        if self.is_ephemeral and self.temp_dir:
            self._finalizer: Optional[Any] = weakref.finalize(
                self, _finalizer_cleanup, self.temp_dir
            )
        else:
            self._finalizer = None

    @property
    def primary_path(self) -> str:
        """
        Resolves to the active binary path passed to downstream rvs engine.
        Returns canonical path for standalone ELF, or active native .so / classes.dex for APK.
        """
        if self.target_type == TargetType.ELF_STANDALONE:
            return self._primary_path
        if self._selected_component is not None:
            return self._selected_component.path
        if self._primary_path is not None:
            return self._primary_path
        if self.components:
            return self.components[0].path
        return self.original_path

    @primary_path.setter
    def primary_path(self, val: str) -> None:
        self._primary_path = str(val)

    @property
    def primary_component(self) -> Optional[TargetComponent]:
        return self._selected_component

    def get_components(self, comp_type: Optional[str] = None) -> List[TargetComponent]:
        """Returns all components, optionally filtered by component type."""
        if comp_type is None:
            return list(self.components)
        if comp_type == "elf_so":
            return [
                c for c in self.components
                if c.component_type in ("elf_so", "elf_standalone", "elf")
            ]
        return [c for c in self.components if c.component_type == comp_type]

    def get_component(
        self, abi: Optional[str] = None, comp_type: str = "elf_so"
    ) -> Optional[TargetComponent]:
        """
        Resolves a single component by ABI or type, applying ABI priority hierarchy.
        """
        candidates = [
            c for c in self.components
            if (comp_type is None)
            or (c.component_type == comp_type)
            or (comp_type == "elf_so" and c.component_type in ("elf_so", "elf_standalone", "elf"))
        ]
        if not candidates:
            return None

        if comp_type == "dex":
            for c in candidates:
                if c.archive_relpath == "classes.dex" or c.name == "classes.dex":
                    return c
            return candidates[0]

        if abi is not None:
            for c in candidates:
                if c.abi == abi:
                    return c
            return None

        # ABI priority resolution when abi=None
        host_abi = get_host_abi()
        preference = [self.default_abi, host_abi, "x86_64", "arm64-v8a", "armeabi-v7a", "x86"]
        seen: Set[str] = set()
        dedup_pref = [x for x in preference if not (x in seen or seen.add(x))]

        for pref in dedup_pref:
            for c in candidates:
                if c.abi == pref:
                    return c
        return candidates[0]

    def select_component(
        self,
        abi: Optional[str] = None,
        comp_type: str = "elf_so",
        name: Optional[str] = None,
    ) -> Optional[TargetComponent]:
        """Explicitly switches the active primary component."""
        if name is not None:
            for c in self.components:
                if c.name == name or c.archive_relpath == name:
                    if abi is None or c.abi == abi:
                        self._selected_component = c
                        return c
            return None

        comp = self.get_component(abi=abi, comp_type=comp_type)
        if comp:
            self._selected_component = comp
        return comp

    def _resolve_initial_component(self) -> None:
        """Determines the default active component upon ingestion."""
        if not self.components:
            self._selected_component = None
            return

        comp = self.get_component(abi=self.default_abi, comp_type="elf_so")
        if comp is None:
            comp = self.get_component(abi=None, comp_type="elf_so")
        if comp is None:
            comp = self.get_component(comp_type="dex")
        if comp is None:
            comp = self.components[0]
        self._selected_component = comp

    def cleanup(self) -> None:
        """Tier 2: Explicit idempotent cleanup. Thread-safe."""
        with self._lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True

            # Detach GC finalizer to prevent redundant calls
            if self._finalizer is not None:
                try:
                    self._finalizer.detach()
                except Exception:
                    pass
                self._finalizer = None

            # Evacuate ephemeral directory
            if self.is_ephemeral and self.temp_dir:
                td = self.temp_dir
                self.temp_dir = None
                cleanup_ephemeral_dir(td)

    def close(self) -> None:
        """Alias for cleanup()."""
        self.cleanup()

    def __enter__(self) -> "UnifiedTarget":
        """Tier 1: Context manager entry."""
        if self._cleaned_up:
            raise RuntimeError("Cannot enter context: UnifiedTarget has already been cleaned up")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Tier 1: Context manager exit with zero exception suppression."""
        self.cleanup()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "primary_path": self.primary_path,
            "target_type": self.target_type.value if hasattr(self.target_type, "value") else str(self.target_type),
            "components": [c.to_dict() for c in self.components],
            "temp_dir": self.temp_dir,
            "is_ephemeral": self.is_ephemeral,
        }


# ==============================================================================
# Feature 2 & Main Ingestion Entry Point
# ==============================================================================

def ingest_target(path: str, default_abi: str = "x86_64") -> UnifiedTarget:
    """
    Main entry point for multi-format target ingestion.

    - Standalone ELF: Zero-copy passthrough; canonical primary_path; temp_dir=None; is_ephemeral=False.
    - APK Package: Ephemeral extraction with Zip Slip defense; indices DEX and native .so; 6-tier watchdog.
    - DEX Standalone: Non-destructive direct referencing; is_ephemeral=False.
    - Unknown format: Safe encapsulation with target_type=UNKNOWN.
    """
    canonical_path = str(Path(path).resolve())
    classification = TargetClassifier.classify(path)

    if classification.target_type == TargetType.ELF_STANDALONE:
        # Zero-copy passthrough
        component = TargetComponent(
            path=canonical_path,
            component_type="elf_so",
            abi=classification.abi or default_abi,
            archive_relpath="",
        )
        return UnifiedTarget(
            primary_path=canonical_path,
            target_type=TargetType.ELF_STANDALONE,
            components=[component],
            temp_dir=None,
            is_ephemeral=False,
            default_abi=default_abi,
            original_path=canonical_path,
        )

    elif classification.target_type == TargetType.DEX_STANDALONE:
        component = TargetComponent(
            path=canonical_path,
            component_type="dex",
            abi=None,
            archive_relpath="",
        )
        return UnifiedTarget(
            primary_path=canonical_path,
            target_type=TargetType.DEX_STANDALONE,
            components=[component],
            temp_dir=None,
            is_ephemeral=False,
            default_abi=default_abi,
            original_path=canonical_path,
        )

    elif classification.target_type == TargetType.APK_PACKAGE:
        temp_dir = create_ephemeral_dir()
        try:
            components = extract_apk_container(canonical_path, temp_dir)
            return UnifiedTarget(
                primary_path=canonical_path,
                target_type=TargetType.APK_PACKAGE,
                components=components,
                temp_dir=temp_dir,
                is_ephemeral=True,
                default_abi=default_abi,
                original_path=canonical_path,
            )
        except Exception:
            cleanup_ephemeral_dir(temp_dir)
            raise

    else:
        # Unknown binary target
        return UnifiedTarget(
            primary_path=canonical_path,
            target_type=TargetType.UNKNOWN,
            components=[],
            temp_dir=None,
            is_ephemeral=False,
            default_abi=default_abi,
            original_path=canonical_path,
        )


__all__ = [
    "TargetType",
    "TargetComponent",
    "TargetClassification",
    "TargetClassifier",
    "UnifiedTarget",
    "ingest_target",
    "extract_apk_container",
    "is_safe_archive_member",
    "create_ephemeral_dir",
    "cleanup_ephemeral_dir",
    "sweep_orphaned_target_dirs",
    "get_host_abi",
    "EPHEMERAL_DIR_PREFIX",
    "TargetIngestionError",
    "TargetNotFoundError",
    "TargetPermissionError",
    "EmptyTargetError",
    "UnparseableBinaryError",
    "SecurityViolationError",
    "MalformedPackageError",
]
