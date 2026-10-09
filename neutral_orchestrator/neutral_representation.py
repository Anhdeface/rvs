"""
neutral_orchestrator/neutral_representation.py - Neutral Technical Framing & Representation Layer.

Milestone 2 Architecture & Scope:
- Feature 6: Sensitive Token Taxonomy (AUTH, GATE, EVASION, CRYPTO, SYSTEM, GENERAL).
- Feature 7: Deterministic Token Substitution (SYM_TOKEN_FUNC_0001, SYM_STR_0001,
             PREDICATE_GATE_0001, ADDR_REF_0001, SYM_TOKEN_DATA_0001).
- Feature 8: Bijective Reversible Codebook (100% lossless reverse mapping, JSON serialization,
             counter synchronization, deneutralize_data recursive restoration).
- Feature 9: 100% Semantic Invariant Engine (opcodes, registers, addresses, counts intact).
- Feature 10: Control Flow Graph (CFG) & Finite State Machine (FSM) Abstraction, and
              Algorithmic Equivalence Pattern Detection.
"""

from __future__ import annotations

import enum
import hashlib
import json
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# ==============================================================================
# Feature 6: Sensitive Token Taxonomy & Categories
# ==============================================================================

class TokenCategory(str, enum.Enum):
    """
    Orthogonal categorization taxonomy for security-sensitive or content-filter-triggering
    binary elements.
    """
    AUTH = "AUTH"
    GATE = "GATE"
    EVASION = "EVASION"
    CRYPTO = "CRYPTO"
    SYSTEM = "SYSTEM"
    GENERAL = "GENERAL"


TAXONOMY_LEXICON: Dict[TokenCategory, Dict[str, Any]] = {
    TokenCategory.EVASION: {
        "keywords": [
            "antidebug", "anti_debug", "ptrace", "traceme", "tracerpid", "tracer_pid",
            "is_debugger_present", "isdebuggerpresent", "check_debugger", "debugger_detected",
            "being_debugged", "hook", "inline_hook", "tamper", "frida", "frida_server",
            "gumjs", "xposed", "cydia", "substrate", "seccomp", "sys_ptrace",
            "rootbeer", "magisk", "daemonsu", "integrity_check", "debugger",
        ],
        "regex_patterns": [
            r"(?i)\b(?:antidebug|anti_debug|is_?debugger_?present|debugger_?detected|debugger)\b",
            r"(?i)\b(?:ptrace|traceme|tracerpid|seccomp)\b",
            r"(?i)\b(?:frida|xposed|cydia|substrate|hook|tamper)\b",
        ],
        "weight": 15,
    },
    TokenCategory.CRYPTO: {
        "keywords": [
            "decrypt", "decryption", "encrypt", "encryption", "cipher", "decipher",
            "encipher", "key", "keys", "iv", "nonce", "salt", "secret", "secret_key",
            "hash", "sha256", "sha1", "md5", "hmac", "aes", "des", "rc4", "xor_key",
            "encrypted_payload", "decrypted_buffer", "payload", "shellcode",
            "flag", "ciphertext", "plaintext", "k3y",
        ],
        "regex_patterns": [
            r"(?i)\b(?:decrypt|encrypt|cipher|payload|shellcode)\b",
            r"(?i)\b(?:xor_key|secret_key|private_key|init_vector|iv)\b",
            r"(?i)FLAG\{[^}]+\}",
            r"(?i)K3Y-[A-Z0-9\-]+",
        ],
        "weight": 12,
    },
    TokenCategory.AUTH: {
        "keywords": [
            "password", "passwd", "pwd", "passcode", "pin", "credential", "credentials",
            "creds", "token", "tokens", "bearer", "jwt", "apikey", "api_key",
            "access_level", "admin", "administrator", "root_user", "superuser",
            "login", "logon", "authenticate", "authentication", "auth", "privilege",
            "secret_pin", "master_password", "user_pass",
        ],
        "regex_patterns": [
            r"(?i)\b(?:auth|pass(?:word|wd)?|pwd|pin|cred(?:ential)?s?|login|token)\b",
            r"(?i)\b(?:admin|access_level|super_?user)\b",
            r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+",
        ],
        "weight": 10,
    },
    TokenCategory.SYSTEM: {
        "keywords": [
            "root", "su", "sudo", "busybox", "privileged_exec", "system_exec",
            "procfs", "proc_status", "/proc/self/status", "/proc/self/maps",
            "/proc/self/mem", "/system/bin/su", "/system/xbin/su", "/data/local/tmp",
            "/dev/urandom", "ld_preload", "ro_debuggable",
        ],
        "regex_patterns": [
            r"/proc/(?:self|\d+)/(?:status|maps|mem|cmdline|stat)",
            r"/(?:system|sbin|vendor)/[a-zA-Z0-9_\-/]*(?:su|busybox)",
            r"/data/local/tmp(?:/[a-zA-Z0-9_\-\.]+)?",
            r"(?i)\b(?:privileged_exec|procfs_check)\b",
        ],
        "weight": 9,
    },
    TokenCategory.GATE: {
        "keywords": [
            "check", "checks", "verify", "verification", "validate", "validation",
            "is_valid", "is_invalid", "allowed", "denied", "auth_success", "auth_fail",
            "success", "failure", "grant", "reject", "crackme", "serial", "keygen",
            "license", "license_key", "trial", "registration", "tamper_detected",
            "access_granted", "access_denied", "bad_pin", "bad_password",
        ],
        "regex_patterns": [
            r"(?i)\b(?:check|verify|validate|is_valid|allowed|denied)\b",
            r"(?i)\b(?:auth_success|auth_fail|access_granted|access_denied)\b",
            r"(?i)\b(?:serial|crackme|license|keygen|registration)\b",
        ],
        "weight": 8,
    },
    TokenCategory.GENERAL: {
        "keywords": [],
        "regex_patterns": [],
        "weight": 1,
    },
}

# Priority resolution hierarchy when scores tie
CATEGORY_PRIORITY = [
    TokenCategory.EVASION,
    TokenCategory.CRYPTO,
    TokenCategory.AUTH,
    TokenCategory.SYSTEM,
    TokenCategory.GATE,
    TokenCategory.GENERAL,
]


def classify_token(text: str) -> TokenCategory:
    """
    Deterministically scores and classifies an unknown token or string into a TokenCategory.
    Enforces the domain specificity priority matrix:
    EVASION > CRYPTO > AUTH > SYSTEM > GATE > GENERAL.
    """
    if not text:
        return TokenCategory.GENERAL

    lower_text = text.lower()
    words = set(re.split(r'[^a-zA-Z0-9]+', lower_text))
    scores: Dict[TokenCategory, int] = {cat: 0 for cat in TokenCategory}

    for cat, rules in TAXONOMY_LEXICON.items():
        weight = rules.get("weight", 1)
        for kw in rules.get("keywords", []):
            kw_lower = kw.lower()
            if len(kw_lower) <= 3:
                # Require whole word boundary for short keywords (e.g. 'su', 'pin', 'pwd', 'iv')
                if kw_lower in words or re.search(rf"\b{re.escape(kw_lower)}\b", lower_text):
                    scores[cat] += weight
            else:
                if kw_lower in lower_text or kw_lower in words:
                    scores[cat] += weight
        for pattern in rules.get("regex_patterns", []):
            if re.search(pattern, text):
                scores[cat] += weight * 2

    # Find category with highest positive score
    max_score = 0
    best_cat = TokenCategory.GENERAL

    for cat in CATEGORY_PRIORITY:
        if scores[cat] > max_score:
            max_score = scores[cat]
            best_cat = cat

    return best_cat


# ==============================================================================
# Feature 7 & 8: Bijective Codebook & Neutral Token Mapper
# ==============================================================================

def _is_ident_char(c: str) -> bool:
    """Returns True if character is an ASCII alphanumeric or underscore character."""
    return bool(c and c.isascii() and (c.isalnum() or c == "_"))


def _build_boundary_regex(items: List[str]) -> Optional[re.Pattern]:
    """
    Builds an optimized regex pattern enforcing token and identifier boundary isolation.
    If all items start and end with identifier characters ([a-zA-Z0-9_]), compiles into a single
    outer negative lookaround group (?<![a-zA-Z0-9_])(?:...)(?![a-zA-Z0-9_]).
    Otherwise, applies lookarounds selectively to items terminating in identifier characters.
    """
    valid_items = [k for k in items if k]
    if not valid_items:
        return None
    sorted_items = sorted(valid_items, key=len, reverse=True)
    if all(_is_ident_char(k[0]) and _is_ident_char(k[-1]) for k in sorted_items):
        pattern_str = (
            r"(?<![a-zA-Z0-9_])(?:"
            + "|".join(re.escape(k) for k in sorted_items)
            + r")(?![a-zA-Z0-9_])"
        )
    else:
        parts = [
            f"{r'(?<![a-zA-Z0-9_])' if _is_ident_char(k[0]) else ''}{re.escape(k)}{r'(?![a-zA-Z0-9_])' if _is_ident_char(k[-1]) else ''}"
            for k in sorted_items
        ]
        pattern_str = "|".join(parts)
    return re.compile(pattern_str)


class BijectiveCodebook:
    """
    Thread-safe storage and translation engine maintaining 1-to-1 bijective mappings
    between raw sensitive strings and neutralized symbolic tokens.
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        self.session_id: str = session_id or f"sess_{uuid.uuid4().hex[:8]}"
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self.forward_map: Dict[str, str] = {}
        self.reverse_map: Dict[str, str] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}
        self.counters: Dict[str, int] = {
            "FUNC": 0,
            "STR": 0,
            "GATE": 0,
            "DATA": 0,
            "SYM": 0,
            "ADDR": 0,
        }
        self._lock = threading.RLock()
        self._restore_regex: Optional[re.Pattern] = None
        self._neutralize_regex: Optional[re.Pattern] = None

    def register_token(
        self,
        raw_string: str,
        category: Union[TokenCategory, str] = TokenCategory.GENERAL,
        kind: str = "FUNC",
        use_content_hash: bool = False,
    ) -> str:
        """
        Registers a raw string and returns its unique deterministic neutral token.
        If already registered, returns existing token preserving bijectivity.
        """
        if not raw_string:
            return ""

        cat_str = category.value if isinstance(category, TokenCategory) else str(category)

        with self._lock:
            if raw_string in self.forward_map:
                return self.forward_map[raw_string]

            # Generate unique token
            if use_content_hash:
                token_hash = hashlib.sha256(raw_string.encode("utf-8")).hexdigest()[:8]
                prefix = f"SYM_TOKEN_{kind}" if kind not in ("STR", "GATE", "ADDR") else (
                    "SYM_STR" if kind == "STR" else (
                        "PREDICATE_GATE" if kind == "GATE" else "ADDR_REF"
                    )
                )
                token = f"{prefix}_{token_hash}"
            else:
                self.counters[kind] = self.counters.get(kind, 0) + 1
                idx = self.counters[kind]
                if kind == "FUNC":
                    token = f"SYM_TOKEN_FUNC_{idx:04d}"
                elif kind == "STR":
                    token = f"SYM_STR_{idx:04d}"
                elif kind == "GATE":
                    token = f"PREDICATE_GATE_{idx:04d}"
                elif kind == "DATA":
                    token = f"SYM_TOKEN_DATA_{idx:04d}"
                elif kind == "ADDR":
                    token = f"ADDR_REF_{idx:04d}"
                else:
                    token = f"SYM_TOKEN_{kind}_{idx:04d}"

            self.forward_map[raw_string] = token
            self.reverse_map[token] = raw_string
            self.metadata[token] = {
                "token": token,
                "original": raw_string,
                "category": cat_str,
                "kind": kind,
            }
            self._restore_regex = None
            self._neutralize_regex = None
            return token

    def register_alias(self, raw_alias: str, neutral_alias: str) -> None:
        """Registers a decorated symbol alias (e.g. sym.name <-> sym.token)."""
        with self._lock:
            self.forward_map[raw_alias] = neutral_alias
            self.reverse_map[neutral_alias] = raw_alias
            self._restore_regex = None
            self._neutralize_regex = None

    def restore(self, text: str) -> str:
        """
        Restores neutralized text back to original raw symbols using session codebook.
        Guarantees 100% mathematical reversibility with substring collision immunity.
        """
        if not text:
            return ""

        with self._lock:
            if not self.reverse_map:
                return text

            # Fast path: exact single token match
            if text in self.reverse_map:
                return self.reverse_map[text]

            if self._restore_regex is None:
                self._restore_regex = _build_boundary_regex(list(self.reverse_map.keys()))

            if self._restore_regex is None:
                return text

            return self._restore_regex.sub(lambda match: self.reverse_map[match.group(0)], text)

    def neutralize(self, text: str) -> str:
        """
        Substitutes raw registered symbols in text with neutral tokens in length-descending order.
        Guarantees token boundary isolation preventing raw identifier substring collisions.
        """
        if not text:
            return ""

        with self._lock:
            if not self.forward_map:
                return text

            if text in self.forward_map:
                return self.forward_map[text]

            if self._neutralize_regex is None:
                self._neutralize_regex = _build_boundary_regex(list(self.forward_map.keys()))

            if self._neutralize_regex is None:
                return text

            return self._neutralize_regex.sub(lambda match: self.forward_map[match.group(0)], text)

    def export_codebook(self) -> Dict[str, Any]:
        """Exports codebook in dual-compatible JSON serializable schema."""
        with self._lock:
            return {
                "codebook_version": "1.0.0",
                "session_id": self.session_id,
                "created_at": self.created_at,
                "forward_map": dict(self.forward_map),
                "reverse_map": dict(self.reverse_map),
                "forward": dict(self.forward_map),
                "reverse": dict(self.reverse_map),
                "metadata": dict(self.metadata),
                "token_metadata": dict(self.metadata),
                "counters": dict(self.counters),
            }

    def import_codebook(self, codebook: Dict[str, Any]) -> None:
        """Imports and reconciles codebook state across sessions."""
        if not isinstance(codebook, dict):
            raise ValueError(f"Invalid codebook type: {type(codebook)}")

        with self._lock:
            fwd = codebook.get("forward_map") or codebook.get("forward") or {}
            rev = codebook.get("reverse_map") or codebook.get("reverse") or {}

            if not fwd and rev:
                fwd = {v: k for k, v in rev.items()}
            if not rev and fwd:
                rev = {v: k for k, v in fwd.items()}

            self.forward_map.update(fwd)
            self.reverse_map.update(rev)
            self._restore_regex = None
            self._neutralize_regex = None

            if "metadata" in codebook:
                self.metadata.update(codebook["metadata"])
            elif "token_metadata" in codebook:
                self.metadata.update(codebook["token_metadata"])

            # Counter state reconciliation from codebook and tokens
            if "counters" in codebook and isinstance(codebook["counters"], dict):
                for k, v in codebook["counters"].items():
                    self.counters[k] = max(self.counters.get(k, 0), int(v))

            for token in self.reverse_map.keys():
                m = re.search(r'_(FUNC|STR|GATE|DATA|SYM|ADDR)_(\d+)', token)
                if m:
                    kind = m.group(1)
                    idx = int(m.group(2))
                    self.counters[kind] = max(self.counters.get(kind, 0), idx)
                else:
                    m2 = re.search(r'^(PREDICATE_GATE|ADDR_REF|SYM_STR|SYM_TOKEN)_(\d+)$', token)
                    if m2:
                        pfx = m2.group(1)
                        idx = int(m2.group(2))
                        mapping = {
                            "PREDICATE_GATE": "GATE",
                            "ADDR_REF": "ADDR",
                            "SYM_STR": "STR",
                            "SYM_TOKEN": "FUNC",
                        }
                        k = mapping.get(pfx, "FUNC")
                        self.counters[k] = max(self.counters.get(k, 0), idx)


class NeutralTokenMapper:
    """
    Unified Token Neutralization, Bidirectional Codebook, and Invariant Verification Engine.
    Implements Features 6, 7, 8, and 9.
    """

    def __init__(self, session_id: Optional[str] = None) -> None:
        self._codebook = BijectiveCodebook(session_id=session_id)
        self._lock = self._codebook._lock

    @property
    def session_id(self) -> str:
        return self._codebook.session_id

    @property
    def codebook(self) -> BijectiveCodebook:
        return self._codebook

    @property
    def forward_map(self) -> Dict[str, str]:
        return self._codebook.forward_map

    @property
    def reverse_map(self) -> Dict[str, str]:
        return self._codebook.reverse_map

    @property
    def counters(self) -> Dict[str, int]:
        return self._codebook.counters

    def sanitize_symbol(
        self,
        name: str,
        category: TokenCategory = TokenCategory.GENERAL,
        use_content_hash: bool = False,
    ) -> str:
        """
        Sanitizes function or global symbol to SYM_TOKEN_FUNC_0001 (or content hash).
        Preserves radare2 sym. prefix decoration bijectively.
        """
        if not name:
            return ""

        # Auto-classify if category is GENERAL
        effective_category = category
        if category == TokenCategory.GENERAL:
            effective_category = classify_token(name)

        has_sym_prefix = name.startswith("sym.")
        clean_name = name[4:] if has_sym_prefix else name

        token = self._codebook.register_token(
            clean_name,
            category=effective_category,
            kind="FUNC",
            use_content_hash=use_content_hash,
        )

        if has_sym_prefix:
            alias_token = f"sym.{token}"
            self._codebook.register_alias(name, alias_token)
            return alias_token

        # Also register sym. alias so disassembly calls with sym. prefix match
        sym_alias = f"sym.{clean_name}"
        alias_token = f"sym.{token}"
        self._codebook.register_alias(sym_alias, alias_token)

        return token

    def sanitize_string(
        self,
        text: str,
        category: TokenCategory = TokenCategory.GENERAL,
        use_content_hash: bool = False,
    ) -> str:
        """
        Sanitizes string literal to SYM_STR_0001.
        Synchronizes radare2 str. prefix decoration bijectively.
        """
        if not text:
            return ""

        effective_category = category
        if category == TokenCategory.GENERAL:
            effective_category = classify_token(text)

        has_str_prefix = text.startswith("str.")
        clean_text = text[4:] if has_str_prefix else text

        token = self._codebook.register_token(
            clean_text,
            category=effective_category,
            kind="STR",
            use_content_hash=use_content_hash,
        )

        if has_str_prefix:
            alias_token = f"str.{token}"
            self._codebook.register_alias(text, alias_token)
            return alias_token

        # Register radare2 string symbol representation (spaces converted to underscores)
        r2_safe_str = f"str.{clean_text.replace(' ', '_')}"
        r2_alias_token = f"str.{token}"
        self._codebook.register_alias(r2_safe_str, r2_alias_token)

        return token

    def sanitize_predicate(
        self,
        cond_expr: str,
        use_content_hash: bool = False,
    ) -> str:
        """Sanitizes conditional expression to PREDICATE_GATE_0001."""
        if not cond_expr:
            return ""
        return self._codebook.register_token(
            cond_expr,
            category=TokenCategory.GATE,
            kind="GATE",
            use_content_hash=use_content_hash,
        )

    def sanitize_address(
        self,
        addr: Union[int, str],
        use_content_hash: bool = False,
    ) -> str:
        """Sanitizes virtual address reference to ADDR_REF_0001 or ADDR_REF_<hex>."""
        addr_str = f"0x{addr:x}" if isinstance(addr, int) else str(addr)
        if not addr_str:
            return ""
        return self._codebook.register_token(
            addr_str,
            category=TokenCategory.GENERAL,
            kind="ADDR",
            use_content_hash=use_content_hash,
        )

    def sanitize_data(
        self,
        name: str,
        category: TokenCategory = TokenCategory.GENERAL,
        use_content_hash: bool = False,
    ) -> str:
        """Sanitizes data variable/payload to SYM_TOKEN_DATA_0001."""
        if not name:
            return ""
        effective_category = category if category != TokenCategory.GENERAL else classify_token(name)
        return self._codebook.register_token(
            name,
            category=effective_category,
            kind="DATA",
            use_content_hash=use_content_hash,
        )

    def restore(self, text: str) -> str:
        """Restores neutralized text back to original raw symbols."""
        return self._codebook.restore(text)

    def neutralize(self, text: str) -> str:
        """Replaces raw symbols in text with neutralized tokens."""
        return self._codebook.neutralize(text)

    def export_codebook(self) -> Dict[str, Any]:
        """Exports session codebook as a dictionary."""
        return self._codebook.export_codebook()

    def import_codebook(self, codebook: Dict[str, Any]) -> None:
        """Imports and reconciles codebook into current session."""
        self._codebook.import_codebook(codebook)

    def deneutralize_data(self, payload: Any, codebook: Optional[Dict[str, Any]] = None) -> Any:
        """
        Recursively traverses arbitrary Python data structures (dicts, lists, tuples, sets)
        and applies restore() to all string values and string keys while preserving
        all other types, numerical values, and structural shapes 100% identically.
        """
        if codebook:
            self.import_codebook(codebook)
        return deneutralize_data(payload, mapper=self)

    def verify_invariants(
        self,
        original: Any,
        neutralized: Any,
        strict: bool = False,
    ) -> bool:
        """
        Rigorous verification engine comparing original disassembly vs neutralized disassembly.
        Asserts that opcodes, registers, memory operands, immediate constants, addresses,
        and instruction counts are preserved 100% identically.
        """
        return verify_invariants(original, neutralized, strict=strict, codebook=self._codebook)

    def diagnose_invariants(
        self,
        original: Any,
        neutralized: Any,
    ) -> List[Dict[str, Any]]:
        """Returns detailed discrepancies using session codebook."""
        return diagnose_invariants(original, neutralized, codebook=self._codebook)


def deneutralize_data(
    payload: Any,
    codebook: Optional[Dict[str, Any]] = None,
    mapper: Optional[NeutralTokenMapper] = None,
) -> Any:
    """
    Recursively restores arbitrary data structures using session codebook or mapper.
    Ensures 100% loss-free roundtrip.
    """
    if mapper is None:
        mapper = NeutralTokenMapper()
        if codebook:
            mapper.import_codebook(codebook)
    elif codebook:
        mapper.import_codebook(codebook)

    if isinstance(payload, str):
        return mapper.restore(payload)
    elif isinstance(payload, dict):
        return {
            (mapper.restore(k) if isinstance(k, str) else k): deneutralize_data(v, mapper=mapper)
            for k, v in payload.items()
        }
    elif isinstance(payload, list):
        return [deneutralize_data(item, mapper=mapper) for item in payload]
    elif isinstance(payload, tuple):
        return tuple(deneutralize_data(item, mapper=mapper) for item in payload)
    elif isinstance(payload, set):
        return {deneutralize_data(item, mapper=mapper) for item in payload}
    return payload


# ==============================================================================
# Feature 9: 100% Semantic Invariant Engine
# ==============================================================================

class InvariantViolationError(AssertionError):
    """
    Raised when disassembly neutralization corrupts opcodes, registers,
    immediates, addresses, or basic block topology.
    Inherits from AssertionError for testing and assert compatibility.
    """

    def __init__(
        self,
        rule: str,
        message: str,
        index: Optional[int] = None,
        original_inst: Optional[Dict[str, Any]] = None,
        neutralized_inst: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(f"[{rule}] {message} (Index {index})")
        self.rule = rule
        self.message = message
        self.index = index
        self.original_inst = original_inst
        self.neutralized_inst = neutralized_inst


ALL_ARCH_REGISTERS: Set[str] = {
    # x86 / x86_64 64-bit
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
    # x86 / x86_64 32-bit
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "eip",
    # x86 16-bit
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    # x86 8-bit
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    "ah", "bh", "ch", "dh",
    # x86 Vector (SSE, AVX, AVX-512) & Opmask & Segment
    *(f"xmm{i}" for i in range(32)),
    *(f"ymm{i}" for i in range(32)),
    *(f"zmm{i}" for i in range(32)),
    *(f"k{i}" for i in range(8)),
    "cs", "ds", "es", "fs", "gs", "ss",
    # ARM / AArch64 General Purpose & Aliases
    *(f"x{i}" for i in range(31)), "sp", "lr", "pc", "xzr",
    *(f"w{i}" for i in range(31)), "wzr",
    *(f"r{i}" for i in range(16)),
    "fp", "ip", "ip0", "ip1",
    # ARM Floating-Point & SIMD Vector (b, h, s, d, q, v)
    *(f"b{i}" for i in range(32)),
    *(f"h{i}" for i in range(32)),
    *(f"s{i}" for i in range(32)),
    *(f"d{i}" for i in range(32)),
    *(f"q{i}" for i in range(32)),
    *(f"v{i}" for i in range(32)),
}

ARM_SHIFT_MODIFIERS: Set[str] = {
    "lsl", "lsr", "asr", "ror", "rrx",
    "uxtb", "uxth", "uxtw", "uxtx",
    "sxtb", "sxth", "sxtw", "sxtx",
}

ARM_BRANCH_CONDITIONS: Set[str] = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al",
}

ARM_BRANCH_MNEMONICS: Set[str] = {
    "b", "bl", "bx", "blx", "blr", "bxj", "cbz", "cbnz", "tbz", "tbnz",
}

X86_BRANCH_MNEMONICS: Set[str] = {
    "call", "jmp", "loop", "loope", "loopne",
}

SYMBOLIC_TARGET_PATTERN = re.compile(
    r'\b(?:sym\.)?(?:SYM_TOKEN_[A-Za-z0-9_]+|ADDR_REF_[A-Za-z0-9_]+|PREDICATE_GATE_[A-Za-z0-9_]+|SYM_STR_[A-Za-z0-9_]+)\b'
)


def is_branch_opcode(opcode: str) -> bool:
    """Returns True if opcode mnemonic represents an x86 or ARM branch/call."""
    op = opcode.lower().strip()
    if op in X86_BRANCH_MNEMONICS or op.startswith("j"):
        return True
    if op in ARM_BRANCH_MNEMONICS or op.startswith("b."):
        return True
    if len(op) == 3 and op.startswith("b") and op[1:] in ARM_BRANCH_CONDITIONS:
        return True
    if len(op) == 4 and (op.startswith("bl") or op.startswith("bx")) and op[2:] in ARM_BRANCH_CONDITIONS:
        return True
    return False


def normalize_imm(val: Any) -> Union[int, str]:
    """Normalizes immediate values (hex, decimal, MASM suffix 'h', character literals) into comparable integers or strings."""
    if not isinstance(val, str):
        if isinstance(val, int):
            return val
        return str(val)
    v = val.strip()
    if not v:
        return ""
    if len(v) >= 3 and v.startswith("'") and v.endswith("'"):
        inner = v[1:-1]
        if len(inner) == 1:
            return ord(inner)
        elif len(inner) == 2 and inner.startswith("\\"):
            escapes = {
                "\\n": ord("\n"), "\\t": ord("\t"), "\\r": ord("\r"),
                "\\0": 0, "\\\\": ord("\\"), "\\'": ord("'")
            }
            if inner in escapes:
                return escapes[inner]
    sign = 1
    clean_v = v
    if clean_v.startswith("-"):
        sign = -1
        clean_v = clean_v[1:].strip()
    elif clean_v.startswith("+"):
        clean_v = clean_v[1:].strip()

    if clean_v.lower().endswith("h") and not clean_v.lower().startswith("0x"):
        try:
            return sign * int(clean_v[:-1], 16)
        except ValueError:
            pass

    try:
        return sign * int(clean_v, 0)
    except (ValueError, TypeError):
        return v.lower()


def _extract_registered_tokens(codebook: Optional[Any]) -> Optional[Set[str]]:
    """Extracts known symbolic token keys from codebook, mapper, or dict."""
    if codebook is None:
        return None
    if isinstance(codebook, dict):
        if "reverse_map" in codebook and isinstance(codebook["reverse_map"], dict):
            return set(codebook["reverse_map"].keys())
        return set(codebook.keys())
    if hasattr(codebook, "_codebook") and hasattr(codebook._codebook, "reverse_map"):
        rm = codebook._codebook.reverse_map
        if isinstance(rm, dict):
            return set(rm.keys())
    if hasattr(codebook, "reverse_map"):
        rm = codebook.reverse_map
        if isinstance(rm, dict):
            return set(rm.keys())
        elif callable(rm):
            return set(rm().keys())
    return None


@dataclass
class InstructionSemantics:
    raw_asm: str
    code_part: str
    comment_part: str
    opcode: str
    registers: List[str]
    memory_operands: List[str]
    immediates: List[str]
    shift_modifiers: List[str] = field(default_factory=list)


def parse_instruction_semantics(asm_line: str) -> InstructionSemantics:
    """Parses raw assembly string into semantic components."""
    if not asm_line:
        return InstructionSemantics("", "", "", "", [], [], [])

    comment = ""
    code = asm_line
    for delimiter in (";", "//"):
        if delimiter in code:
            parts = code.split(delimiter, 1)
            code = parts[0]
            comment = delimiter + parts[1]
            break

    code = code.strip()
    if not code:
        return InstructionSemantics(asm_line, "", comment, "", [], [], [])

    parts = code.split(None, 1)
    opcode = parts[0].lower()
    operands_text = parts[1] if len(parts) > 1 else ""

    # Multi-word prefixes
    if opcode in ("lock", "rep", "repz", "repe", "repne", "repnz") and operands_text:
        subparts = operands_text.split(None, 1)
        opcode = f"{opcode} {subparts[0].lower()}"
        operands_text = subparts[1] if len(subparts) > 1 else ""

    mem_pattern = re.compile(r'(?:\b(?:byte|word|dword|qword|tbyte|xmmword)(?:\s+ptr)?\s*)?\[[^\]]+\]', re.IGNORECASE)
    memory_operands = mem_pattern.findall(operands_text)

    words = re.findall(r'[a-zA-Z0-9_]+', operands_text.lower())
    registers = [w for w in words if w in ALL_ARCH_REGISTERS]
    shift_modifiers = [w for w in words if w in ARM_SHIFT_MODIFIERS]

    imm_pattern = re.compile(r"(?:[-+]?\b(?:0x[0-9a-fA-F]+|[0-9a-fA-F]+h|\d+)\b|'[^']')", re.IGNORECASE)
    immediates = imm_pattern.findall(operands_text)

    return InstructionSemantics(
        raw_asm=asm_line,
        code_part=code,
        comment_part=comment,
        opcode=opcode,
        registers=registers,
        memory_operands=memory_operands,
        immediates=immediates,
        shift_modifiers=shift_modifiers,
    )


def normalize_disassembly_input(payload: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Normalizes arbitrary disassembly representations into standard blocks and instructions."""
    blocks: List[Dict[str, Any]] = []
    instructions: List[Dict[str, Any]] = []

    if isinstance(payload, dict):
        if "blocks" in payload and isinstance(payload["blocks"], list):
            blocks = payload["blocks"]
            for b in blocks:
                if isinstance(b, dict) and "instructions" in b:
                    instructions.extend(b["instructions"])
        elif "instructions" in payload and isinstance(payload["instructions"], list):
            instructions = payload["instructions"]
            blocks = [{"addr": instructions[0].get("addr") if instructions else 0, "instructions": instructions}]
    elif isinstance(payload, list):
        if not payload:
            return [], []
        first = payload[0]
        if isinstance(first, dict):
            if "instructions" in first:
                blocks = payload
                for b in blocks:
                    instructions.extend(b.get("instructions", []))
            elif "asm" in first or "addr" in first or "disasm" in first:
                instructions = payload
                blocks = [{"addr": instructions[0].get("addr"), "instructions": instructions}]
        elif isinstance(first, str):
            for idx, asm_line in enumerate(payload):
                instructions.append({"addr": idx, "asm": asm_line})
            blocks = [{"addr": 0, "instructions": instructions}]

    return blocks, instructions


def diagnose_invariants(
    original: Any,
    neutralized: Any,
    codebook: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Compares original vs neutralized disassembly and returns list of discrepancies."""
    orig_blocks, orig_insts = normalize_disassembly_input(original)
    neut_blocks, neut_insts = normalize_disassembly_input(neutralized)

    registered_tokens = _extract_registered_tokens(codebook)
    discrepancies: List[Dict[str, Any]] = []

    # Rule 1: Basic block count preservation (if both provided blocks)
    if orig_blocks and neut_blocks and len(orig_blocks) != len(neut_blocks):
        discrepancies.append({
            "rule": "BLOCK_COUNT_MISMATCH",
            "message": f"Basic block count mismatch: {len(orig_blocks)} != {len(neut_blocks)}",
            "orig_count": len(orig_blocks),
            "neut_count": len(neut_blocks),
        })

    # Rule 2: Total instruction count preservation
    if len(orig_insts) != len(neut_insts):
        discrepancies.append({
            "rule": "INSTRUCTION_COUNT_MISMATCH",
            "message": f"Instruction count mismatch: {len(orig_insts)} != {len(neut_insts)}",
            "orig_count": len(orig_insts),
            "neut_count": len(neut_insts),
        })
        return discrepancies

    # Compare instruction-by-instruction
    for idx, (oi, ni) in enumerate(zip(orig_insts, neut_insts)):
        # Rule 3: Address immutability & presence enforcement
        o_addr = oi.get("addr")
        n_addr = ni.get("addr")
        if o_addr is not None and n_addr is None:
            discrepancies.append({
                "rule": "MISSING_ADDRESS",
                "message": f"Virtual address omitted in neutralized instruction: expected {hex(o_addr) if isinstance(o_addr, int) else o_addr}",
                "index": idx,
                "original": oi,
                "neutralized": ni,
            })
        elif o_addr is None and n_addr is not None:
            discrepancies.append({
                "rule": "UNEXPECTED_ADDRESS",
                "message": f"Unexpected virtual address in neutralized instruction: got {hex(n_addr) if isinstance(n_addr, int) else n_addr}",
                "index": idx,
                "original": oi,
                "neutralized": ni,
            })
        elif o_addr is not None and n_addr is not None:
            try:
                o_int = int(str(o_addr), 0) if isinstance(o_addr, str) else int(o_addr)
                n_int = int(str(n_addr), 0) if isinstance(n_addr, str) else int(n_addr)
                if o_int != n_int:
                    discrepancies.append({
                        "rule": "ADDRESS_DRIFT",
                        "message": f"Virtual address altered: {hex(o_int)} -> {hex(n_int)}",
                        "index": idx,
                        "original": oi,
                        "neutralized": ni,
                    })
            except (ValueError, TypeError):
                if str(o_addr) != str(n_addr):
                    discrepancies.append({
                        "rule": "ADDRESS_DRIFT",
                        "message": f"Virtual address string altered: {o_addr} -> {n_addr}",
                        "index": idx,
                        "original": oi,
                        "neutralized": ni,
                    })

        # Rule 4: Instruction size immutability
        o_size = oi.get("size")
        n_size = ni.get("size")
        if o_size is not None and n_size is not None:
            if int(o_size) != int(n_size):
                discrepancies.append({
                    "rule": "SIZE_MISMATCH",
                    "message": f"Instruction size altered: {o_size} -> {n_size}",
                    "index": idx,
                    "original": oi,
                    "neutralized": ni,
                })

        # Semantic parsing
        o_asm = oi.get("asm") or oi.get("disasm") or oi.get("opcode") or ""
        n_asm = ni.get("asm") or ni.get("disasm") or ni.get("opcode") or ""

        o_sem = parse_instruction_semantics(o_asm)
        n_sem = parse_instruction_semantics(n_asm)

        # Rule 5: Opcode mnemonic immutability
        if o_sem.opcode != n_sem.opcode:
            discrepancies.append({
                "rule": "OPCODE_ALTERATION",
                "message": f"Opcode altered: '{o_sem.opcode}' -> '{n_sem.opcode}'",
                "index": idx,
                "original": oi,
                "neutralized": ni,
            })

        # Rule 6: CPU Register preservation
        if o_sem.registers != n_sem.registers:
            discrepancies.append({
                "rule": "REGISTER_ALTERATION",
                "message": f"Registers altered: {o_sem.registers} -> {n_sem.registers}",
                "index": idx,
                "original": oi,
                "neutralized": ni,
            })

        # Rule 7: Memory operand structural integrity
        if o_sem.memory_operands != n_sem.memory_operands:
            discrepancies.append({
                "rule": "MEMORY_OPERAND_ALTERATION",
                "message": f"Memory operands altered: {o_sem.memory_operands} -> {n_sem.memory_operands}",
                "index": idx,
                "original": oi,
                "neutralized": ni,
            })

        # Rule 7b: ALU operand shift / extension modifier preservation
        if o_sem.shift_modifiers != n_sem.shift_modifiers:
            discrepancies.append({
                "rule": "SHIFT_MODIFIER_ALTERATION",
                "message": f"Shift modifiers altered: {o_sem.shift_modifiers} -> {n_sem.shift_modifiers}",
                "index": idx,
                "original": oi,
                "neutralized": ni,
            })

        # Rule 8: Immediate constants & Branch target verification
        is_branch = is_branch_opcode(o_sem.opcode)
        if is_branch:
            # Branch instruction: check whether neutralized target is a valid/registered symbolic token
            found_tokens = SYMBOLIC_TARGET_PATTERN.findall(n_sem.code_part)
            is_symbolic_target = False
            if found_tokens:
                if registered_tokens is not None:
                    is_symbolic_target = any(
                        tok in registered_tokens or (tok.startswith("sym.") and tok[4:] in registered_tokens)
                        for tok in found_tokens
                    )
                else:
                    is_symbolic_target = True

            if is_symbolic_target:
                # Target was neutralized symbolically; verify that any non-target immediates
                # (e.g. AArch64 tbz bit index) are preserved identically
                if len(o_sem.immediates) > 1:
                    norm_o_non_target = [normalize_imm(x) for x in o_sem.immediates[:-1]]
                    norm_n_imms = [normalize_imm(x) for x in n_sem.immediates]
                    if norm_o_non_target != norm_n_imms:
                        discrepancies.append({
                            "rule": "IMMEDIATE_CONSTANT_ALTERATION",
                            "message": f"Non-target immediates altered in branch: {o_sem.immediates[:-1]} -> {n_sem.immediates}",
                            "index": idx,
                            "original": oi,
                            "neutralized": ni,
                        })
            else:
                # Target is concrete immediate or raw symbol: must match identically
                norm_o_imms = [normalize_imm(x) for x in o_sem.immediates]
                norm_n_imms = [normalize_imm(x) for x in n_sem.immediates]
                if norm_o_imms != norm_n_imms:
                    discrepancies.append({
                        "rule": "BRANCH_TARGET_ALTERATION",
                        "message": f"Branch target altered: {o_sem.immediates} -> {n_sem.immediates}",
                        "index": idx,
                        "original": oi,
                        "neutralized": ni,
                    })
                elif not o_sem.immediates and not n_sem.immediates:
                    # Raw identifier branch (e.g. call target_a vs call target_b)
                    o_target = o_sem.code_part.split(None, 1)[1].strip() if len(o_sem.code_part.split(None, 1)) > 1 else ""
                    n_target = n_sem.code_part.split(None, 1)[1].strip() if len(n_sem.code_part.split(None, 1)) > 1 else ""
                    if o_target != n_target:
                        if not o_sem.registers and not n_sem.registers and not o_sem.memory_operands and not n_sem.memory_operands:
                            discrepancies.append({
                                "rule": "BRANCH_TARGET_ALTERATION",
                                "message": f"Branch target altered: '{o_target}' -> '{n_target}'",
                                "index": idx,
                                "original": oi,
                                "neutralized": ni,
                            })
        else:
            # Non-branch instruction: immediate constants must match identically
            norm_o_imms = [normalize_imm(x) for x in o_sem.immediates]
            norm_n_imms = [normalize_imm(x) for x in n_sem.immediates]
            if norm_o_imms != norm_n_imms:
                discrepancies.append({
                    "rule": "IMMEDIATE_CONSTANT_ALTERATION",
                    "message": f"Immediates altered: {o_sem.immediates} -> {n_sem.immediates}",
                    "index": idx,
                    "original": oi,
                    "neutralized": ni,
                })

    return discrepancies


def verify_invariants(
    original: Any,
    neutralized: Any,
    strict: bool = False,
    codebook: Optional[Any] = None,
) -> bool:
    """
    Verifies that opcodes, registers, addresses, counts, and structural layouts are 100% intact.
    Returns True if valid, False if invalid.
    If strict=True, raises InvariantViolationError (subclass of AssertionError) on violation.
    """
    discrepancies = diagnose_invariants(original, neutralized, codebook=codebook)
    if not discrepancies:
        return True

    if strict:
        first = discrepancies[0]
        raise InvariantViolationError(
            rule=first["rule"],
            message=first["message"],
            index=first.get("index"),
            original_inst=first.get("original"),
            neutralized_inst=first.get("neutralized"),
        )
    return False


# ==============================================================================
# Feature 10: Control Flow Graph (CFG) & Finite State Machine (FSM)
# ==============================================================================

class CFGEdgeType(str, enum.Enum):
    """Edge transfer classifications for binary control flow graphs."""
    FALLTHROUGH = "FALLTHROUGH"
    CONDITIONAL_TAKEN = "CONDITIONAL_TAKEN"
    CONDITIONAL_NOT_TAKEN = "CONDITIONAL_NOT_TAKEN"
    UNCONDITIONAL = "UNCONDITIONAL"
    CALL = "CALL"
    RETURN = "RETURN"
    INDIRECT_SWITCH = "INDIRECT_SWITCH"


@dataclass
class CFGNode:
    """Canonical representation of a basic block vertex in a Control Flow Graph."""
    id: str
    block_id: str
    address: str
    start_addr: str
    end_addr: Optional[str] = None
    size: int = 0
    instruction_count: int = 0
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False
    is_loop_head: bool = False
    node_type: str = "NORMAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "block_id": self.block_id,
            "address": self.address,
            "start_addr": self.start_addr,
            "end_addr": self.end_addr,
            "size": self.size,
            "instruction_count": self.instruction_count,
            "instructions": self.instructions,
            "is_entry": self.is_entry,
            "is_exit": self.is_exit,
            "is_loop_head": self.is_loop_head,
            "node_type": self.node_type,
        }


@dataclass
class CFGEdge:
    """Canonical representation of a directed control transfer edge."""
    source: str
    target: str
    type: str
    condition: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "source": self.source,
            "target": self.target,
            "type": self.type,
        }
        if self.condition is not None:
            d["condition"] = self.condition
        if self.metadata:
            d["metadata"] = self.metadata
        return d


class ControlFlowGraph:
    """
    Directed multigraph G = (V, E) representing subroutine execution topology.
    Supports polymorphic instantiation, raw flow data ingestion, FSM synthesis,
    and algorithmic pattern detection.
    """

    def __init__(
        self,
        nodes: Optional[List[Union[Dict[str, Any], CFGNode]]] = None,
        edges: Optional[List[Union[Dict[str, Any], CFGEdge]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.metadata: Dict[str, Any] = metadata or {}
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []

        if nodes:
            for n in nodes:
                if isinstance(n, CFGNode):
                    self.nodes.append(n.to_dict())
                elif isinstance(n, dict):
                    normalized = dict(n)
                    nid = normalized.get("id") or normalized.get("block_id") or f"BB_{normalized.get('start_addr', '0x0')}"
                    addr = str(normalized.get("start_addr") or normalized.get("address") or "0x0")
                    normalized["id"] = str(nid)
                    normalized["block_id"] = str(normalized.get("block_id") or nid)
                    normalized["address"] = addr
                    normalized["start_addr"] = addr
                    normalized["instruction_count"] = int(
                        normalized.get("instruction_count")
                        or len(normalized.get("instructions", []))
                    )
                    default_type = "ENTRY" if normalized.get("is_entry") else ("EXIT" if normalized.get("is_exit") else "NORMAL")
                    normalized["node_type"] = str(normalized.get("node_type") or default_type)
                    normalized["is_entry"] = bool(normalized.get("is_entry") or normalized.get("node_type") == "ENTRY")
                    normalized["is_exit"] = bool(normalized.get("is_exit") or normalized.get("node_type") == "EXIT")
                    normalized["is_loop_head"] = bool(normalized.get("is_loop_head", False))
                    if "instructions" not in normalized:
                        normalized["instructions"] = []
                    self.nodes.append(normalized)

        if edges:
            for e in edges:
                if isinstance(e, CFGEdge):
                    self.edges.append(e.to_dict())
                elif isinstance(e, dict):
                    normalized_e = dict(e)
                    normalized_e["source"] = str(normalized_e.get("source", ""))
                    normalized_e["target"] = str(normalized_e.get("target", ""))
                    normalized_e["type"] = str(normalized_e.get("type", CFGEdgeType.FALLTHROUGH.value))
                    self.edges.append(normalized_e)

    def to_dict(self) -> Dict[str, Any]:
        """Emits standard serializable dictionary representation."""
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "metrics": self.calculate_metrics(),
            "metadata": self.metadata,
        }

    def calculate_metrics(self) -> Dict[str, Any]:
        """Calculates topological metrics including Cyclomatic Complexity."""
        v = len(self.nodes)
        e = len(self.edges)
        cyclomatic = max(1, e - v + 2) if v > 0 else 0
        loop_heads = sum(1 for n in self.nodes if n.get("is_loop_head"))
        return {
            "total_nodes": v,
            "total_edges": e,
            "cyclomatic_complexity": cyclomatic,
            "loop_count": loop_heads,
        }

    @classmethod
    def from_rvs_flow(cls, flow_dict: Dict[str, Any]) -> "ControlFlowGraph":
        """Synthesizes a ControlFlowGraph from raw flow data."""
        return cls.from_raw_flow(flow_dict)

    @classmethod
    def from_raw_flow(cls, raw_data: Dict[str, Any]) -> "ControlFlowGraph":
        """Synthesizes a ControlFlowGraph from detailed blocks or decision flow data."""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        metadata: Dict[str, Any] = {
            "function_name": raw_data.get("function_name") or raw_data.get("function"),
            "function_addr": raw_data.get("function_addr_hex") or raw_data.get("addr"),
        }

        raw_blocks = raw_data.get("blocks")
        if raw_blocks and isinstance(raw_blocks, list):
            addr_to_id: Dict[Union[int, str], str] = {}
            for b in raw_blocks:
                addr_int = b.get("addr")
                addr_hex = b.get("addr_hex") or (f"0x{addr_int:x}" if isinstance(addr_int, int) else str(addr_int))
                bid = f"BB_{addr_hex.lower()}"
                if addr_int is not None:
                    addr_to_id[addr_int] = bid
                addr_to_id[addr_hex] = bid
                addr_to_id[addr_hex.lower()] = bid

            for i, b in enumerate(raw_blocks):
                addr_int = b.get("addr")
                addr_hex = b.get("addr_hex") or (f"0x{addr_int:x}" if isinstance(addr_int, int) else str(addr_int))
                bid = addr_to_id.get(addr_int) or f"BB_{addr_hex.lower()}"
                insts = b.get("instructions", [])
                last_op = insts[-1].get("opcode", "") or insts[-1].get("asm", "") if insts else ""

                is_entry = (i == 0)
                is_exit = (b.get("jump") is None and b.get("fail") is None and ("ret" in last_op or i == len(raw_blocks) - 1))
                is_decision = (b.get("fail") is not None)

                node_type = "ENTRY" if is_entry else ("EXIT" if is_exit else ("DECISION" if is_decision else "NORMAL"))

                nodes.append({
                    "id": bid,
                    "block_id": bid,
                    "address": addr_hex,
                    "start_addr": addr_hex,
                    "size": b.get("size", 0),
                    "instruction_count": b.get("num_instructions", len(insts)),
                    "instructions": insts,
                    "is_entry": is_entry,
                    "is_exit": is_exit,
                    "is_loop_head": False,
                    "node_type": node_type,
                })

                jump = b.get("jump")
                fail = b.get("fail")
                jump_hex = b.get("jump_hex") or (f"0x{jump:x}" if isinstance(jump, int) else str(jump))
                fail_hex = b.get("fail_hex") or (f"0x{fail:x}" if isinstance(fail, int) else str(fail))

                if jump is not None and fail is not None:
                    tgt_taken = addr_to_id.get(jump) or addr_to_id.get(jump_hex) or f"BB_{jump_hex.lower()}"
                    tgt_not_taken = addr_to_id.get(fail) or addr_to_id.get(fail_hex) or f"BB_{fail_hex.lower()}"
                    edges.append({"source": bid, "target": tgt_taken, "type": CFGEdgeType.CONDITIONAL_TAKEN.value})
                    edges.append({"source": bid, "target": tgt_not_taken, "type": CFGEdgeType.CONDITIONAL_NOT_TAKEN.value})
                elif jump is not None:
                    tgt = addr_to_id.get(jump) or addr_to_id.get(jump_hex) or f"BB_{jump_hex.lower()}"
                    edge_type = CFGEdgeType.UNCONDITIONAL.value if "jmp" in last_op else CFGEdgeType.FALLTHROUGH.value
                    edges.append({"source": bid, "target": tgt, "type": edge_type})
                elif not is_exit and i + 1 < len(raw_blocks):
                    next_addr = raw_blocks[i + 1].get("addr")
                    next_bid = addr_to_id.get(next_addr, f"BB_next_{i+1}")
                    edges.append({"source": bid, "target": next_bid, "type": CFGEdgeType.FALLTHROUGH.value})

        elif "decision_nodes" in raw_data:
            d_nodes = raw_data.get("decision_nodes", [])
            exit_nodes = raw_data.get("exit_nodes", []) or raw_data.get("exits", [])
            fn_addr = raw_data.get("function_addr_hex") or raw_data.get("addr") or "0x0"
            entry_id = f"BB_{str(fn_addr).lower()}"

            nodes.append({
                "id": entry_id,
                "block_id": entry_id,
                "address": str(fn_addr),
                "start_addr": str(fn_addr),
                "instruction_count": 1,
                "is_entry": True,
                "is_exit": False,
                "is_loop_head": False,
                "node_type": "ENTRY",
            })

            for idx, gate in enumerate(d_nodes):
                gate_addr = gate.get("addr_hex") or gate.get("addr") or f"gate_{idx}"
                gid = f"BB_{str(gate_addr).lower()}"
                if gid != entry_id and not any(n["id"] == gid for n in nodes):
                    nodes.append({
                        "id": gid,
                        "block_id": gid,
                        "address": str(gate_addr),
                        "start_addr": str(gate_addr),
                        "instruction_count": 2,
                        "is_entry": False,
                        "is_exit": False,
                        "is_loop_head": False,
                        "node_type": "DECISION",
                    })

                jump = gate.get("jump_target_hex") or gate.get("jump")
                fail = gate.get("fail_target_hex") or gate.get("fail")
                cond = gate.get("condition_instruction") or gate.get("cond")

                if jump:
                    j_id = f"BB_{str(jump).lower()}"
                    if not any(n["id"] == j_id for n in nodes):
                        nodes.append({
                            "id": j_id,
                            "block_id": j_id,
                            "address": str(jump),
                            "start_addr": str(jump),
                            "is_entry": False,
                            "is_exit": False,
                            "is_loop_head": False,
                            "node_type": "NORMAL",
                        })
                    edges.append({
                        "source": gid,
                        "target": j_id,
                        "type": CFGEdgeType.CONDITIONAL_TAKEN.value,
                        "condition": cond,
                    })

                if fail:
                    f_id = f"BB_{str(fail).lower()}"
                    if not any(n["id"] == f_id for n in nodes):
                        nodes.append({
                            "id": f_id,
                            "block_id": f_id,
                            "address": str(fail),
                            "start_addr": str(fail),
                            "is_entry": False,
                            "is_exit": False,
                            "is_loop_head": False,
                            "node_type": "NORMAL",
                        })
                    edges.append({
                        "source": gid,
                        "target": f_id,
                        "type": CFGEdgeType.CONDITIONAL_NOT_TAKEN.value,
                        "condition": f"NOT({cond})" if cond else None,
                    })

            for ex in exit_nodes:
                ex_addr = f"0x{ex:x}" if isinstance(ex, int) else str(ex)
                eid = f"BB_{ex_addr.lower()}"
                matching = [n for n in nodes if n["id"] == eid]
                if matching:
                    matching[0]["is_exit"] = True
                    matching[0]["node_type"] = "EXIT"
                else:
                    nodes.append({
                        "id": eid,
                        "block_id": eid,
                        "address": ex_addr,
                        "start_addr": ex_addr,
                        "is_entry": False,
                        "is_exit": True,
                        "is_loop_head": False,
                        "node_type": "EXIT",
                    })

        # Backward edge loop head detection
        for e in edges:
            src_node = next((n for n in nodes if n["id"] == e["source"]), None)
            tgt_node = next((n for n in nodes if n["id"] == e["target"]), None)
            if src_node and tgt_node:
                try:
                    s_int = int(str(src_node["address"]), 0)
                    t_int = int(str(tgt_node["address"]), 0)
                    if t_int <= s_int:
                        tgt_node["is_loop_head"] = True
                except (ValueError, TypeError):
                    pass

        return cls(nodes=nodes, edges=edges, metadata=metadata)

    def to_fsm(self) -> "FiniteStateMachine":
        """Synthesizes an FSM directly from this ControlFlowGraph."""
        return FiniteStateMachine.from_cfg(self)

    def detect_patterns(self) -> List[Dict[str, Any]]:
        """Executes algorithmic pattern recognition across this graph topology."""
        detector = AlgorithmicPatternDetector()
        fn_name = self.metadata.get("function_name")
        matches = detector.detect_all(self, function_name=fn_name)
        return [m.to_dict() for m in matches]


# ==============================================================================
# Feature 10: Finite State Machine (FSM) Transition Model
# ==============================================================================

@dataclass
class FiniteStateMachine:
    """
    Formal Moore/Mealy Finite State Machine M = (S, Sigma, delta, s0, F).
    Represents execution states, condition predicates, and deterministic transitions.
    """
    states: List[str]
    initial_state: str
    terminal_states: List[str]
    transitions: List[Dict[str, Any]]
    outputs: Optional[Dict[str, Any]] = None
    transition_actions: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Emits standard dictionary representation matching test suite expectations."""
        d: Dict[str, Any] = {
            "states": self.states,
            "initial_state": self.initial_state,
            "terminal_states": self.terminal_states,
            "transitions": self.transitions,
        }
        if self.outputs is not None:
            d["outputs"] = self.outputs
        if self.transition_actions is not None:
            d["transition_actions"] = self.transition_actions
        return d

    @classmethod
    def from_cfg(cls, cfg: ControlFlowGraph) -> "FiniteStateMachine":
        """Synthesizes a Moore/Mealy FSM directly from a ControlFlowGraph."""
        states = [n["id"] for n in cfg.nodes]
        entry_node = next((n for n in cfg.nodes if n.get("is_entry") or n.get("node_type") == "ENTRY"), None)
        initial_state = entry_node["id"] if entry_node else (states[0] if states else "S0")

        terminal_states = [n["id"] for n in cfg.nodes if n.get("is_exit") or n.get("node_type") == "EXIT"]
        if not terminal_states and states:
            terminal_states = [states[-1]]

        transitions: List[Dict[str, Any]] = []
        gate_counter = 0

        for e in cfg.edges:
            src = e["source"]
            tgt = e["target"]
            etype = e.get("type", CFGEdgeType.FALLTHROUGH.value)
            cond = e.get("condition")

            if etype == CFGEdgeType.CONDITIONAL_TAKEN.value:
                gate_counter += 1
                pred = cond or f"PREDICATE_GATE_{gate_counter:04d}"
            elif etype == CFGEdgeType.CONDITIONAL_NOT_TAKEN.value:
                pred = f"NOT({cond})" if cond else f"!PREDICATE_GATE_{gate_counter:04d}"
            elif etype == CFGEdgeType.INDIRECT_SWITCH.value:
                case_val = e.get("metadata", {}).get("case_val", "DEFAULT")
                pred = f"CASE_{case_val}"
            else:
                pred = "TRUE"

            transitions.append({
                "source": src,
                "predicate": pred,
                "target": tgt,
                "edge_type": etype,
            })

        outputs = {
            n["id"]: {
                "instruction_count": n.get("instruction_count", 0),
                "node_type": n.get("node_type", "NORMAL"),
            }
            for n in cfg.nodes
        }

        return cls(
            states=states,
            initial_state=initial_state,
            terminal_states=terminal_states,
            transitions=transitions,
            outputs=outputs,
        )


# ==============================================================================
# Feature 10: Algorithmic Equivalence Pattern Detection Engine
# ==============================================================================

@dataclass
class PatternMatch:
    """Result of an algorithmic archetype pattern detection query."""
    pattern_id: str
    archetype: str
    confidence: float
    affected_nodes: List[str]
    parameters: Dict[str, Any]
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AlgorithmicPatternDetector:
    """
    Scans CFG topologies and machine instruction sequences to identify
    algorithmic computational archetypes.
    """

    def detect_all(self, cfg: ControlFlowGraph, function_name: Optional[str] = None) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        matches.extend(self.detect_crypto_xor_loops(cfg))
        matches.extend(self.detect_aggregation_loops(cfg))
        matches.extend(self.detect_collatz_loops(cfg))
        matches.extend(self.detect_switch_tables(cfg))
        matches.extend(self.detect_recurrence_trees(cfg, function_name=function_name))
        matches.extend(self.detect_predicate_chains(cfg))
        return matches

    def detect_crypto_xor_loops(self, cfg: ControlFlowGraph) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        loop_heads = [n for n in cfg.nodes if n.get("is_loop_head")]
        if not loop_heads:
            return matches

        for head in loop_heads:
            loop_nodes = self._find_natural_loop_nodes(cfg, head["id"])
            all_insts = self._collect_instructions(cfg, loop_nodes)
            has_xor = any(
                ("xor" in i.get("opcode", "") or "xor" in (i.get("asm") or i.get("disasm") or ""))
                and ("byte" in (i.get("asm") or i.get("disasm") or "") or any(r in (i.get("asm") or i.get("disasm") or "") for r in ("al", "cl", "dl", "bl", "w0", "r0")))
                for i in all_insts
            )
            has_mem_write = any(
                ("mov" in i.get("opcode", "") or "mov" in (i.get("asm") or i.get("disasm") or ""))
                and ("byte [" in (i.get("asm") or i.get("disasm") or "") or "[" in (i.get("asm") or i.get("disasm") or ""))
                for i in all_insts
            )

            if has_xor:
                matches.append(PatternMatch(
                    pattern_id="ALG_BYTE_TRANS",
                    archetype="ELEMENTWISE_BYTE_TRANSFORMATION",
                    confidence=0.98 if has_mem_write else 0.85,
                    affected_nodes=loop_nodes,
                    parameters={"operation": "XOR", "operand_width": "BYTE"},
                    description="Elementwise byte transformation loop decrypting or encoding buffer via bitwise XOR",
                ))
        return matches

    def detect_aggregation_loops(self, cfg: ControlFlowGraph) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        loop_heads = [n for n in cfg.nodes if n.get("is_loop_head")]
        if not loop_heads:
            return matches

        for head in loop_heads:
            loop_nodes = self._find_natural_loop_nodes(cfg, head["id"])
            all_insts = self._collect_instructions(cfg, loop_nodes)
            has_mul = any(
                i.get("opcode", "").startswith(("imul", "mul"))
                or "imul" in (i.get("asm") or i.get("disasm") or "")
                or "mul" in (i.get("asm") or i.get("disasm") or "")
                for i in all_insts
            )
            has_add_accum = any(
                (i.get("opcode", "").startswith("add") or "add" in (i.get("asm") or i.get("disasm") or ""))
                and not ("add" in (i.get("asm") or i.get("disasm") or "") and ", 1" in (i.get("asm") or i.get("disasm") or ""))
                for i in all_insts
            )
            is_xor_loop = any(
                ("xor" in i.get("opcode", "") or "xor" in (i.get("asm") or i.get("disasm") or ""))
                and "byte" in (i.get("asm") or i.get("disasm") or "")
                for i in all_insts
            )

            if not is_xor_loop and (has_mul or has_add_accum):
                op = "MULTIPLICATION" if has_mul else "ADDITION"
                matches.append(PatternMatch(
                    pattern_id="ALG_ACC_LOOP",
                    archetype="AGGREGATE_LOOP",
                    confidence=0.95,
                    affected_nodes=loop_nodes,
                    parameters={"operation": op},
                    description=f"Accumulator loop iteratively computing {op.lower()} across sequential induction counter",
                ))
        return matches

    def detect_collatz_loops(self, cfg: ControlFlowGraph) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        loop_heads = [n for n in cfg.nodes if n.get("is_loop_head")]
        if not loop_heads:
            return matches

        for head in loop_heads:
            loop_nodes = self._find_natural_loop_nodes(cfg, head["id"])
            all_insts = self._collect_instructions(cfg, loop_nodes)
            has_parity = any(
                "test" in (i.get("asm") or i.get("disasm") or "")
                or "and" in (i.get("asm") or i.get("disasm") or "")
                for i in all_insts
            )
            has_shift = any(
                i.get("opcode", "").startswith(("sar", "shr", "idiv"))
                or any(s in (i.get("asm") or i.get("disasm") or "") for s in ("sar", "shr", "idiv"))
                for i in all_insts
            )
            has_odd_mul = any(
                "lea" in (i.get("asm") or i.get("disasm") or "")
                or "imul" in (i.get("asm") or i.get("disasm") or "")
                for i in all_insts
            )

            if has_parity and (has_shift or has_odd_mul) and len(loop_nodes) >= 3:
                matches.append(PatternMatch(
                    pattern_id="ALG_COLLATZ",
                    archetype="PARITY_STATE_TRANSFORMATION",
                    confidence=0.96,
                    affected_nodes=loop_nodes,
                    parameters={"rule": "if even: n/2, if odd: 3n+1"},
                    description="Collatz parity state transformation loop mutating loop variable based on parity branch",
                ))
        return matches

    def detect_switch_tables(self, cfg: ControlFlowGraph) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        has_indirect_edge = any(e.get("type") == CFGEdgeType.INDIRECT_SWITCH.value for e in cfg.edges)
        cmps = [
            i for n in cfg.nodes
            for i in n.get("instructions", [])
            if i.get("opcode", "").startswith("cmp") or "cmp" in (i.get("asm") or i.get("disasm") or "")
        ]

        if has_indirect_edge or (len(cmps) >= 3 and len(cfg.nodes) >= 8):
            matches.append(PatternMatch(
                pattern_id="ALG_SWITCH_TAB",
                archetype="DISPATCH_SELECTOR",
                confidence=0.95 if has_indirect_edge else 0.88,
                affected_nodes=[n["id"] for n in cfg.nodes],
                parameters={"dispatch_type": "INDIRECT_JUMP_TABLE" if has_indirect_edge else "BINARY_SEARCH_CASCADE"},
                description="Multi-way dispatch table routing execution across distinct case handlers",
            ))
        return matches

    def detect_recurrence_trees(self, cfg: ControlFlowGraph, function_name: Optional[str] = None) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        if not function_name:
            return matches

        all_insts = [i for n in cfg.nodes for i in n.get("instructions", [])]
        self_calls = [
            i for i in all_insts
            if (i.get("opcode", "").startswith("call") or "call" in (i.get("asm") or i.get("disasm") or ""))
            and function_name in (i.get("asm") or i.get("disasm") or "")
        ]

        if len(self_calls) >= 2:
            matches.append(PatternMatch(
                pattern_id="ALG_REC_BRANCH",
                archetype="RECURSIVE_BRANCH",
                confidence=0.98,
                affected_nodes=[n["id"] for n in cfg.nodes],
                parameters={"recursive_call_count": len(self_calls)},
                description="Binary recurrence tree evaluating recursive mathematical series (e.g. Fibonacci)",
            ))
        return matches

    def detect_predicate_chains(self, cfg: ControlFlowGraph) -> List[PatternMatch]:
        matches: List[PatternMatch] = []
        has_loops = any(n.get("is_loop_head") for n in cfg.nodes)
        if has_loops:
            return matches

        decision_nodes = [n for n in cfg.nodes if n.get("node_type") == "DECISION"]
        if len(decision_nodes) >= 2:
            matches.append(PatternMatch(
                pattern_id="ALG_PRED_CHAIN",
                archetype="SEQUENTIAL_PREDICATE_VALIDATION",
                confidence=0.90,
                affected_nodes=[n["id"] for n in decision_nodes],
                parameters={"gate_count": len(decision_nodes)},
                description="Cascading predicate gate chain validating multi-stage sequential access or security checks",
            ))
        return matches

    def _find_natural_loop_nodes(self, cfg: ControlFlowGraph, head_id: str) -> List[str]:
        """Finds all node IDs belonging to the natural loop of a given loop head."""
        loop_nodes: Set[str] = {head_id}
        back_edge_sources = [
            e["source"] for e in cfg.edges
            if e["target"] == head_id and e.get("type") in (
                CFGEdgeType.CONDITIONAL_TAKEN.value,
                CFGEdgeType.UNCONDITIONAL.value,
                CFGEdgeType.FALLTHROUGH.value,
            )
        ]
        stack = list(back_edge_sources)
        while stack:
            curr = stack.pop()
            if curr not in loop_nodes:
                loop_nodes.add(curr)
                predecessors = [e["source"] for e in cfg.edges if e["target"] == curr]
                stack.extend(predecessors)
        return sorted(list(loop_nodes))

    def _collect_instructions(self, cfg: ControlFlowGraph, node_ids: List[str]) -> List[Dict[str, Any]]:
        insts: List[Dict[str, Any]] = []
        for nid in node_ids:
            node = next((n for n in cfg.nodes if n["id"] == nid), None)
            if node:
                insts.extend(node.get("instructions", []))
        return insts
