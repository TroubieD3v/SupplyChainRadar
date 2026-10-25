"""Small shared security helpers: secret redaction and bounded-input limits."""

from __future__ import annotations

import re
from dataclasses import dataclass

_URL_CRED = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s:]+(?::[^/@\s]*)?@")
_TOKEN_PATTERNS = [
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bpypi-[A-Za-z0-9_-]{40,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"(?i)\b(bearer|token|authorization)\s*[:=]?\s+[A-Za-z0-9._~+/=-]{20,}"),
    re.compile(r"(?i)\b(_authToken|_auth|password|passwd|api[_-]?key|secret)\s*[:=]\s*\S{6,}"),
]


def redact(text: str | None) -> str | None:
    """Mask URL credentials and common token shapes in free text."""

    if not text:
        return text
    out = _URL_CRED.sub(lambda m: f"{m.group('scheme')}***@", text)
    for pat in _TOKEN_PATTERNS:
        out = pat.sub(lambda m: (m.group(1) + " ***") if m.lastindex else "***", out)
    return out


def redact_str(text: str) -> str:
    """Like redact() but always returns a string."""

    return redact(text) or ""


@dataclass(frozen=True)
class Limits:
    """Ceilings applied to every untrusted input."""

    max_file_bytes: int = 25 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    max_components: int = 100_000
    max_edges: int = 500_000
    max_files: int = 64
    max_dir_depth: int = 5
    max_json_depth: int = 200
    max_zip_entries: int = 2000
    max_zip_ratio: int = 200  # uncompressed/compressed ratio guard (decompression bombs)
    max_path_search_nodes: int = 200_000


DEFAULT_LIMITS = Limits()
