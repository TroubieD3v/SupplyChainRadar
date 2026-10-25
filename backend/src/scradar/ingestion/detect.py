"""Format detection, folder/ZIP import and inventory merging. All reads are static and bounded."""

from __future__ import annotations

import fnmatch
import io
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from scradar.domain.models import ROOT_ID, Inventory
from scradar.ingestion.common import IngestError, sha256_hex
from scradar.ingestion.cyclonedx import parse_cyclonedx
from scradar.ingestion.npm import parse_npm_lock
from scradar.ingestion.pnpm import parse_pnpm_lock
from scradar.ingestion.poetry import parse_poetry_lock
from scradar.ingestion.requirements import parse_requirements
from scradar.ingestion.spdx import parse_spdx
from scradar.security import DEFAULT_LIMITS, Limits, redact, redact_str

SKIP_DIRS = {
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".mypy_cache",
}

_NAME_RULES: list[tuple[str, str]] = [
    ("package-lock.json", "npm"),
    ("npm-shrinkwrap.json", "npm"),
    ("pnpm-lock.yaml", "pnpm"),
    ("poetry.lock", "poetry"),
    ("requirements*.txt", "requirements"),
    ("*-requirements.txt", "requirements"),
    ("*.cdx.json", "sbom-json"),
    ("*.spdx.json", "sbom-json"),
    ("bom.json", "sbom-json"),
    ("sbom.json", "sbom-json"),
    ("*.sbom.json", "sbom-json"),
]
SUPPORTED_FORMATS = ["npm", "pnpm", "poetry", "requirements", "cyclonedx", "spdx"]


def detect_kind(filename: str, data: bytes | None = None) -> str | None:
    base = os.path.basename(filename).lower()
    for pattern, kind in _NAME_RULES:
        if fnmatch.fnmatch(base, pattern):
            return _refine(kind, data)
    if data is not None and base.endswith(".json"):
        return _refine("sbom-json", data)
    return None


def _refine(kind: str, data: bytes | None) -> str | None:
    if kind != "sbom-json":
        return kind
    if data is None:
        return "cyclonedx"
    head = data[:4096].decode("utf-8", "ignore")
    if '"bomFormat"' in head:
        return "cyclonedx"
    if '"spdxVersion"' in head:
        return "spdx"
    # fall back to a real parse of the top-level keys
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (ValueError, RecursionError):
        return None
    if isinstance(doc, dict):
        if doc.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if "spdxVersion" in doc:
            return "spdx"
    return None


def parse_file(
    filename: str,
    data: bytes,
    *,
    kind: str | None = None,
    pyproject: bytes | None = None,
    limits: Limits = DEFAULT_LIMITS,
    label: str | None = None,
) -> Inventory:
    if len(data) > limits.max_file_bytes:
        raise IngestError(f"{filename}: file exceeds the {limits.max_file_bytes} byte limit")
    kind = kind or detect_kind(filename, data)
    if kind is None:
        raise IngestError(f"{filename}: unrecognised or unsupported file type")
    src = label or os.path.basename(filename)
    if kind == "npm":
        return parse_npm_lock(data, src, limits)
    if kind == "pnpm":
        return parse_pnpm_lock(data, src, limits)
    if kind == "poetry":
        return parse_poetry_lock(data, src, limits, pyproject=pyproject)
    if kind == "requirements":
        return parse_requirements(data, src, limits)
    if kind == "cyclonedx":
        return parse_cyclonedx(data, src, limits)
    if kind == "spdx":
        return parse_spdx(data, src, limits)
    raise IngestError(f"{filename}: unsupported kind {kind!r}")


# --- merging --------------------------------------------------------------------------------


def merge_inventories(invs: list[Inventory], label: str) -> Inventory:
    """Merge several inventories under a single application root."""

    if not invs:
        raise IngestError("nothing to import: no supported dependency files were found")
    if len(invs) == 1:
        return invs[0]
    comps: dict = {}
    edges: dict = {}
    warnings: list[str] = []
    notes: list[str] = []
    for inv in invs:
        for cid, c in inv.components.items():
            if cid == ROOT_ID and ROOT_ID in comps:
                continue
            if cid in comps:
                ex = comps[cid]
                ex.locations.extend(loc for loc in c.locations if loc not in ex.locations)
                ex.licenses.extend(x for x in c.licenses if x not in ex.licenses)
                ex.notes.extend(x for x in c.notes if x not in ex.notes)
                ex.direct = ex.direct or c.direct
            else:
                comps[cid] = c.model_copy(deep=True)
        for e in inv.edges:
            edges.setdefault((e.parent, e.child, e.type.value), e)
        warnings.extend(f"[{inv.source_label}] {w}" for w in inv.warnings)
        notes.extend(f"[{inv.source_label}] {n}" for n in inv.coverage_notes)
    comps[ROOT_ID].name = label
    comps[ROOT_ID].version = None
    coverage = "full" if all(i.coverage == "full" for i in invs) else "partial"
    return Inventory(
        format="merged",
        parser="scradar.ingestion.detect",
        parser_version=invs[0].parser_version,
        format_version=None,
        source_label=label,
        checksum=sha256_hex("".join(sorted(i.checksum for i in invs)).encode()),
        components=comps,
        edges=list(edges.values()),
        warnings=warnings,
        graph_complete=all(i.graph_complete for i in invs),
        graph_note="; ".join(i.graph_note for i in invs if i.graph_note) or None,
        coverage=coverage,  # type: ignore[arg-type]
        coverage_notes=notes,
    )


# --- folders --------------------------------------------------------------------------------


@dataclass
class ImportOutcome:
    inventories: list[Inventory]
    skipped: list[str]
    errors: list[str]


def import_directory(root: str | Path, limits: Limits = DEFAULT_LIMITS) -> ImportOutcome:
    """Parse supported files below ``root``. Symlinks are never followed; nothing is executed."""

    root_path = Path(root)
    if root_path.is_symlink() or not root_path.is_dir():
        raise IngestError(f"{root}: not a directory")
    root_real = root_path.resolve()
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root_real, followlinks=False):
        depth = len(Path(dirpath).relative_to(root_real).parts)
        dirnames[:] = [
            d
            for d in dirnames
            if d not in SKIP_DIRS and not (Path(dirpath) / d).is_symlink() and depth < limits.max_dir_depth
        ]
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            if detect_kind(fn) is not None:
                found.append(p)
        if len(found) > limits.max_files:
            raise IngestError(f"more than {limits.max_files} dependency files found; narrow the selection")
    found.sort(key=lambda p: p.relative_to(root_real).as_posix())
    invs: list[Inventory] = []
    skipped: list[str] = []
    errors: list[str] = []
    total = 0
    for p in found:
        rel = p.relative_to(root_real).as_posix()
        size = p.stat().st_size
        total += size
        if size > limits.max_file_bytes or total > limits.max_total_bytes:
            errors.append(f"{rel}: skipped, size limit exceeded")
            continue
        data = p.read_bytes()
        kind = detect_kind(p.name, data)
        if kind is None:
            skipped.append(rel)
            continue
        pyproject = None
        if (
            kind == "poetry"
            and (p.parent / "pyproject.toml").is_file()
            and not (p.parent / "pyproject.toml").is_symlink()
        ):
            pyproject = (p.parent / "pyproject.toml").read_bytes()
        try:
            invs.append(parse_file(p.name, data, kind=kind, pyproject=pyproject, limits=limits, label=rel))
        except IngestError as exc:
            errors.append(f"{rel}: {redact(str(exc))}")
    return ImportOutcome(invs, skipped, errors)


# --- zip (in memory, never extracted to disk) ---------------------------------------------


def import_zip(data: bytes, limits: Limits = DEFAULT_LIMITS) -> ImportOutcome:
    if len(data) > limits.max_file_bytes:
        raise IngestError("archive exceeds the upload size limit")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("not a valid ZIP archive") from exc
    infos = zf.infolist()
    if len(infos) > limits.max_zip_entries:
        raise IngestError(f"archive has {len(infos)} entries, above the limit of {limits.max_zip_entries}")
    total = 0
    wanted: list[zipfile.ZipInfo] = []
    siblings: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = info.filename
        norm = PurePosixPath(name.replace("\\", "/"))
        if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name) or ".." in norm.parts:
            raise IngestError(f"unsafe path in archive: {redact_str(name)[:80]!r}")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise IngestError(f"symlink in archive rejected: {redact_str(name)[:80]!r}")
        if info.is_dir():
            continue
        total += info.file_size
        if info.file_size > limits.max_file_bytes or total > limits.max_total_bytes:
            raise IngestError("archive expands beyond the configured size limits")
        if (
            info.compress_size
            and info.file_size / max(info.compress_size, 1) > limits.max_zip_ratio
            and info.file_size > 1_000_000
        ):
            raise IngestError(
                "archive entry has a suspicious compression ratio (possible decompression bomb)"
            )
        if any(part in SKIP_DIRS for part in norm.parts[:-1]) or len(norm.parts) > limits.max_dir_depth + 1:
            continue
        if norm.name == "pyproject.toml":
            siblings[str(norm.parent)] = info
        if detect_kind(norm.name) is not None:
            wanted.append(info)
    if len(wanted) > limits.max_files:
        raise IngestError(f"archive holds more than {limits.max_files} dependency files")
    invs: list[Inventory] = []
    errors: list[str] = []
    for info in sorted(wanted, key=lambda i: i.filename):
        rel = PurePosixPath(info.filename.replace("\\", "/"))
        blob = _read_bounded(zf, info, limits)
        kind = detect_kind(rel.name, blob)
        if kind is None:
            continue
        pyproject = None
        if kind == "poetry" and str(rel.parent) in siblings:
            pyproject = _read_bounded(zf, siblings[str(rel.parent)], limits)
        try:
            invs.append(
                parse_file(rel.name, blob, kind=kind, pyproject=pyproject, limits=limits, label=str(rel))
            )
        except IngestError as exc:
            errors.append(f"{rel}: {redact(str(exc))}")
    return ImportOutcome(invs, [], errors)


def _read_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limits: Limits) -> bytes:
    with zf.open(info) as fh:
        blob = fh.read(limits.max_file_bytes + 1)
    if len(blob) > limits.max_file_bytes:
        raise IngestError("archive entry larger than declared size")
    return blob
