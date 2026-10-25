"""poetry.lock (lock-version 1.x and 2.x) with optional pyproject.toml for direct dependencies."""

from __future__ import annotations

import re
import tomllib
from typing import Any

from scradar.domain.models import ROOT_ID, Component, DepType, Inventory, Location
from scradar.ingestion.common import (
    IngestError,
    InventoryBuilder,
    decode_text,
    make_id,
    normalize_pypi_name,
    purl_pypi,
    sha256_hex,
)
from scradar.security import DEFAULT_LIMITS, Limits

_NAME_LINE = re.compile(r'^name\s*=\s*"([^"]+)"', re.M)
_PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def _load_toml(data: bytes, limits: Limits, what: str) -> dict[str, Any]:
    text = decode_text(data, limits)
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise IngestError(f"invalid TOML in {what}: {exc}") from exc
    except RecursionError as exc:
        raise IngestError(f"{what}: TOML nesting is too deep") from exc


def direct_dependencies_from_pyproject(
    data: bytes, limits: Limits = DEFAULT_LIMITS
) -> dict[str, tuple[DepType, str | None]]:
    """Names (PEP 503-normalised) of declared direct dependencies with their group type."""

    doc = _load_toml(data, limits, "pyproject.toml")
    out: dict[str, tuple[DepType, str | None]] = {}

    def put(name: str, dtype: DepType, constraint: Any) -> None:
        n = normalize_pypi_name(name)
        if n == "python":
            return
        c = (
            constraint
            if isinstance(constraint, str)
            else (constraint.get("version") if isinstance(constraint, dict) else None)
        )
        if n not in out or dtype == DepType.RUNTIME:
            out[n] = (dtype, c)

    poetry = doc.get("tool", {}).get("poetry", {})
    for name, c in (poetry.get("dependencies") or {}).items():
        put(name, DepType.RUNTIME, c)
    for name, c in (poetry.get("dev-dependencies") or {}).items():
        put(name, DepType.DEV, c)
    for gname, group in (poetry.get("group") or {}).items():
        for name, c in ((group or {}).get("dependencies") or {}).items():
            put(name, DepType.RUNTIME if gname == "main" else DepType.DEV, c)

    project = doc.get("project", {})
    for spec in project.get("dependencies") or []:
        m = _PEP508_NAME.match(str(spec))
        if m:
            put(m.group(1), DepType.RUNTIME, m.group(2).split(";")[0].strip() or None)
    for _extra, specs in (project.get("optional-dependencies") or {}).items():
        for spec in specs or []:
            m = _PEP508_NAME.match(str(spec))
            if m:
                put(m.group(1), DepType.OPTIONAL, m.group(2).split(";")[0].strip() or None)
    for _group, specs in (doc.get("dependency-groups") or {}).items():
        for spec in specs or []:
            if isinstance(spec, str):
                m = _PEP508_NAME.match(spec)
                if m:
                    put(m.group(1), DepType.DEV, m.group(2).split(";")[0].strip() or None)
    return out


def parse_poetry_lock(
    data: bytes,
    source_label: str = "poetry.lock",
    limits: Limits = DEFAULT_LIMITS,
    pyproject: bytes | None = None,
    project_name: str | None = None,
) -> Inventory:
    doc = _load_toml(data, limits, "poetry.lock")
    text = decode_text(data, limits)
    pkgs = doc.get("package")
    if not isinstance(pkgs, list):
        raise IngestError("poetry.lock has no [[package]] entries")
    meta = doc.get("metadata") or {}
    lock_version = str(meta.get("lock-version", ""))
    if not lock_version or lock_version.split(".")[0] not in {"1", "2"}:
        raise IngestError(f"unsupported poetry lock-version {lock_version!r}; supported: 1.x, 2.x")

    name_lines: dict[str, int] = {}
    for m in _NAME_LINE.finditer(text):
        name_lines.setdefault(normalize_pypi_name(m.group(1)), text.count("\n", 0, m.start()) + 1)

    b = InventoryBuilder(
        format="poetry-lock",
        parser="scradar.ingestion.poetry",
        source_label=source_label,
        checksum=sha256_hex(data),
        format_version=lock_version,
        limits=limits,
    )
    b.root("PyPI", project_name or "project", None)

    by_name: dict[str, list[str]] = {}
    raw_deps: list[tuple[str, dict[str, Any]]] = []
    for p in pkgs:
        if not isinstance(p, dict) or not p.get("name") or not p.get("version"):
            b.warn("skipping a [[package]] entry without name/version")
            continue
        norm = normalize_pypi_name(str(p["name"]))
        version = str(p["version"])
        src = p.get("source") or {}
        stype = src.get("type") if isinstance(src, dict) else None
        reason = None
        source = "registry"
        if stype in {"git", "directory", "file", "url"}:
            source, reason = stype, f"{stype} source: registry advisories cannot be matched reliably"
        elif stype == "legacy":
            source = "registry-custom"
        comp = Component(
            id=make_id("PyPI", norm, version),
            ecosystem="PyPI",
            name=norm,
            version=version,
            purl=purl_pypi(norm, version) if reason is None else None,
            source=source,
            unsupported_reason=reason,
            locations=[
                Location(file=b.source_label, line=name_lines.get(norm), detail=f"{p['name']} {version}")
            ],
        )
        if source == "registry-custom":
            comp.notes.append(
                "resolved from a custom package index; advisories assume the PyPI package of the same name"
            )
        merged = b.add_component(comp)
        by_name.setdefault(norm, [])
        if merged.id not in by_name[norm]:
            by_name[norm].append(merged.id)
        raw_deps.append((merged.id, p.get("dependencies") or {}))

    for owner, deps in raw_deps:
        if not isinstance(deps, dict):
            continue
        for dname, spec in deps.items():
            norm = normalize_pypi_name(dname)
            if norm == "python":
                continue
            targets = by_name.get(norm)
            optional = isinstance(spec, dict) and bool(spec.get("optional"))
            constraint = (
                spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            )
            if not targets:
                if not optional:
                    b.warn(f"{b.components[owner].name}: dependency '{dname}' has no entry in the lockfile")
                continue
            conf = "declared" if len(targets) == 1 else "inferred"
            if len(targets) > 1:
                b.warn(
                    f"'{norm}' has {len(targets)} locked versions (marker-conditional); edges to all are marked inferred"
                )
            for t in targets:
                b.add_edge(
                    owner,
                    t,
                    DepType.OPTIONAL if optional else DepType.RUNTIME,
                    constraint=constraint if isinstance(constraint, str) else None,
                    provenance=Location(file=b.source_label, detail=b.components[owner].name),
                    confidence=conf,
                )

    if pyproject is not None:
        directs = direct_dependencies_from_pyproject(pyproject, limits)
        for norm, (dtype, constraint) in directs.items():
            for t in by_name.get(norm, []):
                b.add_edge(
                    ROOT_ID, t, dtype, constraint=constraint, provenance=Location(file="pyproject.toml")
                )
        missing = [n for n in directs if n not in by_name]
        if missing:
            b.warn(
                f"pyproject.toml declares dependencies absent from the lock: {', '.join(sorted(missing)[:10])}"
            )
            b.partial("pyproject.toml and poetry.lock are out of sync", graph=False)
    else:
        inbound = {e.child for e in b.edges.values()}
        top = [cid for cid in b.components if cid != ROOT_ID and cid not in inbound]
        for cid in top:
            b.add_edge(
                ROOT_ID, cid, DepType.RUNTIME, confidence="inferred", provenance=Location(file=b.source_label)
            )
        b.warn(
            "no pyproject.toml supplied: direct dependencies are inferred as packages nothing else depends on"
        )
        b.partial("direct dependencies inferred without pyproject.toml; dev/runtime scope is unknown")
    return b.finish()
