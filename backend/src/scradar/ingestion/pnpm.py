"""pnpm-lock.yaml (lockfileVersion 6.x and 9.x)."""

from __future__ import annotations

import posixpath
from typing import Any

from scradar.domain.models import ROOT_ID, Component, DepType, Inventory, Location
from scradar.ingestion.common import (
    IngestError,
    InventoryBuilder,
    load_yaml,
    make_id,
    purl_npm,
    sha256_hex,
)
from scradar.security import DEFAULT_LIMITS, Limits

SUPPORTED_MAJORS = ("6", "9")


def _strip_peers(s: str) -> str:
    i = s.find("(")
    return s[:i] if i >= 0 else s


def _split_key(key: str) -> tuple[str, str] | None:
    """'/name@1.2.3(peer@1)' (v6) or 'name@1.2.3' (v9) -> (name, version)."""

    base = _strip_peers(key.lstrip("/"))
    idx = base.rfind("@")
    if idx <= 0:
        return None
    return base[:idx], base[idx + 1 :]


def _parse_dep_value(dep_name: str, value: Any) -> tuple[str, str] | tuple[str, None] | None:
    """Return (name, version) or (path, None) for link: targets."""

    if isinstance(value, dict):
        value = value.get("version")
    if not isinstance(value, str):
        return None
    value = _strip_peers(value)
    if value.startswith("link:"):
        return value[5:], None
    if value.startswith("/") or ("@" in value[1:] and not value[0].isdigit()):
        parsed = _split_key(value)  # alias form: 'real-name@1.0.0' or '/real-name@1.0.0'
        return parsed if parsed else None
    return dep_name, value


def parse_pnpm_lock(
    data: bytes,
    source_label: str = "pnpm-lock.yaml",
    limits: Limits = DEFAULT_LIMITS,
) -> Inventory:
    doc = load_yaml(data, limits)
    if not isinstance(doc, dict):
        raise IngestError("pnpm-lock.yaml must be a YAML mapping")
    lv = str(doc.get("lockfileVersion", ""))
    major = lv.split(".")[0]
    if major not in SUPPORTED_MAJORS:
        raise IngestError(f"unsupported pnpm lockfileVersion {lv!r}; supported: 6.x, 9.x")

    b = InventoryBuilder(
        format="pnpm-lock",
        parser="scradar.ingestion.pnpm",
        source_label=source_label,
        checksum=sha256_hex(data),
        format_version=lv,
        limits=limits,
    )
    b.root("npm", "workspace", None)

    importers: dict[str, dict[str, Any]] = {}
    if isinstance(doc.get("importers"), dict):
        importers = {k: (v or {}) for k, v in doc["importers"].items()}
    else:  # single-project v6 layout keeps the dependency maps at top level
        importers = {
            ".": {k: doc.get(k) or {} for k in ("dependencies", "devDependencies", "optionalDependencies")}
        }

    packages = doc.get("packages") or {}
    snapshots = doc.get("snapshots") if major == "9" else packages
    if not isinstance(packages, dict) or not isinstance(snapshots, dict):
        raise IngestError("pnpm lockfile 'packages'/'snapshots' must be mappings")

    def comp_for(name: str, version: str, key_hint: str | None = None) -> str:
        cid = make_id("npm", name, version)
        meta = packages.get(key_hint) if key_hint else None
        integrity = None
        if isinstance(meta, dict) and isinstance(meta.get("resolution"), dict):
            integrity = meta["resolution"].get("integrity")
            tarball = meta["resolution"].get("tarball") or meta["resolution"].get("repo")
        else:
            tarball = None
        source, reason = "registry", None
        if tarball and "/-/" not in str(tarball):
            source, reason = "url", "non-registry tarball/git resolution"
        b.add_component(
            Component(
                id=cid,
                ecosystem="npm",
                name=name,
                version=version,
                purl=purl_npm(name, version) if source == "registry" else None,
                source=source,
                integrity=integrity,
                unsupported_reason=reason,
                locations=[Location(file=b.source_label, detail=key_hint or f"{name}@{version}")],
            )
        )
        return cid

    def snapshot_edges(owner_id: str, entry: Any, label: str) -> None:
        if not isinstance(entry, dict):
            return
        for field, dtype in (("dependencies", DepType.RUNTIME), ("optionalDependencies", DepType.OPTIONAL)):
            for dn, dv in (entry.get(field) or {}).items():
                parsed = _parse_dep_value(dn, dv)
                if not parsed or parsed[1] is None:
                    b.warn(f"{label}: cannot resolve dependency '{dn}'")
                    continue
                name, version = parsed
                cid = comp_for(name, version, f"{name}@{version}" if major == "9" else f"/{name}@{version}")
                b.add_edge(owner_id, cid, dtype, provenance=Location(file=b.source_label, detail=label))

    # snapshot / package-level dependency edges (peer-suffixed variants merge into one node)
    for key, entry in snapshots.items():
        split = _split_key(key)
        if not split:
            b.warn(f"unrecognised package key: {key}")
            continue
        name, version = split
        hint = f"{name}@{version}" if major == "9" else f"/{name}@{version}"
        if hint not in packages and key in packages:
            hint = key
        cid = comp_for(name, version, hint if hint in packages else key)
        snapshot_edges(cid, entry, key)
        if "(" in key:
            b.components[cid].notes.append(
                "peer-dependency variants of this version are merged into one node"
            )

    importer_ids: dict[str, str] = {".": ROOT_ID}
    for path in importers:
        if path != ".":
            wid = f"npm-workspace:{path}"
            importer_ids[path] = wid
            b.add_component(
                Component(
                    id=wid,
                    ecosystem="npm",
                    name=path,
                    version=None,
                    resolved=True,
                    source="workspace",
                    unsupported_reason="workspace package, not a registry package",
                    locations=[Location(file=b.source_label, detail=f"importers/{path}")],
                )
            )
            b.add_edge(
                ROOT_ID, wid, DepType.WORKSPACE, provenance=Location(file=b.source_label, detail="importers")
            )

    for path, imp in importers.items():
        owner = importer_ids[path]
        for field, dtype in (
            ("dependencies", DepType.RUNTIME),
            ("devDependencies", DepType.DEV),
            ("optionalDependencies", DepType.OPTIONAL),
        ):
            for dn, dv in (imp.get(field) or {}).items():
                parsed = _parse_dep_value(dn, dv)
                spec = dv.get("specifier") if isinstance(dv, dict) else None
                if not parsed:
                    b.warn(f"importers/{path}: cannot resolve '{dn}'")
                    continue
                prov = Location(file=b.source_label, detail=f"importers/{path}")
                if parsed[1] is None:
                    target = posixpath.normpath(posixpath.join(path, parsed[0]))
                    tid = importer_ids.get(target)
                    if tid is None:
                        b.warn(
                            f"importers/{path}: link target '{parsed[0]}' is not an importer in this lockfile"
                        )
                        continue
                    b.add_edge(owner, tid, DepType.WORKSPACE, constraint=spec, provenance=prov)
                    continue
                name, version = parsed
                hint = f"{name}@{version}" if major == "9" else f"/{name}@{version}"
                cid = comp_for(name, version, hint)
                b.add_edge(owner, cid, dtype, constraint=spec, provenance=prov)

    if len(importers) > 1:
        b.warn(f"{len(importers) - 1} workspace importer(s) are attached below a synthetic workspace root")
    return b.finish()
