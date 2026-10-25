"""package-lock.json / npm-shrinkwrap.json (lockfileVersion 2 and 3)."""

from __future__ import annotations

import re
from typing import Any

from scradar.domain.models import ROOT_ID, Component, DepType, Inventory, Location
from scradar.ingestion.common import (
    IngestError,
    InventoryBuilder,
    decode_text,
    load_json,
    make_id,
    normalize_licenses,
    purl_npm,
    sha256_hex,
)
from scradar.security import DEFAULT_LIMITS, Limits

SUPPORTED_LOCKFILE_VERSIONS = (2, 3)
_KEY_LINE = re.compile(r'^\s*"([^"\n]+)"\s*:\s*\{', re.M)
_GIT_PREFIXES = ("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "ssh://")

_DEP_FIELDS = (
    ("dependencies", DepType.RUNTIME),
    ("devDependencies", DepType.DEV),
    ("optionalDependencies", DepType.OPTIONAL),
    ("peerDependencies", DepType.PEER),
)


def _install_name(key: str) -> str:
    idx = key.rfind("node_modules/")
    return key[idx + len("node_modules/") :] if idx >= 0 else key


def _parent_base(base: str) -> str:
    idx = base.rfind("node_modules/")
    if idx < 0:
        return ""
    return base[:idx].rstrip("/")


def _resolve(packages: dict[str, Any], base: str, dep: str) -> str | None:
    """Node's resolution walk: nearest node_modules/<dep> going up from ``base``."""

    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in packages:
            return cand
        if not base:
            return None
        base = _parent_base(base)


def _classify_source(entry: dict[str, Any]) -> tuple[str, str | None]:
    if entry.get("link"):
        return "workspace", "workspace link, not a registry package"
    resolved = entry.get("resolved")
    if not resolved:
        return ("bundled" if entry.get("inBundle") else "unknown"), None
    if resolved.startswith(_GIT_PREFIXES):
        return "git", "git dependency: registry advisories cannot be matched to a commit"
    if resolved.startswith("file:"):
        return "file", "local file dependency"
    if resolved.startswith(("http://", "https://")):
        if "/-/" in resolved:
            return "registry", None
        return "url", "tarball URL outside a registry layout"
    return "unknown", "unrecognised resolved source"


def parse_npm_lock(
    data: bytes,
    source_label: str = "package-lock.json",
    limits: Limits = DEFAULT_LIMITS,
) -> Inventory:
    doc = load_json(data, limits)
    text = decode_text(data, limits)
    if not isinstance(doc, dict):
        raise IngestError("package-lock.json must be a JSON object")
    ver = doc.get("lockfileVersion")
    if ver not in SUPPORTED_LOCKFILE_VERSIONS:
        raise IngestError(
            f"unsupported npm lockfileVersion {ver!r}; supported: 2, 3 (regenerate older lockfiles with npm >= 7)"
        )
    packages = doc.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise IngestError("npm lockfile has no 'packages' map with a root entry")

    lines: dict[str, int] = {}
    for m in _KEY_LINE.finditer(text):
        lines.setdefault(m.group(1), text.count("\n", 0, m.start()) + 1)

    b = InventoryBuilder(
        format="npm-package-lock",
        parser="scradar.ingestion.npm",
        source_label=source_label,
        checksum=sha256_hex(data),
        format_version=str(ver),
        limits=limits,
    )
    root_entry = packages[""] or {}
    b.root("npm", root_entry.get("name") or doc.get("name") or "application", root_entry.get("version"))

    key_to_id: dict[str, str] = {"": ROOT_ID}
    link_targets: dict[str, str] = {}
    workspace_dirs = {
        k
        for k, v in packages.items()
        if k and "node_modules/" not in k and isinstance(v, dict) and not v.get("link")
    }

    for key, entry in packages.items():
        if key == "" or not isinstance(entry, dict):
            continue
        if entry.get("link"):
            link_targets[key] = str(entry.get("resolved", ""))
            continue
        in_modules = "node_modules/" in key
        if not in_modules and key not in workspace_dirs:
            continue
        install = _install_name(key) if in_modules else key.rsplit("/", 1)[-1]
        real_name = entry.get("name") or install
        version = entry.get("version")
        source, reason = _classify_source(entry)
        if not in_modules:
            source, reason = "workspace", "workspace package, not a registry package"
        if not isinstance(version, str) or not version:
            b.warn(f"{key}: lock entry has no version; component recorded as unresolved")
            version = None
        cid = make_id("npm", real_name, version) if source != "workspace" else f"npm-workspace:{key}"
        comp = Component(
            id=cid,
            ecosystem="npm",
            name=real_name,
            version=version,
            purl=purl_npm(real_name, version) if version and source in {"registry", "bundled"} else None,
            resolved=version is not None,
            source=source,
            integrity=entry.get("integrity"),
            licenses=normalize_licenses(entry.get("license")),
            unsupported_reason=reason,
            locations=[Location(file=b.source_label, line=lines.get(key), detail=key)],
        )
        if install != real_name:
            comp.notes.append(f"installed under alias '{install}'")
        merged = b.add_component(comp)
        key_to_id[key] = merged.id

    # Links point at workspace folder entries.
    for lk, target in link_targets.items():
        if target in key_to_id:
            key_to_id[lk] = key_to_id[target]
        else:
            b.warn(f"{lk}: link target '{target}' is not present in the lockfile")

    missing = 0
    for key, entry in packages.items():
        if key not in key_to_id or not isinstance(entry, dict) or entry.get("link"):
            continue
        parent_id = key_to_id[key]
        for field, dtype in _DEP_FIELDS:
            deps = entry.get(field)
            if not isinstance(deps, dict):
                continue
            for dep_name, constraint in deps.items():
                target_key = _resolve(packages, key, dep_name)
                if target_key is None or target_key not in key_to_id:
                    if dtype in (DepType.RUNTIME, DepType.DEV):
                        missing += 1
                        b.warn(
                            f"{key or 'root'}: dependency '{dep_name}' is not resolvable inside the lockfile"
                        )
                    continue
                if field == "devDependencies" and key and key not in workspace_dirs:
                    dtype = DepType.DEV
                b.add_edge(
                    parent_id,
                    key_to_id[target_key],
                    dtype,
                    constraint=str(constraint),
                    provenance=Location(
                        file=b.source_label, line=lines.get(key or ""), detail=key or "(root)"
                    ),
                )
    if missing:
        b.partial(f"{missing} declared dependencies could not be resolved inside the lockfile", graph=True)
    if ver == 2 and "dependencies" in doc:
        b.warn("lockfileVersion 2 legacy 'dependencies' tree ignored; 'packages' map is authoritative")
    return b.finish()
