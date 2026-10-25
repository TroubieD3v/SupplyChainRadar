"""CycloneDX 1.6 / 1.7 JSON SBOM import with official-schema validation."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from scradar.domain.models import ROOT_ID, Component, DepType, Inventory, Location
from scradar.ingestion.common import (
    IngestError,
    InventoryBuilder,
    load_json,
    make_id,
    parse_purl,
    purl_to_identity,
    sha256_hex,
)
from scradar.security import DEFAULT_LIMITS, Limits

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
SUPPORTED_SPEC_VERSIONS = ("1.6", "1.7")
_MAX_NESTING = 50


@lru_cache(maxsize=4)
def _validator(spec: str) -> Draft7Validator:
    def load(name: str) -> dict[str, Any]:
        return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))

    schema = load(f"bom-{spec}.schema.json")
    resources = []
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        doc = load(name)
        resources.append((doc["$id"], Resource.from_contents(doc)))
    registry: Registry = Registry().with_resources(resources)
    return Draft7Validator(schema, registry=registry)


def validate_cyclonedx(doc: dict[str, Any]) -> list[str]:
    spec = str(doc.get("specVersion"))
    if spec not in SUPPORTED_SPEC_VERSIONS:
        raise IngestError(f"unsupported CycloneDX specVersion {spec!r}; supported: 1.6, 1.7")
    errors = sorted(_validator(spec).iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [f"/{'/'.join(str(p) for p in e.absolute_path)}: {e.message[:200]}" for e in errors[:10]]


def _licenses(comp: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for item in comp.get("licenses") or []:
        if "expression" in item:
            out.append(str(item["expression"]))
        elif isinstance(item.get("license"), dict):
            out.append(str(item["license"].get("id") or item["license"].get("name") or ""))
    return [s for s in out if s]


def parse_cyclonedx(
    data: bytes,
    source_label: str = "bom.json",
    limits: Limits = DEFAULT_LIMITS,
) -> Inventory:
    doc = load_json(data, limits)
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
        raise IngestError("not a CycloneDX JSON document (bomFormat != 'CycloneDX')")
    problems = validate_cyclonedx(doc)
    if problems:
        raise IngestError("CycloneDX schema validation failed: " + "; ".join(problems))
    spec = str(doc["specVersion"])

    b = InventoryBuilder(
        format="cyclonedx",
        parser="scradar.ingestion.cyclonedx",
        source_label=source_label,
        checksum=sha256_hex(data),
        format_version=spec,
        limits=limits,
    )
    meta_comp = (doc.get("metadata") or {}).get("component") or {}
    root_ref = meta_comp.get("bom-ref")
    b.root("generic", meta_comp.get("name") or "application", meta_comp.get("version"))

    ref_to_id: dict[str, str] = {}
    if root_ref:
        ref_to_id[root_ref] = ROOT_ID
    scope_map = {"required": "runtime", "optional": "optional", "excluded": "excluded"}

    def walk(items: list[dict[str, Any]], depth: int) -> None:
        if depth > _MAX_NESTING:
            raise IngestError("CycloneDX component nesting is too deep")
        for idx, c in enumerate(items):
            name = c.get("name")
            version = c.get("version") or None
            purl_text = c.get("purl")
            purl = parse_purl(purl_text) if purl_text else None
            ident = purl_to_identity(purl) if purl else None
            reason = None
            if ident:
                eco, pname = ident
                version = (purl.version if purl and purl.version else version) or None
                cid = make_id(eco, pname, version)
            else:
                eco, pname = "generic", str(name)
                reason = (
                    "component has no valid purl for a supported ecosystem; it cannot be matched to advisories"
                    if not purl_text
                    else f"purl type not mapped to an advisory ecosystem: {purl_text}"
                )
                cid = make_id("generic", pname, version) + (
                    f"#{c.get('bom-ref')}" if c.get("bom-ref") else ""
                )
            ctype = c.get("type")
            scopes = [scope_map[c["scope"]]] if c.get("scope") in scope_map else []
            repo = None
            for ref in c.get("externalReferences") or []:
                if ref.get("type") == "vcs" and ref.get("url"):
                    repo = str(ref["url"])
                    break
            comp = Component(
                id=cid,
                ecosystem=eco,
                name=pname,
                version=version,
                purl=purl_text if ident else None,
                resolved=version is not None,
                scopes=scopes,
                licenses=_licenses(c),
                source="sbom",
                repository=repo,
                unsupported_reason=reason if ctype != "file" else "file component",
                locations=[Location(file=b.source_label, detail=f"components[{idx}]")],
            )
            merged = b.add_component(comp)
            if c.get("bom-ref"):
                ref_to_id[c["bom-ref"]] = merged.id
            if c.get("components"):
                walk(c["components"], depth + 1)

    walk(doc.get("components") or [], 0)

    deps = doc.get("dependencies")
    listed: set[str] = set()
    if deps is None:
        b.partial("SBOM carries no dependency relationships; dependency paths cannot be derived", graph=True)
    else:
        for d in deps:
            parent = ref_to_id.get(d.get("ref"))
            if parent is None:
                if d.get("ref"):
                    b.warn(f"dependencies: unknown ref '{d['ref']}'")
                continue
            listed.add(parent)
            for child_ref in d.get("dependsOn") or []:
                child = ref_to_id.get(child_ref)
                if child is None:
                    b.warn(f"dependencies: '{d['ref']}' depends on unknown ref '{child_ref}'")
                    continue
                b.add_edge(
                    parent,
                    child,
                    DepType.RUNTIME,
                    provenance=Location(file=b.source_label, detail=f"dependencies/{d.get('ref')}"),
                )
        unlisted = [cid for cid in b.components if cid != ROOT_ID and cid not in listed]
        if unlisted:
            b.partial(
                f"{len(unlisted)} component(s) have no dependency declaration; their outgoing edges are unknown",
                graph=True,
            )
        if not meta_comp.get("bom-ref"):
            b.warn(
                "metadata.component has no bom-ref; no application root is present, paths start at an inferred root"
            )
            b.partial("no application root declared in the SBOM", graph=True)
            # Components nobody depends on become top-level only by explicit, labelled inference.
            inbound = {e.child for e in b.edges.values()}
            for cid in b.components:
                if cid != ROOT_ID and cid not in inbound:
                    b.add_edge(ROOT_ID, cid, DepType.UNKNOWN, confidence="inferred")

    vulns = doc.get("vulnerabilities")
    if vulns:
        b.warn(
            f"SBOM declares {len(vulns)} vulnerabilit{'y' if len(vulns) == 1 else 'ies'}; "
            "these are imported evidence only and are never treated as confirmed findings"
        )
    return b.finish()
