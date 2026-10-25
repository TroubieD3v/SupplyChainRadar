"""SPDX 2.3 JSON import (structural validation; supported relationship types listed below)."""

from __future__ import annotations

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

# (relationship type) -> (direction, dependency type); direction "fwd": A depends on B
RELATIONSHIPS: dict[str, tuple[str, DepType]] = {
    "DEPENDS_ON": ("fwd", DepType.RUNTIME),
    "RUNTIME_DEPENDENCY_OF": ("rev", DepType.RUNTIME),
    "DEPENDENCY_OF": ("rev", DepType.RUNTIME),
    "DEV_DEPENDENCY_OF": ("rev", DepType.DEV),
    "BUILD_DEPENDENCY_OF": ("rev", DepType.DEV),
    "TEST_DEPENDENCY_OF": ("rev", DepType.DEV),
    "OPTIONAL_DEPENDENCY_OF": ("rev", DepType.OPTIONAL),
}


def parse_spdx(
    data: bytes,
    source_label: str = "sbom.spdx.json",
    limits: Limits = DEFAULT_LIMITS,
) -> Inventory:
    doc = load_json(data, limits)
    if not isinstance(doc, dict) or not str(doc.get("spdxVersion", "")).startswith("SPDX-"):
        raise IngestError("not an SPDX JSON document (missing spdxVersion)")
    if doc["spdxVersion"] != "SPDX-2.3":
        raise IngestError(f"unsupported spdxVersion {doc['spdxVersion']!r}; supported: SPDX-2.3")
    if not isinstance(doc.get("packages"), list) or not doc.get("SPDXID"):
        raise IngestError("SPDX document needs 'SPDXID' and a 'packages' array")

    b = InventoryBuilder(
        format="spdx",
        parser="scradar.ingestion.spdx",
        source_label=source_label,
        checksum=sha256_hex(data),
        format_version="2.3",
        limits=limits,
    )
    relationships = [r for r in doc.get("relationships") or [] if isinstance(r, dict)]
    described: set[str] = set(doc.get("documentDescribes") or [])
    for r in relationships:
        if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == doc["SPDXID"]:
            described.add(str(r.get("relatedSpdxElement")))
        if r.get("relationshipType") == "DESCRIBED_BY" and r.get("relatedSpdxElement") == doc["SPDXID"]:
            described.add(str(r.get("spdxElementId")))

    id_map: dict[str, str] = {}
    root_pkg = next((p for p in doc["packages"] if p.get("SPDXID") in described), None)
    b.root(
        "generic",
        (root_pkg or {}).get("name") or doc.get("name") or "application",
        (root_pkg or {}).get("versionInfo"),
    )
    if root_pkg:
        id_map[root_pkg["SPDXID"]] = ROOT_ID

    for idx, p in enumerate(doc["packages"]):
        spdx_id = p.get("SPDXID")
        if not spdx_id or spdx_id in id_map or not p.get("name"):
            continue
        purl_text = next(
            (
                ref.get("referenceLocator")
                for ref in p.get("externalRefs") or []
                if ref.get("referenceType") == "purl"
            ),
            None,
        )
        purl = parse_purl(purl_text) if purl_text else None
        ident = purl_to_identity(purl) if purl else None
        version = p.get("versionInfo") or (purl.version if purl else None)
        if ident:
            eco, name = ident
            version = (purl.version if purl and purl.version else version) or None
            cid = make_id(eco, name, version)
            reason = None
        else:
            eco, name = "generic", str(p["name"])
            cid = make_id("generic", name, version) + f"#{spdx_id}"
            reason = "package has no purl external reference for a supported ecosystem"
        lic = p.get("licenseConcluded") or p.get("licenseDeclared")
        comp = Component(
            id=cid,
            ecosystem=eco,
            name=name,
            version=version,
            purl=purl_text if ident else None,
            resolved=version is not None,
            licenses=[lic] if isinstance(lic, str) and lic not in {"NOASSERTION", "NONE"} else [],
            source="sbom",
            unsupported_reason=reason,
            locations=[Location(file=b.source_label, detail=f"packages[{idx}]")],
        )
        merged = b.add_component(comp)
        id_map[spdx_id] = merged.id

    ignored: dict[str, int] = {}
    edges = 0
    for r in relationships:
        rtype = r.get("relationshipType")
        if rtype in {"DESCRIBES", "DESCRIBED_BY"}:
            continue
        spec = RELATIONSHIPS.get(str(rtype))
        if spec is None:
            ignored[str(rtype)] = ignored.get(str(rtype), 0) + 1
            continue
        a, c = id_map.get(str(r.get("spdxElementId"))), id_map.get(str(r.get("relatedSpdxElement")))
        if a is None or c is None:
            b.warn(
                f"relationship {rtype}: unknown element {r.get('spdxElementId')} -> {r.get('relatedSpdxElement')}"
            )
            continue
        parent, child = (a, c) if spec[0] == "fwd" else (c, a)
        b.add_edge(
            parent, child, spec[1], provenance=Location(file=b.source_label, detail=f"relationship {rtype}")
        )
        edges += 1
    if ignored:
        b.warn(
            "unsupported SPDX relationship types ignored: "
            + ", ".join(f"{k}×{v}" for k, v in sorted(ignored.items()))
        )
    if edges == 0:
        b.partial(
            "SPDX document has no dependency relationships; dependency paths cannot be derived", graph=True
        )
    elif not root_pkg:
        b.partial("SPDX document does not describe a root package", graph=True)
    return b.finish()
