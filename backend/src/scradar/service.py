"""The single analysis entry point used by the CLI, the HTTP API and the remediation simulator."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from typing import Any

from scradar import ENGINE_VERSION
from scradar.domain.models import (
    ROOT_ID,
    Advisory,
    ArtifactInfo,
    Component,
    ComponentEvaluation,
    CoverageSummary,
    Finding,
    Inventory,
    QueryState,
    ScanResult,
    Severity,
    SeverityEvidence,
    utcnow,
)
from scradar.findings.scoring import KevData, score_finding
from scradar.graph.engine import DependencyGraph
from scradar.ingestion.detect import merge_inventories
from scradar.intelligence.osv_model import to_advisory
from scradar.intelligence.providers import ComponentResult, Match, Provider

LIMITATIONS = [
    "Presence of a vulnerable dependency does not prove that the vulnerable code is reachable or exploitable.",
    "'No advisories' means none were found in the data source and snapshot shown, not that the package is safe.",
    "Packages that are unresolved, unsupported or not evaluated are excluded from the advisory result and listed in coverage.",
    "Dependency edges come from the imported files; missing or inferred edges are labelled and never silently completed.",
]

_ID_PRIORITY = ("GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "OSV-", "CVE-")


def _id_rank(vid: str) -> tuple[int, str]:
    for i, p in enumerate(_ID_PRIORITY):
        if vid.startswith(p):
            return (i, vid)
    return (len(_ID_PRIORITY), vid)


def group_matches(matches: list[Match]) -> list[list[Match]]:
    """Union-find over advisory ids and aliases so one real issue yields one finding."""

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for m in matches:
        ids = [m.record["id"], *(m.record.get("aliases") or [])]
        for other in ids[1:]:
            union(ids[0], other)
        find(ids[0])
    groups: dict[str, list[Match]] = {}
    for m in matches:
        groups.setdefault(find(m.record["id"]), []).append(m)
    return list(groups.values())


def _merge_group(group: list[Match]) -> tuple[Advisory, Match]:
    ids: set[str] = set()
    for m in group:
        ids.add(m.record["id"])
        ids.update(m.record.get("aliases") or [])
    primary_id = min((m.record["id"] for m in group), key=_id_rank)
    primary = next(m for m in group if m.record["id"] == primary_id)
    adv = to_advisory(primary.record)
    fixed: set[str] = set()
    best: SeverityEvidence = adv.severity
    for m in group:
        fixed.update(m.fixed_versions)
        sev = to_advisory(m.record).severity
        if (sev.level.rank, sev.score or 0) > (best.level.rank, best.score or 0):
            best = sev
    adv.severity = best
    adv.fixed_versions = sorted(fixed)
    adv.aliases = sorted(ids - {adv.id})
    adv.merged_ids = sorted(m.record["id"] for m in group if m.record["id"] != adv.id)
    return adv, primary


def fingerprint(c: Component, advisory_id: str) -> str:
    raw = f"{c.ecosystem}|{c.name}|{c.version}|{advisory_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _sort_findings(fs: list[Finding]) -> list[Finding]:
    return sorted(
        fs,
        key=lambda f: (-f.advisory.severity.level.rank, -(f.priority.score or -1), f.package, f.advisory.id),
    )


def analyze(
    inventories: list[Inventory],
    provider: Provider,
    *,
    project: str = "project",
    label: str | None = None,
    demo: bool = False,
    kev: KevData | None = None,
    criticality: float | None = None,
    weights: dict[str, float] | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_stage: Callable[[str], None] | None = None,
    max_paths: int = 20,
    scan_id: str | None = None,
    created_at: str | None = None,
) -> ScanResult:
    stage = on_stage or (lambda _s: None)
    stage("analyzing")
    inv = merge_inventories(inventories, label or project)
    if len(inventories) > 1:
        inv.components[ROOT_ID].name = label or project
    graph = DependencyGraph(inv.components, inv.edges)
    graph.compute_scopes()

    packages = [c for c in inv.components.values() if c.kind == "package" and c.source != "workspace"]
    stage("enriching")
    results = provider.evaluate(packages, cancelled)
    for c in packages:
        results.setdefault(
            c.id, ComponentResult(QueryState.NOT_EVALUATED, note="no result returned by the provider")
        )
    stage("analyzing")

    findings: list[Finding] = []
    evaluations: list[ComponentEvaluation] = []
    snapshot_id = getattr(provider, "snapshot_id", None)
    for c in sorted(packages, key=lambda x: x.id):
        res = results[c.id]
        ids: list[str] = []
        for group in group_matches(res.matches):
            adv, primary = _merge_group(group)
            ids.append(adv.id)
            paths = graph.paths_to(c.id, max_paths=max_paths)
            prio = score_finding(
                severity=adv.severity,
                aliases=[adv.id, *adv.aliases],
                paths=paths,
                direct=c.direct,
                scopes=c.scopes,
                kev=kev,
                criticality=criticality,
                weights=weights,
            )
            ev = primary.evidence
            findings.append(
                Finding(
                    fingerprint=fingerprint(c, adv.id),
                    component_id=c.id,
                    ecosystem=c.ecosystem,
                    package=c.name,
                    version=c.version or "",
                    purl=c.purl,
                    advisory=adv,
                    match=ev,
                    paths=paths,
                    direct=c.direct,
                    scopes=c.scopes,
                    priority=prio,
                    source=res.source or "unknown",
                    fetched_at=res.fetched_at,
                    snapshot_id=snapshot_id,
                    location=c.locations[0] if c.locations else None,
                )
            )
        evaluations.append(
            ComponentEvaluation(
                component_id=c.id,
                state=res.state,
                source=res.source,
                fetched_at=res.fetched_at,
                note=res.note,
                advisory_ids=sorted(ids),
            )
        )
    findings = _sort_findings(findings)

    states = [e.state for e in evaluations]
    total = len(packages)
    ev_n = sum(1 for s in states if s == QueryState.EVALUATED)
    ca_n = sum(1 for s in states if s == QueryState.CACHED)
    unresolved = sum(1 for c in packages if not c.resolved)
    coverage = CoverageSummary(
        total_packages=total,
        evaluated=ev_n,
        cached=ca_n,
        not_evaluated=sum(1 for s in states if s == QueryState.NOT_EVALUATED),
        unsupported=sum(1 for s in states if s == QueryState.UNSUPPORTED),
        error=sum(1 for s in states if s == QueryState.ERROR),
        unresolved=unresolved,
        graph_complete=inv.graph_complete,
        percent_evaluated=round(100.0 * (ev_n + ca_n) / total, 1) if total else 100.0,
        notes=list(inv.coverage_notes)
        + ([inv.graph_note] if inv.graph_note and inv.graph_note not in inv.coverage_notes else []),
    )

    artifacts = [
        ArtifactInfo(
            format=i.format,
            format_version=i.format_version,
            parser=i.parser,
            parser_version=i.parser_version,
            source_label=i.source_label,
            checksum=i.checksum,
            components=sum(
                1 for c in i.components.values() if c.kind == "package" and c.source != "workspace"
            ),
            edges=len(i.edges),
            graph_complete=i.graph_complete,
            graph_note=i.graph_note,
            coverage=i.coverage,
            warnings=i.warnings,
        )
        for i in inventories
    ]
    source = provider.source_info(results)
    result = ScanResult(
        engine_version=ENGINE_VERSION,
        scan_id=scan_id or str(uuid.uuid4()),
        project=project,
        created_at=created_at or utcnow().isoformat().replace("+00:00", "Z"),
        demo=demo,
        label=label,
        checksum="",
        artifacts=artifacts,
        components=sorted(inv.components.values(), key=lambda c: (c.kind != "application", c.id)),
        edges=sorted(inv.edges, key=lambda e: (e.parent, e.child, e.type.value)),
        evaluations=evaluations,
        findings=findings,
        coverage=coverage,
        advisory_source=source,
        warnings=inv.warnings[:300],
        limitations=LIMITATIONS,
    )
    result.checksum = scan_checksum(result)
    return result


def scan_checksum(result: ScanResult) -> str:
    """Deterministic digest: ignores scan id, timestamps and fetch times."""

    doc: dict[str, Any] = {
        "engine": result.engine_version,
        "inputs": sorted(a.checksum for a in result.artifacts),
        "components": [(c.id, c.version, c.resolved) for c in result.components],
        "edges": [(e.parent, e.child, e.type.value) for e in result.edges],
        "evaluations": [(e.component_id, e.state.value) for e in result.evaluations],
        "findings": [
            (f.fingerprint, f.advisory.id, f.advisory.severity.level.value, f.advisory.raw_hash)
            for f in result.findings
        ],
        "snapshot": result.advisory_source.snapshot_id,
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()


def severity_counts(result: ScanResult) -> dict[str, int]:
    out = {s.value: 0 for s in Severity}
    for f in result.findings:
        out[f.advisory.severity.level.value] += 1
    return out
