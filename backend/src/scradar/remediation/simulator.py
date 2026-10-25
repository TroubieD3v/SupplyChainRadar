"""Remediation Studio engine.

* candidate mode  - a second, concretely resolved lockfile/SBOM is scanned with the same provider
                    (authoritative: ``confirmed_by_candidate_scan``)
* hypothetical    - a proposed version change or removal without running a resolver
                    (``predicted_partial`` at best; never claims full re-resolution)
"""

from __future__ import annotations

import uuid
from collections import deque
from typing import Literal

from pydantic import Field

from scradar import versions
from scradar.comparison.diff import PackageChange, ScanComparison, compare_scans
from scradar.domain.models import (
    EVALUATED_STATES,
    ROOT_ID,
    Component,
    DepType,
    Edge,
    Inventory,
    Model,
    ScanResult,
    utcnow,
)
from scradar.ingestion.common import make_id, purl_npm, purl_pypi
from scradar.intelligence.providers import Provider
from scradar.service import analyze

Status = Literal["confirmed_by_candidate_scan", "predicted_partial", "unknown", "blocked"]


class Operation(Model):
    op: Literal["set_version", "remove"]
    component: str  # component id, or "name" / "ecosystem:name" when unambiguous
    version: str | None = None


class FindingRef(Model):
    advisory_id: str
    package: str
    version: str | None
    severity: str | None
    cause: str | None = None


class ChangeEvidence(Model):
    component: str
    current_version: str | None
    candidate_version: str | None
    obtained_from: Literal["user_input", "candidate_lockfile", "advisory"]
    advisories_before: list[str]
    advisories_after: list[str]
    parents_impacted: list[str]
    full_reresolution: bool
    status: Status
    candidate_evaluated: bool
    source_freshness: str | None = None


class ScenarioOutcome(Model):
    id: str
    name: str
    mode: Literal["candidate_lockfile", "hypothetical"]
    status: Status
    full_reresolution: bool
    created_at: str
    base_scan_id: str
    candidate_scan_id: str | None = None
    operations: list[Operation] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    advisories_removed: list[FindingRef] = Field(default_factory=list)
    advisories_remaining: list[FindingRef] = Field(default_factory=list)
    newly_introduced: list[FindingRef] = Field(default_factory=list)
    unknown: list[FindingRef] = Field(default_factory=list)
    dependencies_changed: list[PackageChange] = Field(default_factory=list)
    unresolved_constraints: list[str] = Field(default_factory=list)
    coverage_delta: dict[str, float | int] = Field(default_factory=dict)
    evidence: list[ChangeEvidence] = Field(default_factory=list)
    explanation: str = ""
    blocked_reason: str | None = None


class FixSuggestion(Model):
    fingerprint: str
    advisory_id: str
    package: str
    current_version: str
    candidate_versions: list[str]
    obtained_from: Literal["advisory"] = "advisory"
    introducers: list[str]
    direct: bool
    note: str


# --- helpers ----------------------------------------------------------------------------------


def _ref(c) -> FindingRef:  # type: ignore[no-untyped-def]
    return FindingRef(
        advisory_id=c.advisory_id,
        package=c.package,
        version=c.version_after or c.version_before,
        severity=c.severity_after or c.severity_before,
        cause=c.cause,
    )


def _fill_from_comparison(out: ScenarioOutcome, cmp: ScanComparison) -> None:
    for c in cmp.findings:
        if c.classification == "resolved":
            out.advisories_removed.append(_ref(c))
        elif c.classification in {"persistent", "reclassified"}:
            out.advisories_remaining.append(_ref(c))
        elif c.classification == "introduced":
            out.newly_introduced.append(_ref(c))
        else:
            out.unknown.append(_ref(c))
    out.dependencies_changed = cmp.packages
    out.coverage_delta = cmp.coverage_delta


def _inventory_from_scan(scan: ScanResult) -> Inventory:
    comps = {c.id: c.model_copy(deep=True) for c in scan.components}
    return Inventory(
        format="scan-snapshot",
        parser="scradar.remediation",
        parser_version=scan.engine_version,
        source_label=f"scan {scan.scan_id}",
        checksum=scan.checksum,
        components=comps,
        edges=[e.model_copy(deep=True) for e in scan.edges],
        graph_complete=scan.coverage.graph_complete,
        coverage="full" if scan.coverage.graph_complete else "partial",
    )


def _resolve_target(inv: Inventory, ref: str) -> Component | str:
    if ref in inv.components:
        return inv.components[ref]
    eco, _, name = ref.rpartition(":") if ":" in ref else ("", "", ref)
    hits = [
        c
        for c in inv.components.values()
        if c.kind == "package" and c.name == name and (not eco or c.ecosystem == eco)
    ]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        return f"component '{ref}' is not in the scan"
    return f"'{ref}' is ambiguous ({', '.join(sorted(h.id for h in hits))}); use the component id"


def _reachable(comps: dict[str, Component], edges: list[Edge]) -> set[str]:
    kids: dict[str, list[str]] = {}
    for e in edges:
        kids.setdefault(e.parent, []).append(e.child)
    seen = {ROOT_ID}
    q = deque([ROOT_ID])
    while q:
        for c in kids.get(q.popleft(), []):
            if c not in seen and c in comps:
                seen.add(c)
                q.append(c)
    return seen


# --- scenarios ----------------------------------------------------------------------------------


def simulate_candidate(
    base: ScanResult,
    candidate_inventories: list[Inventory],
    provider: Provider,
    *,
    name: str = "candidate lockfile",
) -> tuple[ScenarioOutcome, ScanResult]:
    candidate = analyze(candidate_inventories, provider, project=base.project, label=name, demo=base.demo)
    cmp = compare_scans(base, candidate)
    out = ScenarioOutcome(
        id=str(uuid.uuid4()),
        name=name,
        mode="candidate_lockfile",
        status="confirmed_by_candidate_scan",
        full_reresolution=True,
        created_at=utcnow().isoformat().replace("+00:00", "Z"),
        base_scan_id=base.scan_id,
        candidate_scan_id=candidate.scan_id,
        assumptions=[
            "The candidate file is a concrete resolution produced by your package manager; it was parsed statically.",
            "Both inventories were matched with the same advisory provider"
            + (
                f" and snapshot '{candidate.advisory_source.snapshot_id}'."
                if candidate.advisory_source.snapshot_id
                else "."
            ),
        ],
    )
    _fill_from_comparison(out, cmp)
    if cmp.advisory_source_changed:
        out.assumptions.append(
            "Advisory data differs between base and candidate scans; see the comparison notes."
        )
    if out.unknown:
        out.status = "unknown"
        out.explanation = f"{len(out.unknown)} advisory outcome(s) could not be determined because packages were not evaluated."
    cstates = {e.component_id: e.state for e in candidate.evaluations}
    bfind: dict[tuple[str, str], list[str]] = {}
    for f in base.findings:
        bfind.setdefault((f.ecosystem, f.package), []).append(f.advisory.id)
    cfind: dict[tuple[str, str], list[str]] = {}
    for f in candidate.findings:
        cfind.setdefault((f.ecosystem, f.package), []).append(f.advisory.id)
    cand_comps = {(c.ecosystem, c.name): c for c in candidate.components if c.kind == "package"}
    for ch in cmp.packages:
        cc = cand_comps.get((ch.ecosystem, ch.name))
        out.evidence.append(
            ChangeEvidence(
                component=f"{ch.ecosystem}:{ch.name}",
                current_version=ch.before,
                candidate_version=ch.after,
                obtained_from="candidate_lockfile",
                advisories_before=sorted(bfind.get((ch.ecosystem, ch.name), [])),
                advisories_after=sorted(cfind.get((ch.ecosystem, ch.name), [])),
                parents_impacted=[],
                full_reresolution=True,
                status=out.status,
                candidate_evaluated=bool(cc and cstates.get(cc.id) in EVALUATED_STATES),
                source_freshness=candidate.advisory_source.snapshot_generated
                or candidate.advisory_source.fetched_at,
            )
        )
    if not out.explanation:
        out.explanation = (
            f"Computed from a concrete candidate inventory: {len(out.advisories_removed)} removed, "
            f"{len(out.advisories_remaining)} remaining, {len(out.newly_introduced)} newly introduced; "
            f"{len(out.dependencies_changed)} dependency change(s)."
        )
    return out, candidate


def simulate_hypothetical(
    base: ScanResult,
    operations: list[Operation],
    provider: Provider,
    *,
    name: str = "hypothetical change",
) -> tuple[ScenarioOutcome, ScanResult | None]:
    inv = _inventory_from_scan(base)
    out = ScenarioOutcome(
        id=str(uuid.uuid4()),
        name=name,
        mode="hypothetical",
        status="predicted_partial",
        full_reresolution=False,
        created_at=utcnow().isoformat().replace("+00:00", "Z"),
        base_scan_id=base.scan_id,
        operations=operations,
        assumptions=[
            "No dependency resolver was run: transitive dependencies of changed packages are assumed unchanged.",
            "The result is a prediction. Confirm it by generating a real lockfile and running a candidate scan.",
            "A version without advisory matches is not 'safe'; it only has no match in the advisory data used.",
        ],
    )
    evidence_seed: list[tuple[str, str | None, str | None, list[str]]] = []
    for op in operations:
        target = _resolve_target(inv, op.component)
        if isinstance(target, str):
            out.status, out.blocked_reason = "blocked", target
            return _finish_blocked(out), None
        parents = sorted({e.parent for e in inv.edges if e.child == target.id})
        if op.op == "set_version":
            if not op.version:
                out.status, out.blocked_reason = "blocked", "set_version needs a version"
                return _finish_blocked(out), None
            if versions.comparable(target.ecosystem):
                try:
                    versions.parse(target.ecosystem, op.version)
                except versions.VersionError as exc:
                    out.status, out.blocked_reason = "blocked", str(exc)
                    return _finish_blocked(out), None
            new_id = make_id(target.ecosystem, target.name, op.version)
            new = target.model_copy(deep=True)
            new.id, new.version, new.resolved = new_id, op.version, True
            new.purl = (
                purl_npm(new.name, op.version)
                if new.ecosystem == "npm"
                else purl_pypi(new.name, op.version)
                if new.ecosystem == "PyPI"
                else None
            )
            new.notes = [*new.notes, "hypothetical version: not produced by a resolver"]
            del inv.components[target.id]
            inv.components[new_id] = new
            for e in inv.edges:
                if e.child == target.id:
                    e.child = new_id
                    ok = versions.constraint_satisfied(new.ecosystem, op.version, e.constraint)
                    pname = inv.components[e.parent].name if e.parent in inv.components else e.parent
                    if ok is False:
                        out.unresolved_constraints.append(
                            f"{pname} requires {new.name} '{e.constraint}', which {op.version} does not satisfy; "
                            f"{pname} would also need to change"
                        )
                    elif ok is None and e.constraint:
                        out.unresolved_constraints.append(
                            f"could not evaluate constraint '{e.constraint}' from {pname} against {op.version}"
                        )
                if e.parent == target.id:
                    e.parent = new_id
                    e.confidence = "inferred"
            evidence_seed.append((new_id, target.version, op.version, parents))
        else:
            if not any(e.parent == ROOT_ID and e.child == target.id for e in inv.edges):
                out.status = "blocked"
                out.blocked_reason = (
                    f"{target.name} is a transitive dependency; it is introduced by "
                    f"{', '.join(parents) or 'unknown parents'} and cannot be removed directly"
                )
                return _finish_blocked(out), None
            inv.edges = [e for e in inv.edges if not (e.parent == ROOT_ID and e.child == target.id)]
            keep = _reachable(inv.components, inv.edges)
            dropped = sorted(cid for cid in inv.components if cid not in keep)
            survivors = [cid for cid in _reachable_from(base, target.id) if cid in keep and cid != target.id]
            inv.components = {cid: c for cid, c in inv.components.items() if cid in keep}
            inv.edges = [e for e in inv.edges if e.parent in keep and e.child in keep]
            out.assumptions.append(
                f"Removing {target.name} drops {len(dropped)} package(s) only reachable through it; "
                f"{len(survivors)} of its dependencies stay because other parents still require them."
            )
            evidence_seed.append((target.id, target.version, None, parents))

    candidate = analyze([inv], provider, project=base.project, label=name, demo=base.demo)
    cmp = compare_scans(base, candidate)
    _fill_from_comparison(out, cmp)
    cstates = {e.component_id: e.state for e in candidate.evaluations}
    bfind: dict[str, list[str]] = {}
    for f in base.findings:
        bfind.setdefault(f"{f.ecosystem}:{f.package}", []).append(f.advisory.id)
    cfind: dict[str, list[str]] = {}
    for f in candidate.findings:
        cfind.setdefault(f"{f.ecosystem}:{f.package}", []).append(f.advisory.id)
    all_evaluated = True
    for cid, before, after, parents in evidence_seed:
        comp = candidate.component_map().get(cid)
        key = f"{comp.ecosystem}:{comp.name}" if comp else cid.split("@")[0]
        evaluated = after is None or cstates.get(cid) in EVALUATED_STATES
        all_evaluated = all_evaluated and evaluated
        out.evidence.append(
            ChangeEvidence(
                component=key,
                current_version=before,
                candidate_version=after,
                obtained_from="user_input",
                advisories_before=sorted(bfind.get(key, [])),
                advisories_after=sorted(cfind.get(key, [])),
                parents_impacted=parents,
                full_reresolution=False,
                status="predicted_partial" if evaluated else "unknown",
                candidate_evaluated=evaluated,
                source_freshness=candidate.advisory_source.snapshot_generated
                or candidate.advisory_source.fetched_at,
            )
        )
    if not all_evaluated or out.unknown:
        out.status = "unknown"
        out.explanation = (
            "The proposed version could not be evaluated against advisory data, so its outcome is unknown."
        )
    else:
        out.explanation = (
            f"Predicted without re-resolution: {len(out.advisories_removed)} advisory match(es) would disappear, "
            f"{len(out.advisories_remaining)} remain, {len(out.newly_introduced)} would be introduced."
            + (
                f" {len(out.unresolved_constraints)} parent constraint(s) conflict."
                if out.unresolved_constraints
                else ""
            )
        )
    return out, candidate


def _reachable_from(scan: ScanResult, start: str) -> set[str]:
    kids: dict[str, list[str]] = {}
    for e in scan.edges:
        kids.setdefault(e.parent, []).append(e.child)
    seen = {start}
    q = deque([start])
    while q:
        for c in kids.get(q.popleft(), []):
            if c not in seen:
                seen.add(c)
                q.append(c)
    return seen


def _finish_blocked(out: ScenarioOutcome) -> ScenarioOutcome:
    out.explanation = f"Scenario blocked: {out.blocked_reason}"
    return out


def suggest_fixes(scan: ScanResult) -> list[FixSuggestion]:
    out = []
    for f in scan.findings:
        cands = f.advisory.fixed_versions
        note = (
            "Fixed version(s) come from the advisory's affected ranges."
            if cands
            else "The advisory lists no fixed version; consider removal or a different package."
        )
        if not f.direct:
            note += " This is a transitive dependency: updating the introducing package(s) may or may not pull a fixed version — verify with a candidate lockfile."
        out.append(
            FixSuggestion(
                fingerprint=f.fingerprint,
                advisory_id=f.advisory.id,
                package=f.package,
                current_version=f.version,
                candidate_versions=cands,
                introducers=f.paths.introducers,
                direct=f.direct,
                note=note,
            )
        )
    return out


def compare_plans(outcomes: list[ScenarioOutcome]) -> list[dict]:
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    rows = []
    for o in outcomes:
        benefit = sum(weights.get(r.severity or "", 1) for r in o.advisories_removed) - sum(
            weights.get(r.severity or "", 1) for r in o.newly_introduced
        )
        rows.append(
            {
                "scenario_id": o.id,
                "name": o.name,
                "mode": o.mode,
                "status": o.status,
                "full_reresolution": o.full_reresolution,
                "advisories_removed": len(o.advisories_removed),
                "advisories_remaining": len(o.advisories_remaining),
                "newly_introduced": len(o.newly_introduced),
                "unknown": len(o.unknown),
                "dependencies_changed": len(o.dependencies_changed),
                "unresolved_constraints": len(o.unresolved_constraints),
                "coverage_delta": o.coverage_delta,
                "severity_weighted_benefit": benefit,
                "tradeoff": (
                    f"benefit {benefit:+d} (severity-weighted) for {len(o.dependencies_changed)} changed package(s)"
                    + ("; prediction only" if not o.full_reresolution else "")
                ),
            }
        )
    return rows


__all__ = [
    "Operation",
    "ScenarioOutcome",
    "simulate_candidate",
    "simulate_hypothetical",
    "suggest_fixes",
    "compare_plans",
    "DepType",
]
