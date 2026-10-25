"""Compare two immutable scan snapshots without confusing advisory updates, coverage gaps and fixes."""

from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import Field

from scradar import versions
from scradar.domain.models import EVALUATED_STATES, Finding, Model, QueryState, ScanResult

FindingClass = Literal["introduced", "persistent", "resolved", "reclassified", "unknown_due_to_data_gap"]


class ScanRef(Model):
    scan_id: str
    project: str
    label: str | None
    created_at: str
    snapshot_id: str | None
    advisory_mode: str
    percent_evaluated: float
    demo: bool


class PackageChange(Model):
    ecosystem: str
    name: str
    change: Literal["added", "removed", "upgraded", "downgraded", "changed", "source_changed"]
    before: str | None = None
    after: str | None = None


class FindingChange(Model):
    classification: FindingClass
    cause: str
    explanation: str
    ecosystem: str
    package: str
    version_before: str | None = None
    version_after: str | None = None
    advisory_id: str
    aliases: list[str] = Field(default_factory=list)
    severity_before: str | None = None
    severity_after: str | None = None
    fingerprint_before: str | None = None
    fingerprint_after: str | None = None


class ScanComparison(Model):
    left: ScanRef
    right: ScanRef
    packages: list[PackageChange]
    findings: list[FindingChange]
    counts: dict[str, int]
    package_counts: dict[str, int]
    coverage_delta: dict[str, float | int]
    advisory_source_changed: bool
    notes: list[str]


def _ref(s: ScanResult) -> ScanRef:
    return ScanRef(
        scan_id=s.scan_id,
        project=s.project,
        label=s.label,
        created_at=s.created_at,
        snapshot_id=s.advisory_source.snapshot_id,
        advisory_mode=s.advisory_source.mode,
        percent_evaluated=s.coverage.percent_evaluated,
        demo=s.demo,
    )


def _state_index(s: ScanResult) -> dict[str, QueryState]:
    return {e.component_id: e.state for e in s.evaluations}


def _versions_by_name(s: ScanResult) -> dict[tuple[str, str], list[tuple[str | None, str]]]:
    out: dict[tuple[str, str], list[tuple[str | None, str]]] = {}
    for c in s.components:
        if c.kind != "package" or c.source == "workspace":
            continue
        out.setdefault((c.ecosystem, c.name), []).append((c.version, c.id))
    return out


def _counterpart(f: Finding, others: list[Finding]) -> Finding | None:
    ids = {f.advisory.id, *f.advisory.aliases}
    for o in others:
        if (
            o.ecosystem == f.ecosystem
            and o.package == f.package
            and ({o.advisory.id, *o.advisory.aliases} & ids)
        ):
            return o
    return None


def _cmp(eco: str, a: str | None, b: str | None) -> int | None:
    if a is None or b is None:
        return None
    try:
        return versions.compare(eco, a, b)
    except versions.VersionError:
        return None


def compare_scans(left: ScanResult, right: ScanResult) -> ScanComparison:
    notes: list[str] = []
    lstate, rstate = _state_index(left), _state_index(right)
    lvers, rvers = _versions_by_name(left), _versions_by_name(right)
    source_changed = (
        left.advisory_source.snapshot_id != right.advisory_source.snapshot_id
        or left.advisory_source.mode != right.advisory_source.mode
    )
    if source_changed:
        notes.append(
            "The advisory data source differs between the scans "
            f"({left.advisory_source.mode}:{left.advisory_source.snapshot_id or '-'} -> "
            f"{right.advisory_source.mode}:{right.advisory_source.snapshot_id or '-'}); "
            "some changes can come from advisory updates rather than dependency changes."
        )
    if left.demo or right.demo:
        notes.append("At least one side is demo data built from synthetic fixtures.")

    # --- packages -------------------------------------------------------------------------
    pkgs: list[PackageChange] = []
    for key in sorted(set(lvers) | set(rvers)):
        eco, name = key
        lv = sorted({v for v, _ in lvers.get(key, [])}, key=str)
        rv = sorted({v for v, _ in rvers.get(key, [])}, key=str)
        if not lv:
            pkgs.extend(PackageChange(ecosystem=eco, name=name, change="added", after=v) for v in rv)
        elif not rv:
            pkgs.extend(PackageChange(ecosystem=eco, name=name, change="removed", before=v) for v in lv)
        elif len(lv) == 1 and len(rv) == 1:
            if lv[0] != rv[0]:
                c = _cmp(eco, lv[0], rv[0])
                change = "upgraded" if c == -1 else "downgraded" if c == 1 else "changed"
                pkgs.append(
                    PackageChange(ecosystem=eco, name=name, change=change, before=lv[0], after=rv[0])  # type: ignore[arg-type]
                )
        else:
            for v in rv:
                if v not in lv:
                    pkgs.append(PackageChange(ecosystem=eco, name=name, change="added", after=v))
            for v in lv:
                if v not in rv:
                    pkgs.append(PackageChange(ecosystem=eco, name=name, change="removed", before=v))

    # --- findings -------------------------------------------------------------------------
    changes: list[FindingChange] = []

    def evaluated(states: dict[str, QueryState], cid: str | None) -> bool:
        return cid is not None and states.get(cid) in EVALUATED_STATES

    def same_or_first(index, key, version):  # type: ignore[no-untyped-def]
        cands = index.get(key, [])
        for v, cid in cands:
            if v == version:
                return v, cid
        return cands[0] if cands else (None, None)

    for rf in right.findings:
        lf = _counterpart(rf, left.findings)
        base: dict[str, Any] = dict(
            ecosystem=rf.ecosystem,
            package=rf.package,
            advisory_id=rf.advisory.id,
            aliases=rf.advisory.aliases,
            version_after=rf.version,
            severity_after=rf.advisory.severity.level.value,
            fingerprint_after=rf.fingerprint,
        )
        if lf is not None:
            sev_b = lf.advisory.severity.level.value
            moved = lf.version != rf.version
            if sev_b != rf.advisory.severity.level.value:
                changes.append(
                    FindingChange(
                        classification="reclassified",
                        cause="severity_changed_in_source",
                        explanation=f"severity changed from {sev_b} to {rf.advisory.severity.level.value} in the advisory data",
                        version_before=lf.version,
                        severity_before=sev_b,
                        fingerprint_before=lf.fingerprint,
                        **base,
                    )
                )
            else:
                changes.append(
                    FindingChange(
                        classification="persistent",
                        cause="still_affected_after_version_change" if moved else "unchanged",
                        explanation=(
                            f"version changed {lf.version} -> {rf.version} but it is still inside an affected range"
                            if moved
                            else "present in both scans"
                        ),
                        version_before=lf.version,
                        severity_before=sev_b,
                        fingerprint_before=lf.fingerprint,
                        **base,
                    )
                )
            continue
        key = (rf.ecosystem, rf.package)
        lv, lcid = same_or_first(lvers, key, rf.version)
        if lv is None and lcid is None:
            cls, cause, why = "introduced", "new_dependency", "package is new in the right-hand scan"
        elif not evaluated(lstate, lcid):
            cls, cause, why = (
                "unknown_due_to_data_gap",
                "left_not_evaluated",
                "the earlier scan did not evaluate this package, so it is unknown whether the issue is new",
            )
        elif lv != rf.version:
            cls, cause, why = "introduced", "version_change", f"package changed {lv} -> {rf.version}"
        elif source_changed:
            cls, cause, why = (
                "introduced",
                "advisory_database_update",
                "same package version; the advisory appeared in newer advisory data, not through a dependency change",
            )
        else:
            cls, cause, why = "introduced", "evaluation_difference", "same version and same advisory source"
        changes.append(
            FindingChange(
                classification=cast(FindingClass, cls),
                cause=cause,
                explanation=why,
                version_before=lv,
                **base,
            )
        )  # type: ignore[arg-type]

    for lf in left.findings:
        if _counterpart(lf, right.findings) is not None:
            continue
        key = (lf.ecosystem, lf.package)
        rv, rcid = same_or_first(rvers, key, lf.version)
        base = dict(
            ecosystem=lf.ecosystem,
            package=lf.package,
            advisory_id=lf.advisory.id,
            aliases=lf.advisory.aliases,
            version_before=lf.version,
            version_after=rv,
            severity_before=lf.advisory.severity.level.value,
            fingerprint_before=lf.fingerprint,
        )
        if rv is None and rcid is None:
            cls, cause, why = (
                "resolved",
                "dependency_removed",
                "package is no longer in the dependency inventory",
            )
        elif not evaluated(rstate, rcid):
            cls, cause, why = (
                "unknown_due_to_data_gap",
                "right_not_evaluated",
                "the newer scan did not evaluate this package; it is NOT counted as resolved",
            )
        elif rv != lf.version:
            cls, cause, why = (
                "resolved",
                "version_change",
                f"package changed {lf.version} -> {rv}, outside the affected range",
            )
        elif source_changed:
            cls, cause, why = (
                "resolved",
                "advisory_database_update",
                "same version; the advisory no longer matches in the newer advisory data",
            )
        else:
            cls, cause, why = "resolved", "evaluation_difference", "same version and same advisory source"
        changes.append(
            FindingChange(classification=cast(FindingClass, cls), cause=cause, explanation=why, **base)
        )  # type: ignore[arg-type]

    order = {"introduced": 0, "reclassified": 1, "unknown_due_to_data_gap": 2, "resolved": 3, "persistent": 4}
    changes.sort(key=lambda c: (order[c.classification], c.package, c.advisory_id))
    counts = {k: 0 for k in order}
    for fc in changes:
        counts[fc.classification] += 1
    pcounts: dict[str, int] = {}
    for p in pkgs:
        pcounts[p.change] = pcounts.get(p.change, 0) + 1
    return ScanComparison(
        left=_ref(left),
        right=_ref(right),
        packages=pkgs,
        findings=changes,
        counts=counts,
        package_counts=pcounts,
        coverage_delta={
            "left_percent_evaluated": left.coverage.percent_evaluated,
            "right_percent_evaluated": right.coverage.percent_evaluated,
            "not_evaluated_delta": right.coverage.not_evaluated - left.coverage.not_evaluated,
            "unsupported_delta": right.coverage.unsupported - left.coverage.unsupported,
            "error_delta": right.coverage.error - left.coverage.error,
        },
        advisory_source_changed=source_changed,
        notes=notes,
    )
