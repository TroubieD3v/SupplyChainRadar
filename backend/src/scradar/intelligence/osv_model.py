"""OSV record handling: canonical advisories, CVSS v3 base scores and affected-version matching."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Literal

from scradar import versions
from scradar.domain.models import Advisory, Reference, Severity, SeverityEvidence
from scradar.ingestion.common import normalize_pypi_name

# --- CVSS v3.x base score (FIRST specification, section 7) -----------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr_w = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}
        iss = 1 - (1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]]) * (1 - _W["CIA"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = (
            8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr_w[parts["PR"]] * _W["UI"][parts["UI"]]
        )
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return _roundup(raw)
    except (KeyError, ValueError):
        return None


def level_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "IMPORTANT": Severity.HIGH,
    "LOW": Severity.LOW,
}


def extract_severity(rec: dict[str, Any]) -> SeverityEvidence:
    """Severity exactly as the source states it. Nothing is invented when it is absent."""

    vector = vtype = None
    for s in rec.get("severity") or []:
        stype, score = s.get("type"), str(s.get("score", ""))
        if stype == "CVSS_V3" and score.startswith("CVSS:3"):
            computed = cvss3_base_score(score)
            if computed is not None:
                return SeverityEvidence(
                    level=level_from_score(computed),
                    score=computed,
                    vector=score,
                    vector_type="CVSS_V3",
                    source="CVSS v3 vector published in the advisory (base score computed from the vector)",
                )
        if vector is None and score:
            vector, vtype = score, stype
    label = None
    for holder in [
        rec.get("database_specific") or {},
        *[(a.get("database_specific") or {}) for a in rec.get("affected") or []],
    ]:
        raw = holder.get("severity") if isinstance(holder, dict) else None
        if isinstance(raw, str) and raw.upper() in _LABELS:
            label = raw.upper()
            break
    if label:
        return SeverityEvidence(
            level=_LABELS[label],
            vector=vector,
            vector_type=vtype,
            source=f"advisory database label '{label}'",
            note="no CVSS score available" if vector is None else "CVSS vector type not scored by this tool",
        )
    return SeverityEvidence(
        level=Severity.UNKNOWN,
        vector=vector,
        vector_type=vtype,
        source=None,
        note="severity not provided by source",
    )


def raw_hash(rec: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def to_advisory(rec: dict[str, Any], source: str = "osv", fixed: list[str] | None = None) -> Advisory:
    return Advisory(
        id=str(rec["id"]),
        aliases=sorted({str(a) for a in rec.get("aliases") or [] if a}),
        summary=rec.get("summary"),
        details=rec.get("details"),
        published=rec.get("published"),
        modified=rec.get("modified"),
        severity=extract_severity(rec),
        references=[
            Reference(type=r.get("type"), url=str(r["url"]))
            for r in rec.get("references") or []
            if r.get("url")
        ],
        fixed_versions=fixed or [],
        source=source,
        raw_hash=raw_hash(rec),
    )


# --- affected-version matching ----------------------------------------------------------------

MatchStatus = Literal["affected", "not_affected", "unsupported"]


def _pkg_matches(ecosystem: str, name: str, pkg: dict[str, Any]) -> bool:
    if str(pkg.get("ecosystem", "")).lower() != ecosystem.lower():
        return False
    other = str(pkg.get("name", ""))
    if ecosystem.lower() == "pypi":
        return normalize_pypi_name(other) == normalize_pypi_name(name)
    return other == name


def _event_key(ecosystem: str, ev: dict[str, Any]):
    kind = next(k for k in ("introduced", "fixed", "last_affected", "limit") if k in ev)
    ver = ev[kind]
    rank = 0 if kind == "introduced" else 1
    if ver == "0":
        return (0, None, rank)
    return (1, versions.parse(ecosystem, ver), rank)


def _in_range(ecosystem: str, version: str, events: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    v = versions.parse(ecosystem, version)
    ordered = sorted(events, key=lambda e: _event_key(ecosystem, e))
    affected = False
    fixed_after: list[str] = []
    for ev in ordered:
        if "introduced" in ev:
            if ev["introduced"] == "0" or v >= versions.parse(ecosystem, ev["introduced"]):
                affected = True
        elif "fixed" in ev:
            if v >= versions.parse(ecosystem, ev["fixed"]):
                affected = False
            elif affected:
                fixed_after.append(ev["fixed"])
        elif "last_affected" in ev:
            if v > versions.parse(ecosystem, ev["last_affected"]):
                affected = False
        elif "limit" in ev and v >= versions.parse(ecosystem, ev["limit"]):
            affected = False
    return affected, fixed_after


def affected_by(
    ecosystem: str, name: str, version: str, rec: dict[str, Any]
) -> tuple[MatchStatus, str, list[str]]:
    """Does ``rec`` apply to ecosystem/name@version? Returns (status, rationale, fixed versions)."""

    saw_pkg = False
    unsupported_note = None
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        if not _pkg_matches(ecosystem, name, pkg):
            continue
        saw_pkg = True
        if version in (aff.get("versions") or []):
            fixed = _fixed_of(ecosystem, version, aff)
            return (
                "affected",
                f"{name}@{version} is listed in the advisory's explicit affected versions",
                fixed,
            )
        for rng in aff.get("ranges") or []:
            rtype = rng.get("type")
            if rtype == "GIT":
                continue
            if not versions.comparable(ecosystem):
                unsupported_note = f"no version comparator for ecosystem {ecosystem}"
                continue
            try:
                hit, fixed = _in_range(ecosystem, version, rng.get("events") or [])
            except (versions.VersionError, StopIteration):
                unsupported_note = f"version {version!r} or range events could not be compared as {ecosystem}"
                continue
            if hit:
                bounds = ", ".join(_describe_events(rng.get("events") or []))
                return "affected", f"{name}@{version} falls in affected range [{bounds}]", sorted(set(fixed))
    if unsupported_note:
        return "unsupported", unsupported_note, []
    if not saw_pkg:
        return "not_affected", "advisory does not list this package", []
    return "not_affected", f"{name}@{version} is outside every affected range", []


def _fixed_of(ecosystem: str, version: str, aff: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if not versions.comparable(ecosystem):
        return out
    for rng in aff.get("ranges") or []:
        if rng.get("type") == "GIT":
            continue
        try:
            _, fixed = _in_range(ecosystem, version, rng.get("events") or [])
            out.extend(fixed)
        except (versions.VersionError, StopIteration):
            continue
    return sorted(set(out))


def _describe_events(events: list[dict[str, Any]]) -> list[str]:
    out = []
    for e in events:
        for k in ("introduced", "fixed", "last_affected", "limit"):
            if k in e:
                out.append(f"{k} {e[k]}")
    return out
