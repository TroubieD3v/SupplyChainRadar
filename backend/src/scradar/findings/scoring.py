"""Transparent 0-100 prioritisation score. See docs/scoring-methodology.md.

The score is a weighted mean over the factors that are actually *known*. Unknown factors are
excluded (not treated as zero) and reported through ``confidence``. When the advisory severity
itself is unknown the finding is left unscored rather than ranked on exposure alone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from scradar.domain.models import PathSummary, PriorityScore, ScoreFactor, Severity, SeverityEvidence

DEFAULT_WEIGHTS = {
    "severity": 50.0,
    "known_exploited": 25.0,
    "exposure": 15.0,
    "scope": 10.0,
    "breadth": 5.0,
    "business_criticality": 10.0,
}

_LEVEL_VALUE = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
}


@dataclass
class KevData:
    cves: set[str] = field(default_factory=set)
    released: str | None = None


def load_kev(path: str | Path) -> KevData:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return KevData(
        {v["cveID"] for v in doc.get("vulnerabilities", []) if v.get("cveID")}, doc.get("dateReleased")
    )


def score_finding(
    *,
    severity: SeverityEvidence,
    aliases: list[str],
    paths: PathSummary,
    direct: bool,
    scopes: list[str],
    kev: KevData | None = None,
    criticality: float | None = None,
    weights: dict[str, float] | None = None,
) -> PriorityScore:
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    factors: list[ScoreFactor] = []

    # severity
    if severity.level == Severity.UNKNOWN:
        sev_val, sev_ev = None, "advisory source provided no severity"
    elif severity.score is not None:
        sev_val, sev_ev = severity.score / 10.0, f"CVSS base score {severity.score} ({severity.source})"
    else:
        sev_val, sev_ev = _LEVEL_VALUE[severity.level], f"{severity.level.value} ({severity.source})"
    factors.append(ScoreFactor(name="severity", weight=w["severity"], value=sev_val, evidence=sev_ev))

    # known exploitation (only from a supplied, dated KEV snapshot)
    if kev is None:
        factors.append(
            ScoreFactor(
                name="known_exploited",
                weight=w["known_exploited"],
                value=None,
                evidence="no KEV snapshot supplied",
            )
        )
    else:
        hit = sorted(a for a in aliases if a in kev.cves)
        factors.append(
            ScoreFactor(
                name="known_exploited",
                weight=w["known_exploited"],
                value=1.0 if hit else 0.0,
                evidence=(
                    f"listed in CISA KEV ({', '.join(hit)})"
                    if hit
                    else "not listed in the supplied KEV snapshot"
                )
                + (f" dated {kev.released}" if kev.released else ""),
            )
        )

    # exposure by dependency distance
    if paths.paths:
        depth = min(len(p.nodes) - 1 for p in paths.paths)
        val = 1.0 if direct else {2: 0.7, 3: 0.5}.get(depth, 0.35)
        factors.append(
            ScoreFactor(
                name="exposure",
                weight=w["exposure"],
                value=val,
                evidence=f"shortest path has {depth} hop(s)" + ("; direct dependency" if direct else ""),
            )
        )
    else:
        factors.append(
            ScoreFactor(
                name="exposure",
                weight=w["exposure"],
                value=None,
                evidence="no dependency path from the application is known",
            )
        )

    # scope
    scope_val = {"runtime": 1.0, "optional": 0.5, "dev": 0.25}.get(scopes[0] if scopes else "unknown")
    factors.append(
        ScoreFactor(
            name="scope",
            weight=w["scope"],
            value=scope_val,
            evidence=f"scope: {scopes[0] if scopes else 'unknown'}",
        )
    )

    # breadth: number of distinct routes by which the package enters the project
    if paths.paths:
        n = paths.total_found
        factors.append(
            ScoreFactor(
                name="breadth",
                weight=w["breadth"],
                value=0.2 if n <= 1 else (0.6 if n < 5 else 1.0),
                evidence=f"{n}{'+' if paths.truncated else ''} dependency path(s) found",
            )
        )
    else:
        factors.append(
            ScoreFactor(
                name="breadth", weight=w["breadth"], value=None, evidence="no dependency path is known"
            )
        )

    factors.append(
        ScoreFactor(
            name="business_criticality",
            weight=w["business_criticality"],
            value=criticality,
            evidence="user-supplied criticality" if criticality is not None else "not provided",
        )
    )

    known = [f for f in factors if f.value is not None]
    total_w = sum(f.weight for f in factors)
    known_w = sum(f.weight for f in known)
    confidence = round(known_w / total_w, 3) if total_w else 0.0
    if sev_val is None or not known_w:
        return PriorityScore(score=None, confidence=confidence, factors=factors)
    score = 100.0 * sum(f.weight * f.value for f in known if f.value is not None) / known_w
    return PriorityScore(score=round(score, 1), confidence=confidence, factors=factors)
