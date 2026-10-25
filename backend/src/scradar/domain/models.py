"""Typed domain models shared by the CLI, API, reports and web UI."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCAN_SCHEMA_VERSION = "1.0"

ROOT_ID = "root"


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class DepType(StrEnum):
    RUNTIME = "runtime"
    DEV = "dev"
    OPTIONAL = "optional"
    PEER = "peer"
    WORKSPACE = "workspace"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}[self.value]


class QueryState(StrEnum):
    """What we actually know about advisories for one component."""

    EVALUATED = "evaluated"
    CACHED = "cached"
    NOT_EVALUATED = "not_evaluated"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


EVALUATED_STATES = {QueryState.EVALUATED, QueryState.CACHED}


class Location(Model):
    file: str
    line: int | None = None
    detail: str | None = None  # e.g. node_modules path inside a lockfile


class Component(Model):
    id: str
    kind: Literal["application", "package"] = "package"
    ecosystem: str
    name: str
    version: str | None = None
    purl: str | None = None
    declared: str | None = None  # manifest constraint, kept separate from the resolved version
    resolved: bool = True
    direct: bool = False
    scopes: list[str] = Field(default_factory=list)  # runtime/dev/optional derived from the graph
    dep_types: list[DepType] = Field(default_factory=list)
    licenses: list[str] = Field(default_factory=list)
    source: str | None = None  # registry | git | file | url | workspace | unknown
    repository: str | None = None  # declared VCS coordinate, never guessed from the name
    integrity: str | None = None
    locations: list[Location] = Field(default_factory=list)
    unsupported_reason: str | None = None
    notes: list[str] = Field(default_factory=list)


class Edge(Model):
    parent: str
    child: str
    type: DepType = DepType.RUNTIME
    constraint: str | None = None
    provenance: Location | None = None
    confidence: Literal["declared", "inferred"] = "declared"


class Inventory(Model):
    """Normalised output of one import (or a merge of several)."""

    format: str
    parser: str
    parser_version: str
    format_version: str | None = None
    source_label: str
    checksum: str
    components: dict[str, Component] = Field(default_factory=dict)
    edges: list[Edge] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    graph_complete: bool = True
    graph_note: str | None = None
    coverage: Literal["full", "partial", "unknown"] = "full"
    coverage_notes: list[str] = Field(default_factory=list)


class ArtifactInfo(Model):
    format: str
    format_version: str | None
    parser: str
    parser_version: str
    source_label: str
    checksum: str
    components: int
    edges: int
    graph_complete: bool
    graph_note: str | None = None
    coverage: str
    warnings: list[str] = Field(default_factory=list)


# --- advisories & findings ------------------------------------------------------------------


class SeverityEvidence(Model):
    level: Severity = Severity.UNKNOWN
    score: float | None = None
    vector: str | None = None
    vector_type: str | None = None
    source: str | None = None  # where the level came from, never fabricated
    note: str | None = None


class Reference(Model):
    type: str | None = None
    url: str


class Advisory(Model):
    id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str | None = None
    details: str | None = None
    published: str | None = None
    modified: str | None = None
    severity: SeverityEvidence = Field(default_factory=SeverityEvidence)
    references: list[Reference] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    merged_ids: list[str] = Field(default_factory=list)
    source: str = "osv"
    raw_hash: str | None = None


class MatchEvidence(Model):
    basis: Literal["osv_query", "local_range", "explicit_version"]
    rationale: str
    local_verification: Literal["confirmed", "disagrees", "unavailable", "not_applicable"] = "not_applicable"


class DependencyPath(Model):
    nodes: list[str]  # component ids from the application root to the affected component
    edge_types: list[str] = Field(default_factory=list)
    inferred: bool = False  # True when any edge on the path is an inferred (not declared) relation


class PathSummary(Model):
    paths: list[DependencyPath] = Field(default_factory=list)
    total_found: int = 0
    truncated: bool = False
    introducers: list[str] = Field(default_factory=list)  # direct dependencies that lead here
    reachable_from_root: bool = True
    warning: str | None = None


class ScoreFactor(Model):
    name: str
    weight: float
    value: float | None  # None == unknown, excluded from the weighted mean
    evidence: str


class PriorityScore(Model):
    score: float | None
    confidence: float  # share of total weight backed by known factors
    factors: list[ScoreFactor]
    note: str = "Presence of a dependency does not prove reachability or exploitability."


class Finding(Model):
    fingerprint: str
    component_id: str
    ecosystem: str
    package: str
    version: str
    purl: str | None = None
    advisory: Advisory
    match: MatchEvidence
    paths: PathSummary
    direct: bool
    scopes: list[str]
    priority: PriorityScore
    source: str  # live | cache | offline_fixture
    fetched_at: str | None = None
    snapshot_id: str | None = None
    location: Location | None = None
    triage: dict[str, Any] | None = None


class ComponentEvaluation(Model):
    component_id: str
    state: QueryState
    source: str | None = None
    fetched_at: str | None = None
    note: str | None = None
    advisory_ids: list[str] = Field(default_factory=list)


class RiskSignal(Model):
    source: str
    component_id: str
    name: str
    value: float | str | None
    observed_at: str | None
    scope: str
    explanation: str
    confidence: str


class CoverageSummary(Model):
    total_packages: int
    evaluated: int
    cached: int
    not_evaluated: int
    unsupported: int
    error: int
    unresolved: int
    graph_complete: bool
    percent_evaluated: float
    notes: list[str] = Field(default_factory=list)

    @property
    def fully_covered(self) -> bool:
        return self.not_evaluated == 0 and self.unsupported == 0 and self.error == 0 and self.unresolved == 0


class AdvisorySourceInfo(Model):
    mode: Literal["live", "cached", "offline_fixture", "mixed", "none"]
    provider: str
    snapshot_id: str | None = None
    snapshot_generated: str | None = None
    fetched_at: str | None = None
    offline: bool = False
    notes: list[str] = Field(default_factory=list)


class ScanResult(Model):
    schema_version: str = SCAN_SCHEMA_VERSION
    engine_version: str
    scan_id: str
    project: str
    created_at: str
    demo: bool = False
    label: str | None = None
    checksum: str  # deterministic: excludes ids and timestamps
    artifacts: list[ArtifactInfo]
    components: list[Component]
    edges: list[Edge]
    evaluations: list[ComponentEvaluation]
    findings: list[Finding]
    risk_signals: list[RiskSignal] = Field(default_factory=list)
    coverage: CoverageSummary
    advisory_source: AdvisorySourceInfo
    warnings: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def component_map(self) -> dict[str, Component]:
        return {c.id: c for c in self.components}
