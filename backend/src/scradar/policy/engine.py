"""Policy-as-code: YAML rules evaluated against a scan (and optionally a baseline scan).

Unknown severity is never treated as "below threshold"; it is reported as unknown data and
handled by ``unknown_data.mode``. Rules about *new* findings require a baseline.
"""

from __future__ import annotations

import fnmatch
from datetime import UTC, date, datetime
from typing import Literal

import yaml
from pydantic import Field, ValidationError, field_validator

from scradar.comparison.diff import compare_scans
from scradar.domain.models import EVALUATED_STATES, Finding, Model, QueryState, ScanResult, Severity

EXIT_PASS, EXIT_GATE_FAILED, EXIT_USAGE, EXIT_PROVIDER, EXIT_INCONCLUSIVE = 0, 1, 2, 3, 4

SUPPRESSING = {"accepted_risk", "false_positive", "not_affected"}
_SEV_ORDER = ["low", "medium", "high", "critical"]


class PolicyError(ValueError):
    pass


class Rule(Model):
    id: str
    when: Literal[
        "confirmed_advisory",
        "newly_introduced_confirmed_advisory",
        "exception_expired",
        "unresolved_dependency",
        "license_denied",
    ]
    min_severity: Literal["low", "medium", "high", "critical"] | None = None
    dependency_scope: Literal["runtime", "dev", "optional", "any"] = "any"
    direct_only: bool = False
    action: Literal["fail", "warn"] = "fail"
    description: str | None = None


class UnknownData(Model):
    mode: Literal["ignore", "warn", "fail"] = "warn"


class Licenses(Model):
    deny: list[str] = Field(default_factory=list)
    review: list[str] = Field(default_factory=list)


class ExceptionEntry(Model):
    fingerprint: str | None = None
    advisory: str | None = None
    package: str | None = None
    status: Literal["accepted_risk", "false_positive", "not_affected", "needs_review", "open"]
    rationale: str
    expires: date | None = None
    author: str | None = None
    evidence: str | None = None

    @field_validator("rationale")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("rationale is required")
        return v

    def matches(self, f: Finding) -> bool:
        if self.fingerprint:
            return self.fingerprint == f.fingerprint
        if self.advisory and self.advisory not in {f.advisory.id, *f.advisory.aliases}:
            return False
        if self.package and self.package != f.package:
            return False
        return bool(self.advisory or self.package)


class Policy(Model):
    schema_version: Literal[1] = 1
    name: str
    description: str | None = None
    baseline_fallback: Literal["error", "treat_all_as_new"] = "error"
    rules: list[Rule] = Field(default_factory=list)
    unknown_data: UnknownData = Field(default_factory=UnknownData)
    licenses: Licenses = Field(default_factory=Licenses)
    exceptions: list[ExceptionEntry] = Field(default_factory=list)


class Violation(Model):
    rule_id: str
    action: Literal["fail", "warn"]
    kind: str
    message: str
    fingerprint: str | None = None
    package: str | None = None
    version: str | None = None
    advisory_id: str | None = None
    severity: str | None = None


class SuppressedFinding(Model):
    fingerprint: str
    advisory_id: str
    package: str
    status: str
    rationale: str
    expires: str | None
    author: str | None


class PolicyResult(Model):
    policy: str
    outcome: Literal["pass", "warn", "fail", "inconclusive"]
    exit_code: int
    evaluated_at: str
    baseline_used: bool
    violations: list[Violation]
    warnings: list[Violation]
    suppressed: list[SuppressedFinding]
    expired_exceptions: list[SuppressedFinding]
    unknown_data: dict[str, int]
    notes: list[str]


def load_policy(text: str) -> Policy:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a YAML mapping")
    try:
        return Policy.model_validate(doc)
    except ValidationError as exc:
        raise PolicyError(
            "invalid policy: "
            + "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:8])
        ) from exc


def _scope_ok(rule: Rule, f: Finding) -> bool:
    return rule.dependency_scope == "any" or rule.dependency_scope in f.scopes


def _sev_ok(rule: Rule, f: Finding) -> bool | None:
    """True/False when severity is known; None when it is unknown."""

    if rule.min_severity is None:
        return True
    lvl = f.advisory.severity.level
    if lvl == Severity.UNKNOWN:
        return None
    return _SEV_ORDER.index(lvl.value) >= _SEV_ORDER.index(rule.min_severity)


def evaluate_policy(
    policy: Policy,
    scan: ScanResult,
    *,
    baseline: ScanResult | None = None,
    extra_exceptions: list[ExceptionEntry] | None = None,
    today: date | None = None,
) -> PolicyResult:
    today = today or datetime.now(UTC).date()
    notes: list[str] = []
    exceptions = [*policy.exceptions, *(extra_exceptions or [])]
    violations: list[Violation] = []
    warnings: list[Violation] = []
    suppressed: list[SuppressedFinding] = []
    expired: list[SuppressedFinding] = []
    unknown_sev: set[str] = set()

    active: list[Finding] = []
    for f in scan.findings:
        exc = next((e for e in exceptions if e.matches(f)), None)
        if exc and exc.status in SUPPRESSING:
            entry = SuppressedFinding(
                fingerprint=f.fingerprint,
                advisory_id=f.advisory.id,
                package=f.package,
                status=exc.status,
                rationale=exc.rationale,
                expires=exc.expires.isoformat() if exc.expires else None,
                author=exc.author,
            )
            if exc.expires is None:
                notes.append(f"exception for {f.advisory.id} on {f.package} has no expiry and is not applied")
                active.append(f)
            elif exc.expires < today:
                expired.append(entry)
                active.append(f)
            else:
                suppressed.append(entry)
            continue
        active.append(f)

    new_fps: set[str] | None = None
    needs_baseline = any(r.when == "newly_introduced_confirmed_advisory" for r in policy.rules)
    gap_count = 0
    if needs_baseline:
        if baseline is not None:
            cmp = compare_scans(baseline, scan)
            new_fps = {
                c.fingerprint_after
                for c in cmp.findings
                if c.classification == "introduced" and c.fingerprint_after
            }
            gap_count = sum(1 for c in cmp.findings if c.classification == "unknown_due_to_data_gap")
        elif policy.baseline_fallback == "treat_all_as_new":
            new_fps = {f.fingerprint for f in scan.findings}
            notes.append(
                "no baseline supplied: every finding is treated as new (baseline_fallback: treat_all_as_new)"
            )
        else:
            raise PolicyError(
                "policy uses 'newly_introduced_confirmed_advisory' but no baseline scan was supplied "
                "(pass --baseline, or set baseline_fallback: treat_all_as_new)"
            )

    def emit(rule: Rule, kind: str, msg: str, f: Finding | None = None, **kw) -> None:  # type: ignore[no-untyped-def]
        v = Violation(
            rule_id=rule.id,
            action=rule.action,
            kind=kind,
            message=msg,
            fingerprint=f.fingerprint if f else None,
            package=f.package if f else kw.get("package"),
            version=f.version if f else kw.get("version"),
            advisory_id=f.advisory.id if f else None,
            severity=f.advisory.severity.level.value if f else None,
        )
        (violations if rule.action == "fail" else warnings).append(v)

    for rule in policy.rules:
        if rule.when in {"confirmed_advisory", "newly_introduced_confirmed_advisory"}:
            for f in active:
                if rule.when == "newly_introduced_confirmed_advisory" and (
                    new_fps is None or f.fingerprint not in new_fps
                ):
                    continue
                if not _scope_ok(rule, f) or (rule.direct_only and not f.direct):
                    continue
                ok = _sev_ok(rule, f)
                if ok is None:
                    unknown_sev.add(f.fingerprint)
                    continue
                if ok:
                    label = "new " if rule.when.startswith("newly") else ""
                    emit(
                        rule,
                        rule.when,
                        f"{label}{f.advisory.severity.level.value} advisory {f.advisory.id} in {f.package}@{f.version}",
                        f,
                    )
        elif rule.when == "exception_expired":
            for e in expired:
                emit(
                    rule,
                    "exception_expired",
                    f"exception for {e.advisory_id} on {e.package} expired on {e.expires}",
                    package=e.package,
                )
        elif rule.when == "unresolved_dependency":
            for c in scan.components:
                if (
                    c.kind == "package"
                    and not c.resolved
                    and (rule.dependency_scope == "any" or rule.dependency_scope in c.scopes)
                ):
                    emit(
                        rule,
                        "unresolved_dependency",
                        f"{c.ecosystem}/{c.name} is not resolved to an exact version ({c.declared or 'no constraint'})",
                        package=c.name,
                    )
        elif rule.when == "license_denied":
            for c in scan.components:
                for lic in c.licenses:
                    if any(fnmatch.fnmatch(lic, pat) for pat in policy.licenses.deny):
                        emit(
                            rule,
                            "license_denied",
                            f"{c.name}@{c.version} declares license '{lic}' (denied by policy)",
                            package=c.name,
                            version=c.version,
                        )
    for c in scan.components:
        for lic in c.licenses:
            if any(fnmatch.fnmatch(lic, pat) for pat in policy.licenses.review):
                notes.append(
                    f"license review: {c.name}@{c.version} declares '{lic}' (informational, not legal advice)"
                )

    states = [e.state for e in scan.evaluations]
    unknown = {
        "not_evaluated": sum(1 for s in states if s == QueryState.NOT_EVALUATED),
        "unsupported": sum(1 for s in states if s == QueryState.UNSUPPORTED),
        "error": sum(1 for s in states if s == QueryState.ERROR),
        "unresolved": sum(1 for c in scan.components if c.kind == "package" and not c.resolved),
        "unknown_severity": len(unknown_sev),
        "baseline_data_gaps": gap_count,
    }
    has_unknown = any(unknown.values()) or not scan.coverage.graph_complete
    if has_unknown and policy.unknown_data.mode != "ignore":
        msg = (
            "incomplete data: "
            + ", ".join(f"{k}={v}" for k, v in unknown.items() if v)
            + ("" if scan.coverage.graph_complete else ", dependency graph incomplete")
        )
        notes.append(msg)
    evaluated_any = any(s in EVALUATED_STATES for s in states)
    if scan.coverage.total_packages and not evaluated_any:
        notes.append(
            "no package was evaluated against advisory data; a pass here would not mean 'no vulnerabilities'"
        )

    if violations:
        outcome, code = "fail", EXIT_GATE_FAILED
    elif has_unknown and policy.unknown_data.mode == "fail":
        outcome, code = "inconclusive", EXIT_INCONCLUSIVE
    elif warnings or (has_unknown and policy.unknown_data.mode == "warn"):
        outcome, code = "warn", EXIT_PASS
    else:
        outcome, code = "pass", EXIT_PASS
    return PolicyResult(
        policy=policy.name,
        outcome=outcome,  # type: ignore[arg-type]
        exit_code=code,
        evaluated_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        baseline_used=baseline is not None,
        violations=violations,
        warnings=warnings,
        suppressed=suppressed,
        expired_exceptions=expired,
        unknown_data=unknown,
        notes=notes,
    )


DEFAULT_POLICY = """schema_version: 1
name: default
description: Warn on high/critical runtime advisories; surface unknown data.
rules:
  - id: critical-any
    when: confirmed_advisory
    min_severity: critical
    action: fail
  - id: high-runtime
    when: confirmed_advisory
    min_severity: high
    dependency_scope: runtime
    action: warn
  - id: expired-exception
    when: exception_expired
    action: fail
unknown_data:
  mode: warn
"""
