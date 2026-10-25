import json
from datetime import date

import pytest
from jsonschema import Draft7Validator

from scradar.comparison.diff import compare_scans
from scradar.domain.models import ROOT_ID, Component, Edge, QueryState, ScanResult
from scradar.graph.engine import DependencyGraph
from scradar.ingestion.detect import import_directory
from scradar.intelligence.osv_model import affected_by, cvss3_base_score
from scradar.intelligence.providers import FixtureProvider, NullProvider
from scradar.policy.engine import PolicyError, evaluate_policy, load_policy
from scradar.remediation.simulator import Operation, simulate_candidate, simulate_hypothetical
from scradar.reports.render import render
from scradar.service import analyze, group_matches

from .conftest import EXAMPLES, ROOT, scan_example


def comp(cid, **kw):
    name, _, ver = cid.partition("@")
    return Component(id=cid, ecosystem="npm", name=name, version=ver or None, **kw)


# ------------------------------------------------------------------ graph


def test_two_paths_and_removing_one_parent_keeps_the_other():
    comps = {
        c.id: c
        for c in [
            Component(id=ROOT_ID, kind="application", ecosystem="npm", name="app"),
            comp("fa@1"),
            comp("fb@1"),
            comp("v@1"),
        ]
    }
    edges = [
        Edge(parent=ROOT_ID, child="fa@1"),
        Edge(parent=ROOT_ID, child="fb@1"),
        Edge(parent="fa@1", child="v@1"),
        Edge(parent="fb@1", child="v@1"),
    ]
    g = DependencyGraph(comps, edges)
    s = g.paths_to("v@1")
    assert s.total_found == 2 and sorted(p.nodes[1] for p in s.paths) == ["fa@1", "fb@1"]
    assert g.introducers("v@1") == ["fa@1", "fb@1"]


def test_cycles_terminate_and_are_detected():
    comps = {
        c.id: c
        for c in [
            Component(id=ROOT_ID, kind="application", ecosystem="npm", name="app"),
            comp("a@1"),
            comp("b@1"),
            comp("c@1"),
        ]
    }
    edges = [
        Edge(parent=ROOT_ID, child="a@1"),
        Edge(parent="a@1", child="b@1"),
        Edge(parent="b@1", child="a@1"),
        Edge(parent="b@1", child="c@1"),
    ]
    g = DependencyGraph(comps, edges)
    assert g.analysis()["has_cycles"]
    assert g.paths_to("c@1").total_found == 1


def test_path_search_truncation_is_reported():
    comps = {ROOT_ID: Component(id=ROOT_ID, kind="application", ecosystem="npm", name="app")}
    edges = []
    for layer in range(8):
        for i in range(3):
            comps[f"n{layer}_{i}@1"] = comp(f"n{layer}_{i}@1")
    for i in range(3):
        edges.append(Edge(parent=ROOT_ID, child=f"n0_{i}@1"))
    for layer in range(7):
        for i in range(3):
            for j in range(3):
                edges.append(Edge(parent=f"n{layer}_{i}@1", child=f"n{layer + 1}_{j}@1"))
    s = DependencyGraph(comps, edges).paths_to("n7_0@1", max_paths=10)
    assert s.truncated and len(s.paths) == 10 and s.warning


def test_unconnected_inventory_is_not_a_path():
    comps = {
        ROOT_ID: Component(id=ROOT_ID, kind="application", ecosystem="npm", name="app"),
        "x@1": comp("x@1"),
    }
    s = DependencyGraph(comps, []).paths_to("x@1")
    assert not s.reachable_from_root and s.warning and not s.paths


def test_scopes_from_graph():
    sc = scan_example("npm-vulnerable", FixtureProvider(ROOT / "fixtures/osv/frozen-advisories.json"))
    m = sc.component_map()
    assert m["npm:demo-glob@7.0.0"].scopes == ["dev"]
    assert m["npm:demo-vulnerable-lib@1.2.0"].scopes == ["runtime"]


# ------------------------------------------------------------------ matching


def rec(events, eco="npm", name="p", versions=None, rtype="SEMVER"):
    aff = {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": rtype, "events": events}]}
    if versions:
        aff["versions"] = versions
    return {"id": "X-1", "affected": [aff]}


@pytest.mark.parametrize(
    "version,events,expected",
    [
        ("1.0.0", [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}], "affected"),
        ("1.2.4", [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}], "affected"),
        ("1.2.5", [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}], "not_affected"),
        ("0.9.9", [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}], "not_affected"),
        ("5.0.0", [{"introduced": "0"}], "affected"),
        ("1.1.0", [{"introduced": "0"}, {"last_affected": "1.1.0"}], "affected"),
        ("1.1.1", [{"introduced": "0"}, {"last_affected": "1.1.0"}], "not_affected"),
        (
            "2.1.0",
            [{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}, {"fixed": "2.2.0"}],
            "affected",
        ),
        (
            "1.5.0",
            [{"introduced": "0"}, {"fixed": "1.0.0"}, {"introduced": "2.0.0"}, {"fixed": "2.2.0"}],
            "not_affected",
        ),
    ],
)
def test_semver_ranges(version, events, expected):
    assert affected_by("npm", "p", version, rec(events))[0] == expected


def test_pypi_ranges_use_pep440_and_normalised_names():
    r = rec([{"introduced": "0"}, {"fixed": "2.0.post1"}], eco="PyPI", name="My_Pkg", rtype="ECOSYSTEM")
    assert affected_by("PyPI", "my-pkg", "2.0", r)[0] == "affected"
    assert affected_by("PyPI", "my-pkg", "2.0.post1", r)[0] == "not_affected"


def test_wrong_package_and_unsupported_ecosystem():
    assert affected_by("npm", "other", "1.0.0", rec([{"introduced": "0"}]))[0] == "not_affected"
    r = rec([{"introduced": "0"}, {"fixed": "2"}], eco="Maven", name="g:a")
    assert affected_by("Maven", "g:a", "1", r)[0] == "unsupported"
    assert (
        affected_by("Maven", "g:a", "1", rec([{"introduced": "0"}], eco="Maven", name="g:a", versions=["1"]))[
            0
        ]
        == "affected"
    )


def test_cvss3_scores():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5
    assert cvss3_base_score("garbage") is None


# ------------------------------------------------------------------ findings


def test_alias_duplicates_produce_one_finding(snap1):
    sc = scan_example("npm-vulnerable", snap1)
    ids = [f.advisory.id for f in sc.findings if f.package == "demo-vulnerable-lib"]
    assert ids == ["DEMO-GHSA-0001"]
    f = next(f for f in sc.findings if f.package == "demo-vulnerable-lib")
    assert f.advisory.merged_ids == ["DEMO-OSV-0001"] and "DEMO-CVE-2026-0001" in f.advisory.aliases
    assert f.paths.total_found == 2 and f.advisory.fixed_versions == ["1.2.5"]


def test_group_matches_idempotent_and_union_find():
    from scradar.domain.models import MatchEvidence
    from scradar.intelligence.providers import Match

    ev = MatchEvidence(basis="local_range", rationale="r")
    a = Match({"id": "GHSA-1", "aliases": ["CVE-1"]}, ev)
    b = Match({"id": "OSV-2", "aliases": ["CVE-1", "CVE-2"]}, ev)
    c = Match({"id": "GHSA-3", "aliases": ["CVE-2"]}, ev)
    d = Match({"id": "GHSA-9", "aliases": []}, ev)
    groups = group_matches([a, b, c, d])
    assert sorted(len(g) for g in groups) == [1, 3]
    assert sorted(len(g) for g in group_matches([d, c, b, a])) == [1, 3]


def test_unknown_severity_is_not_invented_or_scored(snap1):
    sc = scan_example("requirements-partial", snap1)
    f = next(f for f in sc.findings if f.package == "demo-flask")
    assert f.advisory.severity.level.value == "unknown" and f.priority.score is None
    assert f.priority.confidence < 1


def test_negative_control_has_no_findings_and_full_coverage(snap1):
    sc = scan_example("npm-clean", snap1)
    assert sc.findings == [] and sc.coverage.fully_covered and sc.coverage.percent_evaluated == 100


def test_partial_requirements_never_look_clean(snap1):
    sc = scan_example("requirements-partial", snap1)
    c = sc.coverage
    assert not c.fully_covered and not c.graph_complete and c.unresolved == 3
    states = {e.component_id: e.state for e in sc.evaluations}
    assert states["PyPI:demo-numpy@unresolved"] == QueryState.UNSUPPORTED


def test_offline_without_data_is_not_evaluated():
    sc = scan_example("npm-vulnerable", NullProvider())
    assert sc.findings == [] and sc.coverage.not_evaluated == 9 and sc.coverage.percent_evaluated == 0
    assert all(e.state == QueryState.NOT_EVALUATED for e in sc.evaluations)


def test_deterministic_checksum(snap1):
    a, b = scan_example("npm-vulnerable", snap1), scan_example("npm-vulnerable", snap1)
    assert a.checksum == b.checksum
    assert [f.fingerprint for f in a.findings] == [f.fingerprint for f in b.findings]


def test_recorded_expected_findings(snap1):
    for name in ("npm-vulnerable", "npm-remediated"):
        sc = scan_example(name, snap1)
        got = sorted(
            (f.package, f.version, f.advisory.id, f.advisory.severity.level.value) for f in sc.findings
        )
        exp = json.loads((ROOT / "fixtures" / "expected" / f"{name}-findings.json").read_text())
        assert got == [tuple(x) for x in exp["findings"]]


# ------------------------------------------------------------------ comparison


def test_remediation_diff_classification(snap1):
    before, after = scan_example("npm-vulnerable", snap1), scan_example("npm-remediated", snap1)
    cmp = compare_scans(before, after)
    by = {(c.package, c.classification): c for c in cmp.findings}
    assert by[("demo-vulnerable-lib", "resolved")].cause == "version_change"
    assert by[("demo-newdep", "introduced")].cause == "new_dependency"
    assert ("demo-glob", "persistent") in by


def test_advisory_update_only_is_not_a_dependency_change(snap1, snap2):
    a, b = scan_example("npm-vulnerable", snap1), scan_example("npm-vulnerable", snap2)
    cmp = compare_scans(a, b)
    assert cmp.packages == [] and cmp.advisory_source_changed
    intro = [c for c in cmp.findings if c.classification == "introduced"]
    assert [(c.package, c.cause) for c in intro] == [("demo-http", "advisory_database_update")]
    recl = [c for c in cmp.findings if c.classification == "reclassified"]
    assert [(c.package, c.severity_before, c.severity_after) for c in recl] == [
        ("demo-parser", "medium", "high")
    ]


def test_coverage_loss_is_not_reported_as_resolved(snap1):
    full = scan_example("npm-vulnerable", snap1)
    blind = scan_example("npm-vulnerable", NullProvider())
    cmp = compare_scans(full, blind)
    assert cmp.counts["resolved"] == 0 and cmp.counts["unknown_due_to_data_gap"] == 3
    reverse = compare_scans(blind, full)
    assert reverse.counts["introduced"] == 0 and reverse.counts["unknown_due_to_data_gap"] == 3


# ------------------------------------------------------------------ remediation


def test_candidate_lockfile_is_authoritative(snap1):
    base = scan_example("npm-vulnerable", snap1)
    inv = import_directory(EXAMPLES / "npm-remediated").inventories
    out, cand = simulate_candidate(base, inv, snap1)
    assert out.status == "confirmed_by_candidate_scan" and out.full_reresolution
    assert {r.package for r in out.advisories_removed} == {"demo-vulnerable-lib", "demo-parser"}
    assert [r.package for r in out.newly_introduced] == ["demo-newdep"]
    assert cand.scan_id != base.scan_id


def test_hypothetical_set_version_is_never_full_resolution(snap1):
    base = scan_example("npm-vulnerable", snap1)
    out, _ = simulate_hypothetical(
        base, [Operation(op="set_version", component="demo-vulnerable-lib", version="1.2.5")], snap1
    )
    assert out.status == "predicted_partial" and not out.full_reresolution
    assert [r.package for r in out.advisories_removed] == ["demo-vulnerable-lib"]
    assert out.unresolved_constraints == []  # ^1.2.0 is satisfied by 1.2.5
    assert all(e.full_reresolution is False for e in out.evidence)


def test_hypothetical_version_without_data_is_unknown_not_safe():
    base = scan_example("npm-vulnerable", FixtureProvider(ROOT / "fixtures/osv/frozen-advisories.json"))
    out, _ = simulate_hypothetical(
        base, [Operation(op="set_version", component="demo-parser", version="9.9.9")], NullProvider()
    )
    assert out.status == "unknown"


def test_removing_one_parent_keeps_shared_vulnerable_package(snap1):
    sc = scan_example("npm-vulnerable", snap1)
    out, cand = simulate_hypothetical(sc, [Operation(op="remove", component="demo-framework-a")], snap1)
    assert out.advisories_removed == [] and any(
        r.package == "demo-vulnerable-lib" for r in out.advisories_remaining
    )
    assert "npm:demo-vulnerable-lib@1.2.0" in cand.component_map()
    out2, _ = simulate_hypothetical(
        sc,
        [
            Operation(op="remove", component="demo-framework-a"),
            Operation(op="remove", component="demo-framework-b"),
        ],
        snap1,
    )
    assert [r.package for r in out2.advisories_removed] == ["demo-vulnerable-lib"]


def test_cannot_remove_transitive_dependency_directly(snap1):
    sc = scan_example("npm-vulnerable", snap1)
    out, _ = simulate_hypothetical(sc, [Operation(op="remove", component="demo-vulnerable-lib")], snap1)
    assert out.status == "blocked" and out.blocked_reason


# ------------------------------------------------------------------ policy


def test_policy_gate_on_new_critical(snap1):
    before, after = scan_example("npm-vulnerable", snap1), scan_example("npm-remediated", snap1)
    pol = load_policy((EXAMPLES / "policy-strict.yaml").read_text())
    res = evaluate_policy(pol, after, baseline=before, today=date(2026, 10, 25))
    assert res.outcome == "fail" and res.exit_code == 1
    assert [v.advisory_id for v in res.violations] == ["DEMO-GHSA-0004"]
    assert [s.advisory_id for s in res.suppressed] == ["DEMO-GHSA-0003"]
    ok = evaluate_policy(pol, before, baseline=before, today=date(2026, 10, 25))
    assert ok.exit_code == 0


def test_policy_requires_baseline_for_new_rules(snap1):
    pol = load_policy((EXAMPLES / "policy-strict.yaml").read_text())
    with pytest.raises(PolicyError, match="baseline"):
        evaluate_policy(pol, scan_example("npm-vulnerable", snap1))


def test_expired_exception_fails_and_reactivates_finding(snap1):
    pol = load_policy((EXAMPLES / "policy-strict.yaml").read_text())
    sc = scan_example("npm-vulnerable", snap1)
    res = evaluate_policy(pol, sc, baseline=sc, today=date(2028, 1, 1))
    assert any(v.rule_id == "expired-exception" for v in res.violations)
    assert res.expired_exceptions and not res.suppressed


def test_unknown_severity_is_not_below_threshold(snap1):
    pol = load_policy(
        "schema_version: 1\nname: t\nrules:\n  - {id: r, when: confirmed_advisory, min_severity: low, action: fail}\nunknown_data: {mode: warn}\n"
    )
    res = evaluate_policy(pol, scan_example("requirements-partial", snap1))
    assert res.unknown_data["unknown_severity"] == 1
    assert [v.package for v in res.violations] == [
        "demo-crypto"
    ]  # low advisory only; unknown one is surfaced, not dropped
    assert res.outcome == "fail"


def test_unknown_data_fail_mode_is_inconclusive_exit_4():
    pol = load_policy("schema_version: 1\nname: t\nrules: []\nunknown_data: {mode: fail}\n")
    res = evaluate_policy(pol, scan_example("npm-vulnerable", NullProvider()))
    assert res.outcome == "inconclusive" and res.exit_code == 4


def test_policy_validation_errors():
    with pytest.raises(PolicyError):
        load_policy("name: x\nrules: [{id: a, when: nonsense}]")
    with pytest.raises(PolicyError):
        load_policy("- not a mapping")


# ------------------------------------------------------------------ reports


def _sarif_validator():
    schema = json.loads((ROOT / "backend/src/scradar/schemas/sarif-schema-2.1.0.json").read_text())
    return Draft7Validator(schema)


def test_sarif_validates_against_official_schema(snap1):
    sc = scan_example("npm-vulnerable", snap1)
    doc = json.loads(render(sc, "sarif", path_prefix="examples/npm-vulnerable"))
    errors = list(_sarif_validator().iter_errors(doc))
    assert not errors, errors[:3]
    r = doc["runs"][0]["results"][0]
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "examples/npm-vulnerable/"
    )
    assert r["partialFingerprints"]["scradarFinding/v1"]
    empty = json.loads(render(scan_example("npm-clean", snap1), "sarif"))
    assert not list(_sarif_validator().iter_errors(empty))


@pytest.mark.parametrize(
    "example", ["npm-vulnerable", "pnpm-monorepo", "requirements-partial", "poetry-vulnerable"]
)
def test_cyclonedx_export_validates_against_1_7_schema(snap1, example):
    from scradar.ingestion.cyclonedx import _validator

    doc = json.loads(render(scan_example(example, snap1), "cyclonedx"))
    errors = list(_validator("1.7").iter_errors(doc))
    assert not errors, errors[:3]


def test_cyclonedx_export_round_trips_through_importer(snap1):
    from scradar.ingestion.cyclonedx import parse_cyclonedx

    sc = scan_example("npm-vulnerable", snap1)
    inv = parse_cyclonedx(render(sc, "cyclonedx").encode())
    assert len([c for c in inv.components.values() if c.kind == "package"]) == sc.coverage.total_packages
    assert inv.graph_complete


def test_reports_share_facts_and_escape_html(snap1):
    sc = scan_example("npm-vulnerable", snap1)
    sc.findings[
        0
    ].advisory.summary = "<script>alert(1)</script> token ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    sc.findings[0].advisory.references[0].url = "https://example.invalid/a?x='><img src=x onerror=alert(1)>"
    html_ = render(sc, "html")
    md = render(sc, "markdown")
    js = render(sc, "json")
    assert "<script>alert" not in html_ and "&lt;script&gt;" in html_ and "<img src=x" not in html_
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in html_ + md
    assert "<script>" not in md.replace("\\<script\\>", "")
    for f in sc.findings:
        assert f.advisory.id in html_ and f.advisory.id in md and f.advisory.id in js
    assert "Demo data" not in html_  # only when flagged
    sc.demo = True
    assert "Demo data" in render(sc, "html") and "Demo data" in render(sc, "markdown")


def test_scan_json_round_trips(snap1):
    sc = scan_example("npm-vulnerable", snap1)
    again = ScanResult.model_validate_json(render(sc, "json"))
    assert again.checksum == sc.checksum and len(again.findings) == len(sc.findings)
    assert analyze(import_directory(EXAMPLES / "npm-vulnerable").inventories, snap1).checksum == sc.checksum


def test_hypothetical_major_bump_reports_parent_constraint_conflicts(snap1):
    base = scan_example("npm-vulnerable", snap1)
    out, _ = simulate_hypothetical(
        base, [Operation(op="set_version", component="demo-vulnerable-lib", version="2.0.0")], snap1
    )
    assert (
        len(out.unresolved_constraints) == 2 and "would also need to change" in out.unresolved_constraints[0]
    )


def test_deep_shared_graph_still_returns_shortest_paths_quickly():
    """Regression: breadth-first enumeration of all simple paths exploded on layered shared graphs."""
    import time

    layers, width = 40, 4
    comps = {ROOT_ID: Component(id=ROOT_ID, kind="application", ecosystem="npm", name="app")}
    edges = [Edge(parent=ROOT_ID, child=f"l0_{i}@1") for i in range(width)]
    for layer in range(layers):
        for i in range(width):
            cid = f"l{layer}_{i}@1"
            comps[cid] = Component(id=cid, ecosystem="npm", name=cid, version="1")
            if layer + 1 < layers:
                edges += [Edge(parent=cid, child=f"l{layer + 1}_{j}@1") for j in range(width)]
    start = time.monotonic()
    s = DependencyGraph(comps, edges).paths_to(f"l{layers - 1}_0@1", max_paths=20)
    assert time.monotonic() - start < 2
    assert len(s.paths) == 20 and all(len(p.nodes) == layers + 1 for p in s.paths)
    assert s.truncated and s.warning
