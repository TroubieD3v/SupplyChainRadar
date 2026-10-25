import json
import time
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from scradar.api.app import Config, create_app
from scradar.cli.main import app as cli

from .conftest import EXAMPLES, ROOT, SNAP1, SNAP2

H = {"X-Scradar-Request": "1"}
runner = CliRunner()


@pytest.fixture
def client(tmp_path):
    cfg = Config(
        database_url=f"sqlite:///{(tmp_path / 't.db').as_posix()}",
        cache_dir=tmp_path / "cache",
        repo_root=ROOT,
    )
    with TestClient(create_app(cfg)) as c:
        yield c


def wait(client, scan_id, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        s = client.get(f"/api/v1/scans/{scan_id}").json()
        if s["state"] in {"completed", "partial", "failed", "cancelled"}:
            return s
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def make_project(client, name="p"):
    return client.post("/api/v1/projects", json={"name": name}, headers=H).json()["id"]


def upload(client, pid, example, mode="fixture:frozen-advisories", fname="package-lock.json", label=None):
    data = (EXAMPLES / example / fname).read_bytes()
    r = client.post(
        f"/api/v1/projects/{pid}/imports",
        files={"files": (fname, data)},
        data={"enrichment": mode, **({"label": label} if label else {})},
        headers=H,
    )
    assert r.status_code == 202, r.text
    return wait(client, r.json()["id"])


# ------------------------------------------------------------------ API


def test_fresh_install_is_honestly_empty(client):
    ov = client.get("/api/v1/overview").json()
    assert (
        ov["projects"] == 0 and ov["scans"] == 0 and ov["totals"]["packages"] == 0 and not ov["has_demo_data"]
    )
    assert client.get("/api/v1/health").json() == {"status": "ok"}
    assert client.get("/api/v1/version").json()["api"] == "v1"


def test_mutations_require_csrf_header_and_optional_token(tmp_path):
    cfg = Config(
        database_url=f"sqlite:///{(tmp_path / 'a.db').as_posix()}",
        cache_dir=tmp_path,
        api_token="s3cret",
        repo_root=ROOT,
    )
    with TestClient(create_app(cfg)) as c:
        assert c.post("/api/v1/projects", json={"name": "x"}).status_code == 403
        assert c.post("/api/v1/projects", json={"name": "x"}, headers=H).status_code == 401
        ok = c.post("/api/v1/projects", json={"name": "x"}, headers={**H, "Authorization": "Bearer s3cret"})
        assert ok.status_code == 201
        assert c.get("/api/v1/projects").status_code == 200


def test_host_header_is_restricted(client):
    assert client.get("/api/v1/health", headers={"host": "evil.example.com"}).status_code == 400


def test_import_scan_findings_paths_and_reports(client):
    pid = make_project(client)
    scan = upload(client, pid, "npm-vulnerable")
    assert scan["state"] == "completed" and scan["summary"]["findings"] == 3 and scan["graph"]["has_cycles"]
    fs = client.get(f"/api/v1/scans/{scan['id']}/findings", params={"q": "vulnerable-lib"}).json()
    f = fs["items"][0]
    assert len(f["paths"]["paths"]) == 2 and f["path_labels"][0][0] == "demo-app"
    detail = client.get(f"/api/v1/findings/{f['id']}").json()
    assert detail["fix"]["candidate_versions"] == ["1.2.5"] and detail["names"]
    comps = client.get(f"/api/v1/scans/{scan['id']}/components", params={"vulnerable": True}).json()
    assert comps["total"] == 3
    cd = client.get(f"/api/v1/scans/{scan['id']}/components/npm:demo-vulnerable-lib@1.2.0").json()
    assert len(cd["parents"]) == 2 and cd["parents"][0]["provenance"]
    g = client.get(f"/api/v1/scans/{scan['id']}/graph").json()
    assert {n["id"] for n in g["nodes"]} >= {"root", "npm:demo-vulnerable-lib@1.2.0"}
    for fmt, needle in [
        ("json", "DEMO-GHSA-0001"),
        ("html", "DEMO-GHSA-0001"),
        ("markdown", "DEMO-GHSA-0001"),
        ("sarif", "DEMO-GHSA-0001"),
        ("cyclonedx", "demo-http"),
    ]:
        r = client.get(f"/api/v1/scans/{scan['id']}/reports", params={"format": fmt})
        assert r.status_code == 200 and needle in r.text
    assert client.get(f"/api/v1/scans/{scan['id']}/reports", params={"format": "pdf"}).status_code == 400


def test_offline_import_without_data_is_not_evaluated_and_partial(client):
    pid = make_project(client)
    scan = upload(client, pid, "npm-vulnerable", mode="osv_cache")
    assert scan["state"] == "partial"
    assert scan["summary"]["findings"] == 0 and scan["summary"]["coverage"]["not_evaluated"] == 9
    assert scan["summary"]["coverage"]["percent_evaluated"] == 0


def test_invalid_upload_fails_without_leaking(client):
    pid = make_project(client)
    r = client.post(
        f"/api/v1/projects/{pid}/imports",
        files={"files": ("package-lock.json", b"{ nope")},
        data={"enrichment": "osv_cache"},
        headers=H,
    )
    s = wait(client, r.json()["id"])
    assert s["state"] == "failed" and "invalid JSON" in s["error"]
    assert client.get(f"/api/v1/scans/{s['id']}/findings").status_code == 409


def test_compare_timeline_and_policy_consistency(client):
    pid = make_project(client)
    a = upload(client, pid, "npm-vulnerable", label="v1")
    b = upload(client, pid, "npm-vulnerable", mode="fixture:frozen-advisories-later", label="v1 refreshed")
    c = upload(client, pid, "npm-remediated", mode="fixture:frozen-advisories-later", label="v2")
    cmp = client.post(
        "/api/v1/scans/compare", json={"left_scan_id": a["id"], "right_scan_id": b["id"]}, headers=H
    ).json()
    assert cmp["package_counts"] == {} and cmp["advisory_source_changed"] and cmp["counts"]["introduced"] == 1
    tl = client.get(f"/api/v1/projects/{pid}/timeline").json()
    assert len(tl["points"]) == 3 and len(tl["deltas"]) == 2
    policy = (EXAMPLES / "policy-strict.yaml").read_text()
    assert client.put(f"/api/v1/projects/{pid}/policies", json={"yaml": policy}, headers=H).status_code == 200
    res = client.post(
        f"/api/v1/projects/{pid}/policies/evaluate",
        json={"scan_id": c["id"], "baseline_scan_id": b["id"]},
        headers=H,
    ).json()
    assert res["outcome"] == "fail" and res["exit_code"] == 1
    assert (
        client.put(
            f"/api/v1/projects/{pid}/policies",
            json={"yaml": "name: x\nrules: [{id: a, when: nope}]"},
            headers=H,
        ).status_code
        == 422
    )


def test_triage_requires_rationale_expiry_and_keeps_audit_trail(client):
    pid = make_project(client)
    scan = upload(client, pid, "npm-vulnerable")
    fid = client.get(f"/api/v1/scans/{scan['id']}/findings").json()["items"][0]["id"]
    url = f"/api/v1/findings/{fid}/triage"
    assert (
        client.patch(url, json={"status": "accepted_risk", "rationale": "ok"}, headers=H).status_code == 422
    )
    past = (date.today() - timedelta(days=1)).isoformat()
    assert (
        client.patch(
            url, json={"status": "accepted_risk", "rationale": "ok", "expires": past}, headers=H
        ).status_code
        == 422
    )
    assert client.patch(url, json={"status": "accepted_risk", "rationale": ""}, headers=H).status_code == 422
    future = (date.today() + timedelta(days=30)).isoformat()
    d = client.patch(
        url,
        json={"status": "accepted_risk", "rationale": "dev only", "expires": future, "author": "a"},
        headers=H,
    ).json()
    assert d["triage"]["status"] == "accepted_risk"
    client.patch(url, json={"status": "needs_review", "rationale": "revisit"}, headers=H)
    hist = client.get(f"/api/v1/findings/{fid}").json()["triage_history"]
    assert [h["to"] for h in hist] == ["needs_review", "accepted_risk"]
    assert (
        client.get(f"/api/v1/scans/{scan['id']}/findings", params={"status": "needs_review"}).json()["total"]
        == 1
    )


def test_remediation_endpoints(client):
    pid = make_project(client)
    scan = upload(client, pid, "npm-vulnerable")
    r = client.post(
        "/api/v1/remediation/scenarios",
        json={
            "base_scan_id": scan["id"],
            "operations": [{"op": "set_version", "component": "demo-parser", "version": "0.9.3"}],
        },
        headers=H,
    ).json()
    assert r["status"] == "predicted_partial" and r["full_reresolution"] is False
    data = (EXAMPLES / "npm-remediated" / "package-lock.json").read_bytes()
    c = client.post(
        "/api/v1/remediation/scenarios/candidate",
        data={"base_scan_id": scan["id"]},
        files={"files": ("package-lock.json", data)},
        headers=H,
    ).json()
    assert c["status"] == "confirmed_by_candidate_scan" and c["full_reresolution"]
    cmp = client.post(
        "/api/v1/remediation/compare", json={"scenario_ids": [r["id"], c["id"]]}, headers=H
    ).json()
    assert [x["mode"] for x in cmp] == ["hypothetical", "candidate_lockfile"]
    assert len(client.get(f"/api/v1/projects/{pid}/scenarios").json()) == 2


def test_demo_data_is_flagged_and_loaded_on_request(client):
    assert client.post("/api/v1/demo", headers=H).status_code == 201
    time.sleep(1.5)
    projects = client.get("/api/v1/projects").json()
    assert len(projects) == 3 and all(p["demo"] for p in projects)
    ov = client.get("/api/v1/overview").json()
    assert ov["has_demo_data"] and all(t["demo"] for t in ov["trend"])
    sid = projects[0]["latest_scan"]["id"]
    assert (
        client.get(f"/api/v1/scans/{sid}/reports", params={"format": "markdown"}).text.count("Demo data") >= 1
    )


def test_idempotency_key_prevents_duplicate_scans(client):
    pid = make_project(client)
    data = (EXAMPLES / "npm-clean" / "package-lock.json").read_bytes()
    kw = dict(
        files={"files": ("package-lock.json", data)},
        data={"enrichment": "fixture:frozen-advisories"},
        headers={**H, "Idempotency-Key": "abc"},
    )
    a = client.post(f"/api/v1/projects/{pid}/imports", **kw).json()
    b = client.post(f"/api/v1/projects/{pid}/imports", **kw).json()
    assert a["id"] == b["id"]


# ------------------------------------------------------------------ CLI


def run(*args):
    return runner.invoke(cli, [str(a) for a in args])


def test_cli_help_and_version():
    assert run("--help").exit_code == 0
    assert "supplychain-radar" in run("--version").stdout


def test_cli_scan_offline_fixture_json_and_atomic_output(tmp_path):
    out = tmp_path / "scan.json"
    r = run(
        "scan", EXAMPLES / "npm-vulnerable", "--offline", "--advisory-fixture", SNAP1, "-f", "json", "-o", out
    )
    assert r.exit_code == 0, r.output
    doc = json.loads(out.read_text())
    assert len(doc["findings"]) == 3 and doc["advisory_source"]["snapshot_id"] == "demo-2026-10-01"
    again = run("scan", EXAMPLES / "npm-vulnerable", "--advisory-fixture", SNAP1, "-f", "json", "-o", out)
    assert again.exit_code == 2 and "--overwrite" in again.output
    assert (
        run(
            "scan",
            EXAMPLES / "npm-vulnerable",
            "--advisory-fixture",
            SNAP1,
            "-f",
            "json",
            "-o",
            out,
            "--overwrite",
        ).exit_code
        == 0
    )


def test_cli_exit_codes(tmp_path):
    before, after = tmp_path / "b.json", tmp_path / "a.json"
    assert (
        run(
            "scan", EXAMPLES / "npm-vulnerable", "--advisory-fixture", SNAP1, "-f", "json", "-o", before
        ).exit_code
        == 0
    )
    assert (
        run(
            "scan", EXAMPLES / "npm-remediated", "--advisory-fixture", SNAP1, "-f", "json", "-o", after
        ).exit_code
        == 0
    )
    pol = EXAMPLES / "policy-strict.yaml"
    assert run("policy", "check", after, "--policy", pol, "--baseline", before).exit_code == 1  # gate failed
    assert run("policy", "check", before, "--policy", pol, "--baseline", before).exit_code == 0
    assert run("policy", "check", after, "--policy", pol).exit_code == 2  # baseline required
    assert run("scan", tmp_path / "missing").exit_code == 2
    bad = tmp_path / "bad.lock"
    bad.write_text("{")
    assert run("scan", bad).exit_code == 2
    assert (
        run(
            "scan",
            EXAMPLES / "npm-vulnerable",
            "--offline",
            "--cache-dir",
            tmp_path / "none",
            "--fail-on-incomplete",
        ).exit_code
        == 4
    )
    assert (
        run(
            "scan",
            EXAMPLES / "npm-vulnerable",
            "--advisory-fixture",
            SNAP1,
            "--policy",
            pol,
            "--baseline",
            before,
        ).exit_code
        == 0
    )
    strict = tmp_path / "p.yaml"
    strict.write_text(
        "schema_version: 1\nname: s\nrules: [{id: c, when: confirmed_advisory, min_severity: critical, action: fail}]\n"
    )
    assert (
        run("scan", EXAMPLES / "npm-vulnerable", "--advisory-fixture", SNAP1, "--policy", strict).exit_code
        == 1
    )


def test_cli_provider_failure_is_exit_3(tmp_path):
    r = run("scan", EXAMPLES / "npm-clean", "--cache-dir", tmp_path / "c", "--osv-url", "http://127.0.0.1:1")
    assert r.exit_code == 3, r.output


def test_cli_compare_report_import_validate_and_remediate(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    run("scan", EXAMPLES / "npm-vulnerable", "--advisory-fixture", SNAP1, "-f", "json", "-o", a)
    run("scan", EXAMPLES / "npm-vulnerable", "--advisory-fixture", SNAP2, "-f", "json", "-o", b)
    html = tmp_path / "diff.html"
    assert (
        run("compare", a, b, "-f", "html", "-o", html).exit_code == 0
        and "advisory_database_update" in html.read_text()
    )
    for fmt, name in [
        ("sarif", "r.sarif"),
        ("html", "r.html"),
        ("markdown", "r.md"),
        ("cyclonedx", "r.cdx.json"),
    ]:
        assert run("report", b, "-f", fmt, "-o", tmp_path / name).exit_code == 0
    v = run("import", "validate", EXAMPLES / "sbom-cyclonedx" / "bom.cdx.json")
    assert v.exit_code == 0 and "valid" in v.stdout
    assert run("import", "validate", tmp_path / "bad.lock").exit_code == 2
    out = tmp_path / "cand.json"
    assert (
        run(
            "remediate", "candidate", a, EXAMPLES / "npm-remediated", "--advisory-fixture", SNAP1, "-o", out
        ).exit_code
        == 0
    )
    assert json.loads(out.read_text())["status"] == "confirmed_by_candidate_scan"
    out2 = tmp_path / "prop.json"
    assert (
        run(
            "remediate", "propose", a, "--set", "demo-parser@0.9.3", "--advisory-fixture", SNAP1, "-o", out2
        ).exit_code
        == 0
    )
    assert json.loads(out2.read_text())["full_reresolution"] is False


def test_cli_table_marks_zero_evaluation_as_not_clean(tmp_path):
    r = run("scan", EXAMPLES / "npm-vulnerable", "--offline", "--cache-dir", tmp_path / "none")
    assert "NOT a clean result" in r.stdout


def test_cli_scan_all_examples_smoke(tmp_path):
    for ex in [
        "pnpm-monorepo",
        "poetry-vulnerable",
        "requirements-partial",
        "sbom-cyclonedx",
        "sbom-cyclonedx-1.7",
        "npm-clean",
    ]:
        r = run(
            "scan", EXAMPLES / ex, "--advisory-fixture", SNAP1, "-f", "json", "-o", tmp_path / f"{ex}.json"
        )
        assert r.exit_code == 0, (ex, r.output)
    assert Path(tmp_path / "npm-clean.json").exists()


def test_cli_stdout_is_utf8_even_on_legacy_code_pages(tmp_path):
    """Regression: Markdown/HTML contain '→'; a cp1251/cp1252 console must not crash the scan."""
    import subprocess
    import sys

    env = {**__import__("os").environ, "PYTHONIOENCODING": "cp1251", "PYTHONUTF8": "0"}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "scradar.cli.main_entry",
            "scan",
            str(EXAMPLES / "npm-vulnerable"),
            "--advisory-fixture",
            str(SNAP1),
            "-f",
            "markdown",
        ],
        capture_output=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert "→".encode() in proc.stdout
