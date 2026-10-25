import io
import json
import stat
import zipfile
from datetime import timedelta

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from scradar.domain.models import ROOT_ID, Component, Edge, QueryState
from scradar.graph.engine import DependencyGraph
from scradar.ingestion.common import IngestError, load_yaml
from scradar.ingestion.detect import import_directory, import_zip, parse_file
from scradar.intelligence.providers import OsvProvider
from scradar.security import Limits, redact
from scradar.service import analyze

from .conftest import EXAMPLES

# ------------------------------------------------------------------ OSV adapter (mock HTTP)

VULN = {
    "id": "GHSA-mock-0001",
    "aliases": ["CVE-2099-0001"],
    "summary": "mock",
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "demo-vulnerable-lib"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.5"}]}],
        }
    ],
}


class Recorder:
    def __init__(self, fail_first=0, redirect=False):
        self.requests: list[httpx.Request] = []
        self.fail_first = fail_first
        self.redirect = redirect

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.redirect:
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})
        if self.fail_first > 0:
            self.fail_first -= 1
            return httpx.Response(503)
        if req.url.path == "/v1/querybatch":
            q = json.loads(req.content)["queries"]
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-mock-0001", "modified": "2026-01-01T00:00:00Z"}]}
                        if x["package"]["name"] == "demo-vulnerable-lib"
                        else {}
                        for x in q
                    ]
                },
            )
        if req.url.path == "/v1/vulns/GHSA-mock-0001":
            return httpx.Response(200, json=VULN)
        return httpx.Response(404)


def provider(rec, tmp_path, **kw):
    return OsvProvider(
        base_url="https://osv.test",
        cache_dir=tmp_path / "cache",
        transport=httpx.MockTransport(rec),
        sleep=lambda _s: None,
        rate_per_second=0,
        **kw,
    )


def scan_with(prov):
    inv = import_directory(EXAMPLES / "npm-vulnerable").inventories
    return analyze(inv, prov, project="x")


def test_osv_live_sends_only_package_identity(tmp_path):
    rec = Recorder()
    sc = scan_with(provider(rec, tmp_path))
    batch = [r for r in rec.requests if r.url.path == "/v1/querybatch"]
    assert len(batch) == 1
    body = json.loads(batch[0].content)
    for q in body["queries"]:
        assert set(q) == {"package", "version"} and set(q["package"]) == {"name", "ecosystem"}
    sent = b"".join(r.content for r in rec.requests).decode()
    assert (
        "demo-app" not in sent and "integrity" not in sent and "sha512" not in sent
    )  # project name / hashes never leave
    assert {r.url.host for r in rec.requests} == {"osv.test"}
    f = sc.findings[0]
    assert (
        f.advisory.id == "GHSA-mock-0001"
        and f.match.basis == "osv_query"
        and f.match.local_verification == "confirmed"
    )
    assert sc.advisory_source.mode == "live"


def test_osv_retries_with_backoff_on_503(tmp_path):
    rec = Recorder(fail_first=2)
    sc = scan_with(provider(rec, tmp_path))
    assert len(sc.findings) == 1 and sc.coverage.error == 0


def test_osv_failure_is_error_state_not_clean(tmp_path):
    rec = Recorder(fail_first=99)
    sc = scan_with(provider(rec, tmp_path, max_retries=1))
    assert sc.findings == [] and sc.coverage.error == 9 and not sc.coverage.fully_covered
    assert all(e.state == QueryState.ERROR for e in sc.evaluations)


def test_osv_does_not_follow_redirects(tmp_path):
    rec = Recorder(redirect=True)
    sc = scan_with(provider(rec, tmp_path, max_retries=0))
    assert {r.url.host for r in rec.requests} == {"osv.test"}
    assert sc.coverage.error == 9


def test_osv_cache_serves_offline_and_misses_are_not_evaluated(tmp_path):
    rec = Recorder()
    scan_with(provider(rec, tmp_path))
    n = len(rec.requests)
    offline = OsvProvider(base_url="https://osv.test", cache_dir=tmp_path / "cache", offline=True)
    sc = scan_with(offline)
    assert len(rec.requests) == n  # no network at all
    assert sc.advisory_source.mode == "cached" and [f.advisory.id for f in sc.findings] == ["GHSA-mock-0001"]
    assert all(e.state == QueryState.CACHED for e in sc.evaluations)
    empty = scan_with(OsvProvider(base_url="https://osv.test", cache_dir=tmp_path / "other", offline=True))
    assert empty.coverage.not_evaluated == 9 and empty.findings == []


def test_osv_rejects_non_https_remote_base_url():
    with pytest.raises(ValueError):
        OsvProvider(base_url="http://evil.example.com")
    OsvProvider(base_url="http://127.0.0.1:9", offline=True)


def test_stale_cache_is_refreshed_online(tmp_path):
    rec = Recorder()
    scan_with(provider(rec, tmp_path, cache_ttl=timedelta(seconds=-1)))
    first = len(rec.requests)
    scan_with(provider(rec, tmp_path, cache_ttl=timedelta(seconds=-1)))
    assert len(rec.requests) > first


# ------------------------------------------------------------------ untrusted input


def make_zip(entries, symlink=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink[0])
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, symlink[1])
    return buf.getvalue()


LOCK = (EXAMPLES / "npm-vulnerable" / "package-lock.json").read_bytes()


def test_zip_happy_path_never_touches_disk():
    out = import_zip(
        make_zip(
            {
                "proj/package-lock.json": LOCK,
                "proj/node_modules/x/package-lock.json": b"{}",
                "proj/README.md": b"hi",
            }
        )
    )
    assert len(out.inventories) == 1 and out.inventories[0].source_label == "proj/package-lock.json"


@pytest.mark.parametrize(
    "name",
    ["../evil/package-lock.json", "/abs/package-lock.json", "a/../../x.json", "C:/win/package-lock.json"],
)
def test_zip_slip_rejected(name):
    with pytest.raises(IngestError, match="unsafe path"):
        import_zip(make_zip({name: LOCK}))


def test_zip_symlink_rejected():
    with pytest.raises(IngestError, match="symlink"):
        import_zip(make_zip({"package-lock.json": LOCK}, symlink=("link", "/etc/passwd")))


def test_zip_bomb_and_entry_limits():
    bomb = make_zip({"package-lock.json": b"0" * 30_000_000})
    with pytest.raises(IngestError):
        import_zip(bomb, Limits(max_file_bytes=25_000_000, max_total_bytes=100_000_000, max_zip_ratio=50))
    many = make_zip({f"d{i}/package-lock.json": b"{}" for i in range(30)})
    with pytest.raises(IngestError, match="more than"):
        import_zip(many, Limits(max_files=10))
    with pytest.raises(IngestError, match="entries"):
        import_zip(make_zip({f"f{i}.txt": b"x" for i in range(20)}), Limits(max_zip_entries=5))


def test_yaml_alias_bomb_rejected():
    bomb = b"lockfileVersion: '9.0'\na: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
    with pytest.raises(IngestError, match="aliases"):
        load_yaml(bomb)


def test_deep_json_and_oversize_rejected_safely():
    with pytest.raises(IngestError):
        parse_file("package-lock.json", b"[" * 100_000 + b"]" * 100_000)
    with pytest.raises(IngestError, match="limit"):
        parse_file("package-lock.json", b"{}" + b" " * 2000, limits=Limits(max_file_bytes=1000))


def test_folder_import_skips_symlinks_and_node_modules(tmp_path):
    (tmp_path / "package-lock.json").write_bytes(LOCK)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package-lock.json").write_bytes(b"not json")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "package-lock.json").write_bytes(LOCK)
    try:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    out = import_directory(tmp_path)
    assert len(out.inventories) == 1 and out.errors == []


def test_imported_content_is_never_executed(tmp_path):
    marker = tmp_path / "pwned"
    lock = json.loads(LOCK)
    lock["packages"][""]["scripts"] = {"postinstall": f"python -c \"open(r'{marker}','w')\""}
    lock["packages"]["node_modules/demo-core"]["hasInstallScript"] = True
    parse_file("package-lock.json", json.dumps(lock).encode())
    assert not marker.exists()


def test_redaction():
    assert "hunter2" not in redact("https://user:hunter2@host/simple")
    assert "ghp_" not in redact("token ghp_abcdefghijklmnopqrstuvwxyz0123456789")
    assert redact("npm_" + "a" * 36) == "***"


# ------------------------------------------------------------------ property tests

_names = st.sampled_from([f"n{i}@1" for i in range(8)])


@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(st.lists(st.tuples(_names, _names), max_size=40), _names)
def test_graph_search_terminates_and_paths_are_valid(pairs, target):
    comps = {ROOT_ID: Component(id=ROOT_ID, kind="application", ecosystem="npm", name="app")}
    for i in range(8):
        comps[f"n{i}@1"] = Component(id=f"n{i}@1", ecosystem="npm", name=f"n{i}", version="1")
    edges = [Edge(parent=ROOT_ID, child="n0@1")] + [Edge(parent=a, child=b) for a, b in pairs]
    g = DependencyGraph(comps, edges)
    s = g.paths_to(target, max_paths=15)
    edge_set = {(e.parent, e.child) for e in edges}
    for p in s.paths:
        assert p.nodes[0] == ROOT_ID and p.nodes[-1] == target
        assert len(set(p.nodes)) == len(p.nodes)
        assert all((a, b) in edge_set for a, b in zip(p.nodes, p.nodes[1:], strict=False))
    g.compute_scopes()
    g.analysis()


@settings(max_examples=150, deadline=None)
@given(st.binary(max_size=3000))
@pytest.mark.parametrize(
    "fname",
    ["package-lock.json", "pnpm-lock.yaml", "poetry.lock", "requirements.txt", "bom.cdx.json", "x.spdx.json"],
)
def test_parsers_only_fail_with_ingest_error(fname, data):
    try:
        parse_file(fname, data)
    except IngestError:
        pass


@settings(max_examples=60, deadline=None)
@given(
    st.dictionaries(
        st.text(max_size=8),
        st.recursive(
            st.none() | st.booleans() | st.integers() | st.text(max_size=5),
            lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=5), c, max_size=3),
            max_leaves=12,
        ),
        max_size=6,
    )
)
def test_structured_garbage_json_only_fails_cleanly(doc):
    for fname in ("package-lock.json", "bom.cdx.json", "x.spdx.json"):
        try:
            parse_file(fname, json.dumps(doc).encode())
        except IngestError:
            pass


def test_repeated_scan_is_idempotent(snap1):
    inv = import_directory(EXAMPLES / "npm-vulnerable").inventories
    a, b = analyze(inv, snap1), analyze(inv, snap1)
    assert a.checksum == b.checksum and len(a.findings) == len(b.findings) == 3


def test_offline_modes_open_no_sockets(monkeypatch, tmp_path):
    """A18: --offline / fixture / cache-only scans must not touch the network at all."""
    import socket

    from scradar.intelligence.providers import FixtureProvider, NullProvider

    def boom(*a, **k):
        raise AssertionError("network access attempted in offline mode")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    inv = import_directory(EXAMPLES / "npm-vulnerable").inventories
    for prov in (
        FixtureProvider(EXAMPLES.parent / "fixtures" / "osv" / "frozen-advisories.json"),
        NullProvider(),
        OsvProvider(cache_dir=tmp_path / "c", offline=True),
    ):
        analyze(inv, prov, project="x")
