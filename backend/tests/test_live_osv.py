"""Optional live integration test (A06). Skipped unless SCRADAR_LIVE=1; never part of the baseline CI gate.

It sends ONE package identity (npm lodash 4.17.15, a long-known vulnerable release) to api.osv.dev.
"""

import os

import pytest

from scradar.domain.models import ROOT_ID, Component, Edge, Inventory, QueryState
from scradar.intelligence.providers import OsvProvider
from scradar.service import analyze

pytestmark = pytest.mark.skipif(
    os.environ.get("SCRADAR_LIVE") != "1", reason="set SCRADAR_LIVE=1 to run live OSV checks"
)


def _inv(version: str) -> Inventory:
    app = Component(id=ROOT_ID, kind="application", ecosystem="npm", name="live-check")
    lodash = Component(
        id=f"npm:lodash@{version}",
        ecosystem="npm",
        name="lodash",
        version=version,
        purl=f"pkg:npm/lodash@{version}",
        source="registry",
    )
    return Inventory(
        format="test",
        parser="test",
        parser_version="0",
        source_label="live",
        checksum="0",
        components={ROOT_ID: app, lodash.id: lodash},
        edges=[Edge(parent=ROOT_ID, child=lodash.id)],
    )


def test_known_vulnerable_release_is_reported_and_fixed_release_is_not(tmp_path):
    prov = OsvProvider(cache_dir=tmp_path)
    old = analyze([_inv("4.17.15")], prov, project="live")
    assert old.coverage.error == 0 and old.advisory_source.mode == "live"
    assert old.findings, "lodash 4.17.15 should have published advisories"
    assert any(f.advisory.fixed_versions for f in old.findings)
    assert all(f.match.local_verification in {"confirmed", "unavailable"} for f in old.findings)
    new = analyze([_inv("4.17.21")], prov, project="live")
    assert all(e.state == QueryState.EVALUATED for e in new.evaluations)
    offline = analyze([_inv("4.17.15")], OsvProvider(cache_dir=tmp_path, offline=True), project="live")
    assert offline.advisory_source.mode == "cached" and len(offline.findings) == len(old.findings)
