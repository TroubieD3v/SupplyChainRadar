from __future__ import annotations

from pathlib import Path

import pytest

from scradar.ingestion.detect import import_directory
from scradar.intelligence.providers import FixtureProvider
from scradar.service import analyze

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
SNAP1 = ROOT / "fixtures" / "osv" / "frozen-advisories.json"
SNAP2 = ROOT / "fixtures" / "osv" / "frozen-advisories-later.json"


@pytest.fixture
def snap1() -> FixtureProvider:
    return FixtureProvider(SNAP1)


@pytest.fixture
def snap2() -> FixtureProvider:
    return FixtureProvider(SNAP2)


def scan_example(name: str, provider, **kw):
    out = import_directory(EXAMPLES / name)
    assert not out.errors, out.errors
    return analyze(
        out.inventories,
        provider,
        project=name,
        scan_id=f"scan-{name}",
        created_at="2026-10-25T00:00:00Z",
        **kw,
    )


@pytest.fixture
def scan():
    return scan_example
