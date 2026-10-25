"""Advisory providers: frozen offline fixtures, the OSV HTTP API (with cache), and a null provider.

A provider never reports "no vulnerabilities" for something it did not actually evaluate.
"""

from __future__ import annotations

import hashlib
import json
import random
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

from scradar import versions
from scradar.domain.models import (
    AdvisorySourceInfo,
    Component,
    MatchEvidence,
    QueryState,
)
from scradar.intelligence.osv_model import affected_by
from scradar.security import redact

OSV_BASE_URL = "https://api.osv.dev"
OSV_ECOSYSTEMS = {"npm", "PyPI", "Maven", "Go", "crates.io", "NuGet", "RubyGems", "Packagist", "Hex", "Pub"}


@dataclass
class Match:
    record: dict[str, Any]
    evidence: MatchEvidence
    fixed_versions: list[str] = field(default_factory=list)


@dataclass
class ComponentResult:
    state: QueryState
    source: str | None = None  # live | cache | offline_fixture
    fetched_at: str | None = None
    note: str | None = None
    matches: list[Match] = field(default_factory=list)


class Provider(Protocol):
    name: str

    def evaluate(
        self, components: list[Component], cancelled: Callable[[], bool] | None = None
    ) -> dict[str, ComponentResult]: ...

    def source_info(self, results: dict[str, ComponentResult]) -> AdvisorySourceInfo: ...


def queryable_reason(c: Component) -> str | None:
    """Why a component cannot be sent for advisory lookup (None means it can)."""

    if c.kind != "package":
        return "application root"
    if not c.resolved or not c.version:
        return c.unsupported_reason or "version is not resolved to one exact release"
    if c.unsupported_reason:
        return c.unsupported_reason
    if c.ecosystem not in OSV_ECOSYSTEMS:
        return f"ecosystem '{c.ecosystem}' is not supported for advisory lookup"
    return None


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# --- null / offline ---------------------------------------------------------------------------


class NullProvider:
    """Offline with no data: every package is explicitly *not evaluated*."""

    name = "none"

    def evaluate(self, components, cancelled=None):  # type: ignore[no-untyped-def]
        out: dict[str, ComponentResult] = {}
        for c in components:
            reason = queryable_reason(c)
            if reason == "application root":
                continue
            if reason:
                out[c.id] = ComponentResult(QueryState.UNSUPPORTED, note=reason)
            else:
                out[c.id] = ComponentResult(
                    QueryState.NOT_EVALUATED,
                    note="offline mode and no advisory data available for this package",
                )
        return out

    def source_info(self, results):  # type: ignore[no-untyped-def]
        return AdvisorySourceInfo(
            mode="none",
            provider="none",
            offline=True,
            notes=[
                "No advisory data source was used. Packages are NOT EVALUATED, which is different from 'no vulnerabilities'."
            ],
        )


# --- frozen fixture -----------------------------------------------------------------------------


class FixtureProvider:
    name = "fixture"

    def __init__(self, path: str | Path | None = None, document: dict[str, Any] | None = None) -> None:
        if document is None:
            if path is None:
                raise ValueError("path or document is required")
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not isinstance(document.get("advisories"), list):
            raise ValueError("advisory fixture must be an object with an 'advisories' array")
        self.doc = document
        self.snapshot_id = str(document.get("snapshot_id", "unnamed-snapshot"))
        self.generated = document.get("generated")
        self.ecosystems = set(document.get("ecosystems") or [])
        self.records: list[dict[str, Any]] = document["advisories"]
        self.index: dict[tuple[str, str], list[dict[str, Any]]] = {}
        from scradar.ingestion.common import normalize_pypi_name

        for rec in self.records:
            for aff in rec.get("affected") or []:
                pkg = aff.get("package") or {}
                eco, name = str(pkg.get("ecosystem", "")).lower(), str(pkg.get("name", ""))
                key = (eco, normalize_pypi_name(name) if eco == "pypi" else name)
                bucket = self.index.setdefault(key, [])
                if rec not in bucket:
                    bucket.append(rec)

    def evaluate(self, components, cancelled=None):  # type: ignore[no-untyped-def]
        from scradar.ingestion.common import normalize_pypi_name

        out: dict[str, ComponentResult] = {}
        for c in components:
            reason = queryable_reason(c)
            if reason == "application root":
                continue
            if reason:
                out[c.id] = ComponentResult(QueryState.UNSUPPORTED, note=reason)
                continue
            assert c.version is not None
            if self.ecosystems and c.ecosystem not in self.ecosystems:
                out[c.id] = ComponentResult(
                    QueryState.NOT_EVALUATED,
                    note=f"snapshot '{self.snapshot_id}' does not cover ecosystem {c.ecosystem}",
                )
                continue
            key = (c.ecosystem.lower(), normalize_pypi_name(c.name) if c.ecosystem == "PyPI" else c.name)
            matches: list[Match] = []
            unsupported: str | None = None
            for rec in self.index.get(key, []):
                status, why, fixed = affected_by(c.ecosystem, c.name, c.version, rec)
                if status == "affected":
                    basis = "explicit_version" if "explicit affected versions" in why else "local_range"
                    matches.append(Match(rec, MatchEvidence(basis=basis, rationale=why), fixed))
                elif status == "unsupported":
                    unsupported = why
            if unsupported and not matches:
                out[c.id] = ComponentResult(
                    QueryState.UNSUPPORTED, "offline_fixture", self.generated, unsupported
                )
            else:
                out[c.id] = ComponentResult(
                    QueryState.EVALUATED,
                    "offline_fixture",
                    self.generated,
                    f"evaluated against frozen snapshot '{self.snapshot_id}'",
                    matches,
                )
        return out

    def source_info(self, results):  # type: ignore[no-untyped-def]
        return AdvisorySourceInfo(
            mode="offline_fixture",
            provider="fixture",
            snapshot_id=self.snapshot_id,
            snapshot_generated=self.generated,
            offline=True,
            notes=[
                f"Frozen advisory snapshot '{self.snapshot_id}' ({len(self.records)} advisories). "
                "Absence of a match means absence from this snapshot only."
            ],
        )


# --- OSV ----------------------------------------------------------------------------------------


class AdvisoryCache:
    """Small JSON-file cache with expiry. Stale entries stay readable in offline mode."""

    def __init__(self, directory: str | Path, ttl: timedelta = timedelta(hours=24)) -> None:
        self.dir = Path(directory)
        self.ttl = ttl
        self._lock = threading.Lock()

    def _path(self, kind: str, key: str) -> Path:
        h = hashlib.sha256(key.encode()).hexdigest()[:40]
        return self.dir / kind / f"{h}.json"

    def get(self, kind: str, key: str) -> tuple[Any, str, bool] | None:
        p = self._path(kind, key)
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        fetched = doc.get("fetched_at")
        try:
            age = datetime.now(UTC) - datetime.fromisoformat(str(fetched).replace("Z", "+00:00"))
            fresh = age <= self.ttl
        except ValueError:
            fresh = False
        return doc.get("value"), str(fetched), fresh

    def put(self, kind: str, key: str, value: Any) -> str:
        p = self._path(kind, key)
        stamp = _now()
        with self._lock:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps({"fetched_at": stamp, "value": value}), encoding="utf-8")
            tmp.replace(p)
        return stamp


class OsvError(RuntimeError):
    pass


class OsvProvider:
    """OSV.dev client: /v1/querybatch then /v1/vulns/{id}. Sends only ecosystem, name and version."""

    name = "osv"

    def __init__(
        self,
        *,
        base_url: str = OSV_BASE_URL,
        cache_dir: str | Path | None = None,
        cache_ttl: timedelta = timedelta(hours=24),
        offline: bool = False,
        batch_size: int = 500,
        concurrency: int = 6,
        timeout: float = 20.0,
        max_retries: int = 4,
        rate_per_second: float = 10.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed = urlparse(base_url)
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError("OSV base URL must be https (http is allowed only for loopback test servers)")
        self.base_url = base_url.rstrip("/")
        self.cache = AdvisoryCache(cache_dir, cache_ttl) if cache_dir else None
        self.offline = offline
        self.batch_size = max(1, min(batch_size, 1000))
        self.concurrency = max(1, min(concurrency, 16))
        self.max_retries = max_retries
        self.min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._sleep = sleep
        self._last = 0.0
        self._rate_lock = threading.Lock()
        self._client = (
            None
            if offline
            else httpx.Client(
                timeout=timeout,
                follow_redirects=False,  # never follow redirects: no data leaves for unexpected hosts
                transport=transport,
                headers={"User-Agent": "supplychain-radar/1.0 (+offline-first)"},
            )
        )
        self.requests_made = 0

    # -- HTTP ----------------------------------------------------------------------------------

    def _throttle(self) -> None:
        with self._rate_lock:
            wait = self._last + self.min_interval - time.monotonic()
            if wait > 0:
                self._sleep(wait)
            self._last = time.monotonic()

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        assert self._client is not None
        url = f"{self.base_url}{path}"
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                self.requests_made += 1
                resp = self._client.request(method, url, json=payload)
                if resp.status_code in {429, 500, 502, 503, 504}:
                    raise OsvError(f"HTTP {resp.status_code}")
                if resp.status_code >= 400:
                    raise OsvError(f"HTTP {resp.status_code} from OSV (not retried)")
                return resp.json()
            except (httpx.TransportError, OsvError, ValueError) as exc:
                last_exc = exc
                if isinstance(exc, OsvError) and "not retried" in str(exc):
                    break
                if attempt < self.max_retries:
                    self._sleep(min(30.0, (2**attempt) * 0.5) + random.uniform(0, 0.25))  # noqa: S311
        raise OsvError(redact(f"{type(last_exc).__name__}: {last_exc}") or "request failed")

    # -- evaluation ---------------------------------------------------------------------------

    @staticmethod
    def _qkey(c: Component) -> str:
        return f"{c.ecosystem}|{c.name}|{c.version}"

    def evaluate(self, components, cancelled=None):  # type: ignore[no-untyped-def]
        out: dict[str, ComponentResult] = {}
        pending: list[Component] = []
        ids_for: dict[str, list[dict[str, str]]] = {}
        stamp_for: dict[str, tuple[str, str]] = {}  # component id -> (source, fetched_at)
        for c in components:
            reason = queryable_reason(c)
            if reason == "application root":
                continue
            if reason:
                out[c.id] = ComponentResult(QueryState.UNSUPPORTED, note=reason)
                continue
            cached = self.cache.get("query", self._qkey(c)) if self.cache else None
            if cached and (self.offline or cached[2]):
                ids_for[c.id] = cached[0]
                stamp_for[c.id] = ("cache", cached[1])
            elif self.offline:
                out[c.id] = ComponentResult(
                    QueryState.NOT_EVALUATED, note="offline mode: no cached advisory lookup for this package"
                )
            else:
                pending.append(c)

        failed: dict[str, str] = {}
        for i in range(0, len(pending), self.batch_size):
            if cancelled and cancelled():
                break
            chunk = pending[i : i + self.batch_size]
            try:
                results = self._query_chunk(chunk)
            except OsvError as exc:
                for c in chunk:
                    failed[c.id] = str(exc)
                continue
            for c, vulns in zip(chunk, results, strict=True):
                ids_for[c.id] = vulns
                stamp = self.cache.put("query", self._qkey(c), vulns) if self.cache else _now()
                stamp_for[c.id] = ("live", stamp)

        # fetch full records
        wanted: dict[str, str | None] = {}
        for vulns in ids_for.values():
            for v in vulns:
                wanted.setdefault(v["id"], v.get("modified"))
        records: dict[str, tuple[dict[str, Any], str, str]] = {}
        vuln_errors: dict[str, str] = {}

        def fetch(vid: str) -> None:
            if cancelled and cancelled():
                return
            cached = self.cache.get("vuln", vid) if self.cache else None
            if cached and (self.offline or cached[2] or cached[0].get("modified") == wanted.get(vid)):
                records[vid] = (cached[0], "cache", cached[1])
                return
            if self.offline:
                vuln_errors[vid] = "advisory body is not in the offline cache"
                return
            try:
                rec = self._request("GET", f"/v1/vulns/{vid}")
            except OsvError as exc:
                vuln_errors[vid] = str(exc)
                return
            stamp = self.cache.put("vuln", vid, rec) if self.cache else _now()
            records[vid] = (rec, "live", stamp)

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            list(pool.map(fetch, sorted(wanted)))

        by_id = {c.id: c for c in components}
        for cid, vulns in ids_for.items():
            c = by_id[cid]
            source, fetched_at = stamp_for[cid]
            missing = [v["id"] for v in vulns if v["id"] not in records]
            if missing:
                out[cid] = ComponentResult(
                    QueryState.ERROR,
                    source,
                    fetched_at,
                    f"could not load advisory body for {', '.join(missing[:3])}: {vuln_errors.get(missing[0], 'unknown error')}",
                )
                continue
            matches: list[Match] = []
            for v in vulns:
                rec, _, _ = records[v["id"]]
                assert c.version is not None
                status, why, fixed = affected_by(c.ecosystem, c.name, c.version, rec)
                verification = {
                    "affected": "confirmed",
                    "not_affected": "disagrees",
                    "unsupported": "unavailable",
                }[status]
                matches.append(
                    Match(
                        rec,
                        MatchEvidence(
                            basis="osv_query",
                            rationale=f"returned by OSV for {c.ecosystem}/{c.name}@{c.version}"
                            + (
                                f"; local check: {why}"
                                if status != "unsupported"
                                else f"; local check unavailable: {why}"
                            ),
                            local_verification=verification,  # type: ignore[arg-type]
                        ),
                        fixed,
                    )
                )
            out[cid] = ComponentResult(
                QueryState.CACHED if source == "cache" else QueryState.EVALUATED,
                source,
                fetched_at,
                "answered from the local OSV cache" if source == "cache" else "queried OSV live",
                matches,
            )
        for cid, msg in failed.items():
            out[cid] = ComponentResult(QueryState.ERROR, note=f"OSV request failed: {msg}")
        for c in pending:
            out.setdefault(
                c.id,
                ComponentResult(
                    QueryState.NOT_EVALUATED, note="scan cancelled before this package was queried"
                ),
            )
        return out

    def _query_chunk(self, chunk: list[Component]) -> list[list[dict[str, str]]]:
        queries = [
            {"package": {"name": c.name, "ecosystem": c.ecosystem}, "version": c.version} for c in chunk
        ]
        resp = self._request("POST", "/v1/querybatch", {"queries": queries})
        results = resp.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            raise OsvError("unexpected querybatch response shape")
        all_ids: list[list[dict[str, str]]] = []
        for idx, r in enumerate(results):
            vulns = list((r or {}).get("vulns") or [])
            token = (r or {}).get("next_page_token")
            guard = 0
            while token and guard < 20:
                page = self._request(
                    "POST",
                    "/v1/querybatch",
                    {"queries": [{**queries[idx], "page_token": token}]},
                )
                sub = (page.get("results") or [{}])[0] or {}
                vulns.extend(sub.get("vulns") or [])
                token = sub.get("next_page_token")
                guard += 1
            all_ids.append(
                [{"id": str(v["id"]), "modified": v.get("modified")} for v in vulns if v.get("id")]
            )
        return all_ids

    def source_info(self, results):  # type: ignore[no-untyped-def]
        sources = {r.source for r in results.values() if r.source}
        stamps = [r.fetched_at for r in results.values() if r.fetched_at]
        if sources == {"live"}:
            mode = "live"
        elif sources == {"cache"}:
            mode = "cached"
        elif sources:
            mode = "mixed"
        else:
            mode = "none"
        notes = []
        if self.offline:
            notes.append("Offline: only the local OSV cache was consulted; cache misses are NOT EVALUATED.")
        else:
            notes.append(
                "Online lookup sent only ecosystem, package name and version to the OSV API (https://api.osv.dev)."
            )
        return AdvisorySourceInfo(
            mode=mode,  # type: ignore[arg-type]
            provider="osv",
            fetched_at=max(stamps) if stamps else None,
            offline=self.offline,
            notes=notes,
        )

    def close(self) -> None:
        if self._client:
            self._client.close()


def verify_comparable(c: Component) -> bool:
    return versions.comparable(c.ecosystem)
