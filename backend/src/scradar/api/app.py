"""FastAPI application: REST API (/api/v1) plus the built web UI."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scradar import ENGINE_VERSION, __version__
from scradar.api import db
from scradar.comparison.diff import compare_scans
from scradar.domain.models import EVALUATED_STATES, ROOT_ID, QueryState, ScanResult, Severity
from scradar.graph.engine import DependencyGraph
from scradar.ingestion.common import IngestError
from scradar.ingestion.detect import import_zip, parse_file
from scradar.intelligence.providers import OSV_BASE_URL, FixtureProvider, NullProvider, OsvProvider
from scradar.policy.engine import DEFAULT_POLICY, ExceptionEntry, PolicyError, evaluate_policy, load_policy
from scradar.remediation.simulator import (
    Operation,
    ScenarioOutcome,
    compare_plans,
    simulate_candidate,
    simulate_hypothetical,
    suggest_fixes,
)
from scradar.reports.render import FORMATS, comparison_to_html, render
from scradar.security import DEFAULT_LIMITS, redact, redact_str
from scradar.service import analyze, severity_counts

STATES = ("queued", "parsing", "enriching", "analyzing", "completed", "partial", "failed", "cancelled")
TRIAGE_STATUSES = ("open", "accepted_risk", "false_positive", "not_affected", "needs_review")


# --- configuration -------------------------------------------------------------------------------


def _find_repo_root() -> Path | None:
    env = os.environ.get("SCRADAR_EXAMPLES_DIR")
    if env:
        return Path(env)
    for p in Path(__file__).resolve().parents:
        if (p / "examples").is_dir() and (p / "fixtures" / "osv").is_dir():
            return p
    return None


@dataclass
class Config:
    database_url: str | None = field(default_factory=lambda: os.environ.get("SCRADAR_DATABASE_URL"))
    cache_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("SCRADAR_CACHE_DIR", Path.home() / ".cache" / "supplychain-radar")
        )
    )
    api_token: str | None = field(default_factory=lambda: os.environ.get("SCRADAR_API_TOKEN") or None)
    allowed_hosts: list[str] = field(
        default_factory=lambda: os.environ.get(
            "SCRADAR_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver"
        ).split(",")
    )
    static_dir: Path | None = field(
        default_factory=lambda: (
            Path(os.environ["SCRADAR_STATIC_DIR"]) if os.environ.get("SCRADAR_STATIC_DIR") else None
        )
    )
    repo_root: Path | None = field(default_factory=_find_repo_root)
    osv_url: str = field(default_factory=lambda: os.environ.get("SCRADAR_OSV_URL", OSV_BASE_URL))
    max_upload_bytes: int = DEFAULT_LIMITS.max_file_bytes
    workers: int = 2


# --- errors ----------------------------------------------------------------------------------------


class ApiError(HTTPException):
    def __init__(self, status: int, code: str, message: str, details: Any = None) -> None:
        super().__init__(status_code=status, detail={"code": code, "message": message, "details": details})


def _err(status: int, code: str, message: str, details: Any = None) -> ApiError:
    return ApiError(status, code, redact(message) or message, details)


# --- request models ---------------------------------------------------------------------------------


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class TriageIn(BaseModel):
    status: Literal["open", "accepted_risk", "false_positive", "not_affected", "needs_review"]
    rationale: str = Field(min_length=1, max_length=4000)
    expires: date | None = None
    author: str | None = Field(default=None, max_length=200)
    evidence: str | None = Field(default=None, max_length=1000)


class CompareIn(BaseModel):
    left_scan_id: str
    right_scan_id: str


class PolicyIn(BaseModel):
    yaml: str = Field(max_length=200_000)


class PolicyEvalIn(BaseModel):
    scan_id: str
    baseline_scan_id: str | None = None


class HypotheticalIn(BaseModel):
    base_scan_id: str
    name: str = Field(default="hypothetical change", max_length=200)
    operations: list[Operation] = Field(min_length=1, max_length=50)


class PlanCompareIn(BaseModel):
    scenario_ids: list[str] = Field(min_length=1, max_length=10)


class SettingsIn(BaseModel):
    default_enrichment: str | None = None
    retention_scans_per_project: int | None = Field(default=None, ge=1, le=1000)


# --- application state ------------------------------------------------------------------------------


class AppState:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.engine = db.make_engine(cfg.database_url)
        db.migrate(self.engine)
        self.Session = db.session_factory(self.engine)
        self.pool = ThreadPoolExecutor(max_workers=cfg.workers, thread_name_prefix="scan")
        self.cancel_flags: dict[str, threading.Event] = {}
        self._cache: OrderedDict[str, ScanResult] = OrderedDict()
        self._lock = threading.Lock()

    # scan JSON cache (results are immutable)
    def result(self, s: Session, scan_id: str) -> tuple[db.ScanRow, ScanResult]:
        row = s.get(db.ScanRow, scan_id)
        if row is None:
            raise _err(404, "not_found", f"scan {scan_id} not found")
        if row.result is None:
            raise _err(
                409, "scan_not_ready", f"scan is {row.state}; no result available", {"state": row.state}
            )
        with self._lock:
            hit = self._cache.get(scan_id)
            if hit is not None:
                self._cache.move_to_end(scan_id)
                return row, hit
        res = ScanResult.model_validate_json(row.result)
        with self._lock:
            self._cache[scan_id] = res
            while len(self._cache) > 32:
                self._cache.popitem(last=False)
        return row, res

    # settings
    def setting(self, s: Session, key: str, default: Any) -> Any:
        row = s.get(db.SettingRow, key)
        return json.loads(row.value) if row else default

    def set_setting(self, s: Session, key: str, value: Any) -> None:
        row = s.get(db.SettingRow, key)
        if row:
            row.value = json.dumps(value)
        else:
            s.add(db.SettingRow(key=key, value=json.dumps(value)))

    # advisory sources
    def fixtures(self) -> dict[str, Path]:
        root = self.cfg.repo_root
        if root is None:
            return {}
        return {p.stem: p for p in sorted((root / "fixtures" / "osv").glob("*.json"))}

    def enrichment_modes(self) -> list[dict[str, Any]]:
        modes = [
            {
                "id": "osv_cache",
                "label": "Offline — OSV cache only",
                "network": False,
                "description": "No network traffic. Packages without a cached OSV answer are NOT EVALUATED.",
            },
            {
                "id": "osv_live",
                "label": "Live OSV lookup",
                "network": True,
                "description": "Sends ecosystem, package name and version (nothing else) to api.osv.dev.",
            },
        ]
        for name, path in self.fixtures().items():
            try:
                meta = json.loads(path.read_text(encoding="utf-8"))
                sid, gen = meta.get("snapshot_id", name), str(meta.get("generated", ""))[:10]
            except (OSError, ValueError):
                continue
            modes.append(
                {
                    "id": f"fixture:{name}",
                    "label": f"Frozen snapshot · {sid} ({gen})",
                    "network": False,
                    "description": "Synthetic, frozen advisory snapshot for reproducible demos and tests.",
                }
            )
        return modes

    def validate_mode(self, mode: str) -> None:
        if mode not in {m["id"] for m in self.enrichment_modes()} and mode != "none":
            raise _err(400, "unknown_enrichment", f"unknown enrichment mode {mode!r}")

    def provider(self, mode: str):  # type: ignore[no-untyped-def]
        if mode == "osv_live":
            return OsvProvider(base_url=self.cfg.osv_url, cache_dir=self.cfg.cache_dir)
        if mode == "osv_cache":
            return OsvProvider(base_url=self.cfg.osv_url, cache_dir=self.cfg.cache_dir, offline=True)
        if mode.startswith("fixture:"):
            path = self.fixtures().get(mode.split(":", 1)[1])
            if path is None:
                raise _err(400, "unknown_enrichment", f"unknown advisory fixture {mode!r}")
            return FixtureProvider(path)
        if mode == "none":
            return NullProvider()
        raise _err(400, "unknown_enrichment", f"unknown enrichment mode {mode!r}")


# --- serialisation helpers ------------------------------------------------------------------------------


def _iso(dt) -> str | None:  # type: ignore[no-untyped-def]
    return dt.isoformat() + "Z" if dt else None


def scan_meta(row: db.ScanRow) -> dict[str, Any]:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "state": row.state,
        "label": row.label,
        "enrichment": row.enrichment,
        "inputs": json.loads(row.inputs or "[]"),
        "demo": row.demo,
        "error": row.error,
        "summary": json.loads(row.summary) if row.summary else None,
        "created_at": _iso(row.created_at),
        "started_at": _iso(row.started_at),
        "finished_at": _iso(row.finished_at),
    }


def summarize(res: ScanResult) -> dict[str, Any]:
    return {
        "severity": severity_counts(res),
        "findings": len(res.findings),
        "packages": res.coverage.total_packages,
        "coverage": res.coverage.model_dump(mode="json"),
        "advisory_source": res.advisory_source.model_dump(mode="json"),
        "checksum": res.checksum,
        "graph_complete": res.coverage.graph_complete,
        "warnings": len(res.warnings),
        "formats": [a.format for a in res.artifacts],
    }


def project_out(p: db.ProjectRow, s: Session) -> dict[str, Any]:
    scans = s.scalars(
        select(db.ScanRow).where(db.ScanRow.project_id == p.id).order_by(db.ScanRow.created_at.desc())
    ).all()
    latest = next((x for x in scans if x.state in {"completed", "partial"}), None)
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "demo": p.demo,
        "created_at": _iso(p.created_at),
        "scan_count": len(scans),
        "latest_scan": scan_meta(latest) if latest else None,
        "active_scan": scan_meta(scans[0])
        if scans and scans[0].state in {"queued", "parsing", "enriching", "analyzing"}
        else None,
    }


# --- app factory -----------------------------------------------------------------------------------------


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config()
    st = AppState(cfg)
    app = FastAPI(
        title="SupplyChain Radar API",
        version=__version__,
        description="Offline-first software supply chain security workbench.",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )
    app.state.st = st
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.allowed_hosts)

    @app.middleware("http")
    async def security(request: Request, call_next: Callable):  # type: ignore[no-untyped-def]
        if request.url.path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
            # Custom header forces a CORS preflight, which we never grant: blocks cross-site form posts.
            if request.headers.get("x-scradar-request") != "1":
                return JSONResponse(
                    {"error": {"code": "csrf", "message": "missing X-Scradar-Request header"}},
                    status_code=403,
                )
            if cfg.api_token and request.headers.get("authorization") != f"Bearer {cfg.api_token}":
                return JSONResponse(
                    {"error": {"code": "unauthorized", "message": "invalid or missing token"}},
                    status_code=401,
                )
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        if not request.url.path.startswith("/api/docs"):
            resp.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
        return resp

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_req: Request, exc: StarletteHTTPException):  # type: ignore[no-untyped-def]
        detail = (
            exc.detail if isinstance(exc.detail, dict) else {"code": "http_error", "message": str(exc.detail)}
        )
        return JSONResponse({"error": detail}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def unhandled(_req: Request, exc: Exception):  # type: ignore[no-untyped-def]
        return JSONResponse(
            {
                "error": {
                    "code": "internal_error",
                    "message": redact_str(f"{type(exc).__name__}: {exc}")[:300],
                }
            },
            status_code=500,
        )

    def session():  # type: ignore[no-untyped-def]
        with st.Session() as s:
            yield s

    r = APIRouter(prefix="/api/v1")

    # ---------------------------------------------------------------- meta
    @r.get("/health")
    def health(s: Session = Depends(session)) -> dict[str, Any]:
        s.execute(select(1))
        return {"status": "ok"}

    @r.get("/version")
    def version_() -> dict[str, Any]:
        return {"version": __version__, "engine": ENGINE_VERSION, "api": "v1"}

    @r.get("/providers/status")
    def providers(s: Session = Depends(session)) -> dict[str, Any]:
        cached = 0
        qdir = cfg.cache_dir / "query"
        if qdir.is_dir():
            cached = sum(1 for _ in qdir.glob("*.json"))
        return {
            "default_enrichment": st.setting(s, "default_enrichment", "osv_cache"),
            "modes": st.enrichment_modes(),
            "osv": {"base_url": cfg.osv_url, "cached_package_queries": cached, "follows_redirects": False},
            "scorecard": {
                "status": "not_implemented",
                "note": "OpenSSF Scorecard enrichment is not part of v1.0.",
            },
            "privacy": (
                "Imported files are parsed in memory and not stored; only the normalised inventory and results are kept. "
                "Network lookups happen only in 'Live OSV' mode and transmit ecosystem, package name and version."
            ),
            "auth": "token" if cfg.api_token else "loopback-only",
        }

    @r.get("/settings")
    def get_settings(s: Session = Depends(session)) -> dict[str, Any]:
        return {
            "default_enrichment": st.setting(s, "default_enrichment", "osv_cache"),
            "retention_scans_per_project": st.setting(s, "retention_scans_per_project", 50),
            "limits": {"max_upload_bytes": cfg.max_upload_bytes, "max_files": DEFAULT_LIMITS.max_files},
        }

    @r.put("/settings")
    def put_settings(body: SettingsIn, s: Session = Depends(session)) -> dict[str, Any]:
        if body.default_enrichment is not None:
            if body.default_enrichment not in {m["id"] for m in st.enrichment_modes()}:
                raise _err(400, "unknown_enrichment", "unknown enrichment mode")
            st.set_setting(s, "default_enrichment", body.default_enrichment)
        if body.retention_scans_per_project is not None:
            st.set_setting(s, "retention_scans_per_project", body.retention_scans_per_project)
        s.commit()
        return get_settings(s)

    # ---------------------------------------------------------------- overview
    @r.get("/overview")
    def overview(s: Session = Depends(session)) -> dict[str, Any]:
        projects = s.scalars(select(db.ProjectRow)).all()
        scans = s.scalars(select(db.ScanRow).order_by(db.ScanRow.created_at)).all()
        names = {p.id: p.name for p in projects}
        latest: dict[str, db.ScanRow] = {}
        for sc in scans:
            if sc.state in {"completed", "partial"}:
                latest[sc.project_id] = sc
        totals = {
            k: 0
            for k in (
                "packages",
                "evaluated",
                "cached",
                "not_evaluated",
                "unsupported",
                "error",
                "unresolved",
            )
        }
        sev = {x.value: 0 for x in Severity}
        for sc in latest.values():
            summ = json.loads(sc.summary or "{}")
            cov = summ.get("coverage", {})
            totals["packages"] += cov.get("total_packages", 0)
            for k in ("evaluated", "cached", "not_evaluated", "unsupported", "error", "unresolved"):
                totals[k] += cov.get(k, 0)
            for k, v in summ.get("severity", {}).items():
                sev[k] += v
        trend = []
        for sc in [x for x in scans if x.state in {"completed", "partial"}][-40:]:
            summ = json.loads(sc.summary or "{}")
            trend.append(
                {
                    "scan_id": sc.id,
                    "project_id": sc.project_id,
                    "project": names.get(sc.project_id),
                    "label": sc.label,
                    "created_at": _iso(sc.created_at),
                    "severity": summ.get("severity", {}),
                    "percent_evaluated": summ.get("coverage", {}).get("percent_evaluated"),
                    "snapshot": summ.get("advisory_source", {}).get("snapshot_id"),
                    "mode": summ.get("advisory_source", {}).get("mode"),
                    "demo": sc.demo,
                }
            )
        return {
            "projects": len(projects),
            "demo_projects": sum(1 for p in projects if p.demo),
            "scans": len(scans),
            "latest_scans": [dict(scan_meta(v), project=names.get(k)) for k, v in latest.items()],
            "totals": totals,
            "severity": sev,
            "trend": trend,
            "has_demo_data": any(p.demo for p in projects),
        }

    # ---------------------------------------------------------------- projects
    @r.get("/projects")
    def list_projects(s: Session = Depends(session)) -> list[dict[str, Any]]:
        rows = s.scalars(select(db.ProjectRow).order_by(db.ProjectRow.created_at.desc())).all()
        return [project_out(p, s) for p in rows]

    @r.post("/projects", status_code=201)
    def create_project(body: ProjectIn, s: Session = Depends(session)) -> dict[str, Any]:
        p = db.ProjectRow(id=str(uuid.uuid4()), name=body.name.strip(), description=body.description)
        s.add(p)
        s.commit()
        return project_out(p, s)

    def _project(s: Session, pid: str) -> db.ProjectRow:
        p = s.get(db.ProjectRow, pid)
        if p is None:
            raise _err(404, "not_found", f"project {pid} not found")
        return p

    @r.get("/projects/{project_id}")
    def get_project(project_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        return project_out(_project(s, project_id), s)

    @r.delete("/projects/{project_id}", status_code=204)
    def delete_project(project_id: str, s: Session = Depends(session)) -> Response:
        s.delete(_project(s, project_id))
        s.commit()
        return Response(status_code=204)

    @r.get("/projects/{project_id}/scans")
    def project_scans(project_id: str, s: Session = Depends(session)) -> list[dict[str, Any]]:
        _project(s, project_id)
        rows = s.scalars(
            select(db.ScanRow)
            .where(db.ScanRow.project_id == project_id)
            .order_by(db.ScanRow.created_at.desc())
        ).all()
        return [scan_meta(x) for x in rows]

    @r.get("/projects/{project_id}/timeline")
    def timeline(project_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        _project(s, project_id)
        rows = s.scalars(
            select(db.ScanRow)
            .where(db.ScanRow.project_id == project_id, db.ScanRow.state.in_(("completed", "partial")))
            .order_by(db.ScanRow.created_at)
        ).all()
        points, deltas = [], []
        prev: ScanResult | None = None
        for row in rows[-30:]:
            _, res = st.result(s, row.id)
            points.append(dict(scan_meta(row)))
            if prev is not None:
                cmp = compare_scans(prev, res)
                deltas.append(
                    {
                        "left": prev.scan_id,
                        "right": res.scan_id,
                        "counts": cmp.counts,
                        "package_counts": cmp.package_counts,
                        "advisory_source_changed": cmp.advisory_source_changed,
                    }
                )
            prev = res
        return {"points": points, "deltas": deltas}

    # ---------------------------------------------------------------- imports / scans
    def _queue_scan(
        s: Session,
        project: db.ProjectRow,
        files: list[tuple[str, bytes]],
        enrichment: str,
        label: str | None,
        demo: bool = False,
        idem: str | None = None,
    ) -> db.ScanRow:
        st.validate_mode(enrichment)
        row = db.ScanRow(
            id=str(uuid.uuid4()),
            project_id=project.id,
            state="queued",
            label=label,
            enrichment=enrichment,
            demo=demo or project.demo,
            idempotency_key=idem,
            inputs=json.dumps(
                [
                    {"name": redact(n), "size": len(b), "sha256": hashlib.sha256(b).hexdigest()}
                    for n, b in files
                ]
            ),
        )
        s.add(row)
        s.commit()
        flag = threading.Event()
        st.cancel_flags[row.id] = flag
        st.pool.submit(_run_scan, row.id, project.name, files, enrichment, label, row.demo, flag)
        return row

    def _set(scan_id: str, **kw: Any) -> None:
        with st.Session() as s2:
            row = s2.get(db.ScanRow, scan_id)
            if row is None:
                return
            for k, v in kw.items():
                setattr(row, k, v)
            s2.commit()

    def _run_scan(
        scan_id: str,
        project_name: str,
        files: list[tuple[str, bytes]],
        enrichment: str,
        label: str | None,
        demo: bool,
        flag: threading.Event,
    ) -> None:
        try:
            _set(scan_id, state="parsing", started_at=db.now())
            invs, errors = [], []
            pyprojects = {
                n.rsplit("/", 1)[0] if "/" in n else "": b for n, b in files if n.endswith("pyproject.toml")
            }
            for name, blob in files:
                if name.endswith("pyproject.toml"):
                    continue
                try:
                    if name.lower().endswith(".zip"):
                        res = import_zip(blob)
                        invs.extend(res.inventories)
                        errors.extend(res.errors)
                    else:
                        folder = name.rsplit("/", 1)[0] if "/" in name else ""
                        invs.append(parse_file(name, blob, pyproject=pyprojects.get(folder), label=name))
                except IngestError as exc:
                    errors.append(f"{name}: {exc}")
            if errors and not invs:
                raise IngestError("; ".join(errors))
            if flag.is_set():
                _set(scan_id, state="cancelled", finished_at=db.now())
                return
            provider = st.provider(enrichment)
            result = analyze(
                invs,
                provider,
                project=project_name,
                label=label,
                demo=demo,
                scan_id=scan_id,
                cancelled=flag.is_set,
                on_stage=lambda stage: _set(scan_id, state=stage),
            )
            if hasattr(provider, "close"):
                provider.close()
            if flag.is_set():
                _set(scan_id, state="cancelled", finished_at=db.now())
                return
            result.warnings = [*(f"import problem: {e}" for e in errors), *result.warnings]
            cov = result.coverage
            partial = bool(errors) or cov.error > 0 or cov.not_evaluated > 0
            _set(
                scan_id,
                state="partial" if partial else "completed",
                result=result.model_dump_json(),
                summary=json.dumps(summarize(result)),
                finished_at=db.now(),
                error="; ".join(errors) if errors else None,
            )
            _apply_retention(scan_id)
        except IngestError as exc:
            _set(scan_id, state="failed", error=redact_str(str(exc))[:2000], finished_at=db.now())
        except Exception as exc:  # noqa: BLE001
            _set(
                scan_id,
                state="failed",
                error=redact_str(f"{type(exc).__name__}: {exc}")[:2000],
                finished_at=db.now(),
            )
        finally:
            st.cancel_flags.pop(scan_id, None)

    def _apply_retention(scan_id: str) -> None:
        with st.Session() as s2:
            row = s2.get(db.ScanRow, scan_id)
            if row is None:
                return
            keep = int(st.setting(s2, "retention_scans_per_project", 50))
            rows = s2.scalars(
                select(db.ScanRow)
                .where(db.ScanRow.project_id == row.project_id)
                .order_by(db.ScanRow.created_at.desc())
            ).all()
            for old in rows[keep:]:
                s2.delete(old)
            s2.commit()

    @r.post("/projects/{project_id}/imports", status_code=202)
    async def create_import(
        project_id: str,
        files: list[UploadFile] = File(...),
        enrichment: str | None = Form(default=None),
        label: str | None = Form(default=None),
        idempotency_key: str | None = Header(default=None),
        s: Session = Depends(session),
    ) -> dict[str, Any]:
        project = _project(s, project_id)
        if idempotency_key:
            existing = s.scalars(
                select(db.ScanRow).where(
                    db.ScanRow.project_id == project_id, db.ScanRow.idempotency_key == idempotency_key
                )
            ).first()
            if existing:
                return scan_meta(existing)
        if not files or len(files) > DEFAULT_LIMITS.max_files:
            raise _err(400, "bad_upload", f"upload between 1 and {DEFAULT_LIMITS.max_files} files")
        blobs: list[tuple[str, bytes]] = []
        total = 0
        for f in files:
            data = await f.read(cfg.max_upload_bytes + 1)
            if len(data) > cfg.max_upload_bytes:
                raise _err(413, "too_large", f"{f.filename}: larger than {cfg.max_upload_bytes} bytes")
            total += len(data)
            if total > DEFAULT_LIMITS.max_total_bytes:
                raise _err(413, "too_large", "total upload size exceeds the limit")
            name = (f.filename or "upload").replace("\\", "/")
            parts = [p for p in name.split("/") if p not in {"", ".", ".."}]
            blobs.append(("/".join(parts[-4:]) or "upload", data))
        mode = enrichment or st.setting(s, "default_enrichment", "osv_cache")
        row = _queue_scan(s, project, blobs, mode, label, idem=idempotency_key)
        return scan_meta(row)

    @r.get("/scans/{scan_id}")
    def get_scan(scan_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        row = s.get(db.ScanRow, scan_id)
        if row is None:
            raise _err(404, "not_found", f"scan {scan_id} not found")
        out = scan_meta(row)
        if row.result:
            _, res = st.result(s, scan_id)
            out["artifacts"] = [a.model_dump(mode="json") for a in res.artifacts]
            out["warnings"] = res.warnings
            out["limitations"] = res.limitations
            out["checksum"] = res.checksum
            out["engine_version"] = res.engine_version
            out["graph"] = DependencyGraph({c.id: c for c in res.components}, res.edges).analysis()
            states: dict[str, int] = {}
            for e in res.evaluations:
                states[e.state.value] = states.get(e.state.value, 0) + 1
            out["evaluation_states"] = states
        return out

    @r.post("/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        row = s.get(db.ScanRow, scan_id)
        if row is None:
            raise _err(404, "not_found", "scan not found")
        flag = st.cancel_flags.get(scan_id)
        if flag is None or row.state not in {"queued", "parsing", "enriching", "analyzing"}:
            raise _err(409, "not_cancellable", f"scan is {row.state}")
        flag.set()
        return {"id": scan_id, "cancel_requested": True}

    # ---------------------------------------------------------------- components & graph
    def _sev_by_component(res: ScanResult) -> dict[str, tuple[str, int]]:
        out: dict[str, tuple[str, int]] = {}
        for f in res.findings:
            lvl, n = out.get(f.component_id, ("unknown", 0))
            best = (
                f.advisory.severity.level.value
                if Severity(f.advisory.severity.level).rank >= Severity(lvl).rank or n == 0
                else lvl
            )
            out[f.component_id] = (best, n + 1)
        return out

    @r.get("/scans/{scan_id}/components")
    def components(
        scan_id: str,
        q: str | None = None,
        ecosystem: str | None = None,
        scope: str | None = None,
        state: str | None = None,
        vulnerable: bool | None = None,
        direct: bool | None = None,
        license: str | None = None,
        sort: Literal["name", "severity", "depth"] = "name",
        page: int = Query(1, ge=1),
        page_size: int = Query(100, ge=1, le=500),
        s: Session = Depends(session),
    ) -> dict[str, Any]:
        _, res = st.result(s, scan_id)
        graph = DependencyGraph({c.id: c for c in res.components}, res.edges)
        depths = graph.depths()
        sev = _sev_by_component(res)
        evals = {e.component_id: e for e in res.evaluations}
        items = []
        for c in res.components:
            if c.kind != "package":
                continue
            ev = evals.get(c.id)
            st_ = ev.state.value if ev else ("first_party" if c.source == "workspace" else "not_evaluated")
            lvl, n = sev.get(c.id, (None, 0))
            if q and q.lower() not in c.name.lower() and q.lower() not in (c.purl or "").lower():
                continue
            if ecosystem and c.ecosystem != ecosystem:
                continue
            if scope and scope not in c.scopes:
                continue
            if state and st_ != state:
                continue
            if vulnerable is not None and (n > 0) != vulnerable:
                continue
            if direct is not None and c.direct != direct:
                continue
            if license and not any(license.lower() in x.lower() for x in c.licenses):
                continue
            items.append(
                {
                    "id": c.id,
                    "name": c.name,
                    "version": c.version,
                    "ecosystem": c.ecosystem,
                    "purl": c.purl,
                    "declared": c.declared,
                    "resolved": c.resolved,
                    "direct": c.direct,
                    "scopes": c.scopes,
                    "licenses": c.licenses,
                    "source": c.source,
                    "state": st_,
                    "state_note": ev.note if ev else c.unsupported_reason,
                    "advisories": n,
                    "max_severity": lvl,
                    "depth": depths.get(c.id),
                    "parents": len(graph.parents.get(c.id, [])),
                }
            )
        if sort == "severity":
            items.sort(
                key=lambda x: (
                    -(Severity(str(x["max_severity"])).rank if x["max_severity"] else -1),
                    x["name"],
                )
            )
        elif sort == "depth":
            items.sort(key=lambda x: (x["depth"] if x["depth"] is not None else 999, x["name"]))
        else:
            items.sort(key=lambda x: (x["name"], x["version"] or ""))
        total = len(items)
        start = (page - 1) * page_size
        ecosystems = sorted({c.ecosystem for c in res.components if c.kind == "package"})
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": items[start : start + page_size],
            "ecosystems": ecosystems,
        }

    @r.get("/scans/{scan_id}/components/{component_id:path}")
    def component_detail(scan_id: str, component_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        _, res = st.result(s, scan_id)
        comps = res.component_map()
        c = comps.get(component_id)
        if c is None:
            raise _err(404, "not_found", "component not in scan")
        graph = DependencyGraph(comps, res.edges)
        paths = graph.paths_to(component_id, max_paths=50)
        ev = next((e for e in res.evaluations if e.component_id == component_id), None)

        def edge_out(e, other):  # type: ignore[no-untyped-def]
            o = comps.get(other)
            return {
                "id": other,
                "name": o.name if o else other,
                "version": o.version if o else None,
                "type": e.type.value,
                "constraint": e.constraint,
                "confidence": e.confidence,
                "provenance": e.provenance.model_dump() if e.provenance else None,
            }

        return {
            "component": c.model_dump(mode="json"),
            "evaluation": ev.model_dump(mode="json") if ev else None,
            "paths": paths.model_dump(mode="json"),
            "parents": [edge_out(e, e.parent) for e in graph.parents.get(component_id, [])],
            "children": [edge_out(e, e.child) for e in graph.children.get(component_id, [])],
            "findings": [f.model_dump(mode="json") for f in res.findings if f.component_id == component_id],
            "names": {n: _label(comps, n) for p in paths.paths for n in p.nodes},
        }

    def _label(comps, cid):  # type: ignore[no-untyped-def]
        c = comps.get(cid)
        if c is None:
            return cid
        return c.name if (c.id == ROOT_ID or not c.version) else f"{c.name}@{c.version}"

    @r.get("/scans/{scan_id}/graph")
    def graph_view(
        scan_id: str,
        mode: Literal["vulnerable", "full", "focus"] = "vulnerable",
        focus: str | None = None,
        limit: int = Query(800, ge=10, le=5000),
        s: Session = Depends(session),
    ) -> dict[str, Any]:
        _, res = st.result(s, scan_id)
        comps = res.component_map()
        graph = DependencyGraph(comps, res.edges)
        depths = graph.depths()
        sev = _sev_by_component(res)
        evals = {e.component_id: e.state.value for e in res.evaluations}
        truncated = False
        note = None
        if mode == "focus":
            if not focus or focus not in comps:
                raise _err(400, "bad_focus", "focus component is required for mode=focus")
            nodes, edges = graph.subgraph_for([focus], max_paths=30)
            for e in graph.children.get(focus, []):
                nodes.add(e.child)
                edges.append(e)
            nodes.add(focus)
        elif mode == "vulnerable":
            targets = sorted({f.component_id for f in res.findings})
            nodes, edges = graph.subgraph_for(targets, max_paths=10)
            nodes.add(ROOT_ID)
            for e in graph.children.get(ROOT_ID, []):
                nodes.add(e.child)
                edges.append(e)
            note = "Showing the application, its direct dependencies and every path to a vulnerable package."
        else:
            nodes = set(comps)
            edges = list(graph.edges)
            if len(nodes) > limit:
                truncated = True
                keep = sorted(nodes, key=lambda n: (depths.get(n, 999), n))[:limit]
                nodes = set(keep)
                note = f"Graph has {len(comps)} nodes; showing the {limit} closest to the root. Use search or focus mode."
        edges = [e for e in edges if e.parent in nodes and e.child in nodes]
        uniq = {(e.parent, e.child, e.type.value): e for e in edges}
        return {
            "mode": mode,
            "truncated": truncated,
            "note": note,
            "total_nodes": len(comps),
            "analysis": graph.analysis(),
            "nodes": [
                {
                    "id": n,
                    "label": comps[n].name,
                    "version": comps[n].version,
                    "ecosystem": comps[n].ecosystem,
                    "kind": comps[n].kind,
                    "depth": depths.get(n),
                    "scopes": comps[n].scopes,
                    "direct": comps[n].direct,
                    "source": comps[n].source,
                    "state": evals.get(n),
                    "severity": sev.get(n, (None, 0))[0],
                    "findings": sev.get(n, (None, 0))[1],
                }
                for n in sorted(nodes)
                if n in comps
            ],
            "edges": [
                {
                    "id": f"{e.parent}->{e.child}:{e.type.value}",
                    "source": e.parent,
                    "target": e.child,
                    "type": e.type.value,
                    "constraint": e.constraint,
                    "confidence": e.confidence,
                    "provenance": e.provenance.model_dump() if e.provenance else None,
                }
                for e in uniq.values()
            ],
        }

    # ---------------------------------------------------------------- findings & triage
    def _triage_map(s: Session, project_id: str) -> dict[str, db.TriageRow]:
        return {
            t.fingerprint: t
            for t in s.scalars(select(db.TriageRow).where(db.TriageRow.project_id == project_id)).all()
        }

    def _triage_out(t: db.TriageRow | None) -> dict[str, Any]:
        if t is None:
            return {"status": "open", "expired": False}
        expired = (
            t.expires is not None
            and t.expires < date.today()
            and t.status in {"accepted_risk", "false_positive", "not_affected"}
        )
        return {
            "status": t.status,
            "rationale": t.rationale,
            "expires": t.expires.isoformat() if t.expires else None,
            "author": t.author,
            "evidence": t.evidence,
            "updated_at": _iso(t.updated_at),
            "expired": expired,
        }

    @r.get("/scans/{scan_id}/findings")
    def findings(
        scan_id: str,
        severity: str | None = None,
        q: str | None = None,
        scope: str | None = None,
        status: str | None = None,
        direct: bool | None = None,
        s: Session = Depends(session),
    ) -> dict[str, Any]:
        row, res = st.result(s, scan_id)
        triage = _triage_map(s, row.project_id)
        comps = res.component_map()
        items = []
        for f in res.findings:
            t = _triage_out(triage.get(f.fingerprint))
            if severity and f.advisory.severity.level.value not in severity.split(","):
                continue
            if q and not any(
                q.lower() in x.lower()
                for x in [f.package, f.advisory.id, *f.advisory.aliases, f.advisory.summary or ""]
            ):
                continue
            if scope and scope not in f.scopes:
                continue
            if status and t["status"] != status:
                continue
            if direct is not None and f.direct != direct:
                continue
            d = f.model_dump(mode="json")
            d["id"] = f"{scan_id}~{f.fingerprint}"
            d["triage"] = t
            d["path_labels"] = [[_label(comps, n) for n in p.nodes] for p in f.paths.paths[:3]]
            items.append(d)
        return {"total": len(items), "items": items, "coverage": res.coverage.model_dump(mode="json")}

    def _split_finding(finding_id: str) -> tuple[str, str]:
        if "~" not in finding_id:
            raise _err(400, "bad_finding_id", "finding id must be '<scan_id>~<fingerprint>'")
        a, b = finding_id.split("~", 1)
        return a, b

    @r.get("/findings/{finding_id}")
    def finding_detail(finding_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        scan_id, fp = _split_finding(finding_id)
        row, res = st.result(s, scan_id)
        f = next((x for x in res.findings if x.fingerprint == fp), None)
        if f is None:
            raise _err(404, "not_found", "finding not in scan")
        comps = res.component_map()
        t = s.scalars(
            select(db.TriageRow).where(
                db.TriageRow.project_id == row.project_id, db.TriageRow.fingerprint == fp
            )
        ).first()
        hist = s.scalars(
            select(db.TriageEventRow)
            .where(db.TriageEventRow.project_id == row.project_id, db.TriageEventRow.fingerprint == fp)
            .order_by(db.TriageEventRow.at.desc())
        ).all()
        fix = next((x for x in suggest_fixes(res) if x.fingerprint == fp), None)
        d = f.model_dump(mode="json")
        d["id"] = finding_id
        d["triage"] = _triage_out(t)
        d["triage_history"] = [
            {
                "from": h.from_status,
                "to": h.to_status,
                "rationale": h.rationale,
                "expires": h.expires.isoformat() if h.expires else None,
                "author": h.author,
                "at": _iso(h.at),
            }
            for h in hist
        ]
        d["fix"] = fix.model_dump() if fix else None
        d["names"] = {n: _label(comps, n) for p in f.paths.paths for n in p.nodes} | {
            i: _label(comps, i) for i in f.paths.introducers
        }
        d["scan"] = {
            "id": scan_id,
            "created_at": res.created_at,
            "demo": res.demo,
            "advisory_source": res.advisory_source.model_dump(mode="json"),
        }
        return d

    @r.patch("/findings/{finding_id}/triage")
    def triage_finding(finding_id: str, body: TriageIn, s: Session = Depends(session)) -> dict[str, Any]:
        scan_id, fp = _split_finding(finding_id)
        row, res = st.result(s, scan_id)
        f = next((x for x in res.findings if x.fingerprint == fp), None)
        if f is None:
            raise _err(404, "not_found", "finding not in scan")
        if body.status in {"accepted_risk", "false_positive", "not_affected"} and body.expires is None:
            raise _err(422, "expiry_required", "suppressing statuses require an expiry date")
        if body.expires is not None and body.expires < date.today():
            raise _err(422, "expiry_in_past", "expiry must not be in the past")
        t = s.scalars(
            select(db.TriageRow).where(
                db.TriageRow.project_id == row.project_id, db.TriageRow.fingerprint == fp
            )
        ).first()
        prev = t.status if t else None
        if t is None:
            t = db.TriageRow(
                project_id=row.project_id,
                fingerprint=fp,
                advisory_id=f.advisory.id,
                package=f.package,
                status=body.status,
                rationale=body.rationale,
            )
            s.add(t)
        t.status, t.rationale, t.expires, t.author, t.evidence, t.updated_at = (
            body.status,
            body.rationale,
            body.expires,
            body.author,
            body.evidence,
            db.now(),
        )
        s.add(
            db.TriageEventRow(
                project_id=row.project_id,
                fingerprint=fp,
                from_status=prev,
                to_status=body.status,
                rationale=body.rationale,
                expires=body.expires,
                author=body.author,
            )
        )
        s.commit()
        return finding_detail(finding_id, s)

    # ---------------------------------------------------------------- comparison
    def _same_project(s: Session, a: str, b: str) -> tuple[ScanResult, ScanResult]:
        ra, la = st.result(s, a)
        rb, lb = st.result(s, b)
        if ra.project_id != rb.project_id:
            raise _err(400, "different_projects", "both scans must belong to the same project")
        return la, lb

    @r.post("/scans/compare")
    def compare(body: CompareIn, s: Session = Depends(session)) -> dict[str, Any]:
        left, right = _same_project(s, body.left_scan_id, body.right_scan_id)
        return compare_scans(left, right).model_dump(mode="json")

    @r.get("/scans/compare/report")
    def compare_report(left: str, right: str, s: Session = Depends(session)) -> Response:
        a, b = _same_project(s, left, right)
        html = comparison_to_html(compare_scans(a, b))
        return Response(
            html,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="scradar-compare-{left[:8]}-{right[:8]}.html"'
            },
        )

    # ---------------------------------------------------------------- remediation
    @r.get("/scans/{scan_id}/fixes")
    def fixes(scan_id: str, s: Session = Depends(session)) -> list[dict[str, Any]]:
        _, res = st.result(s, scan_id)
        comps = res.component_map()
        out = []
        for fx in suggest_fixes(res):
            d = fx.model_dump()
            d["introducer_labels"] = [_label(comps, i) for i in fx.introducers]
            out.append(d)
        return out

    def _store_scenario(s: Session, project_id: str, outcome: ScenarioOutcome) -> dict[str, Any]:
        s.add(
            db.ScenarioRow(
                id=outcome.id,
                project_id=project_id,
                base_scan_id=outcome.base_scan_id,
                name=outcome.name,
                mode=outcome.mode,
                status=outcome.status,
                outcome=outcome.model_dump_json(),
            )
        )
        s.commit()
        return outcome.model_dump(mode="json")

    @r.post("/remediation/scenarios", status_code=201)
    def hypothetical(body: HypotheticalIn, s: Session = Depends(session)) -> dict[str, Any]:
        row, base = st.result(s, body.base_scan_id)
        outcome, _ = simulate_hypothetical(base, body.operations, st.provider(row.enrichment), name=body.name)
        return _store_scenario(s, row.project_id, outcome)

    @r.post("/remediation/scenarios/candidate", status_code=201)
    async def candidate(
        base_scan_id: str = Form(...),
        name: str = Form(default="candidate lockfile"),
        files: list[UploadFile] = File(...),
        s: Session = Depends(session),
    ) -> dict[str, Any]:
        row, base = st.result(s, base_scan_id)
        invs = []
        for f in files[: DEFAULT_LIMITS.max_files]:
            data = await f.read(cfg.max_upload_bytes + 1)
            if len(data) > cfg.max_upload_bytes:
                raise _err(413, "too_large", "candidate file too large")
            fname = (f.filename or "candidate").replace("\\", "/").rsplit("/", 1)[-1]
            try:
                if fname.lower().endswith(".zip"):
                    invs.extend(import_zip(data).inventories)
                else:
                    invs.append(parse_file(fname, data, label=fname))
            except IngestError as exc:
                raise _err(400, "invalid_input", f"{fname}: {exc}") from exc
        if not invs:
            raise _err(400, "invalid_input", "no supported candidate files")
        outcome, _ = simulate_candidate(base, invs, st.provider(row.enrichment), name=name[:200])
        return _store_scenario(s, row.project_id, outcome)

    @r.get("/remediation/scenarios/{scenario_id}")
    def get_scenario(scenario_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        row = s.get(db.ScenarioRow, scenario_id)
        if row is None:
            raise _err(404, "not_found", "scenario not found")
        return json.loads(row.outcome)

    @r.get("/projects/{project_id}/scenarios")
    def list_scenarios(project_id: str, s: Session = Depends(session)) -> list[dict[str, Any]]:
        _project(s, project_id)
        rows = s.scalars(
            select(db.ScenarioRow)
            .where(db.ScenarioRow.project_id == project_id)
            .order_by(db.ScenarioRow.created_at.desc())
        ).all()
        return [json.loads(x.outcome) for x in rows]

    @r.post("/remediation/compare")
    def plan_compare(body: PlanCompareIn, s: Session = Depends(session)) -> list[dict[str, Any]]:
        outs = []
        for sid in body.scenario_ids:
            row = s.get(db.ScenarioRow, sid)
            if row is None:
                raise _err(404, "not_found", f"scenario {sid} not found")
            outs.append(ScenarioOutcome.model_validate_json(row.outcome))
        return compare_plans(outs)

    # ---------------------------------------------------------------- policies
    def _policy_text(s: Session, project_id: str) -> tuple[str, int, bool]:
        row = s.get(db.PolicyRow, project_id)
        return (row.yaml, row.version, False) if row else (DEFAULT_POLICY, 0, True)

    def _exceptions(s: Session, project_id: str) -> list[ExceptionEntry]:
        out = []
        for t in _triage_map(s, project_id).values():
            if t.status in {"accepted_risk", "false_positive", "not_affected"}:
                out.append(
                    ExceptionEntry(
                        fingerprint=t.fingerprint,
                        status=t.status,  # type: ignore[arg-type]
                        rationale=t.rationale,
                        expires=t.expires,
                        author=t.author,
                    )  # type: ignore[arg-type]
                )
        return out

    @r.get("/projects/{project_id}/policies")
    def get_policy(project_id: str, s: Session = Depends(session)) -> dict[str, Any]:
        _project(s, project_id)
        text_, ver, default = _policy_text(s, project_id)
        return {"yaml": text_, "version": ver, "is_default": default}

    @r.post("/policies/validate")
    def validate_policy(body: PolicyIn) -> dict[str, Any]:
        try:
            pol = load_policy(body.yaml)
        except PolicyError as exc:
            return {"valid": False, "error": str(exc)}
        return {
            "valid": True,
            "name": pol.name,
            "rules": len(pol.rules),
            "unknown_data": pol.unknown_data.mode,
        }

    @r.put("/projects/{project_id}/policies")
    def put_policy(project_id: str, body: PolicyIn, s: Session = Depends(session)) -> dict[str, Any]:
        _project(s, project_id)
        try:
            load_policy(body.yaml)
        except PolicyError as exc:
            raise _err(422, "invalid_policy", str(exc)) from exc
        row = s.get(db.PolicyRow, project_id)
        if row:
            row.yaml, row.version, row.updated_at = body.yaml, row.version + 1, db.now()
        else:
            row = db.PolicyRow(project_id=project_id, yaml=body.yaml, version=1)
            s.add(row)
        s.commit()
        return {"yaml": row.yaml, "version": row.version, "is_default": False}

    @r.post("/projects/{project_id}/policies/evaluate")
    def eval_policy(project_id: str, body: PolicyEvalIn, s: Session = Depends(session)) -> dict[str, Any]:
        _project(s, project_id)
        row, res = st.result(s, body.scan_id)
        if row.project_id != project_id:
            raise _err(400, "different_projects", "scan does not belong to project")
        base = st.result(s, body.baseline_scan_id)[1] if body.baseline_scan_id else None
        try:
            pol = load_policy(_policy_text(s, project_id)[0])
            out = evaluate_policy(pol, res, baseline=base, extra_exceptions=_exceptions(s, project_id))
        except PolicyError as exc:
            raise _err(422, "policy_error", str(exc)) from exc
        return out.model_dump(mode="json")

    # ---------------------------------------------------------------- reports
    @r.get("/scans/{scan_id}/reports")
    def reports(
        scan_id: str,
        format: str = Query("json"),
        include_policy: bool = False,
        s: Session = Depends(session),
    ) -> Response:
        if format not in FORMATS:
            raise _err(400, "bad_format", f"format must be one of {', '.join(FORMATS)}")
        row, res = st.result(s, scan_id)
        pres = None
        if include_policy:
            try:
                pres = evaluate_policy(
                    load_policy(_policy_text(s, row.project_id)[0]),
                    res,
                    extra_exceptions=_exceptions(s, row.project_id),
                )
            except PolicyError:
                pres = None
        body = render(res, format, policy=pres)
        ext, media = {
            "json": ("json", "application/json"),
            "markdown": ("md", "text/markdown"),
            "html": ("html", "text/html"),
            "sarif": ("sarif", "application/sarif+json"),
            "cyclonedx": ("cdx.json", "application/vnd.cyclonedx+json"),
        }[format]
        return Response(
            body,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="scradar-{scan_id[:8]}.{ext}"'},
        )

    # ---------------------------------------------------------------- demo data
    @r.post("/demo", status_code=201)
    def load_demo(s: Session = Depends(session)) -> dict[str, Any]:
        root = cfg.repo_root
        if root is None:
            raise _err(503, "demo_unavailable", "demo examples are not available in this installation")
        snaps = st.fixtures()
        if "frozen-advisories" not in snaps or "frozen-advisories-later" not in snaps:
            raise _err(503, "demo_unavailable", "demo advisory snapshots are missing")
        ex = root / "examples"

        def files(*rel: str) -> list[tuple[str, bytes]]:
            return [(r_.split("/", 1)[1] if "/" in r_ else r_, (ex / r_).read_bytes()) for r_ in rel]

        created = []
        p1 = db.ProjectRow(
            id=str(uuid.uuid4()),
            name="Demo · npm storefront",
            description="Synthetic npm project: release 1.0 → advisory refresh → release 1.1. Demo data only.",
            demo=True,
        )
        p2 = db.ProjectRow(
            id=str(uuid.uuid4()),
            name="Demo · Python services",
            description="Synthetic Poetry service plus a partially pinned requirements.txt. Demo data only.",
            demo=True,
        )
        p3 = db.ProjectRow(
            id=str(uuid.uuid4()),
            name="Demo · pnpm monorepo",
            description="Synthetic pnpm workspace with a shared transitive dependency. Demo data only.",
            demo=True,
        )
        s.add_all([p1, p2, p3])
        s.commit()
        s.add(
            db.PolicyRow(
                project_id=p1.id, yaml=(ex / "policy-strict.yaml").read_text(encoding="utf-8"), version=1
            )
        )
        s.commit()
        plan = [
            (p1, files("npm-vulnerable/package-lock.json"), "fixture:frozen-advisories", "release 1.0"),
            (
                p1,
                files("npm-vulnerable/package-lock.json"),
                "fixture:frozen-advisories-later",
                "release 1.0 · advisory refresh",
            ),
            (p1, files("npm-remediated/package-lock.json"), "fixture:frozen-advisories-later", "release 1.1"),
            (
                p2,
                files(
                    "poetry-vulnerable/poetry.lock",
                    "poetry-vulnerable/pyproject.toml",
                    "requirements-partial/requirements.txt",
                ),
                "fixture:frozen-advisories",
                "main",
            ),
            (p3, files("pnpm-monorepo/pnpm-lock.yaml"), "fixture:frozen-advisories", "main"),
        ]
        for proj, fl, mode, label in plan:
            row = _queue_scan(s, proj, fl, mode, label, demo=True)
            created.append(row.id)
        return {"projects": [p1.id, p2.id, p3.id], "scans": created}

    app.include_router(r)

    # ---------------------------------------------------------------- static UI
    static = cfg.static_dir
    if static is None and cfg.repo_root is not None and (cfg.repo_root / "frontend" / "dist").is_dir():
        static = cfg.repo_root / "frontend" / "dist"
    if static is not None and static.is_dir():
        static_root = static.resolve()

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str) -> Response:
            if full_path.startswith("api/"):
                raise _err(404, "not_found", "unknown API route")
            candidate = (static_root / full_path).resolve()
            if full_path and candidate.is_file() and static_root in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(static_root / "index.html")

    return app


__all__ = ["create_app", "Config", "EVALUATED_STATES", "QueryState"]
