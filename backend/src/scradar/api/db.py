"""SQLite persistence (SQLAlchemy 2). Scan results are stored as immutable JSON snapshots."""

from __future__ import annotations

import os
from datetime import UTC, date, datetime
from pathlib import Path

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

SCHEMA_VERSION = 1


def now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class ProjectRow(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(20), default="queued")
    label: Mapped[str | None] = mapped_column(String(200), nullable=True)
    enrichment: Mapped[str] = mapped_column(String(40))
    inputs: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of {name, size, sha256}
    idempotency_key: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    demo: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    result: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON ScanResult (immutable)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class TriageRow(Base):
    __tablename__ = "triage"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    advisory_id: Mapped[str] = mapped_column(String(100))
    package: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(30))
    rationale: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires: Mapped[date | None] = mapped_column(Date, nullable=True)
    author: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class TriageEventRow(Base):
    __tablename__ = "triage_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    from_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_status: Mapped[str] = mapped_column(String(30))
    rationale: Mapped[str] = mapped_column(Text)
    expires: Mapped[date | None] = mapped_column(Date, nullable=True)
    author: Mapped[str | None] = mapped_column(String(200), nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=now)


class PolicyRow(Base):
    __tablename__ = "policies"
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    yaml: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class ScenarioRow(Base):
    __tablename__ = "scenarios"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    base_scan_id: Mapped[str] = mapped_column(String(36))
    name: Mapped[str] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(40))
    outcome: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class SettingRow(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class MetaRow(Base):
    __tablename__ = "schema_meta"
    key: Mapped[str] = mapped_column(String(50), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))


MIGRATIONS: dict[int, list[str]] = {
    # version -> SQL statements applied after create_all() for upgrades of existing databases.
    1: [],
}


def make_engine(url: str | None = None):  # type: ignore[no-untyped-def]
    if url is None:
        data_dir = Path(
            os.environ.get("SCRADAR_DATA_DIR", Path.home() / ".local" / "share" / "supplychain-radar")
        )
        data_dir.mkdir(parents=True, exist_ok=True)
        url = f"sqlite:///{(data_dir / 'scradar.db').as_posix()}"
    engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _rec):  # type: ignore[no-untyped-def]
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()

    return engine


def migrate(engine) -> int:  # type: ignore[no-untyped-def]
    """Create tables and apply ordered migrations; returns the resulting schema version."""

    Base.metadata.create_all(engine)
    with Session(engine) as s:
        row = s.get(MetaRow, "schema_version")
        current = int(row.value) if row else 0
        for v in sorted(MIGRATIONS):
            if v > current:
                for stmt in MIGRATIONS[v]:
                    s.execute(text(stmt))
                current = v
        if row:
            row.value = str(current)
        else:
            s.add(MetaRow(key="schema_version", value=str(current)))
        s.commit()
    return current


def session_factory(engine):  # type: ignore[no-untyped-def]
    return sessionmaker(engine, expire_on_commit=False)
