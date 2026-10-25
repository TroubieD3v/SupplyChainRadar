# ADR 0001 — SQLite persistence and an in-process job runner

*Status: accepted for v1.0.*

## Context
The brief suggested PostgreSQL + Alembic and Redis-backed workers. SupplyChain Radar v1.0 is a local, single-user workbench bound to loopback; a scan takes seconds and its inputs are already in memory.

## Decision
* Persist with SQLAlchemy 2 on **SQLite** (WAL, foreign keys on). `SCRADAR_DATABASE_URL` accepts another SQLAlchemy URL, but only SQLite is tested — we make no claim about PostgreSQL.
* Scan results are stored as immutable JSON snapshots with indexed summary columns; triage, policies and scenarios have their own tables. Normalised `ComponentIdentity/PackageOccurrence/DependencyEdge/Finding` tables from the brief are represented *inside* the snapshot (`ScanResult`) rather than as relational tables.
* Schema upgrades use a small ordered migration table (`api/db.py: MIGRATIONS`) instead of Alembic.
* Jobs run on a two-thread in-process pool with cooperative cancellation. There are no retries beyond the OSV client's own backoff, and jobs do not survive a process restart (a scan interrupted by a restart stays in its last state).

## Consequences
One-command start with no services; trivially reproducible tests. Not suitable for multi-user deployments. If that is needed, the intended path is: move snapshots to Postgres JSONB, add Alembic, and replace `ThreadPoolExecutor` with a queue worker behind the same `_run_scan` function.
