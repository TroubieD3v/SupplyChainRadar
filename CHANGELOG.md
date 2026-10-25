# Changelog

## 1.0.0 — 2026-10-25

First release.

### Added
- Static importers: npm `package-lock.json` (v2/v3), `pnpm-lock.yaml` (6.x/9.x), `poetry.lock` (1.x/2.x, with `pyproject.toml`), `requirements.txt` (pinned only), CycloneDX 1.6/1.7 JSON (schema-validated), SPDX 2.3 JSON, folder and in-memory ZIP import.
- Dependency graph engine with scope derivation, cycle handling and shortest-first, bounded path search.
- OSV integration (batch query, retries with backoff, cache, offline mode), frozen-snapshot provider, CVSS v3 scoring, alias-merged findings, transparent priority score.
- Remediation Studio: candidate-lockfile rescans and hypothetical what-if simulations with explicit confidence labels; plan comparison.
- Scan comparison with causes (dependency change vs advisory update vs coverage gap), policy-as-code with baselines, expiring exceptions and exit codes 0–4.
- Reports: JSON, Markdown, HTML, SARIF 2.1.0, CycloneDX 1.7.
- CLI (`supplychain-radar`, alias `scradar`), FastAPI API (`/api/v1`), React web UI (dark by default, light toggle).
- Docker Compose stack (loopback only), CI workflows, benchmarks, threat model, ADRs.

### Known gaps
See [docs/limitations.md](docs/limitations.md) and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md): no OpenSSF Scorecard/EPSS adapters, SQLite instead of PostgreSQL/Redis, SPDX validated structurally only.
