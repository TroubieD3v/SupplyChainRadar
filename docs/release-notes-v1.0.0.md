# SupplyChain Radar v1.0.0

Offline-first software supply chain security workbench: import lockfiles/SBOMs, see **why** a vulnerable package is in your project, which advisories apply, what changed between scans, and which upgrade could remove the risk.

## Highlights
- **Dependency path explanations** for every finding, with the lockfile line that declared each edge.
- **Honest unknowns**: unresolved, unsupported, not-evaluated and errored packages are never reported as clean; lost coverage is never reported as a fix.
- **Remediation Studio**: authoritative candidate-lockfile rescans vs clearly-labelled predictions.
- **Scan comparison** that separates dependency changes from advisory-database updates.
- **Policy-as-code** with baselines, expiring exceptions with audit trail, and CLI exit codes 0–4.
- **CLI + API + web UI** over one engine; exports to JSON, Markdown, HTML, SARIF 2.1.0 and CycloneDX 1.7.
- New UI (dark by default, light toggle) built on the Primary `#121212` / Secondary `#008542` / Tertiary `#D97706` / Neutral `#64748B` palette, Manrope + Inter.

## Install
```bash
pip install supplychain_radar-1.0.0-py3-none-any.whl     # CLI + API (attached below)
supplychain-radar scan ./your-project --offline --advisory-fixture frozen.json
```
The web UI bundle (`supplychain-radar-ui-v1.0.0.tar.gz`) is served by `supplychain-radar serve` when `SCRADAR_STATIC_DIR` points at the extracted folder; or use Docker:
```bash
git clone https://github.com/TroubieD3v/SupplyChainRadar && cd SupplyChainRadar
docker compose up --build -d      # http://127.0.0.1:8000
```
Verify downloads with `SHA256SUMS.txt`.

## What was verified before release
- Backend: ruff, ruff-format, mypy (strict-ish), **pytest** (unit, property/fuzz, integration with a mock OSV server, CLI exit codes, SARIF/CycloneDX schema validation, adversarial ZIP/YAML/JSON inputs).
- Frontend: eslint, tsc, vitest, production build, `npm audit` clean.
- **Playwright journey** (12 steps: empty state → import → findings → paths → triage → graph → candidate & what-if remediation → advisory-refresh comparison → policy gate → SARIF download → provider outage → keyboard/theme) passed locally in Microsoft Edge.
- Live check against `api.osv.dev` (one real package) passed once; it is an optional, non-gating test.
- The wheel was built and run from a clean virtualenv.
- GitHub Actions CI is green on the release commit: backend on Python 3.12 and 3.13, security-regression, frontend, Playwright E2E on Linux/Chromium, and the container job (`docker compose up --build --wait` + smoke test).

## Known gaps (also in `docs/limitations.md`)
- Not a reachability/exploitability analyser; no malware detection.
- **Not implemented:** OpenSSF Scorecard and EPSS adapters, PostgreSQL/Redis (SQLite + in-process jobs instead), SPDX JSON-Schema validation, Maven/Go/Cargo lockfile parsers (SBOM only).
- Benchmarks use synthetic fixtures (not independent validation); browser performance on very large graphs was not measured.
- Local development and the local gate ran on Windows with Python 3.14; Docker was verified in CI only (the local Docker daemon was unavailable).
