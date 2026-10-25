# Implementation plan and acceptance status

Source of truth: the project specification (SupplyChain Radar v1.0). This file records what was built, the deviations, and the **verified** state of the acceptance matrix. "Verified" means a test or command was run and its result observed; anything else is stated as such.

## Milestones

| Milestone | Scope | State |
|---|---|---|
| M0 Architecture | domain model, unknown/coverage semantics, fixtures designed first (`scripts/generate_examples.py`) | done |
| M1 Foundation | FastAPI, Typer CLI, React shell, SQLite, compose, health | done (compose image build: see A01) |
| M2 Import & graph | 6 parsers, folder/ZIP import, graph engine, graph UI | done |
| M3 OSV & findings | OSV client (batch, retry, cache, offline), frozen fixtures, alias merge, findings UI | done |
| M4 History/policy/export | snapshots, diff, policy engine, SARIF/HTML/MD/JSON/CycloneDX | done |
| M5 Remediation Studio | candidate + hypothetical modes, plan comparison | done |
| M6 UX polish | 10 screens, dark default + toggle, triage with expiry/audit, accessible names | done; Scorecard not implemented |
| M7 Hardening/CI/bench | adversarial tests, fuzzing, E2E, benchmarks, CI workflows | done (workflows not yet executed on GitHub when this was written) |
| M8 Release | docs, screenshots, changelog, release notes, wheel | see CHANGELOG |

## Deviations from the brief (all deliberate, all documented)

1. **SQLite + in-process thread pool** instead of PostgreSQL/Redis/Alembic — [ADR 0001](docs/adr/0001-sqlite-and-in-process-jobs.md).
2. **Tailwind 4 + own primitives** instead of shadcn/ui; self-hosted fonts and icons — [ADR 0002](docs/adr/0002-ui-stack.md).
3. **pip/venv** instead of `uv` (not installed on the dev machine); `make setup` documents the flow.
4. **OpenSSF Scorecard (P1) and EPSS are not implemented.** The provider status endpoint says so. CISA KEV is supported from a local file.
5. SPDX 2.3 is validated structurally, not against a JSON Schema.
6. Normalised per-entity relational tables are replaced by immutable JSON snapshots plus indexed summaries ([data-model.md](docs/data-model.md)).

## Acceptance matrix (P0 = must pass)

| ID | P | Status | Evidence |
|---|---|---|---|
| A01 | P0 | **partly verified** | `docker compose config` passes; the image build/start is exercised by the `containers` CI job and was verified locally only if noted in the release notes |
| A02 | P0 | verified | `test_cli_*` (help, scan, compare, policy check, report, remediate, import validate) |
| A03 | P0 | verified | `test_parsers.py`: npm v2/v3, pnpm 6/9, Poetry 1/2, pinned requirements |
| A04 | P0 | verified | CycloneDX 1.6 and 1.7 import + schema rejection tests |
| A05 | P0 | verified | `test_partial_requirements_never_look_clean`, `test_cyclonedx_without_dependencies_…`, `test_unconnected_inventory_is_not_a_path` |
| A06 | P0 | verified | mock-server adapter tests; one live run of `test_live_osv.py` against api.osv.dev succeeded (lodash 4.17.15 vulnerable, 4.17.21 evaluated, cached replay offline) |
| A07 | P0 | verified | range/true-positive/negative tests, recorded expected findings |
| A08 | P0 | verified | `test_alias_duplicates_produce_one_finding`, union-find test |
| A09 | P0 | verified | shared-parent, cycle, truncation, deep-graph tests; Playwright graph step |
| A10 | P0 | verified | `test_remediation_diff_classification`, `test_advisory_update_only…`, `test_coverage_loss_is_not_reported_as_resolved` |
| A11 | P0 | verified | candidate rescan and hypothetical-mode tests (`full_reresolution` false) |
| A12 | P0 | verified | exit codes 0/1/2/3/4 in `test_cli_exit_codes`, `test_cli_provider_failure_is_exit_3` |
| A13 | P0 | verified | SARIF validated against the official 2.1.0 schema; CycloneDX 1.7 export validated against the official 1.7 schema |
| A14 | P0 | verified | `test_reports_share_facts_and_escape_html` (same ids in all formats, escaping, token masking) |
| A15 | P0 | verified | E2E: empty state; demo data labelled; overview from stored scans; provider-outage test |
| A16 | P0 | verified locally (Edge); CI job defined | `tests/e2e/journey.spec.ts` — 12 steps incl. keyboard/theme |
| A17 | P0 | verified | zip-slip, symlink, bomb, YAML alias, deep JSON, oversize, fuzz tests |
| A18 | P0 | verified | `test_offline_modes_open_no_sockets` |
| A19 | P0 | verified | expected-findings fixtures + `npm-clean` negative control |
| A20 | P0 | verified | `docs/limitations.md`, `docs/threat-model.md`, `docs/supported-formats.md` |
| A21 | P1 | done | SPDX 2.3 relationship tests |
| A22 | P1 | **not done** | Scorecard adapter absent |
| A23 | P1 | done | exception expiry in policy + API audit trail |
| A24 | P1 | partial | measured 1k/10k benchmarks; UI bounded, not virtualised or benchmarked in-browser |
| A25 | P1 | done | real screenshots, wheel + UI bundle + checksums in release |
