# Limitations (read before trusting a result)

1. **Not reachability analysis.** A matched advisory means the vulnerable *version* is in your dependency set. Whether the vulnerable code runs is unknown.
2. **"No advisories" is relative to a data source.** With a frozen snapshot it means "not in that snapshot"; with OSV it means "OSV had none when fetched" (`fetched_at` is shown).
3. **Coverage gaps are explicit.** Unpinned requirements, git/file/URL dependencies, unknown ecosystems, offline cache misses and provider errors are `unresolved`, `unsupported`, `not_evaluated` or `error` — and policies can fail closed on them.
4. **Graphs are only as complete as the file.** `requirements.txt` has no transitive graph; SBOMs may lack edges; pnpm peer variants merge into one node; marker-conditional Poetry duplicates link with `inferred` edges; npm peer-dependency edges that were not installed are absent.
5. **Hypothetical remediation is a prediction.** No resolver runs. Parent constraints are checked for npm ranges and PEP 440 specifiers only; anything else is reported as "could not evaluate".
6. **CVSS v4 is not scored**; only the advisory database label is used when present.
7. **Not implemented in v1.0:** OpenSSF Scorecard and EPSS adapters, SPDX JSON-Schema validation, PostgreSQL/Redis, multi-user auth, automatic fixes, Maven/Go/Cargo lockfile parsers (those ecosystems are reachable only through SBOMs), VEX import, per-line SARIF locations for pnpm/CycloneDX/SPDX.
8. **Fixture benchmarks are self-made.** They prove the matcher implements the fixture semantics; they are not independent validation and do not generalise.
9. **Browser performance of very large graphs was not measured**; the UI limits what it draws and offers search/focus instead.
10. **Docker image build** is defined and validated with `docker compose config` and runs in CI; see the release notes for what was verified locally.
