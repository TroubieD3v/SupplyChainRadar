# Data model

## Persisted tables (SQLite, `api/db.py`)

| Table | Purpose |
|---|---|
| `projects` | id, name, description, `demo` flag |
| `scans` | state machine, enrichment mode, input fingerprints (name/size/sha256, never the content), timings, `summary` JSON, immutable `result` JSON (`ScanResult`) |
| `triage` / `triage_events` | per-project decisions keyed by finding fingerprint (status, rationale, expiry, author) + append-only audit trail |
| `policies` | one versioned YAML policy per project |
| `scenarios` | saved remediation outcomes (JSON) |
| `settings`, `schema_meta` | defaults (e.g. enrichment mode, retention) and schema version |

Raw imported files are **not** stored.

## Snapshot (`ScanResult`, schema 1.0)

| Entity | Fields (abridged) |
|---|---|
| `ArtifactInfo` | format, format_version, parser + version, source label, sha256, counts, `graph_complete`, `coverage`, warnings |
| `Component` | id `eco:name@version`, ecosystem, name, version, `purl`, `declared` constraint (kept separate from the resolved version), `resolved`, `direct`, `scopes`, licenses, `source`, locations (file/line/detail), `unsupported_reason` |
| `Edge` | parent, child, type (`runtime`/`dev`/`optional`/`peer`/`workspace`/`unknown`), constraint, provenance, `confidence` |
| `ComponentEvaluation` | state (`evaluated`/`cached`/`not_evaluated`/`unsupported`/`error`), source, `fetched_at`, note, advisory ids |
| `Finding` | fingerprint, component, merged `Advisory` (aliases, severity evidence, references, fixed versions, raw hash), `MatchEvidence`, `PathSummary` (paths, introducers, truncation), `PriorityScore` factors, source, snapshot id |
| `CoverageSummary` | totals per state, unresolved, graph completeness, percent evaluated |
| `AdvisorySourceInfo` | mode (`live`/`cached`/`offline_fixture`/`mixed`/`none`), provider, snapshot id/date, fetch time, notes |

`checksum` hashes the deterministic parts only (inputs, components, edges, evaluation states, findings, snapshot id, engine version), so identical inputs reproduce it.

Mapping to the brief's entities: `ComponentIdentity`/`PackageOccurrence` → `Component` (+ `locations`); `DependencyEdge` → `Edge`; `ImportArtifact` → `ArtifactInfo`; `Advisory`, `Finding` → same; `Exception` → `triage` rows + policy `exceptions`; `RemediationScenario` → `scenarios`; `ScanComparison` → computed on demand from two snapshots; `RiskSignal` → model exists, no provider in v1.0.
