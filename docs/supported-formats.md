# Supported formats

All parsers are static: file content is data. Nothing is executed, installed or fetched. Every input is bounded (25 MB per file, 100 MB total, ≤ 64 files, directory depth 5, 100 k components, 500 k edges).

| Format | Parser | Versions covered by tests | Graph | Notes |
|---|---|---|---|---|
| npm `package-lock.json`, `npm-shrinkwrap.json` | `ingestion/npm.py` | lockfileVersion **2, 3** | complete | Node resolution walk (nearest `node_modules`); aliases resolved to the real package; scoped names; workspace links; git/file/URL sources marked *unsupported for lookup*; line numbers for each entry. v1 is rejected. |
| pnpm `pnpm-lock.yaml` | `ingestion/pnpm.py` | **6.x**, **9.x** | complete | `importers` become workspace nodes below a synthetic root; `link:` edges; peer-suffixed variants merge into one node (noted); YAML aliases/anchors are rejected (entity-expansion defence). v5 is rejected. |
| Poetry `poetry.lock` | `ingestion/poetry.py` | lock-version **1.x, 2.x** | complete | PEP 503 name normalisation; optional edges; marker-conditional duplicate versions link with `confidence: inferred`; `pyproject.toml` (Poetry and PEP 621/735) supplies direct dependencies, otherwise they are inferred and labelled; git/directory/url sources unsupported for lookup. |
| `requirements.txt` | `ingestion/requirements.py` | pinned `==` / `===` | **partial** | Ranges, unpinned, `name @ url`, VCS, editable and `-r/-c` references stay *unresolved* (never guessed). Hashes and continuation lines handled; custom index URLs are redacted and flagged. No transitive graph. |
| CycloneDX JSON | `ingestion/cyclonedx.py` | **1.6, 1.7**, validated against the official JSON Schemas bundled in `backend/src/scradar/schemas` | as declared | Components without a mappable purl are inventory-only. Missing `dependencies` → no edges, graph marked incomplete. Embedded `vulnerabilities` are *imported evidence only*, never findings. |
| SPDX JSON | `ingestion/spdx.py` | **2.3** | from relationships | Structural validation only (no JSON Schema). Supported: `DEPENDS_ON`, `DEPENDENCY_OF`, `RUNTIME_/DEV_/BUILD_/TEST_/OPTIONAL_DEPENDENCY_OF`, `DESCRIBES`/`DESCRIBED_BY`; other relationship types are reported as ignored. |
| Folder | `detect.import_directory` | — | — | Skips `node_modules`, `.git`, venvs, build output; never follows symlinks; pairs `poetry.lock` with a sibling `pyproject.toml`. |
| ZIP | `detect.import_zip` | — | — | Read in memory (nothing extracted to disk); rejects `..`/absolute/drive paths, symlinks, too many entries, oversize or high-ratio entries. |

## Advisory ecosystems

Lookup is attempted for `npm`, `PyPI`, `Maven`, `Go`, `crates.io`, `NuGet`, `RubyGems`, `Packagist`, `Hex`, `Pub` (those present in an SBOM with a valid purl). Local range verification and what-if constraint checks exist only where a version comparator exists (SemVer family and PyPI); for the rest the OSV server's answer is used and the local check is reported as `unavailable`.

## Export formats

JSON (versioned scan snapshot), Markdown, self-contained HTML (no scripts, strict CSP), SARIF 2.1.0 (validated against the official schema in tests), CycloneDX 1.7 JSON (validated against the official schema in tests; completeness reported honestly).
