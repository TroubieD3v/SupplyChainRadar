# Benchmarks

Run `python scripts/benchmark.py --write docs/benchmark-results.json`. The script prints the environment, so results are comparable only on similar machines.

## 1. Fixture accuracy
Expected matches live in `fixtures/expected/*.json` and were derived by hand from the fixture design (which packages sit inside which advisory ranges), then compared with scanner output. Result: 5/5 true positives, 0 false positives, 0 false negatives; the `npm-clean` negative control has 0 findings.

**Caveat:** the fixtures are synthetic (`demo-*` packages, `DEMO-*` advisories) and were written by the same authors as the matcher. This is a regression test of intended semantics — **not** independent third-party validation, and it says nothing about precision/recall on real registries. The optional live test (`SCRADAR_LIVE=1 pytest backend/tests/test_live_osv.py`) additionally checks one real package (lodash 4.17.15 vs 4.17.21) against api.osv.dev.

## 2. Scale
Generated npm lockfiles (layered DAG, ≤4 dependencies per package, 40 direct dependencies, 10 vulnerable leaves).

| Packages | Edges | Lockfile | Parse | Analyse (graph + matching + 20 paths × 10 findings) | Path search (median / max) |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,930 | 0.21 MB | 0.024 s | 0.334 s | 1.4 ms / 75.9 ms |
| 10,000 | 19,675 | 2.19 MB | 0.218 s | 0.218 s | 10.6 ms / 11.1 ms |

Environment: Windows 11, AMD64, Python 3.14.4, single run (see `docs/benchmark-results.json`). In both runs every finding's path list hit the 20-path cap and was reported as `truncated`, which is the intended behaviour on heavily shared graphs. An earlier implementation that enumerated all simple paths breadth-first found no path at all within its budget on these graphs; the current search returns shortest paths first (regression test `test_deep_shared_graph_still_returns_shortest_paths_quickly`).

UI rendering performance on very large graphs was **not** measured. The API/UI keep the drawn graph bounded (vulnerable-path subgraph by default, 800-node cap in full mode, focus mode, search) instead of virtualising everything.
