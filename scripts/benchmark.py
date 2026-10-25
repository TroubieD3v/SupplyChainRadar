"""Reproducible benchmarks.

1. Fixture accuracy: precision/recall of confirmed matches against hand-derived expectations.
   These are SYNTHETIC fixtures written by the project authors; the numbers say the matcher does what the
   fixtures encode. They are NOT independent third-party validation and do not generalise to real ecosystems.
2. Scale: generated npm lockfiles with ~1,000 and ~10,000 packages; wall-clock for parse, graph, advisory
   matching and path search. Environment details are printed with the results.

Run:  python scripts/benchmark.py [--write docs/benchmark-results.json]
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

from scradar.graph.engine import DependencyGraph  # noqa: E402
from scradar.ingestion.detect import import_directory, parse_file  # noqa: E402
from scradar.intelligence.providers import FixtureProvider  # noqa: E402
from scradar.service import analyze  # noqa: E402


def fixture_accuracy() -> dict:
    fp = FixtureProvider(ROOT / "fixtures/osv/frozen-advisories.json")
    tp = fn = fp_ = 0
    per = {}
    for name in ("npm-vulnerable", "npm-remediated", "npm-clean"):
        res = analyze(import_directory(ROOT / "examples" / name).inventories, fp)
        got = {(f.package, f.version, f.advisory.id) for f in res.findings}
        exp_file = ROOT / "fixtures/expected" / f"{name}-findings.json"
        exp = {(a, b, c) for a, b, c, _ in json.loads(exp_file.read_text())["findings"]} if exp_file.exists() else set()
        tp += len(got & exp)
        fn += len(exp - got)
        fp_ += len(got - exp)
        per[name] = {"expected": len(exp), "found": len(got), "true_positive": len(got & exp)}
    precision = tp / (tp + fp_) if tp + fp_ else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"true_positives": tp, "false_positives": fp_, "false_negatives": fn, "precision": precision, "recall": recall, "per_example": per}


def generate_lock(n: int, seed: int = 7, fan_out: int = 4) -> bytes:
    """Layered DAG with heavy sharing: node i depends on up to `fan_out` later nodes; ~1% share a vulnerable name."""

    rnd = random.Random(seed)
    pkgs = {}
    for i in range(n):
        deps = {}
        for _ in range(rnd.randint(0, fan_out)):
            j = rnd.randint(i + 1, min(n - 1, i + 60)) if i + 1 < n else None
            if j is not None:
                deps[f"pkg-{j}"] = "^1.0.0"
        name = f"pkg-{i}"
        pkgs[f"node_modules/{name}"] = {
            "version": "1.0.0",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",
            "integrity": "sha512-x",
            "license": "MIT",
            **({"dependencies": deps} if deps else {}),
        }
    direct = {f"pkg-{i}": "^1.0.0" for i in range(0, min(n, 40))}
    doc = {
        "name": "bench",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {"": {"name": "bench", "version": "1.0.0", "dependencies": direct}, **pkgs},
    }
    return json.dumps(doc).encode()


def bench_scale(n: int) -> dict:
    data = generate_lock(n)
    advisories = {
        "snapshot_id": "bench",
        "generated": "2026-01-01T00:00:00Z",
        "ecosystems": ["npm"],
        "advisories": [
            {
                "id": f"BENCH-{k}",
                "affected": [{"package": {"ecosystem": "npm", "name": f"pkg-{k}"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}],
            }
            for k in range(n - 1, n - 11, -1)
        ],
    }
    fp = FixtureProvider(document=advisories)
    t0 = time.perf_counter()
    inv = parse_file("package-lock.json", data)
    t1 = time.perf_counter()
    res = analyze([inv], fp, project="bench", max_paths=20)
    t2 = time.perf_counter()
    g = DependencyGraph({c.id: c for c in res.components}, res.edges)
    t3 = time.perf_counter()
    worst = max((f.paths for f in res.findings), key=lambda p: p.total_found, default=None)
    paths_ms = []
    for f in res.findings:
        s = time.perf_counter()
        g.paths_to(f.component_id, max_paths=20)
        paths_ms.append((time.perf_counter() - s) * 1000)
    return {
        "packages": len(inv.components) - 1,
        "edges": len(inv.edges),
        "lockfile_mb": round(len(data) / 1e6, 2),
        "parse_s": round(t1 - t0, 3),
        "analyze_s (graph+match+paths for all findings)": round(t2 - t1, 3),
        "graph_build_s": round(t3 - t2, 3),
        "findings": len(res.findings),
        "path_search_ms_median": round(statistics.median(paths_ms), 2) if paths_ms else None,
        "path_search_ms_max": round(max(paths_ms), 2) if paths_ms else None,
        "paths_truncated_findings": sum(1 for f in res.findings if f.paths.truncated),
        "max_paths_reported": worst.total_found if worst else 0,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", type=Path)
    ap.add_argument("--sizes", type=int, nargs="*", default=[1000, 10000])
    args = ap.parse_args()
    out = {
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor()[:60]},
        "fixture_accuracy": fixture_accuracy(),
        "scale": {str(n): bench_scale(n) for n in args.sizes},
        "note": "Synthetic inputs generated by this script; timings are single-run on the stated machine.",
    }
    text = json.dumps(out, indent=2)
    print(text)
    if args.write:
        args.write.write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
