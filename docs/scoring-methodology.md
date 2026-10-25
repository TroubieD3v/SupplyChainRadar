# Prioritisation score (0–100)

The score exists to *order* findings. It is not CVSS, not a probability of exploitation, and not a verdict.

```
score = 100 × Σ(weight_i × value_i) / Σ(weight_i)      over factors whose value is KNOWN
confidence = Σ(known weights) / Σ(all weights)
```

Unknown factors are **excluded**, never treated as zero. If the advisory's severity itself is unknown the finding is left **unscored** (`score: null`) instead of being ranked on exposure alone.

| Factor | Weight | Value (0–1) | Source / when unknown |
|---|---:|---|---|
| `severity` | 50 | CVSS v3 base score ÷ 10 (computed from the advisory's own vector); else the advisory database label (critical 1.0, high 0.75, medium 0.5, low 0.25) | unknown if the source gives neither |
| `known_exploited` | 25 | 1.0 if a CVE alias is in a supplied CISA KEV file, 0.0 if the file is supplied and the CVE is absent | unknown without `--kev-file` (offline by design; no EPSS in v1.0) |
| `exposure` | 15 | direct 1.0; 2 hops 0.7; 3 hops 0.5; deeper 0.35 | unknown if no path from the application is known |
| `scope` | 10 | runtime 1.0; optional 0.5; dev 0.25 | unknown when scope cannot be derived |
| `breadth` | 5 | 1 path 0.2; 2–4 paths 0.6; ≥5 paths 1.0 | unknown if no path is known |
| `business_criticality` | 10 | user-supplied 0–1 | unknown unless provided (library argument; not yet exposed in the UI) |

Weights are configurable through `analyze(..., weights=...)`. The UI shows every factor, its value (or "unknown — excluded") and its evidence string; reports include the same breakdown.

## Limitations
* Presence of a dependency does not prove reachability or exploitability; nothing here analyses code.
* CVSS v4 vectors are stored but not scored (only v3.x is computed); such advisories rely on the database label if any.
* Severity is the *source's* statement. Different databases may disagree; the highest known severity within an alias group is used and the evidence says where it came from.
