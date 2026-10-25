"""Report generators: JSON, Markdown, self-contained HTML, SARIF 2.1.0 and CycloneDX 1.7 JSON.

All generators read the same ScanResult so facts stay identical across formats. Every string that
came from an imported file or advisory is escaped (HTML) or passed through secret redaction.
"""

from __future__ import annotations

import html
import json
import uuid
from typing import Any

from scradar import __version__
from scradar.comparison.diff import ScanComparison
from scradar.domain.models import ROOT_ID, QueryState, ScanResult, Severity
from scradar.policy.engine import PolicyResult
from scradar.security import redact
from scradar.service import severity_counts

TOOL_URI = "https://github.com/TroubieD3v/SupplyChainRadar"
FORMATS = ("json", "markdown", "html", "sarif", "cyclonedx")


def _r(text: Any) -> str:
    return redact(str(text)) or "" if text is not None else ""


def _name(scan: ScanResult, cid: str) -> str:
    c = scan.component_map().get(cid)
    if c is None:
        return cid
    if c.id == ROOT_ID:
        return c.name
    return f"{c.name}@{c.version}" if c.version else c.name


# --- JSON ---------------------------------------------------------------------------------------


def to_json(scan: ScanResult, policy: PolicyResult | None = None) -> str:
    doc = scan.model_dump(mode="json")
    if policy is not None:
        doc["policy"] = policy.model_dump(mode="json")
    return json.dumps(doc, indent=2, ensure_ascii=False)


# --- Markdown -------------------------------------------------------------------------------------


def _md(text: Any) -> str:
    s = _r(text)
    for ch in ("\\", "`", "*", "_", "[", "]", "<", ">", "|", "#"):
        s = s.replace(ch, "\\" + ch)
    return s.replace("\n", " ")


def to_markdown(scan: ScanResult, policy: PolicyResult | None = None) -> str:
    sc = severity_counts(scan)
    cov = scan.coverage
    src = scan.advisory_source
    lines = [f"# SupplyChain Radar report — {_md(scan.project)}", ""]
    if scan.demo:
        lines += ["> **Demo data.** Built from synthetic fixtures; not a scan of a real project.", ""]
    lines += [
        f"- Scan: `{scan.scan_id}` at {scan.created_at} (engine {scan.engine_version})",
        f"- Checksum: `{scan.checksum}`",
        f"- Advisory source: **{src.mode}** via {src.provider}"
        + (f", snapshot `{_md(src.snapshot_id)}` ({src.snapshot_generated})" if src.snapshot_id else "")
        + (f", fetched {src.fetched_at}" if src.fetched_at else ""),
        f"- Coverage: {cov.percent_evaluated}% of {cov.total_packages} packages evaluated "
        f"(not evaluated {cov.not_evaluated}, unsupported {cov.unsupported}, errors {cov.error}, unresolved {cov.unresolved}); "
        f"dependency graph {'complete' if cov.graph_complete else '**incomplete**'}",
        "",
        "## Summary",
        "",
        "| Critical | High | Medium | Low | Unknown severity |",
        "|---:|---:|---:|---:|---:|",
        f"| {sc['critical']} | {sc['high']} | {sc['medium']} | {sc['low']} | {sc['unknown']} |",
        "",
    ]
    if policy:
        lines += [
            f"**Policy `{_md(policy.policy)}`: {policy.outcome.upper()}** (exit code {policy.exit_code})",
            "",
        ]
        for v in policy.violations + policy.warnings:
            lines.append(f"- [{v.action}] `{_md(v.rule_id)}` — {_md(v.message)}")
        for n in policy.notes:
            lines.append(f"- note: {_md(n)}")
        lines.append("")
    lines += ["## Confirmed advisory matches", ""]
    if not scan.findings:
        lines.append(
            "No advisory matched the evaluated packages in the data source above."
            + (" Coverage is incomplete — see below." if not cov.fully_covered else "")
        )
    for f in scan.findings:
        a = f.advisory
        lines += [
            f"### {_md(a.id)} — {_md(f.package)}@{_md(f.version)} ({a.severity.level.value})",
            "",
            f"{_md(a.summary or 'No summary provided.')}",
            "",
            f"- Aliases: {', '.join(_md(x) for x in a.aliases) or '—'}",
            f"- Severity evidence: {_md(a.severity.source or 'not provided by source')}"
            + (f" — `{_md(a.severity.vector)}`" if a.severity.vector else ""),
            f"- Priority score: {f.priority.score if f.priority.score is not None else 'unscored'} "
            f"(confidence {f.priority.confidence})",
            f"- Match: {f.match.basis} — {_md(f.match.rationale)}",
            f"- Scope: {', '.join(f.scopes)}; {'direct' if f.direct else 'transitive'}",
            f"- Fixed in: {', '.join(_md(v) for v in a.fixed_versions) or 'no fixed version listed'}",
            f"- Source: {f.source}" + (f", fetched {f.fetched_at}" if f.fetched_at else ""),
            "- Dependency paths:",
        ]
        if not f.paths.paths:
            lines.append(f"  - {_md(f.paths.warning or 'no path available')}")
        for p in f.paths.paths[:5]:
            lines.append(
                "  - "
                + " → ".join(_md(_name(scan, n)) for n in p.nodes)
                + (" *(inferred edge)*" if p.inferred else "")
            )
        if f.paths.truncated:
            lines.append("  - … more paths exist (search limit reached)")
        for ref in a.references[:4]:
            lines.append(f"- Reference ({_md(ref.type or 'link')}): <{_r(ref.url).replace('>', '%3E')}>")
        lines.append("")
    gaps = [e for e in scan.evaluations if e.state not in (QueryState.EVALUATED, QueryState.CACHED)]
    lines += ["## Unknown coverage", ""]
    if not gaps:
        lines.append("Every package was evaluated.")
    for e in gaps[:200]:
        lines.append(f"- {_md(_name(scan, e.component_id))}: **{e.state.value}** — {_md(e.note or '')}")
    lines.append("")
    if scan.warnings:
        lines += ["## Parser warnings", ""] + [f"- {_md(w)}" for w in scan.warnings[:100]] + [""]
    lines += ["## Limitations", ""] + [f"- {_md(x)}" for x in scan.limitations] + [""]
    return "\n".join(lines)


# --- HTML -----------------------------------------------------------------------------------------

_CSS = """
:root{--bg:#121212;--surface:#1b1d21;--surface2:#23262c;--text:#eef1f6;--muted:#9aa5b5;--line:#2f343c;
--green:#4cd38a;--green-d:#008542;--orange:#f59e0b;--red:#ef4444;--slate:#64748b}
@media (prefers-color-scheme: light){:root{--bg:#eef3ff;--surface:#ffffff;--surface2:#e5eeff;--text:#121212;--muted:#475569;--line:#d3e4fe;--green:#008542}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,system-ui,Segoe UI,sans-serif}
main{max-width:1080px;margin:0 auto;padding:40px 24px}h1,h2,h3{font-family:Manrope,Inter,system-ui,sans-serif;letter-spacing:-.01em}
h1{font-size:34px;margin:8px 0 4px}h2{margin-top:40px}.muted{color:var(--muted)}
.chip{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;background:var(--surface2)}
.demo{background:#d97706;color:#121212}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-top:20px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:18px 20px}
.big{font-family:Manrope,Inter,sans-serif;font-size:30px;font-weight:800}.sev-critical{color:var(--red)}.sev-high{color:var(--orange)}
.sev-medium{color:#fbbf24}.sev-low{color:var(--slate)}.sev-unknown{color:var(--muted)}
.finding{margin-top:16px}.path{font-family:ui-monospace,Consolas,monospace;font-size:13px;background:var(--surface2);border-radius:10px;padding:6px 10px;margin:4px 0;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.bar{height:6px;border-radius:999px;background:var(--surface2);overflow:hidden}.bar>i{display:block;height:100%;background:var(--green)}
.pass{color:var(--green)}.fail{color:var(--red)}.warn,.inconclusive{color:var(--orange)}
"""


def _h(text: Any) -> str:
    return html.escape(_r(text), quote=True)


def to_html(scan: ScanResult, policy: PolicyResult | None = None) -> str:
    sc = severity_counts(scan)
    cov = scan.coverage
    src = scan.advisory_source
    out: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>SupplyChain Radar — {_h(scan.project)}</title><style>{_CSS}</style></head><body><main>",
        "<span class='chip'>SupplyChain Radar report</span>",
    ]
    if scan.demo:
        out.append(" <span class='chip demo'>Demo data</span>")
    out.append(f"<h1>{_h(scan.project)}</h1>")
    out.append(
        f"<p class='muted'>Scan {_h(scan.scan_id)} · {_h(scan.created_at)} · engine {_h(scan.engine_version)} · checksum "
        f"<code>{_h(scan.checksum[:16])}…</code></p>"
    )
    out.append("<div class='grid'>")
    for lvl in ("critical", "high", "medium", "low", "unknown"):
        out.append(
            f"<div class='card'><div class='muted'>{lvl.title()}</div><div class='big sev-{lvl}'>{sc[lvl]}</div></div>"
        )
    out.append(
        f"<div class='card'><div class='muted'>Evaluated</div><div class='big'>{cov.percent_evaluated}%</div>"
        f"<div class='bar'><i style='width:{max(0.0, min(100.0, cov.percent_evaluated))}%'></i></div></div>"
    )
    out.append("</div>")
    out.append(
        "<div class='card' style='margin-top:14px'><b>Advisory source:</b> "
        f"{_h(src.mode)} via {_h(src.provider)}"
        + (
            f" — snapshot <code>{_h(src.snapshot_id)}</code> ({_h(src.snapshot_generated)})"
            if src.snapshot_id
            else ""
        )
        + (f" — fetched {_h(src.fetched_at)}" if src.fetched_at else "")
        + f"<br><b>Coverage:</b> {cov.total_packages} packages; not evaluated {cov.not_evaluated}, unsupported {cov.unsupported}, "
        f"errors {cov.error}, unresolved {cov.unresolved}; graph {'complete' if cov.graph_complete else '<b>incomplete</b>'}"
        + "".join(f"<br><span class='muted'>{_h(n)}</span>" for n in src.notes + cov.notes)
        + "</div>"
    )
    if policy:
        out.append(
            f"<h2>Policy <code>{_h(policy.policy)}</code>: <span class='{policy.outcome}'>{policy.outcome.upper()}</span></h2><ul>"
        )
        for v in policy.violations + policy.warnings:
            out.append(f"<li><b>[{_h(v.action)}]</b> {_h(v.rule_id)} — {_h(v.message)}</li>")
        for n in policy.notes:
            out.append(f"<li class='muted'>{_h(n)}</li>")
        out.append("</ul>")
    out.append("<h2>Confirmed advisory matches</h2>")
    if not scan.findings:
        out.append(
            "<p>No advisory matched the evaluated packages in the data source above."
            + (" <b>Coverage is incomplete.</b>" if not cov.fully_covered else "")
            + "</p>"
        )
    for f in scan.findings:
        a = f.advisory
        lvl = a.severity.level.value
        out.append("<div class='card finding'>")
        out.append(
            f"<span class='chip sev-{lvl}'>{_h(lvl)}</span> <b>{_h(a.id)}</b> <span class='muted'>{_h(', '.join(a.aliases))}</span>"
            f"<h3>{_h(f.package)}@{_h(f.version)}</h3><p>{_h(a.summary or 'No summary provided.')}</p>"
        )
        out.append("<table>")
        rows = [
            (
                "Severity evidence",
                (a.severity.source or "not provided by source")
                + (f" — {a.severity.vector}" if a.severity.vector else ""),
            ),
            (
                "Priority",
                f"{f.priority.score if f.priority.score is not None else 'unscored'} (confidence {f.priority.confidence})",
            ),
            ("Match", f"{f.match.basis}: {f.match.rationale}"),
            ("Scope", f"{', '.join(f.scopes)} · {'direct' if f.direct else 'transitive'}"),
            ("Fixed in", ", ".join(a.fixed_versions) or "no fixed version listed"),
            ("Introduced by", ", ".join(_name(scan, i) for i in f.paths.introducers) or "—"),
            ("Source", f"{f.source}" + (f", fetched {f.fetched_at}" if f.fetched_at else "")),
        ]
        out.extend(f"<tr><th>{_h(k)}</th><td>{_h(v)}</td></tr>" for k, v in rows)
        out.append("</table><div style='margin-top:10px'>")
        if not f.paths.paths:
            out.append(f"<div class='path'>{_h(f.paths.warning or 'no dependency path available')}</div>")
        for p in f.paths.paths[:6]:
            out.append(
                "<div class='path'>"
                + " → ".join(_h(_name(scan, n)) for n in p.nodes)
                + (" (inferred)" if p.inferred else "")
                + "</div>"
            )
        if f.paths.truncated:
            out.append("<div class='muted'>More paths exist; the search limit was reached.</div>")
        out.append("</div>")
        refs = [r for r in a.references if r.url.startswith(("https://", "http://"))][:4]
        if refs:
            out.append(
                "<p class='muted'>References (not fetched by this tool): "
                + " · ".join(
                    f"<a rel='noopener noreferrer nofollow' href='{_h(r.url)}'>{_h(r.type or 'link')}</a>"
                    for r in refs
                )
                + "</p>"
            )
        out.append("</div>")
    gaps = [e for e in scan.evaluations if e.state not in (QueryState.EVALUATED, QueryState.CACHED)]
    out.append("<h2>Unknown coverage</h2>")
    if not gaps:
        out.append("<p>Every package was evaluated.</p>")
    else:
        out.append("<table><tr><th>Package</th><th>State</th><th>Reason</th></tr>")
        out.extend(
            f"<tr><td>{_h(_name(scan, e.component_id))}</td><td>{_h(e.state.value)}</td><td>{_h(e.note)}</td></tr>"
            for e in gaps[:300]
        )
        out.append("</table>")
    if scan.warnings:
        out.append(
            "<h2>Parser warnings</h2><ul>"
            + "".join(f"<li>{_h(w)}</li>" for w in scan.warnings[:100])
            + "</ul>"
        )
    out.append("<h2>Limitations</h2><ul>" + "".join(f"<li>{_h(x)}</li>" for x in scan.limitations) + "</ul>")
    out.append(f"<p class='muted'>Generated by SupplyChain Radar {__version__}.</p></main></body></html>")
    return "".join(out)


# --- SARIF 2.1.0 ------------------------------------------------------------------------------------

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "warning",
}


def to_sarif(scan: ScanResult, path_prefix: str = "") -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in scan.findings:
        a = f.advisory
        if a.id not in rules:
            props: dict[str, Any] = {
                "tags": ["security", "supply-chain", f"severity:{a.severity.level.value}"],
                "aliases": a.aliases,
            }
            if a.severity.score is not None:
                props["security-severity"] = f"{a.severity.score:.1f}"
            help_uri = next((r.url for r in a.references if r.url.startswith("https://")), None)
            rule: dict[str, Any] = {
                "id": a.id,
                "name": "VulnerableDependency",
                "shortDescription": {"text": _r(a.summary or a.id)[:1000]},
                "fullDescription": {"text": _r(a.details or a.summary or a.id)[:4000]},
                "defaultConfiguration": {"level": _LEVEL[a.severity.level]},
                "help": {
                    "text": (
                        f"Severity evidence: {a.severity.source or 'not provided by source'}. "
                        f"Fixed versions: {', '.join(a.fixed_versions) or 'none listed'}."
                    )
                },
                "properties": props,
            }
            if help_uri:
                rule["helpUri"] = help_uri
            rules[a.id] = rule
        loc = f.location
        phys: dict[str, Any] = {
            "artifactLocation": {"uri": _uri(path_prefix, loc.file if loc else "dependency-manifest")}
        }
        if loc and loc.line:
            phys["region"] = {"startLine": loc.line}
        path_text = (
            " → ".join(_name(scan, n) for n in f.paths.paths[0].nodes)
            if f.paths.paths
            else "no dependency path available"
        )
        results.append(
            {
                "ruleId": a.id,
                "ruleIndex": list(rules).index(a.id),
                "level": _LEVEL[a.severity.level],
                "message": {
                    "text": _r(
                        f"{f.package}@{f.version} is affected by {a.id} ({a.severity.level.value}). Path: {path_text}. "
                        f"Fixed in: {', '.join(a.fixed_versions) or 'no fixed version listed'}."
                    )
                },
                "locations": [{"physicalLocation": phys}],
                "partialFingerprints": {"scradarFinding/v1": f.fingerprint},
                "properties": {
                    "package": f.package,
                    "version": f.version,
                    "ecosystem": f.ecosystem,
                    "purl": f.purl,
                    "aliases": a.aliases,
                    "scopes": f.scopes,
                    "direct": f.direct,
                    "matchBasis": f.match.basis,
                    "advisorySource": f.source,
                    "references": [r.url for r in a.references][:10],
                },
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SupplyChain Radar",
                        "semanticVersion": __version__,
                        "informationUri": TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": f"supplychain-radar/{_r(scan.project)}/"},
                "results": results,
                "properties": {
                    "coverage": scan.coverage.model_dump(mode="json"),
                    "advisorySource": scan.advisory_source.model_dump(mode="json"),
                    "demo": scan.demo,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _uri(prefix: str, file: str) -> str:
    p = (f"{prefix.rstrip('/')}/{file}" if prefix else file).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


# --- CycloneDX 1.7 -----------------------------------------------------------------------------------


def to_cyclonedx(scan: ScanResult) -> str:
    comps = []
    root = scan.component_map()[ROOT_ID]
    scope_map = {"runtime": "required", "optional": "optional", "dev": "optional"}
    pkg_ids = []
    for c in scan.components:
        if c.kind != "package":
            continue
        pkg_ids.append(c.id)
        item: dict[str, Any] = {"type": "library", "bom-ref": c.id, "name": c.name}
        if c.version:
            item["version"] = c.version
        if c.purl:
            item["purl"] = c.purl
        if c.scopes and c.scopes[0] in scope_map:
            item["scope"] = scope_map[c.scopes[0]]
        if c.licenses:
            item["licenses"] = [{"license": {"name": _r(lic)[:200]}} for lic in c.licenses]
        props = [{"name": "scradar:source", "value": c.source or "unknown"}]
        if not c.resolved:
            props.append({"name": "scradar:resolved", "value": "false"})
        if c.scopes and c.scopes[0] == "dev":
            props.append({"name": "scradar:scope", "value": "dev"})
        item["properties"] = props
        comps.append(item)
    children: dict[str, list[str]] = {}
    for e in scan.edges:
        children.setdefault(e.parent, [])
        if e.child not in children[e.parent]:
            children[e.parent].append(e.child)
    deps = []
    for cid in [ROOT_ID, *pkg_ids]:
        if cid in children or scan.coverage.graph_complete:
            deps.append({"ref": cid, "dependsOn": sorted(children.get(cid, []))})
    complete = scan.coverage.graph_complete and scan.coverage.unresolved == 0
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'scradar:' + scan.checksum)}",
        "version": 1,
        "metadata": {
            "timestamp": scan.created_at,
            "tools": {
                "components": [{"type": "application", "name": "SupplyChain Radar", "version": __version__}]
            },
            "component": {"type": "application", "bom-ref": ROOT_ID, "name": _r(root.name)},
        },
        "components": comps,
        "dependencies": deps,
        "compositions": [{"aggregate": "complete" if complete else "incomplete", "dependencies": [ROOT_ID]}],
    }
    if root.version:
        doc["metadata"]["component"]["version"] = root.version  # type: ignore[index]
    return json.dumps(doc, indent=2)


# --- comparison --------------------------------------------------------------------------------------


def comparison_to_markdown(cmp: ScanComparison) -> str:
    lines = [
        f"# Scan comparison — {_md(cmp.left.project)}",
        "",
        f"- Left: `{cmp.left.scan_id}` {cmp.left.created_at} ({cmp.left.advisory_mode}:{_md(cmp.left.snapshot_id or '-')}, {cmp.left.percent_evaluated}% evaluated)",
        f"- Right: `{cmp.right.scan_id}` {cmp.right.created_at} ({cmp.right.advisory_mode}:{_md(cmp.right.snapshot_id or '-')}, {cmp.right.percent_evaluated}% evaluated)",
        "",
        "| " + " | ".join(cmp.counts) + " |",
        "|" + "---:|" * len(cmp.counts),
        "| " + " | ".join(str(v) for v in cmp.counts.values()) + " |",
        "",
    ]
    lines += [f"> {_md(n)}" for n in cmp.notes] + [""]
    lines += ["## Advisory changes", ""]
    for c in cmp.findings:
        lines.append(
            f"- **{c.classification}** `{_md(c.advisory_id)}` {_md(c.package)} "
            f"{_md(c.version_before or '∅')} → {_md(c.version_after or '∅')} — {_md(c.cause)}: {_md(c.explanation)}"
        )
    lines += ["", "## Package changes", ""]
    for p in cmp.packages:
        lines.append(
            f"- {p.change}: {_md(p.ecosystem)}/{_md(p.name)} {_md(p.before or '')} → {_md(p.after or '')}"
        )
    return "\n".join(lines) + "\n"


def comparison_to_html(cmp: ScanComparison) -> str:
    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>Scan comparison — {_h(cmp.left.project)}</title><style>{_CSS}</style></head><body><main>",
        f"<span class='chip'>Scan comparison</span><h1>{_h(cmp.left.project)}</h1>",
        "<div class='grid'>",
    ]
    for k, v in cmp.counts.items():
        out.append(
            f"<div class='card'><div class='muted'>{_h(k.replace('_', ' '))}</div><div class='big'>{v}</div></div>"
        )
    out.append("</div>")
    for n in cmp.notes:
        out.append(f"<p class='card muted'>{_h(n)}</p>")
    out.append(
        "<h2>Advisory changes</h2><table><tr><th>Class</th><th>Advisory</th><th>Package</th><th>Cause</th></tr>"
    )
    for c in cmp.findings:
        out.append(
            f"<tr><td>{_h(c.classification)}</td><td>{_h(c.advisory_id)}</td><td>{_h(c.package)} "
            f"{_h(c.version_before or '∅')} → {_h(c.version_after or '∅')}</td><td>{_h(c.cause)}: {_h(c.explanation)}</td></tr>"
        )
    out.append(
        "</table><h2>Package changes</h2><table><tr><th>Change</th><th>Package</th><th>Before</th><th>After</th></tr>"
    )
    for p in cmp.packages:
        out.append(
            f"<tr><td>{_h(p.change)}</td><td>{_h(p.ecosystem)}/{_h(p.name)}</td><td>{_h(p.before)}</td><td>{_h(p.after)}</td></tr>"
        )
    out.append("</table></main></body></html>")
    return "".join(out)


def render(scan: ScanResult, fmt: str, *, policy: PolicyResult | None = None, path_prefix: str = "") -> str:
    if fmt == "json":
        return to_json(scan, policy)
    if fmt in {"markdown", "md"}:
        return to_markdown(scan, policy)
    if fmt == "html":
        return to_html(scan, policy)
    if fmt == "sarif":
        return to_sarif(scan, path_prefix)
    if fmt == "cyclonedx":
        return to_cyclonedx(scan)
    raise ValueError(f"unknown report format {fmt!r}; choose one of {', '.join(FORMATS)}")
