"""`supplychain-radar` command line interface.

Exit codes: 0 ok / policy passed, 1 policy gate failed, 2 malformed input or usage error,
3 scanner/provider error, 4 incomplete evaluation when --fail-on-incomplete is set.
Machine-readable output goes to stdout (or --output); diagnostics go to stderr.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from scradar import __version__
from scradar.comparison.diff import compare_scans
from scradar.domain.models import Inventory, QueryState, ScanResult
from scradar.findings.scoring import load_kev
from scradar.ingestion.common import IngestError
from scradar.ingestion.detect import import_directory, import_zip, parse_file
from scradar.intelligence.providers import OSV_BASE_URL, FixtureProvider, OsvProvider
from scradar.policy.engine import (
    DEFAULT_POLICY,
    EXIT_GATE_FAILED,
    EXIT_INCONCLUSIVE,
    EXIT_PASS,
    EXIT_PROVIDER,
    EXIT_USAGE,
    ExceptionEntry,
    PolicyError,
    evaluate_policy,
    load_policy,
)
from scradar.remediation.simulator import Operation, simulate_candidate, simulate_hypothetical, suggest_fixes
from scradar.reports.render import comparison_to_html, comparison_to_markdown, render
from scradar.service import analyze, severity_counts

app = typer.Typer(
    name="supplychain-radar",
    help="Offline-first software supply chain security workbench: dependency paths, OSV advisories, "
    "remediation simulation, scan comparison and policy gates.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
policy_app = typer.Typer(help="Validate and evaluate policy-as-code files.", no_args_is_help=True)
import_app = typer.Typer(help="Validate inputs without any network traffic.", no_args_is_help=True)
remediate_app = typer.Typer(
    help="Remediation Studio: fix suggestions and upgrade simulations.", no_args_is_help=True
)
app.add_typer(policy_app, name="policy")
app.add_typer(import_app, name="import")
app.add_typer(remediate_app, name="remediate")

err = Console(stderr=True, highlight=False)
out = Console(highlight=False, soft_wrap=True, width=None if sys.stdout.isatty() else 160)

DEFAULT_CACHE = Path(os.environ.get("SCRADAR_CACHE_DIR", Path.home() / ".cache" / "supplychain-radar"))


class CliExit(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: int, message: str) -> None:
    err.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code)


def _stdout(text: str) -> None:
    """Always emit UTF-8 on stdout, even when the console code page (e.g. cp1251) cannot encode it."""

    data = (text if text.endswith("\n") else text + "\n").encode("utf-8")
    buf = getattr(sys.stdout, "buffer", None)
    if buf is not None:
        buf.write(data)
        buf.flush()
    else:
        sys.stdout.write(data.decode("utf-8"))


def _write(output: Path | None, text: str, overwrite: bool) -> None:
    if output is None:
        _stdout(text)
        return
    if output.exists() and not overwrite:
        _fail(EXIT_USAGE, f"{output} exists; pass --overwrite to replace it")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=output.parent, prefix=".scradar-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, output)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    err.print(f"wrote {output}")


def load_targets(targets: list[Path]) -> tuple[list[Inventory], list[str]]:
    invs: list[Inventory] = []
    errors: list[str] = []
    for t in targets:
        if not t.exists():
            errors.append(f"{t}: does not exist")
            continue
        if t.is_dir():
            res = import_directory(t)
            invs.extend(res.inventories)
            errors.extend(res.errors)
        elif t.suffix.lower() == ".zip":
            res = import_zip(t.read_bytes())
            invs.extend(res.inventories)
            errors.extend(res.errors)
        else:
            pyproject = None
            if t.name == "poetry.lock" and (t.parent / "pyproject.toml").is_file():
                pyproject = (t.parent / "pyproject.toml").read_bytes()
            invs.append(parse_file(t.name, t.read_bytes(), pyproject=pyproject, label=t.name))
    return invs, errors


def make_provider(offline: bool, fixture: Path | None, cache_dir: Path | None, osv_url: str):  # type: ignore[no-untyped-def]
    if fixture is not None:
        return FixtureProvider(fixture)
    return OsvProvider(base_url=osv_url, cache_dir=cache_dir, offline=offline)


def load_scan(path: Path) -> ScanResult:
    try:
        return ScanResult.model_validate_json(path.read_bytes())
    except Exception as exc:  # noqa: BLE001
        raise CliExit(
            EXIT_USAGE, f"{path}: not a SupplyChain Radar scan JSON ({type(exc).__name__})"
        ) from exc


def _table(scan: ScanResult) -> None:
    sc = severity_counts(scan)
    cov = scan.coverage
    src = scan.advisory_source
    if scan.demo:
        out.print("[bold yellow]DEMO DATA[/bold yellow] (synthetic fixtures)")
    out.print(f"[bold]{scan.project}[/bold]  scan {scan.scan_id}  {scan.created_at}")
    out.print(
        f"advisory source: {src.mode} via {src.provider}"
        + (f" snapshot={src.snapshot_id}" if src.snapshot_id else "")
        + f"  |  coverage: {cov.percent_evaluated}% of {cov.total_packages} evaluated"
        f" (not evaluated {cov.not_evaluated}, unsupported {cov.unsupported}, errors {cov.error}, unresolved {cov.unresolved})"
        + ("" if cov.graph_complete else "  |  graph INCOMPLETE")
    )
    out.print(" ".join(f"{k}={v}" for k, v in sc.items()))
    t = Table(show_lines=False)
    for col in ("Severity", "Advisory", "Package", "Scope", "Score", "Fixed in", "Shortest path"):
        t.add_column(col)
    names = scan.component_map()
    for f in scan.findings:
        path = f.paths.paths[0].nodes if f.paths.paths else []
        label = " > ".join((names[n].name if n in names else n) for n in path) or (f.paths.warning or "-")
        t.add_row(
            f.advisory.severity.level.value,
            f.advisory.id,
            f"{f.package}@{f.version}",
            f"{f.scopes[0] if f.scopes else '?'}{' direct' if f.direct else ''}",
            "-" if f.priority.score is None else f"{f.priority.score:.0f}",
            ", ".join(f.advisory.fixed_versions) or "-",
            label + (f" (+{f.paths.total_found - 1} more)" if f.paths.total_found > 1 else ""),
        )
    if scan.findings:
        out.print(t)
    else:
        if cov.evaluated + cov.cached == 0 and cov.total_packages:
            out.print(
                "[yellow]No package was evaluated against advisory data. This is NOT a clean result.[/yellow]"
            )
        else:
            out.print(
                "No advisory matched the evaluated packages."
                + (
                    ""
                    if cov.fully_covered
                    else " [yellow]Coverage is incomplete; this is not a clean bill of health.[/yellow]"
                )
            )


@app.callback(invoke_without_command=True)
def _main(
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.")] = False,
) -> None:
    if version:
        out.print(f"supplychain-radar {__version__}")
        raise typer.Exit(0)


@app.command()
def scan(
    targets: Annotated[
        list[Path], typer.Argument(help="Folders, lockfiles, SBOMs or .zip archives (static parsing only).")
    ],
    format: Annotated[
        str, typer.Option("--format", "-f", help="table|json|markdown|html|sarif|cyclonedx")
    ] = "table",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write to this file (atomic).")
    ] = None,
    overwrite: Annotated[bool, typer.Option(help="Allow replacing an existing output file.")] = False,
    offline: Annotated[
        bool, typer.Option(help="No network: use the local OSV cache only; misses are NOT EVALUATED.")
    ] = False,
    advisory_fixture: Annotated[
        Path | None, typer.Option(help="Frozen OSV-format advisory snapshot (implies no network).")
    ] = None,
    cache_dir: Annotated[Path | None, typer.Option(help="OSV cache directory.")] = DEFAULT_CACHE,
    project: Annotated[str | None, typer.Option(help="Project name shown in reports.")] = None,
    label: Annotated[str | None, typer.Option(help="Free-form scan label, e.g. a release tag.")] = None,
    policy: Annotated[Path | None, typer.Option(help="Evaluate this policy after the scan.")] = None,
    baseline: Annotated[Path | None, typer.Option(help="Baseline scan JSON for 'new finding' rules.")] = None,
    kev_file: Annotated[
        Path | None, typer.Option(help="Local CISA KEV JSON snapshot used in prioritisation.")
    ] = None,
    fail_on_incomplete: Annotated[
        bool, typer.Option(help="Exit 4 when any package is not evaluated/unsupported.")
    ] = False,
    allow_partial_import: Annotated[
        bool, typer.Option(help="Continue when some files fail to parse.")
    ] = False,
    demo: Annotated[bool, typer.Option(help="Mark the result as demo data.")] = False,
    osv_url: Annotated[str, typer.Option(hidden=True)] = OSV_BASE_URL,
) -> None:
    """Scan dependency files and match resolved packages against advisories."""

    try:
        invs, errors = load_targets(targets)
    except IngestError as exc:
        _fail(EXIT_USAGE, str(exc))
    for e in errors:
        err.print(f"[yellow]import problem:[/yellow] {e}")
    if errors and not allow_partial_import:
        _fail(
            EXIT_USAGE,
            f"{len(errors)} input file(s) could not be imported (use --allow-partial-import to continue)",
        )
    if not invs:
        _fail(EXIT_USAGE, "no supported dependency files found")
    try:
        provider = make_provider(offline, advisory_fixture, cache_dir, osv_url)
    except (ValueError, OSError) as exc:
        _fail(EXIT_USAGE, f"advisory source: {exc}")
    proj = project or (targets[0].resolve().name if targets[0].is_dir() else targets[0].resolve().parent.name)
    kev = load_kev(kev_file) if kev_file else None
    result = analyze(invs, provider, project=proj, label=label, demo=demo, kev=kev)
    result.warnings = [*(f"import problem: {e}" for e in errors), *result.warnings]

    pres = None
    if policy is not None:
        try:
            pol = load_policy(policy.read_text(encoding="utf-8"))
            base = load_scan(baseline) if baseline else None
            pres = evaluate_policy(pol, result, baseline=base)
        except (PolicyError, CliExit) as exc:
            _fail(getattr(exc, "code", EXIT_USAGE), str(exc))

    prefix = ""
    first = targets[0]
    if first.is_dir():
        try:
            prefix = first.resolve().relative_to(Path.cwd().resolve()).as_posix()
        except ValueError:
            prefix = ""
    if format == "table":
        if output:
            _write(output, render(result, "json", policy=pres), overwrite)
        _table(result)
    else:
        try:
            text = render(result, format, policy=pres, path_prefix=prefix)
        except ValueError as exc:
            _fail(EXIT_USAGE, str(exc))
        _write(output, text, overwrite)

    if pres is not None:
        err.print(f"policy {pres.policy}: {pres.outcome.upper()}")
        for v in pres.violations:
            err.print(f"  [red]fail[/red] {v.rule_id}: {v.message}")
        for v in pres.warnings:
            err.print(f"  [yellow]warn[/yellow] {v.rule_id}: {v.message}")
    provider_errors = sum(1 for e in result.evaluations if e.state == QueryState.ERROR)
    if provider_errors:
        err.print(
            f"[red]{provider_errors} package(s) could not be evaluated because of provider errors[/red]"
        )
        raise typer.Exit(EXIT_PROVIDER)
    if pres is not None and pres.exit_code:
        raise typer.Exit(pres.exit_code)
    if fail_on_incomplete and not result.coverage.fully_covered:
        err.print("[yellow]evaluation incomplete (--fail-on-incomplete)[/yellow]")
        raise typer.Exit(EXIT_INCONCLUSIVE)


@app.command()
def compare(
    left: Annotated[Path, typer.Argument(help="Earlier scan JSON")],
    right: Annotated[Path, typer.Argument(help="Later scan JSON")],
    format: Annotated[str, typer.Option("--format", "-f", help="table|json|markdown|html")] = "table",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    overwrite: bool = False,
) -> None:
    """Compare two immutable scan outputs (dependency, advisory and coverage changes)."""

    try:
        cmp = compare_scans(load_scan(left), load_scan(right))
    except CliExit as exc:
        _fail(exc.code, str(exc))
    if format == "json":
        _write(output, cmp.model_dump_json(indent=2), overwrite)
    elif format in {"markdown", "md"}:
        _write(output, comparison_to_markdown(cmp), overwrite)
    elif format == "html":
        _write(output, comparison_to_html(cmp), overwrite)
    elif format == "table":
        out.print(" ".join(f"{k}={v}" for k, v in cmp.counts.items()))
        for n in cmp.notes:
            out.print(f"[yellow]note:[/yellow] {n}")
        t = Table()
        for col in ("Class", "Cause", "Advisory", "Package", "Versions"):
            t.add_column(col)
        for c in cmp.findings:
            t.add_row(
                c.classification,
                c.cause,
                c.advisory_id,
                c.package,
                f"{c.version_before or '-'} -> {c.version_after or '-'}",
            )
        out.print(t)
        for p in cmp.packages:
            out.print(f"{p.change:>11} {p.ecosystem}/{p.name} {p.before or ''} -> {p.after or ''}")
    else:
        _fail(EXIT_USAGE, f"unknown format {format!r}")


@app.command()
def report(
    scan_json: Annotated[Path, typer.Argument(help="Scan JSON produced by `scan --format json`.")],
    format: Annotated[
        str, typer.Option("--format", "-f", help="json|markdown|html|sarif|cyclonedx")
    ] = "html",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    overwrite: bool = False,
    policy: Annotated[Path | None, typer.Option(help="Include this policy's result.")] = None,
    baseline: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Render a report from a stored scan."""

    try:
        scan_ = load_scan(scan_json)
        pres = None
        if policy:
            pres = evaluate_policy(
                load_policy(policy.read_text(encoding="utf-8")),
                scan_,
                baseline=load_scan(baseline) if baseline else None,
            )
        text = render(scan_, format, policy=pres)
    except (CliExit, PolicyError, ValueError) as exc:
        _fail(getattr(exc, "code", EXIT_USAGE), str(exc))
    _write(output, text, overwrite)


@policy_app.command("check")
def policy_check(
    scan_json: Annotated[Path, typer.Argument()],
    policy: Annotated[
        Path | None, typer.Option(help="Policy YAML (defaults to the built-in default policy).")
    ] = None,
    baseline: Annotated[Path | None, typer.Option(help="Baseline scan for 'newly introduced' rules.")] = None,
    exceptions: Annotated[Path | None, typer.Option(help="YAML list of additional exceptions.")] = None,
    format: Annotated[str, typer.Option("--format", "-f", help="table|json")] = "table",
) -> None:
    """Evaluate a policy. Exit 0 pass/warn, 1 gate failed, 2 usage error, 4 inconclusive."""

    import yaml

    try:
        pol = load_policy(policy.read_text(encoding="utf-8") if policy else DEFAULT_POLICY)
        scan_ = load_scan(scan_json)
        base = load_scan(baseline) if baseline else None
        extra = []
        if exceptions:
            raw = yaml.safe_load(exceptions.read_text(encoding="utf-8")) or []
            extra = [ExceptionEntry.model_validate(x) for x in raw]
        res = evaluate_policy(pol, scan_, baseline=base, extra_exceptions=extra)
    except (PolicyError, CliExit) as exc:
        _fail(getattr(exc, "code", EXIT_USAGE), str(exc))
    except Exception as exc:  # noqa: BLE001
        _fail(EXIT_USAGE, f"invalid input: {exc}")
    if format == "json":
        _stdout(res.model_dump_json(indent=2))
    else:
        color = {"pass": "green", "warn": "yellow", "fail": "red", "inconclusive": "yellow"}[res.outcome]
        out.print(
            f"policy [bold]{res.policy}[/bold]: [{color}]{res.outcome.upper()}[/{color}] (exit {res.exit_code})"
        )
        for v in res.violations:
            out.print(f"  [red]FAIL[/red] {v.rule_id}: {v.message}")
        for v in res.warnings:
            out.print(f"  [yellow]WARN[/yellow] {v.rule_id}: {v.message}")
        for s in res.suppressed:
            out.print(f"  suppressed {s.advisory_id} on {s.package}: {s.status} until {s.expires}")
        for n in res.notes:
            out.print(f"  note: {n}")
    raise typer.Exit(res.exit_code)


@policy_app.command("validate")
def policy_validate(policy: Annotated[Path, typer.Argument()]) -> None:
    """Validate a policy file."""

    try:
        pol = load_policy(policy.read_text(encoding="utf-8"))
    except PolicyError as exc:
        _fail(EXIT_USAGE, str(exc))
    out.print(f"policy '{pol.name}' is valid: {len(pol.rules)} rule(s), unknown_data={pol.unknown_data.mode}")


@import_app.command("validate")
def import_validate(path: Annotated[Path, typer.Argument()]) -> None:
    """Parse and validate an input statically (no network)."""

    try:
        invs, errors = load_targets([path])
    except IngestError as exc:
        _fail(EXIT_USAGE, str(exc))
    for e in errors:
        err.print(f"[red]invalid:[/red] {e}")
    for inv in invs:
        pkgs = sum(1 for c in inv.components.values() if c.kind == "package")
        out.print(
            f"[green]valid[/green] {inv.source_label}: {inv.format} {inv.format_version or ''} — {pkgs} packages, "
            f"{len(inv.edges)} edges, coverage {inv.coverage}, graph {'complete' if inv.graph_complete else 'incomplete'}"
        )
        for w in inv.warnings:
            out.print(f"  warning: {w}")
    if errors or not invs:
        raise typer.Exit(EXIT_USAGE)


@remediate_app.command("suggest")
def remediate_suggest(scan_json: Annotated[Path, typer.Argument()]) -> None:
    """List fixed versions sourced from advisories, with the packages that introduce each issue."""

    try:
        scan_ = load_scan(scan_json)
    except CliExit as exc:
        _fail(exc.code, str(exc))
    _stdout(json.dumps([s.model_dump() for s in suggest_fixes(scan_)], indent=2))


@remediate_app.command("candidate")
def remediate_candidate(
    base_scan: Annotated[Path, typer.Argument(help="Base scan JSON")],
    candidate: Annotated[list[Path], typer.Argument(help="Candidate lockfile(s)/folder")],
    offline: bool = False,
    advisory_fixture: Annotated[Path | None, typer.Option()] = None,
    cache_dir: Annotated[Path | None, typer.Option()] = DEFAULT_CACHE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    overwrite: bool = False,
    osv_url: Annotated[str, typer.Option(hidden=True)] = OSV_BASE_URL,
) -> None:
    """Authoritative simulation: rescan a concrete candidate lockfile and diff it against the base."""

    try:
        base = load_scan(base_scan)
        invs, errors = load_targets(candidate)
    except (CliExit, IngestError) as exc:
        _fail(getattr(exc, "code", EXIT_USAGE), str(exc))
    if errors or not invs:
        _fail(EXIT_USAGE, "; ".join(errors) or "no candidate inventory found")
    outcome, _ = simulate_candidate(base, invs, make_provider(offline, advisory_fixture, cache_dir, osv_url))
    _write(output, outcome.model_dump_json(indent=2), overwrite)


@remediate_app.command("propose")
def remediate_propose(
    base_scan: Annotated[Path, typer.Argument()],
    set_: Annotated[
        list[str] | None, typer.Option("--set", help="name@version or component-id=version")
    ] = None,
    remove: Annotated[list[str] | None, typer.Option("--remove", help="direct dependency to remove")] = None,
    offline: bool = False,
    advisory_fixture: Annotated[Path | None, typer.Option()] = None,
    cache_dir: Annotated[Path | None, typer.Option()] = DEFAULT_CACHE,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    overwrite: bool = False,
    osv_url: Annotated[str, typer.Option(hidden=True)] = OSV_BASE_URL,
) -> None:
    """Hypothetical simulation without a resolver (always reported as a prediction)."""

    ops: list[Operation] = []
    for s in set_ or []:
        if "=" in s:
            comp, ver = s.rsplit("=", 1)
        elif "@" in s[1:]:
            idx = s.rfind("@")
            comp, ver = s[:idx], s[idx + 1 :]
        else:
            _fail(EXIT_USAGE, f"--set expects name@version, got {s!r}")
        ops.append(Operation(op="set_version", component=comp, version=ver))
    ops.extend(Operation(op="remove", component=r) for r in remove or [])
    if not ops:
        _fail(EXIT_USAGE, "nothing to simulate: pass --set and/or --remove")
    try:
        base = load_scan(base_scan)
    except CliExit as exc:
        _fail(exc.code, str(exc))
    outcome, _ = simulate_hypothetical(
        base, ops, make_provider(offline, advisory_fixture, cache_dir, osv_url)
    )
    _write(output, outcome.model_dump_json(indent=2), overwrite)
    if outcome.status == "blocked":
        raise typer.Exit(EXIT_USAGE)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address (loopback by default).")] = "127.0.0.1",
    port: int = 8000,
) -> None:
    """Run the HTTP API and web UI."""

    import uvicorn

    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get("SCRADAR_API_TOKEN"):
        err.print("[yellow]warning:[/yellow] binding to a non-loopback address without SCRADAR_API_TOKEN set")
    uvicorn.run("scradar.api.app:create_app", factory=True, host=host, port=port, log_level="info")


@app.command()
def version() -> None:
    """Print the version."""

    out.print(f"supplychain-radar {__version__}")


__all__ = ["app", "EXIT_PASS", "EXIT_GATE_FAILED"]
