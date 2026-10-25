import { Database, FlaskConical, FolderPlus, Lightbulb } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { get, send } from "../api/client";
import type { Finding, Overview as OverviewData, Project, Severity } from "../api/types";
import { useFetch, useSelection } from "../app/state";
import { Button, Card, Chip, DemoBadge, Dial, Empty, ErrorBox, Label, PageHeader, Progress, SEV_COLOR, SeverityChip, Spinner, Stat, StateChip, shortDate } from "../components/ui";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export default function Overview() {
  const sel = useSelection();
  const nav = useNavigate();
  const { data: ov, error, loading, reload } = useFetch<OverviewData>(() => get("/overview"), [sel.projects.length, sel.scans.length, sel.scan?.state]);
  const scanId = sel.scan && ["completed", "partial"].includes(sel.scan.state) ? sel.scan.id : null;
  const { data: findings } = useFetch<{ items: Finding[] }>(scanId ? () => get(`/scans/${scanId}/findings`) : null, [scanId]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function loadDemo() {
    setBusy(true);
    setErr(null);
    try {
      await send("POST", "/demo");
      sel.reload();
      reload();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (loading && !ov) return <Spinner />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!ov) return null;

  if (ov.projects === 0) {
    return (
      <>
        <PageHeader eyebrow={<Chip tone="accent">No data yet</Chip>} title="Know what you depend on.">
          Import a lockfile or SBOM to see why a package is in your project, which known advisories apply, and which upgrade could remove them. Nothing is shown here until you do — there are no placeholder numbers.
        </PageHeader>
        <div className="grid gap-6 lg:grid-cols-2">
          <Empty icon={<FolderPlus className="h-6 w-6" />} title="Start with your own files" actions={<Link to="/projects"><Button>Create a project</Button></Link>}>
            Supports package-lock.json, pnpm-lock.yaml, poetry.lock, requirements.txt, CycloneDX and SPDX JSON. Files are parsed statically and never executed.
          </Empty>
          <Empty icon={<FlaskConical className="h-6 w-6" />} title="Or explore synthetic demo data" actions={<Button variant="soft" onClick={loadDemo} loading={busy}>Load demo data</Button>}>
            Creates three clearly labelled demo projects from synthetic fixtures (not real packages or advisories), including a release-to-release comparison.
          </Empty>
        </div>
        {err && <div className="mt-4"><ErrorBox error={err} /></div>}
      </>
    );
  }

  const scan = sel.scan;
  const sum = scan?.summary;
  const cov = sum?.coverage;
  const affectedPct = cov && cov.evaluated + cov.cached > 0 ? (new Set((findings?.items ?? []).map((f) => f.component_id)).size / (cov.evaluated + cov.cached)) * 100 : 0;
  const top = (findings?.items ?? []).slice().sort((a, b) => (b.priority.score ?? -1) - (a.priority.score ?? -1)).slice(0, 3);
  const trend = ov.trend.filter((t) => t.project_id === sel.project?.id).map((t, i) => ({ ...t, name: t.label ?? `scan ${i + 1}`, ...t.severity }));
  const worst = sum ? ORDER.find((s) => sum.severity[s] > 0) : null;
  const tip = findings?.items.find((f) => f.advisory.fixed_versions.length > 0);

  return (
    <>
      <PageHeader
        eyebrow={
          <div className="flex flex-wrap gap-2">
            {scan && <StateChip state={scan.state} />}
            {scan?.demo && <DemoBadge />}
            {sum && <Chip>{sum.advisory_source.mode.replace("_", " ")}</Chip>}
          </div>
        }
        title={sel.project?.name ?? "Overview"}
        actions={<Link to="/projects"><Button variant="soft">Import another file</Button></Link>}
      >
        {sum
          ? `${sum.findings} confirmed advisor${sum.findings === 1 ? "y" : "ies"} across ${sum.packages} packages — ${cov!.percent_evaluated}% of packages were evaluated${cov!.graph_complete ? "" : ", and the dependency graph is incomplete"}.`
          : "This project has no finished scan yet."}
      </PageHeader>

      {sum && cov ? (
        <section className="grid items-center gap-8 lg:grid-cols-[1fr_1.1fr]">
          <div>
            <Dial outer={cov.percent_evaluated} inner={affectedPct} center={sum.findings} caption="Confirmed advisories" sub={worst ? `Highest severity: ${worst}` : (cov.not_evaluated + cov.unsupported + cov.error + cov.unresolved === 0) ? "None matched" : "None matched · coverage incomplete"} />
            <div className="mx-auto mt-8 grid max-w-md grid-cols-2 gap-8">
              <div>
                <Label>Evaluated coverage</Label>
                <div className="font-headline mt-1 text-3xl font-bold text-accent">{cov.percent_evaluated}%</div>
              </div>
              <div className="text-right">
                <Label>Dependency graph</Label>
                <div className="font-headline mt-1 text-3xl font-bold">{cov.graph_complete ? "Complete" : "Partial"}</div>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {ORDER.map((s) => (
              <button key={s} onClick={() => nav(`/findings?severity=${s}`)} className="rounded-2xl border border-outline/30 bg-surface-low p-4 text-left transition hover:bg-surface-high" aria-label={`${sum.severity[s]} ${s} advisories — open filtered findings`}>
                <Label>{s}</Label>
                <div className="font-headline mt-2 text-3xl font-semibold" style={{ color: s === "unknown" ? undefined : SEV_COLOR[s] }}>{sum.severity[s]}</div>
              </button>
            ))}
            <Stat label="Not evaluated" value={cov.not_evaluated + cov.unsupported + cov.error} sub={`unresolved ${cov.unresolved} · errors ${cov.error}`} tone={cov.not_evaluated + cov.unsupported + cov.error > 0 ? "warn" : undefined} />
          </div>
        </section>
      ) : (
        <Empty title="No finished scan">Select or import a scan to see results.</Empty>
      )}

      <section className="mt-14">
        <div className="mb-5 flex items-end justify-between">
          <div>
            <h2 className="text-2xl font-semibold">Projects</h2>
            <p className="text-muted">{ov.projects} project{ov.projects === 1 ? "" : "s"} · {ov.scans} scan snapshot{ov.scans === 1 ? "" : "s"}</p>
          </div>
          <Link to="/projects" className="text-sm font-semibold text-accent hover:underline">View all</Link>
        </div>
        <div className="no-scrollbar flex snap-x gap-4 overflow-x-auto pb-4">
          {sel.projects.map((p) => <ProjectCard key={p.id} p={p} active={p.id === sel.project?.id} onOpen={() => sel.setProjectId(p.id)} />)}
        </div>
      </section>

      {trend.length > 0 && (
        <section className="mt-10">
          <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-2xl font-semibold">Advisory trend</h2>
              <p className="text-muted">Confirmed advisories per scan. Bars are labelled with their advisory source and evaluated coverage — a drop caused by lost coverage is not a fix.</p>
            </div>
            <div className="flex gap-4 text-xs font-medium">
              {(["critical", "high", "medium", "low"] as Severity[]).map((s) => <span key={s} className="flex items-center gap-2"><span className="h-3 w-3 rounded-full" style={{ background: SEV_COLOR[s] }} />{s}</span>)}
            </div>
          </div>
          <Card tone="low" className="h-80 !p-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={trend} margin={{ top: 8, right: 8, left: -16, bottom: 8 }} onClick={(e: any) => e?.activePayload?.[0] && (sel.setScanId(e.activePayload[0].payload.scan_id), nav("/findings"))}>
                <CartesianGrid vertical={false} stroke="rgb(var(--outline) / .4)" />
                <XAxis dataKey="name" tick={{ fill: "rgb(var(--muted))", fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: "rgb(var(--muted))", fontSize: 11 }} axisLine={false} tickLine={false} />
                <Tooltip cursor={{ fill: "rgb(var(--surface-high) / .5)" }} content={<TrendTip />} />
                {(["low", "medium", "high", "critical"] as Severity[]).map((s) => <Bar key={s} dataKey={s} stackId="a" fill={SEV_COLOR[s]} radius={s === "critical" ? [6, 6, 0, 0] : 0} cursor="pointer">{trend.map((_, i) => <Cell key={i} />)}</Bar>)}
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </section>
      )}

      {top.length > 0 && (
        <section className="mt-10">
          <h2 className="mb-5 text-2xl font-semibold">Top priorities</h2>
          <div className="grid gap-4 md:grid-cols-3">
            {top.map((f) => (
              <Link key={f.id} to={`/findings?open=${encodeURIComponent(f.id)}`} className="flex flex-col justify-between rounded-3xl bg-surface-high p-6 transition hover:bg-surface-top">
                <div className="flex items-start justify-between">
                  <SeverityChip level={f.advisory.severity.level} />
                  <span className="text-xs font-bold text-muted">{f.direct ? "direct" : "transitive"} · {f.scopes[0]}</span>
                </div>
                <div className="mt-8">
                  <h3 className="text-lg font-semibold">{f.package}</h3>
                  <div className="text-sm text-muted">{f.version} · {f.advisory.id}</div>
                  <div className="mt-2 flex items-baseline gap-2"><span className="font-headline text-2xl font-bold">{f.priority.score ?? "—"}</span><span className="text-sm text-muted">priority</span></div>
                  <div className="mt-3"><Progress value={f.priority.score ?? 0} tone={f.advisory.severity.level === "critical" ? "danger" : "warn"} label="priority score" /></div>
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}

      {tip && (
        <section className="mt-10">
          <Card tone="inverse" className="flex flex-col items-start gap-5 md:flex-row md:items-center">
            <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-white/10"><Lightbulb className="h-7 w-7" aria-hidden /></div>
            <div className="flex-1">
              <h3 className="text-xl font-semibold">Suggested next step</h3>
              <p className="mt-1 opacity-80">
                {tip.package} {tip.version} is affected by {tip.advisory.id}; the advisory lists {tip.advisory.fixed_versions.join(", ")} as fixed. {tip.direct ? "It is a direct dependency." : `It enters through ${tip.paths.introducers.map((i) => tip.names?.[i] ?? i.split(":").pop()).join(", ") || "other packages"}.`} Simulate the change before touching your lockfile.
              </p>
            </div>
            <Link to="/remediation"><Button variant="accent">Open Remediation Studio</Button></Link>
          </Card>
        </section>
      )}
      {!sum && <div className="mt-6 flex items-center gap-2 text-sm text-muted"><Database className="h-4 w-4" /> Results appear after a scan completes.</div>}
    </>
  );
}

function TrendTip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-2xl border border-outline bg-surface p-3 text-xs shadow-xl">
      <div className="font-semibold">{p.name}</div>
      <div className="text-muted">{shortDate(p.created_at)} · {p.mode?.replace("_", " ")}{p.snapshot ? ` · ${p.snapshot}` : ""}</div>
      <div className="mt-1">evaluated {p.percent_evaluated}%</div>
      {ORDER.map((s) => p[s] > 0 && <div key={s} style={{ color: SEV_COLOR[s] }}>{s}: {p[s]}</div>)}
      <div className="mt-1 text-muted">Click to open this scan's findings</div>
    </div>
  );
}

function ProjectCard({ p, active, onOpen }: { p: Project; active: boolean; onOpen: () => void }) {
  const sum = p.latest_scan?.summary;
  return (
    <button onClick={onOpen} aria-pressed={active} className={"w-72 shrink-0 snap-start rounded-3xl p-6 text-left transition " + (active ? "bg-surface-high ring-2 ring-accent/60" : "bg-surface-low hover:bg-surface-high")}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent-soft text-accent"><Database className="h-5 w-5" aria-hidden /></div>
        <div className="flex gap-1">{p.demo && <DemoBadge />}{p.active_scan && <StateChip state={p.active_scan.state} />}</div>
      </div>
      <h3 className="mt-6 text-lg font-semibold">{p.name}</h3>
      <div className="mt-2 flex justify-between text-sm"><span className="text-muted">Advisories</span><span className="font-headline font-bold">{sum ? sum.findings : "—"}</span></div>
      <div className="mt-2"><Progress value={sum?.coverage.percent_evaluated ?? 0} label="coverage" /></div>
      <div className="mt-1 text-xs text-muted">{sum ? `${sum.coverage.percent_evaluated}% evaluated · ${p.scan_count} scan${p.scan_count === 1 ? "" : "s"}` : "no finished scan"}</div>
    </button>
  );
}
