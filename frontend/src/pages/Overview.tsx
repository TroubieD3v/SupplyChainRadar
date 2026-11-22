import { ArrowRight, FlaskConical, FolderPlus } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { get, send } from "../api/client";
import type { Finding, Overview as OverviewData, Project, Severity } from "../api/types";
import { useFetch, useSelection } from "../app/state";
import { Button, Card, Chip, DemoBadge, Empty, ErrorBox, Note, PageHeader, PanelHead, Progress, SEV_CLASS, SEV_COLOR, SeverityChip, Spinner, StateChip, cx, shortDate } from "../components/ui";

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
        <div className="grid gap-3 lg:grid-cols-2">
          <Empty icon={<FolderPlus className="h-6 w-6" />} title="Start with your own files" actions={<Link to="/projects"><Button>Create a project</Button></Link>}>
            Supports package-lock.json, pnpm-lock.yaml, poetry.lock, requirements.txt, CycloneDX and SPDX JSON. Files are parsed statically and never executed.
          </Empty>
          <Empty icon={<FlaskConical className="h-6 w-6" />} title="Or explore synthetic demo data" actions={<Button variant="soft" onClick={loadDemo} loading={busy}>Load demo data</Button>}>
            Creates three clearly labelled demo projects from synthetic fixtures (not real packages or advisories), including a release-to-release comparison.
          </Empty>
        </div>
        {err && <div className="mt-3"><ErrorBox error={err} /></div>}
      </>
    );
  }

  const scan = sel.scan;
  const sum = scan?.summary;
  const cov = sum?.coverage;
  const top = (findings?.items ?? []).slice().sort((a, b) => (b.priority.score ?? -1) - (a.priority.score ?? -1)).slice(0, 6);
  const trend = ov.trend.filter((t) => t.project_id === sel.project?.id).map((t, i) => ({ ...t, name: t.label ?? `scan ${i + 1}`, ...t.severity }));
  const tip = findings?.items.find((f) => f.advisory.fixed_versions.length > 0);
  const notEval = cov ? cov.not_evaluated + cov.unsupported + cov.error : 0;
  const th = "border-b border-outline px-3 py-1.5 text-left text-xs font-medium text-muted";

  return (
    <>
      <PageHeader
        eyebrow={
          <>
            {scan && <StateChip state={scan.state} />}
            {scan?.demo && <DemoBadge />}
            {sum && <Chip>{sum.advisory_source.mode.replace("_", " ")}</Chip>}
          </>
        }
        title={sel.project?.name ?? "Overview"}
        actions={<Link to="/projects"><Button variant="soft">Import another file</Button></Link>}
      >
        {sum
          ? `${sum.findings} confirmed advisor${sum.findings === 1 ? "y" : "ies"} across ${sum.packages} packages — ${cov!.percent_evaluated}% of packages were evaluated${cov!.graph_complete ? "" : ", and the dependency graph is incomplete"}.`
          : "This project has no finished scan yet."}
      </PageHeader>

      {sum && cov ? (
        <section aria-label="Severity counters" className="grid grid-cols-2 gap-px overflow-hidden rounded-[3px] border border-outline bg-outline sm:grid-cols-4 xl:grid-cols-9">
          {ORDER.map((s) => (
            <button
              key={s}
              onClick={() => nav(`/findings?severity=${s}`)}
              className="bg-surface px-3 py-2 text-left transition-colors hover:bg-surface-high"
              aria-label={`${sum.severity[s]} ${s} advisories — open filtered findings`}
            >
              <div className="flex items-center gap-1.5 text-xs capitalize text-muted">
                <span className={cx("size-2 rounded-[1px]", SEV_CLASS[s])} aria-hidden />
                {s === "unknown" ? "unassigned" : s}
              </div>
              <div className="font-mono text-[18px] font-medium leading-7" style={{ color: sum.severity[s] && s !== "unknown" ? SEV_COLOR[s] : undefined }}>
                {sum.severity[s]}
              </div>
            </button>
          ))}
          <SumCell label="Confirmed advisories" value={sum.findings} />
          <SumCell label="Packages" value={sum.packages} />
          <SumCell label="Evaluated" value={`${cov.percent_evaluated}%`} tone="ok" />
          <SumCell label="Not evaluated" value={notEval} sub={`unresolved ${cov.unresolved} · errors ${cov.error}`} tone={notEval > 0 ? "warn" : undefined} />
        </section>
      ) : (
        <Empty title="No finished scan">Select or import a scan to see results.</Empty>
      )}

      <div className="mt-3 grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
        <Card className="!p-0">
          <PanelHead title="Advisory trend">
            {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
              <span key={s} className="flex items-center gap-1 capitalize">
                <span className="size-2 rounded-[1px]" style={{ background: SEV_COLOR[s] }} />
                {s}
              </span>
            ))}
          </PanelHead>
          {trend.length > 0 ? (
            <div className="h-64 px-2 pb-1 pt-3">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={trend} margin={{ top: 4, right: 8, left: -18, bottom: 0 }} barCategoryGap="32%" onClick={(e: any) => e?.activePayload?.[0] && (sel.setScanId(e.activePayload[0].payload.scan_id), nav("/findings"))}>
                  <CartesianGrid vertical={false} stroke="rgb(var(--outline))" />
                  <XAxis dataKey="name" tick={{ fill: "rgb(var(--muted))", fontSize: 10.5 }} axisLine={{ stroke: "rgb(var(--outline))" }} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: "rgb(var(--muted))", fontSize: 10.5 }} axisLine={false} tickLine={false} />
                  <Tooltip cursor={{ fill: "rgb(var(--surface-high) / .5)" }} content={<TrendTip />} />
                  {(["low", "medium", "high", "critical"] as Severity[]).map((s) => (
                    <Bar key={s} dataKey={s} stackId="a" fill={SEV_COLOR[s]} cursor="pointer" maxBarSize={34} isAnimationActive={false} />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="px-3 py-8 text-center text-xs text-muted">Import a second scan to see a trend.</p>
          )}
          <p className="border-t border-outline px-3 py-1.5 text-[11px] text-dim">Confirmed advisories per scan. A drop caused by lost coverage is not a fix; hover a bar for its source and coverage.</p>
        </Card>

        <Card className="!p-0">
          <PanelHead title="Top priorities">
            <Link to="/findings" className="flex items-center gap-1 text-accent hover:underline">
              All findings <ArrowRight className="h-3 w-3" />
            </Link>
          </PanelHead>
          {top.length === 0 ? (
            <p className="px-3 py-8 text-center text-xs text-muted">No confirmed advisories in this scan.</p>
          ) : (
            <table className="w-full table-fixed text-[12.5px]">
              <thead>
                <tr>
                  <th className={cx(th, "w-[86px]")}>Severity</th>
                  <th className={th}>Package</th>
                  <th className={cx(th, "w-[150px]")}>Advisory</th>
                  <th className={cx(th, "w-[92px]")}>Path</th>
                  <th className={cx(th, "w-[120px]")}>Priority</th>
                </tr>
              </thead>
              <tbody>
                {top.map((f) => (
                  <tr key={f.id} className="border-b border-line-soft last:border-b-0 hover:bg-surface-high/50">
                    <td className="px-3 py-1.5"><SeverityChip level={f.advisory.severity.level} /></td>
                    <td className="truncate px-3 py-1.5">
                      <Link to={`/findings?open=${encodeURIComponent(f.id)}`} className="text-accent hover:underline">{f.package}</Link>
                      <span className="ml-1.5 font-mono text-[11.5px] text-muted">{f.version}</span>
                    </td>
                    <td className="truncate px-3 py-1.5 font-mono text-[11.5px] text-muted">{f.advisory.id}</td>
                    <td className="px-3 py-1.5 text-xs text-muted">{f.direct ? "direct" : "transitive"}</td>
                    <td className="px-3 py-1.5">
                      <div className="flex items-center gap-2">
                        <Progress value={f.priority.score ?? 0} tone={f.advisory.severity.level === "critical" ? "danger" : "warn"} label="priority score" />
                        <span className="w-7 text-right font-mono text-xs">{f.priority.score ?? "—"}</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {tip && (
            <div className="border-t border-outline p-2">
              <Note title="Suggested next step">
                {tip.package} {tip.version} is affected by {tip.advisory.id}; the advisory lists {tip.advisory.fixed_versions.join(", ")} as fixed. {tip.direct ? "It is a direct dependency." : `It enters through ${tip.paths.introducers.map((i) => tip.names?.[i] ?? i.split(":").pop()).join(", ") || "other packages"}.`} Simulate the change before touching your lockfile.{" "}
                <Link to="/remediation" className="text-accent hover:underline">Open Remediation Studio</Link>
              </Note>
            </div>
          )}
        </Card>
      </div>

      <Card className="mt-3 !p-0">
        <PanelHead title="Projects">
          <span>{ov.projects} project{ov.projects === 1 ? "" : "s"} · {ov.scans} scan snapshot{ov.scans === 1 ? "" : "s"}</span>
          <Link to="/projects" className="text-accent hover:underline">View all</Link>
        </PanelHead>
        <table className="w-full text-[12.5px]">
          <thead>
            <tr>
              <th className={th}>Project</th>
              <th className={th}>Latest scan</th>
              <th className={cx(th, "w-[260px]")}>Advisories</th>
              <th className={cx(th, "w-[200px]")}>Evaluated</th>
              <th className={cx(th, "w-[70px] text-right")}>Scans</th>
            </tr>
          </thead>
          <tbody>
            {sel.projects.map((p) => <ProjectRow key={p.id} p={p} active={p.id === sel.project?.id} onOpen={() => sel.setProjectId(p.id)} />)}
          </tbody>
        </table>
      </Card>
    </>
  );
}

function SumCell({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: string; tone?: "ok" | "warn" }) {
  return (
    <div className="bg-surface px-3 py-2">
      <div className="truncate text-xs text-muted">{label}</div>
      <div className={cx("font-mono text-[18px] font-medium leading-7", tone === "ok" && "text-ok", tone === "warn" && "text-warn")}>{value}</div>
      {sub && <div className="truncate text-[11px] text-dim">{sub}</div>}
    </div>
  );
}

function TrendTip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-[3px] border border-outline bg-surface px-2.5 py-2 text-xs">
      <div className="font-medium">{p.name}</div>
      <div className="text-muted">{shortDate(p.created_at)} · {p.mode?.replace("_", " ")}{p.snapshot ? ` · ${p.snapshot}` : ""}</div>
      <div className="mt-1">evaluated {p.percent_evaluated}%</div>
      {ORDER.map((s) => p[s] > 0 && <div key={s} style={{ color: SEV_COLOR[s] }}>{s}: {p[s]}</div>)}
      <div className="mt-1 text-dim">Click to open this scan's findings</div>
    </div>
  );
}

function SevBar({ sev }: { sev: Record<Severity, number> }) {
  const total = ORDER.reduce((a, s) => a + (sev[s] ?? 0), 0);
  if (!total) return <span className="text-xs text-dim">none</span>;
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-32 overflow-hidden bg-surface-high" role="img" aria-label={ORDER.map((s) => `${sev[s]} ${s}`).join(", ")}>
        {ORDER.map((s) => sev[s] > 0 && <span key={s} className={SEV_CLASS[s]} style={{ width: `${(100 * sev[s]) / total}%` }} />)}
      </div>
      <span className="font-mono text-[11.5px] text-muted">
        {ORDER.slice(0, 4).map((s) => sev[s]).join(" / ")}
      </span>
    </div>
  );
}

function ProjectRow({ p, active, onOpen }: { p: Project; active: boolean; onOpen: () => void }) {
  const sum = p.latest_scan?.summary;
  return (
    <tr className={cx("border-b border-line-soft last:border-b-0", active ? "bg-accent-soft/60" : "hover:bg-surface-high/50")}>
      <td className="px-3 py-1.5">
        <button onClick={onOpen} aria-pressed={active} className="text-left text-accent hover:underline">
          {p.name}
        </button>
        <span className="ml-2 inline-flex gap-1 align-middle">
          {p.demo && <DemoBadge />}
          {p.active_scan && <StateChip state={p.active_scan.state} />}
        </span>
      </td>
      <td className="px-3 py-1.5 text-xs text-muted">{p.latest_scan ? `${p.latest_scan.label ?? "scan"} · ${shortDate(p.latest_scan.created_at)}` : "—"}</td>
      <td className="px-3 py-1.5">{sum ? <SevBar sev={sum.severity} /> : <span className="text-xs text-dim">no finished scan</span>}</td>
      <td className="px-3 py-1.5">
        <div className="flex items-center gap-2">
          <Progress value={sum?.coverage.percent_evaluated ?? 0} label="coverage" />
          <span className="w-10 text-right font-mono text-xs">{sum ? `${sum.coverage.percent_evaluated}%` : "—"}</span>
        </div>
      </td>
      <td className="px-3 py-1.5 text-right font-mono text-xs">{p.scan_count}</td>
    </tr>
  );
}
