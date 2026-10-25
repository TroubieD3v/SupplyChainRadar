import { useEffect, useState } from "react";
import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { download, get, send } from "../api/client";
import type { Comparison, ScanMeta } from "../api/types";
import { useFetch, useSelection } from "../app/state";
import { Button, Card, Chip, Empty, ErrorBox, Label, Note, PageHeader, Select, Spinner, Stat, fmtDate, shortDate } from "../components/ui";

const CLS: Record<string, { tone: "danger" | "accent" | "warn" | "neutral" | "info"; text: string }> = {
  introduced: { tone: "danger", text: "introduced" },
  resolved: { tone: "accent", text: "resolved" },
  persistent: { tone: "neutral", text: "persistent" },
  reclassified: { tone: "warn", text: "reclassified" },
  unknown_due_to_data_gap: { tone: "info", text: "unknown (data gap)" },
};

export default function CompareTimeline() {
  const { project, scans, setScanId } = useSelection();
  const done = scans.filter((s) => ["completed", "partial"].includes(s.state));
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");
  const [cmp, setCmp] = useState<Comparison | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { data: tl, loading } = useFetch<{ points: ScanMeta[] }>(project ? () => get(`/projects/${project.id}/timeline`) : null, [project?.id, scans.length]);

  useEffect(() => {
    if (done.length >= 2) {
      setLeft(done[done.length - 1].id);
      setRight(done[0].id);
    } else {
      setLeft("");
      setRight("");
    }
    setCmp(null);
  }, [project?.id, done.length]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!left || !right || left === right) return setCmp(null);
    setBusy(true);
    send<Comparison>("POST", "/scans/compare", { left_scan_id: left, right_scan_id: right })
      .then((c) => (setCmp(c), setErr(null)))
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false));
  }, [left, right]);

  if (!project) return <Empty title="No project selected">Create or select a project first.</Empty>;
  const points = (tl?.points ?? []).map((p, i) => ({
    name: p.label ?? `scan ${i + 1}`,
    id: p.id,
    date: p.created_at,
    total: p.summary?.findings ?? 0,
    critical: p.summary?.severity.critical ?? 0,
    high: p.summary?.severity.high ?? 0,
    coverage: p.summary?.coverage.percent_evaluated ?? 0,
    snapshot: p.summary?.advisory_source.snapshot_id,
    mode: p.summary?.advisory_source.mode,
  }));
  const label = (s: ScanMeta) => `${s.label ?? "scan"} · ${fmtDate(s.created_at)}`;

  return (
    <>
      <PageHeader eyebrow={<Chip tone="info">Immutable snapshots</Chip>} title="Compare & Timeline">
        Separates dependency changes from advisory database updates, and never counts lost coverage as a fix.
      </PageHeader>

      {done.length < 2 ? (
        <Empty title="Two finished scans are needed">Import another version of this project (or re-scan the same lockfile against a newer advisory snapshot) to compare. {done.length === 1 ? "There is one finished scan so far." : ""}</Empty>
      ) : (
        <>
          <section className="mb-8">
            <h2 className="mb-3 text-2xl font-semibold">Timeline</h2>
            {loading && !tl ? <Spinner /> : (
              <Card tone="low" className="h-72 !p-4">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={points} margin={{ top: 8, right: 8, left: -12, bottom: 8 }}>
                    <CartesianGrid vertical={false} stroke="rgb(var(--outline) / .4)" />
                    <XAxis dataKey="name" tick={{ fill: "rgb(var(--muted))", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis yAxisId="l" allowDecimals={false} tick={{ fill: "rgb(var(--muted))", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis yAxisId="r" orientation="right" domain={[0, 100]} unit="%" tick={{ fill: "rgb(var(--muted))", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip content={({ active, payload }: any) => active && payload?.length ? (
                      <div className="rounded-2xl border border-outline bg-surface p-3 text-xs shadow-xl"><div className="font-semibold">{payload[0].payload.name}</div><div className="text-muted">{shortDate(payload[0].payload.date)} · {payload[0].payload.mode?.replace("_", " ")} {payload[0].payload.snapshot ?? ""}</div><div className="mt-1">advisories {payload[0].payload.total} (critical {payload[0].payload.critical}, high {payload[0].payload.high})</div><div>evaluated {payload[0].payload.coverage}%</div></div>
                    ) : null} />
                    <Area yAxisId="l" type="monotone" dataKey="total" name="advisories" stroke="rgb(var(--warn))" fill="rgb(var(--warn) / .18)" strokeWidth={2.5} />
                    <Line yAxisId="r" type="monotone" dataKey="coverage" name="evaluated %" stroke="rgb(var(--accent))" strokeWidth={2} strokeDasharray="5 4" dot={{ r: 3 }} />
                  </ComposedChart>
                </ResponsiveContainer>
              </Card>
            )}
            <p className="mt-2 text-xs text-muted">Orange area: confirmed advisories. Dashed green: share of packages evaluated — read the two together.</p>
          </section>

          <Card className="mb-8">
            <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
              <label className="block space-y-1.5"><span className="text-xs font-semibold text-muted">Earlier (left)</span><Select value={left} onChange={(e) => setLeft(e.target.value)}>{done.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}</Select></label>
              <label className="block space-y-1.5"><span className="text-xs font-semibold text-muted">Later (right)</span><Select value={right} onChange={(e) => setRight(e.target.value)}>{done.map((s) => <option key={s.id} value={s.id}>{label(s)}</option>)}</Select></label>
              <Button variant="soft" disabled={!cmp} onClick={() => download("/scans/compare/report", { left, right }, "scradar-comparison.html")}>Download HTML</Button>
            </div>
          </Card>

          {err && <ErrorBox error={err} />}
          {left === right && <Note tone="warn">Pick two different scans.</Note>}
          {busy && <Spinner />}
          {cmp && !busy && (
            <>
              <section className="grid grid-cols-2 gap-3 md:grid-cols-5">
                {Object.entries(cmp.counts).map(([k, v]) => <Stat key={k} label={CLS[k]?.text ?? k} value={v} tone={k === "introduced" && v > 0 ? "danger" : k === "resolved" && v > 0 ? "accent" : undefined} />)}
              </section>
              <div className="mt-4 space-y-3">{cmp.notes.map((n, i) => <Note key={i} tone="warn">{n}</Note>)}</div>
              <Card tone="low" className="mt-4">
                <Label>Advisory source & coverage</Label>
                <div className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                  <div>Left: {cmp.left.advisory_mode.replace("_", " ")} {cmp.left.snapshot_id ?? ""} · {cmp.left.percent_evaluated}% evaluated</div>
                  <div>Right: {cmp.right.advisory_mode.replace("_", " ")} {cmp.right.snapshot_id ?? ""} · {cmp.right.percent_evaluated}% evaluated</div>
                </div>
                {cmp.coverage_delta.not_evaluated_delta !== 0 && <p className="mt-2 text-sm text-warn">Not-evaluated packages changed by {cmp.coverage_delta.not_evaluated_delta > 0 ? "+" : ""}{cmp.coverage_delta.not_evaluated_delta}. Affected advisories are shown as “unknown”, not resolved.</p>}
              </Card>

              <h2 className="mb-3 mt-8 text-2xl font-semibold">Advisory changes</h2>
              <div className="overflow-x-auto rounded-3xl border border-outline/40">
                <table className="w-full min-w-[720px] text-left text-sm">
                  <thead className="bg-surface-low"><tr>{["Change", "Advisory", "Package", "Version", "Why"].map((h) => <th key={h} className="px-4 py-3"><Label>{h}</Label></th>)}</tr></thead>
                  <tbody>
                    {cmp.findings.map((f, i) => (
                      <tr key={i} className="border-t border-outline/30">
                        <td className="px-4 py-3"><Chip tone={CLS[f.classification].tone}>{CLS[f.classification].text}</Chip></td>
                        <td className="px-4 py-3"><button className="font-semibold hover:underline" onClick={() => setScanId(right)}>{f.advisory_id}</button><div className="text-xs text-muted">{f.severity_before && f.severity_after && f.severity_before !== f.severity_after ? `${f.severity_before} → ${f.severity_after}` : f.severity_after ?? f.severity_before}</div></td>
                        <td className="px-4 py-3">{f.package}</td>
                        <td className="px-4 py-3 font-mono text-xs">{f.version_before ?? "∅"} → {f.version_after ?? "∅"}</td>
                        <td className="px-4 py-3 text-xs text-muted"><span className="font-semibold text-ink">{f.cause.replace(/_/g, " ")}</span> — {f.explanation}</td>
                      </tr>
                    ))}
                    {cmp.findings.length === 0 && <tr><td colSpan={5} className="px-4 py-8 text-center text-muted">No advisories in either scan.</td></tr>}
                  </tbody>
                </table>
              </div>

              <h2 className="mb-3 mt-8 text-2xl font-semibold">Package changes</h2>
              {cmp.packages.length === 0 ? <p className="text-muted">The dependency inventory is identical.{cmp.advisory_source_changed ? " Any difference above comes from the advisory data." : ""}</p> : (
                <ul className="grid gap-2 sm:grid-cols-2">{cmp.packages.map((p, i) => <li key={i} className="flex items-center gap-2 rounded-2xl bg-surface-low px-4 py-2.5 text-sm"><Chip tone={p.change === "added" ? "accent" : p.change === "removed" ? "danger" : p.change === "downgraded" ? "warn" : "info"}>{p.change}</Chip><span className="font-semibold">{p.name}</span><span className="font-mono text-xs text-muted">{p.before ?? "∅"} → {p.after ?? "∅"}</span></li>)}</ul>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}
