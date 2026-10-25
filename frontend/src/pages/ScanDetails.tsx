import { Check, Circle, X } from "lucide-react";
import { get } from "../api/client";
import { useFetch, useSelection } from "../app/state";
import { Card, Chip, DemoBadge, ErrorBox, Label, Note, PageHeader, Spinner, Stat, StateChip, fmtDate } from "../components/ui";
import { RequireScan } from "../components/RequireScan";
import { ScanMeta } from "../api/types";

const STAGES = ["queued", "parsing", "enriching", "analyzing", "completed"];

export default function ScanDetails() {
  const { scan, loading, project } = useSelection();
  // Failed/cancelled scans are inspectable here too (RequireScan would hide them).
  if (!loading && scan && ["failed", "cancelled"].includes(scan.state)) return <Body scan={scan} projectName={project?.name} />;
  return <RequireScan>{(s) => <Body scan={s} projectName={project?.name} />}</RequireScan>;
}

function Body({ scan, projectName }: { scan: ScanMeta; projectName?: string }) {
  const { data, error, loading, reload } = useFetch<any>(() => get(`/scans/${scan.id}`), [scan.id, scan.state]);
  const stageIdx = scan.state === "partial" ? 4 : STAGES.indexOf(scan.state);
  const failed = scan.state === "failed" || scan.state === "cancelled";
  const cov = scan.summary?.coverage;
  const src = scan.summary?.advisory_source;
  const dur = scan.started_at && scan.finished_at ? ((new Date(scan.finished_at).getTime() - new Date(scan.started_at).getTime()) / 1000).toFixed(1) : null;

  return (
    <>
      <PageHeader eyebrow={<div className="flex gap-2"><StateChip state={scan.state} />{scan.demo && <DemoBadge />}</div>} title="Scan Details">
        {projectName} · {scan.label ?? "scan"} · started {fmtDate(scan.started_at ?? scan.created_at)}{dur && ` · ${dur}s`}. Scans are immutable snapshots.
      </PageHeader>

      <Card tone="low" className="mb-6">
        <ol className="flex flex-wrap items-center gap-x-2 gap-y-3" aria-label="Scan progress">
          {STAGES.map((st, i) => {
            const done = !failed && i <= stageIdx;
            const current = !failed && i === stageIdx && st !== "completed";
            return (
              <li key={st} className="flex items-center gap-2">
                <span className={"flex h-7 w-7 items-center justify-center rounded-full text-xs " + (done ? "bg-accent text-on-accent" : "bg-surface-high text-muted") + (current ? " ring-2 ring-accent/50" : "")}>
                  {done ? <Check className="h-4 w-4" /> : <Circle className="h-3 w-3" />}
                </span>
                <span className={"text-sm font-semibold " + (done ? "" : "text-muted")}>{st === "completed" && scan.state === "partial" ? "partial" : st}</span>
                {i < STAGES.length - 1 && <span className="mx-1 h-px w-6 bg-outline" aria-hidden />}
              </li>
            );
          })}
          {failed && <li className="flex items-center gap-2 text-danger"><X className="h-5 w-5" /> {scan.state}</li>}
        </ol>
      </Card>

      {scan.error && <div className="mb-6"><ErrorBox error={scan.error} /></div>}
      {loading && !data && <Spinner />}
      {error && <ErrorBox error={error} onRetry={reload} />}

      {cov && (
        <section className="mb-8 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Packages" value={cov.total_packages} sub={`${data?.artifacts?.length ?? "…"} input file(s)`} />
          <Stat label="Evaluated" value={`${cov.percent_evaluated}%`} tone="accent" sub={`evaluated ${cov.evaluated} · cached ${cov.cached}`} />
          <Stat label="Gaps" value={cov.not_evaluated + cov.unsupported + cov.error} tone={cov.not_evaluated + cov.unsupported + cov.error ? "warn" : undefined} sub={`not evaluated ${cov.not_evaluated} · unsupported ${cov.unsupported} · errors ${cov.error}`} />
          <Stat label="Graph" value={cov.graph_complete ? "Complete" : "Partial"} tone={cov.graph_complete ? undefined : "warn"} sub={data?.graph ? `${data.graph.edges} edges · depth ${data.graph.max_depth}${data.graph.has_cycles ? " · cycles" : ""}` : undefined} />
        </section>
      )}

      {cov && cov.total_packages > 0 && (
        <Card tone="low" className="mb-8">
          <Label>Evaluation coverage</Label>
          <div className="mt-3 flex h-3 overflow-hidden rounded-full bg-surface-high" role="img" aria-label="Coverage breakdown">
            <div className="bg-accent" style={{ width: `${((cov.evaluated + cov.cached) / cov.total_packages) * 100}%` }} title="evaluated" />
            <div className="bg-warn" style={{ width: `${(cov.not_evaluated / cov.total_packages) * 100}%` }} title="not evaluated" />
            <div className="bg-info" style={{ width: `${(cov.unsupported / cov.total_packages) * 100}%` }} title="unsupported" />
            <div className="bg-danger" style={{ width: `${(cov.error / cov.total_packages) * 100}%` }} title="error" />
          </div>
          <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted">
            <span><span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-accent" />evaluated</span>
            <span><span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-warn" />not evaluated</span>
            <span><span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-info" />unsupported / unresolved</span>
            <span><span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-danger" />error</span>
          </div>
          {cov.notes.map((n, i) => <p key={i} className="mt-2 text-sm text-muted">• {n}</p>)}
        </Card>
      )}

      {src && (
        <Card className="mb-8">
          <Label>Advisory data source</Label>
          <dl className="mt-3 grid grid-cols-[150px_1fr] gap-y-2 text-sm">
            <dt className="text-muted">Mode</dt><dd className="font-semibold">{src.mode.replace("_", " ")} · {src.provider}</dd>
            {src.snapshot_id && <><dt className="text-muted">Snapshot</dt><dd className="font-mono text-xs">{src.snapshot_id} ({src.snapshot_generated})</dd></>}
            {src.fetched_at && <><dt className="text-muted">Fetched</dt><dd>{fmtDate(src.fetched_at)}</dd></>}
            <dt className="text-muted">Network</dt><dd>{src.offline ? "none (offline)" : "OSV API — ecosystem, name and version only"}</dd>
            <dt className="text-muted">Checksum</dt><dd className="break-all font-mono text-xs">{scan.summary?.checksum}</dd>
            {data?.engine_version && <><dt className="text-muted">Engine</dt><dd>{data.engine_version}</dd></>}
          </dl>
          {src.notes.map((n, i) => <p key={i} className="mt-3 text-sm text-muted">{n}</p>)}
        </Card>
      )}

      {data?.artifacts && (
        <section className="mb-8">
          <h2 className="mb-3 text-xl font-semibold">Inputs & provenance</h2>
          <div className="space-y-3">
            {data.artifacts.map((a: any, i: number) => (
              <Card key={i} tone="low">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-mono text-sm font-semibold">{a.source_label}</div>
                  <div className="flex gap-2"><Chip tone="info">{a.format} {a.format_version ?? ""}</Chip><Chip tone={a.coverage === "full" ? "accent" : "warn"}>coverage {a.coverage}</Chip><Chip tone={a.graph_complete ? "accent" : "warn"}>graph {a.graph_complete ? "complete" : "partial"}</Chip></div>
                </div>
                <p className="mt-2 text-xs text-muted">parser {a.parser} {a.parser_version} · {a.components} packages · {a.edges} edges · sha256 <span className="font-mono">{a.checksum.slice(0, 16)}…</span></p>
                {a.graph_note && <p className="mt-1 text-sm text-warn">{a.graph_note}</p>}
                {a.warnings.length > 0 && <ul className="mt-3 list-inside list-disc space-y-0.5 text-xs text-muted">{a.warnings.slice(0, 8).map((w: string, j: number) => <li key={j}>{w}</li>)}{a.warnings.length > 8 && <li>… {a.warnings.length - 8} more</li>}</ul>}
              </Card>
            ))}
          </div>
        </section>
      )}

      {data?.limitations && <Note tone="info" title="What this scan does not tell you"><ul className="list-inside list-disc space-y-1">{data.limitations.map((l: string, i: number) => <li key={i}>{l}</li>)}</ul></Note>}
      {!cov && scan.inputs.length > 0 && <Card tone="low"><Label>Inputs</Label><ul className="mt-2 text-sm">{scan.inputs.map((i) => <li key={i.sha256} className="font-mono text-xs">{i.name} · sha256 {i.sha256.slice(0, 16)}…</li>)}</ul></Card>}
    </>
  );
}
