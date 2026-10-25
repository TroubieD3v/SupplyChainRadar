import { Search, ShieldCheck } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { get } from "../api/client";
import type { Coverage, Finding, Severity } from "../api/types";
import { useFetch } from "../app/state";
import { FindingDrawer } from "../components/FindingDrawer";
import { RequireScan } from "../components/RequireScan";
import { Card, Chip, Empty, ErrorBox, Input, Note, PageHeader, Progress, Select, SeverityChip, Spinner, cx } from "../components/ui";

const SEVS: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export default function Findings() {
  return <RequireScan>{(scan) => <Body scanId={scan.id} />}</RequireScan>;
}

function Body({ scanId }: { scanId: string }) {
  const [sp, setSp] = useSearchParams();
  const sevs = (sp.get("severity") ?? "").split(",").filter(Boolean);
  const q = sp.get("q") ?? "";
  const scope = sp.get("scope") ?? "";
  const status = sp.get("status") ?? "";
  const open = sp.get("open");
  const update = (k: string, v: string | null) => {
    const n = new URLSearchParams(sp);
    if (v) n.set(k, v);
    else n.delete(k);
    setSp(n, { replace: true });
  };
  const { data, error, loading, reload } = useFetch<{ total: number; items: Finding[]; coverage: Coverage }>(
    () => get(`/scans/${scanId}/findings`, { severity: sevs.join(","), q, scope, status }),
    [scanId, sp.toString()],
  );
  const toggle = (s: Severity) => update("severity", (sevs.includes(s) ? sevs.filter((x) => x !== s) : [...sevs, s]).join(",") || null);
  const cov = data?.coverage;
  const gaps = cov ? cov.not_evaluated + cov.unsupported + cov.error : 0;

  return (
    <>
      <PageHeader eyebrow={<Chip tone="accent">Confirmed advisory matches</Chip>} title="Findings">
        Each finding is a published advisory matched to an exact package version — with its evidence, the dependency path that brought it in, and what could fix it. Presence is not proof of exploitability.
      </PageHeader>

      {cov && gaps + cov.unresolved > 0 && (
        <div className="mb-5"><Note tone="warn" title="This list is not exhaustive">{gaps} package(s) were not evaluated, unsupported or errored and {cov.unresolved} are unresolved. Findings for them are <b>unknown</b>, not absent.</Note></div>
      )}

      <Card tone="low" className="mb-5 !p-4">
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Severity filter">
          {SEVS.map((s) => <button key={s} aria-pressed={sevs.includes(s)} onClick={() => toggle(s)} className={cx("rounded-full transition", sevs.includes(s) ? "ring-2 ring-accent" : "opacity-70 hover:opacity-100")}><SeverityChip level={s} /></button>)}
          <div className="relative ml-auto min-w-[200px] flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" aria-hidden />
            <Input aria-label="Search findings" className="!py-2 !pl-9" placeholder="Package, advisory id, alias…" value={q} onChange={(e) => update("q", e.target.value || null)} />
          </div>
          <Select aria-label="Scope" className="!w-auto !py-2" value={scope} onChange={(e) => update("scope", e.target.value || null)}><option value="">Any scope</option><option>runtime</option><option>dev</option><option>optional</option></Select>
          <Select aria-label="Triage status" className="!w-auto !py-2" value={status} onChange={(e) => update("status", e.target.value || null)}><option value="">Any status</option><option value="open">open</option><option value="needs_review">needs review</option><option value="accepted_risk">accepted risk</option><option value="false_positive">false positive</option><option value="not_affected">not affected</option></Select>
        </div>
      </Card>

      {error && <ErrorBox error={error} onRetry={reload} />}
      {loading && !data && <Spinner />}
      {data && data.items.length === 0 && (
        <Empty icon={<ShieldCheck className="h-6 w-6" />} title={sevs.length || q || scope || status ? "No findings match these filters" : "No advisories matched"}>
          {sevs.length || q || scope || status ? "Clear a filter to see more." : gaps + cov!.unresolved > 0 ? "Nothing matched the packages that could be evaluated, but coverage is incomplete — this is not a clean result." : "No known advisory matched any package in the data source used for this scan. That is not proof the packages are safe."}
        </Empty>
      )}
      <ul className="space-y-3">
        {data?.items.map((f) => (
          <li key={f.id}>
            <button onClick={() => update("open", f.id)} className="w-full rounded-3xl border border-outline/40 bg-surface p-5 text-left transition hover:border-accent/60 hover:bg-surface-low">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityChip level={f.advisory.severity.level} />
                <span className="font-headline text-lg font-semibold">{f.package}</span>
                <span className="font-mono text-sm text-muted">{f.version}</span>
                <span className="ml-auto flex items-center gap-2">
                  {f.triage.status !== "open" && <Chip tone={f.triage.expired ? "danger" : "info"}>{f.triage.expired ? "expired · " : ""}{f.triage.status.replace("_", " ")}</Chip>}
                  <Chip tone={f.scopes[0] === "runtime" ? "accent" : "info"}>{f.scopes[0]}</Chip>
                  <Chip>{f.direct ? "direct" : "transitive"}</Chip>
                </span>
              </div>
              <div className="mt-2 text-sm"><span className="font-semibold">{f.advisory.id}</span> <span className="text-muted">{[...f.advisory.aliases].slice(0, 2).join(", ")}</span> — {f.advisory.summary ?? "no summary"}</div>
              <div className="mt-3 grid items-center gap-3 text-xs text-muted sm:grid-cols-[1fr_180px]">
                <div className="truncate font-mono">{f.path_labels?.[0]?.join(" → ") ?? "no dependency path"}{f.paths.total_found > 1 && <span className="ml-2 text-warn">+{f.paths.total_found - 1} more path{f.paths.total_found > 2 ? "s" : ""}</span>}</div>
                <div className="flex items-center gap-2"><Progress value={f.priority.score ?? 0} tone={f.advisory.severity.level === "critical" ? "danger" : "warn"} label="priority" /><span className="w-12 text-right font-semibold text-ink">{f.priority.score ?? "—"}</span></div>
              </div>
            </button>
          </li>
        ))}
      </ul>
      <FindingDrawer id={open} onClose={() => update("open", null)} onChanged={reload} />
    </>
  );
}
