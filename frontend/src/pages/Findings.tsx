import { Search, ShieldCheck } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { get } from "../api/client";
import type { Coverage, Finding, Severity } from "../api/types";
import { useFetch } from "../app/state";
import { FindingDrawer } from "../components/FindingDrawer";
import { RequireScan } from "../components/RequireScan";
import { Card, Chip, Empty, ErrorBox, Input, Note, PageHeader, Progress, Select, SeverityChip, Spinner, cx } from "../components/ui";

const SEVS: Severity[] = ["critical", "high", "medium", "low", "unknown"];
const TH = "border-b border-outline px-3 py-1.5 text-left text-xs font-medium text-muted";

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
      <PageHeader eyebrow={<Chip>Confirmed advisory matches</Chip>} title="Findings">
        Each finding is a published advisory matched to an exact package version — with its evidence, the dependency path that brought it in, and what could fix it. Presence is not proof of exploitability.
      </PageHeader>

      {cov && gaps + cov.unresolved > 0 && (
        <div className="mb-2"><Note tone="warn" title="This list is not exhaustive">{gaps} package(s) were not evaluated, unsupported or errored and {cov.unresolved} are unresolved. Findings for them are <b>unknown</b>, not absent.</Note></div>
      )}

      <Card className="!p-0">
        <div className="flex flex-wrap items-center gap-2 border-b border-outline px-3 py-1.5">
          <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Severity filter">
            {SEVS.map((s) => (
              <button
                key={s}
                aria-pressed={sevs.includes(s)}
                onClick={() => toggle(s)}
                className={cx("flex h-6 items-center rounded-[3px] border px-2 transition-colors", sevs.includes(s) ? "border-accent/60 bg-accent-soft" : "border-outline hover:bg-surface-high")}
              >
                <SeverityChip level={s} />
              </button>
            ))}
          </div>
          <div className="relative ml-auto min-w-[200px] flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-dim" aria-hidden />
            <Input aria-label="Search findings" className="!pl-6" placeholder="Package, advisory id, alias…" value={q} onChange={(e) => update("q", e.target.value || null)} />
          </div>
          <Select aria-label="Scope" className="!w-auto" value={scope} onChange={(e) => update("scope", e.target.value || null)}><option value="">Any scope</option><option>runtime</option><option>dev</option><option>optional</option></Select>
          <Select aria-label="Triage status" className="!w-auto" value={status} onChange={(e) => update("status", e.target.value || null)}><option value="">Any status</option><option value="open">open</option><option value="needs_review">needs review</option><option value="accepted_risk">accepted risk</option><option value="false_positive">false positive</option><option value="not_affected">not affected</option></Select>
        </div>

        {error && <div className="p-3"><ErrorBox error={error} onRetry={reload} /></div>}
        {loading && !data && <div className="px-3"><Spinner /></div>}
        {data && data.items.length === 0 && (
          <div className="p-3">
            <Empty icon={<ShieldCheck className="h-6 w-6" />} title={sevs.length || q || scope || status ? "No findings match these filters" : "No advisories matched"}>
              {sevs.length || q || scope || status ? "Clear a filter to see more." : gaps + cov!.unresolved > 0 ? "Nothing matched the packages that could be evaluated, but coverage is incomplete — this is not a clean result." : "No known advisory matched any package in the data source used for this scan. That is not proof the packages are safe."}
            </Empty>
          </div>
        )}
        {data && data.items.length > 0 && (
          <table className="w-full table-fixed text-[12.5px]">
            <thead>
              <tr>
                <th className={cx(TH, "w-[92px]")}>Severity</th>
                <th className={cx(TH, "w-[200px]")}>Component</th>
                <th className={TH}>Advisory</th>
                <th className={cx(TH, "w-[84px]")}>Scope</th>
                <th className={cx(TH, "w-[26%]")}>Introduced by</th>
                <th className={cx(TH, "w-[110px]")}>Analysis</th>
                <th className={cx(TH, "w-[120px]")}>Priority</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((f) => (
                <tr key={f.id} onClick={() => update("open", f.id)} className={cx("cursor-pointer border-b border-line-soft last:border-b-0", open === f.id ? "bg-accent-soft/60" : "hover:bg-surface-high/50")}>
                  <td className="px-3 py-1.5"><SeverityChip level={f.advisory.severity.level} /></td>
                  <td className="truncate px-3 py-1.5">
                    <button onClick={(e) => { e.stopPropagation(); update("open", f.id); }} className="text-left text-accent hover:underline">
                      {f.package}
                    </button>
                    <span className="ml-1.5 font-mono text-[11.5px] text-muted">{f.version}</span>
                  </td>
                  <td className="truncate px-3 py-1.5" title={f.advisory.summary ?? undefined}>
                    <span className="font-mono text-[11.5px]">{f.advisory.id}</span> <span className="text-muted">{f.advisory.summary ?? "no summary"}</span>
                  </td>
                  <td className="px-3 py-1.5 text-xs text-muted">{f.scopes[0]}</td>
                  <td className="truncate px-3 py-1.5 font-mono text-[11px] text-muted" title={f.path_labels?.[0]?.join(" → ")}>
                    <span className="mr-1 font-sans text-xs">{f.direct ? "direct" : "transitive"}</span>
                    {f.path_labels?.[0]?.slice(1, -1).join(" → ") || ""}
                    {f.paths.total_found > 1 && <span className="ml-1 font-sans text-warn">+{f.paths.total_found - 1}</span>}
                  </td>
                  <td className="px-3 py-1.5">
                    {f.triage.status === "open" ? <span className="text-xs text-dim">not set</span> : <Chip tone={f.triage.expired ? "danger" : "info"}>{f.triage.expired ? "expired · " : ""}{f.triage.status.replace("_", " ")}</Chip>}
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="flex items-center gap-2">
                      <Progress value={f.priority.score ?? 0} tone={f.advisory.severity.level === "critical" ? "danger" : "warn"} label="priority" />
                      <span className="w-8 text-right font-mono text-xs">{f.priority.score ?? "—"}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {data && data.items.length > 0 && <div className="border-t border-outline px-3 py-1.5 text-[11px] text-dim">{data.items.length} of {data.total} findings</div>}
      </Card>
      <FindingDrawer id={open} onClose={() => update("open", null)} onChanged={reload} />
    </>
  );
}
