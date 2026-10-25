import { Search } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { get } from "../api/client";
import type { ComponentRow, Finding } from "../api/types";
import { useFetch } from "../app/state";
import { PathList } from "../components/FindingDrawer";
import { RequireScan } from "../components/RequireScan";
import { Button, Card, Chip, Drawer, ErrorBox, Input, Label, PageHeader, Select, SeverityChip, Spinner, StateChip } from "../components/ui";

export default function Dependencies() {
  return <RequireScan>{(scan) => <Body scanId={scan.id} />}</RequireScan>;
}

function Body({ scanId }: { scanId: string }) {
  const [sp, setSp] = useSearchParams();
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<string | null>(sp.get("open"));
  const f = { q: sp.get("q") ?? "", ecosystem: sp.get("ecosystem") ?? "", scope: sp.get("scope") ?? "", state: sp.get("state") ?? "", vulnerable: sp.get("vulnerable") ?? "", direct: sp.get("direct") ?? "", license: sp.get("license") ?? "", sort: sp.get("sort") ?? "name" };
  const set = (k: string, v: string) => {
    const n = new URLSearchParams(sp);
    if (v) n.set(k, v);
    else n.delete(k);
    setSp(n, { replace: true });
    setPage(1);
  };
  const { data, error, loading, reload } = useFetch<{ total: number; items: ComponentRow[]; ecosystems: string[]; page_size: number }>(
    () => get(`/scans/${scanId}/components`, { ...f, page, page_size: 50 }),
    [scanId, page, sp.toString()],
  );
  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1;

  return (
    <>
      <PageHeader title="Dependencies" eyebrow={<Chip tone="info">{data?.total ?? "…"} packages match</Chip>}>
        Every resolved package with its scope, advisory state and number of parents. Select a row for all parent paths and the exact lockfile location.
      </PageHeader>
      <Card tone="low" className="mb-5 !p-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="relative sm:col-span-2">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" aria-hidden />
            <Input aria-label="Search packages" className="!pl-9" placeholder="Search name or purl…" value={f.q} onChange={(e) => set("q", e.target.value)} />
          </div>
          <Select aria-label="Ecosystem" value={f.ecosystem} onChange={(e) => set("ecosystem", e.target.value)}><option value="">All ecosystems</option>{data?.ecosystems.map((e) => <option key={e}>{e}</option>)}</Select>
          <Select aria-label="Scope" value={f.scope} onChange={(e) => set("scope", e.target.value)}><option value="">Any scope</option><option>runtime</option><option>dev</option><option>optional</option><option>unknown</option></Select>
          <Select aria-label="Evaluation state" value={f.state} onChange={(e) => set("state", e.target.value)}><option value="">Any state</option><option value="evaluated">evaluated</option><option value="cached">cached</option><option value="not_evaluated">not evaluated</option><option value="unsupported">unsupported</option><option value="error">error</option></Select>
          <Select aria-label="Vulnerability" value={f.vulnerable} onChange={(e) => set("vulnerable", e.target.value)}><option value="">Vulnerable or not</option><option value="true">With advisories</option><option value="false">Without advisories</option></Select>
          <Select aria-label="Directness" value={f.direct} onChange={(e) => set("direct", e.target.value)}><option value="">Direct & transitive</option><option value="true">Direct only</option><option value="false">Transitive only</option></Select>
          <Input aria-label="License" placeholder="License contains…" value={f.license} onChange={(e) => set("license", e.target.value)} />
          <Select aria-label="Sort" value={f.sort} onChange={(e) => set("sort", e.target.value)}><option value="name">Sort: name</option><option value="severity">Sort: severity</option><option value="depth">Sort: depth</option></Select>
        </div>
      </Card>

      {error && <ErrorBox error={error} onRetry={reload} />}
      {loading && !data && <Spinner />}
      {data && (
        <div className="overflow-x-auto rounded-3xl border border-outline/40">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="bg-surface-low"><tr>{["Package", "Scope", "Depth", "Parents", "License", "State", "Advisories"].map((h) => <th key={h} className="px-4 py-3"><Label>{h}</Label></th>)}</tr></thead>
            <tbody>
              {data.items.map((c) => (
                <tr key={c.id} tabIndex={0} onClick={() => setOpen(c.id)} onKeyDown={(e) => e.key === "Enter" && setOpen(c.id)} className="cursor-pointer border-t border-outline/30 hover:bg-surface-low focus-visible:bg-surface-low" aria-label={`${c.name} ${c.version ?? "unresolved"}`}>
                  <td className="px-4 py-3"><div className="font-semibold">{c.name}</div><div className="font-mono text-xs text-muted">{c.version ?? "unresolved"} · {c.ecosystem}{c.declared && !c.resolved ? ` · ${c.declared}` : ""}</div></td>
                  <td className="px-4 py-3"><Chip tone={c.scopes[0] === "runtime" ? "accent" : "info"}>{c.scopes[0] ?? "?"}</Chip> {c.direct && <Chip tone="neutral">direct</Chip>}</td>
                  <td className="px-4 py-3">{c.depth ?? <span className="text-muted" title="No path from the application root">—</span>}</td>
                  <td className="px-4 py-3">{c.parents}</td>
                  <td className="px-4 py-3 text-xs">{c.licenses.join(", ") || <span className="text-muted">not declared</span>}</td>
                  <td className="px-4 py-3"><StateChip state={c.state} /></td>
                  <td className="px-4 py-3">{c.advisories > 0 ? <span className="flex items-center gap-2"><SeverityChip level={c.max_severity} /><span className="font-semibold">{c.advisories}</span></span> : <span className="text-muted">{["evaluated", "cached"].includes(c.state) ? "none found" : "unknown"}</span>}</td>
                </tr>
              ))}
              {data.items.length === 0 && <tr><td colSpan={7} className="px-4 py-10 text-center text-muted">No packages match these filters.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      {data && pages > 1 && (
        <div className="mt-4 flex items-center justify-between text-sm text-muted">
          <span>Page {page} of {pages}</span>
          <div className="flex gap-2"><Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button><Button size="sm" variant="outline" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</Button></div>
        </div>
      )}
      <ComponentDrawer scanId={scanId} id={open} onClose={() => setOpen(null)} />
    </>
  );
}

function ComponentDrawer({ scanId, id, onClose }: { scanId: string; id: string | null; onClose: () => void }) {
  const { data, error, loading } = useFetch<any>(id ? () => get(`/scans/${scanId}/components/${encodeURIComponent(id).replace(/%3A/g, ":").replace(/%40/g, "@")}`) : null, [scanId, id]);
  const c = data?.component;
  return (
    <Drawer open={Boolean(id)} onClose={onClose} wide title={c ? `${c.name}${c.version ? "@" + c.version : ""}` : "Package"}>
      {loading && <Spinner />}
      {error && <ErrorBox error={error} />}
      {c && (
        <div className="space-y-7">
          <div className="flex flex-wrap gap-2">
            {data.evaluation && <StateChip state={data.evaluation.state} />}
            <Chip tone="neutral">{c.ecosystem}</Chip>
            <Chip tone={c.scopes[0] === "runtime" ? "accent" : "info"}>{c.scopes[0]}</Chip>
            <Chip>{c.direct ? "direct" : "transitive"}</Chip>
            {c.source && <Chip>{c.source}</Chip>}
          </div>
          <dl className="grid grid-cols-[130px_1fr] gap-y-2 text-sm">
            <dt className="text-muted">purl</dt><dd className="break-all font-mono text-xs">{c.purl ?? "— (not a valid registry identity)"}</dd>
            <dt className="text-muted">Declared</dt><dd className="font-mono text-xs">{c.declared ?? "—"}</dd>
            <dt className="text-muted">Licenses</dt><dd>{c.licenses.join(", ") || "not declared"}</dd>
            <dt className="text-muted">Advisory state</dt><dd>{data.evaluation?.note ?? c.unsupported_reason ?? "—"}</dd>
            {c.unsupported_reason && <><dt className="text-muted">Not evaluated because</dt><dd className="text-warn">{c.unsupported_reason}</dd></>}
          </dl>
          <section><Label>Where it comes from</Label><ul className="mt-2 space-y-1 text-sm">{c.locations.map((l: any, i: number) => <li key={i} className="font-mono text-xs"><span className="font-semibold">{l.file}{l.line ? `:${l.line}` : ""}</span> <span className="text-muted">{l.detail}</span></li>)}</ul></section>
          <section><Label>All parent paths ({data.paths.total_found}{data.paths.truncated ? "+" : ""})</Label><div className="mt-3"><PathList paths={data.paths.paths} names={data.names} truncated={data.paths.truncated} warning={data.paths.warning} /></div></section>
          <section>
            <Label>Direct parents ({data.parents.length})</Label>
            <ul className="mt-2 space-y-1 text-sm">{data.parents.map((p: any, i: number) => <li key={i}><span className="font-semibold">{p.name}{p.version ? `@${p.version}` : ""}</span> <span className="text-muted">— {p.type}{p.constraint ? `, requires ${p.constraint}` : ""}{p.confidence === "inferred" ? " (inferred)" : ""}{p.provenance ? ` · ${p.provenance.file}${p.provenance.line ? ":" + p.provenance.line : ""}` : ""}</span></li>)}</ul>
          </section>
          {data.children.length > 0 && <section><Label>Depends on ({data.children.length})</Label><ul className="mt-2 text-sm">{data.children.map((p: any, i: number) => <li key={i}>{p.name}@{p.version} <span className="text-muted">{p.type}</span></li>)}</ul></section>}
          {data.findings.length > 0 && <section><Label>Advisories</Label><ul className="mt-2 space-y-2">{data.findings.map((f: Finding) => <li key={f.fingerprint}><Link className="flex items-center gap-2 rounded-xl bg-surface-low p-3 hover:bg-surface-high" to={`/findings?open=${encodeURIComponent(scanId + "~" + f.fingerprint)}`}><SeverityChip level={f.advisory.severity.level} /><span className="font-semibold">{f.advisory.id}</span><span className="truncate text-sm text-muted">{f.advisory.summary}</span></Link></li>)}</ul></section>}
        </div>
      )}
    </Drawer>
  );
}
