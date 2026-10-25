import { FileUp, Plus, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { get, saveBlob, send, upload } from "../api/client";
import type { FindingRef, Scenario } from "../api/types";
import { useFetch } from "../app/state";
import { RequireScan } from "../components/RequireScan";
import { Button, Card, Chip, ErrorBox, Field, Input, Label, Modal, Note, PageHeader, Segmented, Select, SeverityChip, Spinner, fmtDate } from "../components/ui";

const STATUS: Record<Scenario["status"], { tone: "accent" | "warn" | "neutral" | "danger"; label: string; help: string }> = {
  confirmed_by_candidate_scan: { tone: "accent", label: "Confirmed by candidate scan", help: "A concrete candidate inventory was scanned with the same advisory data." },
  predicted_partial: { tone: "warn", label: "Predicted (partial)", help: "No resolver was run. Only the changed package was re-evaluated; transitive dependencies are assumed unchanged." },
  unknown: { tone: "neutral", label: "Unknown", help: "The candidate could not be evaluated against advisory data, so nothing can be claimed." },
  blocked: { tone: "danger", label: "Blocked", help: "The requested change cannot be simulated." },
};

export default function Remediation() {
  return <RequireScan>{(scan) => <Body scanId={scan.id} projectId={scan.project_id} />}</RequireScan>;
}

function Body({ scanId, projectId }: { scanId: string; projectId: string }) {
  const [tab, setTab] = useState<"candidate" | "whatif" | "plans">("whatif");
  const { data: fixes } = useFetch<any[]>(() => get(`/scans/${scanId}/fixes`), [scanId]);
  const { data: comps } = useFetch<{ items: any[] }>(() => get(`/scans/${scanId}/components`, { page_size: 500, sort: "name" }), [scanId]);
  const { data: plans, reload: reloadPlans } = useFetch<Scenario[]>(() => get(`/projects/${projectId}/scenarios`), [projectId]);
  const [result, setResult] = useState<Scenario | null>(null);
  const [ops, setOps] = useState<{ op: "set_version" | "remove"; component: string; version: string }[]>([{ op: "set_version", component: "", version: "" }]);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => setResult(null), [scanId]);

  const packages = (comps?.items ?? []).filter((c) => c.source !== "workspace");
  const directs = packages.filter((c) => c.direct);

  async function runWhatIf() {
    setBusy(true);
    setErr(null);
    try {
      const body = { base_scan_id: scanId, name: name || "what-if change", operations: ops.filter((o) => o.component).map((o) => ({ op: o.op, component: o.component, version: o.op === "set_version" ? o.version : null })) };
      const r = await send<Scenario>("POST", "/remediation/scenarios", body);
      setResult(r);
      reloadPlans();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function runCandidate() {
    setBusy(true);
    setErr(null);
    try {
      const fd = new FormData();
      fd.append("base_scan_id", scanId);
      fd.append("name", name || "candidate lockfile");
      files.forEach((f) => fd.append("files", f, f.name));
      const r = await upload<Scenario>("/remediation/scenarios/candidate", fd);
      setResult(r);
      setFiles([]);
      reloadPlans();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader eyebrow={<Chip tone="accent">Never edits your lockfiles</Chip>} title="Remediation Studio" actions={<Segmented label="Mode" value={tab} onChange={setTab} options={[{ id: "whatif", label: "What-if" }, { id: "candidate", label: "Candidate lockfile" }, { id: "plans", label: `Plans${plans?.length ? ` (${plans.length})` : ""}` }]} />}>
        Compare the current inventory with a change before you make it. A candidate lockfile is authoritative; a what-if without a resolver is only a prediction and is labelled that way.
      </PageHeader>

      {fixes && fixes.length > 0 && tab === "whatif" && (
        <section className="mb-8">
          <h2 className="mb-3 text-xl font-semibold">Fix versions named by advisories</h2>
          <div className="grid gap-3 md:grid-cols-2">
            {fixes.map((f) => (
              <Card key={f.fingerprint} tone="low" className="!p-4">
                <div className="flex items-center justify-between gap-2"><div className="font-semibold">{f.package} <span className="font-mono text-sm text-muted">{f.current_version}</span></div><Chip>{f.direct ? "direct" : "transitive"}</Chip></div>
                <div className="mt-1 text-xs text-muted">{f.advisory_id} · fixed in {f.candidate_versions.join(", ") || "no listed version"} <span className="opacity-70">(from advisory)</span></div>
                {!f.direct && <div className="mt-1 text-xs text-muted">Enters through {f.introducer_labels.join(", ") || "unknown parents"}</div>}
                {f.candidate_versions[0] && <Button size="sm" variant="soft" className="mt-3" onClick={() => setOps([{ op: "set_version", component: f.package, version: f.candidate_versions[0] }])}>Try {f.candidate_versions[0]}</Button>}
              </Card>
            ))}
          </div>
        </section>
      )}

      {tab === "whatif" && (
        <Card className="mb-8">
          <h2 className="text-xl font-semibold">Hypothetical change</h2>
          <p className="mt-1 text-sm text-muted">No dependency resolver runs. Parents whose constraints the new version breaks are listed instead of guessed.</p>
          <div className="mt-5 space-y-3">
            {ops.map((o, i) => (
              <div key={i} className="grid gap-3 sm:grid-cols-[200px_1fr_160px_auto]">
                <Select aria-label="Operation" value={o.op} onChange={(e) => setOps(ops.map((x, j) => (j === i ? { ...x, op: e.target.value as any } : x)))}><option value="set_version">Change version</option><option value="remove">Remove direct dependency</option></Select>
                <Select aria-label="Package" value={o.component} onChange={(e) => setOps(ops.map((x, j) => (j === i ? { ...x, component: e.target.value } : x)))}>
                  <option value="">Choose a package…</option>
                  {(o.op === "remove" ? directs : packages).map((c) => <option key={c.id} value={c.id}>{c.name}@{c.version ?? "?"}{c.advisories ? ` · ${c.advisories} advisory` : ""}</option>)}
                </Select>
                {o.op === "set_version" ? <Input aria-label="Target version" placeholder="target version" value={o.version} onChange={(e) => setOps(ops.map((x, j) => (j === i ? { ...x, version: e.target.value } : x)))} /> : <span />}
                <Button variant="ghost" size="sm" aria-label="Remove row" disabled={ops.length === 1} onClick={() => setOps(ops.filter((_, j) => j !== i))}><Trash2 className="h-4 w-4" /></Button>
              </div>
            ))}
            <Button variant="ghost" size="sm" onClick={() => setOps([...ops, { op: "set_version", component: "", version: "" }])}><Plus className="h-4 w-4" /> Add change</Button>
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
            <Field label="Plan name (optional)"><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. bump vulnerable-lib to 1.2.5" /></Field>
            <Button onClick={runWhatIf} loading={busy} disabled={!ops.some((o) => o.component && (o.op === "remove" || o.version))}>Simulate</Button>
          </div>
        </Card>
      )}

      {tab === "candidate" && (
        <Card className="mb-8">
          <h2 className="text-xl font-semibold">Scan a candidate lockfile</h2>
          <p className="mt-1 text-sm text-muted">Generate the updated lockfile with your package manager on a branch, then upload it here. It is parsed statically and matched with the same advisory source as the base scan.</p>
          <div className="mt-5 flex flex-wrap items-center gap-3">
            <Button variant="outline" onClick={() => input.current?.click()}><FileUp className="h-4 w-4" /> Choose lockfile / SBOM</Button>
            <input ref={input} type="file" multiple hidden aria-label="Choose candidate files" onChange={(e) => e.target.files && setFiles(Array.from(e.target.files))} />
            <span className="text-sm text-muted">{files.map((f) => f.name).join(", ") || "no file selected"}</span>
          </div>
          <div className="mt-5 grid gap-3 sm:grid-cols-[1fr_auto] sm:items-end">
            <Field label="Plan name (optional)"><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. branch upgrade/framework-a" /></Field>
            <Button onClick={runCandidate} loading={busy} disabled={files.length === 0}>Rescan candidate</Button>
          </div>
        </Card>
      )}

      {err && <div className="mb-6"><ErrorBox error={err} /></div>}
      {result && tab !== "plans" && <ScenarioCard s={result} />}
      {tab === "plans" && <Plans plans={plans} />}
    </>
  );
}

function RefList({ title, items, tone }: { title: string; items: FindingRef[]; tone: "accent" | "warn" | "danger" | "neutral" }) {
  return (
    <div>
      <div className="mb-2 flex items-center gap-2"><Label>{title}</Label><Chip tone={tone}>{items.length}</Chip></div>
      {items.length === 0 ? <p className="text-sm text-muted">None</p> : (
        <ul className="space-y-1.5">{items.map((r, i) => <li key={i} className="flex flex-wrap items-center gap-2 rounded-xl bg-surface-low px-3 py-2 text-sm"><SeverityChip level={r.severity} /><span className="font-semibold">{r.package}</span><span className="font-mono text-xs text-muted">{r.version}</span><span className="text-xs text-muted">{r.advisory_id}{r.cause ? ` · ${r.cause.replace(/_/g, " ")}` : ""}</span></li>)}</ul>
      )}
    </div>
  );
}

function ScenarioCard({ s }: { s: Scenario }) {
  const st = STATUS[s.status];
  const [confirm, setConfirm] = useState(false);
  return (
    <Card className="mb-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2"><Chip tone={st.tone}>{st.label}</Chip><Chip tone={s.full_reresolution ? "accent" : "warn"}>full re-resolution: {s.full_reresolution ? "yes" : "no"}</Chip></div>
          <h2 className="mt-3 text-2xl font-semibold">{s.name}</h2>
          <p className="mt-1 max-w-2xl text-sm text-muted">{s.explanation}</p>
        </div>
        <Button variant="soft" size="sm" onClick={() => setConfirm(true)}>Export plan</Button>
      </div>
      <Note tone={s.status === "confirmed_by_candidate_scan" ? "accent" : "warn"} title={st.label}>{st.help}</Note>
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <RefList title="Advisories removed" items={s.advisories_removed} tone="accent" />
        <RefList title="Newly introduced" items={s.newly_introduced} tone="danger" />
        <RefList title="Remaining" items={s.advisories_remaining} tone="warn" />
        <RefList title="Unknown outcome" items={s.unknown} tone="neutral" />
      </div>
      {s.unresolved_constraints.length > 0 && <div className="mt-6"><Label>Unresolved constraints</Label><ul className="mt-2 space-y-1 text-sm text-warn">{s.unresolved_constraints.map((c, i) => <li key={i}>• {c}</li>)}</ul></div>}
      {s.dependencies_changed.length > 0 && (
        <div className="mt-6"><Label>Dependencies changed ({s.dependencies_changed.length})</Label>
          <ul className="mt-2 grid gap-1 text-sm sm:grid-cols-2">{s.dependencies_changed.map((d, i) => <li key={i} className="font-mono text-xs"><Chip className="mr-2">{d.change}</Chip>{d.name} {d.before ?? "∅"} → {d.after ?? "∅"}</li>)}</ul></div>
      )}
      {s.evidence.length > 0 && (
        <div className="mt-6 overflow-x-auto"><Label>Evidence</Label>
          <table className="mt-2 w-full min-w-[640px] text-left text-xs"><thead className="text-muted"><tr>{["Package", "From → to", "Source of version", "Advisories before → after", "Parents", "Evaluated"].map((h) => <th key={h} className="py-1.5 pr-3 font-semibold">{h}</th>)}</tr></thead>
            <tbody>{s.evidence.map((e, i) => <tr key={i} className="border-t border-outline/30"><td className="py-2 pr-3 font-semibold">{e.component}</td><td className="pr-3 font-mono">{e.current_version ?? "∅"} → {e.candidate_version ?? "∅"}</td><td className="pr-3">{e.obtained_from.replace(/_/g, " ")}</td><td className="pr-3">{e.advisories_before.join(", ") || "none"} → {e.advisories_after.join(", ") || "none"}</td><td className="pr-3">{e.parents_impacted.length}</td><td>{e.candidate_evaluated ? "yes" : <span className="text-warn">no</span>}</td></tr>)}</tbody></table></div>
      )}
      <div className="mt-6"><Label>Assumptions</Label><ul className="mt-2 list-inside list-disc space-y-1 text-sm text-muted">{s.assumptions.map((a, i) => <li key={i}>{a}</li>)}</ul></div>
      <Modal open={confirm} onClose={() => setConfirm(false)} title="Export this plan?" actions={<><Button variant="outline" onClick={() => setConfirm(false)}>Cancel</Button><Button onClick={() => (saveBlob(new Blob([JSON.stringify(s, null, 2)], { type: "application/json" }), `remediation-${s.id.slice(0, 8)}.json`), setConfirm(false))}>Download JSON</Button></>}>
        This downloads the analysis as a JSON file. {s.full_reresolution ? "" : "It is a prediction — confirm it with a real candidate lockfile. "}Your lockfiles are never modified by this tool.
      </Modal>
    </Card>
  );
}

function Plans({ plans }: { plans: Scenario[] | null }) {
  const [picked, setPicked] = useState<string[]>([]);
  const [rows, setRows] = useState<any[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (!plans) return <Spinner />;
  if (plans.length === 0) return <p className="text-muted">No saved plans yet. Every simulation you run is saved here for comparison.</p>;
  async function compare() {
    try {
      setRows(await send("POST", "/remediation/compare", { scenario_ids: picked }));
      setErr(null);
    } catch (e: any) {
      setErr(e.message);
    }
  }
  return (
    <>
      <div className="space-y-2">
        {plans.map((p) => (
          <label key={p.id} className="flex cursor-pointer items-center gap-3 rounded-2xl bg-surface-low p-4 hover:bg-surface-high">
            <input type="checkbox" className="accent-[rgb(var(--accent))]" checked={picked.includes(p.id)} onChange={(e) => setPicked(e.target.checked ? [...picked, p.id].slice(0, 10) : picked.filter((x) => x !== p.id))} />
            <div className="min-w-0 flex-1"><div className="font-semibold">{p.name}</div><div className="text-xs text-muted">{fmtDate(p.created_at)} · {p.mode.replace("_", " ")}</div></div>
            <Chip tone={STATUS[p.status].tone}>{STATUS[p.status].label}</Chip>
          </label>
        ))}
      </div>
      <Button className="mt-4" disabled={picked.length < 1} onClick={compare}>Compare {picked.length || ""} plan{picked.length === 1 ? "" : "s"}</Button>
      {err && <div className="mt-4"><ErrorBox error={err} /></div>}
      {rows && (
        <div className="mt-6 overflow-x-auto rounded-3xl border border-outline/40">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="bg-surface-low"><tr>{["Plan", "Removed", "Remaining", "New", "Unknown", "Changed pkgs", "Constraint conflicts", "Trade-off"].map((h) => <th key={h} className="px-4 py-3"><Label>{h}</Label></th>)}</tr></thead>
            <tbody>{rows.map((r) => <tr key={r.scenario_id} className="border-t border-outline/30"><td className="px-4 py-3"><div className="font-semibold">{r.name}</div><Chip tone={r.full_reresolution ? "accent" : "warn"}>{r.full_reresolution ? "confirmed" : "prediction"}</Chip></td><td className="px-4 py-3 font-semibold text-accent">{r.advisories_removed}</td><td className="px-4 py-3">{r.advisories_remaining}</td><td className="px-4 py-3 text-danger">{r.newly_introduced}</td><td className="px-4 py-3">{r.unknown}</td><td className="px-4 py-3">{r.dependencies_changed}</td><td className="px-4 py-3">{r.unresolved_constraints}</td><td className="px-4 py-3 text-xs text-muted">{r.tradeoff}</td></tr>)}</tbody>
          </table>
        </div>
      )}
    </>
  );
}
