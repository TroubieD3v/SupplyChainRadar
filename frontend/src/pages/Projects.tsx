import { FileUp, FlaskConical, Lock, Plus, Trash2, Wifi } from "lucide-react";
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { get, send, upload } from "../api/client";
import { useFetch, useSelection } from "../app/state";
import { Button, Card, Chip, DemoBadge, ErrorBox, Field, Input, Label, Modal, Note, PageHeader, Select, Spinner, StateChip, fmtDate } from "../components/ui";

const FORMATS: [RegExp, string][] = [
  [/^(package-lock|npm-shrinkwrap)\.json$/i, "npm lockfile"],
  [/^pnpm-lock\.yaml$/i, "pnpm lockfile"],
  [/^poetry\.lock$/i, "Poetry lockfile"],
  [/^pyproject\.toml$/i, "pyproject.toml (direct dependencies for Poetry)"],
  [/requirements.*\.txt$/i, "requirements.txt (partial coverage)"],
  [/\.(cdx|sbom)\.json$|^bom\.json$|^sbom\.json$/i, "CycloneDX SBOM"],
  [/\.spdx\.json$/i, "SPDX SBOM"],
  [/\.zip$/i, "ZIP archive (read in memory, never extracted)"],
  [/\.json$/i, "JSON (CycloneDX/SPDX detected by content)"],
];
const detect = (n: string) => FORMATS.find(([re]) => re.test(n))?.[1] ?? null;
const kb = (n: number) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

export default function Projects() {
  const sel = useSelection();
  const nav = useNavigate();
  const { data: prov } = useFetch<any>(() => get("/providers/status"), []);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [mode, setMode] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const [del, setDel] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const effectiveMode = mode || prov?.default_enrichment || "osv_cache";
  const modeInfo = prov?.modes?.find((m: any) => m.id === effectiveMode);

  async function createProject() {
    if (!name.trim()) return;
    setCreating(true);
    setErr(null);
    try {
      const p = await send("POST", "/projects", { name: name.trim() });
      setName("");
      sel.reload();
      sel.setProjectId(p.id);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setCreating(false);
    }
  }

  async function doImport() {
    if (!sel.project || files.length === 0) return;
    setBusy(true);
    setErr(null);
    try {
      const fd = new FormData();
      files.forEach((f) => fd.append("files", f, (f as any).webkitRelativePath || f.name));
      fd.append("enrichment", effectiveMode);
      if (label) fd.append("label", label);
      const meta = await upload(`/projects/${sel.project.id}/imports`, fd);
      setFiles([]);
      setLabel("");
      sel.reload();
      sel.setScanId(meta.id);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function demo() {
    setBusy(true);
    try {
      await send("POST", "/demo");
      sel.reload();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function removeProject() {
    if (!sel.project) return;
    await send("DELETE", `/projects/${sel.project.id}`);
    setDel(false);
    sel.reload();
  }

  const addFiles = (list: FileList | File[]) => setFiles((cur) => [...cur, ...Array.from(list)].slice(0, 32));

  return (
    <>
      <PageHeader eyebrow={<Chip tone="accent">Static parsing only</Chip>} title="Projects & Imports" actions={<Button variant="soft" onClick={demo} loading={busy}><FlaskConical className="h-4 w-4" /> Load demo data</Button>}>
        Files are parsed in memory and never executed — no <code className="font-mono text-sm">npm install</code>, no install scripts. Only the normalised inventory and results are stored.
      </PageHeader>
      {err && <div className="mb-6"><ErrorBox error={err} /></div>}

      <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
        <Card tone="low">
          <h2 className="text-xl font-semibold">New project</h2>
          <div className="mt-4 flex gap-2">
            <Input aria-label="Project name" placeholder="e.g. storefront-web" value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && createProject()} maxLength={200} />
            <Button onClick={createProject} loading={creating} disabled={!name.trim()}><Plus className="h-4 w-4" /> Create</Button>
          </div>
          <h3 className="mb-3 mt-8 text-sm font-semibold text-muted">Your projects</h3>
          {sel.projects.length === 0 ? <p className="text-sm text-muted">No projects yet.</p> : (
            <ul className="space-y-2">
              {sel.projects.map((p) => (
                <li key={p.id}>
                  <button onClick={() => sel.setProjectId(p.id)} aria-pressed={p.id === sel.project?.id} className={"flex w-full items-center justify-between gap-3 rounded-2xl px-4 py-3 text-left transition " + (p.id === sel.project?.id ? "bg-surface-high ring-1 ring-accent/60" : "bg-surface hover:bg-surface-high")}>
                    <div className="min-w-0"><div className="truncate font-semibold">{p.name}</div><div className="text-xs text-muted">{p.scan_count} scan{p.scan_count === 1 ? "" : "s"}</div></div>
                    {p.demo && <DemoBadge />}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold">Import into {sel.project ? `“${sel.project.name}”` : "a project"}</h2>
              <p className="mt-1 text-sm text-muted">Select lockfiles, SBOMs, a pyproject.toml next to poetry.lock, or a .zip.</p>
            </div>
            {sel.project && <Button variant="ghost" size="sm" onClick={() => setDel(true)} aria-label="Delete project"><Trash2 className="h-4 w-4" /></Button>}
          </div>
          <div
            onDragOver={(e) => (e.preventDefault(), setDrag(true))}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => (e.preventDefault(), setDrag(false), addFiles(e.dataTransfer.files))}
            className={"mt-5 flex flex-col items-center rounded-3xl border-2 border-dashed px-6 py-10 text-center transition " + (drag ? "border-accent bg-accent-soft/40" : "border-outline")}
          >
            <FileUp className="h-8 w-8 text-muted" aria-hidden />
            <p className="mt-3 font-semibold">Drop files here</p>
            <Button className="mt-4" variant="outline" onClick={() => input.current?.click()} disabled={!sel.project}>Choose files</Button>
            <input ref={input} type="file" multiple hidden aria-label="Choose dependency files" onChange={(e) => e.target.files && addFiles(e.target.files)} />
          </div>
          {files.length > 0 && (
            <ul className="mt-4 divide-y divide-outline/30 rounded-2xl bg-surface-low">
              {files.map((f, i) => {
                const kind = detect(f.name);
                return (
                  <li key={i} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm">
                    <div className="min-w-0"><div className="truncate font-mono text-xs">{f.name}</div><div className="text-xs text-muted">{kb(f.size)}</div></div>
                    <div className="flex items-center gap-2">{kind ? <Chip tone="accent">{kind}</Chip> : <Chip tone="warn">unrecognised</Chip>}<button className="text-muted hover:text-danger" aria-label={`Remove ${f.name}`} onClick={() => setFiles(files.filter((_, j) => j !== i))}>×</button></div>
                  </li>
                );
              })}
            </ul>
          )}
          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            <Field label="Advisory source">
              <Select value={effectiveMode} onChange={(e) => setMode(e.target.value)}>
                {(prov?.modes ?? []).map((m: any) => <option key={m.id} value={m.id}>{m.label}</option>)}
              </Select>
            </Field>
            <Field label="Scan label (optional)"><Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. release 2.4.0" maxLength={200} /></Field>
          </div>
          {modeInfo && (
            <div className="mt-4"><Note tone={modeInfo.network ? "warn" : "accent"} title={modeInfo.network ? "Privacy disclosure — network lookup" : "No network traffic"}>
              <div className="flex gap-2">{modeInfo.network ? <Wifi className="mt-0.5 h-4 w-4 shrink-0" /> : <Lock className="mt-0.5 h-4 w-4 shrink-0" />}<span>{modeInfo.description}{modeInfo.network ? " Package names of private packages would be revealed to api.osv.dev." : ""}</span></div>
            </Note></div>
          )}
          <Button className="mt-5" onClick={doImport} loading={busy} disabled={!sel.project || files.length === 0}>Import and scan</Button>
        </Card>
      </div>

      <section className="mt-12">
        <h2 className="mb-4 text-2xl font-semibold">Import history</h2>
        {sel.loading ? <Spinner /> : sel.scans.length === 0 ? <p className="text-muted">No imports for this project yet.</p> : (
          <div className="overflow-x-auto rounded-3xl border border-outline/40">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-low"><tr>{["Scan", "State", "Inputs", "Source", "Findings", "Coverage", ""].map((h) => <th key={h} className="px-4 py-3"><Label>{h}</Label></th>)}</tr></thead>
              <tbody>
                {sel.scans.map((s) => (
                  <tr key={s.id} className="border-t border-outline/30 hover:bg-surface-low">
                    <td className="px-4 py-3"><div className="font-semibold">{s.label ?? "scan"}</div><div className="text-xs text-muted">{fmtDate(s.created_at)}</div></td>
                    <td className="px-4 py-3"><StateChip state={s.state} />{s.error && <div className="mt-1 max-w-[260px] truncate text-xs text-danger" title={s.error}>{s.error}</div>}</td>
                    <td className="px-4 py-3 text-xs">{s.inputs.map((i) => i.name).join(", ")}</td>
                    <td className="px-4 py-3 text-xs">{s.summary?.advisory_source.mode.replace("_", " ") ?? s.enrichment}</td>
                    <td className="px-4 py-3 font-semibold">{s.summary?.findings ?? "—"}</td>
                    <td className="px-4 py-3">{s.summary ? `${s.summary.coverage.percent_evaluated}%` : "—"}</td>
                    <td className="px-4 py-3 text-right">
                      {["queued", "parsing", "enriching", "analyzing"].includes(s.state) ? <Button size="sm" variant="outline" onClick={async () => (await send("POST", `/scans/${s.id}/cancel`), sel.reload())}>Cancel</Button> : <Button size="sm" variant="soft" onClick={() => (sel.setScanId(s.id), nav("/scan"))}>Details</Button>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <Modal open={del} onClose={() => setDel(false)} title="Delete this project?" actions={<><Button variant="outline" onClick={() => setDel(false)}>Keep it</Button><Button variant="danger" onClick={removeProject}>Delete project</Button></>}>
        All scan snapshots, triage decisions, policies and scenarios of “{sel.project?.name}” are removed from this machine. This cannot be undone.
      </Modal>
    </>
  );
}
