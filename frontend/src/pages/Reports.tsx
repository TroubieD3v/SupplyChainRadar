import { FileCode2, FileJson, FileText, Globe, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { download, get, getToken, send, setToken } from "../api/client";
import { useFetch, useSelection, useTheme } from "../app/state";
import { Button, Card, Chip, DemoBadge, ErrorBox, Field, Input, Label, Note, PageHeader, Select, Spinner, Toggle } from "../components/ui";

const FORMATS = [
  { id: "html", ext: "html", icon: Globe, title: "HTML report", text: "Self-contained, no scripts; safe to email." },
  { id: "markdown", ext: "md", icon: FileText, title: "Markdown", text: "For pull-request comments and wikis." },
  { id: "json", ext: "json", icon: FileJson, title: "JSON", text: "The full versioned scan snapshot (CLI input for compare/policy)." },
  { id: "sarif", ext: "sarif", icon: ShieldCheck, title: "SARIF 2.1.0", text: "For GitHub code scanning upload." },
  { id: "cyclonedx", ext: "cdx.json", icon: FileCode2, title: "CycloneDX 1.7", text: "Normalised inventory and dependency graph." },
];

export default function Reports() {
  const { scan } = useSelection();
  const { theme, toggle } = useTheme();
  const { data: prov, error, reload } = useFetch<any>(() => get("/providers/status"), []);
  const { data: settings, reload: reloadSettings } = useFetch<any>(() => get("/settings"), []);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [token, setTok] = useState(getToken());
  const [saved, setSaved] = useState(false);
  const ready = scan && ["completed", "partial"].includes(scan.state);

  async function dl(f: (typeof FORMATS)[number]) {
    if (!scan) return;
    setBusy(f.id);
    setErr(null);
    try {
      await download(`/scans/${scan.id}/reports`, { format: f.id, include_policy: "true" }, `scradar-${scan.id.slice(0, 8)}.${f.ext}`);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(null);
    }
  }
  async function setDefault(id: string) {
    await send("PUT", "/settings", { default_enrichment: id });
    reloadSettings();
    reload();
  }

  return (
    <>
      <PageHeader eyebrow={scan?.demo ? <DemoBadge /> : undefined} title="Reports & Settings">
        Every export is rendered from the same scan snapshot, so numbers match across formats. Free text from imported files is escaped and secrets are masked.
      </PageHeader>

      <section className="mb-12">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-2">
          <h2 className="text-2xl font-semibold">Download for the selected scan</h2>
          {scan && <span className="text-sm text-muted">{scan.label ?? "scan"} · {scan.state}</span>}
        </div>
        {!ready && <Note tone="warn">Select a finished scan (top bar) to enable downloads.</Note>}
        {err && <div className="mb-4"><ErrorBox error={err} /></div>}
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FORMATS.map((f) => (
            <Card key={f.id} tone="low" className="flex flex-col justify-between !p-5">
              <div><div className="flex h-11 w-11 items-center justify-center rounded-xl bg-surface-high text-accent"><f.icon className="h-5 w-5" aria-hidden /></div><h3 className="mt-4 text-lg font-semibold">{f.title}</h3><p className="mt-1 text-sm text-muted">{f.text}</p></div>
              <Button className="mt-5" variant="soft" disabled={!ready} loading={busy === f.id} onClick={() => dl(f)}>Download .{f.ext}</Button>
            </Card>
          ))}
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <Card>
          <h2 className="text-xl font-semibold">Advisory source</h2>
          <p className="mt-1 text-sm text-muted">Default for new imports. “Offline” is the safe default: nothing leaves this machine.</p>
          {!prov && !error && <Spinner />}
          {error && <ErrorBox error={error} onRetry={reload} />}
          {prov && (
            <div className="mt-4 space-y-2">
              {prov.modes.map((m: any) => (
                <label key={m.id} className="flex cursor-pointer items-start gap-3 rounded-2xl bg-surface-low p-4 hover:bg-surface-high">
                  <input type="radio" name="enrichment" className="mt-1 accent-[rgb(var(--accent))]" checked={prov.default_enrichment === m.id} onChange={() => setDefault(m.id)} />
                  <div><div className="flex items-center gap-2 font-semibold">{m.label}{m.network ? <Chip tone="warn">network</Chip> : <Chip tone="accent">offline</Chip>}</div><div className="text-sm text-muted">{m.description}</div></div>
                </label>
              ))}
            </div>
          )}
        </Card>
        <div className="space-y-6">
          <Card tone="low">
            <h2 className="text-xl font-semibold">Providers & privacy</h2>
            {prov && (
              <dl className="mt-4 grid grid-cols-[130px_1fr] gap-y-2 text-sm">
                <dt className="text-muted">OSV endpoint</dt><dd className="break-all font-mono text-xs">{prov.osv.base_url}</dd>
                <dt className="text-muted">Redirects</dt><dd>never followed</dd>
                <dt className="text-muted">Cached lookups</dt><dd>{prov.osv.cached_package_queries}</dd>
                <dt className="text-muted">Scorecard</dt><dd>{prov.scorecard.note}</dd>
                <dt className="text-muted">API access</dt><dd>{prov.auth === "token" ? "bearer token required for changes" : "loopback only, no token"}</dd>
              </dl>
            )}
            {prov && <p className="mt-4 text-sm leading-relaxed text-muted">{prov.privacy}</p>}
            <p className="mt-2 text-sm text-muted">No telemetry is collected.</p>
          </Card>
          <Card tone="low">
            <h2 className="text-xl font-semibold">Interface</h2>
            <div className="mt-4 flex items-center justify-between"><div><div className="font-semibold">Dark theme</div><div className="text-sm text-muted">Dark is the default; switch any time.</div></div><Toggle checked={theme === "dark"} onChange={toggle} label="Dark theme" /></div>
            <div className="mt-6 space-y-3">
              <Field label="API token (only if the server sets SCRADAR_API_TOKEN)"><Input type="password" autoComplete="off" value={token} onChange={(e) => (setTok(e.target.value), setSaved(false))} placeholder="stored in this browser only" /></Field>
              <Button size="sm" variant="soft" onClick={() => (setToken(token), setSaved(true))}>Save token</Button>
              {saved && <span className="ml-3 text-sm text-accent">Saved locally.</span>}
            </div>
            {settings && <div className="mt-6"><Label>Retention</Label><p className="mt-1 text-sm text-muted">Keeps the latest {settings.retention_scans_per_project} scans per project. Uploads are limited to {Math.round(settings.limits.max_upload_bytes / 1048576)} MB per file and {settings.limits.max_files} files.</p>
              <Select aria-label="Retention" className="mt-2 !w-auto" value={settings.retention_scans_per_project} onChange={async (e) => (await send("PUT", "/settings", { retention_scans_per_project: Number(e.target.value) }), reloadSettings())}>{[10, 25, 50, 100, 500].map((n) => <option key={n} value={n}>{n} scans</option>)}</Select></div>}
          </Card>
        </div>
      </section>
    </>
  );
}
