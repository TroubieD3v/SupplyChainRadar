import { useEffect, useState } from "react";
import { get, send } from "../api/client";
import type { PolicyResult } from "../api/types";
import { useFetch, useSelection } from "../app/state";
import { Button, Card, Chip, CopyBlock, Empty, ErrorBox, Field, Label, Note, PageHeader, Select, Textarea } from "../components/ui";

const GH_ACTION = `name: dependency-security
on:
  pull_request:
  push: { branches: [main] }
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install supplychain-radar
      - name: Scan (OSV lookup sends only ecosystem, name and version)
        run: supplychain-radar scan . -f json -o scan.json --policy policy.yaml --baseline baseline.json
      - run: supplychain-radar scan . -f sarif -o results.sarif --overwrite
        if: always()
  upload-sarif:
    needs: scan
    if: always()
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: results.sarif }`;

export default function Policies() {
  const { project, scans, scan } = useSelection();
  const done = scans.filter((s) => ["completed", "partial"].includes(s.state));
  const { data, reload } = useFetch<{ yaml: string; version: number; is_default: boolean }>(project ? () => get(`/projects/${project.id}/policies`) : null, [project?.id]);
  const [text, setText] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [result, setResult] = useState<PolicyResult | null>(null);
  const [baseline, setBaseline] = useState("");
  const [target, setTarget] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (data) setText(data.yaml);
  }, [data]);
  useEffect(() => setTarget(scan?.id ?? ""), [scan?.id]);

  if (!project) return <Empty title="No project selected">Create a project to attach a policy.</Empty>;

  async function validate() {
    const r = await send("POST", "/policies/validate", { yaml: text });
    setMsg(r.valid ? { ok: true, text: `Valid: “${r.name}”, ${r.rules} rule(s), unknown data → ${r.unknown_data}` } : { ok: false, text: r.error });
  }
  async function save() {
    setBusy(true);
    try {
      await send("PUT", `/projects/${project!.id}/policies`, { yaml: text });
      setMsg({ ok: true, text: "Policy saved." });
      reload();
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally {
      setBusy(false);
    }
  }
  async function evaluate() {
    setBusy(true);
    setErr(null);
    try {
      setResult(await send("POST", `/projects/${project!.id}/policies/evaluate`, { scan_id: target, baseline_scan_id: baseline || null }));
    } catch (e: any) {
      setResult(null);
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }
  const tone = { pass: "accent", warn: "warn", fail: "danger", inconclusive: "warn" } as const;

  return (
    <>
      <PageHeader eyebrow={<Chip tone="accent">Same engine as the CLI</Chip>} title="Policies & CI">
        Policy rules gate pull requests. Unknown severity is never treated as “below threshold”, and rules about <i>new</i> findings need a baseline scan — they fail loudly without one.
      </PageHeader>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <div className="flex items-center justify-between"><h2 className="text-xl font-semibold">Policy YAML</h2>{data && <Chip tone={data.is_default ? "neutral" : "accent"}>{data.is_default ? "built-in default" : `saved v${data.version}`}</Chip>}</div>
          <Textarea aria-label="Policy YAML" spellCheck={false} rows={22} className="mt-4 font-mono !text-[12.5px] leading-relaxed" value={text} onChange={(e) => setText(e.target.value)} />
          {msg && <div className="mt-3"><Note tone={msg.ok ? "accent" : "warn"}>{msg.text}</Note></div>}
          <div className="mt-4 flex gap-2"><Button variant="soft" onClick={validate}>Validate</Button><Button onClick={save} loading={busy}>Save policy</Button></div>
        </Card>

        <div className="space-y-6">
          <Card tone="low">
            <h2 className="text-xl font-semibold">Evaluate</h2>
            {done.length === 0 ? <p className="mt-3 text-sm text-muted">No finished scans to evaluate yet.</p> : (
              <>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <Field label="Scan to evaluate"><Select value={target} onChange={(e) => setTarget(e.target.value)}>{done.map((s) => <option key={s.id} value={s.id}>{s.label ?? "scan"} · {new Date(s.created_at).toLocaleDateString()}</option>)}</Select></Field>
                  <Field label="Baseline scan (for new-finding rules)"><Select value={baseline} onChange={(e) => setBaseline(e.target.value)}><option value="">None</option>{done.filter((s) => s.id !== target).map((s) => <option key={s.id} value={s.id}>{s.label ?? "scan"} · {new Date(s.created_at).toLocaleDateString()}</option>)}</Select></Field>
                </div>
                <Button className="mt-4" onClick={evaluate} loading={busy} disabled={!target}>Evaluate policy</Button>
              </>
            )}
            {err && <div className="mt-4"><ErrorBox error={err} /></div>}
            {result && (
              <div className="mt-5 space-y-3">
                <div className="flex items-center gap-3"><Chip tone={tone[result.outcome]}>{result.outcome}</Chip><span className="text-sm text-muted">CLI exit code <span className="font-mono font-semibold text-ink">{result.exit_code}</span> · baseline {result.baseline_used ? "used" : "not used"}</span></div>
                {[...result.violations, ...result.warnings].map((v, i) => <div key={i} className="rounded-xl bg-surface p-3 text-sm"><Chip tone={v.action === "fail" ? "danger" : "warn"}>{v.action}</Chip> <span className="font-semibold">{v.rule_id}</span> — {v.message}</div>)}
                {result.suppressed.map((s, i) => <div key={i} className="rounded-xl bg-surface p-3 text-sm text-muted">Suppressed {s.advisory_id} on {s.package}: {s.status.replace("_", " ")} until {s.expires} — “{s.rationale}”</div>)}
                {result.expired_exceptions.map((s, i) => <div key={i} className="rounded-xl bg-danger-soft p-3 text-sm text-danger">Exception for {s.advisory_id} on {s.package} expired {s.expires}</div>)}
                <div className="text-xs text-muted">Unknown data: {Object.entries(result.unknown_data).filter(([, v]) => v).map(([k, v]) => `${k.replace(/_/g, " ")} ${v}`).join(", ") || "none"}</div>
                {result.notes.map((n, i) => <p key={i} className="text-xs text-muted">• {n}</p>)}
              </div>
            )}
          </Card>
          <Card tone="low">
            <Label>Exit codes</Label>
            <ul className="mt-3 space-y-1.5 text-sm"><li><b className="font-mono">0</b> scan completed, policy passed (warnings allowed)</li><li><b className="font-mono">1</b> policy gate failed</li><li><b className="font-mono">2</b> malformed input, bad policy or usage error</li><li><b className="font-mono">3</b> scanner / provider error</li><li><b className="font-mono">4</b> inconclusive (incomplete data with <code>unknown_data.mode: fail</code>)</li></ul>
          </Card>
        </div>
      </div>

      <section className="mt-10 grid gap-6 lg:grid-cols-2">
        <div><h2 className="mb-3 text-xl font-semibold">CLI</h2>
          <CopyBlock label="CLI commands" text={`# reproducible offline scan against a frozen snapshot\nsupplychain-radar scan . --offline --advisory-fixture fixtures/osv/frozen-advisories.json -f json -o scan.json\n\n# gate: fail on NEW critical advisories relative to a baseline\nsupplychain-radar policy check scan.json --policy policy.yaml --baseline baseline.json\necho "exit code: $?"\n\n# compare two scans, export SARIF\nsupplychain-radar compare baseline.json scan.json -f html -o diff.html\nsupplychain-radar report scan.json -f sarif -o results.sarif`} /></div>
        <div><h2 className="mb-3 text-xl font-semibold">GitHub Actions</h2><CopyBlock label="GitHub Actions workflow" text={GH_ACTION} /></div>
      </section>
    </>
  );
}
