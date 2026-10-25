import { ExternalLink } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { get, send } from "../api/client";
import type { Finding } from "../api/types";
import { useFetch } from "../app/state";
import { Button, Chip, Drawer, ErrorBox, Field, Input, Label, Note, Progress, Select, SeverityChip, Spinner, Textarea, fmtDate } from "./ui";

export function PathList({ paths, names, truncated, warning }: { paths: Finding["paths"]["paths"]; names: Record<string, string>; truncated?: boolean; warning?: string | null }) {
  if (paths.length === 0) return <Note tone="warn">{warning ?? "No dependency path from the application is known."}</Note>;
  return (
    <ol className="space-y-2">
      {paths.map((p, i) => (
        <li key={i} className="flex flex-wrap items-center gap-1.5 rounded-2xl bg-surface-low p-3 text-sm">
          {p.nodes.map((n, j) => (
            <span key={j} className="flex items-center gap-1.5">
              {j > 0 && (
                <span className="text-muted" title={p.edge_types[j - 1]}>
                  →
                </span>
              )}
              <span className={"rounded-lg px-2 py-0.5 font-mono text-xs " + (j === p.nodes.length - 1 ? "bg-warn-soft text-warn" : j === 0 ? "bg-primary text-on-primary" : "bg-surface-high")}>{names[n] ?? n}</span>
            </span>
          ))}
          {p.inferred && <Chip tone="warn">inferred edge</Chip>}
          {p.edge_types.includes("dev") && <Chip tone="info">dev</Chip>}
        </li>
      ))}
      {truncated && <li className="text-xs text-muted">More paths exist; the search limit was reached.</li>}
    </ol>
  );
}

const STATUSES = [
  ["open", "Open"],
  ["needs_review", "Needs review"],
  ["accepted_risk", "Accepted risk"],
  ["false_positive", "False positive"],
  ["not_affected", "Not affected"],
];

export function FindingDrawer({ id, onClose, onChanged }: { id: string | null; onClose: () => void; onChanged?: () => void }) {
  const { data: f, error, loading, reload } = useFetch<Finding>(id ? () => get(`/findings/${id}`) : null, [id]);
  return (
    <Drawer open={Boolean(id)} onClose={onClose} wide title={f ? `${f.advisory.id} · ${f.package}@${f.version}` : "Finding"}>
      {loading && <Spinner />}
      {error && <ErrorBox error={error} onRetry={reload} />}
      {f && <FindingBody f={f} onChanged={() => (reload(), onChanged?.())} />}
    </Drawer>
  );
}

function FindingBody({ f, onChanged }: { f: Finding; onChanged: () => void }) {
  const a = f.advisory;
  const [status, setStatus] = useState(f.triage.status);
  const [rationale, setRationale] = useState("");
  const [expires, setExpires] = useState("");
  const [author, setAuthor] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const needsExpiry = ["accepted_risk", "false_positive", "not_affected"].includes(status);

  async function save() {
    setSaving(true);
    setErr(null);
    try {
      await send("PATCH", `/findings/${f.id}/triage`, { status, rationale, expires: expires || null, author: author || null });
      setRationale("");
      onChanged();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-7">
      <section>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityChip level={a.severity.level} />
          {f.scan?.demo && <Chip tone="warn">demo data</Chip>}
          <Chip tone="neutral">{f.direct ? "direct" : "transitive"}</Chip>
          {f.scopes.map((s) => (
            <Chip key={s} tone={s === "runtime" ? "accent" : "info"}>
              {s}
            </Chip>
          ))}
          {f.triage.expired && <Chip tone="danger">exception expired</Chip>}
        </div>
        <h3 className="mt-3 text-2xl font-semibold">{a.summary ?? "No summary provided"}</h3>
        {a.details && a.details !== a.summary && <p className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-muted">{a.details}</p>}
      </section>

      <section>
        <Label>Evidence</Label>
        <dl className="mt-3 grid grid-cols-[130px_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted">Package</dt>
          <dd className="font-mono text-xs">{f.ecosystem}/{f.package}@{f.version} {f.purl && <span className="text-muted">· {f.purl}</span>}</dd>
          <dt className="text-muted">Aliases</dt>
          <dd className="font-mono text-xs">{[...new Set([...a.aliases, ...a.merged_ids])].join(", ") || "—"}</dd>
          <dt className="text-muted">Severity</dt>
          <dd>
            {a.severity.level}
            {a.severity.score != null && ` (${a.severity.score.toFixed(1)})`} — <span className="text-muted">{a.severity.source ?? "the source did not provide severity"}</span>
            {a.severity.vector && <div className="mt-0.5 break-all font-mono text-xs text-muted">{a.severity.vector}</div>}
          </dd>
          <dt className="text-muted">Match</dt>
          <dd>
            {f.match.basis} <span className="text-muted">— {f.match.rationale}</span>
            {f.match.local_verification !== "not_applicable" && <Chip className="ml-2" tone={f.match.local_verification === "confirmed" ? "accent" : "warn"}>local check: {f.match.local_verification}</Chip>}
          </dd>
          <dt className="text-muted">Source</dt>
          <dd>
            {f.source}
            {f.snapshot_id && ` · snapshot ${f.snapshot_id}`}
            {f.fetched_at && ` · ${fmtDate(f.fetched_at)}`}
          </dd>
          <dt className="text-muted">Published</dt>
          <dd>{fmtDate(a.published)} <span className="text-muted">· modified {fmtDate(a.modified)}</span></dd>
          <dt className="text-muted">Found in</dt>
          <dd className="font-mono text-xs">{f.location ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : "—"} {f.location?.detail && <span className="text-muted">({f.location.detail})</span>}</dd>
        </dl>
      </section>

      <section>
        <Label>How it got into the project</Label>
        <div className="mt-3">
          <PathList paths={f.paths.paths} names={f.names ?? {}} truncated={f.paths.truncated} warning={f.paths.warning} />
          {f.paths.introducers.length > 0 && (
            <p className="mt-3 text-sm text-muted">
              Introduced through: <span className="font-semibold text-ink">{f.paths.introducers.map((i) => f.names?.[i] ?? i).join(", ")}</span>. Removing one parent does not remove the package while another path remains.
            </p>
          )}
        </div>
      </section>

      <section>
        <Label>Possible fix</Label>
        <div className="mt-3 space-y-3 rounded-2xl bg-surface-low p-4 text-sm">
          {a.fixed_versions.length ? (
            <div>
              Fixed in <span className="font-mono font-semibold">{a.fixed_versions.join(", ")}</span> <span className="text-muted">(from the advisory's affected ranges)</span>
            </div>
          ) : (
            <div>The advisory lists no fixed version.</div>
          )}
          {f.fix && <p className="text-muted">{f.fix.note}</p>}
          <Link to="/remediation" className="inline-block font-semibold text-accent hover:underline">
            Simulate this upgrade in Remediation Studio →
          </Link>
        </div>
      </section>

      <section>
        <Label>Priority score</Label>
        <div className="mt-3 rounded-2xl bg-surface-low p-4">
          <div className="flex items-baseline gap-3">
            <span className="font-headline text-4xl font-semibold">{f.priority.score ?? "—"}</span>
            <span className="text-sm text-muted">{f.priority.score == null ? "unscored: severity unknown" : "/ 100"} · confidence {Math.round(f.priority.confidence * 100)}% of weight known</span>
          </div>
          <ul className="mt-4 space-y-3">
            {f.priority.factors.map((x) => (
              <li key={x.name}>
                <div className="flex justify-between text-xs">
                  <span className="font-semibold">{x.name.replace(/_/g, " ")} <span className="font-normal text-muted">(weight {x.weight})</span></span>
                  <span className="text-muted">{x.value == null ? "unknown — excluded" : x.value.toFixed(2)}</span>
                </div>
                <Progress value={(x.value ?? 0) * 100} tone={x.value == null ? "info" : "accent"} label={x.name} />
                <div className="mt-0.5 text-xs text-muted">{x.evidence}</div>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-muted">{f.priority.note}</p>
        </div>
      </section>

      {a.references.length > 0 && (
        <section>
          <Label>References</Label>
          <p className="mt-1 text-xs text-muted">Shown as text; this tool never fetches them.</p>
          <ul className="mt-2 space-y-1 text-sm">
            {a.references.slice(0, 10).map((r, i) => (
              <li key={i} className="flex items-center gap-2">
                <ExternalLink className="h-3.5 w-3.5 shrink-0 text-muted" aria-hidden />
                <span className="text-muted">{r.type ?? "link"}</span>
                {/^https?:\/\//.test(r.url) ? (
                  <a href={r.url} target="_blank" rel="noopener noreferrer nofollow" className="break-all text-accent hover:underline">
                    {r.url}
                  </a>
                ) : (
                  <span className="break-all">{r.url}</span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <Label>Triage</Label>
        <div className="mt-3 space-y-3 rounded-2xl bg-surface-low p-4">
          <div className="text-sm">
            Current status: <span className="font-semibold">{f.triage.status.replace(/_/g, " ")}</span>
            {f.triage.expires && <span className="text-muted"> · until {f.triage.expires}</span>}
            {f.triage.rationale && <div className="mt-1 text-muted">“{f.triage.rationale}”</div>}
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="New status">
              <Select value={status} onChange={(e) => setStatus(e.target.value)}>
                {STATUSES.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label={needsExpiry ? "Expires (required)" : "Expires (optional)"}>
              <Input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
            </Field>
          </div>
          <Field label="Rationale (required)">
            <Textarea rows={3} value={rationale} onChange={(e) => setRationale(e.target.value)} placeholder="Why is this status justified? Link evidence if you have it." />
          </Field>
          <Field label="Author">
            <Input value={author} onChange={(e) => setAuthor(e.target.value)} placeholder="you@example.com" />
          </Field>
          {err && <ErrorBox error={err} />}
          <Button onClick={save} loading={saving} disabled={!rationale.trim() || (needsExpiry && !expires)}>
            Save triage decision
          </Button>
          {f.triage_history && f.triage_history.length > 0 && (
            <div>
              <div className="mb-2 mt-2 text-xs font-semibold text-muted">Audit trail</div>
              <ul className="space-y-1.5 text-xs text-muted">
                {f.triage_history.map((h, i) => (
                  <li key={i}>
                    {fmtDate(h.at)} — {h.from ?? "open"} → <span className="font-semibold text-ink">{h.to}</span>
                    {h.expires && ` (until ${h.expires})`} {h.author && `by ${h.author}`}: {h.rationale}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
