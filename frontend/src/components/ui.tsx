import clsx from "clsx";
import { AlertTriangle, Check, Copy, Loader2, X } from "lucide-react";
import { useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import type { Severity } from "../api/types";

export const cx = clsx;

// ---- layout atoms -----------------------------------------------------------------------------
export function Card({ children, className, tone = "default", as: Tag = "div", ...rest }: { children: ReactNode; className?: string; tone?: "default" | "low" | "high" | "inverse" | "accent"; as?: any } & Record<string, any>) {
  const tones = {
    default: "bg-surface border border-outline",
    low: "bg-surface border border-outline",
    high: "bg-surface-low border border-outline",
    inverse: "bg-surface-low border border-outline",
    accent: "bg-accent-soft border border-accent/40",
  };
  return (
    <Tag className={cx("rounded-[3px] p-3", tones[tone], className)} {...rest}>
      {children}
    </Tag>
  );
}

/** Panel title bar used inside a Card with `!p-0`. */
export function PanelHead({ title, children }: { title: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex min-h-9 items-center justify-between gap-3 border-b border-outline px-3 py-1.5">
      <h2 className="text-[12.5px] font-semibold">{title}</h2>
      {children && <div className="flex items-center gap-2 text-xs text-muted">{children}</div>}
    </div>
  );
}

export function PageHeader({ eyebrow, title, children, actions }: { eyebrow?: ReactNode; title: string; children?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-4 flex flex-col gap-3 border-b border-outline pb-3 md:flex-row md:items-start md:justify-between">
      <div className="min-w-0 max-w-3xl">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-[17px] font-semibold leading-7">{title}</h1>
          {eyebrow}
        </div>
        {children && <p className="text-[12.5px] leading-snug text-muted">{children}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-1.5">{actions}</div>}
    </header>
  );
}

export function Label({ children }: { children: ReactNode }) {
  return <div className="text-xs font-medium text-muted">{children}</div>;
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "accent" | "warn" | "danger" }) {
  return (
    <div className="min-w-0 border border-outline bg-surface px-3 py-2">
      <Label>{label}</Label>
      <div className={cx("font-mono text-[17px] font-medium leading-6", tone === "accent" && "text-ok", tone === "warn" && "text-warn", tone === "danger" && "text-danger")}>{value}</div>
      {sub && <div className="truncate text-[11px] text-dim">{sub}</div>}
    </div>
  );
}

// ---- chips ------------------------------------------------------------------------------------
export function Chip({ children, tone = "neutral", className, title }: { children: ReactNode; tone?: "neutral" | "accent" | "ok" | "warn" | "danger" | "info" | "solid"; className?: string; title?: string }) {
  const tones = {
    neutral: "border-outline bg-surface-high/60 text-muted",
    accent: "border-accent/40 bg-accent-soft text-accent",
    ok: "border-ok/40 bg-ok-soft text-ok",
    warn: "border-warn/40 bg-warn-soft text-warn",
    danger: "border-danger/40 bg-danger-soft text-danger",
    info: "border-outline bg-info-soft text-info",
    solid: "border-primary bg-primary text-on-primary",
  };
  return (
    <span title={title} className={cx("inline-flex h-[18px] items-center gap-1 whitespace-nowrap rounded-[3px] border px-1.5 text-[11px] font-medium leading-none", tones[tone], className)}>
      {children}
    </span>
  );
}

const SEV_BG: Record<Severity, string> = { critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low", unknown: "bg-sev-unknown" };
const SEV_TEXT: Record<Severity, string> = { critical: "text-sev-critical", high: "text-sev-high", medium: "text-sev-medium", low: "text-sev-low", unknown: "text-muted" };
export function SeverityChip({ level }: { level: Severity | string | null | undefined }) {
  const l = (level ?? "unknown") as Severity;
  return (
    <span
      title={l === "unknown" ? "The advisory source gave no severity" : undefined}
      className={cx("inline-flex items-center gap-1.5 whitespace-nowrap text-xs capitalize", SEV_TEXT[l] ?? "text-muted")}
    >
      <span className={cx("size-2 shrink-0 rounded-[1px]", SEV_BG[l] ?? "bg-sev-unknown", l === "unknown" && "border border-dashed border-muted bg-transparent")} aria-hidden />
      {l}
    </span>
  );
}

export const SEV_COLOR: Record<Severity, string> = {
  critical: "rgb(var(--sev-critical))",
  high: "rgb(var(--sev-high))",
  medium: "rgb(var(--sev-medium))",
  low: "rgb(var(--sev-low))",
  unknown: "rgb(var(--sev-unknown))",
};
export const SEV_CLASS = SEV_BG;

export function StateChip({ state }: { state: string }) {
  const map: Record<string, ["ok" | "warn" | "danger" | "info" | "neutral", string]> = {
    completed: ["ok", "completed"],
    partial: ["warn", "partial"],
    failed: ["danger", "failed"],
    cancelled: ["neutral", "cancelled"],
    queued: ["info", "queued"],
    parsing: ["info", "parsing"],
    enriching: ["info", "enriching"],
    analyzing: ["info", "analyzing"],
    evaluated: ["ok", "evaluated"],
    cached: ["ok", "cached"],
    not_evaluated: ["warn", "not evaluated"],
    unsupported: ["neutral", "unsupported"],
    error: ["danger", "error"],
    first_party: ["neutral", "first-party"],
  };
  const [tone, label] = map[state] ?? ["neutral", state];
  const busy = ["queued", "parsing", "enriching", "analyzing"].includes(state);
  return (
    <Chip tone={tone}>
      {busy && <Loader2 className="h-3 w-3 animate-spin" aria-hidden />}
      {label}
    </Chip>
  );
}

export function DemoBadge({ className }: { className?: string }) {
  return (
    <span title="Built from synthetic fixtures; not a real project" className={cx("inline-flex h-[18px] items-center whitespace-nowrap rounded-[3px] border border-warn/50 bg-warn-soft px-1.5 text-[11px] font-medium text-warn", className)}>
      Demo data
    </span>
  );
}

// ---- controls -----------------------------------------------------------------------------------
type BtnVariant = "primary" | "accent" | "soft" | "outline" | "danger" | "ghost";
export function Button({ variant = "primary", size = "md", className, children, loading, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; size?: "sm" | "md"; loading?: boolean }) {
  const v: Record<BtnVariant, string> = {
    primary: "border-primary bg-primary text-on-primary hover:brightness-110",
    accent: "border-primary bg-primary text-on-primary hover:brightness-110",
    soft: "border-outline bg-surface-high text-ink hover:bg-surface-top",
    outline: "border-outline bg-transparent text-ink hover:bg-surface-high",
    danger: "border-danger/50 bg-danger-soft text-danger hover:bg-danger/20",
    ghost: "border-transparent text-muted hover:bg-surface-high hover:text-ink",
  };
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-[3px] border font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        size === "md" ? "h-7 px-3 text-[12.5px]" : "h-6 px-2 text-xs",
        v[variant],
        className,
      )}
    >
      {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Toggle({ checked, onChange, label, tone = "accent" }: { checked: boolean; onChange: (v: boolean) => void; label: string; tone?: "accent" | "info" }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={cx("relative h-4 w-7 shrink-0 rounded-full border transition-colors", checked ? (tone === "accent" ? "border-primary bg-primary" : "border-info bg-info") : "border-outline bg-surface-high")}
    >
      <span className={cx("absolute top-[2px] h-2.5 w-2.5 rounded-full transition-all", checked ? "left-[13px] bg-on-primary" : "left-[2px] bg-muted")} />
    </button>
  );
}

const field = "w-full rounded-[3px] border border-outline bg-surface-low px-2 py-1 text-[12.5px] text-ink placeholder:text-dim focus:border-accent focus:outline-none disabled:opacity-50";
export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx(field, props.type !== "file" && "h-7", props.className)} />;
}
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx(field, "h-7 pr-6", props.className)} />;
}
export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx(field, "font-mono text-[12px] leading-relaxed", props.className)} />;
}
export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="text-xs font-medium text-muted">{label}</span>
      {children}
      {hint && <span className="block text-[11.5px] text-dim">{hint}</span>}
    </label>
  );
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { id: T; label: string }[]; label: string }) {
  return (
    <div role="tablist" aria-label={label} className="inline-flex rounded-[3px] border border-outline bg-surface-low p-px">
      {options.map((o) => (
        <button
          key={o.id}
          role="tab"
          aria-selected={value === o.id}
          onClick={() => onChange(o.id)}
          className={cx("h-6 rounded-[2px] px-3 text-[12.5px] font-medium transition-colors", value === o.id ? "bg-surface-top text-ink" : "text-muted hover:text-ink")}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Progress({ value, tone = "accent", label }: { value: number; tone?: "accent" | "warn" | "info" | "danger"; label?: string }) {
  const color = { accent: "bg-accent", warn: "bg-warn", info: "bg-info", danger: "bg-danger" }[tone];
  return (
    <div className="h-1.5 w-full overflow-hidden bg-surface-high" role="progressbar" aria-valuenow={Math.round(value)} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
      <div className={cx("h-full transition-all", color)} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  );
}

// ---- states -----------------------------------------------------------------------------------
export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-xs text-muted" role="status">
      <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> {label}…
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-[3px] border border-danger/40 bg-danger-soft px-3 py-2 text-xs text-danger">
      <AlertTriangle className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden />
      <div className="flex-1">
        <div className="font-medium">Request failed</div>
        <div className="mt-0.5 break-words opacity-90">{error}</div>
      </div>
      {onRetry && (
        <Button size="sm" variant="outline" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Empty({ icon, title, children, actions }: { icon?: ReactNode; title: string; children?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-col items-start rounded-[3px] border border-dashed border-outline bg-surface/50 px-4 py-4">
      <div className="flex items-center gap-2">
        {icon && <span className="text-muted [&>svg]:h-4 [&>svg]:w-4">{icon}</span>}
        <h3 className="text-[13px] font-semibold">{title}</h3>
      </div>
      {children && <p className="mt-1 max-w-xl text-[12.5px] leading-relaxed text-muted">{children}</p>}
      {actions && <div className="mt-3 flex flex-wrap gap-1.5">{actions}</div>}
    </div>
  );
}

export function Note({ tone = "info", children, title }: { tone?: "info" | "warn" | "accent"; children: ReactNode; title?: string }) {
  const t = { info: "border-l-info", warn: "border-l-warn", accent: "border-l-accent" }[tone];
  return (
    <div className={cx("rounded-[3px] border border-l-2 border-outline bg-surface-low px-3 py-2 text-[12.5px] leading-relaxed text-ink", t)}>
      {title && <div className="mb-0.5 font-medium">{title}</div>}
      {children}
    </div>
  );
}

// ---- overlays -----------------------------------------------------------------------------------
export function Drawer({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      prev?.focus?.();
    };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/45" onClick={onClose} aria-hidden />
      <aside
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : "Details"}
        className={cx("relative flex h-full w-full flex-col overflow-hidden border-l border-outline bg-bg", wide ? "max-w-3xl" : "max-w-xl")}
      >
        <div className="flex h-10 items-center justify-between gap-3 border-b border-outline bg-surface px-3">
          <div className="min-w-0 flex-1 truncate text-[13px] font-semibold">{title}</div>
          <button onClick={onClose} aria-label="Close" className="rounded-[3px] p-1 text-muted hover:bg-surface-high hover:text-ink">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-3">{children}</div>
      </aside>
    </div>
  );
}

export function Modal({ open, onClose, title, children, actions }: { open: boolean; onClose: () => void; title: string; children: ReactNode; actions: ReactNode }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden />
      <div role="alertdialog" aria-modal="true" aria-label={title} className="relative w-full max-w-md rounded-[3px] border border-outline bg-surface p-4">
        <h3 className="text-[14px] font-semibold">{title}</h3>
        <div className="mt-2 text-[12.5px] leading-relaxed text-muted">{children}</div>
        <div className="mt-4 flex justify-end gap-1.5">{actions}</div>
      </div>
    </div>
  );
}

export function CopyBlock({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-[3px] border border-outline bg-surface-low p-3 pr-10 font-mono text-[12px] leading-relaxed text-ink" aria-label={label}>
        <code>{text}</code>
      </pre>
      <button
        aria-label={`Copy ${label}`}
        onClick={() => {
          navigator.clipboard?.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }}
        className="absolute right-2 top-2 rounded-[3px] border border-outline bg-surface p-1 text-muted hover:text-ink"
      >
        {done ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
    </div>
  );
}

/** Two concentric rings: outer = evaluated coverage, inner = share of evaluated packages affected. */
export function Dial({ outer, inner, center, caption, sub }: { outer: number; inner: number; center: ReactNode; caption: string; sub?: ReactNode }) {
  const c = 2 * Math.PI * 45;
  const o = Math.max(0, Math.min(100, outer));
  const i = Math.max(0, Math.min(100, inner));
  return (
    <div className="relative flex h-36 w-36 items-center justify-center" role="img" aria-label={`${caption}. Outer ring ${o.toFixed(0)} percent evaluated, inner ring ${i.toFixed(0)} percent of evaluated packages affected.`}>
      <svg viewBox="0 0 100 100" className="absolute h-full w-full -rotate-90" aria-hidden>
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="5" stroke="rgb(var(--surface-high))" />
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="5" stroke="rgb(var(--accent))" strokeDasharray={c} strokeDashoffset={c * (1 - o / 100)} />
      </svg>
      <svg viewBox="0 0 100 100" className="absolute h-3/4 w-3/4 -rotate-90" aria-hidden>
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="6" stroke="rgb(var(--surface-high))" />
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="6" stroke="rgb(var(--warn))" strokeDasharray={c} strokeDashoffset={c * (1 - i / 100)} />
      </svg>
      <div className="z-10 text-center">
        <div className="font-mono text-2xl font-medium">{center}</div>
        <div className="text-[11px] text-muted">{caption}</div>
        {sub && <div className="text-[11px] text-warn">{sub}</div>}
      </div>
    </div>
  );
}

export const fmtDate = (s?: string | null) =>
  s ? new Date(s).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
export const shortDate = (s?: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "—");
