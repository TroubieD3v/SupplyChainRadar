import clsx from "clsx";
import { AlertTriangle, Check, Copy, Loader2, X } from "lucide-react";
import { useEffect, useRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";
import type { Severity } from "../api/types";

export const cx = clsx;

// ---- layout atoms -----------------------------------------------------------------------------
export function Card({ children, className, tone = "default", as: Tag = "div", ...rest }: { children: ReactNode; className?: string; tone?: "default" | "low" | "high" | "inverse" | "accent"; as?: any } & Record<string, any>) {
  const tones = {
    default: "bg-surface border border-outline/40",
    low: "bg-surface-low border border-outline/30",
    high: "bg-surface-high",
    inverse: "bg-[#1e2d44] text-[#eef1f6] dark:bg-[#0f1a2b]",
    accent: "bg-accent text-on-accent",
  };
  return (
    <Tag className={cx("rounded-3xl p-5 sm:p-6", tones[tone], className)} {...rest}>
      {children}
    </Tag>
  );
}

export function PageHeader({ eyebrow, title, children, actions }: { eyebrow?: ReactNode; title: string; children?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="mb-8 flex flex-col gap-5 md:flex-row md:items-end md:justify-between">
      <div className="max-w-2xl">
        {eyebrow && <div className="mb-3">{eyebrow}</div>}
        <h1 className="text-4xl font-semibold leading-none tracking-tight sm:text-5xl">{title}</h1>
        {children && <p className="mt-4 text-base leading-relaxed text-muted sm:text-lg">{children}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </header>
  );
}

export function Label({ children }: { children: ReactNode }) {
  return <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-muted">{children}</div>;
}

export function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "accent" | "warn" | "danger" }) {
  return (
    <div className="rounded-2xl border border-outline/30 bg-surface-low p-4 sm:p-5">
      <Label>{label}</Label>
      <div className={cx("font-headline mt-2 text-3xl font-semibold", tone === "accent" && "text-accent", tone === "warn" && "text-warn", tone === "danger" && "text-danger")}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </div>
  );
}

// ---- chips ------------------------------------------------------------------------------------
export function Chip({ children, tone = "neutral", className, title }: { children: ReactNode; tone?: "neutral" | "accent" | "warn" | "danger" | "info" | "solid"; className?: string; title?: string }) {
  const tones = {
    neutral: "bg-surface-high text-muted",
    accent: "bg-accent-soft text-accent",
    warn: "bg-warn-soft text-warn",
    danger: "bg-danger-soft text-danger",
    info: "bg-info-soft text-info",
    solid: "bg-primary text-on-primary",
  };
  return (
    <span title={title} className={cx("inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wider", tones[tone], className)}>
      {children}
    </span>
  );
}

const SEV_TONE: Record<Severity, "danger" | "warn" | "info" | "neutral"> = { critical: "danger", high: "warn", medium: "warn", low: "info", unknown: "neutral" };
export function SeverityChip({ level }: { level: Severity | string | null | undefined }) {
  const l = (level ?? "unknown") as Severity;
  return (
    <Chip tone={SEV_TONE[l] ?? "neutral"} className={cx(l === "medium" && "opacity-80", l === "unknown" && "border border-dashed border-muted/60 bg-transparent")} title={l === "unknown" ? "The advisory source gave no severity" : undefined}>
      {l}
    </Chip>
  );
}

export const SEV_COLOR: Record<Severity, string> = {
  critical: "rgb(var(--danger))",
  high: "rgb(var(--warn))",
  medium: "#e8b04a",
  low: "rgb(var(--info))",
  unknown: "rgb(var(--outline))",
};

export function StateChip({ state }: { state: string }) {
  const map: Record<string, ["accent" | "warn" | "danger" | "info" | "neutral", string]> = {
    completed: ["accent", "completed"],
    partial: ["warn", "partial"],
    failed: ["danger", "failed"],
    cancelled: ["neutral", "cancelled"],
    queued: ["info", "queued"],
    parsing: ["info", "parsing"],
    enriching: ["info", "enriching"],
    analyzing: ["info", "analyzing"],
    evaluated: ["accent", "evaluated"],
    cached: ["accent", "cached"],
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
    <span
      title="Built from synthetic fixtures; not a real project"
      style={{ background: "#d97706", color: "#121212" }}
      className={cx("inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wider", className)}
    >
      Demo data
    </span>
  );
}

// ---- controls -----------------------------------------------------------------------------------
type BtnVariant = "primary" | "accent" | "soft" | "outline" | "danger" | "ghost";
export function Button({ variant = "primary", size = "md", className, children, loading, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: BtnVariant; size?: "sm" | "md"; loading?: boolean }) {
  const v: Record<BtnVariant, string> = {
    primary: "bg-primary text-on-primary hover:opacity-90",
    accent: "bg-accent text-on-accent hover:opacity-90",
    soft: "bg-surface-high text-ink hover:bg-surface-top",
    outline: "border border-outline text-ink hover:bg-surface-high",
    danger: "bg-[#b91c1c] text-white hover:opacity-90",
    ghost: "text-muted hover:bg-surface-high hover:text-ink",
  };
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-xl font-semibold transition disabled:cursor-not-allowed disabled:opacity-50",
        size === "md" ? "px-5 py-2.5 text-sm" : "px-3 py-1.5 text-xs",
        v[variant],
        className,
      )}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
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
      className={cx("relative h-7 w-12 shrink-0 rounded-full transition-colors", checked ? (tone === "accent" ? "bg-accent" : "bg-info") : "bg-surface-top")}
    >
      <span className={cx("absolute top-1 h-5 w-5 rounded-full bg-white shadow transition-all", checked ? "left-6" : "left-1")} />
    </button>
  );
}

const field =
  "w-full rounded-xl border border-outline/60 bg-surface-low px-3.5 py-2.5 text-sm text-ink placeholder:text-muted/70 focus:border-accent focus:outline-none";
export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx(field, props.className)} />;
}
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cx(field, "pr-8", props.className)} />;
}
export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx(field, props.className)} />;
}
export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-semibold text-muted">{label}</span>
      {children}
      {hint && <span className="block text-xs text-muted">{hint}</span>}
    </label>
  );
}

export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { id: T; label: string }[]; label: string }) {
  return (
    <div role="tablist" aria-label={label} className="inline-flex rounded-xl bg-surface-high p-1">
      {options.map((o) => (
        <button
          key={o.id}
          role="tab"
          aria-selected={value === o.id}
          onClick={() => onChange(o.id)}
          className={cx("rounded-lg px-3.5 py-1.5 text-sm font-semibold transition", value === o.id ? "bg-surface text-ink shadow-sm" : "text-muted hover:text-ink")}
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
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-high" role="progressbar" aria-valuenow={Math.round(value)} aria-valuemin={0} aria-valuemax={100} aria-label={label}>
      <div className={cx("h-full rounded-full transition-all", color)} style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
    </div>
  );
}

// ---- states -----------------------------------------------------------------------------------
export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-10 text-sm text-muted" role="status">
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> {label}…
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-3 rounded-2xl border border-danger/40 bg-danger-soft p-4 text-sm text-danger">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <div className="flex-1">
        <div className="font-semibold">Request failed</div>
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
    <div className="flex flex-col items-center rounded-3xl border border-dashed border-outline px-6 py-14 text-center">
      {icon && <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-high text-muted">{icon}</div>}
      <h3 className="text-xl font-semibold">{title}</h3>
      {children && <p className="mt-2 max-w-md text-sm leading-relaxed text-muted">{children}</p>}
      {actions && <div className="mt-6 flex flex-wrap justify-center gap-2">{actions}</div>}
    </div>
  );
}

export function Note({ tone = "info", children, title }: { tone?: "info" | "warn" | "accent"; children: ReactNode; title?: string }) {
  const t = { info: "bg-info-soft text-ink", warn: "bg-warn-soft text-ink", accent: "bg-accent-soft text-ink" }[tone];
  return (
    <div className={cx("rounded-2xl p-4 text-sm leading-relaxed", t)}>
      {title && <div className="mb-1 font-semibold">{title}</div>}
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
      <div className="absolute inset-0 bg-black/50" onClick={onClose} aria-hidden />
      <aside
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : "Details"}
        className={cx("relative flex h-full w-full flex-col overflow-hidden bg-bg shadow-2xl", wide ? "max-w-3xl" : "max-w-xl")}
      >
        <div className="flex items-center justify-between gap-3 border-b border-outline/40 px-5 py-4">
          <div className="min-w-0 flex-1 truncate font-headline text-lg font-semibold">{title}</div>
          <button onClick={onClose} aria-label="Close" className="rounded-lg p-2 text-muted hover:bg-surface-high hover:text-ink">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
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
      <div role="alertdialog" aria-modal="true" aria-label={title} className="relative w-full max-w-md rounded-3xl bg-surface p-6 shadow-2xl">
        <h3 className="text-xl font-semibold">{title}</h3>
        <div className="mt-3 text-sm leading-relaxed text-muted">{children}</div>
        <div className="mt-6 flex justify-end gap-2">{actions}</div>
      </div>
    </div>
  );
}

export function CopyBlock({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-2xl bg-[#0d1522] p-4 pr-12 font-mono text-[12.5px] leading-relaxed text-[#d6e2f5]" aria-label={label}>
        <code>{text}</code>
      </pre>
      <button
        aria-label={`Copy ${label}`}
        onClick={() => {
          navigator.clipboard?.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        }}
        className="absolute right-3 top-3 rounded-lg bg-white/10 p-1.5 text-white/80 hover:bg-white/20"
      >
        {done ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </button>
    </div>
  );
}

export function Dial({ outer, inner, center, caption, sub }: { outer: number; inner: number; center: ReactNode; caption: string; sub?: ReactNode }) {
  const c1 = 2 * Math.PI * 45;
  const c2 = 2 * Math.PI * 45;
  const o = Math.max(0, Math.min(100, outer));
  const i = Math.max(0, Math.min(100, inner));
  return (
    <div className="relative mx-auto flex h-72 w-72 items-center justify-center sm:h-80 sm:w-80" role="img" aria-label={`${caption}. Outer ring ${o.toFixed(0)} percent evaluated, inner ring ${i.toFixed(0)} percent of evaluated packages affected.`}>
      <div className="absolute inset-0 rounded-full bg-accent/10 blur-3xl" aria-hidden />
      <svg viewBox="0 0 100 100" className="absolute h-full w-full -rotate-90" aria-hidden>
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="6" stroke="rgb(var(--surface-high))" />
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="6" strokeLinecap="round" stroke="rgb(var(--accent))" strokeDasharray={c1} strokeDashoffset={c1 * (1 - o / 100)} style={{ transition: "stroke-dashoffset .8s ease" }} />
      </svg>
      <svg viewBox="0 0 100 100" className="absolute h-3/4 w-3/4 -rotate-90" aria-hidden>
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="8" stroke="rgb(var(--surface-high))" />
        <circle cx="50" cy="50" r="45" fill="none" strokeWidth="8" strokeLinecap="round" stroke="rgb(var(--warn))" strokeDasharray={c2} strokeDashoffset={c2 * (1 - i / 100)} style={{ transition: "stroke-dashoffset .8s ease" }} />
      </svg>
      <div className="z-10 text-center">
        <div className="font-headline text-5xl font-bold sm:text-6xl">{center}</div>
        <div className="mt-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-muted">{caption}</div>
        {sub && <div className="mt-3 text-sm font-semibold text-warn">{sub}</div>}
      </div>
    </div>
  );
}

export const fmtDate = (s?: string | null) =>
  s ? new Date(s).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
export const shortDate = (s?: string | null) => (s ? new Date(s).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "—");
