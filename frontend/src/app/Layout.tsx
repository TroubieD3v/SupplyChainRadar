import { Boxes, ChevronRight, FileText, FolderUp, GitCompare, LayoutDashboard, MoreHorizontal, Moon, Network, Radar, ScanLine, ScrollText, ShieldAlert, Sun, Wrench } from "lucide-react";
import { Suspense, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import type { Severity } from "../api/types";
import { DemoBadge, Drawer, SEV_CLASS, Select, StateChip, cx, shortDate } from "../components/ui";
import { useSelection, useTheme } from "./state";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, primary: true, group: "Portfolio" },
  { to: "/projects", label: "Projects & Imports", short: "Projects", icon: FolderUp, group: "Portfolio" },
  { to: "/scan", label: "Scan Details", short: "Scan", icon: ScanLine, group: "Project" },
  { to: "/dependencies", label: "Dependencies", short: "Packages", icon: Boxes, group: "Project" },
  { to: "/graph", label: "Dependency Graph", short: "Graph", icon: Network, primary: true, group: "Project" },
  { to: "/findings", label: "Findings", icon: ShieldAlert, primary: true, group: "Project" },
  { to: "/remediation", label: "Remediation Studio", short: "Remediate", icon: Wrench, primary: true, group: "Project" },
  { to: "/compare", label: "Compare & Timeline", short: "Compare", icon: GitCompare, group: "Project" },
  { to: "/policies", label: "Policies & CI", short: "Policies", icon: ScrollText, group: "Governance" },
  { to: "/reports", label: "Reports & Settings", short: "Reports", icon: FileText, group: "Governance" },
];
const GROUPS = ["Portfolio", "Project", "Governance"];
const PROJECT_PAGES = ["/scan", "/dependencies", "/graph", "/findings", "/remediation", "/compare"];
const SEVS: [Severity, string][] = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["unknown", "Unassigned"],
];

function Brand() {
  return (
    <div className="flex items-center gap-2">
      <Radar className="h-4 w-4 text-ink" aria-hidden />
      <span className="whitespace-nowrap text-[13px] font-semibold">SupplyChain Radar</span>
    </div>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      onClick={toggle}
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
      className="flex h-7 w-7 items-center justify-center rounded-[3px] border border-outline text-muted transition-colors hover:bg-surface-high hover:text-ink"
    >
      {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
    </button>
  );
}

/** Project header in the style of a component-analysis portfolio: name, scan, severity counters, coverage. */
function ProjectBand() {
  const sel = useSelection();
  const sum = sel.scan?.summary;
  if (!sel.project) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-outline bg-surface px-4 py-2 lg:px-5">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="truncate text-[14px] font-semibold">{sel.project.name}</span>
          {sel.scan && <span className="font-mono text-xs text-muted">{sel.scan.label ?? "scan"}</span>}
          {sel.scan && <StateChip state={sel.scan.state} />}
          {sel.scan?.demo && <DemoBadge />}
        </div>
        <div className="text-[11.5px] text-dim">
          {sel.scan ? `scanned ${shortDate(sel.scan.created_at)}` : "no scan yet"}
          {sum ? ` · ${sum.packages} packages · ${sum.advisory_source.mode.replace("_", " ")}` : ""}
        </div>
      </div>
      {sum && (
        <div className="flex items-stretch gap-1" aria-label="Advisories by severity">
          {SEVS.map(([s, label]) => (
            <Link
              key={s}
              to={`/findings?severity=${s}`}
              title={`${sum.severity[s]} ${label.toLowerCase()}`}
              className={cx("flex min-w-[52px] flex-col items-center rounded-[3px] border border-outline px-2 py-0.5 hover:bg-surface-high", sum.severity[s] === 0 && "opacity-55")}
            >
              <span className="font-mono text-[14px] font-medium leading-5">{sum.severity[s]}</span>
              <span className="flex items-center gap-1 text-[10.5px] text-muted">
                <span className={cx("size-1.5 rounded-[1px]", SEV_CLASS[s])} aria-hidden />
                {label}
              </span>
            </Link>
          ))}
        </div>
      )}
      {sum && (
        <div className="ml-auto text-right text-xs">
          <div className="font-mono text-[14px] font-medium leading-5">{sum.coverage.percent_evaluated}%</div>
          <div className="text-[10.5px] text-muted">evaluated{sum.coverage.graph_complete ? "" : " · graph partial"}</div>
        </div>
      )}
    </div>
  );
}

function Crumbs() {
  const { pathname } = useLocation();
  const sel = useSelection();
  const item = NAV.find((n) => (n.to === "/" ? pathname === "/" : pathname.startsWith(n.to)));
  return (
    <div className="flex min-w-0 items-center gap-1 text-[12.5px] text-muted">
      <span className="hidden sm:inline">{item?.group ?? "Portfolio"}</span>
      <ChevronRight className="hidden h-3 w-3 text-dim sm:block" aria-hidden />
      {item?.group === "Project" && sel.project && (
        <>
          <span className="truncate">{sel.project.name}</span>
          <ChevronRight className="h-3 w-3 text-dim" aria-hidden />
        </>
      )}
      <span className="truncate text-ink">{item?.label ?? "Overview"}</span>
    </div>
  );
}

export function Layout() {
  const sel = useSelection();
  const { pathname } = useLocation();
  const [more, setMore] = useState(false);
  const link = ({ isActive }: { isActive: boolean }) =>
    cx("flex h-7 items-center gap-2 rounded-[3px] px-2 text-[12.5px] transition-colors", isActive ? "bg-surface-high font-medium text-ink" : "text-muted hover:bg-surface-high/60 hover:text-ink");
  const showBand = PROJECT_PAGES.some((p) => pathname.startsWith(p));

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[212px_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[70] focus:rounded-[3px] focus:bg-primary focus:px-3 focus:py-1.5 focus:text-on-primary">
        Skip to content
      </a>
      <div className="hidden border-r border-outline bg-chrome lg:block">
        <aside className="sticky top-0 flex h-screen flex-col">
          <div className="flex h-10 items-center border-b border-outline px-3">
            <Brand />
          </div>
          <nav aria-label="Primary" className="flex flex-1 flex-col overflow-y-auto px-2 py-2">
            {GROUPS.map((g) => (
              <div key={g} className="mb-2">
                <div className="px-2 pb-0.5 pt-1.5 text-[11px] font-medium text-dim">{g}</div>
                {NAV.filter((n) => n.group === g).map(({ to, label, icon: Icon }) => (
                  <NavLink key={to} to={to} end={to === "/"} className={link}>
                    <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden />
                    {label}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
          <p className="border-t border-outline p-3 text-[11px] leading-snug text-dim">Offline-first. Nothing leaves this machine unless you pick Live OSV lookup.</p>
        </aside>
      </div>

      <div className="min-w-0">
        <header className="sticky top-0 z-40 flex flex-wrap items-center gap-2 border-b border-outline bg-bg px-4 py-1.5 lg:h-10 lg:px-5 lg:py-0">
          <div className="lg:hidden">
            <Brand />
          </div>
          <div className="hidden lg:block">
            <Crumbs />
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            {sel.projects.length > 0 && (
              <>
                <Select aria-label="Project" className="!w-auto max-w-[220px]" value={sel.project?.id ?? ""} onChange={(e) => sel.setProjectId(e.target.value)}>
                  {sel.projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Select>
                <Select aria-label="Scan" className="!w-auto max-w-[260px]" value={sel.scan?.id ?? ""} onChange={(e) => sel.setScanId(e.target.value)} disabled={sel.scans.length === 0}>
                  {sel.scans.length === 0 && <option value="">No scans yet</option>}
                  {sel.scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {(s.label ?? "scan") + " · " + shortDate(s.created_at) + (["completed", "partial"].includes(s.state) ? "" : " · " + s.state)}
                    </option>
                  ))}
                </Select>
              </>
            )}
            <ThemeToggle />
          </div>
        </header>
        {showBand && <ProjectBand />}

        <main id="main" className="mx-auto max-w-[1440px] px-4 pb-24 pt-4 lg:px-5 lg:pb-8">
          <Suspense fallback={<div className="py-6 text-xs text-muted" role="status">Loading…</div>}>
            <Outlet />
          </Suspense>
        </main>
      </div>

      <nav aria-label="Primary mobile" className="fixed inset-x-0 bottom-0 z-40 flex items-stretch justify-around border-t border-outline bg-chrome px-2 py-1 lg:hidden">
        {NAV.filter((n) => n.primary).map(({ to, label, short, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => cx("flex min-w-[64px] flex-col items-center gap-0.5 rounded-[3px] px-2 py-1 text-[10.5px]", isActive ? "bg-surface-high text-ink" : "text-muted")}>
            <Icon className="h-4 w-4" aria-hidden />
            {short ?? label}
          </NavLink>
        ))}
        <button onClick={() => setMore(true)} className="flex min-w-[64px] flex-col items-center gap-0.5 rounded-[3px] px-2 py-1 text-[10.5px] text-muted">
          <MoreHorizontal className="h-4 w-4" aria-hidden />
          More
        </button>
      </nav>
      <Drawer open={more} onClose={() => setMore(false)} title="All sections">
        <div className="grid gap-0.5">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === "/"} onClick={() => setMore(false)} className={link}>
              <Icon className="h-3.5 w-3.5" aria-hidden />
              {label}
            </NavLink>
          ))}
        </div>
      </Drawer>
    </div>
  );
}
