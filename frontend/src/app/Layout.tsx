import { Boxes, FileText, FolderUp, GitCompare, LayoutDashboard, MoreHorizontal, Moon, Network, Radar, ScanLine, ScrollText, ShieldAlert, Sun, Wrench } from "lucide-react";
import { Suspense, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { DemoBadge, Drawer, Select, cx, shortDate } from "../components/ui";
import { useSelection, useTheme } from "./state";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, primary: true },
  { to: "/projects", label: "Projects & Imports", short: "Projects", icon: FolderUp },
  { to: "/scan", label: "Scan Details", short: "Scan", icon: ScanLine },
  { to: "/dependencies", label: "Dependencies", short: "Packages", icon: Boxes },
  { to: "/graph", label: "Dependency Graph", short: "Graph", icon: Network, primary: true },
  { to: "/findings", label: "Findings", icon: ShieldAlert, primary: true },
  { to: "/remediation", label: "Remediation Studio", short: "Remediate", icon: Wrench, primary: true },
  { to: "/compare", label: "Compare & Timeline", short: "Compare", icon: GitCompare },
  { to: "/policies", label: "Policies & CI", short: "Policies", icon: ScrollText },
  { to: "/reports", label: "Reports & Settings", short: "Reports", icon: FileText },
];

function Brand() {
  return (
    <div className="flex items-center gap-3">
      <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-primary text-on-primary">
        <Radar className="h-5 w-5" aria-hidden />
      </div>
      <span className="font-headline whitespace-nowrap text-lg font-bold tracking-tight">SupplyChain Radar</span>
    </div>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      onClick={toggle}
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
      className="flex h-10 w-10 items-center justify-center rounded-full text-muted transition hover:bg-surface-high hover:text-ink"
    >
      {theme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
    </button>
  );
}

export function Layout() {
  const sel = useSelection();
  const [more, setMore] = useState(false);
  const link = ({ isActive }: { isActive: boolean }) =>
    cx("flex items-center gap-3 rounded-2xl px-4 py-2.5 text-sm font-semibold transition", isActive ? "bg-primary text-on-primary" : "text-muted hover:bg-surface-high hover:text-ink");

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[272px_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[70] focus:rounded-xl focus:bg-primary focus:px-4 focus:py-2 focus:text-on-primary">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-screen flex-col gap-6 border-r border-outline/30 bg-surface-low p-5 lg:flex">
        <Brand />
        <nav aria-label="Primary" className="flex flex-1 flex-col gap-1 overflow-y-auto">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === "/"} className={link}>
              <Icon className="h-[18px] w-[18px]" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
        <p className="text-[11px] leading-relaxed text-muted">Offline-first. Nothing leaves this machine unless you pick Live OSV lookup.</p>
      </aside>

      <div className="min-w-0">
        <header className="glass sticky top-0 z-40 flex flex-wrap items-center gap-3 border-b border-outline/30 px-4 py-3 sm:px-8">
          <div className="lg:hidden">
            <Brand />
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {sel.projects.length > 0 && (
              <>
                <Select aria-label="Project" className="!w-auto max-w-[220px] !py-2" value={sel.project?.id ?? ""} onChange={(e) => sel.setProjectId(e.target.value)}>
                  {sel.projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </Select>
                <Select aria-label="Scan" className="!w-auto max-w-[260px] !py-2" value={sel.scan?.id ?? ""} onChange={(e) => sel.setScanId(e.target.value)} disabled={sel.scans.length === 0}>
                  {sel.scans.length === 0 && <option value="">No scans yet</option>}
                  {sel.scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {(s.label ?? "scan") + " · " + shortDate(s.created_at) + (["completed", "partial"].includes(s.state) ? "" : " · " + s.state)}
                    </option>
                  ))}
                </Select>
              </>
            )}
            {sel.scan?.demo && <DemoBadge />}
            <ThemeToggle />
          </div>
        </header>

        <main id="main" className="mx-auto max-w-[1280px] px-4 pb-32 pt-8 sm:px-8 lg:pb-16">
          <Suspense fallback={<div className="py-10 text-sm text-muted" role="status">Loading…</div>}>
            <Outlet />
          </Suspense>
        </main>
      </div>

      <nav aria-label="Primary mobile" className="glass fixed inset-x-0 bottom-0 z-40 flex items-stretch justify-around border-t border-outline/30 px-2 py-1.5 lg:hidden">
        {NAV.filter((n) => n.primary).map(({ to, label, short, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => cx("flex min-w-[64px] flex-col items-center gap-1 rounded-xl px-2 py-1.5 text-[10px] font-bold uppercase tracking-wider", isActive ? "text-accent" : "text-muted")}>
            <Icon className="h-5 w-5" aria-hidden />
            {short ?? label}
          </NavLink>
        ))}
        <button onClick={() => setMore(true)} className="flex min-w-[64px] flex-col items-center gap-1 rounded-xl px-2 py-1.5 text-[10px] font-bold uppercase tracking-wider text-muted">
          <MoreHorizontal className="h-5 w-5" aria-hidden />
          More
        </button>
      </nav>
      <Drawer open={more} onClose={() => setMore(false)} title="All sections">
        <div className="grid gap-1">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === "/"} onClick={() => setMore(false)} className={link}>
              <Icon className="h-[18px] w-[18px]" aria-hidden />
              {label}
            </NavLink>
          ))}
        </div>
      </Drawer>
    </div>
  );
}
