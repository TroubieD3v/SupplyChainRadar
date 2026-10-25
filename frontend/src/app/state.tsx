import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { get } from "../api/client";
import type { Project, ScanMeta } from "../api/types";

// ---- theme -----------------------------------------------------------------------------------
type Theme = "dark" | "light";
const ThemeCtx = createContext<{ theme: Theme; toggle: () => void }>({ theme: "dark", toggle: () => {} });
export const useTheme = () => useContext(ThemeCtx);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem("scradar-theme") === "light" ? "light" : "dark"));
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
    localStorage.setItem("scradar-theme", theme);
  }, [theme]);
  const value = useMemo(() => ({ theme, toggle: () => setTheme((t) => (t === "dark" ? "light" : "dark")) }), [theme]);
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>;
}

// ---- project / scan selection ------------------------------------------------------------------
interface Sel {
  projects: Project[];
  loading: boolean;
  error: string | null;
  project: Project | null;
  scans: ScanMeta[];
  scan: ScanMeta | null;
  setProjectId: (id: string) => void;
  setScanId: (id: string) => void;
  reload: () => void;
}
const SelCtx = createContext<Sel>(null as unknown as Sel);
export const useSelection = () => useContext(SelCtx);

const isDone = (s: ScanMeta["state"]) => ["completed", "partial"].includes(s);
const isBusy = (s: ScanMeta["state"]) => ["queued", "parsing", "enriching", "analyzing"].includes(s);

export function SelectionProvider({ children }: { children: ReactNode }) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [scans, setScans] = useState<ScanMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [projectId, setPid] = useState<string>(() => localStorage.getItem("scradar-project") ?? "");
  const [scanId, setSid] = useState<string>(() => localStorage.getItem("scradar-scan") ?? "");
  const [tick, setTick] = useState(0);
  const timer = useRef<number>();

  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const ps: Project[] = await get("/projects");
        if (!alive) return;
        setProjects(ps);
        setError(null);
        const pid = ps.find((p) => p.id === projectId)?.id ?? ps[0]?.id ?? "";
        if (pid !== projectId) setPid(pid);
        if (pid) {
          const ss: ScanMeta[] = await get(`/projects/${pid}/scans`);
          if (!alive) return;
          setScans(ss);
          if (!ss.find((s) => s.id === scanId)) {
            const best = ss.find((s) => isDone(s.state)) ?? ss[0];
            setSid(best?.id ?? "");
          }
          if (ss.some((s) => isBusy(s.state)) || ps.some((p) => p.active_scan)) {
            timer.current = window.setTimeout(reload, 900);
          }
        } else {
          setScans([]);
          setSid("");
        }
      } catch (e: any) {
        if (alive) setError(e.message ?? String(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
      window.clearTimeout(timer.current);
    };
  }, [tick, projectId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    localStorage.setItem("scradar-project", projectId);
  }, [projectId]);
  useEffect(() => {
    localStorage.setItem("scradar-scan", scanId);
  }, [scanId]);

  const value = useMemo<Sel>(
    () => ({
      projects,
      loading,
      error,
      project: projects.find((p) => p.id === projectId) ?? null,
      scans,
      scan: scans.find((s) => s.id === scanId) ?? null,
      setProjectId: (id) => {
        setPid(id);
        setSid("");
      },
      setScanId: setSid,
      reload,
    }),
    [projects, loading, error, projectId, scans, scanId, reload],
  );
  return <SelCtx.Provider value={value}>{children}</SelCtx.Provider>;
}

// ---- data fetching -----------------------------------------------------------------------------
export function useFetch<T>(loader: (() => Promise<T>) | null, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(Boolean(loader));
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!loader) {
      setData(null);
      setLoading(false);
      return;
    }
    let alive = true;
    setLoading(true);
    loader()
      .then((d) => alive && (setData(d), setError(null)))
      .catch((e) => alive && setError(e.message ?? String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [...deps, tick]); // eslint-disable-line react-hooks/exhaustive-deps
  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}
