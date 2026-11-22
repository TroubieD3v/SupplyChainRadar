# ADR 0002 — UI stack and design system

*Status: accepted for v1.0.*

* **React 18 + TypeScript + Vite**, **Tailwind CSS 4**, **@xyflow/react** (graph), **Recharts** (charts), **@dagrejs/dagre** (layout), **lucide-react** (icons). Fonts (IBM Plex Sans for text, IBM Plex Mono for versions, ids and numbers) are self-hosted through `@fontsource` packages — no request leaves the machine for fonts or icons, consistent with the offline-first promise.
* `shadcn/ui` is **not** used; a small set of accessible primitives lives in `frontend/src/components/ui.tsx` and follows the same token-driven approach.
* **Design tokens** (`frontend/src/index.css`) are a neutral graphite palette (dark `#191b1e` background, `#1f2226` panels, hairline `#2f333a` borders) with a matching light theme; colour is reserved for severity and scan state. Dark is the default theme; the toggle persists in `localStorage`. The layout follows component-analysis portfolio tools: a grouped sidebar, a project header with per-severity counters on every project page, dense tables for findings and packages, and bottom navigation on small screens.
* Severity colours are semantic (critical = red, high = orange, medium = amber, low = slate blue); *unknown* severity uses a dashed outline so it can never be mistaken for "low".
* Pages are lazy-loaded; the graph view is bounded (vulnerable-path subgraph by default, 800-node cap in full mode) rather than virtualising 10k nodes.
