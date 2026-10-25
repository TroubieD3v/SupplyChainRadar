# ADR 0002 — UI stack and design system

*Status: accepted for v1.0.*

* **React 18 + TypeScript + Vite**, **Tailwind CSS 4**, **@xyflow/react** (graph), **Recharts** (charts), **@dagrejs/dagre** (layout), **lucide-react** (icons). Fonts (Manrope for headlines, Inter for body/labels) are self-hosted through `@fontsource` packages — no request leaves the machine for fonts or icons, consistent with the offline-first promise.
* `shadcn/ui` is **not** used; a small set of accessible primitives lives in `frontend/src/components/ui.tsx` and follows the same token-driven approach.
* **Design tokens** (`frontend/src/index.css`) come from the brand sheet: Primary `#121212`, Secondary `#008542`, Tertiary `#D97706`, Neutral `#64748B`. Dark is the default theme; the toggle persists in `localStorage`. Layout language (rounded surface cards, bento stats, circular dial, bottom navigation on small screens) follows the EcoSync reference screens.
* Severity colours are semantic (critical = red, high/tertiary = orange, low = neutral slate); *unknown* severity uses a dashed outline so it can never be mistaken for "low".
* Pages are lazy-loaded; the graph view is bounded (vulnerable-path subgraph by default, 800-node cap in full mode) rather than virtualising 10k nodes.
