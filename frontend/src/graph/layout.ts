import dagre from "@dagrejs/dagre";
import type { GraphData } from "../api/types";

export const NODE_W = 210;
export const NODE_H = 58;

export interface Laid {
  positions: Record<string, { x: number; y: number }>;
  width: number;
  height: number;
}

export function layout(data: GraphData, dir: "LR" | "TB" = "LR"): Laid {
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({ rankdir: dir, nodesep: 22, ranksep: 90, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));
  data.nodes.forEach((n) => g.setNode(n.id, { width: NODE_W, height: NODE_H }));
  data.edges.forEach((e) => g.setEdge(e.source, e.target, {}, e.id));
  dagre.layout(g);
  const positions: Record<string, { x: number; y: number }> = {};
  data.nodes.forEach((n) => {
    const p = g.node(n.id);
    positions[n.id] = { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 };
  });
  const gr = g.graph();
  return { positions, width: gr.width ?? 0, height: gr.height ?? 0 };
}

/** Nodes/edges that lie on some path from the root to `target` (reverse reachability within the loaded graph). */
export function ancestry(data: GraphData, target: string): { nodes: Set<string>; edges: Set<string> } {
  const incoming = new Map<string, typeof data.edges>();
  data.edges.forEach((e) => {
    const l = incoming.get(e.target) ?? [];
    l.push(e);
    incoming.set(e.target, l);
  });
  const nodes = new Set([target]);
  const edges = new Set<string>();
  const q = [target];
  while (q.length) {
    const n = q.pop()!;
    for (const e of incoming.get(n) ?? []) {
      edges.add(e.id);
      if (!nodes.has(e.source)) {
        nodes.add(e.source);
        q.push(e.source);
      }
    }
  }
  return { nodes, edges };
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** Standalone SVG built from the real graph data (not a screenshot of the UI). */
export function toSvg(data: GraphData, laid: Laid): string {
  const sevColor: Record<string, string> = { critical: "#ef4444", high: "#f59e0b", medium: "#e8b04a", low: "#64748b" };
  const edges = data.edges
    .map((e) => {
      const a = laid.positions[e.source];
      const b = laid.positions[e.target];
      if (!a || !b) return "";
      const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2;
      const mx = (x1 + x2) / 2;
      const dash = e.type === "dev" ? ' stroke-dasharray="6 4"' : e.type === "optional" ? ' stroke-dasharray="2 4"' : "";
      return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" stroke="#7c8aa0" stroke-width="1.5"${dash}/>`;
    })
    .join("");
  const nodes = data.nodes
    .map((n) => {
      const p = laid.positions[n.id];
      const stroke = n.severity ? sevColor[n.severity] ?? "#64748b" : n.kind === "application" ? "#4cc67f" : "#3e4656";
      return `<g><rect x="${p.x}" y="${p.y}" width="${NODE_W}" height="${NODE_H}" rx="14" fill="#1b1d21" stroke="${stroke}" stroke-width="2"/>` +
        `<text x="${p.x + 12}" y="${p.y + 24}" fill="#eef1f6" font-family="Inter,sans-serif" font-size="13" font-weight="600">${esc(n.label.slice(0, 26))}</text>` +
        `<text x="${p.x + 12}" y="${p.y + 43}" fill="#94a3b8" font-family="monospace" font-size="11">${esc(n.version ?? n.kind)}${n.findings ? ` · ${n.findings} advisory` : ""}</text></g>`;
    })
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.ceil(laid.width)}" height="${Math.ceil(laid.height)}" viewBox="0 0 ${Math.ceil(laid.width)} ${Math.ceil(laid.height)}"><rect width="100%" height="100%" fill="#121212"/>${edges}${nodes}</svg>`;
}
