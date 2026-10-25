import { describe, expect, it } from "vitest";
import type { GraphData } from "../api/types";
import { ancestry, layout, toSvg } from "../graph/layout";

const node = (id: string, extra: Partial<GraphData["nodes"][number]> = {}) => ({ id, label: id, version: "1", ecosystem: "npm", kind: "package", depth: 1, scopes: ["runtime"], direct: false, source: null, state: "evaluated", severity: null, findings: 0, ...extra });
const edge = (s: string, t: string) => ({ id: `${s}->${t}`, source: s, target: t, type: "runtime", constraint: null, confidence: "declared", provenance: null });

const data: GraphData = {
  mode: "full", truncated: false, note: null, total_nodes: 5, analysis: {},
  nodes: [node("root", { kind: "application" }), node("a"), node("b"), node("v", { severity: "high", findings: 1 }), node("x<script>")],
  edges: [edge("root", "a"), edge("root", "b"), edge("a", "v"), edge("b", "v"), edge("root", "x<script>")],
};

describe("graph helpers", () => {
  it("highlights both parents of a shared vulnerable package", () => {
    const { nodes, edges } = ancestry(data, "v");
    expect([...nodes].sort()).toEqual(["a", "b", "root", "v"]);
    expect(edges.size).toBe(4);
    expect(nodes.has("x<script>")).toBe(false);
  });
  it("lays out every node left-to-right", () => {
    const l = layout(data);
    expect(Object.keys(l.positions)).toHaveLength(5);
    expect(l.positions["root"].x).toBeLessThan(l.positions["v"].x);
  });
  it("escapes labels in exported SVG", () => {
    const svg = toSvg(data, layout(data));
    expect(svg).not.toContain("<script>");
    expect(svg).toContain("&lt;script&gt;");
  });
});
