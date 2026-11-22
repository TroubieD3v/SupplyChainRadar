import { Background, BackgroundVariant, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, ReactFlowProvider, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { Download, Search } from "lucide-react";
import { memo, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { get, saveBlob } from "../api/client";
import type { GraphData } from "../api/types";
import { useFetch } from "../app/state";
import { NODE_H, NODE_W, ancestry, layout, toSvg } from "../graph/layout";
import { RequireScan } from "../components/RequireScan";
import { Button, Card, Chip, ErrorBox, Input, Label, Note, PageHeader, Segmented, SEV_COLOR, SeverityChip, Spinner, cx } from "../components/ui";

type Mode = "vulnerable" | "full" | "focus";

const GNode = memo(function GNode({ data, selected }: NodeProps) {
  const d = data as any;
  const app = d.kind === "application";
  const sev = d.severity as keyof typeof SEV_COLOR | null;
  return (
    <div
      style={{ width: NODE_W, height: NODE_H, borderColor: sev ? SEV_COLOR[sev] : undefined, opacity: d.dim ? 0.28 : 1 }}
      className={cx("flex flex-col justify-center rounded-[3px] border-[1.5px] px-2.5 text-left transition", app ? "border-primary bg-primary text-on-primary" : "border-outline bg-surface text-ink", selected && "outline outline-1 outline-offset-2 outline-accent", d.match && "outline outline-1 outline-offset-2 outline-warn")}
    >
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-muted" />
      <div className="truncate text-[12.5px] font-medium leading-tight">{d.label}</div>
      <div className={cx("flex items-center gap-1.5 truncate font-mono text-[11px]", app ? "opacity-70" : "text-muted")}>
        {d.version ?? d.kind}
        {d.findings > 0 && <span className="rounded-[2px] px-1 font-sans text-[10px] font-medium text-bg" style={{ background: SEV_COLOR[sev ?? "unknown"] }}>{d.findings}</span>}
        {d.state && !["evaluated", "cached"].includes(d.state) && d.kind !== "application" && <span title={`advisory state: ${d.state}`} className="font-sans text-[10px] text-warn">?</span>}
      </div>
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-muted" />
    </div>
  );
});
const nodeTypes = { pkg: GNode };

export default function GraphPage() {
  return <RequireScan>{(scan) => <ReactFlowProvider><Body scanId={scan.id} /></ReactFlowProvider>}</RequireScan>;
}

function Body({ scanId }: { scanId: string }) {
  const [mode, setMode] = useState<Mode>("vulnerable");
  const [focus, setFocus] = useState<string>("");
  const [selNode, setSelNode] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [hideDev, setHideDev] = useState(false);
  const { data, error, loading, reload } = useFetch<GraphData>(
    mode === "focus" && !focus ? null : () => get(`/scans/${scanId}/graph`, { mode, focus: mode === "focus" ? focus : undefined }),
    [scanId, mode, focus],
  );

  const view = useMemo(() => {
    if (!data) return null;
    if (!hideDev) return data;
    const keepEdges = data.edges.filter((e) => e.type !== "dev");
    const reach = new Set(["root"]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const e of keepEdges) {
        if (reach.has(e.source) && !reach.has(e.target)) {
          reach.add(e.target);
          grew = true;
        }
      }
    }
    return { ...data, nodes: data.nodes.filter((n) => reach.has(n.id)), edges: keepEdges.filter((e) => reach.has(e.source) && reach.has(e.target)) };
  }, [data, hideDev]);

  const laid = useMemo(() => (view ? layout(view) : null), [view]);
  const anc = useMemo(() => (view && selNode ? ancestry(view, selNode) : null), [view, selNode]);
  const q = query.trim().toLowerCase();

  const nodes: Node[] = useMemo(
    () =>
      view && laid
        ? view.nodes.map((n) => ({
            id: n.id,
            type: "pkg",
            position: laid.positions[n.id],
            selected: n.id === selNode,
            data: { ...n, dim: anc ? !anc.nodes.has(n.id) : false, match: q.length > 1 && n.label.toLowerCase().includes(q) },
          }))
        : [],
    [view, laid, selNode, anc, q],
  );
  const dark = document.documentElement.classList.contains("dark");
  const ON = dark ? "#8fb4d8" : "#2c5d8a";
  const OFF = dark ? "#5d636b" : "#9aa2ab";
  const INF = dark ? "#d0a866" : "#87601a";
  const edges: Edge[] = useMemo(
    () =>
      view
        ? view.edges.map((e) => {
            const on = anc?.edges.has(e.id);
            const inferred = e.confidence === "inferred";
            return {
              id: e.id,
              source: e.source,
              target: e.target,
              selected: e.id === selEdge,
              animated: Boolean(on),
              markerEnd: { type: MarkerType.ArrowClosed, width: 13, height: 13, color: on ? ON : OFF },
              style: {
                stroke: on ? ON : inferred ? INF : OFF,
                strokeWidth: on ? 2 : 1.2,
                opacity: anc && !on ? 0.12 : 1,
                strokeDasharray: e.type === "dev" ? "6 4" : e.type === "optional" ? "2 4" : inferred ? "3 3" : undefined,
              },
            };
          })
        : [],
    [view, anc, selEdge, ON, OFF, INF],
  );

  useEffect(() => {
    setSelNode(null);
    setSelEdge(null);
  }, [mode, focus, scanId]);

  const node = view?.nodes.find((n) => n.id === selNode);
  const edge = view?.edges.find((e) => e.id === selEdge);
  const matches = q.length > 1 ? view?.nodes.filter((n) => n.label.toLowerCase().includes(q)) ?? [] : [];
  const nameOf = (id: string) => view?.nodes.find((n) => n.id === id)?.label ?? id;

  return (
    <>
      <PageHeader eyebrow={<Chip tone="info">Edges come from your files</Chip>} title="Dependency Graph">
        Follow how a package reached your project. Select a node to highlight every path from the application to it; select an edge to see the exact lockfile entry that declared it.
      </PageHeader>

      <Card className="mb-3 !px-3 !py-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <Segmented label="Graph mode" value={mode} onChange={setMode} options={[{ id: "vulnerable", label: "Vulnerable paths" }, { id: "full", label: "Full graph" }, { id: "focus", label: "Focus" }]} />
          <div className="relative min-w-[200px] flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-dim" aria-hidden />
            <Input aria-label="Find a package in the graph" className="!pl-6" placeholder="Find package…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <label className="flex items-center gap-2 text-[12.5px] text-muted"><input type="checkbox" checked={hideDev} onChange={(e) => setHideDev(e.target.checked)} className="accent-[rgb(var(--accent))]" /> Hide dev-only</label>
          <div className="ml-auto flex gap-2">
            <Button size="sm" variant="outline" disabled={!view} onClick={() => view && saveBlob(new Blob([JSON.stringify(view, null, 2)], { type: "application/json" }), `graph-${scanId.slice(0, 8)}.json`)}><Download className="h-3.5 w-3.5" /> JSON</Button>
            <Button size="sm" variant="outline" disabled={!view || !laid} onClick={() => view && laid && saveBlob(new Blob([toSvg(view, laid)], { type: "image/svg+xml" }), `graph-${scanId.slice(0, 8)}.svg`)}><Download className="h-3.5 w-3.5" /> SVG</Button>
          </div>
        </div>
        {matches.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1 text-xs">
            {matches.slice(0, 8).map((m) => <button key={m.id} onClick={() => setSelNode(m.id)} className="rounded-[3px] border border-warn/40 bg-warn-soft px-2 py-0.5 font-medium text-warn">{m.label}{m.version ? `@${m.version}` : ""}</button>)}
          </div>
        )}
      </Card>

      {mode === "focus" && !focus && <Note tone="info">Select a node in another mode and press “Focus on this package”, or pick one here.<div className="mt-2 text-xs">Tip: focus shows all paths into the package and its direct dependencies.</div></Note>}
      {error && <ErrorBox error={error} onRetry={reload} />}
      {loading && !data && <Spinner label="Laying out graph" />}
      {view?.note && <p className="mb-3 text-[12.5px] text-muted">{view.note}</p>}

      {view && (
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="h-[620px] overflow-hidden rounded-[3px] border border-outline bg-surface-low" role="application" aria-label={`Dependency graph with ${view.nodes.length} nodes`}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={nodeTypes}
              onNodeClick={(_, n) => (setSelNode(n.id), setSelEdge(null))}
              onEdgeClick={(_, e) => (setSelEdge(e.id), setSelNode(null))}
              onPaneClick={() => (setSelNode(null), setSelEdge(null))}
              fitView
              minZoom={0.05}
              maxZoom={1.6}
              onlyRenderVisibleElements
              nodesDraggable={false}
              nodesConnectable={false}
              colorMode={document.documentElement.classList.contains("dark") ? "dark" : "light"}
              proOptions={{ hideAttribution: true }}
            >
              <Background variant={BackgroundVariant.Dots} gap={20} size={1} color={dark ? "#33373e" : "#cdd3d9"} />
              <Controls showInteractive={false} />
              <MiniMap pannable zoomable style={{ width: 150, height: 100, background: dark ? "#1f2226" : "#f8f9fa", border: `1px solid ${dark ? "#2f333a" : "#cdd3d9"}`, borderRadius: 3 }} maskColor={dark ? "rgba(20,22,25,.55)" : "rgba(226,229,232,.55)"} nodeColor={(n) => ((n.data as any).severity ? SEV_COLOR[(n.data as any).severity as keyof typeof SEV_COLOR] : OFF)} />
            </ReactFlow>
          </div>

          <aside className="space-y-3" aria-live="polite">
            <Card tone="low">
              <Label>Legend</Label>
              <ul className="mt-2 space-y-1.5 text-xs text-muted">
                <li className="flex items-center gap-2"><span className="h-3 w-5 rounded-[2px] border-[1.5px]" style={{ borderColor: SEV_COLOR.critical }} /> border colour = highest advisory severity</li>
                <li className="flex items-center gap-2"><span className="w-5 border-t-2 border-dashed border-muted" /> dev dependency · <span className="w-5 border-t-2 border-dotted border-muted" /> optional</li>
                <li className="flex items-center gap-2"><span className="w-5 border-t-2 border-dashed border-warn" /> inferred (not declared) relation</li>
                <li><span className="font-semibold text-warn">?</span> advisory state unknown for that package</li>
              </ul>
              <p className="mt-2 text-xs text-dim">{view.nodes.length} of {view.total_nodes} nodes shown · {view.analysis.has_cycles ? "cycles present (handled)" : "no cycles"} · max depth {String(view.analysis.max_depth)}</p>
            </Card>

            {node && (
              <Card>
                <div className="flex items-start justify-between gap-2"><h3 className="text-[13px] font-semibold">{node.label}</h3>{node.severity && <SeverityChip level={node.severity} />}</div>
                <p className="font-mono text-xs text-muted">{node.version ?? node.kind} · {node.ecosystem}</p>
                <div className="mt-3 flex flex-wrap gap-1.5"><Chip tone="info">{node.scopes[0] ?? "—"}</Chip><Chip>{node.direct ? "direct" : `depth ${node.depth ?? "?"}`}</Chip>{node.findings > 0 && <Chip tone="warn">{node.findings} advisor{node.findings > 1 ? "ies" : "y"}</Chip>}</div>
                {anc && <p className="mt-3 text-xs text-muted">Highlighted: {anc.nodes.size - 1} package(s) on paths to this node.</p>}
                <div className="mt-4 flex flex-wrap gap-2">
                  {node.kind !== "application" && <Button size="sm" variant="soft" onClick={() => (setFocus(node.id), setMode("focus"))}>Focus on this package</Button>}
                  {node.findings > 0 && <Link to={`/findings?q=${encodeURIComponent(node.label)}`}><Button size="sm" variant="outline">View findings</Button></Link>}
                  {node.kind !== "application" && <Link to={`/dependencies?q=${encodeURIComponent(node.label)}&open=${encodeURIComponent(node.id)}`}><Button size="sm" variant="outline">Package detail</Button></Link>}
                </div>
              </Card>
            )}
            {edge && (
              <Card>
                <Label>Relation</Label>
                <p className="mt-2 text-[12.5px]"><span className="font-semibold">{nameOf(edge.source)}</span> → <span className="font-semibold">{nameOf(edge.target)}</span></p>
                <dl className="mt-3 grid grid-cols-[100px_1fr] gap-y-1.5 text-xs">
                  <dt className="text-muted">Type</dt><dd>{edge.type}</dd>
                  <dt className="text-muted">Constraint</dt><dd className="font-mono">{edge.constraint ?? "—"}</dd>
                  <dt className="text-muted">Confidence</dt><dd>{edge.confidence === "declared" ? "declared in the imported file" : "inferred by the importer"}</dd>
                  <dt className="text-muted">Supplied by</dt><dd className="break-all font-mono">{edge.provenance ? `${edge.provenance.file}${edge.provenance.line ? ":" + edge.provenance.line : ""} ${edge.provenance.detail ?? ""}` : "—"}</dd>
                </dl>
              </Card>
            )}
            {!node && !edge && <p className="px-1 text-[12.5px] text-muted">Select a node or an edge for details. Use the search box to locate a package.</p>}
          </aside>
        </div>
      )}
    </>
  );
}
