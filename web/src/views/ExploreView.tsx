import { AnimatePresence, motion } from "framer-motion";
import { RefreshCw, Search, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { GraphCanvas, NODE_COLORS } from "../components/GraphCanvas";
import { CveChip, SectionTitle, cn } from "../components/ui";
import { useApp } from "../lib/store";
import type { NodeLabel } from "../lib/types";

const LABELS = Object.keys(NODE_COLORS) as NodeLabel[];

export function ExploreView() {
  const { graph, reloadGraph, settings, update, focusNode } = useApp();
  const [active, setActive] = useState<Set<NodeLabel>>(new Set(LABELS));
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(focusNode);
  useEffect(() => { if (focusNode) setSelected(focusNode); }, [focusNode]);

  const data = graph.data;
  const view = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };
    const nodes = data.nodes.filter((n) => active.has(n.label));
    const ids = new Set(nodes.map((n) => n.id));
    return { nodes, edges: data.edges.filter((e) => ids.has(e.source) && ids.has(e.target)) };
  }, [data, active]);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? new Set(view.nodes.filter((n) => n.name.toLowerCase().includes(q)).map((n) => n.id)) : undefined;
  }, [query, view.nodes]);

  const node = data?.nodes.find((n) => n.id === selected) ?? null;
  const related = useMemo(() => {
    if (!data || !node) return [];
    const byId = new Map(data.nodes.map((n) => [n.id, n]));
    return data.edges
      .filter((e) => e.source === node.id || e.target === node.id)
      .map((e) => ({ type: e.type, out: e.source === node.id, other: byId.get(e.source === node.id ? e.target : e.source)! }))
      .filter((r) => r.other);
  }, [data, node]);

  const toggle = (l: NodeLabel) => setActive((s) => { const n = new Set(s); n.has(l) ? n.delete(l) : n.add(l); return n; });
  const counts = (l: NodeLabel) => data?.nodes.filter((n) => n.label === l).length ?? 0;

  return (
    <div className="flex h-full flex-col px-4 pb-24 pt-8 sm:px-8 md:pb-6">
      <SectionTitle eyebrow="Knowledge graph" title="Explore the graph">
        <button className="btn" onClick={() => void reloadGraph()}><RefreshCw size={14} className={cn(graph.loading && "animate-spin")} />Refresh</button>
      </SectionTitle>

      <div className="card relative flex min-h-[460px] flex-1 overflow-hidden">
        <div className="absolute left-4 top-4 z-10 w-[min(300px,calc(100%-2rem))] space-y-3">
          <div className="relative">
            <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input className="input !bg-surface/85 !pl-9 backdrop-blur" placeholder="Search nodes…" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search nodes" />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {LABELS.map((l) => (
              <button key={l} onClick={() => toggle(l)} aria-pressed={active.has(l)}
                className={cn("chip !font-sans gap-2 backdrop-blur", active.has(l) ? "border-line bg-surface/85 text-ink" : "border-line/50 bg-surface/40 text-muted line-through")}>
                <i className="h-2 w-2 rounded-full" style={{ background: NODE_COLORS[l] }} />{l}<span className="text-muted">{counts(l)}</span>
              </button>
            ))}
          </div>
        </div>

        {graph.loading && !data && <div className="m-auto text-sm text-muted">Loading graph…</div>}
        {graph.error && (
          <div className="m-auto max-w-sm space-y-3 p-6 text-center">
            <p className="text-sm text-muted">{graph.error}</p>
            <button className="btn" onClick={() => update({ source: "demo" })}>Use demo data</button>
          </div>
        )}
        {data && data.nodes.length === 0 && (
          <div className="m-auto max-w-sm space-y-3 p-6 text-center">
            <p className="font-semibold">The graph is empty</p>
            <p className="text-sm text-muted">Neo4j is reachable but holds no nodes. Run the pipeline (<code className="font-mono">06_load_neo4j.py</code>) or explore demo data.</p>
            {settings.source !== "demo" && <button className="btn" onClick={() => update({ source: "demo" })}>Use demo data</button>}
          </div>
        )}
        {data && data.nodes.length > 0 && (
          <GraphCanvas nodes={view.nodes} edges={view.edges} highlight={matches} selectedId={selected} onSelect={setSelected} />
        )}

        <div className="pointer-events-none absolute bottom-4 left-4 hidden gap-4 text-[11px] text-muted sm:flex">
          <span>Drag to move · scroll to zoom · click a node</span>
          <span className="flex items-center gap-1.5"><i className="h-0.5 w-4 rounded bg-[#fb7185]" />exploit chain</span>
        </div>

        <AnimatePresence>
          {node && (
            <motion.aside key={node.id} initial={{ x: 40, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 40, opacity: 0 }}
              transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
              className="absolute inset-y-3 right-3 z-10 flex w-[min(340px,calc(100%-1.5rem))] flex-col overflow-hidden rounded-2xl border border-line bg-surface/90 shadow-card backdrop-blur-xl">
              <div className="flex items-start justify-between gap-3 border-b border-line p-4">
                <div>
                  <span className="chip !font-sans border-line" style={{ color: NODE_COLORS[node.label] }}><i className="h-2 w-2 rounded-full" style={{ background: NODE_COLORS[node.label] }} />{node.label}</span>
                  <h3 className="mt-2 break-words font-semibold leading-snug">{node.name}</h3>
                </div>
                <button className="btn !p-1.5" onClick={() => setSelected(null)} aria-label="Close"><X size={15} /></button>
              </div>
              <div className="flex-1 space-y-5 overflow-y-auto p-4 text-sm">
                {node.label === "CVE" && (
                  <>
                    <div className="flex flex-wrap gap-2">
                      {node.date_added && <span className="chip border-line text-muted">added {node.date_added}</span>}
                      {node.ransomware && <span className={cn("chip border-line", node.ransomware === "Known" ? "text-bad" : "text-muted")}>ransomware: {node.ransomware}</span>}
                      {!node.in_corpus && <span className="chip border-line text-muted">outside corpus</span>}
                    </div>
                    {node.text && <p className="leading-relaxed text-muted">{node.text}</p>}
                    <CveChip id={node.name} />
                  </>
                )}
                <div>
                  <div className="label mb-2">Connections · {related.length}</div>
                  <ul className="space-y-1.5">
                    {related.map((r, i) => (
                      <li key={i}>
                        <button onClick={() => setSelected(r.other.id)} className="flex w-full items-center gap-2.5 rounded-lg border border-line bg-elevated/40 px-3 py-2 text-left transition hover:border-accent/50">
                          <i className="h-2 w-2 shrink-0 rounded-full" style={{ background: NODE_COLORS[r.other.label] }} />
                          <span className="min-w-0 flex-1 truncate">{r.other.name}</span>
                          <span className="font-mono text-[10px] text-muted">{r.out ? "" : "← "}{r.type}{r.out ? " →" : ""}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </motion.aside>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
