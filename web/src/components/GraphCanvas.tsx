import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { useApp } from "../lib/store";
import type { GEdge, GNode, NodeLabel } from "../lib/types";

export const NODE_COLORS: Record<NodeLabel, string> = {
  CVE: "#fb7185",
  Product: "#5eead4",
  Vendor: "#818cf8",
  Weakness: "#fbbf24",
};
const RADIUS: Record<NodeLabel, number> = { CVE: 6, Product: 5, Vendor: 8, Weakness: 4.5 };

interface Props {
  nodes: GNode[];
  edges: GEdge[];
  height?: number | string;
  highlight?: Set<string>;
  selectedId?: string | null;
  onSelect?: (id: string | null) => void;
  labelsAlways?: boolean;
  fitOnLoad?: boolean;
}

/* react-force-graph mutates the node/link objects it is given, so it receives copies. */
export function GraphCanvas({ nodes, edges, height = "100%", highlight, selectedId, onSelect, labelsAlways, fitOnLoad = true }: Props) {
  const { settings } = useApp();
  const dark = settings.theme === "dark";
  const wrap = useRef<HTMLDivElement>(null);
  const fg = useRef<any>(null);
  const [size, setSize] = useState({ w: 600, h: 400 });
  const [hover, setHover] = useState<string | null>(null);

  const data = useMemo(() => ({
    nodes: nodes.map((n) => ({ ...n })),
    links: edges.map((e) => ({ ...e })),
  }), [nodes, edges]);

  const neighbors = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const e of edges) {
      (m.get(e.source) ?? m.set(e.source, new Set()).get(e.source)!).add(e.target);
      (m.get(e.target) ?? m.set(e.target, new Set()).get(e.target)!).add(e.source);
    }
    return m;
  }, [edges]);

  useEffect(() => {
    if (!wrap.current) return;
    const ro = new ResizeObserver(([entry]) => {
      const { width, height: h } = entry.contentRect;
      setSize({ w: Math.max(200, width), h: Math.max(200, h) });
    });
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const f = fg.current;
    if (!f) return;
    f.d3Force("charge")?.strength(-90);
    f.d3Force("link")?.distance((l: any) => (l.type === "CHAINED_WITH" ? 70 : 38));
  }, [data]);

  const focus = hover ?? selectedId ?? null;
  const dim = (id: string) =>
    (focus && id !== focus && !neighbors.get(focus)?.has(id)) || (highlight && highlight.size > 0 && !highlight.has(id) && !focus);

  const text = dark ? "226,232,245" : "30,41,59";
  const edgeBase = dark ? "148,163,184" : "100,116,139";

  return (
    <div ref={wrap} className="relative h-full w-full overflow-hidden" style={{ height }}>
      <ForceGraph2D
        ref={fg}
        graphData={data}
        width={size.w}
        height={size.h}
        backgroundColor="rgba(0,0,0,0)"
        cooldownTicks={140}
        onEngineStop={() => fitOnLoad && fg.current?.zoomToFit(500, 40)}
        nodeRelSize={5}
        enableNodeDrag
        onNodeHover={(n: any) => setHover(n ? n.id : null)}
        onNodeClick={(n: any) => onSelect?.(n.id === selectedId ? null : n.id)}
        onBackgroundClick={() => onSelect?.(null)}
        linkColor={(l: any) => {
          const a = typeof l.source === "object" ? l.source.id : l.source;
          const b = typeof l.target === "object" ? l.target.id : l.target;
          const off = dim(a) && dim(b);
          if (l.type === "CHAINED_WITH") return off ? "rgba(251,113,133,.12)" : "rgba(251,113,133,.9)";
          return `rgba(${edgeBase},${off ? 0.07 : focus ? 0.45 : 0.22})`;
        }}
        linkWidth={(l: any) => (l.type === "CHAINED_WITH" ? 2 : 1)}
        linkDirectionalParticles={(l: any) => (l.type === "CHAINED_WITH" ? 3 : 0)}
        linkDirectionalParticleWidth={2.4}
        linkDirectionalParticleSpeed={0.008}
        nodePointerAreaPaint={(n: any, color, ctx) => {
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(n.x, n.y, RADIUS[n.label as NodeLabel] + 3, 0, 2 * Math.PI);
          ctx.fill();
        }}
        nodeCanvasObject={(n: any, ctx, scale) => {
          const r = RADIUS[n.label as NodeLabel];
          const color = NODE_COLORS[n.label as NodeLabel];
          const off = dim(n.id);
          const active = n.id === focus || n.id === selectedId || highlight?.has(n.id);
          ctx.globalAlpha = off ? 0.18 : n.in_corpus === false ? 0.55 : 1;
          if (active) {
            const g = ctx.createRadialGradient(n.x, n.y, r, n.x, n.y, r * 3.4);
            g.addColorStop(0, color + "88");
            g.addColorStop(1, color + "00");
            ctx.fillStyle = g;
            ctx.beginPath();
            ctx.arc(n.x, n.y, r * 3.4, 0, 2 * Math.PI);
            ctx.fill();
          }
          ctx.beginPath();
          ctx.arc(n.x, n.y, r, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
          if (n.in_corpus === false) {
            ctx.setLineDash([2, 2]);
            ctx.strokeStyle = `rgb(${text})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
            ctx.setLineDash([]);
          }
          const showLabel = active || labelsAlways || scale > 2.2 || (n.label === "Vendor" && scale > 1.1);
          if (showLabel && !off) {
            const fs = Math.max(3.2, 11 / scale);
            ctx.font = `${n.label === "CVE" ? 500 : 400} ${fs}px ${n.label === "CVE" ? "JetBrains Mono" : "Inter"}, sans-serif`;
            ctx.textAlign = "center";
            ctx.textBaseline = "top";
            ctx.fillStyle = `rgba(${text},${active ? 1 : 0.8})`;
            ctx.fillText(n.name, n.x, n.y + r + 2);
          }
          ctx.globalAlpha = 1;
        }}
      />
    </div>
  );
}
