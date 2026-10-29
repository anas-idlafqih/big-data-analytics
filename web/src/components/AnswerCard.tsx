import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, ChevronDown, Clock, Database, Network, RefreshCw, Route, ShieldAlert, Sparkles, Terminal, Timer, Waypoints } from "lucide-react";
import { Fragment, useEffect, useMemo, useState, type ReactNode } from "react";
import { CVE_RE } from "../lib/api";
import { useApp } from "../lib/store";
import type { AskResult, GraphData, Outcome, ReqMode } from "../lib/types";
import { GraphCanvas, NODE_COLORS } from "./GraphCanvas";
import { CopyButton, CountUp, CveChip, Stat, cn } from "./ui";

type Meta = { title: string; tag: string; icon: typeof Network; tone: string };
const META: Record<string, Meta> = {
  auto: { title: "Auto-routed", tag: "Router picks the engine", icon: Route, tone: "text-accent" },
  graph: { title: "GraphRAG", tag: "Graph-grounded", icon: Network, tone: "text-accent" },
  vector: { title: "Vector RAG", tag: "Baseline", icon: Waypoints, tone: "text-accent2" },
  cypher: { title: "Cypher query", tag: "Exact · no LLM", icon: Terminal, tone: "text-warn" },
};

const STEPS: Record<ReqMode, string[]> = {
  auto: ["Routing the question", "Retrieving from the graph", "Generating the answer"],
  graph: ["Retrieving from the graph", "Generating the answer"],
  vector: ["Vector search for the closest CVE texts", "Generating the answer"],
};

/** The CVEs in the retrieved context plus everything one hop away. */
export function evidenceGraph(g: GraphData | null, cves: string[]): GraphData {
  if (!g || !cves.length) return { nodes: [], edges: [] };
  const seeds = new Set(cves.map((c) => `CVE:${c}`));
  const keep = new Set(seeds);
  for (const e of g.edges) {
    if (seeds.has(e.source)) keep.add(e.target);
    if (seeds.has(e.target)) keep.add(e.source);
  }
  for (const e of g.edges) if (e.type === "PRODUCES" && keep.has(e.target)) keep.add(e.source);
  return {
    nodes: g.nodes.filter((n) => keep.has(n.id)),
    edges: g.edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
  };
}

/** Turns CVE ids inside the answer into links that open the graph on that node. */
function Linked({ text, onOpen }: { text: string; onOpen: (id: string) => void }) {
  const parts: ReactNode[] = [];
  let last = 0;
  for (const m of text.matchAll(new RegExp(CVE_RE.source, "gi"))) {
    parts.push(text.slice(last, m.index));
    const id = m[0].toUpperCase();
    parts.push(<button key={m.index} className="font-mono text-[0.92em] text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent" onClick={() => onOpen(id)}>{id}</button>);
    last = (m.index ?? 0) + m[0].length;
  }
  parts.push(text.slice(last));
  return <>{parts.map((p, i) => <Fragment key={i}>{p}</Fragment>)}</>;
}

function Loader({ mode, outcome }: { mode: ReqMode; outcome: Extract<Outcome, { state: "loading" }> }) {
  const steps = STEPS[mode];
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(t);
  }, []);
  // Stages come from real server events: route -> retrieval -> first token.
  const stage = outcome.text ? steps.length - 1 : outcome.context_cves ? steps.length - 1 : mode === "auto" && outcome.route ? 1 : 0;
  const elapsed = (now - outcome.startedAt) / 1000;
  return (
    <div className="space-y-5">
      {outcome.route && (
        <div className="flex items-center gap-2 rounded-lg border border-line bg-elevated/40 px-3 py-2 text-xs">
          <Route size={13} className="text-accent" /><b>{outcome.route.label}</b><span className="text-muted">— {outcome.route.reason}</span>
        </div>
      )}
      <ol className="space-y-2.5">
        {steps.map((s, i) => (
          <li key={s} className={cn("flex items-center gap-3 text-sm transition-colors", i > stage ? "text-muted/50" : i === stage ? "text-ink" : "text-muted")}>
            <span className={cn("grid h-5 w-5 place-items-center rounded-full border text-[10px]",
              i < stage ? "border-good/50 bg-good/15 text-good" : i === stage ? "border-accent/60 text-accent" : "border-line")}>
              {i < stage ? "✓" : i === stage ? <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" /> : i + 1}
            </span>
            {s}{i === stage && <span className="text-muted">…</span>}
          </li>
        ))}
      </ol>
      {outcome.text ? (
        <div className="rounded-xl border border-accent/25 bg-accent/[.06] p-4 text-[15.5px] leading-relaxed caret">{outcome.text}</div>
      ) : (
        <div className="space-y-2.5">
          <div className="shimmer h-3.5 w-11/12 rounded-md" />
          <div className="shimmer h-3.5 w-8/12 rounded-md" />
        </div>
      )}
      <div className="font-mono text-xs tabular-nums text-muted">{elapsed.toFixed(1)} s{mode !== "auto" || outcome.route?.kind !== "aggregate" ? " — a local model on CPU: 10–60 s is normal" : ""}</div>
    </div>
  );
}

type Tab = "evidence" | "context" | "query";

function Proof({ data, sub, hover }: { data: AskResult; sub: GraphData; hover: Set<string> }) {
  const tabs = ([
    sub.nodes.length > 0 && ["evidence", "Evidence graph"],
    data.context && ["context", "Context sent to the model"],
    (data.cypher || data.route) && ["query", data.cypher ? "Query & route" : "Route"],
  ].filter(Boolean) as [Tab, string][]);
  const [tab, setTab] = useState<Tab>(tabs[0]?.[0] ?? "query");
  const cited = useMemo(() => new Set(data.sources.map((s) => `CVE:${s}`)), [data.sources]);
  const hi = hover.size ? hover : cited;
  if (!tabs.length) return <p className="text-sm text-muted">Nothing to show for this answer.</p>;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1 rounded-lg border border-line bg-elevated/40 p-0.5 text-[12.5px]">
        {tabs.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} className={cn("rounded-md px-3 py-1.5 font-medium transition", tab === id ? "bg-surface text-ink shadow-sm" : "text-muted hover:text-ink")}>{label}</button>
        ))}
      </div>
      {tab === "evidence" && (
        <>
          <div className="h-[280px] overflow-hidden rounded-xl border border-line bg-bg/40">
            <GraphCanvas nodes={sub.nodes} edges={sub.edges} highlight={hi} labelsAlways />
          </div>
          <div className="flex flex-wrap gap-4 text-xs text-muted">
            {(Object.keys(NODE_COLORS) as (keyof typeof NODE_COLORS)[]).map((k) => (
              <span key={k} className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-full" style={{ background: NODE_COLORS[k] }} />{k}</span>
            ))}
            <span>Glowing = cited as a source</span>
          </div>
        </>
      )}
      {tab === "context" && (
        <pre className="max-h-[300px] overflow-auto whitespace-pre-wrap rounded-xl border border-line bg-bg/50 p-4 font-mono text-[12px] leading-relaxed text-muted">{data.context}</pre>
      )}
      {tab === "query" && (
        <div className="space-y-3 text-sm">
          {data.route && <p><b>{data.route.label}.</b> <span className="text-muted">{data.route.reason}</span></p>}
          {data.cypher
            ? <pre className="overflow-auto rounded-xl border border-line bg-bg/50 p-4 font-mono text-[12px] leading-relaxed">{data.cypher}</pre>
            : <p className="text-muted">No Cypher ran for this answer: the model answered from the retrieved context.</p>}
        </div>
      )}
    </div>
  );
}

function Body({ data, turnId, mode }: { data: AskResult; turnId: number; mode: ReqMode }) {
  const { graph, openNode } = useApp();
  const [open, setOpen] = useState(false);
  const [hover, setHover] = useState<Set<string>>(new Set());
  const sub = useMemo(() => evidenceGraph(graph.data, data.context_cves), [graph.data, data.context_cves]);
  const ransom = useMemo(() => new Set((graph.data?.nodes ?? []).filter((n) => n.ransomware === "Known").map((n) => n.name)), [graph.data]);
  const total = data.retrieval_s + data.generation_s;
  const noLlm = data.mode === "cypher";
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        {data.route && <span className="chip !font-sans border-line text-muted" title={data.route.reason}><Route size={12} className="text-accent" />{data.route.label}</span>}
        {noLlm && <span className="chip !font-sans border-warn/40 bg-warn/10 text-warn">Computed by Cypher · no LLM guessing</span>}
        {data.cached && <span className="chip !font-sans border-line text-muted">cached</span>}
      </div>

      {!!data.ungrounded?.length && (
        <div className="flex gap-3 rounded-xl border border-warn/40 bg-warn/10 p-3.5 text-sm">
          <ShieldAlert size={18} className="mt-0.5 shrink-0 text-warn" />
          <span>The answer mentions <b className="font-mono">{data.ungrounded.join(", ")}</b>, which is not in the retrieved context. Treat that part as unverified.</span>
        </div>
      )}

      <div className="rounded-xl border border-accent/25 bg-accent/[.06] p-4 text-[15.5px] leading-relaxed">
        <Linked text={data.answer || "(empty answer)"} onOpen={openNode} />
      </div>

      <div>
        <div className="label mb-2">Sources cited <span className="normal-case tracking-normal text-muted/70">— limited to the retrieved context</span></div>
        <div className="flex flex-wrap gap-1.5">
          {data.sources.length
            ? data.sources.map((s) => (
              <span key={s} onMouseEnter={() => setHover(new Set([`CVE:${s}`]))} onMouseLeave={() => setHover(new Set())}>
                <CveChip id={s} tone="source" ransom={ransom.has(s)} onOpen={openNode} />
              </span>))
            : <span className="text-sm text-muted">{noLlm ? "This is a computed result; the query below is the proof." : "The model cited no source."}</span>}
        </div>
        {data.sources.some((s) => ransom.has(s)) && <p className="mt-2 flex items-center gap-1.5 text-xs text-muted"><i className="h-1.5 w-1.5 rounded-full bg-bad" />Red dot: used in ransomware campaigns</p>}
      </div>

      <div className="grid grid-cols-[repeat(auto-fit,minmax(118px,1fr))] gap-2.5">
        <Stat icon={<Database size={13} />} label={noLlm ? "Query" : "Retrieval"}>
          {noLlm ? <><CountUp value={Math.max(1, data.retrieval_s * 1000)} suffix=" ms" /></> : <CountUp value={data.retrieval_s} decimals={1} suffix=" s" />}
        </Stat>
        <Stat icon={<Sparkles size={13} />} label="Generation">{noLlm ? "none" : <CountUp value={data.generation_s} decimals={1} suffix=" s" />}</Stat>
        <Stat icon={<Timer size={13} />} label="Total">{noLlm ? <CountUp value={Math.max(1, total * 1000)} suffix=" ms" /> : <CountUp value={total} decimals={1} suffix=" s" />}</Stat>
        <Stat icon={<Network size={13} />} label="In context"><CountUp value={data.context_cves.length} /></Stat>
      </div>

      <div className="rounded-xl border border-line">
        <button className="flex w-full items-center justify-between px-4 py-3 text-sm font-medium" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
          <span className="flex items-center gap-2"><Network size={15} className="text-accent" />Why this answer
            <span className="font-mono text-xs text-muted">evidence · context · query</span></span>
          <ChevronDown size={16} className={cn("text-muted transition-transform", open && "rotate-180")} />
        </button>
        <AnimatePresence initial={false}>
          {open && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }} className="overflow-hidden" key={`ev-${turnId}-${mode}`}>
              <div className="space-y-4 border-t border-line p-4">
                <div className="flex flex-wrap gap-1.5">
                  {data.context_cves.map((c) => <CveChip key={c} id={c} tone={data.sources.includes(c) ? "source" : "neutral"} ransom={ransom.has(c)} onOpen={openNode} />)}
                </div>
                <Proof data={data} sub={sub} hover={hover} />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

export function AnswerCard({ mode, outcome, turnId }: { mode: ReqMode; outcome?: Outcome; turnId: number }) {
  const { retry } = useApp();
  const meta = outcome?.state === "done" ? META[outcome.data.mode] ?? META[mode] : META[mode];
  const Icon = meta.icon;
  return (
    <motion.section layout className="card h-full p-5 sm:p-6">
      <header className="mb-5 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className={cn("grid h-9 w-9 place-items-center rounded-xl border border-line bg-elevated/70", meta.tone)}><Icon size={18} /></span>
          <div>
            <div className="font-semibold leading-tight">{meta.title}</div>
            <div className="text-xs text-muted">{meta.tag}</div>
          </div>
        </div>
        {outcome?.state === "done" && <CopyButton text={outcome.data.answer} label="Copy" />}
        {outcome?.state === "loading" && <span className="flex items-center gap-1.5 text-xs text-muted"><Clock size={13} />running</span>}
      </header>

      {(!outcome || outcome.state === "loading") && <Loader mode={mode} outcome={outcome?.state === "loading" ? outcome : { state: "loading", startedAt: Date.now() }} />}
      {outcome?.state === "error" && (
        <div className="space-y-4">
          <div className="flex gap-3 rounded-xl border border-bad/40 bg-bad/10 p-4 text-sm">
            <AlertTriangle size={18} className="mt-0.5 shrink-0 text-bad" />
            <span>{outcome.message}</span>
          </div>
          <button className="btn" onClick={() => retry(turnId, mode)}><RefreshCw size={14} />Try again</button>
        </div>
      )}
      {outcome?.state === "done" && <Body data={outcome.data} turnId={turnId} mode={mode} />}
    </motion.section>
  );
}
