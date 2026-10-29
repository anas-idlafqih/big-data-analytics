import { AnimatePresence, motion } from "framer-motion";
import { BarChart3, Check, Link2, Share2, Target, Trash2, Zap } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { AnswerCard } from "../components/AnswerCard";
import { Composer, type ComposerHandle } from "../components/Composer";
import { CountUp, spotlight } from "../components/ui";
import { CVE_RE } from "../lib/api";
import { shareLink, useApp } from "../lib/store";
import type { Turn } from "../lib/types";

const EXAMPLES = [
  { icon: Target, title: "Factual · 1 hop", desc: "Which products does one CVE affect?", q: "Which products does CVE-2026-21589 affect?", route: "Exact lookup" },
  { icon: Link2, title: "Multi-hop · exploit chain", desc: "Follow CHAINED_WITH between CVEs.", q: "Which CVEs are chained with CVE-2026-105133?", route: "Exact lookup" },
  { icon: BarChart3, title: "Aggregation", desc: "Counts and rankings run as exact Cypher.", q: "Which products are affected by more than one CVE?", route: "Cypher · no LLM" },
];

const item = { hidden: { opacity: 0, y: 16 }, show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.22, 1, 0.36, 1] as const } } };

function Verdict({ turn }: { turn: Turn }) {
  const g = turn.outcomes.graph, v = turn.outcomes.vector;
  if (g?.state !== "done" || v?.state !== "done") return null;
  const ids = [...new Set((turn.question.match(CVE_RE) ?? []).map((s) => s.toUpperCase()))];
  const inG = ids.filter((i) => g.data.context_cves.includes(i));
  const inV = ids.filter((i) => v.data.context_cves.includes(i));
  const faster = v.data.retrieval_s + v.data.generation_s - (g.data.retrieval_s + g.data.generation_s);
  let msg = "Both answers are shown side by side — compare the cited sources.";
  let tone = "border-line bg-elevated/40";
  if (inG.length && !inV.length) {
    tone = "border-good/40 bg-good/10";
    msg = `GraphRAG resolved ${inG[0]} exactly and followed its links; vector search never retrieved it.`;
  } else if (inG.length && inV.length) msg = "Both modes retrieved the CVE named in the question — check whether the answers agree.";
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className={`mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-xl border px-4 py-3 text-sm ${tone}`}>
      <Zap size={16} className="text-accent" />
      <span className="flex-1">{msg}</span>
      <span className="font-mono text-xs text-muted">{faster > 0 ? `GraphRAG ${faster.toFixed(1)} s faster` : `Vector ${(-faster).toFixed(1)} s faster`}</span>
    </motion.div>
  );
}

function ShareButton({ turn }: { turn: Turn }) {
  const [ok, setOk] = useState(false);
  return (
    <button className="btn !py-1 text-xs" title="Copy a link that re-runs this question" onClick={() => {
      void navigator.clipboard?.writeText(shareLink(turn)); setOk(true); setTimeout(() => setOk(false), 1500);
    }}>{ok ? <Check size={13} className="text-good" /> : <Share2 size={13} />}{ok ? "Link copied" : "Share"}</button>
  );
}

function TurnView({ turn }: { turn: Turn }) {
  const single = turn.mode === "compare" ? null : turn.mode;
  return (
    <motion.article initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }} className="space-y-4">
      <div className="flex items-center justify-end gap-3">
        <ShareButton turn={turn} />
        <div className="max-w-[80%] rounded-2xl rounded-br-md border border-accent/25 bg-gradient-to-br from-accent/15 to-accent2/15 px-4 py-2.5 text-[15px]">{turn.question}</div>
      </div>
      {single ? (
        <AnswerCard mode={single} outcome={turn.outcomes[single]} turnId={turn.id} />
      ) : (
        <>
          <div className="grid gap-4 lg:grid-cols-2">
            <AnswerCard mode="graph" outcome={turn.outcomes.graph} turnId={turn.id} />
            <AnswerCard mode="vector" outcome={turn.outcomes.vector} turnId={turn.id} />
          </div>
          <Verdict turn={turn} />
        </>
      )}
    </motion.article>
  );
}

export function AskView() {
  const { turns, ask, stop, busy, clearTurns, graph, settings, healthState } = useApp();
  const composer = useRef<ComposerHandle>(null);
  const end = useRef<HTMLDivElement>(null);
  const counts = useMemo(() => {
    const n = graph.data?.nodes ?? [];
    const c = (l: string) => n.filter((x) => x.label === l).length;
    return [
      { label: "CVEs", v: c("CVE") }, { label: "Products", v: c("Product") },
      { label: "Vendors", v: c("Vendor") }, { label: "Relationships", v: graph.data?.edges.length ?? 0 },
    ];
  }, [graph.data]);

  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth", block: "end" }); }, [turns.length]);
  const empty = turns.length === 0;
  const live = settings.source === "live";
  const llmDown = live && healthState.health && !healthState.health.ollama;
  const emptyGraph = !graph.loading && graph.data && graph.data.nodes.length === 0;

  return (
    <div className="mx-auto flex min-h-full max-w-5xl flex-col px-4 pb-6 pt-8 sm:px-8">
      {empty ? (
        <motion.div variants={{ show: { transition: { staggerChildren: 0.08 } } }} initial="hidden" animate="show" className="flex flex-1 flex-col justify-center pb-10">
          <motion.div variants={item} className="mb-5 inline-flex w-fit items-center gap-2 rounded-full border border-line bg-elevated/50 px-3 py-1.5 text-xs text-muted">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" />Knowledge graph × local LLM{settings.source === "demo" && " · demo data"}
          </motion.div>
          <motion.h1 variants={item} className="text-4xl font-extrabold leading-[1.05] tracking-tight sm:text-6xl">
            Ask the <span className="text-gradient">vulnerability graph</span>.
          </motion.h1>
          <motion.p variants={item} className="mt-5 max-w-xl text-base leading-relaxed text-muted sm:text-lg">
            Lookups and exploit chains go through the graph; counts and rankings are computed as exact Cypher. Every answer shows its sources and the query or context behind it.
          </motion.p>
          {(emptyGraph || llmDown) && (
            <motion.div variants={item} className="mt-5 max-w-xl rounded-xl border border-warn/40 bg-warn/10 p-4 text-sm">
              {emptyGraph
                ? <>Neo4j is up but holds no data. Load the pipeline output (<code className="font-mono">06_load_neo4j.py</code>) or a sample with <code className="font-mono">python scripts/seed_demo_graph.py</code>.</>
                : <>Ollama is not running: lookups, chains and retrieval need it. Aggregations still work because they run as Cypher.</>}
            </motion.div>
          )}
          <motion.div variants={item} className="mt-8"><Composer ref={composer} busy={busy} onSubmit={ask} onStop={stop} /></motion.div>
          <motion.div variants={item} className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {counts.map((c) => (
              <div key={c.label} className="rounded-2xl border border-line bg-surface/60 px-4 py-3 backdrop-blur">
                <div className="font-mono text-2xl font-medium tabular-nums">{graph.loading ? "–" : <CountUp value={c.v} />}</div>
                <div className="label mt-0.5 !text-[10px]">{c.label}</div>
              </div>
            ))}
          </motion.div>
          <motion.div variants={item} className="mt-10"><div className="label mb-3">Try an example</div>
            <div className="grid gap-3 md:grid-cols-3">
              {EXAMPLES.map((e) => (
                <button key={e.title} onMouseMove={spotlight} onClick={() => composer.current?.setText(e.q)}
                  className="card spot group p-4 text-left transition hover:-translate-y-0.5 hover:border-accent/40">
                  <div className="flex items-center justify-between">
                    <span className="grid h-9 w-9 place-items-center rounded-xl border border-line bg-elevated/70 text-accent transition group-hover:scale-110"><e.icon size={17} /></span>
                    <span className="rounded-full border border-line px-2 py-0.5 text-[10px] text-muted">{e.route}</span>
                  </div>
                  <div className="mt-3 font-semibold">{e.title}</div>
                  <div className="mt-1 text-sm text-muted">{e.desc}</div>
                  <div className="mt-3 line-clamp-2 font-mono text-[12px] leading-snug text-muted/80">{e.q}</div>
                </button>
              ))}
            </div>
          </motion.div>
        </motion.div>
      ) : (
        <div className="flex-1 space-y-10 pb-6">
          <div className="flex justify-end">
            <button className="btn !py-1.5 text-xs" onClick={clearTurns}><Trash2 size={13} />Clear conversation</button>
          </div>
          <AnimatePresence initial={false}>
            {turns.map((t) => <TurnView key={t.id} turn={t} />)}
          </AnimatePresence>
          <div ref={end} />
        </div>
      )}
      {!empty && (
        <div className="sticky bottom-[60px] z-10 -mx-4 bg-gradient-to-t from-bg via-bg/90 to-transparent px-4 pb-2 pt-6 sm:-mx-8 sm:px-8 md:bottom-0">
          <Composer ref={composer} busy={busy} onSubmit={ask} onStop={stop} compact />
          <p className="mt-2 text-center text-[11px] text-muted">Answers come from a small local model and the extracted graph — verify critical findings against NVD.</p>
        </div>
      )}
    </div>
  );
}
