import { motion } from "framer-motion";
import { Info, Network, TrendingUp } from "lucide-react";
import { useState } from "react";
import { CountUp, SectionTitle, cn } from "../components/ui";
import { ARMS, BY_TYPE, METRICS, OVERALL, type Arm, type MetricId } from "../lib/benchmark";

function Bar({ value, color, delay, max = 100 }: { value: number; color: string; delay: number; max?: number }) {
  return (
    <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-elevated">
      <motion.div className="h-full rounded-full" style={{ background: color }} initial={{ width: 0 }}
        animate={{ width: `${(value / max) * 100}%` }} transition={{ duration: 0.9, delay, ease: [0.22, 1, 0.36, 1] }} />
    </div>
  );
}

export function BenchmarkView() {
  const [metric, setMetric] = useState<MetricId>("f1");
  const [hidden, setHidden] = useState<Set<Arm>>(new Set());
  const arms = ARMS.filter((a) => !hidden.has(a.id));
  const o = OVERALL;
  const gain = o.graph.f1 - o.vector.f1;

  const toggle = (a: Arm) => setHidden((s) => { const n = new Set(s); n.has(a) ? n.delete(a) : n.add(a); return n; });

  const kpis = [
    { label: "GraphRAG F1", value: o.graph.f1, suffix: "%", note: `vs ${o.vector.f1}% for vector RAG`, icon: Network, hot: true },
    { label: "F1 gain over vector", value: gain, suffix: " pts", note: "same model, same questions", icon: TrendingUp },
    { label: "Multi-hop F1", value: BY_TYPE[1].f1.graph, suffix: "%", note: `vector: ${BY_TYPE[1].f1.vector}%`, icon: Network },
    { label: "Median latency", value: o.graph.latency!, suffix: " s", decimals: 1, note: `vector: ${o.vector.latency} s`, icon: TrendingUp },
  ];

  return (
    <div className="mx-auto max-w-6xl px-4 pb-28 pt-8 sm:px-8 md:pb-10">
      <SectionTitle eyebrow="Evaluation" title="GraphRAG vs. the alternatives">
        <span className="text-sm text-muted">22 questions · 4 question types · 4 approaches</span>
      </SectionTitle>

      <motion.div variants={{ show: { transition: { staggerChildren: 0.07 } } }} initial="hidden" animate="show" className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {kpis.map((k) => (
          <motion.div key={k.label} variants={{ hidden: { opacity: 0, y: 14 }, show: { opacity: 1, y: 0 } }}
            className={cn("card p-4", k.hot && "border-accent/40 shadow-glow")}>
            <div className="flex items-center gap-2 text-muted"><k.icon size={14} /><span className="label !text-[10px]">{k.label}</span></div>
            <div className={cn("mt-2 font-mono text-3xl font-medium tabular-nums", k.hot && "text-gradient")}>
              <CountUp value={k.value} decimals={k.decimals ?? 0} suffix={k.suffix} />
            </div>
            <div className="mt-1 text-xs text-muted">{k.note}</div>
          </motion.div>
        ))}
      </motion.div>

      <div className="mt-8 flex flex-wrap items-center justify-between gap-3">
        <div role="tablist" className="flex rounded-xl border border-line bg-elevated/50 p-0.5">
          {METRICS.map((m) => (
            <button key={m.id} role="tab" aria-selected={metric === m.id} onClick={() => setMetric(m.id)}
              className={cn("relative rounded-[10px] px-3.5 py-1.5 text-[13px] font-medium transition-colors", metric === m.id ? "text-ink" : "text-muted hover:text-ink")}>
              {metric === m.id && <motion.span layoutId="metric-pill" className="absolute inset-0 rounded-[10px] border border-line bg-surface" transition={{ type: "spring", stiffness: 500, damping: 36 }} />}
              <span className="relative">{m.label}</span>
            </button>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          {ARMS.map((a) => (
            <button key={a.id} onClick={() => toggle(a.id)} title={a.hint} aria-pressed={!hidden.has(a.id)}
              className={cn("chip !font-sans gap-2", hidden.has(a.id) ? "border-line/50 text-muted line-through" : "border-line bg-surface/70 text-ink")}>
              <i className="h-2 w-2 rounded-full" style={{ background: a.color }} />{a.label}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        <section className="card p-5 lg:col-span-2">
          <h2 className="font-semibold">Overall · {METRICS.find((m) => m.id === metric)!.label}</h2>
          <p className="mb-5 text-xs text-muted">Macro average over 22 questions</p>
          <div className="space-y-4">
            {arms.map((a, i) => (
              <div key={a.id}>
                <div className="mb-1.5 flex justify-between text-sm"><span>{a.label}</span><span className="font-mono tabular-nums">{o[a.id][metric]}%</span></div>
                <Bar value={o[a.id][metric]} color={a.color} delay={i * 0.08} />
              </div>
            ))}
          </div>
        </section>

        <section className="card p-5 lg:col-span-3">
          <h2 className="font-semibold">F1 by question type</h2>
          <p className="mb-5 text-xs text-muted">Where each approach wins and fails</p>
          <div className="space-y-5">
            {BY_TYPE.map((t, ti) => (
              <div key={t.id}>
                <div className="mb-2 flex items-baseline justify-between text-sm">
                  <span className="font-medium">{t.label}</span><span className="font-mono text-xs text-muted">n={t.n}</span>
                </div>
                <div className="space-y-1.5">
                  {arms.map((a, i) => (
                    <div key={a.id} className="flex items-center gap-3">
                      <span className="w-[88px] shrink-0 truncate text-[11px] text-muted">{a.label}</span>
                      <Bar value={t.f1[a.id]} color={a.color} delay={0.1 + ti * 0.08 + i * 0.04} />
                      <span className="w-9 text-right font-mono text-[11px] tabular-nums">{t.f1[a.id]}%</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="card mt-4 overflow-x-auto">
        <table className="w-full min-w-[640px] text-sm">
          <thead>
            <tr className="border-b border-line text-left">
              {["Approach", "Precision", "Recall", "F1", "Exact", "Median", "p95", "Source prec."].map((h) => <th key={h} className="label px-4 py-3 !text-[10px]">{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {ARMS.map((a) => {
              const r = o[a.id];
              return (
                <tr key={a.id} className="border-b border-line/60 last:border-0 transition hover:bg-elevated/40">
                  <td className="px-4 py-3 font-medium"><span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ background: a.color }} />{a.label}</td>
                  {[r.precision, r.recall, r.f1, r.exact].map((v, i) => <td key={i} className="px-4 py-3 font-mono tabular-nums">{v}%</td>)}
                  <td className="px-4 py-3 font-mono tabular-nums">{r.latency! < 1 ? `${r.latency! * 1000} ms` : `${r.latency} s`}</td>
                  <td className="px-4 py-3 font-mono tabular-nums">{r.p95! < 1 ? `${r.p95! * 1000} ms` : `${r.p95} s`}</td>
                  <td className="px-4 py-3 font-mono tabular-nums">{r.sourcePrecision ? `${r.sourcePrecision}%` : "–"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div className="card p-5 text-sm leading-relaxed">
          <div className="mb-2 font-semibold">What this tells us</div>
          <ul className="list-disc space-y-1.5 pl-5 text-muted">
            <li>Graph retrieval is decisive on <b className="text-ink">lookups and multi-hop</b> questions (98% and 88% F1).</li>
            <li><b className="text-ink">Aggregation</b> (counts, “most”) fails for both RAG modes — generated Cypher or direct queries do better.</li>
            <li>GraphRAG cites sources more often (95% of answers) and more accurately (85%).</li>
          </ul>
        </div>
        <div className="card flex gap-3 p-5 text-sm leading-relaxed text-muted">
          <Info size={18} className="mt-0.5 shrink-0 text-warn" />
          <p>One run per question and approach on a CPU laptop, so differences are indicative rather than statistically established. Gold answers describe the graph built from LLM extraction, not the real world.</p>
        </div>
      </div>
    </div>
  );
}
