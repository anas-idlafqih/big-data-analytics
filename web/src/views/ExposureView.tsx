import { motion } from "framer-motion";
import { Flame, Link2, Package, ShieldAlert } from "lucide-react";
import { useMemo } from "react";
import { CountUp, SectionTitle, cn } from "../components/ui";
import { exposure } from "../lib/analytics";
import { useApp } from "../lib/store";

function HBar({ label, sub, value, max, color, i }: { label: string; sub?: string; value: number; max: number; color: string; i: number }) {
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-3 text-sm">
        <span className="min-w-0 truncate">{label}{sub && <span className="ml-2 text-xs text-muted">{sub}</span>}</span>
        <span className="font-mono tabular-nums text-muted">{value}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-elevated">
        <motion.div className="h-full rounded-full" style={{ background: color }} initial={{ width: 0 }}
          animate={{ width: `${(value / max) * 100}%` }} transition={{ duration: 0.8, delay: i * 0.05, ease: [0.22, 1, 0.36, 1] }} />
      </div>
    </div>
  );
}

export function ExposureView() {
  const { graph, openNode } = useApp();
  const x = useMemo(() => (graph.data && graph.data.nodes.length ? exposure(graph.data) : null), [graph.data]);

  if (!x) {
    return (
      <div className="mx-auto max-w-6xl px-4 pt-8 sm:px-8">
        <SectionTitle eyebrow="Exposure" title="What the corpus says" />
        <div className="card p-10 text-center text-sm text-muted">{graph.loading ? "Loading the graph…" : "The graph is empty — load data first."}</div>
      </div>
    );
  }
  const kpis = [
    { label: "CVEs in the corpus", v: x.cves, icon: ShieldAlert },
    { label: "Used in ransomware", v: x.ransomware, icon: Flame, hot: x.ransomware > 0 },
    { label: "In exploit chains", v: x.chained, icon: Link2 },
    { label: "Vendors affected", v: x.vendors, icon: Package },
  ];
  const maxV = Math.max(...x.topVendors.map((v) => v.cves), 1);
  const maxW = Math.max(...x.weaknesses.map((w) => w.n), 1);
  const maxT = Math.max(...x.timeline.map((t) => t.n), 1);

  return (
    <div className="mx-auto max-w-6xl px-4 pb-28 pt-8 sm:px-8 md:pb-10">
      <SectionTitle eyebrow="Exposure" title="What the corpus says" />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {kpis.map((k, i) => (
          <motion.div key={k.label} initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}
            className={cn("card p-4", k.hot && "border-bad/40")}>
            <div className="flex items-center gap-2 text-muted"><k.icon size={14} className={k.hot ? "text-bad" : undefined} /><span className="label !text-[10px]">{k.label}</span></div>
            <div className="mt-2 font-mono text-3xl font-medium tabular-nums"><CountUp value={k.v} /></div>
          </motion.div>
        ))}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <section className="card p-5">
          <h2 className="font-semibold">Most exposed vendors</h2>
          <p className="mb-5 text-xs text-muted">Distinct CVEs affecting any of the vendor's products</p>
          <div className="space-y-4">{x.topVendors.map((v, i) => <HBar key={v.name} label={v.name} sub={`${v.products} product${v.products > 1 ? "s" : ""}`} value={v.cves} max={maxV} color="rgb(var(--accent))" i={i} />)}</div>
        </section>
        <section className="card p-5">
          <h2 className="font-semibold">Weakness types</h2>
          <p className="mb-5 text-xs text-muted">CVEs per weakness</p>
          <div className="space-y-4">{x.weaknesses.map((w, i) => <HBar key={w.name} label={w.name} value={w.n} max={maxW} color="rgb(var(--accent2))" i={i} />)}</div>
        </section>
      </div>

      <section className="card mt-4 p-5">
        <h2 className="font-semibold">CVEs added per month</h2>
        <p className="mb-4 text-xs text-muted">From the date each CVE entered the catalogue</p>
        <div className="flex h-36 items-end gap-3">
          {x.timeline.map((t, i) => (
            <div key={t.month} className="flex flex-1 flex-col items-center justify-end gap-2">
              <span className="font-mono text-xs tabular-nums text-muted">{t.n}</span>
              <motion.div className="w-full rounded-t-lg bg-gradient-to-t from-accent/30 to-accent" initial={{ height: 0 }}
                animate={{ height: `${(t.n / maxT) * 100}px` }} transition={{ duration: 0.7, delay: i * 0.06, ease: [0.22, 1, 0.36, 1] }} />
              <span className="font-mono text-[11px] text-muted">{t.month.slice(2)}</span>
            </div>
          ))}
        </div>
      </section>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <section className="card p-5">
          <h2 className="font-semibold">Products hit more than once</h2>
          <p className="mb-4 text-xs text-muted">Patch these first: one product, several CVEs</p>
          {x.topProducts.length ? (
            <ul className="space-y-2 text-sm">
              {x.topProducts.map((p) => (
                <li key={p.name} className="flex items-center justify-between rounded-lg border border-line bg-elevated/40 px-3 py-2">
                  <span>{p.name} <span className="text-xs text-muted">{p.vendor}</span></span><span className="font-mono text-xs">{p.cves} CVEs</span>
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-muted">No product is affected by more than one CVE.</p>}
        </section>
        <section className="card p-5">
          <h2 className="font-semibold">Exploit chains</h2>
          <p className="mb-4 text-xs text-muted">CVEs an attacker can combine</p>
          {x.clusters.length ? (
            <ul className="space-y-2">
              {x.clusters.map((c) => (
                <li key={c.join()} className="flex flex-wrap items-center gap-2 rounded-lg border border-bad/30 bg-bad/5 px-3 py-2">
                  {c.map((id, i) => (
                    <span key={id} className="flex items-center gap-2">
                      {i > 0 && <span className="text-bad">→</span>}
                      <button className="font-mono text-[13px] hover:text-accent" onClick={() => openNode(`CVE:${id}`)}>{id}</button>
                    </span>
                  ))}
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-muted">No exploit chains recorded.</p>}
        </section>
      </div>
    </div>
  );
}
