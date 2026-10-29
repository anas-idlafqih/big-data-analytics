import { AnimatePresence, motion } from "framer-motion";
import { Download, FileUp, Flame, Link2, ShieldCheck, Sparkles } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { CopyButton, CveChip, SectionTitle, cn } from "../components/ui";
import { findings, matchStack, parseStackInput, toCSV, toMarkdown, type Level } from "../lib/analytics";
import { useApp } from "../lib/store";

const SAMPLE = "Citrix NetScaler ADC\nMicrosoft Windows Shell\nFortiOS\nPlex Media Server\nJira Software Data Center\nUbuntu 22.04";

const TONE: Record<Level, string> = {
  Critical: "border-bad/50 bg-bad/10 text-bad",
  High: "border-warn/50 bg-warn/10 text-warn",
  Medium: "border-accent2/40 bg-accent2/10 text-accent2",
  Low: "border-line bg-elevated/50 text-muted",
};

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

export function TriageView() {
  const { graph, openNode } = useApp();
  const [text, setText] = useState("");
  const file = useRef<HTMLInputElement>(null);
  const g = graph.data;

  const result = useMemo(() => {
    if (!g || !text.trim()) return null;
    const lines = parseStackInput(text);
    const matches = matchStack(g, lines);
    return { matches, found: findings(g, matches), unmatched: matches.filter((m) => !m.products.length).map((m) => m.input) };
  }, [g, text]);
  const ransom = useMemo(() => new Set((g?.nodes ?? []).filter((n) => n.ransomware === "Known").map((n) => n.name)), [g]);
  const counts = useMemo(() => {
    const c: Record<Level, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    result?.found.forEach((f) => c[f.level]++);
    return c;
  }, [result]);
  const chains = useMemo(
    () => (result?.found ?? []).filter((f) => f.chainInStack.length && f.cve.name < f.chainInStack[0]).map((f) => [f.cve.name, f.chainInStack[0]]),
    [result],
  );

  return (
    <div className="mx-auto max-w-6xl px-4 pb-28 pt-8 sm:px-8 md:pb-10">
      <SectionTitle eyebrow="Triage" title="Is my stack affected?">
        <span className="text-sm text-muted">Runs in your browser — nothing you paste is sent anywhere.</span>
      </SectionTitle>

      <div className="grid gap-4 lg:grid-cols-5">
        <section className="card p-5 lg:col-span-2">
          <label htmlFor="stack" className="font-semibold">Your software</label>
          <p className="mb-3 text-xs text-muted">One product or vendor per line, comma-separated, or a CycloneDX/SPDX JSON SBOM.</p>
          <textarea id="stack" className="input h-52 resize-y font-mono text-[13px] leading-relaxed" value={text} onChange={(e) => setText(e.target.value)}
            placeholder={"NetScaler ADC\nFortiOS 7.2\nAtlassian\n…"} spellCheck={false} />
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="btn" onClick={() => setText(SAMPLE)}><Sparkles size={14} />Load a sample</button>
            <button className="btn" onClick={() => file.current?.click()}><FileUp size={14} />Upload file</button>
            <input ref={file} type="file" accept=".txt,.csv,.json" hidden onChange={async (e) => {
              const f = e.target.files?.[0];
              if (f) setText(await f.text());
              e.target.value = "";
            }} />
          </div>
          {result && (
            <div className="mt-5">
              <div className="label mb-2">Matched in the graph</div>
              <ul className="space-y-1.5 text-sm">
                {result.matches.map((m, i) => (
                  <li key={i} className="flex items-center justify-between gap-3 rounded-lg border border-line bg-elevated/40 px-3 py-2">
                    <span className="min-w-0 truncate">{m.input}</span>
                    <span className={cn("shrink-0 font-mono text-[11px]", m.products.length ? "text-good" : "text-muted")}>
                      {m.products.length ? `${m.via === "vendor" ? "vendor → " : ""}${m.products.length} product${m.products.length > 1 ? "s" : ""}` : "not found"}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>

        <section className="lg:col-span-3">
          {!g || g.nodes.length === 0 ? (
            <div className="card p-8 text-center text-sm text-muted">{graph.loading ? "Loading the graph…" : "The graph is empty — there is nothing to match against yet."}</div>
          ) : !result ? (
            <div className="card grid place-items-center p-10 text-center">
              <ShieldCheck size={34} className="text-accent" />
              <p className="mt-3 font-semibold">Paste your software list to see what applies to you</p>
              <p className="mt-1 max-w-sm text-sm text-muted">CVEs are ranked by ransomware use, exploit chains inside your own stack, breadth, recency and weakness type.</p>
            </div>
          ) : (
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
              <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                {(Object.keys(counts) as Level[]).map((l) => (
                  <div key={l} className={cn("rounded-xl border px-4 py-3", TONE[l])}>
                    <div className="font-mono text-2xl font-medium tabular-nums">{counts[l]}</div>
                    <div className="label !text-[10px] !text-current opacity-80">{l}</div>
                  </div>
                ))}
              </div>

              {chains.length > 0 && (
                <div className="flex gap-3 rounded-xl border border-bad/40 bg-bad/10 p-4 text-sm">
                  <Link2 size={18} className="mt-0.5 shrink-0 text-bad" />
                  <div>
                    <b>Attack chain inside your stack.</b> An attacker can combine{" "}
                    {chains.map(([a, b], i) => <span key={a}>{i > 0 && "; "}<span className="font-mono">{a}</span> → <span className="font-mono">{b}</span></span>)}.
                  </div>
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm text-muted">{result.found.length} CVE{result.found.length === 1 ? "" : "s"} affect your stack</div>
                {result.found.length > 0 && (
                  <div className="flex gap-2">
                    <CopyButton text={toMarkdown(result.found, result.unmatched)} label="Copy report" />
                    <button className="btn !px-2.5 !py-1.5 text-xs" onClick={() => download("exposure.csv", toCSV(result.found), "text/csv")}><Download size={14} />CSV</button>
                  </div>
                )}
              </div>

              <ul className="space-y-3">
                <AnimatePresence initial={false}>
                  {result.found.map((f, i) => (
                    <motion.li key={f.cve.id} layout initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.04, 0.4) }} className="card p-4">
                      <div className="flex flex-wrap items-center gap-3">
                        <span className={cn("chip !font-sans font-semibold", TONE[f.level])}>{f.level}</span>
                        <CveChip id={f.cve.name} ransom={ransom.has(f.cve.name)} onOpen={openNode} />
                        {f.cve.ransomware === "Known" && <span className="flex items-center gap-1 text-xs text-bad"><Flame size={13} />ransomware</span>}
                        <div className="ml-auto flex items-center gap-2">
                          <div className="h-1.5 w-24 overflow-hidden rounded-full bg-elevated">
                            <motion.div className={cn("h-full rounded-full", f.score >= 70 ? "bg-bad" : f.score >= 50 ? "bg-warn" : "bg-accent2")}
                              initial={{ width: 0 }} animate={{ width: `${f.score}%` }} transition={{ duration: 0.7, delay: 0.1 }} />
                          </div>
                          <span className="w-7 text-right font-mono text-xs tabular-nums text-muted">{f.score}</span>
                        </div>
                      </div>
                      {f.cve.text && <p className="mt-3 text-sm leading-relaxed text-muted">{f.cve.text}</p>}
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {f.products.map((p) => <span key={p} className="chip !font-sans border-line bg-elevated/50 text-ink">{p}</span>)}
                      </div>
                      {f.reasons.length > 0 && <p className="mt-3 text-xs text-muted">Why this rank: {f.reasons.join(" · ")}</p>}
                    </motion.li>
                  ))}
                </AnimatePresence>
              </ul>

              {result.found.length === 0 && <div className="card p-6 text-center text-sm text-muted">None of the matched products has a known CVE in this graph.</div>}
              {result.unmatched.length > 0 && (
                <p className="text-xs text-muted">Not found in the graph (so not assessed): {result.unmatched.join(", ")}. The corpus only covers products named in the ingested advisories.</p>
              )}
              <p className="text-xs text-muted">Priority is a transparent heuristic over the fields the graph holds. It is not a CVSS score and does not replace your own risk assessment.</p>
            </motion.div>
          )}
        </section>
      </div>
    </div>
  );
}
