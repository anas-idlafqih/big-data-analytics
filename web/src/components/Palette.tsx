import { AnimatePresence, motion } from "framer-motion";
import { BarChart3, CornerDownLeft, FlaskConical, History, MessageSquareText, Moon, Orbit, Search, ShieldCheck, Gauge, Settings as Cog, Sun, Target } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { useApp, type View } from "../lib/store";
import { cn } from "./ui";

interface Cmd { id: string; group: string; label: string; hint?: string; icon: LucideIcon; run: () => void }

const NAV: [View, string, LucideIcon][] = [
  ["ask", "Ask", MessageSquareText], ["triage", "Triage my stack", ShieldCheck], ["exposure", "Exposure dashboard", Gauge],
  ["explore", "Graph explorer", Orbit], ["benchmark", "Benchmark", BarChart3], ["settings", "Settings", Cog],
];
const EXAMPLES = [
  "Which products does CVE-2026-21589 affect?",
  "Which CVEs are chained with CVE-2026-105133?",
  "Which products are affected by more than one CVE?",
  "Which vendor has the most CVEs in the corpus?",
];

export function Palette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const app = useApp();
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => { if (open) { setQ(""); setIdx(0); setTimeout(() => input.current?.focus(), 30); } }, [open]);

  const all = useMemo<Cmd[]>(() => {
    const go = (fn: () => void) => () => { fn(); onClose(); };
    const cmds: Cmd[] = [
      ...NAV.map(([v, label, icon]) => ({ id: `nav-${v}`, group: "Go to", label, icon, run: go(() => app.setView(v)) })),
      ...EXAMPLES.map((e) => ({ id: `ex-${e}`, group: "Ask an example", label: e, icon: Target, run: go(() => app.ask(e, "auto")) })),
      ...[...new Set(app.turns.map((t) => t.question))].slice(-5).reverse().map((e) => ({ id: `re-${e}`, group: "Recent questions", label: e, icon: History, run: go(() => app.ask(e, "auto")) })),
      { id: "theme", group: "Preferences", label: app.settings.theme === "dark" ? "Switch to light theme" : "Switch to dark theme", icon: app.settings.theme === "dark" ? Sun : Moon, run: go(() => app.update({ theme: app.settings.theme === "dark" ? "light" : "dark" })) },
      { id: "src", group: "Preferences", label: app.settings.source === "demo" ? "Use the live API" : "Use demo data", icon: FlaskConical, run: go(() => app.update({ source: app.settings.source === "demo" ? "live" : "demo" })) },
      ...(app.graph.data?.nodes.filter((n) => n.label === "CVE") ?? []).map((n) => ({ id: n.id, group: "CVEs", label: n.name, hint: n.text?.slice(0, 70) ?? "", icon: Search, run: go(() => app.openNode(n.id)) })),
    ];
    return cmds;
  }, [app, onClose]);

  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    const hit = s ? all.filter((c) => (c.label + " " + (c.hint ?? "")).toLowerCase().includes(s)) : all.filter((c) => c.group !== "CVEs");
    const ask: Cmd[] = s.length > 3 ? [{ id: "ask-q", group: "Ask", label: `Ask: “${q.trim()}”`, icon: MessageSquareText, run: () => { app.ask(q.trim(), "auto"); onClose(); } }] : [];
    return [...ask, ...hit].slice(0, 30);
  }, [all, q, app, onClose]);

  useEffect(() => setIdx(0), [q]);
  useEffect(() => { document.querySelector(`[data-pi="${idx}"]`)?.scrollIntoView({ block: "nearest" }); }, [idx]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(list.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); list[idx]?.run(); }
    else if (e.key === "Escape") onClose();
  };

  return (
    <AnimatePresence>
      {open && (
        <motion.div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 px-4 pt-[14vh] backdrop-blur-sm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onMouseDown={onClose}>
          <motion.div role="dialog" aria-label="Command palette" initial={{ opacity: 0, y: -12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }} onMouseDown={(e) => e.stopPropagation()}
            className="w-full max-w-xl overflow-hidden rounded-2xl border border-line bg-surface shadow-2xl">
            <div className="flex items-center gap-3 border-b border-line px-4">
              <Search size={16} className="text-muted" />
              <input ref={input} autoFocus value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} placeholder="Type a CVE, a page, or a question…"
                className="h-12 flex-1 bg-transparent text-[15px] outline-none placeholder:text-muted/70" aria-label="Search commands" />
              <kbd className="rounded border border-line px-1.5 py-0.5 font-mono text-[10px] text-muted">Esc</kbd>
            </div>
            <ul className="max-h-[50vh] overflow-y-auto p-2">
              {list.length === 0 && <li className="px-3 py-6 text-center text-sm text-muted">No match. Press Enter to ask it as a question.</li>}
              {list.map((c, i) => (
                <li key={c.id} data-pi={i}>
                  {(i === 0 || list[i - 1].group !== c.group) && <div className="label px-3 pb-1 pt-3 !text-[10px]">{c.group}</div>}
                  <button onMouseMove={() => setIdx(i)} onClick={c.run}
                    className={cn("flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm", i === idx ? "bg-elevated text-ink" : "text-muted")}>
                    <c.icon size={15} className={i === idx ? "text-accent" : undefined} />
                    <span className="min-w-0 flex-1 truncate">{c.label}{c.hint && <span className="ml-2 text-xs text-muted">{c.hint}</span>}</span>
                    {i === idx && <CornerDownLeft size={13} className="text-muted" />}
                  </button>
                </li>
              ))}
            </ul>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
