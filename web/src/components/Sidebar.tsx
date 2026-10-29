import { motion } from "framer-motion";
import { BarChart3, Gauge, MessageSquareText, Moon, Orbit, Settings as Cog, ShieldCheck, Sun } from "lucide-react";
import { useApp, type View } from "../lib/store";
import { Logo, cn } from "./ui";

export const NAV: { id: View; label: string; icon: typeof Orbit }[] = [
  { id: "ask", label: "Ask", icon: MessageSquareText },
  { id: "triage", label: "Triage", icon: ShieldCheck },
  { id: "exposure", label: "Exposure", icon: Gauge },
  { id: "explore", label: "Graph", icon: Orbit },
  { id: "benchmark", label: "Benchmark", icon: BarChart3 },
  { id: "settings", label: "Settings", icon: Cog },
];

export function StatusPill({ compact }: { compact?: boolean }) {
  const { healthState, settings } = useApp();
  const { health, checking, error } = healthState;
  let tone = "bg-muted", text = "Checking…";
  if (!checking || health || error) {
    if (settings.source === "demo") { tone = "bg-warn"; text = "Demo data"; }
    else if (!health) { tone = "bg-bad"; text = "API offline"; }
    else if (health.status === "ok") { tone = "bg-good"; text = "All systems up"; }
    else { tone = "bg-warn"; text = `${!health.neo4j ? "Neo4j" : "Ollama"} down`; }
  }
  return (
    <div className="flex items-center gap-2 rounded-full border border-line bg-elevated/50 px-3 py-1.5 text-xs font-medium">
      <span className="relative flex h-2 w-2">
        <span className={cn("absolute inline-flex h-full w-full animate-ping rounded-full opacity-60", tone)} />
        <span className={cn("relative inline-flex h-2 w-2 rounded-full", tone)} />
      </span>
      {!compact && text}
    </div>
  );
}

export function ThemeToggle() {
  const { settings, update } = useApp();
  const dark = settings.theme === "dark";
  return (
    <button className="btn !h-9 !w-9 !p-0" aria-label="Toggle theme" onClick={() => update({ theme: dark ? "light" : "dark" })}>
      <motion.span key={settings.theme} initial={{ rotate: -90, opacity: 0 }} animate={{ rotate: 0, opacity: 1 }}>
        {dark ? <Sun size={16} /> : <Moon size={16} />}
      </motion.span>
    </button>
  );
}

export function Sidebar({ view, onChange, onPalette }: { view: View; onChange: (v: View) => void; onPalette: () => void }) {
  return (
    <>
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-[232px] flex-col border-r border-line bg-surface/50 p-4 backdrop-blur-xl md:flex">
        <div className="flex items-center gap-3 px-2 pb-6 pt-2">
          <Logo />
          <div className="leading-tight">
            <div className="font-bold tracking-tight">CVE Graph</div>
            <div className="text-[11px] text-muted">GraphRAG workbench</div>
          </div>
        </div>
        <nav className="flex flex-col gap-1">
          {NAV.map((n) => {
            const on = view === n.id;
            return (
              <button key={n.id} onClick={() => onChange(n.id)} aria-current={on ? "page" : undefined}
                className={cn("relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-colors", on ? "text-ink" : "text-muted hover:text-ink")}>
                {on && <motion.span layoutId="nav-pill" className="absolute inset-0 rounded-xl border border-line bg-elevated/80" transition={{ type: "spring", stiffness: 420, damping: 34 }} />}
                {on && <motion.span layoutId="nav-bar" className="absolute -left-4 top-2.5 h-5 w-1 rounded-r-full bg-gradient-to-b from-accent to-accent2" />}
                <n.icon size={17} className={cn("relative", on && "text-accent")} />
                <span className="relative">{n.label}</span>
              </button>
            );
          })}
        </nav>
        <button onClick={onPalette} className="mt-6 flex items-center justify-between rounded-xl border border-line bg-elevated/40 px-3 py-2 text-xs text-muted transition hover:border-accent/40 hover:text-ink">
          <span>Search or jump to…</span><kbd className="rounded border border-line px-1 font-mono">Ctrl K</kbd>
        </button>
        <div className="mt-auto flex items-center justify-between gap-2">
          <StatusPill />
          <ThemeToggle />
        </div>
      </aside>

      <nav className="fixed inset-x-0 bottom-0 z-30 flex items-center justify-around border-t border-line bg-surface/85 px-2 pb-[max(.5rem,env(safe-area-inset-bottom))] pt-2 backdrop-blur-xl md:hidden">
        {NAV.map((n) => {
          const on = view === n.id;
          return (
            <button key={n.id} onClick={() => onChange(n.id)} className={cn("flex flex-1 flex-col items-center gap-1 rounded-lg py-1 text-[10px] font-medium", on ? "text-accent" : "text-muted")}>
              <n.icon size={19} />{n.label}
            </button>
          );
        })}
      </nav>
    </>
  );
}
