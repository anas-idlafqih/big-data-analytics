import { AnimatePresence, motion } from "framer-motion";
import { lazy, Suspense, useEffect, useState, type ComponentType } from "react";
import { Palette } from "./components/Palette";
import { Sidebar, StatusPill, ThemeToggle } from "./components/Sidebar";
import { Logo } from "./components/ui";
import { AppProvider, useApp, type View } from "./lib/store";
import { AskView } from "./views/AskView";

// Heavier views (charts, the force-graph library) load on first visit.
const ExploreView = lazy(() => import("./views/ExploreView").then((m) => ({ default: m.ExploreView })));
const TriageView = lazy(() => import("./views/TriageView").then((m) => ({ default: m.TriageView })));
const ExposureView = lazy(() => import("./views/ExposureView").then((m) => ({ default: m.ExposureView })));
const BenchmarkView = lazy(() => import("./views/BenchmarkView").then((m) => ({ default: m.BenchmarkView })));
const SettingsView = lazy(() => import("./views/SettingsView").then((m) => ({ default: m.SettingsView })));

const VIEWS: Record<View, ComponentType> = {
  ask: AskView, triage: TriageView, exposure: ExposureView, explore: ExploreView, benchmark: BenchmarkView, settings: SettingsView,
};

function Shell() {
  const { view, setView } = useApp();
  const [palette, setPalette] = useState(false);
  const Current = VIEWS[view];

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((p) => !p); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="relative h-full">
      <div className="aurora"><div className="grid-bg" /></div>
      <Sidebar view={view} onChange={setView} onPalette={() => setPalette(true)} />
      <header className="fixed inset-x-0 top-0 z-20 flex items-center justify-between border-b border-line bg-surface/70 px-4 py-2.5 backdrop-blur-xl md:hidden">
        <div className="flex items-center gap-2.5"><Logo size={28} /><span className="font-bold tracking-tight">CVE Graph</span></div>
        <div className="flex items-center gap-2"><StatusPill compact /><ThemeToggle /></div>
      </header>
      <main className="relative z-10 h-full overflow-y-auto pt-14 md:ml-[232px] md:pt-0">
        <AnimatePresence mode="wait">
          <motion.div key={view} className="min-h-full" style={{ height: view === "explore" ? "100%" : undefined }}
            initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}>
            <Suspense fallback={<div className="grid h-64 place-items-center text-sm text-muted">Loading…</div>}>
              <Current />
            </Suspense>
          </motion.div>
        </AnimatePresence>
      </main>
      <Palette open={palette} onClose={() => setPalette(false)} />
    </div>
  );
}

export default function App() {
  return <AppProvider><Shell /></AppProvider>;
}
