import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api } from "./api";
import type { AskMode, GraphData, Health, Outcome, ReqMode, Settings, Turn } from "./types";

export type View = "ask" | "triage" | "exposure" | "explore" | "benchmark" | "settings";
export const VIEWS: View[] = ["ask", "triage", "exposure", "explore", "benchmark", "settings"];

const KEY = "cve-graphrag.settings";
const TURNS_KEY = "cve-graphrag.turns";
const KEY_KEY = "cve-graphrag.apikey";
const DEFAULTS: Settings = { apiUrl: "http://127.0.0.1:8000", apiKey: "", source: "live", theme: "dark" };
const MODES: AskMode[] = ["auto", "graph", "vector", "compare"];

/** The API key lives in sessionStorage only: it is gone when the tab closes and never sits in localStorage. */
function loadSettings(): { settings: Settings; stored: boolean } {
  let apiKey = "";
  try { apiKey = sessionStorage.getItem(KEY_KEY) ?? ""; } catch { /* ignore */ }
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return { settings: { ...DEFAULTS, ...JSON.parse(raw), apiKey }, stored: true };
  } catch { /* storage unavailable */ }
  return { settings: { ...DEFAULTS, apiKey }, stored: false };
}

function loadTurns(): Turn[] {
  try { return (JSON.parse(localStorage.getItem(TURNS_KEY) ?? "[]") as Turn[]).filter((t) => t && t.question); } catch { return []; }
}

export function parseHash(hash = window.location.hash): { view: View; q?: string; m?: AskMode } {
  const [path, query = ""] = hash.replace(/^#\/?/, "").split("?");
  const params = new URLSearchParams(query);
  const view = (VIEWS as string[]).includes(path) ? (path as View) : "ask";
  const m = params.get("m") as AskMode | null;
  return { view, q: params.get("q") ?? undefined, m: m && MODES.includes(m) ? m : undefined };
}

export function shareLink(t: Pick<Turn, "question" | "mode">): string {
  const p = new URLSearchParams({ q: t.question, m: t.mode });
  return `${window.location.origin}${window.location.pathname}#/ask?${p}`;
}

interface GraphState { data: GraphData | null; loading: boolean; error: string | null }
export type HealthState = { health: Health | null; checking: boolean; error: string | null };

interface Ctx {
  settings: Settings;
  update: (patch: Partial<Settings>) => void;
  view: View;
  setView: (v: View) => void;
  focusNode: string | null;
  openNode: (id: string) => void;
  healthState: HealthState;
  refreshHealth: () => Promise<void>;
  graph: GraphState;
  reloadGraph: () => Promise<void>;
  turns: Turn[];
  busy: boolean;
  ask: (question: string, mode: AskMode) => void;
  stop: () => void;
  retry: (turnId: number, mode: ReqMode) => void;
  clearTurns: () => void;
}

const AppContext = createContext<Ctx | null>(null);
export const useApp = () => {
  const c = useContext(AppContext);
  if (!c) throw new Error("useApp outside provider");
  return c;
};

export function AppProvider({ children }: { children: ReactNode }) {
  const initial = useRef(loadSettings());
  const [settings, setSettings] = useState<Settings>(initial.current.settings);
  const [ready, setReady] = useState(initial.current.stored);
  const [view, setViewState] = useState<View>(() => parseHash().view);
  const [focusNode, setFocusNode] = useState<string | null>(null);
  const [healthState, setHealthState] = useState<HealthState>({ health: null, checking: true, error: null });
  const [graph, setGraph] = useState<GraphState>({ data: null, loading: true, error: null });
  const [turns, setTurns] = useState<Turn[]>(loadTurns);
  const nextId = useRef(Math.max(0, ...turns.map((t) => t.id)) + 1);
  const settingsRef = useRef(settings);
  settingsRef.current = settings;
  const controllers = useRef(new Map<string, AbortController>());

  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((prev) => {
      const next = { ...prev, ...patch };
      try {
        const { apiKey, ...rest } = next;
        localStorage.setItem(KEY, JSON.stringify(rest));
        if (apiKey) sessionStorage.setItem(KEY_KEY, apiKey); else sessionStorage.removeItem(KEY_KEY);
      } catch { /* ignore */ }
      return next;
    });
  }, []);

  useEffect(() => { document.documentElement.dataset.theme = settings.theme; }, [settings.theme]);

  const setView = useCallback((v: View) => {
    setViewState(v);
    window.history.replaceState(null, "", `#/${v}`);
  }, []);
  const openNode = useCallback((id: string) => { setFocusNode(id.startsWith("CVE-") ? `CVE:${id}` : id); setView("explore"); }, [setView]);

  useEffect(() => {
    const onHash = () => setViewState(parseHash().view);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const refreshHealth = useCallback(async () => {
    setHealthState((h) => ({ ...h, checking: true }));
    try {
      setHealthState({ health: await api.health(settingsRef.current), checking: false, error: null });
    } catch (e) {
      setHealthState({ health: null, checking: false, error: (e as Error).message });
    }
  }, []);

  const reloadGraph = useCallback(async () => {
    setGraph((g) => ({ ...g, loading: true, error: null }));
    try {
      setGraph({ data: await api.graph(settingsRef.current), loading: false, error: null });
    } catch (e) {
      setGraph({ data: null, loading: false, error: (e as Error).message });
    }
  }, []);

  // First visit: use the live API if it answers, otherwise fall back to demo data.
  useEffect(() => {
    if (initial.current.stored) return;
    api.health({ ...DEFAULTS, source: "live" }).catch(() => update({ source: "demo" })).finally(() => setReady(true));
  }, [update]);

  useEffect(() => {
    if (!ready) return;
    void refreshHealth();
    void reloadGraph();
    const t = setInterval(() => void refreshHealth(), 30_000);
    return () => clearInterval(t);
  }, [ready, settings.apiUrl, settings.apiKey, settings.source, refreshHealth, reloadGraph]);

  // Keep the conversation across reloads: finished answers only.
  useEffect(() => {
    const keep = turns
      .filter((t) => Object.values(t.outcomes).length > 0 && Object.values(t.outcomes).every((o) => o?.state === "done"))
      .slice(-30);
    try { localStorage.setItem(TURNS_KEY, JSON.stringify(keep)); } catch { /* quota or private mode */ }
  }, [turns]);

  const run = useCallback((turnId: number, question: string, mode: ReqMode) => {
    const id = `${turnId}:${mode}`;
    controllers.current.get(id)?.abort();
    const ctrl = new AbortController();
    controllers.current.set(id, ctrl);
    const startedAt = Date.now();
    const put = (outcome: Outcome) =>
      setTurns((ts) => ts.map((t) => (t.id === turnId ? { ...t, outcomes: { ...t.outcomes, [mode]: outcome } } : t)));
    const patch = (p: Partial<Extract<Outcome, { state: "loading" }>>) =>
      setTurns((ts) => ts.map((t) => {
        const o = t.outcomes[mode];
        return t.id === turnId && o?.state === "loading" ? { ...t, outcomes: { ...t.outcomes, [mode]: { ...o, ...p } } } : t;
      }));
    put({ state: "loading", startedAt });
    api.ask(settingsRef.current, question, mode, (e) => {
      if (e.type === "route") patch({ route: e.route });
      else if (e.type === "retrieval") patch({ context_cves: e.context_cves });
      else setTurns((ts) => ts.map((t) => {
        const o = t.outcomes[mode];
        return t.id === turnId && o?.state === "loading" ? { ...t, outcomes: { ...t.outcomes, [mode]: { ...o, text: (o.text ?? "") + e.text } } } : t;
      }));
    }, ctrl.signal).then(
      (data) => put({ state: "done", data }),
      (e: Error) => put({ state: "error", message: e.name === "AbortError" ? "Stopped." : e.message }),
    ).finally(() => controllers.current.delete(id));
  }, []);

  const ask = useCallback((question: string, mode: AskMode) => {
    const id = nextId.current++;
    const modes: ReqMode[] = mode === "compare" ? ["graph", "vector"] : [mode];
    setTurns((ts) => [...ts, { id, question, mode, outcomes: {}, createdAt: Date.now() }]);
    setViewState("ask");
    modes.forEach((m) => run(id, question, m));
  }, [run]);

  const stop = useCallback(() => { controllers.current.forEach((c) => c.abort()); }, []);

  const retry = useCallback((turnId: number, mode: ReqMode) => {
    const t = turns.find((x) => x.id === turnId);
    if (t) run(turnId, t.question, mode);
  }, [turns, run]);

  // Shared link (#/ask?q=...&m=...): run the question once, as soon as the data source is known.
  const linked = useRef(false);
  useEffect(() => {
    if (!ready || linked.current) return;
    linked.current = true;
    const { q, m } = parseHash();
    if (q) { ask(q, m ?? "auto"); window.history.replaceState(null, "", "#/ask"); }
  }, [ready, ask]);

  const busy = turns.some((t) => Object.values(t.outcomes).some((o) => o?.state === "loading"));

  const value = useMemo<Ctx>(() => ({
    settings, update, view, setView, focusNode, openNode, healthState, refreshHealth, graph, reloadGraph,
    turns, busy, ask, stop, retry, clearTurns: () => setTurns([]),
  }), [settings, update, view, setView, focusNode, openNode, healthState, refreshHealth, graph, reloadGraph, turns, busy, ask, stop, retry]);

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}
