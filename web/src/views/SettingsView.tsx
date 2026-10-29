import { CheckCircle2, Eye, EyeOff, FlaskConical, Plug, RefreshCw, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { CopyButton, SectionTitle, cn } from "../components/ui";
import { useApp } from "../lib/store";

function Service({ name, ok, detail }: { name: string; ok: boolean | null; detail: string }) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-line bg-elevated/40 p-4">
      {ok === null ? <span className="h-5 w-5 animate-pulse rounded-full bg-muted/40" />
        : ok ? <CheckCircle2 className="text-good" size={20} /> : <XCircle className="text-bad" size={20} />}
      <div className="min-w-0">
        <div className="font-medium">{name}</div>
        <div className="truncate text-xs text-muted">{detail}</div>
      </div>
    </div>
  );
}

const STACK = [
  { label: "Neo4j", cmd: "docker compose -f docker/docker-compose.yml up -d neo4j" },
  { label: "API", cmd: "python -m uvicorn api.app:app --port 8000" },
  { label: "Frontend", cmd: "cd web && npm run dev" },
];

export function SettingsView() {
  const { settings, update, healthState, refreshHealth } = useApp();
  const [url, setUrl] = useState(settings.apiUrl);
  const [key, setKey] = useState(settings.apiKey);
  const [show, setShow] = useState(false);
  useEffect(() => { setUrl(settings.apiUrl); setKey(settings.apiKey); }, [settings.apiUrl, settings.apiKey]);
  const dirty = url !== settings.apiUrl || key !== settings.apiKey;
  const { health, checking, error } = healthState;
  const demo = settings.source === "demo";

  return (
    <div className="mx-auto max-w-3xl px-4 pb-28 pt-8 sm:px-8 md:pb-10">
      <SectionTitle eyebrow="Configuration" title="Settings" />

      <section className="card p-5 sm:p-6">
        <h2 className="mb-1 font-semibold">Data source</h2>
        <p className="mb-4 text-sm text-muted">Use the live API, or explore the interface with a built-in sample graph — no Neo4j or Ollama needed.</p>
        <div className="grid gap-3 sm:grid-cols-2">
          {([["live", "Live API", "Your FastAPI backend, Neo4j and Ollama", Plug], ["demo", "Demo data", "Simulated answers on a sample graph", FlaskConical]] as const).map(([id, t, d, Icon]) => (
            <button key={id} onClick={() => update({ source: id })} aria-pressed={settings.source === id}
              className={cn("flex items-start gap-3 rounded-xl border p-4 text-left transition", settings.source === id ? "border-accent/60 bg-accent/10 shadow-glow" : "border-line hover:border-accent/30")}>
              <Icon size={18} className={settings.source === id ? "text-accent" : "text-muted"} />
              <span><span className="block font-medium">{t}</span><span className="text-xs text-muted">{d}</span></span>
            </button>
          ))}
        </div>
      </section>

      <section className={cn("card mt-4 space-y-4 p-5 transition sm:p-6", demo && "opacity-50")}>
        <h2 className="font-semibold">API connection</h2>
        <div>
          <label className="label mb-1.5 block" htmlFor="api-url">API URL</label>
          <input id="api-url" className="input font-mono" value={url} onChange={(e) => setUrl(e.target.value)} disabled={demo} spellCheck={false} />
        </div>
        <div>
          <label className="label mb-1.5 block" htmlFor="api-key">API key <span className="normal-case tracking-normal">(X-API-Key, optional · kept for this tab only)</span></label>
          <div className="relative">
            <input id="api-key" className="input pr-10 font-mono" type={show ? "text" : "password"} value={key} onChange={(e) => setKey(e.target.value)} disabled={demo} autoComplete="off" />
            <button className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 text-muted hover:text-ink" onClick={() => setShow((s) => !s)} aria-label="Show key">{show ? <EyeOff size={16} /> : <Eye size={16} />}</button>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-primary" disabled={!dirty || demo} onClick={() => update({ apiUrl: url.trim(), apiKey: key })}>Save</button>
          <button className="btn" onClick={() => void refreshHealth()}><RefreshCw size={14} className={cn(checking && "animate-spin")} />Test connection</button>
        </div>
      </section>

      <section className="card mt-4 p-5 sm:p-6">
        <h2 className="mb-4 font-semibold">Service health</h2>
        <div className="grid gap-3 sm:grid-cols-3">
          <Service name="API" ok={checking && !health && !error ? null : !!health} detail={demo ? "Simulated" : error ?? settings.apiUrl} />
          <Service name="Neo4j" ok={health ? health.neo4j : error ? false : null} detail={health?.neo4j ? "Connected" : "Graph database"} />
          <Service name="Ollama" ok={health ? health.ollama : error ? false : null} detail={health?.ollama ? "Model server running" : "Local LLM"} />
        </div>
      </section>

      <section className="card mt-4 p-5 sm:p-6">
        <h2 className="mb-4 font-semibold">Start the stack</h2>
        <div className="space-y-2">
          {STACK.map((s) => (
            <div key={s.label} className="flex items-center gap-3 rounded-xl border border-line bg-bg/50 px-4 py-3">
              <span className="label w-20 shrink-0">{s.label}</span>
              <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[13px]">{s.cmd}</code>
              <CopyButton text={s.cmd} />
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
