import { animate } from "framer-motion";
import { Check, Copy, ExternalLink } from "lucide-react";
import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { nvdUrl } from "../lib/api";

export const cn = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

export function spotlight(e: MouseEvent<HTMLElement>) {
  const r = e.currentTarget.getBoundingClientRect();
  e.currentTarget.style.setProperty("--mx", `${e.clientX - r.left}px`);
  e.currentTarget.style.setProperty("--my", `${e.clientY - r.top}px`);
}

export function Logo({ size = 36 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <defs>
        <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
          <stop stopColor="rgb(var(--accent))" />
          <stop offset="1" stopColor="rgb(var(--accent2))" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="9" fill="url(#lg)" />
      <path d="M10 11L22 10L16 22Z" stroke="#070a14" strokeWidth="1.6" fill="none" strokeLinejoin="round" />
      <circle cx="10" cy="11" r="3" fill="#070a14" />
      <circle cx="22" cy="10" r="3" fill="#070a14" />
      <circle cx="16" cy="22" r="3" fill="#070a14" />
    </svg>
  );
}

export function CountUp({ value, decimals = 0, suffix = "", duration = 1.1 }: { value: number; decimals?: number; suffix?: string; duration?: number }) {
  const [v, setV] = useState(0);
  useEffect(() => {
    const c = animate(0, value, { duration, ease: [0.22, 1, 0.36, 1], onUpdate: setV });
    return () => c.stop();
  }, [value, duration]);
  return <>{v.toFixed(decimals)}{suffix}</>;
}

export function CveChip({ id, tone = "neutral", ransom, onOpen }: { id: string; tone?: "source" | "neutral"; ransom?: boolean; onOpen?: (id: string) => void }) {
  const cls = tone === "source"
    ? "border-good/40 bg-good/10 text-good"
    : "border-line bg-elevated/60 text-ink";
  return (
    <span className={cn("chip gap-0 !p-0 overflow-hidden", cls)}>
      <button className="flex items-center gap-1.5 py-1 pl-2.5 pr-2 transition hover:bg-white/5" onClick={() => onOpen?.(id)} title="Show in the graph">
        {ransom && <span className="h-1.5 w-1.5 rounded-full bg-bad" title="Used in ransomware campaigns" />}
        {id}
      </button>
      <a className="border-l border-line/60 px-1.5 py-1 opacity-60 transition hover:bg-white/5 hover:opacity-100" href={nvdUrl(id)} target="_blank" rel="noreferrer" title="Open on NVD" aria-label={`${id} on NVD`}>
        <ExternalLink size={11} />
      </a>
    </span>
  );
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      className="btn !px-2.5 !py-1.5 text-xs"
      onClick={() => { void navigator.clipboard?.writeText(text); setOk(true); setTimeout(() => setOk(false), 1400); }}
      aria-label="Copy"
    >
      {ok ? <Check size={14} className="text-good" /> : <Copy size={14} />}
      {label && <span>{ok ? "Copied" : label}</span>}
    </button>
  );
}

export function Stat({ icon, label, children, hint }: { icon?: ReactNode; label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="rounded-xl border border-line bg-elevated/40 px-3.5 py-3" title={hint}>
      <div className="flex items-center gap-1.5 text-muted">{icon}<span className="label truncate !text-[10px]">{label}</span></div>
      <div className="mt-1 whitespace-nowrap font-mono text-xl font-medium tabular-nums">{children}</div>
    </div>
  );
}

export function SectionTitle({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <div className="label text-accent">{eyebrow}</div>
        <h1 className="mt-1.5 text-2xl font-bold tracking-tight sm:text-3xl">{title}</h1>
      </div>
      {children}
    </div>
  );
}
