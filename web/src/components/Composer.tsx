import { motion } from "framer-motion";
import { ArrowUp, Columns2, Network, Route, Square, Waypoints } from "lucide-react";
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";
import type { AskMode } from "../lib/types";
import { cn } from "./ui";

const MODES: { id: AskMode; label: string; icon: typeof Network; hint: string }[] = [
  { id: "auto", label: "Auto", icon: Route, hint: "A router picks the engine: exact Cypher for counts and rankings, GraphRAG for the rest" },
  { id: "graph", label: "GraphRAG", icon: Network, hint: "CVE ids are resolved in the graph, then the exploit chain is followed" },
  { id: "vector", label: "Vector", icon: Waypoints, hint: "The 5 CVE texts closest to the question by embedding" },
  { id: "compare", label: "Compare", icon: Columns2, hint: "Run both side by side" },
];

export interface ComposerHandle { focus: () => void; setText: (t: string) => void }

export const Composer = forwardRef<ComposerHandle, { busy: boolean; onSubmit: (q: string, m: AskMode) => void; onStop: () => void; compact?: boolean }>(
  function Composer({ busy, onSubmit, onStop, compact }, ref) {
    const [text, setText] = useState("");
    const [mode, setMode] = useState<AskMode>("auto");
    const area = useRef<HTMLTextAreaElement>(null);

    useImperativeHandle(ref, () => ({
      focus: () => area.current?.focus(),
      setText: (t) => { setText(t); requestAnimationFrame(() => area.current?.focus()); },
    }));

    useEffect(() => {
      const el = area.current;
      if (!el) return;
      el.style.height = "auto";
      el.style.height = Math.min(el.scrollHeight, 180) + "px";
    }, [text]);

    const send = () => {
      const q = text.trim();
      if (!q) return;
      onSubmit(q, mode);
      setText("");
    };

    return (
      <div className={cn("card p-2.5 shadow-glow/0 transition focus-within:border-accent/50 focus-within:shadow-glow", compact && "p-2")}>
        <textarea
          ref={area}
          rows={1}
          value={text}
          maxLength={1000}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }}
          placeholder="Ask about a CVE, an exploit chain, a vendor…"
          className="block max-h-44 w-full resize-none bg-transparent px-3 pb-1 pt-2.5 text-[15px] leading-relaxed outline-none placeholder:text-muted/70"
          aria-label="Question"
        />
        <div className="flex flex-wrap items-center justify-between gap-2 px-1 pt-1">
          <div role="radiogroup" aria-label="Mode" className="relative flex rounded-xl border border-line bg-elevated/50 p-0.5">
            {MODES.map((m) => {
              const on = mode === m.id;
              return (
                <button key={m.id} role="radio" aria-checked={on} title={m.hint} onClick={() => setMode(m.id)}
                  className={cn("relative flex items-center gap-1.5 rounded-[10px] px-3 py-1.5 text-[13px] font-medium transition-colors", on ? "text-ink" : "text-muted hover:text-ink")}>
                  {on && <motion.span layoutId="mode-pill" className="absolute inset-0 rounded-[10px] border border-line bg-surface shadow-sm" transition={{ type: "spring", stiffness: 500, damping: 36 }} />}
                  <m.icon size={14} className={cn("relative", on && "text-accent")} />
                  <span className="relative">{m.label}</span>
                </button>
              );
            })}
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden font-mono text-[11px] text-muted sm:block">
              {text.length > 0 ? `${text.length}/1000` : <><kbd className="rounded border border-line px-1">Enter</kbd> send · <kbd className="rounded border border-line px-1">Ctrl K</kbd> menu</>}
            </span>
            {busy ? (
              <motion.button whileTap={{ scale: 0.92 }} onClick={onStop} aria-label="Stop" title="Stop generating" className="btn !h-9 !w-9 !rounded-xl !p-0 border-bad/50 text-bad">
                <Square size={14} fill="currentColor" />
              </motion.button>
            ) : (
              <motion.button whileTap={{ scale: 0.92 }} onClick={send} disabled={!text.trim()} aria-label="Send" className="btn btn-primary !h-9 !w-9 !rounded-xl !p-0">
                <ArrowUp size={18} strokeWidth={2.4} />
              </motion.button>
            )}
          </div>
        </div>
      </div>
    );
  },
);
