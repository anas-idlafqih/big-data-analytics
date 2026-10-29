import { demoAsk, demoGraph, demoHealth } from "./demo";
import { readSSE } from "./sse";
import type { AskResult, GraphData, Health, ReqMode, RouteInfo, Settings } from "./types";

const TIMEOUT_MS = 180_000; // CPU generation can take 10–60 s

export type StreamEvent =
  | { type: "route"; route: RouteInfo }
  | { type: "retrieval"; context_cves: string[] }
  | { type: "token"; text: string };

async function failure(res: Response): Promise<Error> {
  let detail = res.statusText;
  try { detail = (await res.json()).detail ?? detail; } catch { /* body is not JSON */ }
  if (res.status === 401) return new Error("Unauthorized — check the API key in Settings.");
  if (res.status === 429) return new Error(`Slow down — ${detail}`);
  return new Error(`${res.status}: ${detail}`);
}

function headers(s: Settings): HeadersInit {
  return { "Content-Type": "application/json", ...(s.apiKey ? { "X-API-Key": s.apiKey } : {}) };
}

function network(e: unknown, s: Settings): Error {
  if (e instanceof DOMException && e.name === "AbortError") return e as unknown as Error;
  if (e instanceof TypeError) return new Error(`API unreachable at ${s.apiUrl}. Start it, or switch to demo data in Settings.`);
  return e as Error;
}

async function request<T>(s: Settings, path: string, timeout = TIMEOUT_MS): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(s.apiUrl.replace(/\/$/, "") + path, { signal: ctrl.signal, headers: headers(s) });
    if (!res.ok) throw await failure(res);
    return (await res.json()) as T;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw new Error("The request timed out.");
    throw network(e, s);
  } finally {
    clearTimeout(timer);
  }
}

/** Streams /ask/stream: progress events go to onEvent, the final result is returned.
 *  Aborting `signal` closes the connection, which stops the generation on the server. */
async function askLive(s: Settings, question: string, mode: ReqMode, onEvent: (e: StreamEvent) => void, signal?: AbortSignal): Promise<AskResult> {
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), TIMEOUT_MS);
  signal?.addEventListener("abort", () => timeout.abort(), { once: true });
  try {
    const res = await fetch(s.apiUrl.replace(/\/$/, "") + "/ask/stream", {
      method: "POST", headers: headers(s), body: JSON.stringify({ question, mode }), signal: timeout.signal,
    });
    if (!res.ok) throw await failure(res);
    for await (const { event, data } of readSSE(res)) {
      if (event === "route") onEvent({ type: "route", route: data as RouteInfo });
      else if (event === "retrieval") onEvent({ type: "retrieval", context_cves: (data as { context_cves: string[] }).context_cves });
      else if (event === "token") onEvent({ type: "token", text: data as string });
      else if (event === "result") return data as AskResult;
      else if (event === "error") throw new Error((data as { detail: string }).detail);
    }
    throw new Error("The connection closed before an answer arrived.");
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError" && !signal?.aborted) throw new Error("The request timed out.");
    throw network(e, s);
  } finally {
    clearTimeout(timer);
  }
}

export const api = {
  ask: (s: Settings, question: string, mode: ReqMode, onEvent: (e: StreamEvent) => void, signal?: AbortSignal): Promise<AskResult> =>
    s.source === "demo" ? demoAsk(question, mode, onEvent, signal) : askLive(s, question, mode, onEvent, signal),
  health: (s: Settings): Promise<Health> => (s.source === "demo" ? demoHealth() : request<Health>(s, "/health", 4000)),
  graph: (s: Settings): Promise<GraphData> => (s.source === "demo" ? demoGraph() : request<GraphData>(s, "/graph", 20_000)),
};

export const nvdUrl = (id: string) => `https://nvd.nist.gov/vuln/detail/${id}`;
export const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
