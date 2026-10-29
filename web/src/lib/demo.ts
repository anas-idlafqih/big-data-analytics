import type { AskResult, EdgeType, GEdge, GNode, GraphData, Health, NodeLabel, Progress, ReqMode, RouteInfo } from "./types";

/* A small graph rebuilt from facts that appear in the project's benchmark, so the whole UI
   can be explored without Neo4j or Ollama running. It mirrors the server-side router. */

const VENDORS: Record<string, string[]> = {
  Atlassian: ["Confluence Data Center", "Jira Software Data Center", "Jira Service Management Data Center",
    "Bitbucket Data Center", "Bamboo Data Center", "Crowd Data Center", "Crucible", "Fisheye"],
  Fortinet: ["FortiOS", "FortiMail"],
  Citrix: ["NetScaler ADC"],
  Adobe: ["Adobe Commerce", "Magento"],
  Microsoft: ["Windows Shell"],
  Cisco: ["IOS XE", "ASA"],
  "Palo Alto Networks": ["PAN-OS"],
  F5: ["BIG-IP APM"],
  Plex: ["Plex Media Server"],
  VMware: ["VeloCloud Orchestrator"],
  MikroTik: ["RouterOS"],
};

const CVES: { id: string; weakness: string; products: string[]; date: string; ransomware?: string; text: string }[] = [
  { id: "CVE-2026-21589", weakness: "Remote Code Execution", date: "2026-02-11", ransomware: "Known",
    products: VENDORS.Atlassian,
    text: "A template injection flaw in the Atlassian Data Center product line lets an authenticated attacker execute arbitrary code on the host." },
  { id: "CVE-2026-105133", weakness: "Authentication Bypass", date: "2026-03-02", products: ["NetScaler ADC"],
    text: "Improper session validation in NetScaler ADC allows an unauthenticated attacker to bypass the login flow." },
  { id: "CVE-2026-88412", weakness: "Privilege Escalation", date: "2026-03-02", products: ["Windows Shell"],
    text: "A race condition in the Windows Shell lets a local attacker elevate privileges. Observed chained after a NetScaler session bypass." },
  { id: "CVE-2026-77310", weakness: "Privilege Escalation", date: "2026-04-19", products: ["Windows Shell"],
    text: "Windows Shell mishandles a link target and lets a low-privileged user run code as SYSTEM." },
  { id: "CVE-2026-19004", weakness: "Remote Code Execution", date: "2026-05-07", ransomware: "Known", products: ["NetScaler ADC"],
    text: "A memory corruption bug in the NetScaler ADC gateway allows remote code execution." },
  { id: "CVE-2025-25249", weakness: "Remote Code Execution", date: "2026-01-14", products: ["FortiOS", "FortiMail"],
    text: "A heap overflow in the Fortinet management interface lets a remote attacker run arbitrary code." },
  { id: "CVE-2026-31337", weakness: "Remote Code Execution", date: "2026-02-27", products: ["Adobe Commerce", "Magento"],
    text: "Insecure deserialization in Adobe Commerce and Magento allows remote code execution." },
  { id: "CVE-2026-47021", weakness: "Authentication Bypass", date: "2026-04-03", products: ["PAN-OS"],
    text: "PAN-OS GlobalProtect fails to validate a token, allowing authentication bypass." },
  { id: "CVE-2026-52210", weakness: "Authentication Bypass", date: "2026-04-03", products: ["BIG-IP APM"],
    text: "BIG-IP APM access policy evaluation can be skipped by a crafted request." },
  { id: "CVE-2026-60118", weakness: "Privilege Escalation", date: "2026-05-21", products: ["IOS XE", "ASA"],
    text: "A web UI flaw in Cisco IOS XE and ASA lets an attacker create an admin account." },
  { id: "CVE-2026-96652", weakness: "Path Traversal", date: "2026-06-08", products: ["Plex Media Server"],
    text: "Plex Media Server allows reading arbitrary files through a crafted library path." },
  { id: "CVE-2026-96654", weakness: "Denial of Service", date: "2026-06-08", products: ["Plex Media Server"],
    text: "A malformed request crashes the Plex Media Server transcoder." },
  { id: "CVE-2026-71005", weakness: "Server-Side Request Forgery", date: "2026-05-30", products: ["VeloCloud Orchestrator"],
    text: "VeloCloud Orchestrator can be coerced into sending requests to internal hosts." },
  { id: "CVE-2026-33902", weakness: "Authentication Bypass", date: "2026-03-25", products: ["RouterOS"],
    text: "MikroTik RouterOS exposes an administrative endpoint without authentication." },
];

const CHAINS: [string, string][] = [
  ["CVE-2026-105133", "CVE-2026-88412"],
  ["CVE-2026-60118", "CVE-2026-52210"],
];

export function buildDemoGraph(): GraphData {
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  const add = (label: NodeLabel, name: string, extra: Partial<GNode> = {}) => {
    nodes.push({ id: `${label}:${name}`, label, name, in_corpus: true, ...extra });
  };
  const link = (a: string, b: string, type: EdgeType) => edges.push({ source: a, target: b, type });

  for (const [vendor, products] of Object.entries(VENDORS)) {
    add("Vendor", vendor);
    for (const p of products) {
      add("Product", p);
      link(`Vendor:${vendor}`, `Product:${p}`, "PRODUCES");
    }
  }
  const seen = new Set<string>();
  for (const c of CVES) {
    add("CVE", c.id, { text: c.text, date_added: c.date, ransomware: c.ransomware ?? "Unknown" });
    if (!seen.has(c.weakness)) { seen.add(c.weakness); add("Weakness", c.weakness); }
    link(`CVE:${c.id}`, `Weakness:${c.weakness}`, "HAS_WEAKNESS");
    for (const p of c.products) link(`CVE:${c.id}`, `Product:${p}`, "AFFECTS");
  }
  for (const [a, b] of CHAINS) link(`CVE:${a}`, `CVE:${b}`, "CHAINED_WITH");
  return { nodes, edges };
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("Aborted", "AbortError")); }, { once: true });
  });

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const graph = buildDemoGraph();
const vendorOf = new Map(graph.edges.filter((e) => e.type === "PRODUCES").map((e) => [e.target.slice(8), e.source.slice(7)]));

const affects = (id: string) =>
  graph.edges.filter((e) => e.source === `CVE:${id}` && e.type === "AFFECTS").map((e) => e.target.slice(8));
const chained = (id: string) =>
  graph.edges
    .filter((e) => e.type === "CHAINED_WITH" && (e.source === `CVE:${id}` || e.target === `CVE:${id}`))
    .map((e) => (e.source === `CVE:${id}` ? e.target : e.source).slice(4));
const cvesOfProduct = (p: string) =>
  graph.edges.filter((e) => e.type === "AFFECTS" && e.target === `Product:${p}`).map((e) => e.source.slice(4));
const nodeOf = (id: string) => graph.nodes.find((n) => n.id === `CVE:${id}`)!;

const join = (xs: string[]) => (xs.length > 1 ? `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}` : xs[0] ?? "");
const plural = (n: number, w: string) => (n === 1 ? `${n} ${w}` : `${n} ${w}s`);
const NOISE = ["CVE-2026-96654", "CVE-2026-71005", "CVE-2026-33902", "CVE-2026-47021", "CVE-2026-96652"];

/* ---- router (mirror of api/routing.py) ---- */
const RULES: [string, RegExp][] = [
  ["vendor_most", /\b(vendor|company|manufacturer)\b.*\b(most|highest|largest|biggest)\b.*\bcves?\b|\bmost\b.*\bcves?\b.*\b(vendor|company)\b/],
  ["vendors_affected", /\bhow many\b.*\b(different |distinct )?(vendors|companies)\b/],
  ["chain_count", /\bhow many\b.*\bcves?\b.*\b(chain|chained)\b/],
  ["products_multi", /\bproducts?\b.*\b(more than one|multiple|several|at least two)\b.*\b(cves?|vulnerabilit)/],
];
const LABELS: Record<string, string> = {
  vendor_most: "Vendor with the most CVEs", vendors_affected: "Count of affected vendors", chain_count: "CVEs in exploit chains",
  products_multi: "Products hit by several CVEs", vendor_cves: "CVEs affecting a vendor",
};
const CYPHER: Record<string, string> = {
  vendor_most: `MATCH (v:Vendor)-[:PRODUCES]->(:Product)<-[:AFFECTS]-(c:CVE)\nWITH v, count(DISTINCT c) AS n\nWITH max(n) AS m, collect({name: v.name, n: n}) AS xs\nUNWIND xs AS x WITH x, m WHERE x.n = m\nRETURN x.name AS name, x.n AS n ORDER BY name`,
  vendors_affected: `MATCH (v:Vendor)-[:PRODUCES]->(:Product)<-[:AFFECTS]-(:CVE)\nRETURN count(DISTINCT v) AS n`,
  chain_count: `MATCH (c:CVE) WHERE c.in_corpus AND (c)-[:CHAINED_WITH]-()\nRETURN c.cve_id AS id ORDER BY id`,
  products_multi: `MATCH (c:CVE)-[:AFFECTS]->(p:Product)\nWITH p, count(DISTINCT c) AS n WHERE n > 1\nRETURN p.name AS name, n ORDER BY n DESC, name`,
  vendor_cves: `MATCH (:Vendor {name: "%V"})-[:PRODUCES]->(:Product)<-[:AFFECTS]-(c:CVE)\nRETURN DISTINCT c.cve_id AS id ORDER BY id`,
};

export function classify(question: string): RouteInfo & { template?: string; vendor?: string } {
  const q = question.toLowerCase().replace(/\s+/g, " ").trim();
  if (question.match(CVE_RE)) return { kind: "lookup", label: "Exact CVE lookup", reason: "A CVE id is named, so the graph resolves it exactly before the model reads it." };
  const why = "Counting and ranking are computed by a Cypher query, not guessed by the model.";
  for (const [t, rx] of RULES) if (rx.test(q)) return { kind: "aggregate", label: LABELS[t], reason: why, template: t };
  const m = q.match(/\bhow many\b.*\bcves?\b\s+(?:affects?|impacts?|targets?)\s+(.+?)\s*\??$/);
  const name = m?.[1].replace(/\b(products?|software|systems?)\b/g, "").replace(/[?.!"']/g, "").trim();
  if (name) return { kind: "aggregate", label: LABELS.vendor_cves, reason: why, template: "vendor_cves", vendor: name };
  return { kind: "semantic", label: "Hybrid retrieval", reason: "No exact entity or aggregation detected: vector search seeds the graph expansion." };
}

function runTemplate(route: ReturnType<typeof classify>): Pick<AskResult, "answer" | "sources" | "context_cves" | "cypher"> | null {
  const t = route.template!;
  let cypher = CYPHER[t];
  const vendors = Object.keys(VENDORS);
  if (t === "vendor_most") {
    const counts = vendors.map((v) => [v, new Set(VENDORS[v].flatMap(cvesOfProduct)).size] as const);
    const max = Math.max(...counts.map((c) => c[1]));
    const top = counts.filter((c) => c[1] === max).map((c) => c[0]).sort();
    return { answer: `${join(top)} (${plural(max, "CVE")}${top.length > 1 ? " each" : ""}).`, sources: [], context_cves: [], cypher };
  }
  if (t === "vendors_affected") {
    const n = vendors.filter((v) => VENDORS[v].some((p) => cvesOfProduct(p).length)).length;
    return { answer: `${plural(n, "vendor")} ${n === 1 ? "has" : "have"} products affected by a CVE.`, sources: [], context_cves: [], cypher };
  }
  if (t === "chain_count") {
    const ids = [...new Set(CHAINS.flat())].sort();
    return { answer: `${ids.length} CVEs are part of an exploit chain.`, sources: ids, context_cves: ids, cypher };
  }
  if (t === "products_multi") {
    const rows = graph.nodes.filter((n) => n.label === "Product").map((p) => [p.name, cvesOfProduct(p.name).length] as const)
      .filter((r) => r[1] > 1).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    return rows.length ? { answer: rows.map((r) => `${r[0]} (${r[1]} CVEs)`).join(", "), sources: [], context_cves: [], cypher } : null;
  }
  const vendor = vendors.find((v) => v.toLowerCase() === route.vendor);
  if (!vendor) return null;
  const ids = [...new Set(VENDORS[vendor].flatMap(cvesOfProduct))].sort();
  cypher = cypher.replace("%V", vendor);
  return { answer: `${plural(ids.length, "CVE")} ${ids.length === 1 ? "affects" : "affect"} ${vendor} products.`, sources: ids, context_cves: ids, cypher };
}

function factBlock(id: string): string {
  const n = nodeOf(id);
  const prods = affects(id).map((p) => `${p} (${vendorOf.get(p)})`);
  const weak = graph.edges.find((e) => e.source === `CVE:${id}` && e.type === "HAS_WEAKNESS")?.target.slice(9);
  const ch = chained(id);
  return [`[${id}] added ${n.date_added}; ransomware use: ${n.ransomware}`, `  Affects: ${prods.join(", ")}`, `  Weakness: ${weak}`,
    ...(ch.length ? [`  Chained with: ${ch.join(", ")}`] : []), `  Summary: ${n.text}`].join("\n");
}
const textBlock = (id: string) => `[${id}] ${nodeOf(id).text}`;

type Emit = (e: { type: "route"; route: RouteInfo } | { type: "retrieval"; context_cves: string[] } | { type: "token"; text: string }) => void;

export async function demoAsk(question: string, mode: ReqMode, emit: Emit = () => {}, signal?: AbortSignal): Promise<AskResult> {
  const route = mode === "auto" ? classify(question) : null;
  const pub = route ? { kind: route.kind, label: route.label, reason: route.reason } : null;
  if (pub) emit({ type: "route", route: pub });
  const base = { route: pub, ungrounded: [] as string[], cached: false };

  if (route?.kind === "aggregate") {
    await sleep(220, signal);
    const out = runTemplate(route);
    if (out) return { ...base, mode: "cypher", ...out, retrieval_s: 0.01, generation_s: 0, context: null };
  }

  const effective = mode === "vector" ? "vector" : "graph";
  const t0 = effective === "graph" ? 0.4 : 1.1;
  const t1 = effective === "graph" ? 1.6 : 2.2;
  await sleep(t0 * 700, signal);

  const q = question.toLowerCase();
  const ids = [...new Set((question.match(CVE_RE) ?? []).map((s) => s.toUpperCase()))].filter((i) => graph.nodes.some((n) => n.id === `CVE:${i}`));
  let answer = "The retrieved context does not contain enough information to answer this question.";
  let sources: string[] = [];
  let context_cves: string[] = effective === "graph" ? [] : NOISE;

  if (ids.length && effective === "graph") {
    const id = ids[0];
    if (q.includes("chain")) {
      const c = chained(id);
      answer = c.length ? join(c) : `No CVE is chained with ${id} in the graph.`;
      sources = [id, ...c]; context_cves = [id, ...c];
    } else {
      answer = join(affects(id)) || `${id} is not linked to any product.`;
      sources = [id]; context_cves = [id];
    }
  } else if (ids.length) {
    answer = `No information about ${ids[0]} is provided in the context.`;
  } else {
    const hit = graph.nodes.find((n) => n.label !== "CVE" && q.includes(n.name.toLowerCase()));
    const cves = hit ? cvesOfProduct(hit.name) : [];
    if (hit && cves.length) {
      answer = `${hit.name} is affected by ${join(cves)}.`;
      sources = cves;
      context_cves = effective === "graph" ? cves : [...cves.slice(0, 2), ...NOISE].slice(0, 5);
    }
  }

  emit({ type: "retrieval", context_cves });
  await sleep(t1 * 250, signal);
  for (const w of answer.split(/(\s+)/)) { emit({ type: "token", text: w }); await sleep(22, signal); }
  const block = effective === "graph" ? factBlock : textBlock;
  return {
    ...base, mode: effective, answer, sources, context_cves,
    retrieval_s: +(t0 + Math.random() * 0.2).toFixed(2), generation_s: +(t1 + Math.random() * 0.5).toFixed(2),
    context: context_cves.map(block).join("\n\n") || null,
  };
}

export type { Progress };

export async function demoHealth(): Promise<Health> {
  await sleep(250);
  return { status: "ok", neo4j: true, ollama: true };
}

export async function demoGraph(): Promise<GraphData> {
  await sleep(350);
  return graph;
}
