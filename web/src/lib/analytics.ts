import type { GNode, GraphData } from "./types";

/* Everything here is computed from the graph payload, so it works with live data and demo data. */

const norm = (s: string) =>
  s.toLowerCase().replace(/\bv?\d+(\.\d+)*[a-z]?\b/g, " ").replace(/[^a-z0-9]+/g, " ").trim();

export interface Match {
  input: string;
  products: GNode[];
  via: "product" | "vendor" | "none";
  confidence: number;
}

/** Turns a free-form product/vendor list into graph products. */
export function matchStack(g: GraphData, lines: string[]): Match[] {
  const products = g.nodes.filter((n) => n.label === "Product");
  const vendors = g.nodes.filter((n) => n.label === "Vendor");
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const productsOf = (v: GNode) => g.edges.filter((e) => e.type === "PRODUCES" && e.source === v.id).map((e) => byId.get(e.target)!).filter(Boolean);
  const tokens = (s: string) => new Set(norm(s).split(" ").filter(Boolean));

  return lines.map((raw) => {
    const input = raw.trim();
    const q = norm(input);
    if (q.length < 2) return { input, products: [], via: "none", confidence: 0 };

    const exact = products.filter((p) => norm(p.name) === q);
    if (exact.length) return { input, products: exact, via: "product", confidence: 1 };

    const qt = tokens(input);
    const fuzzy = products
      .map((p) => {
        const pt = tokens(p.name);
        const inter = [...qt].filter((t) => pt.has(t)).length;
        const contains = q.length >= 4 && (norm(p.name).includes(q) || q.includes(norm(p.name)));
        return { p, score: contains ? 0.8 : inter / Math.max(qt.size, pt.size, 1) };
      })
      .filter((x) => x.score >= 0.6)
      .sort((a, b) => b.score - a.score);
    if (fuzzy.length) {
      const best = fuzzy[0].score;
      return { input, products: fuzzy.filter((x) => x.score === best).map((x) => x.p), via: "product", confidence: best };
    }

    const v = vendors.find((x) => norm(x.name) === q || (q.length >= 4 && (norm(x.name).includes(q) || q.includes(norm(x.name)))));
    if (v) return { input, products: productsOf(v), via: "vendor", confidence: 0.7 };
    return { input, products: [], via: "none", confidence: 0 };
  });
}

export type Level = "Critical" | "High" | "Medium" | "Low";

export interface Finding {
  cve: GNode;
  products: string[];
  score: number;
  level: Level;
  reasons: string[];
  chainedWith: string[];
  chainInStack: string[];
}

const WEAKNESS_WEIGHT: [RegExp, number, string][] = [
  [/remote code|rce|code execution/i, 15, "remote code execution"],
  [/auth.*bypass|bypass.*auth/i, 12, "authentication bypass"],
  [/privilege/i, 8, "privilege escalation"],
];

export const levelOf = (score: number): Level => (score >= 70 ? "Critical" : score >= 50 ? "High" : score >= 30 ? "Medium" : "Low");

/** Which CVEs hit the stack, and how urgent each one is. The score is a transparent heuristic
 *  built from the fields the graph holds (no CVSS/EPSS yet), not an industry severity rating. */
export function findings(g: GraphData, matches: Match[]): Finding[] {
  const stack = new Set(matches.flatMap((m) => m.products.map((p) => p.id)));
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const dates = g.nodes.filter((n) => n.label === "CVE" && n.date_added).map((n) => Date.parse(n.date_added!));
  const latest = dates.length ? Math.max(...dates) : Date.now();

  const hits = new Map<string, Set<string>>();
  for (const e of g.edges) {
    if (e.type === "AFFECTS" && stack.has(e.target)) (hits.get(e.source) ?? hits.set(e.source, new Set()).get(e.source)!).add(e.target);
  }
  const partners = (id: string) =>
    g.edges.filter((e) => e.type === "CHAINED_WITH" && (e.source === id || e.target === id)).map((e) => (e.source === id ? e.target : e.source));
  const weakness = (id: string) => g.edges.find((e) => e.source === id && e.type === "HAS_WEAKNESS");

  const out: Finding[] = [];
  for (const [id, prods] of hits) {
    const cve = byId.get(id)!;
    let score = 10;
    const reasons: string[] = [];
    if (cve.ransomware === "Known") { score += 35; reasons.push("used in ransomware campaigns"); }
    const chained = partners(id);
    const inStack = chained.filter((p) => hits.has(p));
    if (inStack.length) { score += 25; reasons.push(`chained with ${inStack.map((p) => p.slice(4)).join(", ")}, also in your stack`); }
    else if (chained.length) { score += 10; reasons.push("part of an exploit chain"); }
    if (prods.size > 1) { score += Math.min(15, (prods.size - 1) * 5); reasons.push(`hits ${prods.size} of your products`); }
    if (cve.date_added) {
      const age = (latest - Date.parse(cve.date_added)) / 86_400_000;
      if (age <= 30) { score += 15; reasons.push("added in the last 30 days of the corpus"); }
      else if (age <= 90) { score += 8; reasons.push("added in the last 90 days of the corpus"); }
    }
    const w = weakness(id);
    const wn = w ? byId.get(w.target)?.name ?? "" : "";
    const hit = WEAKNESS_WEIGHT.find(([rx]) => rx.test(wn));
    if (hit) { score += hit[1]; reasons.push(hit[2]); }
    score = Math.min(100, score);
    out.push({
      cve, score, level: levelOf(score), reasons,
      products: [...prods].map((p) => byId.get(p)!.name).sort(),
      chainedWith: chained.map((p) => p.slice(4)), chainInStack: inStack.map((p) => p.slice(4)),
    });
  }
  return out.sort((a, b) => b.score - a.score || a.cve.name.localeCompare(b.cve.name));
}

const esc = (s: string) => `"${s.replace(/"/g, '""')}"`;

export function toCSV(f: Finding[]): string {
  const rows = f.map((x) => [x.cve.name, x.level, String(x.score), x.products.join("; "), x.cve.ransomware ?? "", x.cve.date_added ?? "", x.chainedWith.join("; "), x.reasons.join("; ")].map(esc).join(","));
  return ["cve,priority,score,your_products,ransomware,date_added,chained_with,why", ...rows].join("\n");
}

export function toMarkdown(f: Finding[], unmatched: string[]): string {
  const lines = [`# Exposure report`, "", `${f.length} CVEs affect your stack.`, ""];
  for (const lvl of ["Critical", "High", "Medium", "Low"] as Level[]) {
    const group = f.filter((x) => x.level === lvl);
    if (!group.length) continue;
    lines.push(`## ${lvl} (${group.length})`, "");
    for (const x of group) lines.push(`- **${x.cve.name}** (score ${x.score}) — ${x.products.join(", ")}. ${x.reasons.join("; ")}.`);
    lines.push("");
  }
  if (unmatched.length) lines.push("## Not found in the graph", "", ...unmatched.map((u) => `- ${u}`), "");
  lines.push("_Priority is a heuristic over ransomware use, exploit chains, breadth, recency and weakness type — not a CVSS score._");
  return lines.join("\n");
}

/** Parses pasted text, a CSV/TXT list, or a CycloneDX/SPDX-style JSON SBOM into product names. */
export function parseStackInput(text: string): string[] {
  const t = text.trim();
  if (t.startsWith("{")) {
    try {
      const j = JSON.parse(t);
      const comps: { name?: string }[] = j.components ?? j.packages ?? [];
      const names = comps.map((c) => c.name).filter((n): n is string => !!n);
      if (names.length) return [...new Set(names)];
    } catch { /* not JSON: fall through to plain text */ }
  }
  return [...new Set(t.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean))];
}

/* ---------------------------------------------------------------- exposure dashboard */

export interface Exposure {
  cves: number;
  ransomware: number;
  chained: number;
  vendors: number;
  topVendors: { name: string; cves: number; products: number }[];
  topProducts: { name: string; vendor: string; cves: number }[];
  weaknesses: { name: string; n: number }[];
  timeline: { month: string; n: number }[];
  clusters: string[][];
}

export function exposure(g: GraphData): Exposure {
  const byId = new Map(g.nodes.map((n) => [n.id, n]));
  const cves = g.nodes.filter((n) => n.label === "CVE");
  const vendorOf = new Map(g.edges.filter((e) => e.type === "PRODUCES").map((e) => [e.target, e.source]));
  const cvesOfProduct = new Map<string, Set<string>>();
  for (const e of g.edges) if (e.type === "AFFECTS") (cvesOfProduct.get(e.target) ?? cvesOfProduct.set(e.target, new Set()).get(e.target)!).add(e.source);

  const perVendor = new Map<string, { cves: Set<string>; products: number }>();
  for (const [p, set] of cvesOfProduct) {
    const v = vendorOf.get(p);
    if (!v) continue;
    const x = perVendor.get(v) ?? perVendor.set(v, { cves: new Set(), products: 0 }).get(v)!;
    set.forEach((c) => x.cves.add(c));
    x.products += 1;
  }
  const weak = new Map<string, number>();
  for (const e of g.edges) if (e.type === "HAS_WEAKNESS") { const n = byId.get(e.target)?.name; if (n) weak.set(n, (weak.get(n) ?? 0) + 1); }
  const months = new Map<string, number>();
  for (const c of cves) if (c.date_added) months.set(c.date_added.slice(0, 7), (months.get(c.date_added.slice(0, 7)) ?? 0) + 1);

  // connected components of CHAINED_WITH
  const adj = new Map<string, Set<string>>();
  for (const e of g.edges) if (e.type === "CHAINED_WITH") {
    (adj.get(e.source) ?? adj.set(e.source, new Set()).get(e.source)!).add(e.target);
    (adj.get(e.target) ?? adj.set(e.target, new Set()).get(e.target)!).add(e.source);
  }
  const seen = new Set<string>();
  const clusters: string[][] = [];
  for (const start of adj.keys()) {
    if (seen.has(start)) continue;
    const comp: string[] = [], stack = [start];
    while (stack.length) {
      const n = stack.pop()!;
      if (seen.has(n)) continue;
      seen.add(n); comp.push(n.slice(4));
      adj.get(n)?.forEach((m) => stack.push(m));
    }
    clusters.push(comp.sort());
  }

  return {
    cves: cves.length,
    ransomware: cves.filter((c) => c.ransomware === "Known").length,
    chained: seen.size,
    vendors: perVendor.size,
    topVendors: [...perVendor].map(([v, x]) => ({ name: byId.get(v)!.name, cves: x.cves.size, products: x.products }))
      .sort((a, b) => b.cves - a.cves || b.products - a.products || a.name.localeCompare(b.name)).slice(0, 8),
    topProducts: [...cvesOfProduct].map(([p, s]) => ({ name: byId.get(p)?.name ?? p, vendor: byId.get(vendorOf.get(p) ?? "")?.name ?? "", cves: s.size }))
      .sort((a, b) => b.cves - a.cves || a.name.localeCompare(b.name)).filter((x) => x.cves > 1).slice(0, 8),
    weaknesses: [...weak].map(([name, n]) => ({ name, n })).sort((a, b) => b.n - a.n),
    timeline: [...months].map(([month, n]) => ({ month, n })).sort((a, b) => a.month.localeCompare(b.month)),
    clusters: clusters.sort((a, b) => b.length - a.length),
  };
}
