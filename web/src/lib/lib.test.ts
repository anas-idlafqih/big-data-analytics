import { describe, expect, it } from "vitest";
import { exposure, findings, matchStack, parseStackInput, levelOf, toCSV } from "./analytics";
import { buildDemoGraph, classify, demoAsk } from "./demo";
import { parseBlock, readSSE } from "./sse";

const g = buildDemoGraph();

describe("stack matching", () => {
  it("matches exact product names, ignoring versions and case", () => {
    const [m] = matchStack(g, ["netscaler adc 14.1"]);
    expect(m.products.map((p) => p.name)).toEqual(["NetScaler ADC"]);
    expect(m.via).toBe("product");
  });

  it("expands a vendor to its products", () => {
    const [m] = matchStack(g, ["Atlassian"]);
    expect(m.via).toBe("vendor");
    expect(m.products.length).toBe(8);
  });

  it("reports unknown software as not found", () => {
    expect(matchStack(g, ["Ubuntu 22.04"])[0].products).toEqual([]);
  });
});

describe("findings", () => {
  const f = findings(g, matchStack(g, ["NetScaler ADC", "Windows Shell"]));

  it("lists every CVE that hits the stack", () => {
    expect(f.map((x) => x.cve.name).sort()).toEqual(["CVE-2026-105133", "CVE-2026-19004", "CVE-2026-77310", "CVE-2026-88412"]);
  });

  it("ranks a ransomware CVE above a plain one", () => {
    const rans = f.find((x) => x.cve.name === "CVE-2026-19004")!;
    const plain = f.find((x) => x.cve.name === "CVE-2026-77310")!;
    expect(rans.score).toBeGreaterThan(plain.score);
  });

  it("flags a chain whose two halves are both in the stack", () => {
    const a = f.find((x) => x.cve.name === "CVE-2026-105133")!;
    expect(a.chainInStack).toEqual(["CVE-2026-88412"]);
    expect(a.reasons.join(" ")).toMatch(/chained with/);
  });

  it("is sorted by score, high to low, with scores capped at 100", () => {
    for (let i = 1; i < f.length; i++) expect(f[i - 1].score).toBeGreaterThanOrEqual(f[i].score);
    expect(Math.max(...f.map((x) => x.score))).toBeLessThanOrEqual(100);
  });

  it("maps scores to levels", () => {
    expect([levelOf(80), levelOf(55), levelOf(35), levelOf(10)]).toEqual(["Critical", "High", "Medium", "Low"]);
  });

  it("exports a CSV with a header and one row per CVE", () => {
    expect(toCSV(f).split("\n").length).toBe(f.length + 1);
  });
});

describe("stack input", () => {
  it("splits lines, commas and semicolons and removes duplicates", () => {
    expect(parseStackInput("A, B\nB;C")).toEqual(["A", "B", "C"]);
  });
  it("reads component names from a CycloneDX SBOM", () => {
    expect(parseStackInput(JSON.stringify({ components: [{ name: "FortiOS" }, { name: "Magento" }] }))).toEqual(["FortiOS", "Magento"]);
  });
});

describe("exposure", () => {
  const x = exposure(g);
  it("counts CVEs, ransomware and chains", () => {
    expect(x.cves).toBe(14);
    expect(x.ransomware).toBe(2);
    expect(x.chained).toBe(4);
    expect(x.clusters.length).toBe(2);
  });
  it("finds products hit more than once", () => {
    expect(x.topProducts.map((p) => p.name).sort()).toEqual(["NetScaler ADC", "Plex Media Server", "Windows Shell"]);
  });
});

describe("router (demo mirror of api/routing.py)", () => {
  it.each([
    ["Which products are affected by more than one CVE?", "aggregate"],
    ["Which vendor has the most CVEs in the corpus?", "aggregate"],
    ["How many CVEs affect Adobe products?", "aggregate"],
    ["Which products does CVE-2026-21589 affect?", "lookup"],
    ["Which vulnerabilities let someone bypass login?", "semantic"],
  ])("%s -> %s", (q, kind) => expect(classify(q).kind).toBe(kind));

  it("answers aggregation exactly, with Cypher and no LLM", async () => {
    const r = await demoAsk("Which products are affected by more than one CVE?", "auto");
    expect(r.mode).toBe("cypher");
    expect(r.answer).toBe("NetScaler ADC (2 CVEs), Plex Media Server (2 CVEs), Windows Shell (2 CVEs)");
    expect(r.cypher).toMatch(/MATCH/);
  });

  it("streams tokens before the final result", async () => {
    const seen: string[] = [];
    const r = await demoAsk("Which products does CVE-2026-31337 affect?", "auto", (e) => seen.push(e.type));
    expect(seen[0]).toBe("route");
    expect(seen).toContain("retrieval");
    expect(seen.filter((t) => t === "token").length).toBeGreaterThan(0);
    expect(r.sources).toEqual(["CVE-2026-31337"]);
  });

  it("can be cancelled", async () => {
    const ctrl = new AbortController();
    const p = demoAsk("Which products does CVE-2026-31337 affect?", "graph", () => {}, ctrl.signal);
    ctrl.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("SSE", () => {
  it("parses an event block and ignores comments", () => {
    expect(parseBlock('event: token\ndata: "hi"')).toEqual({ event: "token", data: "hi" });
    expect(parseBlock(": keep-alive")).toBeNull();
  });

  it("reassembles events split across network chunks", async () => {
    const enc = new TextEncoder();
    const parts = ['event: route\ndata: {"a"', ':1}\n\nevent: result\r\ndata: 2\r\n\r\n'];
    const body = new ReadableStream({ start(c) { parts.forEach((p) => c.enqueue(enc.encode(p))); c.close(); } });
    const out: unknown[] = [];
    for await (const e of readSSE(new Response(body))) out.push(e);
    expect(out).toEqual([{ event: "route", data: { a: 1 } }, { event: "result", data: 2 }]);
  });
});
