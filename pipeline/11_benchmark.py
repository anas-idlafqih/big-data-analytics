"""Benchmark of four ways to answer questions over the knowledge graph.

Arms (same graph, same local LLM):
  oracle_cypher  the hand-written gold query: ceiling of the structured approach, and its latency
  vector         classic RAG: top-k CVE texts by embedding similarity
  graph          GraphRAG: vector hits + entity linking + graph facts + exploit-chain hop
  text2cypher    the LLM writes the Cypher query (schema in the prompt), we execute it

Scoring is automatic (no LLM judge):
  * list answers: the entities (products / vendors / CVE ids) mentioned in the answer are compared
    with the gold set -> precision, recall, F1. Mentions are found by name or alias, longest first.
  * number answers: the first integer of the answer must equal the gold value (CVE ids ignored).
  * sources (vector/graph): precision of the declared CVEs against the question's evidence CVEs.
Results are cached per (question, arm) in benchmark/results.json: the run can be interrupted and
resumed. Output: benchmark/results.md.

Usage (Neo4j + Ollama running, plugged in, other apps closed; about 1-1.5 h for everything):
    python pipeline/11_benchmark.py --limit 3            # quick trial
    python pipeline/11_benchmark.py
    python pipeline/11_benchmark.py --arms graph vector --types A B
    python pipeline/11_benchmark.py --report-only
"""
import argparse
import importlib
import json
import re
import statistics
import time
from pathlib import Path

from neo4j import READ_ACCESS, Query

import ollama_client

loader = importlib.import_module("06_load_neo4j")  # URI, USER, get_password(), GraphDatabase
rag = importlib.import_module("09_graphrag")       # answer()

BASE_DIR = Path(__file__).resolve().parent.parent
QUESTIONS = BASE_DIR / "benchmark" / "questions.json"
RESULTS = BASE_DIR / "benchmark" / "results.json"
REPORT = BASE_DIR / "benchmark" / "results.md"
ARMS = ["oracle_cypher", "vector", "graph", "text2cypher"]
# bump when an arm's prompt or retrieval changes: stale cached results are then recomputed
ARM_VERSION = {"oracle_cypher": "v1", "vector": "v1", "graph": "v2", "text2cypher": "v2"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
WRITE_RE = re.compile(r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD|CALL|FOREACH)\b", re.I)

TEXT2CYPHER_PROMPT = """You translate questions into read-only Cypher for a Neo4j graph about software vulnerabilities.
Graph schema:
(:CVE {cve_id, in_corpus, text, date_added, ransomware_use})   text = the advisory text
(:Vendor {vendor_id, name, aliases})
(:Product {product_id, name, aliases})
(:Weakness {weakness_id, name})
(:Vendor)-[:PRODUCES]->(:Product)
(:CVE)-[:AFFECTS]->(:Product)
(:CVE)-[:CHAINED_WITH]->(:CVE)    each pair is stored once, in one direction: always match it WITHOUT direction
(:CVE)-[:HAS_WEAKNESS]->(:Weakness)
Rules:
- Read-only query. Return only what the question asks, with readable values (name, cve_id).
- Use DISTINCT for lists and count(DISTINCT x) for counts.
- When the question gives a product, vendor or weakness name, match it with toLower(x.name) CONTAINS toLower('...').
- To select the CVEs of the corpus use c.in_corpus = true.
- For criteria on the described behaviour use toLower(c.text) CONTAINS '<keyword>' (any(...) over several keywords).
- Cypher is not SQL: there is no GROUP BY and no HAVING. Aggregations in RETURN or WITH group by the other
  returned values automatically; to filter on an aggregate, put it in a WITH clause and then use WHERE.
- Strings use single quotes.
Examples:
Q: Which products does CVE-2019-0001 affect?
A: MATCH (:CVE {cve_id: 'CVE-2019-0001'})-[:AFFECTS]->(p:Product) RETURN DISTINCT p.name AS name
Q: Which products are affected by the CVEs that are chained with CVE-2019-0002?
A: MATCH (:CVE {cve_id: 'CVE-2019-0002'})-[:CHAINED_WITH]-(:CVE)-[:AFFECTS]->(p:Product) RETURN DISTINCT p.name AS name
Q: How many CVEs affect Acme products?
A: MATCH (v:Vendor)-[:PRODUCES]->(:Product)<-[:AFFECTS]-(c:CVE) WHERE toLower(v.name) CONTAINS toLower('Acme') RETURN count(DISTINCT c) AS n
Reply as JSON: {"cypher": "<the query>"}."""

LOOKUPS: dict = {}  # entity type -> (surface form -> canonical name), filled in main()
_PATTERNS: dict = {}


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def build_lookup(rows: list[dict]) -> dict:
    """surface form -> canonical name. Forms of 2-3 characters (e.g. 'F5') are matched
    case-sensitively, longer ones case-insensitively."""
    lookup = {"long": {}, "short": {}}
    for r in rows:
        for form in [r["name"]] + list(r["aliases"]):
            if not form or len(form) < 2:
                continue
            if len(form) <= 3:
                lookup["short"].setdefault(form, r["name"])
            else:
                lookup["long"].setdefault(form.lower(), r["name"])
    return lookup


def _compile(forms, flags):
    if not forms:
        return None
    forms = sorted(forms, key=len, reverse=True)
    return re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(f) for f in forms) + r")(?![A-Za-z0-9])", flags)


def mentions(text: str, entity_type: str) -> set:
    """Canonical entities mentioned in the text (whole words, longest surface form first)."""
    lk = LOOKUPS[entity_type]
    if entity_type not in _PATTERNS:
        _PATTERNS[entity_type] = (_compile(lk["long"], re.I), _compile(lk["short"], 0))
    long_p, short_p = _PATTERNS[entity_type]
    found = set()
    if long_p:
        found |= {lk["long"][m.group(1).lower()] for m in long_p.finditer(text)}
    if short_p:
        found |= {lk["short"][m.group(1)] for m in short_p.finditer(text)}
    return found


def score(q: dict, answer: str) -> dict:
    kind = q["answer_type"]
    if kind == "number":
        nums = re.findall(r"\b\d+\b", CVE_RE.sub(" ", answer))
        ok = bool(nums) and int(nums[0]) == q["gold"]["value"]
        return {"precision": float(ok), "recall": float(ok), "f1": float(ok), "exact": ok, "predicted": nums[:1]}
    gold = {i["name"] for i in q["gold"]}
    pred = set(CVE_RE.findall(answer)) if kind == "cves" else mentions(answer, kind)
    tp = len(pred & gold)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(gold) if gold else 0.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0,
            "exact": pred == gold, "predicted": sorted(pred)}


def source_precision(q: dict, sources: list[str]):
    """Share of the declared sources that are evidence for the gold answer (None if not applicable)."""
    if not sources or not q.get("evidence"):
        return None
    return len(set(sources) & set(q["evidence"])) / len(set(sources))


# --------------------------------------------------------------------------- #
# Arms
# --------------------------------------------------------------------------- #
def rows_to_text(rows: list[dict]) -> str:
    return "; ".join(str(v) for row in rows[:300] for v in row.values())


def run_oracle(q, driver) -> dict:
    t0 = time.time()
    with driver.session(default_access_mode=READ_ACCESS) as s:
        rows = [r.data() for r in s.run(q["gold_cypher"])]
    return {"answer": rows_to_text(rows), "latency_s": round(time.time() - t0, 4), "cypher": q["gold_cypher"]}


def run_rag(q, driver, mode) -> dict:
    r = rag.answer(q["question"], mode=mode, k=5, driver=driver)
    return {"answer": r["answer"], "sources": r["sources"], "latency_s": round(r["retrieval_s"] + r["generation_s"], 2),
            "prompt_tokens": r["prompt_tokens"], "output_tokens": r["output_tokens"],
            "context_cves": r["context_cves"]}


def run_text2cypher(q, driver) -> dict:
    t0, ptok, otok, error, cypher = time.time(), 0, 0, None, None
    schema = {"type": "object", "required": ["cypher"], "properties": {"cypher": {"type": "string"}}}
    for attempt in (1, 2):
        user = f"Question: {q['question']}"
        if error:
            user += f"\nYour previous query:\n{cypher}\nfailed with: {error}\nWrite a corrected query."
        res = ollama_client.chat(TEXT2CYPHER_PROMPT, user, schema=schema, num_ctx=4096)
        ptok += res["prompt_tokens"] or 0
        otok += res["output_tokens"] or 0
        try:
            cypher = json.loads(res["text"])["cypher"].strip().rstrip(";")
        except (ValueError, KeyError, TypeError):
            error, cypher = "the reply was not valid JSON", res["text"]
            continue
        if WRITE_RE.search(cypher):
            error = "write operations are forbidden"
            continue
        try:
            with driver.session(default_access_mode=READ_ACCESS) as s:
                rows = [r.data() for r in s.run(Query(cypher, timeout=30))]
            return {"answer": rows_to_text(rows), "latency_s": round(time.time() - t0, 2), "prompt_tokens": ptok,
                    "output_tokens": otok, "cypher": cypher, "attempts": attempt, "error": None}
        except ollama_client.OllamaError:
            raise
        except Exception as e:
            error = str(e).splitlines()[0]
    return {"answer": "", "latency_s": round(time.time() - t0, 2), "prompt_tokens": ptok, "output_tokens": otok,
            "cypher": cypher, "attempts": 2, "error": error}


def needs_run(results: dict, qid: str, arm: str, force: bool) -> bool:
    rec = results.get(f"{qid}|{arm}")
    return force or rec is None or rec.get("version") != ARM_VERSION[arm]


def run_arm(arm, q, driver) -> dict:
    if arm == "oracle_cypher":
        return run_oracle(q, driver)
    if arm == "text2cypher":
        return run_text2cypher(q, driver)
    return run_rag(q, driver, arm)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def avg(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else None


def pct(x):
    return "-" if x is None else f"{100 * x:.0f}%"


def secs(x):
    return "-" if x is None else (f"{x * 1000:.0f} ms" if x < 0.5 else f"{x:.1f} s")


def build_report(questions: list[dict], results: dict, arms: list[str]) -> str:
    qmap = {q["id"]: q for q in questions}
    by_arm = {a: [(qmap[k.split("|")[0]], r) for k, r in results.items()
                  if k.endswith("|" + a) and k.split("|")[0] in qmap] for a in arms}
    L = ["# Benchmark results", "",
         f"{len(questions)} questions, {len({q['type'] for q in questions})} types. Local LLM and embedding model on a CPU laptop; "
         "one run per question and arm, so differences are indicative, not statistically established.", "",
         "## Overall (macro average over questions)", "",
         "| Arm | Questions | Precision | Recall | F1 | Exact | Latency median | Latency p95 | Prompt tok. | Output tok. | Source precision | Answers with sources |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for a in arms:
        rs = by_arm[a]
        if not rs:
            continue
        lat = sorted(r["latency_s"] for _, r in rs)
        sp = [source_precision(q, r.get("sources", [])) for q, r in rs if a in ("vector", "graph")]
        has_src = [bool(r.get("sources")) for _, r in rs if a in ("vector", "graph")]
        L.append(f"| {a} | {len(rs)} | {pct(avg([r['precision'] for _, r in rs]))} | {pct(avg([r['recall'] for _, r in rs]))} | "
                 f"{pct(avg([r['f1'] for _, r in rs]))} | {pct(avg([float(r['exact']) for _, r in rs]))} | "
                 f"{secs(statistics.median(lat))} | {secs(lat[min(len(lat) - 1, int(0.95 * len(lat)))])} | "
                 f"{avg([r.get('prompt_tokens') for _, r in rs]) and round(avg([r.get('prompt_tokens') for _, r in rs])) or '-'} | "
                 f"{avg([r.get('output_tokens') for _, r in rs]) and round(avg([r.get('output_tokens') for _, r in rs])) or '-'} | "
                 f"{pct(avg(sp))} | {pct(avg([float(h) for h in has_src])) if has_src else '-'} |")

    L += ["", "## F1 by question type", "", "| Type | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
    names = {"A": "A factual (1 hop)", "B": "B multi-hop", "C": "C aggregation", "D": "D semantic (silver gold)"}
    for t in sorted({q["type"] for q in questions}):
        cells = []
        for a in arms:
            xs = [r["f1"] for q, r in by_arm[a] if q["type"] == t]
            cells.append(f"{pct(avg(xs))} (n={len(xs)})" if xs else "-")
        L.append(f"| {names.get(t, t)} | " + " | ".join(cells) + " |")

    t2c = by_arm.get("text2cypher") or []
    if t2c:
        ok = [r for _, r in t2c if not r.get("error")]
        L += ["", "## Text2Cypher", "",
              f"- Valid and executed queries: {len(ok)}/{len(t2c)}; first-attempt success: "
              f"{sum(1 for _, r in t2c if r.get('attempts') == 1 and not r.get('error'))}/{len(t2c)}",
              "- Few-shot examples in the prompt follow the pattern of three templates (A1, B1, C2) with other entities."]

    L += ["", "## F1 per question", "", "| Question | Type | " + " | ".join(arms) + " |", "|---|---|" + "---|" * len(arms)]
    for q in questions:
        cells = []
        for a in arms:
            r = results.get(f"{q['id']}|{a}")
            cells.append("-" if r is None else f"{r['f1']:.2f}")
        L.append(f"| {q['id']} {q['question'][:70]} | {q['type']} | " + " | ".join(cells) + " |")

    L += ["", "## Failures (F1 < 0.5) for the RAG arms", ""]
    for q in questions:
        for a in ("vector", "graph"):
            r = results.get(f"{q['id']}|{a}")
            if r and r["f1"] < 0.5:
                gold = q["gold"]["value"] if q["answer_type"] == "number" else f"{len(q['gold'])} item(s)"
                L.append(f"- `{q['id']}` / {a}: gold {gold}; answer: {r['answer'][:140]!r}")

    bad_oracle = [q["id"] for q in questions
                  if (results.get(f"{q['id']}|oracle_cypher") or {}).get("f1", 1.0) < 1.0]
    if bad_oracle:
        L += ["", "## Scoring check", "",
              "The oracle arm must score 1.00 everywhere. It does not for: " + ", ".join(bad_oracle) +
              ". This points to a scoring artifact (an entity name that the matcher misses), not to a model error."]
    if t2c:
        L += ["", "## Text2Cypher: queries that did not give the gold answer", ""]
        for q in questions:
            r = results.get(f"{q['id']}|text2cypher")
            if r and r["f1"] < 1:
                L.append(f"- `{q['id']}` (F1 {r['f1']:.2f}): `{' '.join((r.get('cypher') or '').split())[:230]}`"
                         + (f" -> ERROR: {r['error'][:110]}" if r.get("error") else ""))

    L += ["", "## Reading notes", "",
          "- The gold answers describe the graph built from LLM extraction, not the real world; type D uses keyword matching (silver).",
          "- List answers are scored by entity mentions (name or alias): an answer that names extra entities is penalised in precision.",
          "- Number answers: the first integer of the answer must equal the gold value.",
          "- Latency is wall-clock on a CPU laptop and varies with machine load; compare arms within this run only.",
          "- Prompts were adjusted once after a 4-question pilot (graph v2: explicit CVE ids define the context; "
          "text2cypher v2: generic Cypher syntax hints). The pilot questions are part of this benchmark.",
          "- The oracle arm is correct by construction (it is the query that defines the gold): it shows the cost of a structured query, not an accuracy."]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def save_results(results: dict) -> None:
    tmp = RESULTS.with_suffix(".tmp")
    tmp.write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
    tmp.replace(RESULTS)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--arms", nargs="+", choices=ARMS, default=ARMS)
    parser.add_argument("--types", nargs="+", choices=list("ABCD"), default=list("ABCD"))
    parser.add_argument("--limit", type=int, default=None, help="questions per type")
    parser.add_argument("--force", action="store_true", help="redo cached results")
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--rescore", action="store_true",
                        help="recompute the scores of cached answers (after a scoring fix); no model call")
    args = parser.parse_args()

    if not QUESTIONS.exists():
        raise SystemExit("benchmark/questions.json not found. Run 10_make_questions.py first.")
    all_questions = json.loads(QUESTIONS.read_text(encoding="utf-8"))["questions"]
    questions = [q for q in all_questions if q["type"] in args.types]
    if args.limit:
        kept, count = [], {}
        for q in questions:
            count[q["type"]] = count.get(q["type"], 0) + 1
            if count[q["type"]] <= args.limit:
                kept.append(q)
        questions = kept
    results = json.loads(RESULTS.read_text(encoding="utf-8")) if RESULTS.exists() else {}

    if not args.report_only:
        driver = loader.GraphDatabase.driver(loader.URI, auth=(loader.USER, loader.get_password()))
        driver.verify_connectivity()
        with driver.session() as s:
            for etype, label in (("products", "Product"), ("vendors", "Vendor")):
                LOOKUPS[etype] = build_lookup([r.data() for r in s.run(
                    f"MATCH (x:{label}) RETURN x.name AS name, coalesce(x.aliases, []) AS aliases")])
        if args.rescore:
            qmap = {q["id"]: q for q in all_questions}
            for key, rec in results.items():
                if key.split("|")[0] in qmap:
                    rec.update(score(qmap[key.split("|")[0]], rec["answer"]))
            save_results(results)
            print(f"{len(results)} cached result(s) rescored.")
        todo = [] if args.rescore else [(q, a) for q in questions for a in args.arms if needs_run(results, q["id"], a, args.force)]
        print(f"{len(todo)} run(s) to do ({len(questions) * len(args.arms) - len(todo)} cached)")
        try:
            if any(a != "oracle_cypher" for _, a in todo):
                print("Warm-up (loading the models, not timed)...")
                ollama_client.embed(["warm-up"])
                ollama_client.chat("Reply OK.", "OK")
            for i, (q, a) in enumerate(todo, 1):
                try:
                    rec = run_arm(a, q, driver)
                except ollama_client.OllamaError:
                    raise
                except Exception as e:  # keep going: record the failure
                    rec = {"answer": "", "latency_s": 0.0, "error": f"{type(e).__name__}: {str(e).splitlines()[0]}"}
                rec.update(score(q, rec["answer"]))
                rec["version"] = ARM_VERSION[a]
                results[f"{q['id']}|{a}"] = rec
                save_results(results)
                print(f"[{i}/{len(todo)}] {q['id']:<6} {a:<14} F1 {rec['f1']:.2f}  {rec['latency_s']}s"
                      + (f"  ERROR {rec['error']}" if rec.get("error") else ""))
        except ollama_client.OllamaError as e:
            print(f"\nStopped: {e}\nResults so far are saved; re-run to resume.")
        driver.close()

    report = build_report(all_questions, results, args.arms)
    REPORT.write_text(report, encoding="utf-8")
    print(f"\nReport written to {REPORT}")


if __name__ == "__main__":
    main()