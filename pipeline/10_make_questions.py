"""Generate the benchmark questions and their gold answers from the Neo4j graph.

~22 questions in 4 types, from templates (reproducible, seed 42):
  A factual       one hop: products of a CVE, vendor of a product, CVEs of a product
  B multi-hop     chained CVEs -> products; weakness -> vendors; product -> vendor -> sibling products
  C aggregation   most exposed vendor, counts, products hit by several CVEs
  D semantic      paraphrased questions; gold = CVEs whose text matches a keyword list ("silver" gold)

Gold answers are computed in Python from the graph (the whole graph is read once). Each question
also carries `evidence` (the CVEs supporting the gold, to score the declared sources) and `gold_cypher`: the hand-written query that produces the same answer. It is the
"oracle" of the structured approach and is documentation; --verify runs every one of them and
checks that Neo4j returns exactly the Python gold.

IMPORTANT: the gold describes the GRAPH (built from LLM extraction), not the real world.
Read benchmark/questions.json and check a sample by hand against the source texts.

Usage:
    python pipeline/10_make_questions.py
    python pipeline/10_make_questions.py --verify
"""
import argparse
import importlib
import json
import random
from collections import defaultdict
from pathlib import Path

loader = importlib.import_module("06_load_neo4j")  # reuses URI, USER, get_password()

BASE_DIR = Path(__file__).resolve().parent.parent
OUT = BASE_DIR / "benchmark" / "questions.json"
SEED = 42

SEMANTIC = [  # (question, keywords searched in the CVE text)
    ("Which vulnerabilities allow an attacker to read or access files they should not be able to reach?",
     ["path traversal", "directory traversal", "read arbitrary files", "arbitrary file read", "arbitrary file access",
      "read and write to arbitrary files", "files or directories accessible", "access specific files"]),
    ("Which vulnerabilities let someone get past the login or authentication step?",
     ["authentication bypass", "bypass authentication", "improper authentication", "missing authentication"]),
    ("Which vulnerabilities could let an attacker remotely run their own code or commands on the system?",
     ["remote code execution", "arbitrary code", "command injection", "execute arbitrary commands"]),
    ("Which vulnerabilities can crash a service or make it unavailable?",
     ["denial of service"]),
]


def lit(x) -> str:
    """Cypher literal for a string or a list of strings."""
    return json.dumps(x)


def load_graph(session) -> dict:
    def rows(q):
        return [r.data() for r in session.run(q)]
    return {
        "cves": {r["id"]: r for r in rows(
            "MATCH (c:CVE) RETURN c.cve_id AS id, c.in_corpus AS in_corpus, coalesce(c.text, '') AS text")},
        "products": {r["id"]: r for r in rows(
            "MATCH (p:Product) RETURN p.product_id AS id, p.name AS name, coalesce(p.aliases, []) AS aliases")},
        "vendors": {r["id"]: r for r in rows(
            "MATCH (v:Vendor) RETURN v.vendor_id AS id, v.name AS name, coalesce(v.aliases, []) AS aliases")},
        "produces": rows("MATCH (v:Vendor)-[:PRODUCES]->(p:Product) RETURN v.vendor_id AS v, p.product_id AS p"),
        "affects": rows("MATCH (c:CVE)-[:AFFECTS]->(p:Product) RETURN c.cve_id AS c, p.product_id AS p"),
        "chained": rows("MATCH (a:CVE)-[:CHAINED_WITH]-(b:CVE) RETURN a.cve_id AS a, b.cve_id AS b"),
        "weak": rows("MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:Weakness) RETURN c.cve_id AS c, w.weakness_id AS wid, w.name AS wname"),
    }


def build(g: dict) -> list[dict]:
    rng = random.Random(SEED)
    cves, products, vendors = g["cves"], g["products"], g["vendors"]
    in_corpus = {c for c, r in cves.items() if r["in_corpus"]}

    cve_products, product_cves = defaultdict(set), defaultdict(set)
    for r in g["affects"]:
        cve_products[r["c"]].add(r["p"])
        product_cves[r["p"]].add(r["c"])
    vendor_of = {r["p"]: r["v"] for r in g["produces"]}
    vendor_products, vendor_cves = defaultdict(set), defaultdict(set)
    for p, v in vendor_of.items():
        vendor_products[v].add(p)
        vendor_cves[v] |= product_cves[p]
    chain = defaultdict(set)
    for r in g["chained"]:
        chain[r["a"]].add(r["b"])
    weakness_cves, weakness_name = defaultdict(set), {}
    for r in g["weak"]:
        weakness_cves[r["wid"]].add(r["c"])
        weakness_name[r["wid"]] = r["wname"]

    prod = lambda pid: {"name": products[pid]["name"], "aliases": products[pid]["aliases"]}
    vend = lambda vid: {"name": vendors[vid]["name"], "aliases": vendors[vid]["aliases"]}
    cve_item = lambda c: {"name": c, "aliases": []}

    qs: list[dict] = []

    def add(qtype, sub, question, answer_type, gold, cypher, evidence, quality="exact (graph)"):
        """`evidence` = the CVE ids that support the gold answer (used to score declared sources)."""
        qs.append({"id": f"{qtype}{sub}-{sum(1 for q in qs if q['id'].startswith(qtype + sub)) + 1}",
                   "type": qtype, "question": question, "answer_type": answer_type,
                   "gold": gold, "gold_cypher": cypher, "evidence": sorted(set(evidence)),
                   "gold_quality": quality})

    # ---------------------------------------------------------------- A factual
    ordered = sorted((c for c in cve_products if c in in_corpus), key=lambda c: (-len(cve_products[c]), c))
    for c in list(dict.fromkeys(ordered[:1] + [x for x in ordered if len(cve_products[x]) == 2][:1])):
        add("A", "1", f"Which products does {c} affect?", "products",
            [prod(p) for p in sorted(cve_products[c])],
            f'MATCH (:CVE {{cve_id: {lit(c)}}})-[:AFFECTS]->(p:Product) RETURN DISTINCT p.name AS name', [c])

    name_count = defaultdict(int)
    for r in products.values():
        name_count[r["name"]] += 1
    cands = sorted(p for p in vendor_of if len(products[p]["name"]) >= 6 and name_count[products[p]["name"]] == 1)
    for p in rng.sample(cands, min(2, len(cands))):
        add("A", "2", f"Which vendor produces {products[p]['name']}?", "vendors", [vend(vendor_of[p])],
            f'MATCH (v:Vendor)-[:PRODUCES]->(:Product {{product_id: {lit(p)}}}) RETURN DISTINCT v.name AS name', sorted(product_cves[p]))

    multi = sorted((p for p in product_cves if len(product_cves[p]) >= 2), key=lambda p: (-len(product_cves[p]), p))
    for p in list(dict.fromkeys(multi[:1] + [x for x in multi if len(product_cves[x]) == 2][:1])):
        add("A", "3", f"Which CVEs affect {products[p]['name']}?", "cves",
            [cve_item(c) for c in sorted(product_cves[p])],
            f'MATCH (c:CVE)-[:AFFECTS]->(:Product {{product_id: {lit(p)}}}) RETURN DISTINCT c.cve_id AS name',
            sorted(product_cves[p]))

    # --------------------------------------------------------------- B multi-hop
    seeds, seen_gold = [], []
    for c in sorted(chain, key=lambda c: (-len({p for o in chain[c] for p in cve_products[o]}), c)):
        gold = {p for o in chain[c] for p in cve_products[o]}
        if c in in_corpus and gold and gold not in seen_gold:
            seeds.append((c, gold)); seen_gold.append(gold)
        if len(seeds) == 2:
            break
    for c, gold in seeds:
        add("B", "1", f"Which products are affected by the CVEs that are chained with {c}?", "products",
            [prod(p) for p in sorted(gold)],
            f'MATCH (:CVE {{cve_id: {lit(c)}}})-[:CHAINED_WITH]-(:CVE)-[:AFFECTS]->(p:Product) RETURN DISTINCT p.name AS name',
            [c] + sorted(o for o in chain[c] if cve_products[o]))

    wv = {w: {vendor_of[p] for c in cs for p in cve_products[c] if p in vendor_of} for w, cs in weakness_cves.items()}
    for w in sorted((w for w in wv if len(wv[w]) >= 2), key=lambda w: (-len(wv[w]), w))[:2]:
        add("B", "2", f'Which vendors have products affected by a CVE with the weakness "{weakness_name[w]}"?', "vendors",
            [vend(v) for v in sorted(wv[w])],
            f'MATCH (:Weakness {{weakness_id: {lit(w)}}})<-[:HAS_WEAKNESS]-(:CVE)-[:AFFECTS]->(:Product)<-[:PRODUCES]-(v:Vendor) '
            f'RETURN DISTINCT v.name AS name',
            sorted(c for c in weakness_cves[w] if c in in_corpus and any(p in vendor_of for p in cve_products[c])))

    for v in sorted((v for v in vendor_products if len(vendor_products[v]) >= 3), key=lambda v: (-len(vendor_products[v]), v))[:2]:
        p = sorted(vendor_products[v], key=lambda x: products[x]["name"])[0]
        others = sorted(vendor_products[v] - {p})
        add("B", "3", f"Which other products made by the same vendor as {products[p]['name']} are affected by CVEs in the corpus?",
            "products", [prod(o) for o in others],
            f'MATCH (:Product {{product_id: {lit(p)}}})<-[:PRODUCES]-(:Vendor)-[:PRODUCES]->(o:Product) '
            f'WHERE o.product_id <> {lit(p)} RETURN DISTINCT o.name AS name',
            sorted({c for o in others for c in product_cves[o]}))

    # -------------------------------------------------------------- C aggregation
    counts = {v: len(cs & in_corpus) for v, cs in vendor_cves.items()}
    if counts:
        top = max(counts.values())
        add("C", "1", "Which vendor has the most CVEs in the corpus?", "vendors",
            [vend(v) for v in sorted(v for v, n in counts.items() if n == top)],
            'MATCH (v:Vendor)-[:PRODUCES]->(:Product)<-[:AFFECTS]-(c:CVE) WITH v, count(DISTINCT c) AS n '
            'WITH max(n) AS m, collect([v.name, n]) AS xs UNWIND xs AS x WITH x, m WHERE x[1] = m RETURN x[0] AS name',
            sorted(set().union(*(vendor_cves[v] for v, n in counts.items() if n == top)) & in_corpus))
        mid = sorted(v for v, n in counts.items() if 2 <= n <= 8)
        for v in rng.sample(mid, min(2, len(mid))):
            add("C", "2", f"How many CVEs affect {vendors[v]['name']} products?", "number", {"value": counts[v]},
                f'MATCH (:Vendor {{vendor_id: {lit(v)}}})-[:PRODUCES]->(:Product)<-[:AFFECTS]-(c:CVE) RETURN count(DISTINCT c) AS n',
                sorted(vendor_cves[v] & in_corpus))
        add("C", "3", "How many CVEs in the corpus are part of an exploit chain?", "number",
            {"value": sum(1 for c in in_corpus if chain.get(c))},
            'MATCH (c:CVE) WHERE c.in_corpus AND (c)-[:CHAINED_WITH]-() RETURN count(c) AS n',
            sorted(c for c in in_corpus if chain.get(c)))
        add("C", "4", "Which products are affected by more than one CVE?", "products",
            [prod(p) for p in sorted(multi)],
            'MATCH (c:CVE)-[:AFFECTS]->(p:Product) WITH p, count(DISTINCT c) AS n WHERE n > 1 RETURN p.name AS name',
            sorted(set().union(*(product_cves[p] for p in multi))))
        add("C", "5", "How many different vendors are affected by CVEs in the corpus?", "number",
            {"value": sum(1 for n in counts.values() if n > 0)},
            'MATCH (v:Vendor)-[:PRODUCES]->(:Product)<-[:AFFECTS]-(:CVE) RETURN count(DISTINCT v) AS n', [])

    # ----------------------------------------------------------------- D semantic
    for question, kws in SEMANTIC:
        gold = sorted(c for c in in_corpus if any(k in cves[c]["text"].lower() for k in kws))
        if not gold:
            print(f"  (skipped, no CVE matches the keywords) {question}")
            continue
        add("D", "1", question, "cves", [cve_item(c) for c in gold],
            f'MATCH (c:CVE) WHERE c.in_corpus AND any(k IN {lit(kws)} WHERE toLower(c.text) CONTAINS k) '
            f'RETURN c.cve_id AS name', gold, quality="silver (keyword match on the CVE text)")
    return qs


def verify(session, questions: list[dict]) -> int:
    bad = 0
    for q in questions:
        rows = [list(r.data().values())[0] for r in session.run(q["gold_cypher"])]
        if q["answer_type"] == "number":
            ok = len(rows) == 1 and rows[0] == q["gold"]["value"]
        else:
            ok = set(rows) == {i["name"] for i in q["gold"]}
        print(f"  {'OK  ' if ok else 'DIFF'} {q['id']}")
        if not ok:
            bad += 1
            print(f"       python gold: {sorted(i['name'] for i in q['gold']) if q['answer_type'] != 'number' else q['gold']}")
            print(f"       cypher     : {sorted(map(str, rows))}")
    return bad


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--verify", action="store_true", help="run every gold_cypher and compare with the Python gold")
    args = parser.parse_args()

    driver = loader.GraphDatabase.driver(loader.URI, auth=(loader.USER, loader.get_password()))
    try:
        driver.verify_connectivity()
    except Exception as e:
        raise SystemExit(f"Cannot connect to Neo4j at {loader.URI}: {e}")
    with driver.session() as session:
        graph = load_graph(session)
        questions = build(graph)
        OUT.parent.mkdir(exist_ok=True)
        OUT.write_text(json.dumps({
            "meta": {"seed": SEED, "cves": len(graph["cves"]), "products": len(graph["products"]),
                     "vendors": len(graph["vendors"]),
                     "note": "Gold answers describe the graph built from LLM extraction, not the real world."},
            "questions": questions}, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"{len(questions)} questions written to {OUT}\n")
        for q in questions:
            size = q["gold"]["value"] if q["answer_type"] == "number" else f"{len(q['gold'])} item(s)"
            print(f"  {q['id']:<6} [{q['answer_type']:<8}] gold: {str(size):<10} {q['question']}")
        if args.verify:
            print("\nVerifying gold_cypher against the Python gold:")
            bad = verify(session, questions)
            print(f"\n{'ALL CONSISTENT' if not bad else str(bad) + ' DIFFERENCE(S): check the query or the gold'}")
    driver.close()


if __name__ == "__main__":
    main()