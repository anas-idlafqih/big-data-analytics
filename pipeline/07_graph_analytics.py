"""Graph analytics on the Neo4j knowledge graph: Cypher queries and GDS algorithms.

Writes benchmark/graph_analytics.md with, for every analysis, the question, the Cypher used
and the result. Each step is isolated: if one fails, the error is reported and the others run.

Usage (Neo4j up, graph loaded by 06_load_neo4j.py):
    python pipeline/07_graph_analytics.py
"""
import importlib
from pathlib import Path

loader = importlib.import_module("06_load_neo4j")  # reuses URI, USER and get_password()
GraphDatabase = loader.GraphDatabase

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT = BASE_DIR / "benchmark" / "graph_analytics.md"

CYPHER_ANALYSES = [
    ("Data quality: CVEs of the corpus without any product",
     "How many CVEs have no AFFECTS relationship? (extraction gaps)",
     """MATCH (c:CVE) WHERE c.in_corpus AND NOT (c)-[:AFFECTS]->()
RETURN count(c) AS cves_without_product"""),

    ("Most exposed vendors",
     "Which vendors have the most distinct CVEs affecting their products? (aggregation over 3 hops)",
     """MATCH (v:Vendor)-[:PRODUCES]->(p:Product)<-[:AFFECTS]-(c:CVE)
RETURN v.name AS vendor, count(DISTINCT p) AS products, count(DISTINCT c) AS cves
ORDER BY cves DESC, products DESC LIMIT 10"""),

    ("Products hit by several CVEs",
     "Which products are affected by more than one CVE?",
     """MATCH (c:CVE)-[:AFFECTS]->(p:Product)
WITH p, collect(c.cve_id) AS cves WHERE size(cves) > 1
OPTIONAL MATCH (v:Vendor)-[:PRODUCES]->(p)
RETURN p.name AS product, v.name AS vendor, size(cves) AS n_cves, cves
ORDER BY n_cves DESC"""),

    ("Exploit chains",
     "Which CVEs are chained together, and which products do they affect? (CISA 'chained with')",
     """MATCH (a:CVE)-[:CHAINED_WITH]->(b:CVE)
OPTIONAL MATCH (a)-[:AFFECTS]->(pa:Product)
OPTIONAL MATCH (b)-[:AFFECTS]->(pb:Product)
RETURN a.cve_id AS cve_a, collect(DISTINCT pa.name) AS products_a,
       b.cve_id AS cve_b, collect(DISTINCT pb.name) AS products_b
ORDER BY cve_a"""),

    ("Weaknesses shared across vendors",
     "Which weakness types appear in CVEs of several vendors? (CVE -> Weakness, CVE -> Product <- Vendor)",
     """MATCH (w:Weakness)<-[:HAS_WEAKNESS]-(c:CVE)-[:AFFECTS]->(:Product)<-[:PRODUCES]-(v:Vendor)
WITH w, collect(DISTINCT v.name) AS vendors, count(DISTINCT c) AS cves
WHERE cves > 1
RETURN w.name AS weakness, cves, vendors ORDER BY cves DESC LIMIT 10"""),

    ("Known ransomware use by vendor",
     "Which vendors have CVEs flagged by CISA with known ransomware campaign use?",
     """MATCH (c:CVE {ransomware_use: 'Known'})-[:AFFECTS]->(:Product)<-[:PRODUCES]-(v:Vendor)
RETURN v.name AS vendor, count(DISTINCT c) AS cves ORDER BY cves DESC LIMIT 10"""),
]

PROJECTION = """CALL gds.graph.project(
  'cyber', ['CVE', 'Product', 'Vendor', 'Weakness'],
  {AFFECTS: {orientation: 'UNDIRECTED'}, PRODUCES: {orientation: 'UNDIRECTED'},
   HAS_WEAKNESS: {orientation: 'UNDIRECTED'}, CHAINED_WITH: {orientation: 'UNDIRECTED'}})
YIELD nodeCount, relationshipCount RETURN nodeCount, relationshipCount"""

GDS_ANALYSES = [
    ("PageRank: most central nodes",
     "Which nodes are the most connected to other well-connected nodes?",
     """CALL gds.pageRank.stream('cyber') YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS n, score
RETURN labels(n)[0] AS label, coalesce(n.name, n.cve_id) AS name, round(score, 3) AS score
ORDER BY score DESC LIMIT 10"""),

    ("Betweenness: bridge nodes",
     "Which nodes connect otherwise separate groups? (shortest paths going through them)",
     """CALL gds.betweenness.stream('cyber') YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS n, score WHERE score > 0
RETURN labels(n)[0] AS label, coalesce(n.name, n.cve_id) AS name, round(score, 2) AS score
ORDER BY score DESC LIMIT 10"""),

    ("Louvain: communities",
     "Which groups of CVEs, products, vendors and weaknesses are densely connected?",
     """CALL gds.louvain.stream('cyber') YIELD nodeId, communityId
WITH communityId, gds.util.asNode(nodeId) AS n
RETURN communityId, count(*) AS size,
       collect(CASE WHEN n:Vendor THEN n.name END)[..5] AS vendors,
       collect(CASE WHEN n:CVE THEN n.cve_id END)[..4] AS sample_cves
ORDER BY size DESC LIMIT 8"""),

    ("Connected components",
     "How fragmented is the graph? (component size -> number of components)",
     """CALL gds.wcc.stream('cyber') YIELD nodeId, componentId
WITH componentId, count(*) AS size
RETURN size AS component_size, count(*) AS components ORDER BY component_size DESC"""),
]


def fmt(value) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    text = "" if value is None else str(value)
    return text if len(text) < 90 else text[:87] + "..."


def md_table(rows: list[dict]) -> str:
    if not rows:
        return "_No result._"
    cols = list(rows[0].keys())
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(fmt(r[c]).replace("|", "/") for c in cols) + " |" for r in rows]
    return "\n".join(lines)


def run_step(session, title: str, question: str, query: str, out: list[str]) -> None:
    out += [f"### {title}", "", f"*{question}*", "", "```cypher", query, "```", ""]
    try:
        rows = [r.data() for r in session.run(query)]
        out += [md_table(rows), ""]
        print(f"  OK   {title} ({len(rows)} rows)")
    except Exception as e:
        out += [f"**Failed:** `{e}`", ""]
        print(f"  FAIL {title}: {str(e).splitlines()[0]}")


def main() -> None:
    driver = GraphDatabase.driver(loader.URI, auth=(loader.USER, loader.get_password()))
    try:
        driver.verify_connectivity()
    except Exception as e:
        raise SystemExit(f"Cannot connect to Neo4j at {loader.URI}: {e}")

    out = ["# Graph analytics", ""]
    with driver.session() as session:
        counts = [r.data() for r in session.run("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC")]
        out += ["## Graph size", "", md_table(counts), "", "## Cypher analyses", ""]
        print("Cypher analyses:")
        for title, question, query in CYPHER_ANALYSES:
            run_step(session, title, question, query, out)

        out += ["## Graph Data Science analyses", ""]
        print("GDS analyses:")
        try:
            session.run("CALL gds.graph.drop('cyber', false)").consume()
            info = session.run(PROJECTION).single()
            out += [f"Projected graph `cyber`: {info['nodeCount']} nodes, {info['relationshipCount']} relationships "
                    "(all relationship types, undirected).", ""]
            for title, question, query in GDS_ANALYSES:
                run_step(session, title, question, query, out)
            session.run("CALL gds.graph.drop('cyber', false)").consume()
        except Exception as e:
            out += [f"**GDS projection failed:** `{e}`", ""]
            print(f"  FAIL GDS projection: {str(e).splitlines()[0]}")
    driver.close()

    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"\nReport written to {REPORT}")


if __name__ == "__main__":
    main()