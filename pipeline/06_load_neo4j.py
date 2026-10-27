"""Load the graph tables (data/processed/*.csv, produced by the Spark ETL) into Neo4j.

Idempotent: constraints and MERGE, so running it twice does not duplicate anything.
Use --reset to empty the database first (needed if the corpus shrank since the last load).

Graph model:
  (:CVE {cve_id, in_corpus, text, date_added, ransomware_use})
  (:Vendor {vendor_id, name, aliases})  -[:PRODUCES]->  (:Product {product_id, name, aliases})
  (:CVE) -[:AFFECTS {versions_raw, source}]-> (:Product)
  (:CVE) -[:CHAINED_WITH]-> (:CVE)         stored once (a < b); query it undirected
  (:CVE) -[:HAS_WEAKNESS {source}]-> (:Weakness {weakness_id, name})
  (:CVE) -[:MENTIONS_CWE]-> (:CWE {cwe_id})
  in_corpus = false marks stub CVEs that are only cited in a chain.

Connection: bolt://localhost:7687, user neo4j, password from NEO4J_PASSWORD or docker/.env.

Usage:
    python pipeline/06_load_neo4j.py
    python pipeline/06_load_neo4j.py --reset
"""
import argparse
import csv
import os
import time
from pathlib import Path

from neo4j import GraphDatabase

BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED = BASE_DIR / "data" / "processed"
ENV_FILE = BASE_DIR / "docker" / ".env"
URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
BATCH = 500

CONSTRAINTS = [
    "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.cve_id IS UNIQUE",
    "CREATE CONSTRAINT vendor_id IF NOT EXISTS FOR (n:Vendor) REQUIRE n.vendor_id IS UNIQUE",
    "CREATE CONSTRAINT product_id IF NOT EXISTS FOR (n:Product) REQUIRE n.product_id IS UNIQUE",
    "CREATE CONSTRAINT weakness_id IF NOT EXISTS FOR (n:Weakness) REQUIRE n.weakness_id IS UNIQUE",
    "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.cwe_id IS UNIQUE",
]

# (table, cypher, list-columns, boolean-columns)
LOADS = [
    ("cves", """UNWIND $rows AS r MERGE (c:CVE {cve_id: r.cve_id})
                SET c.in_corpus = r.in_corpus, c.text = r.text, c.ransomware_use = r.ransomware_use,
                    c.date_added = CASE WHEN r.date_added IS NULL THEN null ELSE date(r.date_added) END""",
     [], ["in_corpus"]),
    ("vendors", "UNWIND $rows AS r MERGE (v:Vendor {vendor_id: r.vendor_id}) SET v.name = r.name, v.aliases = r.aliases",
     ["aliases"], []),
    ("products", "UNWIND $rows AS r MERGE (p:Product {product_id: r.product_id}) SET p.name = r.name, p.aliases = r.aliases",
     ["aliases"], []),
    ("products", """UNWIND $rows AS r WITH r WHERE r.vendor_id IS NOT NULL
                    MATCH (v:Vendor {vendor_id: r.vendor_id}) MATCH (p:Product {product_id: r.product_id})
                    MERGE (v)-[:PRODUCES]->(p)""", ["aliases"], []),
    ("weaknesses", "UNWIND $rows AS r MERGE (w:Weakness {weakness_id: r.weakness_id}) SET w.name = r.name", [], []),
    ("cwes", "UNWIND $rows AS r MERGE (:CWE {cwe_id: r.cwe_id})", [], []),
    ("affects", """UNWIND $rows AS r MATCH (c:CVE {cve_id: r.cve_id}) MATCH (p:Product {product_id: r.product_id})
                   MERGE (c)-[a:AFFECTS]->(p) SET a.versions_raw = r.versions_raw, a.source = 'llm_extraction'""",
     ["versions_raw"], []),
    ("chained", """UNWIND $rows AS r MATCH (a:CVE {cve_id: r.cve_a}) MATCH (b:CVE {cve_id: r.cve_b})
                   MERGE (a)-[:CHAINED_WITH]->(b)""", [], []),
    ("has_weakness", """UNWIND $rows AS r MATCH (c:CVE {cve_id: r.cve_id}) MATCH (w:Weakness {weakness_id: r.weakness_id})
                        MERGE (c)-[h:HAS_WEAKNESS]->(w) SET h.source = 'llm_extraction'""", [], []),
    ("mentions_cwe", """UNWIND $rows AS r MATCH (c:CVE {cve_id: r.cve_id}) MATCH (x:CWE {cwe_id: r.cwe_id})
                        MERGE (c)-[:MENTIONS_CWE]->(x)""", [], []),
]


def get_password() -> str:
    if os.environ.get("NEO4J_PASSWORD"):
        return os.environ["NEO4J_PASSWORD"]
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith("NEO4J_PASSWORD="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("Neo4j password not found: set NEO4J_PASSWORD or fill docker/.env")


def read_table(name: str, list_cols: list[str], bool_cols: list[str]) -> list[dict]:
    path = PROCESSED / f"{name}.csv"
    if not path.exists():
        raise SystemExit(f"{path} not found. Run scripts/03_run_etl.ps1 first.")
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for raw in csv.DictReader(f):
            row = {k: (v if v != "" else None) for k, v in raw.items()}  # empty CSV cell = null
            for c in list_cols:
                row[c] = row[c].split("|") if row.get(c) else []
            for c in bool_cols:
                row[c] = (row[c] == "true")
            rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--reset", action="store_true", help="delete all nodes before loading")
    args = parser.parse_args()

    driver = GraphDatabase.driver(URI, auth=(USER, get_password()))
    for attempt in range(1, 13):  # Neo4j needs up to a minute after a start
        try:
            driver.verify_connectivity()
            break
        except Exception as e:
            if attempt == 12:
                raise SystemExit(f"Cannot connect to Neo4j at {URI}: {e}\nIs the stack up? (docker compose ... ps)")
            print(f"Waiting for Neo4j ({attempt}/12)...")
            time.sleep(5)

    with driver.session() as session:
        if args.reset:
            session.run("MATCH (n) DETACH DELETE n")
            print("Database emptied.")
        for q in CONSTRAINTS:
            session.run(q)

        cache: dict[str, list[dict]] = {}
        for table, query, list_cols, bool_cols in LOADS:
            key = f"{table}|{tuple(list_cols)}|{tuple(bool_cols)}"
            rows = cache.setdefault(key, read_table(table, list_cols, bool_cols))
            for i in range(0, len(rows), BATCH):
                session.run(query, rows=rows[i:i + BATCH])
            print(f"  loaded {table}: {len(rows)} rows")

        print("\nNodes:")
        for rec in session.run("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC"):
            print(f"  {rec['label']}: {rec['n']}")
        print("Relationships:")
        for rec in session.run("MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS n ORDER BY n DESC"):
            print(f"  {rec['rel']}: {rec['n']}")
    driver.close()
    print("\nNEO4J LOAD OK. Open http://localhost:7474")


if __name__ == "__main__":
    main()