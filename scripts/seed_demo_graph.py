"""Load a small SAMPLE graph into an empty Neo4j so the API and the web app can be tried
without running the whole pipeline (no HDFS, Spark or LLM extraction).

The CVE ids and texts are invented sample data shaped like the real graph; do not read the
answers as real vulnerability intelligence.

    python scripts/seed_demo_graph.py                     # refuses if the graph is not empty
    python scripts/seed_demo_graph.py --fake-embeddings   # no Ollama: hash vectors for the index
    python scripts/seed_demo_graph.py --force             # wipe the graph first (destructive!)
"""
import argparse
import hashlib
import importlib
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pipeline"))
loader = importlib.import_module("06_load_neo4j")
import ollama_client  # noqa: E402

DIM = 768
VENDORS = {
    "Atlassian": ["Confluence Data Center", "Jira Software Data Center", "Jira Service Management Data Center",
                  "Bitbucket Data Center", "Bamboo Data Center", "Crowd Data Center", "Crucible", "Fisheye"],
    "Fortinet": ["FortiOS", "FortiMail"], "Citrix": ["NetScaler ADC"], "Adobe": ["Adobe Commerce", "Magento"],
    "Microsoft": ["Windows Shell"], "Cisco": ["IOS XE", "ASA"], "Palo Alto Networks": ["PAN-OS"],
    "F5": ["BIG-IP APM"], "Plex": ["Plex Media Server"], "VMware": ["VeloCloud Orchestrator"], "MikroTik": ["RouterOS"],
}
A = VENDORS["Atlassian"]
CVES = [  # id, weakness, products, date, ransomware, text
    ("CVE-2026-21589", "Remote Code Execution", A, "2026-02-11", "Known", "A template injection flaw in the Atlassian Data Center product line lets an authenticated attacker execute arbitrary code."),
    ("CVE-2026-105133", "Authentication Bypass", ["NetScaler ADC"], "2026-03-02", "Unknown", "Improper session validation in NetScaler ADC allows an unauthenticated attacker to bypass the login flow."),
    ("CVE-2026-88412", "Privilege Escalation", ["Windows Shell"], "2026-03-02", "Unknown", "A race condition in the Windows Shell lets a local attacker elevate privileges. Observed chained after a NetScaler session bypass."),
    ("CVE-2026-77310", "Privilege Escalation", ["Windows Shell"], "2026-04-19", "Unknown", "Windows Shell mishandles a link target and lets a low-privileged user run code as SYSTEM."),
    ("CVE-2026-19004", "Remote Code Execution", ["NetScaler ADC"], "2026-05-07", "Known", "A memory corruption bug in the NetScaler ADC gateway allows remote code execution."),
    ("CVE-2025-25249", "Remote Code Execution", ["FortiOS", "FortiMail"], "2026-01-14", "Unknown", "A heap overflow in the Fortinet management interface lets a remote attacker run arbitrary code."),
    ("CVE-2026-31337", "Remote Code Execution", ["Adobe Commerce", "Magento"], "2026-02-27", "Unknown", "Insecure deserialization in Adobe Commerce and Magento allows remote code execution."),
    ("CVE-2026-47021", "Authentication Bypass", ["PAN-OS"], "2026-04-03", "Unknown", "PAN-OS GlobalProtect fails to validate a token, allowing authentication bypass."),
    ("CVE-2026-52210", "Authentication Bypass", ["BIG-IP APM"], "2026-04-03", "Unknown", "BIG-IP APM access policy evaluation can be skipped by a crafted request."),
    ("CVE-2026-60118", "Privilege Escalation", ["IOS XE", "ASA"], "2026-05-21", "Unknown", "A web UI flaw in Cisco IOS XE and ASA lets an attacker create an admin account."),
    ("CVE-2026-96652", "Path Traversal", ["Plex Media Server"], "2026-06-08", "Unknown", "Plex Media Server allows reading arbitrary files through a crafted library path."),
    ("CVE-2026-96654", "Denial of Service", ["Plex Media Server"], "2026-06-08", "Unknown", "A malformed request crashes the Plex Media Server transcoder."),
    ("CVE-2026-71005", "Server-Side Request Forgery", ["VeloCloud Orchestrator"], "2026-05-30", "Unknown", "VeloCloud Orchestrator can be coerced into sending requests to internal hosts."),
    ("CVE-2026-33902", "Authentication Bypass", ["RouterOS"], "2026-03-25", "Unknown", "MikroTik RouterOS exposes an administrative endpoint without authentication."),
]
CHAINS = [("CVE-2026-105133", "CVE-2026-88412"), ("CVE-2026-60118", "CVE-2026-52210")]


def fake_embed(text: str) -> list[float]:
    """Deterministic unit vector from the text hash (plumbing tests only, not semantic)."""
    out, i = [], 0
    while len(out) < DIM:
        d = hashlib.sha256(f"{i}:{text}".encode()).digest()
        out += [b / 255 - 0.5 for b in d]
        i += 1
    v = out[:DIM]
    n = math.sqrt(sum(x * x for x in v)) or 1
    return [x / n for x in v]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--force", action="store_true", help="delete every node first")
    ap.add_argument("--fake-embeddings", action="store_true", help="hash vectors instead of Ollama embeddings")
    args = ap.parse_args()
    embed = (lambda ts: [fake_embed(t) for t in ts]) if args.fake_embeddings else ollama_client.embed

    driver = loader.GraphDatabase.driver(loader.URI, auth=(loader.USER, loader.get_password()))
    with driver.session() as s:
        n = s.run("MATCH (n) RETURN count(n) AS n").single()["n"]
        if n and not args.force:
            raise SystemExit(f"The graph already holds {n} nodes; refusing to touch it (use --force to wipe it).")
        if n:
            s.run("MATCH (n) DETACH DELETE n").consume()
        for v, products in VENDORS.items():
            s.run("MERGE (v:Vendor {vendor_id: $v}) SET v.name = $v, v.aliases = [$v]", v=v).consume()
            for p in products:
                s.run("MATCH (v:Vendor {vendor_id: $v}) MERGE (p:Product {product_id: $p}) SET p.name = $p, p.aliases = [$p] "
                      "MERGE (v)-[:PRODUCES]->(p)", v=v, p=p).consume()
        vectors = embed([c[5] for c in CVES])
        for (cid, weak, prods, date, rans, text), vec in zip(CVES, vectors):
            s.run("MERGE (c:CVE {cve_id: $id}) SET c.in_corpus = true, c.text = $text, c.ransomware_use = $r, "
                  "c.date_added = date($d), c.embedding = $vec "
                  "MERGE (w:Weakness {weakness_id: $w}) SET w.name = $w MERGE (c)-[:HAS_WEAKNESS]->(w)",
                  id=cid, text=text, r=rans, d=date, vec=vec, w=weak).consume()
            for p in prods:
                s.run("MATCH (c:CVE {cve_id: $id}), (p:Product {product_id: $p}) MERGE (c)-[:AFFECTS]->(p)", id=cid, p=p).consume()
        for a, b in CHAINS:
            s.run("MATCH (a:CVE {cve_id: $a}), (b:CVE {cve_id: $b}) MERGE (a)-[:CHAINED_WITH]->(b)", a=a, b=b).consume()
        s.run(f"CREATE VECTOR INDEX cve_embedding IF NOT EXISTS FOR (c:CVE) ON (c.embedding) "
              f"OPTIONS {{indexConfig: {{`vector.dimensions`: {DIM}, `vector.similarity_function`: 'cosine'}}}}").consume()
        counts = s.run("MATCH (n) RETURN labels(n)[0] AS l, count(*) AS c ORDER BY l").data()
    driver.close()
    print("Sample graph loaded:", ", ".join(f"{r['l']} {r['c']}" for r in counts))


if __name__ == "__main__":
    main()
