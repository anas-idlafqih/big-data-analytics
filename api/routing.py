"""Question router: sends aggregation questions to exact Cypher instead of the LLM.

The benchmark shows GraphRAG scores 2% F1 on counting/ranking questions (C) while the same
question answered by a Cypher query is exact. So the API classifies the question first:

  aggregate  counts, "most", "more than one"  -> templated Cypher, no LLM (exact, ~10 ms)
  lookup     a CVE id is named                -> graph retrieval + LLM (exact entity lookup)
  semantic   anything else                    -> hybrid retrieval (vector seeds + graph) + LLM

Pure functions where possible, so the classifier is unit-testable without Neo4j or Ollama.
"""
import re
from dataclasses import dataclass, field

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

CYPHER = {
    "vendor_most": """MATCH (v:Vendor)-[:PRODUCES]->(:Product)<-[:AFFECTS]-(c:CVE)
WITH v, count(DISTINCT c) AS n
WITH max(n) AS m, collect({name: v.name, n: n}) AS xs
UNWIND xs AS x WITH x, m WHERE x.n = m
RETURN x.name AS name, x.n AS n ORDER BY name""",
    "vendors_affected": """MATCH (v:Vendor)-[:PRODUCES]->(:Product)<-[:AFFECTS]-(:CVE)
RETURN count(DISTINCT v) AS n""",
    "chain_count": """MATCH (c:CVE) WHERE c.in_corpus AND (c)-[:CHAINED_WITH]-()
RETURN c.cve_id AS id ORDER BY id""",
    "products_multi": """MATCH (c:CVE)-[:AFFECTS]->(p:Product)
WITH p, count(DISTINCT c) AS n WHERE n > 1
RETURN p.name AS name, n ORDER BY n DESC, name""",
    "vendor_cves": """MATCH (:Vendor {name: $vendor})-[:PRODUCES]->(:Product)<-[:AFFECTS]-(c:CVE)
RETURN DISTINCT c.cve_id AS id ORDER BY id""",
}
VENDOR_LOOKUP = """MATCH (v:Vendor)
WHERE toLower(v.name) = $n OR $n IN [a IN coalesce(v.aliases, []) | toLower(a)]
RETURN v.name AS name LIMIT 1"""

LABELS = {
    "vendor_most": "Vendor with the most CVEs",
    "vendors_affected": "Count of affected vendors",
    "chain_count": "CVEs in exploit chains",
    "products_multi": "Products hit by several CVEs",
    "vendor_cves": "CVEs affecting a vendor",
}

_RULES = [
    ("vendor_most", re.compile(r"\b(vendor|company|manufacturer)\b.*\b(most|highest|largest|biggest)\b.*\bcves?\b"
                               r"|\bmost\b.*\bcves?\b.*\b(vendor|company)\b")),
    ("vendors_affected", re.compile(r"\bhow many\b.*\b(different |distinct )?(vendors|companies)\b")),
    ("chain_count", re.compile(r"\bhow many\b.*\bcves?\b.*\b(chain|chained)\b")),
    ("products_multi", re.compile(r"\bproducts?\b.*\b(more than one|multiple|several|at least two)\b.*\b(cves?|vulnerabilit)")),
]
_VENDOR_COUNT = re.compile(r"\bhow many\b.*\bcves?\b\s+(?:affect|affects|impact|impacts|target|targets)\s+(?P<name>.+?)\s*\??$")


@dataclass
class Route:
    kind: str                       # "aggregate" | "lookup" | "semantic"
    label: str
    reason: str
    template: str | None = None
    params: dict = field(default_factory=dict)

    def public(self) -> dict:
        return {"kind": self.kind, "label": self.label, "reason": self.reason}


def _clean_name(raw: str) -> str:
    name = re.sub(r"\b(products?|software|systems?)\b", "", raw.strip(" ?.!\"'"), flags=re.IGNORECASE)
    return re.sub(r"'s$", "", re.sub(r"\s+", " ", name).strip())


def classify(question: str) -> Route:
    q = " ".join(question.lower().split())
    if CVE_RE.search(question):
        return Route("lookup", "Exact CVE lookup", "A CVE id is named, so the graph resolves it exactly before the model reads it.")
    for template, rx in _RULES:
        if rx.search(q):
            return Route("aggregate", LABELS[template], "Counting and ranking are computed by a Cypher query, not guessed by the model.", template)
    m = _VENDOR_COUNT.search(q)
    if m and _clean_name(m.group("name")):
        return Route("aggregate", LABELS["vendor_cves"], "Counting and ranking are computed by a Cypher query, not guessed by the model.",
                     "vendor_cves", {"vendor_query": _clean_name(m.group("name"))})
    return Route("semantic", "Hybrid retrieval", "No exact entity or aggregation detected: vector search seeds the graph expansion.")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _join(xs: list[str]) -> str:
    return xs[0] if len(xs) == 1 else ", ".join(xs[:-1]) + " and " + xs[-1]


def execute(session, route: Route) -> dict | None:
    """Run the template. Returns None when it cannot be answered (e.g. unknown vendor) so the
    caller can fall back to graph retrieval."""
    t = route.template
    if t is None:
        return None
    ids: list[str] = []
    cypher = CYPHER[t]
    if t == "vendor_most":
        rows = session.run(cypher).data()
        if not rows:
            return None
        names = [r["name"] for r in rows]
        text = f"{_join(names)} ({_plural(rows[0]['n'], 'CVE')}{' each' if len(names) > 1 else ''})."
    elif t == "vendors_affected":
        n = session.run(cypher).single()["n"]
        text = f"{_plural(n, 'vendor')} {'has' if n == 1 else 'have'} products affected by a CVE."
    elif t == "chain_count":
        ids = [r["id"] for r in session.run(cypher).data()]
        text = f"{len(ids)} CVEs are part of an exploit chain."
    elif t == "products_multi":
        rows = session.run(cypher).data()
        if not rows:
            return None
        text = ", ".join(f"{r['name']} ({r['n']} CVEs)" for r in rows)
    else:  # vendor_cves
        found = session.run(VENDOR_LOOKUP, {"n": route.params["vendor_query"].lower()}).single()
        if not found:
            return None
        vendor = found["name"]
        ids = [r["id"] for r in session.run(cypher, {"vendor": vendor}).data()]
        cypher = cypher.replace("$vendor", f'"{vendor}"')
        text = f"{_plural(len(ids), 'CVE')} {'affects' if len(ids) == 1 else 'affect'} {vendor} products."
    return {"answer": text, "sources": ids, "context_cves": ids, "cypher": cypher}
