"""GraphRAG over the Neo4j knowledge graph, with a vector-only baseline.

Two modes (same index, same LLM, so the comparison is fair):
  vector : top-k CVE texts by embedding similarity (classic RAG, the graph is not used)
  graph  : the same top-k, plus
             * entity linking: the CVE ids written in the question and the CVEs of the
               vendors/products it names,
             * graph facts for every CVE (products, vendors, weaknesses, ransomware flag),
             * one hop along CHAINED_WITH edges (exploit chains)
           and everything is given to the LLM as a structured context.

The LLM must answer from the context only and return JSON {answer, sources}. The schema
restricts 'sources' to the retrieved CVE ids, so a source can never be invented; whether the
declared sources really support the answer is measured by the benchmark.

Usage:
    python pipeline/09_graphrag.py "Which Fortinet products are affected by path traversal?"
    python pipeline/09_graphrag.py "..." --mode vector --k 5 --show-context
Importable: answer(question, mode, k) returns a dict (used by the benchmark).
"""
import argparse
import importlib
import json
import os
import re
import time

import ollama_client

loader = importlib.import_module("06_load_neo4j")  # reuses URI, USER, get_password()

INDEX_NAME = "cve_embedding"
QUERY_PREFIX = os.environ.get("EMBED_QUERY_PREFIX", "search_query: ")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
MAX_LINKED = 6      # CVEs added by entity linking
MAX_CHAINED = 6     # CVEs added by the exploit-chain hop
SEED_VECTOR_K = 0   # vector hits kept when the question names CVE ids that exist in the graph

SYSTEM = (
    "You answer questions about software vulnerabilities using ONLY the context provided. "
    "Reply as JSON with two fields: 'answer' (concise) and 'sources' (the ids of the CVEs "
    "from the context that support the answer). If the context does not contain the answer, "
    "say so in 'answer' and leave 'sources' empty. Do not use outside knowledge."
)

FACTS_QUERY = """
MATCH (c:CVE) WHERE c.cve_id IN $ids
OPTIONAL MATCH (c)-[:AFFECTS]->(p:Product)
OPTIONAL MATCH (v:Vendor)-[:PRODUCES]->(p)
WITH c, collect(DISTINCT CASE WHEN p IS NULL THEN null
                              ELSE p.name + coalesce(' (' + v.name + ')', '') END) AS products
OPTIONAL MATCH (c)-[:HAS_WEAKNESS]->(w:Weakness)
WITH c, products, collect(DISTINCT w.name) AS weaknesses
OPTIONAL MATCH (c)-[:CHAINED_WITH]-(o:CVE)
RETURN c.cve_id AS cve_id, c.text AS text, c.ransomware_use AS ransomware,
       toString(c.date_added) AS date_added, products, weaknesses,
       collect(DISTINCT o.cve_id) AS chained"""

LINK_QUERY = """
MATCH (c:CVE)-[:AFFECTS]->(p:Product)
OPTIONAL MATCH (v:Vendor)-[:PRODUCES]->(p)
WITH c, p, v, toLower($q) AS q
WHERE any(n IN coalesce(p.aliases, []) + [p.name] WHERE size(n) >= 4 AND q CONTAINS toLower(n))
   OR (v IS NOT NULL AND any(n IN coalesce(v.aliases, []) + [v.name] WHERE size(n) >= 4 AND q CONTAINS toLower(n)))
RETURN DISTINCT c.cve_id AS cve_id ORDER BY cve_id LIMIT $limit"""


def vector_search(session, question: str, k: int) -> list[str]:
    qvec = ollama_client.embed([QUERY_PREFIX + question])[0]
    rows = session.run(
        "CALL db.index.vector.queryNodes($index, $k, $vec) YIELD node, score "
        "RETURN node.cve_id AS cve_id, score ORDER BY score DESC",
        {"index": INDEX_NAME, "k": k, "vec": qvec})
    return [r.data()["cve_id"] for r in rows]


def facts(session, ids: list[str]) -> list[dict]:
    if not ids:
        return []
    by_id = {r.data()["cve_id"]: r.data() for r in session.run(FACTS_QUERY, {"ids": ids})}
    return [by_id[i] for i in ids if i in by_id]  # keep the retrieval order


def block(f: dict, mode: str, text_chars: int) -> str:
    text = " ".join((f["text"] or "").split())
    text = text.split("CISA note:")[-1].strip() if "CISA note:" in text and mode == "graph" else text
    if mode == "vector":
        return f"[{f['cve_id']}] {text[:text_chars]}"
    lines = [f"[{f['cve_id']}] added {f['date_added'] or 'n/a'}; ransomware use: {f['ransomware'] or 'n/a'}",
             f"  Affects: {', '.join(f['products']) or 'n/a'}",
             f"  Weakness: {', '.join(f['weaknesses']) or 'n/a'}"]
    if f["chained"]:
        lines.append(f"  Chained with: {', '.join(f['chained'])}")
    lines.append(f"  Summary: {text[:text_chars]}")
    return "\n".join(lines)


def retrieve(question: str, mode: str = "graph", k: int = 5, driver=None) -> dict:
    """Retrieval half of answer(): the context text, its CVE ids and the retrieval time."""
    own_driver = driver is None
    if own_driver:
        driver = loader.GraphDatabase.driver(loader.URI, auth=(loader.USER, loader.get_password()))
    t0 = time.time()
    with driver.session() as session:
        ids = vector_search(session, question, k)
        linked, chained, chain_facts = [], [], []
        if mode == "graph":
            # entity linking, part 1: CVE ids written in the question (embeddings are poor at exact ids)
            seeds = list(dict.fromkeys(CVE_RE.findall(question)))
            known = {f["cve_id"] for f in facts(session, seeds)}
            seeds = [c for c in seeds if c in known]
            # an explicit entity is an exact lookup: it defines the context, vector hits would only add noise
            ids = seeds + [c for c in (ids[:SEED_VECTOR_K] if seeds else ids) if c not in seeds]
            linked = [c for c in (r.data()["cve_id"] for r in session.run(LINK_QUERY, {"q": question, "limit": MAX_LINKED}))
                      if c not in ids]
            main = facts(session, ids + linked)
            seen = set(ids + linked)
            for f in main:
                for o in f["chained"]:
                    if o not in seen and len(chained) < MAX_CHAINED:
                        chained.append(o)
                        seen.add(o)
            chain_facts = facts(session, chained)
            parts = [block(f, "graph", 350) for f in main]
            if chain_facts:
                parts.append("Related CVEs (exploit chains):")
                parts += [block(f, "graph", 200) for f in chain_facts]
        else:
            main = facts(session, ids)
            parts = [block(f, "vector", 700) for f in main]
    if own_driver:
        driver.close()
    retrieval_s = round(time.time() - t0, 2)

    context = "\n\n".join(parts)
    context_ids = [f["cve_id"] for f in main] + [f["cve_id"] for f in chain_facts]
    return {"context": context, "context_ids": context_ids, "retrieval_s": retrieval_s}


def _schema(context_ids: list[str]) -> dict:
    # the declared sources can only be CVE ids of the retrieved context (enum in the schema)
    id_schema = {"type": "string", "enum": context_ids} if context_ids else {"type": "string"}
    return {"type": "object", "required": ["answer", "sources"],
            "properties": {"answer": {"type": "string"},
                           "sources": {"type": "array", "items": id_schema}}}


def _finish(question: str, mode: str, ret: dict, result: dict) -> dict:
    context_ids = ret["context_ids"]
    try:
        parsed = json.loads(result["text"])
        answer_text, sources = str(parsed["answer"]), sorted(set(parsed.get("sources", [])))
    except (ValueError, KeyError, TypeError):  # should not happen with a schema; keep the raw text
        answer_text, sources = result["text"], []
    inline = sorted(set(CVE_RE.findall(answer_text)) - set(CVE_RE.findall(question)))
    return {
        "question": question, "mode": mode, "answer": answer_text,
        "context_cves": context_ids, "sources": sources,
        "cited_outside_context": [c for c in inline if c not in context_ids],
        "retrieval_s": ret["retrieval_s"], "generation_s": result["wall_s"],
        "prompt_tokens": result["prompt_tokens"], "output_tokens": result["output_tokens"],
        "context": ret["context"],
    }


def answer(question: str, mode: str = "graph", k: int = 5, driver=None, num_ctx: int = 8192) -> dict:
    ret = retrieve(question, mode, k, driver)
    result = ollama_client.chat(SYSTEM, f"Context:\n{ret['context']}\n\nQuestion: {question}",
                                num_ctx=num_ctx, schema=_schema(ret["context_ids"]))
    return _finish(question, mode, ret, result)


class AnswerStream:
    """Pulls the text of the "answer" field out of the partial JSON the model streams."""
    _START = re.compile(r'"answer"\s*:\s*"')

    def __init__(self) -> None:
        self.buf = ""
        self.sent = 0

    def feed(self, delta: str) -> str:
        """Add a chunk; return the newly decoded part of the answer ('' if there is none yet)."""
        self.buf += delta
        m = self._START.search(self.buf)
        if not m:
            return ""
        raw, i, esc = [], m.end(), False
        for ch in self.buf[i:]:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                break
            raw.append(ch)
        text = "".join(raw)
        tail = re.search(r"\\+$", text)
        if tail and len(tail.group()) % 2:      # a lone backslash: its escape is not complete yet
            text = text[:-1]
        text = re.sub(r"\\u[0-9a-fA-F]{0,3}$", "", text)
        try:
            decoded = json.loads(f'"{text}"')
        except ValueError:
            return ""
        out, self.sent = decoded[self.sent:], len(decoded)
        return out


def answer_stream(question: str, mode: str = "graph", k: int = 5, driver=None, num_ctx: int = 8192):
    """Generator version of answer(). Yields ("retrieval", ret), then ("token", text) while the
    answer is generated, then ("final", result) with the same dict answer() returns."""
    ret = retrieve(question, mode, k, driver)
    yield "retrieval", ret
    parser, result = AnswerStream(), None
    for kind, payload in ollama_client.chat_stream(
            SYSTEM, f"Context:\n{ret['context']}\n\nQuestion: {question}",
            num_ctx=num_ctx, schema=_schema(ret["context_ids"])):
        if kind == "delta":
            piece = parser.feed(payload)
            if piece:
                yield "token", piece
        else:
            result = payload
    yield "final", _finish(question, mode, ret, result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("question")
    parser.add_argument("--mode", choices=["graph", "vector"], default="graph")
    parser.add_argument("--k", type=int, default=5, help="CVEs retrieved by vector search")
    parser.add_argument("--show-context", action="store_true")
    args = parser.parse_args()
    try:
        r = answer(args.question, args.mode, args.k)
    except ollama_client.OllamaError as e:
        raise SystemExit(str(e))

    if args.show_context:
        print("--- CONTEXT SENT TO THE LLM ---\n" + r["context"] + "\n")
    print(f"[{r['mode']}] {r['question']}\n\n{r['answer']}\n")
    print(f"Retrieved CVEs ({len(r['context_cves'])}): {', '.join(r['context_cves'])}")
    print(f"Sources declared by the model: {', '.join(r['sources']) or 'none'}")
    if r["cited_outside_context"]:
        print(f"WARNING mentioned in the answer but NOT in the retrieved context: {', '.join(r['cited_outside_context'])}")
    print(f"Retrieval {r['retrieval_s']}s | generation {r['generation_s']}s | "
          f"tokens: prompt {r['prompt_tokens']}, output {r['output_tokens']}")


if __name__ == "__main__":
    main()