"""Embed the CVE texts with a local Ollama model and create the Neo4j vector index.

Idempotent: only CVEs without an embedding are processed (use --force to redo everything,
for instance after changing the embedding model).

Prerequisite: ollama pull nomic-embed-text   (about 270 MB)

Usage:
    python pipeline/08_build_vector_index.py
    python pipeline/08_build_vector_index.py --force
"""
import argparse
import importlib
import os

import ollama_client

loader = importlib.import_module("06_load_neo4j")  # reuses URI, USER, get_password()

INDEX_NAME = "cve_embedding"
# nomic-embed-text expects a task prefix; set EMBED_DOC_PREFIX="" for models that do not
DOC_PREFIX = os.environ.get("EMBED_DOC_PREFIX", "search_document: ")
BATCH = 8
MAX_CHARS = 6000


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--force", action="store_true", help="re-embed everything and rebuild the index")
    args = parser.parse_args()

    driver = loader.GraphDatabase.driver(loader.URI, auth=(loader.USER, loader.get_password()))
    try:
        driver.verify_connectivity()
    except Exception as e:
        raise SystemExit(f"Cannot connect to Neo4j at {loader.URI}: {e}")

    with driver.session() as session:
        if args.force:
            session.run(f"DROP INDEX {INDEX_NAME} IF EXISTS").consume()
        where = "c.text IS NOT NULL" + ("" if args.force else " AND c.embedding IS NULL")
        rows = [r.data() for r in session.run(
            f"MATCH (c:CVE) WHERE {where} RETURN c.cve_id AS cve_id, c.text AS text ORDER BY cve_id")]
        print(f"{len(rows)} CVE text(s) to embed with {ollama_client.EMBED_MODEL}")

        dim = None
        try:
            for i in range(0, len(rows), BATCH):
                chunk = rows[i:i + BATCH]
                vectors = ollama_client.embed([DOC_PREFIX + r["text"][:MAX_CHARS] for r in chunk])
                dim = len(vectors[0])
                session.run(
                    "UNWIND $rows AS r MATCH (c:CVE {cve_id: r.cve_id}) SET c.embedding = r.embedding",
                    rows=[{"cve_id": r["cve_id"], "embedding": v} for r, v in zip(chunk, vectors)],
                ).consume()
                print(f"  embedded {min(i + BATCH, len(rows))}/{len(rows)}")
        except ollama_client.OllamaError as e:
            raise SystemExit(str(e))

        if dim is None:  # nothing new: read the dimension from an existing embedding
            rec = session.run("MATCH (c:CVE) WHERE c.embedding IS NOT NULL RETURN size(c.embedding) AS d LIMIT 1").single()
            if rec is None:
                raise SystemExit("No CVE text to embed. Is the graph loaded? (06_load_neo4j.py)")
            dim = rec["d"]

        session.run(
            f"CREATE VECTOR INDEX {INDEX_NAME} IF NOT EXISTS FOR (c:CVE) ON (c.embedding) "
            f"OPTIONS {{indexConfig: {{`vector.dimensions`: {dim}, `vector.similarity_function`: 'cosine'}}}}"
        ).consume()
        session.run("CALL db.awaitIndexes(120)").consume()
        print(f"Vector index '{INDEX_NAME}' ready ({dim} dimensions, cosine).")

        # self-test: a CVE must be its own nearest neighbour
        probe = session.run("MATCH (c:CVE) WHERE c.embedding IS NOT NULL RETURN c.cve_id AS id, c.embedding AS v LIMIT 1").single()
        hit = session.run(
            "CALL db.index.vector.queryNodes($i, 1, $v) YIELD node, score RETURN node.cve_id AS id, score",
            i=INDEX_NAME, v=probe["v"]).single()
        print(f"Self-test: {probe['id']} -> nearest {hit['id']} (score {hit['score']:.3f})",
              "OK" if hit["id"] == probe["id"] else "UNEXPECTED")
    driver.close()
    print("VECTOR INDEX OK")


if __name__ == "__main__":
    main()