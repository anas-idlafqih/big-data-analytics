# Cybersecurity Knowledge Graph & GraphRAG vs Graph Analytics Benchmark

##  Overview
This project builds a Knowledge Graph of software vulnerabilities (CVEs, Products, CWEs) extracted from public security advisories using an LLM. It then compares two analytical approaches:
1. **Graph Analytics**: Direct Cypher queries and Graph Data Science (GDS) algorithms.
2. **GraphRAG**: Retrieval from the graph combined with an LLM for natural language reasoning.

##  Architecture
- **Ingestion**: CISA KEV + NVD (JSON feeds) -> HDFS (pseudo-distributed)
- **Processing**: Apache Spark (local mode) for ETL and deduplication
- **LLM Extraction**: Ollama / Mistral API -> Prose advisories to structured JSON
- **Storage**: Neo4j (Knowledge Graph)
- **Evaluation**: Benchmark of Accuracy, Recall, Latency, and Explainability (provenance).

##  Project Structure
- `data/raw/`: Raw feeds (KEV, NVD, advisories)
- `data/processed/`: LLM-extracted JSON
- `pipeline/`: Python scripts (extraction, ETL, Neo4j loading)
- `benchmark/`: Test questions and results
- `docker/`: Infrastructure as Code (docker-compose)

##  How to Run
Frontend (React + Vite), from the repo root:

```bash
docker compose -f docker/docker-compose.yml up -d neo4j
python -m uvicorn api.app:app --port 8000
cd web && npm install && npm run dev      # http://127.0.0.1:5173
```

No backend running? The app falls back to built-in demo data (Settings > Data source).

Try the stack without the full pipeline (sample data, not real vulnerabilities):

```bash
python scripts/seed_demo_graph.py --fake-embeddings   # loads a small sample graph into an EMPTY Neo4j
python scripts/mock_ollama.py                         # stand-in for Ollama: canned answers, plumbing tests only
```

Tests:

```bash
pip install -r requirements-dev.txt && python -m pytest tests   # router, streaming parser, API contract
cd web && npm test                                              # triage scoring, analytics, SSE, demo router
```

API additions: `POST /ask` now takes `mode: auto|graph|vector` (auto routes aggregations to exact Cypher), `POST /ask/stream` streams
server-sent events, `GET /graph` feeds the explorer. Env: `ASK_CACHE_TTL`, `RATE_LIMIT_PER_MIN`, `CORS_ORIGINS`.

##  License
MIT License