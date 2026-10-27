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
*(To be completed)*

##  License
MIT License