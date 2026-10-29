/* Numbers copied from benchmark/results.md (22 questions, one run per arm, local CPU laptop). */

export type Arm = "oracle_cypher" | "graph" | "text2cypher" | "vector";

export const ARMS: { id: Arm; label: string; hint: string; color: string }[] = [
  { id: "oracle_cypher", label: "Oracle Cypher", hint: "Hand-written Cypher — the ceiling", color: "#94a3b8" },
  { id: "graph", label: "GraphRAG", hint: "Graph retrieval + LLM", color: "#5eead4" },
  { id: "text2cypher", label: "Text2Cypher", hint: "LLM writes the Cypher", color: "#fbbf24" },
  { id: "vector", label: "Vector RAG", hint: "Embedding similarity + LLM", color: "#818cf8" },
];

export const OVERALL: Record<Arm, { precision: number; recall: number; f1: number; exact: number; latency: number | null; p95: number | null; sourcePrecision: number | null }> = {
  oracle_cypher: { precision: 100, recall: 100, f1: 100, exact: 100, latency: 0.008, p95: 0.014, sourcePrecision: null },
  vector: { precision: 37, recall: 31, f1: 32, exact: 23, latency: 23.3, p95: 30.0, sourcePrecision: 70 },
  graph: { precision: 63, recall: 51, f1: 54, exact: 36, latency: 15.9, p95: 24.2, sourcePrecision: 85 },
  text2cypher: { precision: 50, recall: 51, f1: 50, exact: 41, latency: 17.2, p95: 29.7, sourcePrecision: null },
};

export const BY_TYPE: { id: string; label: string; n: number; f1: Record<Arm, number> }[] = [
  { id: "A", label: "Factual · 1 hop", n: 6, f1: { oracle_cypher: 100, vector: 67, graph: 98, text2cypher: 83 } },
  { id: "B", label: "Multi-hop", n: 6, f1: { oracle_cypher: 100, vector: 37, graph: 88, text2cypher: 50 } },
  { id: "C", label: "Aggregation", n: 6, f1: { oracle_cypher: 100, vector: 0, graph: 2, text2cypher: 17 } },
  { id: "D", label: "Semantic", n: 4, f1: { oracle_cypher: 100, vector: 23, graph: 13, text2cypher: 49 } },
];

export const METRICS = [
  { id: "f1", label: "F1", unit: "%" },
  { id: "precision", label: "Precision", unit: "%" },
  { id: "recall", label: "Recall", unit: "%" },
  { id: "exact", label: "Exact match", unit: "%" },
] as const;
export type MetricId = (typeof METRICS)[number]["id"];
