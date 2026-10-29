export type Mode = "graph" | "vector";
/** What the API accepts: "auto" lets the router choose. */
export type ReqMode = "auto" | Mode;
export type AskMode = ReqMode | "compare";
export type NodeLabel = "CVE" | "Product" | "Vendor" | "Weakness";
export type EdgeType = "AFFECTS" | "PRODUCES" | "HAS_WEAKNESS" | "CHAINED_WITH";

export interface RouteInfo {
  kind: "aggregate" | "lookup" | "semantic";
  label: string;
  reason: string;
}

export interface AskResult {
  answer: string;
  /** Engine that actually ran; "cypher" = aggregation answered by a query, no LLM. */
  mode: Mode | "cypher";
  route?: RouteInfo | null;
  cypher?: string | null;
  context?: string | null;
  ungrounded?: string[];
  cached?: boolean;
  sources: string[];
  context_cves: string[];
  retrieval_s: number;
  generation_s: number;
}

export interface GNode {
  id: string;
  label: NodeLabel;
  name: string;
  in_corpus: boolean;
  text?: string | null;
  ransomware?: string | null;
  date_added?: string | null;
}

export interface GEdge {
  source: string;
  target: string;
  type: EdgeType;
}

export interface GraphData {
  nodes: GNode[];
  edges: GEdge[];
}

export interface Health {
  status: "ok" | "degraded";
  neo4j: boolean;
  ollama: boolean;
}

export interface Progress {
  route?: RouteInfo;
  context_cves?: string[];
  text?: string;
}

export type Outcome =
  | ({ state: "loading"; startedAt: number } & Progress)
  | { state: "done"; data: AskResult }
  | { state: "error"; message: string };

export interface Turn {
  id: number;
  question: string;
  mode: AskMode;
  outcomes: Partial<Record<ReqMode, Outcome>>;
  createdAt: number;
}

export interface Settings {
  apiUrl: string;
  apiKey: string;
  source: "live" | "demo";
  theme: "dark" | "light";
}
