# Graph analytics

## Graph size

| label | n |
|---|---|
| Weakness | 77 |
| CVE | 61 |
| Product | 59 |
| Vendor | 31 |
| CWE | 1 |

## Cypher analyses

### Data quality: CVEs of the corpus without any product

*How many CVEs have no AFFECTS relationship? (extraction gaps)*

```cypher
MATCH (c:CVE) WHERE c.in_corpus AND NOT (c)-[:AFFECTS]->()
RETURN count(c) AS cves_without_product
```

| cves_without_product |
|---|
| 0 |

### Most exposed vendors

*Which vendors have the most distinct CVEs affecting their products? (aggregation over 3 hops)*

```cypher
MATCH (v:Vendor)-[:PRODUCES]->(p:Product)<-[:AFFECTS]-(c:CVE)
RETURN v.name AS vendor, count(DISTINCT p) AS products, count(DISTINCT c) AS cves
ORDER BY cves DESC, products DESC LIMIT 10
```

| vendor | products | cves |
|---|---|---|
| Cisco | 4 | 5 |
| Microsoft | 4 | 4 |
| Citrix | 2 | 4 |
| Plex | 1 | 4 |
| Fortinet | 5 | 3 |
| MikroTik | 1 | 3 |
| Google | 2 | 2 |
| Adobe | 2 | 2 |
| Check Point | 2 | 2 |
| Zammad GmbH | 1 | 2 |

### Products hit by several CVEs

*Which products are affected by more than one CVE?*

```cypher
MATCH (c:CVE)-[:AFFECTS]->(p:Product)
WITH p, collect(c.cve_id) AS cves WHERE size(cves) > 1
OPTIONAL MATCH (v:Vendor)-[:PRODUCES]->(p)
RETURN p.name AS product, v.name AS vendor, size(cves) AS n_cves, cves
ORDER BY n_cves DESC
```

| product | vendor | n_cves | cves |
|---|---|---|---|
| NetScaler Gateway | Citrix | 4 | CVE-2026-88772, CVE-2026-19490, CVE-2026-88771, CVE-2026-88779 |
| Plex Media Server | Plex | 4 | CVE-2026-96652, CVE-2026-96656, CVE-2026-96654, CVE-2026-96655 |
| NetScaler ADC | Citrix | 4 | CVE-2026-88779, CVE-2026-19490, CVE-2026-88771, CVE-2026-88772 |
| RouterOS | MikroTik | 3 | CVE-2026-67277, CVE-2026-86060, CVE-2026-67279 |
| Linux kernel |  | 3 | CVE-2025-39964, CVE-2025-39682, CVE-2026-53266 |
| Adobe Commerce | Adobe | 2 | CVE-2026-75650, CVE-2026-71362 |
| FortiSwitchManager | Fortinet | 2 | CVE-2025-61624, CVE-2025-25249 |
| FortiOS | Fortinet | 2 | CVE-2025-25249, CVE-2025-61624 |
| Artifactory | JFrog | 2 | CVE-2026-42016, CVE-2026-42018 |
| Secure Email Gateway | Cisco | 2 | CVE-2026-76461, CVE-2026-76519 |
| Zammad | Zammad GmbH | 2 | CVE-2026-102490, CVE-2026-102489 |
| VeloCloud Orchestrator | Arista | 2 | CVE-2026-114625, CVE-2026-93952 |
| Ahsay AhsayCBS | Ahsay | 2 | CVE-2026-105134, CVE-2026-105133 |

### Exploit chains

*Which CVEs are chained together, and which products do they affect? (CISA 'chained with')*

```cypher
MATCH (a:CVE)-[:CHAINED_WITH]->(b:CVE)
OPTIONAL MATCH (a)-[:AFFECTS]->(pa:Product)
OPTIONAL MATCH (b)-[:AFFECTS]->(pb:Product)
RETURN a.cve_id AS cve_a, collect(DISTINCT pa.name) AS products_a,
       b.cve_id AS cve_b, collect(DISTINCT pb.name) AS products_b
ORDER BY cve_a
```

| cve_a | products_a | cve_b | products_b |
|---|---|---|---|
| CVE-2023-22621 |  | CVE-2023-22894 | Strapi |
| CVE-2026-102489 | Zammad | CVE-2026-102490 | Zammad |
| CVE-2026-105133 | Ahsay AhsayCBS | CVE-2026-105134 | Ahsay AhsayCBS |
| CVE-2026-96652 | Plex Media Server | CVE-2026-96654 | Plex Media Server |
| CVE-2026-96652 | Plex Media Server | CVE-2026-96655 | Plex Media Server |
| CVE-2026-96652 | Plex Media Server | CVE-2026-96656 | Plex Media Server |
| CVE-2026-96654 | Plex Media Server | CVE-2026-96656 | Plex Media Server |
| CVE-2026-96654 | Plex Media Server | CVE-2026-96655 | Plex Media Server |
| CVE-2026-96655 | Plex Media Server | CVE-2026-96656 | Plex Media Server |

### Weaknesses shared across vendors

*Which weakness types appear in CVEs of several vendors? (CVE -> Weakness, CVE -> Product <- Vendor)*

```cypher
MATCH (w:Weakness)<-[:HAS_WEAKNESS]-(c:CVE)-[:AFFECTS]->(:Product)<-[:PRODUCES]-(v:Vendor)
WITH w, collect(DISTINCT v.name) AS vendors, count(DISTINCT c) AS cves
WHERE cves > 1
RETURN w.name AS weakness, cves, vendors ORDER BY cves DESC LIMIT 10
```

| weakness | cves | vendors |
|---|---|---|
| authentication bypass | 7 | BeyondTrust, Fortinet, Cisco, Citrix, Ivanti |
| Remote Code Execution | 6 | ONLYOFFICE, Zammad GmbH, F5, Citrix, Palo Alto Networks, WSO2 |
| path traversal | 5 | Fortinet, Check Point, WSO2, GitLab |
| Denial of Service | 4 | MikroTik, Citrix, ISC |
| arbitrary code execution | 4 | Adobe, Check Point, Apple, Siemens |
| command injection | 3 | Microsoft, Ahsay, Apache |
| spoofing | 3 | Microsoft, BeyondTrust, Ivanti |
| heap-based buffer overflow | 3 | Microsoft, Fortinet, F5 |
| improper authentication | 2 | Ahsay, JFrog |
| OS command injection | 2 | Ahsay, EG Secure Solutions |

### Known ransomware use by vendor

*Which vendors have CVEs flagged by CISA with known ransomware campaign use?*

```cypher
MATCH (c:CVE {ransomware_use: 'Known'})-[:AFFECTS]->(:Product)<-[:PRODUCES]-(v:Vendor)
RETURN v.name AS vendor, count(DISTINCT c) AS cves ORDER BY cves DESC LIMIT 10
```

_No result._

## Graph Data Science analyses

Projected graph `cyber`: 228 nodes, 520 relationships (all relationship types, undirected).

### PageRank: most central nodes

*Which nodes are the most connected to other well-connected nodes?*

```cypher
CALL gds.pageRank.stream('cyber') YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS n, score
RETURN labels(n)[0] AS label, coalesce(n.name, n.cve_id) AS name, round(score, 3) AS score
ORDER BY score DESC LIMIT 10
```

| label | name | score |
|---|---|---|
| CVE | CVE-2026-21589 | 3.074 |
| Weakness | Remote Code Execution | 2.8 |
| CVE | CVE-2026-58704 | 2.48 |
| Vendor | Atlassian | 2.382 |
| CVE | CVE-2026-96654 | 2.328 |
| CVE | CVE-2026-87886 | 2.307 |
| Weakness | authentication bypass | 2.291 |
| CVE | CVE-2023-22894 | 2.22 |
| CVE | CVE-2026-67277 | 2.1 |
| CVE | CVE-2026-96656 | 1.96 |

### Betweenness: bridge nodes

*Which nodes connect otherwise separate groups? (shortest paths going through them)*

```cypher
CALL gds.betweenness.stream('cyber') YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS n, score WHERE score > 0
RETURN labels(n)[0] AS label, coalesce(n.name, n.cve_id) AS name, round(score, 2) AS score
ORDER BY score DESC LIMIT 10
```

| label | name | score |
|---|---|---|
| Weakness | Remote Code Execution | 8358.22 |
| CVE | CVE-2026-93616 | 6291.25 |
| Weakness | path traversal | 6142.2 |
| Product | Security Management Server | 5840.0 |
| Vendor | Check Point | 5733.0 |
| Product | Security Gateway | 5624.0 |
| Weakness | arbitrary code execution | 5577.0 |
| CVE | CVE-2026-85102 | 5549.0 |
| Weakness | authentication bypass | 4404.99 |
| Vendor | Microsoft | 4092.1 |

### Louvain: communities

*Which groups of CVEs, products, vendors and weaknesses are densely connected?*

```cypher
CALL gds.louvain.stream('cyber') YIELD nodeId, communityId
WITH communityId, gds.util.asNode(nodeId) AS n
RETURN communityId, count(*) AS size,
       collect(CASE WHEN n:Vendor THEN n.name END)[..5] AS vendors,
       collect(CASE WHEN n:CVE THEN n.cve_id END)[..4] AS sample_cves
ORDER BY size DESC LIMIT 8
```

| communityId | size | vendors | sample_cves |
|---|---|---|---|
| 116 | 32 | Microsoft, Ahsay, JFrog, EG Secure Solutions, Apache | CVE-2026-105133, CVE-2026-96951, CVE-2026-0322, CVE-2026-106931 |
| 131 | 28 | BeyondTrust, Arista, Cisco, Ivanti | CVE-2026-93952, CVE-2026-102764, CVE-2026-76460, CVE-2026-76504 |
| 204 | 21 | Fortinet, F5, WSO2 | CVE-2026-104286, CVE-2026-5430, CVE-2025-61624, CVE-2026-94127 |
| 122 | 19 | ONLYOFFICE, Check Point | CVE-2026-93616, CVE-2021-3199, CVE-2026-87902, CVE-2023-22894 |
| 112 | 15 | Apple, Google | CVE-2026-86950, CVE-2026-87491, CVE-2026-58704 |
| 126 | 14 | MikroTik | CVE-2026-86060, CVE-2026-67279, CVE-2026-67277 |
| 109 | 14 | Adobe, Siemens | CVE-2026-71362, CVE-2026-110936, CVE-2026-75650, CVE-2026-85102 |
| 142 | 14 | Citrix, ISC | CVE-2015-5477, CVE-2026-88779, CVE-2026-19490, CVE-2026-88772 |

### Connected components

*How fragmented is the graph? (component size -> number of components)*

```cypher
CALL gds.wcc.stream('cyber') YIELD nodeId, componentId
WITH componentId, count(*) AS size
RETURN size AS component_size, count(*) AS components ORDER BY component_size DESC
```

| component_size | components |
|---|---|
| 187 | 1 |
| 13 | 1 |
| 12 | 1 |
| 7 | 1 |
| 5 | 1 |
| 4 | 1 |

