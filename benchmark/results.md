# Benchmark results

22 questions, 4 types. Local LLM and embedding model on a CPU laptop; one run per question and arm, so differences are indicative, not statistically established.

## Overall (macro average over questions)

| Arm | Questions | Precision | Recall | F1 | Exact | Latency median | Latency p95 | Prompt tok. | Output tok. | Source precision | Answers with sources |
|---|---|---|---|---|---|---|---|---|---|---|---|
| oracle_cypher | 22 | 100% | 100% | 100% | 100% | 8 ms | 14 ms | - | - | - | - |
| vector | 22 | 37% | 31% | 32% | 23% | 23.3 s | 30.0 s | 725 | 67 | 70% | 77% |
| graph | 22 | 63% | 51% | 54% | 36% | 15.9 s | 24.2 s | 613 | 61 | 85% | 95% |
| text2cypher | 22 | 50% | 51% | 50% | 41% | 17.2 s | 29.7 s | 575 | 63 | - | - |

## F1 by question type

| Type | oracle_cypher | vector | graph | text2cypher |
|---|---|---|---|---|
| A factual (1 hop) | 100% (n=6) | 67% (n=6) | 98% (n=6) | 83% (n=6) |
| B multi-hop | 100% (n=6) | 37% (n=6) | 88% (n=6) | 50% (n=6) |
| C aggregation | 100% (n=6) | 0% (n=6) | 2% (n=6) | 17% (n=6) |
| D semantic (silver gold) | 100% (n=4) | 23% (n=4) | 13% (n=4) | 49% (n=4) |

## Text2Cypher

- Valid and executed queries: 19/22; first-attempt success: 19/22
- Few-shot examples in the prompt follow the pattern of three templates (A1, B1, C2) with other entities.

## F1 per question

| Question | Type | oracle_cypher | vector | graph | text2cypher |
|---|---|---|---|---|---|
| A1-1 Which products does CVE-2026-21589 affect? | A | 1.00 | 0.00 | 1.00 | 1.00 |
| A1-2 Which products does CVE-2025-25249 affect? | A | 1.00 | 0.00 | 1.00 | 1.00 |
| A2-1 Which vendor produces Windows Shell? | A | 1.00 | 1.00 | 1.00 | 0.00 |
| A2-2 Which vendor produces VeloCloud Orchestrator? | A | 1.00 | 1.00 | 1.00 | 1.00 |
| A3-1 Which CVEs affect NetScaler ADC? | A | 1.00 | 1.00 | 0.86 | 1.00 |
| A3-2 Which CVEs affect Adobe Commerce? | A | 1.00 | 1.00 | 1.00 | 1.00 |
| B1-1 Which products are affected by the CVEs that are chained with CVE-2026 | B | 1.00 | 0.00 | 1.00 | 1.00 |
| B1-2 Which products are affected by the CVEs that are chained with CVE-2026 | B | 1.00 | 0.00 | 1.00 | 1.00 |
| B2-1 Which vendors have products affected by a CVE with the weakness "Remot | B | 1.00 | 0.40 | 0.44 | 0.00 |
| B2-2 Which vendors have products affected by a CVE with the weakness "authe | B | 1.00 | 0.80 | 0.89 | 1.00 |
| B3-1 Which other products made by the same vendor as Bamboo Data Center are | B | 1.00 | 0.00 | 0.92 | 0.00 |
| B3-2 Which other products made by the same vendor as FortiMail are affected | B | 1.00 | 1.00 | 1.00 | 0.00 |
| C1-1 Which vendor has the most CVEs in the corpus? | C | 1.00 | 0.00 | 0.00 | 0.00 |
| C2-1 How many CVEs affect Adobe products? | C | 1.00 | 0.00 | 0.00 | 1.00 |
| C2-2 How many CVEs affect Plex products? | C | 1.00 | 0.00 | 0.00 | 0.00 |
| C3-1 How many CVEs in the corpus are part of an exploit chain? | C | 1.00 | 0.00 | 0.00 | 0.00 |
| C4-1 Which products are affected by more than one CVE? | C | 1.00 | 0.00 | 0.13 | 0.00 |
| C5-1 How many different vendors are affected by CVEs in the corpus? | C | 1.00 | 0.00 | 0.00 | 0.00 |
| D1-1 Which vulnerabilities allow an attacker to read or access files they s | D | 1.00 | 0.46 | 0.36 | 0.34 |
| D1-2 Which vulnerabilities let someone get past the login or authentication | D | 1.00 | 0.46 | 0.00 | 0.83 |
| D1-3 Which vulnerabilities could let an attacker remotely run their own cod | D | 1.00 | 0.00 | 0.17 | 0.76 |
| D1-4 Which vulnerabilities can crash a service or make it unavailable? | D | 1.00 | 0.00 | 0.00 | 0.00 |

## Failures (F1 < 0.5) for the RAG arms

- `A1-1` / vector: gold 8 item(s); answer: 'No information about CVE-2026-21589 is provided in the context.'
- `A1-2` / vector: gold 2 item(s); answer: 'No information about CVE-2025-25249 is provided in the context.'
- `B1-1` / vector: gold 1 item(s); answer: 'None'
- `B1-2` / vector: gold 1 item(s); answer: 'None of the provided CVEs are chained with CVE-2026-105133.'
- `B2-1` / vector: gold 6 item(s); answer: 'BeyondTrust, F5, Palo Alto Networks, N-able'
- `B2-1` / graph: gold 6 item(s); answer: 'F5 (BIG-IP APM), Palo Alto Networks (PAN-OS), N-able (N-central)'
- `B3-1` / vector: gold 7 item(s); answer: 'None of the products mentioned in the corpus are made by the same vendor as Bamboo Data Center. The products mentioned in the corpus are Ado'
- `C1-1` / vector: gold 1 item(s); answer: 'Adobe Commerce and Magento'
- `C1-1` / graph: gold 1 item(s); answer: 'Adobe'
- `C2-1` / vector: gold 2; answer: '3'
- `C2-1` / graph: gold 2; answer: 'Two'
- `C2-2` / vector: gold 4; answer: 'CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656'
- `C2-2` / graph: gold 4; answer: 'Yes, multiple CVEs affect Plex products. The exact number is not specified in the provided context.'
- `C3-1` / vector: gold 9; answer: '4'
- `C3-1` / graph: gold 9; answer: '4'
- `C4-1` / vector: gold 13 item(s); answer: 'Acronis Backup plugin for cPanel & WHM, Acronis Backup extension for Plesk, Acronis Backup plugin for DirectAdmin'
- `C4-1` / graph: gold 13 item(s); answer: 'Adobe Commerce and Magento Open Source'
- `C5-1` / vector: gold 31; answer: '3'
- `C5-1` / graph: gold 31; answer: 'At least 5 different vendors are affected by CVEs in the corpus: Adobe, ISC, BeyondTrust, Plex, and Remote Support.'
- `D1-1` / vector: gold 9 item(s); answer: 'The vulnerabilities that allow an attacker to read or access files they should not be able to reach are CVE-2026-20079, CVE-2026-76519, CVE-'
- `D1-1` / graph: gold 9 item(s); answer: 'The vulnerabilities that allow an attacker to read or access files they should not be able to reach are: relative path traversal (CVE-2026-7'
- `D1-2` / vector: gold 10 item(s); answer: 'CVE-2026-20079, CVE-2026-76460, CVE-2026-76504'
- `D1-2` / graph: gold 10 item(s); answer: 'Authentication bypass vulnerabilities in Cisco Secure Firewall Management Center (FMC) Software, Cisco Security Cloud Control (SCC) Firewall'
- `D1-3` / vector: gold 21 item(s); answer: 'Apache Struts RCE Vulnerability, Cisco Secure Firewall Management Center (FMC) Software vulnerability, Cisco AsyncOS Software for Cisco Secu'
- `D1-3` / graph: gold 21 item(s); answer: 'The vulnerabilities that could let an attacker remotely run their own code or commands on the system are: command injection in Apache Struts'
- `D1-4` / vector: gold 4 item(s); answer: 'BIG-IP APM, Cisco Identity Services Engine (ISE), Cisco Secure Firewall Management Center (FMC), and SiteGuard Server Edition'
- `D1-4` / graph: gold 4 item(s); answer: 'heap-based buffer overflow, authentication bypass, OS command injection, command injection'

## Text2Cypher: queries that did not give the gold answer

- `A2-1` (F1 0.00): `MATCH (v:Vendor)-[:PRODUCES]->(:Product) WHERE v.name CONTAINS 'Windows Shell' RETURN DISTINCT v.name AS name`
- `B2-1` (F1 0.00): `MATCH (v:Vendor)-[:PRODUCES]->(:Product)-[:AFFECTS]->(:CVE {weakness_id: 'Remote Code Execution'}), (:CVE)-[:CHAINED_WITH]->(:CVE) RETURN DISTINCT v.name AS name`
- `B3-1` (F1 0.00): `MATCH (v:Vendor {name: 'Bamboo Data Center'})-[:PRODUCES]->(p:Product) <-[:AFFECTS]-(c:CVE {in_corpus: true}) RETURN DISTINCT p.name AS name`
- `B3-2` (F1 0.00): `MATCH (v:Vendor {name: 'FortiMail'})-[:PRODUCES]->(p:Product) WHERE v IN MATCH (c:CVE {in_corpus: true})-[:AFFECTS]->(p) RETURN DISTINCT p.name AS name` -> ERROR: {neo4j_code: Neo.ClientError.Statement.SyntaxError} {message: Invalid input '{': expected an expression, ')' o
- `C1-1` (F1 0.00): `MATCH (c:CVE {in_corpus: true})-[:HAS_WEAKNESS]->(w:Weakness)-[:CHAINED_WITH]->(c2:CVE) WHERE c2.cve_id = c.cve_id AND c2.in_corpus = true RETURN DISTINCT c.vendor_id AS vendor_id, COUNT(DISTINCT c) AS n GROUP BY c.vendor_id ORDER` -> ERROR: {neo4j_code: Neo.ClientError.Statement.SyntaxError} {message: Invalid input 'GROUP': expected 'FOREACH', ',', 
- `C2-2` (F1 0.00): `MATCH (p:Product {name: 'Plex'})-[:AFFECTS]->(c:CVE) RETURN count(DISTINCT c) AS n`
- `C3-1` (F1 0.00): `MATCH (c:CVE {in_corpus: true})-[:CHAINED_WITH]->(c2:CVE) RETURN count(DISTINCT c) AS n`
- `C4-1` (F1 0.00): `MATCH (c:CVE)-[:AFFECTS]->(p:Product) WHERE c.in_corpus = true AND c HAS (n:CVE) WHERE n IN (c)-[:CHAINED_WITH]->(m:CVE) AND m IN (c)-[:AFFECTS]->(p) RETURN DISTINCT p.name AS name` -> ERROR: {neo4j_code: Neo.ClientError.Statement.SyntaxError} {message: Invalid input 'HAS': expected an expression, 'FO
- `C5-1` (F1 0.00): `MATCH (c:CVE {in_corpus: true})-[:AFFECTS]->(p:Product)-[:PRODUCES]->(v:Vendor) RETURN DISTINCT v.name AS name`
- `D1-1` (F1 0.34): `MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:Weakness) WHERE toLower(c.text) CONTAINS 'read' OR toLower(c.text) CONTAINS 'access' RETURN DISTINCT c.cve_id AS cve_id, w.name AS weakness_name`
- `D1-2` (F1 0.83): `MATCH (c:CVE) WHERE toLower(c.text) CONTAINS 'login' OR toLower(c.text) CONTAINS 'authentication' RETURN DISTINCT c.cve_id AS cve_id`
- `D1-3` (F1 0.76): `MATCH (c:CVE {in_corpus: true})-[:HAS_WEAKNESS]->(w:Weakness) WHERE toLower(w.name) CONTAINS toLower('remote code execution') OR toLower(w.name) CONTAINS toLower('command injection') RETURN DISTINCT c.cve_id AS cve_id`
- `D1-4` (F1 0.00): `MATCH (c:CVE {in_corpus: true})-[:AFFECTS]->(p:Product) WHERE toLower(c.text) CONTAINS 'crash' OR toLower(c.text) CONTAINS 'unavailable' RETURN DISTINCT c.cve_id AS cve_id`

## Reading notes

- The gold answers describe the graph built from LLM extraction, not the real world; type D uses keyword matching (silver).
- List answers are scored by entity mentions (name or alias): an answer that names extra entities is penalised in precision.
- Number answers: the first integer of the answer must equal the gold value.
- Latency is wall-clock on a CPU laptop and varies with machine load; compare arms within this run only.
- Prompts were adjusted once after a 4-question pilot (graph v2: explicit CVE ids define the context; text2cypher v2: generic Cypher syntax hints). The pilot questions are part of this benchmark.
- The oracle arm is correct by construction (it is the query that defines the gold): it shows the cost of a structured query, not an accuracy.
