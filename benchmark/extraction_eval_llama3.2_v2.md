# Extraction evaluation: `llama3.2`

- Documents: 25 (25 valid JSON, prompt version(s): v2)

## Products and vendors vs NVD ground truth

| Entity | View | Precision | Recall (recoverable GT) | F1 | Extracted | Recoverable GT |
|---|---|---|---|---|---|---|
| product | raw LLM | 86% | 100% | 93% | 37 | 32 |
| vendor | raw LLM | 96% | 96% | 96% | 24 | 24 |
| product | after grounding filter | 86% | 100% | 93% | 37 | 32 |
| vendor | after grounding filter | 96% | 96% | 96% | 24 | 24 |

## What the grounding filter removed (items not found in the text)

- Versions: 6 dropped out of 82 extracted
- Products: 0 dropped; vendors: 0 dropped
- CWE ids written by the LLM: 29, of which 27 were not in the text (LLM-written CWE ids are unreliable; v3 extracts explicit ones by regex instead)

## Rule-based extraction (regex, no LLM)

- Explicit CWE ids in the text: 1 in 1/25 documents, 1 confirmed by NVD
- Exploit-chain edges (CVE chained with CVE): 17

## Latency and cost (local CPU)

- Latency per document: median 18.0s, p95 62.6s, total 10.0 min
- Tokens per document: prompt 458 (mean), output 91 (mean)
- Output length drives latency: long multi-product advisories are the slowest.

## Mismatches to classify (alias / granularity vs real error)

- `CVE-2023-22894`: NVD vendor missed: strapi
- `CVE-2026-104935`: extracted product not in NVD: ICS
- `CVE-2026-105133`: extracted product not in NVD: Ahsay AhsayCBS
- `CVE-2026-105134`: extracted product not in NVD: Ahsay AhsayCBS
- `CVE-2026-106931`: extracted vendor not in NVD: EG Secure Solutions
- `CVE-2026-88779`: extracted product not in NVD: NetScaler ADC
- `CVE-2026-96951`: extracted product not in NVD: Windows Shell
