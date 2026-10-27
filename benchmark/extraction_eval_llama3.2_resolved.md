# Extraction evaluation: `llama3.2_resolved`

- Documents: 60 (60 valid JSON, prompt version(s): v3)

## Products and vendors vs NVD ground truth

| Entity | View | Precision | Recall (recoverable GT) | F1 | Extracted | Recoverable GT |
|---|---|---|---|---|---|---|
| product | raw LLM | 76% | 86% | 81% | 80 | 69 |
| vendor | raw LLM | 98% | 92% | 95% | 55 | 59 |
| product | after grounding filter | 76% | 86% | 81% | 80 | 69 |
| vendor | after grounding filter | 98% | 92% | 95% | 55 | 59 |

## What the grounding filter removed (items not found in the text)

- Versions: 24 dropped out of 129 extracted
- Products: 0 dropped; vendors: 0 dropped

## Rule-based extraction (regex, no LLM)

- Explicit CWE ids in the text: 1 in 1/60 documents, 1 confirmed by NVD
- Exploit-chain edges (CVE chained with CVE): 17

## Latency and cost (local CPU)

- Latency per document: median 20.0s, p95 57.3s, total 24.1 min
- Tokens per document: prompt 415 (mean), output 70 (mean)
- Output length drives latency: long multi-product advisories are the slowest.

## Mismatches to classify (alias / granularity vs real error)

- `CVE-2023-22894`: NVD vendor missed: strapi
- `CVE-2025-25249`: NVD product missed: fortisase
- `CVE-2025-39682`: NVD vendor missed: linux
- `CVE-2025-39964`: NVD vendor missed: linux
- `CVE-2026-105133`: extracted product not in NVD: Ahsay AhsayCBS
- `CVE-2026-105134`: extracted product not in NVD: Ahsay AhsayCBS
- `CVE-2026-106931`: extracted vendor not in NVD: EG Secure Solutions
- `CVE-2026-19490`: extracted product not in NVD: NetScaler ADC
- `CVE-2026-53266`: NVD vendor missed: linux
- `CVE-2026-5430`: NVD product missed: api_manager, traffic_manager, universal_gateway
- `CVE-2026-58704`: extracted product not in NVD: Cellular Modem
- `CVE-2026-65660`: extracted product not in NVD: Microsoft SharePoint
- `CVE-2026-71362`: NVD product missed: magento
- `CVE-2026-7273`: extracted product not in NVD: GS1900-48HPv2 | NVD product missed: gs1900-48hpv2_firmware
- `CVE-2026-76460`: extracted product not in NVD: ISE | NVD product missed: identity_services_engine, identity_services_engine_passive_identity_connector
- `CVE-2026-76461`: extracted product not in NVD: Secure Email Gateway | NVD product missed: asyncos
- `CVE-2026-76519`: extracted product not in NVD: Secure Email Gateway
- `CVE-2026-81963`: extracted product not in NVD: Windows Update Stack
- `CVE-2026-85102`: extracted product not in NVD: Security Gateway
- `CVE-2026-85880`: extracted product not in NVD: Windows
- `CVE-2026-86950`: extracted product not in NVD: iOS
- `CVE-2026-87902`: NVD vendor missed: wordpress
- `CVE-2026-88771`: extracted product not in NVD: NetScaler ADC
- `CVE-2026-88772`: extracted product not in NVD: NetScaler ADC
- `CVE-2026-88779`: extracted product not in NVD: NetScaler ADC
- `CVE-2026-93616`: extracted product not in NVD: Security Management Server | NVD product missed: multi-domain_security_management
- `CVE-2026-94127`: extracted product not in NVD: BIG-IP APM
- `CVE-2026-96951`: extracted product not in NVD: Windows Shell
