# Stage 09 — Threat Intelligence Ingestion & Multi-Source Exploration Report

**Report ID**: `12_threat_intelligence_exploration_report`  
**Notebook Source**: [`intelligence/notebooks/01_document_processing_and_chunking.ipynb`](../../../intelligence/notebooks/01_document_processing_and_chunking.ipynb)  
**Status**: ✅ Completed & Verified  
**Date**: October 2026  

---

## 1. Executive Summary & Objective

SentinelAI couples wire-speed machine learning intrusion detection with autonomous threat intelligence reasoning. While the Tri-Tier ML models (Stage 06 & Stage 07) classify incoming network traffic into 9 attack families (DDoS, Infiltration, Botnet, Web Exploits, etc.) with microsecond latency, raw model scores alone do not provide actionable root-cause attribution, adversary profiling, or defensive mitigation steps.

To bridge machine learning detection to contextualized SOC reasoning, Stage 09 ingests and normalizes four authoritative cyber threat intelligence knowledge repositories:
1. **MITRE ATT&CK (Enterprise Matrix)** — Adversary Tactics, Techniques, and Procedures (TTPs).
2. **CISA Known Exploited Vulnerabilities (KEV)** — Actively weaponized CVEs in the wild.
3. **NVD (National Vulnerability Database)** — Structured vulnerability metrics (CVSS, CWE).
4. **OWASP Top 10 (2025 Release)** — Web application risk vectors, prevention checklists, and defense frameworks.

---

## 2. Ingested Data Sources & Physical Manifest

All raw datasets were inspected, validated, and loaded from `intelligence/data/raw/`:

| Knowledge Source | File / Directory Path | Asset Count | Size on Disk | Primary Format |
| :--- | :--- | :---: | :---: | :---: |
| **MITRE ATT&CK** | `intelligence/data/raw/mitre_attack/enterprise-attack.json` | 1 JSON file | $40.59\text{ MB}$ | STIX 2.1 JSON |
| **CISA KEV** | `intelligence/data/raw/cisa/known_exploited_vulnerabilities.json` | 1 JSON file | $1.41\text{ MB}$ | Flat JSON Catalog |
| **NVD Sample** | `intelligence/data/raw/nvd/sql_injection_sample.json` | 1 JSON file | $0.06\text{ MB}$ | NVD 2.0 JSON API |
| **OWASP Top 10** | `intelligence/data/raw/owasp/repository/2025/docs/en/` | 16 Markdown files | $0.11\text{ MB}$ | Markdown Docs |

---

## 3. Exploratory Analysis & Empirical Findings

### 3.1 MITRE ATT&CK Enterprise Matrix (STIX 2.1)
The Enterprise Matrix represents adversary knowledge as a directed graph of threat objects:
* **Total STIX Objects**: **$26,690$**
* **Object Type Distribution**:
  * `relationship`: $21,819$ edges ($81.75\%$) linking actors $\to$ software $\to$ techniques $\to$ mitigations
  * `attack-pattern` (Techniques): $867$ active techniques ($3.25\%$)
  * `malware`: $750$ malware families ($2.81\%$)
  * `course-of-action` (Defensive Mitigations): $268$ records ($1.00\%$)
  * `tool`: $196$ dual-use utilities ($0.73\%$)
  * `intrusion-set` (APT Groups): $193$ nation-state & criminal actors ($0.72\%$)
* **Kill Chain Tactics Coverage**:
  * Top tactics by technique count: *Defense Evasion* ($340+$), *Persistence* ($280+$), *Privilege Escalation* ($240+$), *Initial Access*, and *Lateral Movement*.
* **Key Architecture Note**: Techniques feature rich metadata (`technique_id` e.g. `T1059`, kill-chain tactics, supported platforms, and detection guidance).

### 3.2 CISA Known Exploited Vulnerabilities (KEV) Catalog
Unlike theoretical vulnerability catalogs, CISA KEV catalogs vulnerabilities that are **actively exploited by adversaries in the wild**:
* **Catalog Version**: `2026.04.14`
* **Total Weaponized Vulnerabilities**: **$1,741$ CVEs**
* **Top 10 Targeted Vendors**:
  1. *Microsoft* ($380+$ CVEs)
  2. *Cisco* ($150+$ CVEs)
  3. *Apple* ($110+$ CVEs)
  4. *Google* ($90+$ CVEs)
  5. *Adobe* ($70+$ CVEs)
  6. *Oracle*, *Apache*, *Linux*, *Citrix*, *Fortinet*
* **Ransomware Campaign Weaponization**:
  * **$18.6\%$** of all KEV CVEs are confirmed to be weaponized in known ransomware playbooks (`knownRansomwareCampaignUse == "Known"`).
* **Actionable Remediation**: Every record includes mandatory due dates and federal action mandates (`requiredAction`), providing ready-to-use mitigation text for the SentinelAI reasoning engine.

### 3.3 NVD (National Vulnerability Database)
* Explored sample covering Common Weakness Enumeration **CWE-89 (SQL Injection)**.
* Validated parsing of CVSS v2.0 and CVSS v3.1 base scores, attack vector vectors, and vulnerability descriptions.
* Provides deterministic quantitative severity anchoring (`CRITICAL`, `HIGH`, `MEDIUM`) for RAG ranking.

### 3.4 OWASP Top 10 (2025 Release)
* **16 Markdown Documents** discovered in the official 2025 repository covering core categories:
  * `A01:2025` - Broken Access Control
  * `A02:2025` - Security Misconfiguration
  * `A03:2025` - Software Supply Chain Failures
  * `A04:2025` - Cryptographic Failures
  * `A05:2025` - Insecure Design
  * `A06:2025` - Injection
  * `A07:2025` - Authentication Failures
  * `A08:2025` - Software & Data Integrity Failures
  * `A09:2025` - Security Logging & Monitoring Failures
  * `A10:2025` - Mishandling of Privileged Functionality
* **Document Granularity**: Average document contains $\approx 1,500$ words ($~1,950$ tokens), structured with standardized `##` headings:
  * *Description*
  * *How to Prevent*
  * *Example Attack Scenarios*
  * *References & CWE Mapping*
* **Chunking Insight**: Natural Markdown heading boundaries provide ideal chunking split points for retrieval ($300-500$ tokens per section).

---

## 4. Cross-Source Comparison & RAG Chunking Strategy

| Source | Raw Format | Granularity | Proposed Chunking Strategy | RAG Retrieval Role |
| :--- | :--- | :--- | :--- | :--- |
| **MITRE ATT&CK** | STIX 2.1 JSON | Technique / Sub-technique | **Entity-Level Chunking**: 1 chunk per attack pattern with tactical metadata | Threat Attribution & TTP Mapping |
| **CISA KEV** | Flat JSON Catalog | Single CVE | **Entity-Level Chunking**: 1 chunk per CVE with vendor/product/remediation | Weaponization & Zero-Day Verification |
| **NVD** | JSON API | CVE & CWE Metric | **Field-Level Chunking**: CVE ID + Description + CVSS Score + CWE tags | Technical Vulnerability Profiling |
| **OWASP Top 10** | Markdown | Long-form Document | **Semantic Heading Chunking**: Split by `##` headers ($300-500$ tokens) | Defense Playbooks & Architecture Fixes |

---

## 5. Architectural Requirements for Step 3 (Chunking & Embeddings)

1. **Heterogeneous Parsers**: Implement specialized extractors for STIX graph objects, flat JSON records, and hierarchical Markdown.
2. **Standardized Chunk Schema**:
   * `chunk_id`: Deterministic hash (`source:entity_id:section`)
   * `text`: Dense semantic text representation for vector embedding.
   * `metadata`:
     * `source`: `mitre` | `cisa` | `nvd` | `owasp`
     * `category`: Mapping to SentinelAI's 9 ML attack families.
     * `identifier`: `T1059` | `CVE-XXXX-XXXX` | `A06:2025`
     * `severity`: `CRITICAL` | `HIGH` | `MEDIUM` | `INFO`
3. **Downstream Store**: ChromaDB vector store paired with sentence-transformers embedding model (`all-MiniLM-L6-v2` or `BAAI/bge-small-en-v1.5`).
