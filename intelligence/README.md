# SentinelAI: Threat Intelligence & Autonomous RAG Subsystem

The **`intelligence/`** subsystem powers SentinelAI's contextual security reasoning, autonomous alert enrichment, and automated incident response recommendations. It unifies authoritative threat intelligence feeds with a Retrieval-Augmented Generation (RAG) agent.

---

## 🗂️ Directory Architecture

```text
intelligence/
├── README.md                           <-- Subsystem Guide & Architecture (This document)
├── data/
│   ├── raw/                            <-- Source threat feeds
│   │   ├── mitre_attack/               <-- STIX 2.1 Enterprise Matrix (enterprise-attack.json)
│   │   ├── cisa/                       <-- CISA KEV (known_exploited_vulnerabilities.json)
│   │   ├── nvd/                        <-- NVD CVE samples (sql_injection_sample.json)
│   │   └── owasp/                      <-- OWASP Top 10 2025 release documentation
│   └── processed/                      <-- Normalized vector chunks & ChromaDB store
│       ├── threat_intel_chunks.json    <-- 3,774 standardized knowledge chunks
│       └── chroma_db/                  <-- Persistent local vector database
├── notebooks/
│   ├── 01_document_processing_and_chunking.ipynb  <-- Step 2: 7-Section Multi-Source Threat Exploration
│   └── create_01_notebook.py           <-- Generator script for reproducible execution
├── rag/                                <-- RAG core components
│   ├── ingestion.py                    <-- Document loaders and chunking extractors (3,774 chunks)
│   ├── embeddings.py                   <-- Vector embeddings (all-MiniLM-L6-v2, 384D)
│   └── retrieval.py                    <-- Hybrid semantic search & ChromaDB query engine
├── agent/                              <-- Autonomous SOC agent
│   ├── tools.py                        <-- Custom security tools (IP lookup, CVE search, TTP mapping)
│   ├── workflow.py                     <-- Stateful incident investigation workflow
│   └── report_generator.py             <-- Incident summary and automated playbook synthesizer
└── reports/                            <-- Generated SOC incident briefs & mitigation playbooks
```

---

## 📚 Multi-Source Threat Feeds Explored

1. **MITRE ATT&CK Enterprise Matrix**: $26,690$ STIX 2.1 threat objects ($867$ active techniques across 14 kill chain tactics).
2. **CISA Known Exploited Vulnerabilities (KEV)**: $1,741$ weaponized CVEs actively exploited in the wild ($18.6\%$ ransomware weaponization).
3. **NVD (National Vulnerability Database)**: Granular CVSS v2/v3 base scores, severity categories, and CWE mappings.
4. **OWASP Top 10 (2025 Release)**: 16 authoritative Markdown documentation files providing web application threat analysis and remediation checklists.

---

## 📖 Associated Documentation

* Stage 09 Full Report: [`docs/stages/09_threat_intelligence/12_threat_intelligence_exploration_report.md`](../docs/stages/09_threat_intelligence/12_threat_intelligence_exploration_report.md)
* Stage 09 README: [`docs/stages/09_threat_intelligence/README.md`](../docs/stages/09_threat_intelligence/README.md)
* Interactive Exploration Notebook: [`intelligence/notebooks/01_document_processing_and_chunking.ipynb`](notebooks/01_document_processing_and_chunking.ipynb)
