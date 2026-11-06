# SentinelAI: Machine Learning Data Manifest & Storage Lifecycle

This document records the provenance of all training datasets used in SentinelAI, the post-training data pruning policy, and the remaining testing artifacts.

---

## 1. Provenance of Datasets Used in Model Training

SentinelAI's production models were trained, calibrated, and evaluated across **20,432,819 network flows** synthesized from three authoritative network intrusion detection corpora:

| Dataset Corpus | Raw Size | Flow Count | Origin Environment | Key Threat Contributions |
| :--- | :---: | :---: | :--- | :--- |
| **CSE-CIC-IDS2018** | $6.09\text{ GB}$ | $16,232,943$ | AWS Cloud Enterprise | Volumetric DoS/DDoS, Brute Force, Infiltration, Botnet |
| **CIC-IDS2017** | $0.98\text{ GB}$ | $2,830,743$ | Canadian Cyber Lab | $96.45\%$ of Reconnaissance / PortScan flows, Web Attacks |
| **UNSW-NB15** | $0.71\text{ GB}$ | $1,369,133$ | Australian Cyber Range | $84.16\%$ of Web Exploits, $100\%$ of Fuzzing, Backdoors |
| **Unified Core** | **$7.78\text{ GB}$ (Raw)** | **$20,432,819$** | Multi-Cloud & Enterprise | **All 9 canonical MITRE attack families** |

### Data Transformation Pipeline (Stages 01 – 05)
1. **Cleaning & Harmonization (Stages 01–03)**:
   * Unified column schemas, timestamps, and standardized units ($\mu s$ and $ms$ converted to seconds).
   * Fixed label casing and sanitized typos (e.g., `'Infilteration'` $\to$ `'Infiltration'`).
   * Scaled TCP window sizes into dimensionless $[0, 1]$ ratios.
2. **Unified Dataset (Stage 04)**:
   * Compiled all 20.4M flows into 83 row groups with $0$ missing and $0$ infinite values.
3. **Feature Engineering & Transformation (Stage 05)**:
   * Applied $\log_e(1 + x)$ to 12 heavy-tailed rate/volume columns.
   * Engineered physics-based network ratios: `traffic_symmetry_ratio`, `pkt_len_ratio`, and `bytes_per_packet`.
   * Fitted leak-free `RobustScaler` on the training slice.
4. **Full-Scale Production Training (Stage 07)**:
   * Trained Tier 1 (Isolation Forest), Tier 2 (LightGBM Binary Gatekeeper), and Tier 3 (LightGBM Multi-Class Classifier) across $18,389,537$ training flows.
   * Serialized production weights into `ml/saved_models/production/` ($29.5\text{ MB}$).

---

## 2. Post-Training Data Pruning Policy (Storage Optimization)

### Rationale
During development, the complete data pipeline required over **$19.3\text{ GB}$** of disk space:
* Raw CSV parts: $\approx 7.78\text{ GB}$
* Interim merged CSV and Parquet partitions: $\approx 9.85\text{ GB}$
* Unscaled intermediate Parquet tables: $\approx 645\text{ MB}$
* 20.4M transformed training Parquet: $\approx 742\text{ MB}$

Because model training and zero-shot cross-dataset evaluation were fully completed and validated, storing $19+\text{ GB}$ of static raw/interim CSVs is redundant. To alleviate local disk constraints, all raw, interim, and redundant intermediate files were **pruned post-training**.

### What Was Pruned:
* ❌ `ml/data/raw/` (all 22 uncleaned CSV parts from 2017, 2018, and NB15).
* ❌ `ml/data/interim/` (all interim merged raw CSVs and Parquet partitions).
* ❌ `ml/data/processed/merged_sentinel_core.parquet` (untransformed 20.4M table).
* ❌ `ml/data/processed/sentinel_20M_transformed.parquet` (full 20.4M training dataset).

---

## 3. Retained Artifacts in the Repository

The repository retains all necessary components for model inference, testing, and documentation without the multi-gigabyte storage penalty:

```text
ml/
├── saved_models/
│   └── production/                              <-- 🚀 Active Production Models (29.5 MB)
│       ├── tier1_anomaly_detector.joblib        <-- Tier 1 Unsupervised Anomaly Model
│       ├── tier2_binary_gatekeeper.joblib       <-- Tier 2 Binary Gatekeeper (sub-100µs)
│       ├── tier3_threat_classifier.joblib       <-- Tier 3 9-Class Threat Classifier
│       ├── feature_scaler.joblib                <-- Pre-fitted RobustScaler
│       └── label_encoder.joblib                 <-- Canonical label encoder
│
└── data/processed/
    ├── sentinel_1M_transformed.parquet          <-- 🧪 Compact 1M Benchmark (29.13 MB)
    │                                                Preserves 100% of rare attack classes;
    │                                                powers test suites & Streamlit demo streams.
    ├── full_20m_evaluation_metrics.json         <-- Formal audit manifest of the 20.4M evaluation
    └── system_evaluation_metrics.json           <-- Cross-dataset zero-shot evaluation benchmarks
```

### Reproducibility Note
Should full re-training on 20.4M flows ever be required from scratch:
1. Download original raw CSV datasets from the Canadian Institute for Cybersecurity (CIC) and UNSW.
2. Place raw CSVs into `ml/data/raw/`.
3. Run the automated ETL and training scripts:
   * [`ml/training/transform_full_20m.py`](../training/transform_full_20m.py)
   * [`ml/training/train_full_20m.py`](../training/train_full_20m.py)

