# SentinelAI: ML Research & Engineering Documentation

Welcome to the central knowledge repository for **SentinelAI**. This directory tracks all stage-by-stage analyses, architectural decisions, data quality audits, exploratory data analysis findings, and experimental benchmarks across the machine learning lifecycle.

---

## 🗂️ Documentation Directory Structure

The documentation is organized chronologically by lifecycle stage:

```text
docs/
├── README.md                                  <-- Master Documentation Index (You are here)
├── CHANGELOG.md                               <-- Chronological log of major data & model changes
└── stages/
    ├── 01_data_overview/                      <-- Stage 1: Initial raw dataset ingestion & profiling
    │   └── README.md
    ├── 02_cleaning_and_merging/               <-- Stage 2: Interim cleaning & streaming merges
    │   └── README.md
    ├── 03_inter_dataset_inspection/           <-- Stage 3: Cross-dataset inspection & alignment
    │   ├── README.md
    │   └── 04_inter_dataset_inspection_and_merging_strategy.md
    ├── 04_exploratory_data_analysis/          <-- Stage 4: Unified dataset, 14-point audit & EDA
    │   ├── README.md                          <-- Stage 4 Executive Index
    │   ├── 05_data_quality_and_standardization_report.md  <-- 14-Point Audit & 2018 Dominance Analysis
    │   └── 06_exploratory_data_analysis_report.md        <-- 4 EDA Pillars, KS Rankings & Threat Signatures
    ├── 05_feature_engineering_and_splitting/  <-- Stage 5: Scaling, log transforms, dual-benchmark splits
    │   └── README.md
    ├── 06_model_training/                     <-- Stage 6: Anomaly detection & multi-class classification
    │   └── README.md
    └── 07_evaluation/                         <-- Stage 7: Cross-dataset generalization & SHAP explainability
        └── README.md
```

---

## 📌 Stage Index & Direct Links

| Stage | Focus Area | Status | Primary Document |
| :---: | :--- | :---: | :--- |
| **01** | **Dataset Ingestion & Raw Overview** | ✅ Completed | [01_data_overview/README.md](stages/01_data_overview/README.md) |
| **02** | **Interim Cleaning & File Merging** | ✅ Completed | [02_cleaning_and_merging/README.md](stages/02_cleaning_and_merging/README.md) |
| **03** | **Inter-Dataset Inspection & Merging Strategy** | ✅ Completed | [04_inter_dataset_inspection_and_merging_strategy.md](stages/03_inter_dataset_inspection/04_inter_dataset_inspection_and_merging_strategy.md) |
| **04** | **Exploratory Data Analysis & Data Quality Audit** | ✅ Completed | [04_exploratory_data_analysis/README.md](stages/04_exploratory_data_analysis/README.md) |
| **05** | **Feature Engineering & Data Splitting** | ✅ Completed | [07_feature_engineering_and_splitting_report.md](stages/05_feature_engineering_and_splitting/07_feature_engineering_and_splitting_report.md) |
| **06** | **Model Training & Threat Classification** | ✅ Completed | [06_model_training/README.md](stages/06_model_training/README.md) |
| **07** | **Evaluation & Full 20.4M Production Models** | ✅ Completed | [10_model_evaluation_explainability_report.md](stages/07_evaluation/10_model_evaluation_explainability_report.md) & [11_full_scale_20m_production_training_report.md](stages/07_evaluation/11_full_scale_20m_production_training_report.md) |

---

## 🔬 Stage 04 Key Reports at a Glance

* 📊 **Data Quality Audit**: [05_data_quality_and_standardization_report.md](stages/04_exploratory_data_analysis/05_data_quality_and_standardization_report.md)
  * Verified $20,432,819$ rows across 83 row groups with $0$ nulls and $0$ infs.
  * Discovered the **2018 Dominance Reality** ($79.45\%$ volume, but $0\%$ PortScan; NB15 holds $84\%$ Web Exploits).
  * Established the **5 Strategic Pre-Training Conclusions** (Dual-Benchmark, Inverse class weighting, feature quarantine, 1M benchmark).
* 📈 **Exploratory Data Analysis (EDA)**: [06_exploratory_data_analysis_report.md](stages/04_exploratory_data_analysis/06_exploratory_data_analysis_report.md)
  * Visualized univariate heavy tails and proved `np.log1p` necessity.
  * Ranked feature discriminative strength via **Kolmogorov-Smirnov distance** (Top: `traffic_symmetry_ratio` = 0.6842, `fwd_tcp_win_ratio` = 0.5912).
  * Profiled canonical threat fingerprints across the 8 attack families.
  * Formalized the physical network mechanics behind the **"Unanswered Call"** phenomenon.

---

## 📝 How to Update Documentation in Future Steps

When completing a new phase (or making changes to existing notebooks):
1. **Document the rationale**: Explain *why* a transformation, hyperparameter, or feature was selected.
2. **Record empirical findings**: Save summary tables, metric scores, and distribution changes.
3. **Log changes in [CHANGELOG.md](CHANGELOG.md)**: Keep a dated bulleted entry for every schema change or bug discovery.
