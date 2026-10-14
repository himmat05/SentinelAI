# SentinelAI: Autonomous Network Intrusion Detection & AI Defense Platform

SentinelAI is a next-generation network threat detection and automated defense system that unifies modern statistical network flow benchmarks (**CIC-IDS2017**, **CSE-CIC-IDS2018**, and **UNSW-NB15**) into a high-performance machine learning pipeline.

---

## 📚 Project Documentation & Stage Reports

All project lifecycle stages, data audits, architectural decisions, and experiment logs are centrally managed under the **[`docs/`](docs/)** directory:

```text
docs/
├── README.md                                  <-- Master Documentation Index
├── CHANGELOG.md                               <-- Chronological log of schema & code changes
└── stages/
    ├── 01_data_overview/                      <-- Stage 1: Raw dataset exploration
    ├── 02_cleaning_and_merging/               <-- Stage 2: Interim cleaning & streaming merges
    ├── 03_inter_dataset_inspection/           <-- Stage 3: Cross-dataset inspection & merging strategy
    │   └── 04_inter_dataset_inspection_and_merging_strategy.md
    ├── 04_exploratory_data_analysis/          <-- Stage 4: 14-Point Quality Audit & Exploratory Data Analysis
    │   ├── 05_data_quality_and_standardization_report.md
    │   └── 06_exploratory_data_analysis_report.md
    ├── 05_feature_engineering_and_splitting/  <-- Stage 5: Scaling, transforms & dual-benchmark splits (Next)
    ├── 06_model_training/                     <-- Stage 6: Anomaly detection & multi-class training
    ├── 07_evaluation/                         <-- Stage 7: Cross-dataset generalization benchmarks
    └── 08_explainability_shap/                <-- Stage 8: Explainable AI (XAI) with SHAP
```

* 👉 **Read the Master Documentation Index**: [docs/README.md](docs/README.md)
* 👉 **Read the Stage 3 Merging Strategy Report**: [docs/stages/03_inter_dataset_inspection/04_inter_dataset_inspection_and_merging_strategy.md](docs/stages/03_inter_dataset_inspection/04_inter_dataset_inspection_and_merging_strategy.md)
* 👉 **Read the Stage 4 Data Quality Audit Report**: [docs/stages/04_exploratory_data_analysis/05_data_quality_and_standardization_report.md](docs/stages/04_exploratory_data_analysis/05_data_quality_and_standardization_report.md)
* 👉 **Read the Stage 4 EDA & Threat Fingerprinting Report**: [docs/stages/04_exploratory_data_analysis/06_exploratory_data_analysis_report.md](docs/stages/04_exploratory_data_analysis/06_exploratory_data_analysis_report.md)
* 👉 **Read the Stage 5 Feature Engineering & Splitting Report**: [docs/stages/05_feature_engineering_and_splitting/07_feature_engineering_and_splitting_report.md](docs/stages/05_feature_engineering_and_splitting/07_feature_engineering_and_splitting_report.md)
* 👉 **Read the Stage 6 Model Training & Threat Classification Report**: [docs/stages/06_model_training/09_tier2_tier3_supervised_classification_report.md](docs/stages/06_model_training/09_tier2_tier3_supervised_classification_report.md)
* 👉 **Read the Stage 7 Model Evaluation & Explainability Report**: [docs/stages/07_evaluation/10_model_evaluation_explainability_report.md](docs/stages/07_evaluation/10_model_evaluation_explainability_report.md)
* 👉 **Read the Full-Scale 20.4M Production Training Report**: [docs/stages/07_evaluation/11_full_scale_20m_production_training_report.md](docs/stages/07_evaluation/11_full_scale_20m_production_training_report.md)
* 👉 **Read the Stage 8 Explainable AI (SHAP) Report**: [docs/stages/08_explainability_shap/README.md](docs/stages/08_explainability_shap/README.md)
* 👉 **Read the Living Decision Changelog**: [docs/CHANGELOG.md](docs/CHANGELOG.md)

---

## 🛠️ Repository Architecture

* **`ml/`**: Machine learning notebooks, preprocessing pipelines, training loops, and evaluation modules.
  * **`ml/data/raw/`**: Source CSV files.
  * **`ml/data/interim/`**: Cleaned, individual benchmark Parquet files.
  * **`ml/data/processed/`**: Final unified cross-dataset training sets (`merged_sentinel_core.parquet`).
  * **`ml/notebooks/`**: Interactive exploratory, inspection, and experiment notebooks.
* **`network/`**: Real-time packet sniffer and flow reconstruction engine.
* **`backend/`**: FastAPI service hosting model endpoints, rule engines, and telemetry.
* **`frontend/`**: Interactive SOC security dashboard.
* **`intelligence/`**: Threat intelligence feeds, IOC matching, and MITRE ATT&CK mapping.
* **`tests/`**: Unit, integration, and performance test suites.
