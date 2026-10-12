# Stage 06: Model Training & Threat Classification

**Location**: `docs/stages/06_model_training/`  
**Modeling Notebooks**:
* [`ml/notebooks/09_tier1_unsupervised_anomaly_detection.ipynb`](../../../ml/notebooks/09_tier1_unsupervised_anomaly_detection.ipynb) — Tier 1 Isolation Forest Anomaly Detector
* [`ml/notebooks/10_tier2_tier3_supervised_classification.ipynb`](../../../ml/notebooks/10_tier2_tier3_supervised_classification.ipynb) — Tier 2 Binary & Tier 3 Multi-Class LightGBM Classifiers  
**Training Corpus**: [`ml/data/processed/sentinel_1M_transformed.parquet`](../../../ml/data/processed/sentinel_1M_transformed.parquet) ($1,000,000$ flows)  
**Status**: ✅ Completed & Verified

---

## 📑 Stage Documentation & Reports

1. 📄 **[08_tier1_unsupervised_anomaly_detection_report.md](08_tier1_unsupervised_anomaly_detection_report.md)**:
   * **Tier 1 (Isolation Forest)**: Baseline training on $290,592$ normal flows with zero attack labels.
   * **ROC-AUC**: `0.7091` in-distribution, `0.6986` zero-shot on UNSW-NB15 ($1.48\%$ degradation).
   * Operational threshold calibration at $5\%$ and $1\%$ target FPR.

2. 📄 **[09_tier2_tier3_supervised_classification_report.md](09_tier2_tier3_supervised_classification_report.md)**:
   * **Tier 2 (Binary LightGBM)**: ROC-AUC = **`0.9523`**, PR-AUC = **`0.9708`**.
   * Calibrated operational thresholds ($0.10\%$ FPR firewall profile).
   * **Tier 3 (Multi-Class LightGBM)**: Macro F1 = **`0.8453`** across all 9 canonical classes.
   * Inverse class frequency weighting prevents loss starvation on rare Web Exploits.
   * Complete Tri-Tier Defense System comparison table.

---

## 🛡️ Production Model Artifacts Serialized

| Model Tier | Model Artifact File | Size | Operational Role |
| :--- | :--- | :---: | :--- |
| **Tier 1** | [`ml/saved_models/isolation_forest_model.joblib`](../../../ml/saved_models/isolation_forest_model.joblib) | $7.19\text{ MB}$ | **Zero-Day Sensor**: Unsupervised wire outlier scoring |
| **Tier 2** | [`ml/saved_models/binary_lightgbm_model.joblib`](../../../ml/saved_models/binary_lightgbm_model.joblib) | $0.51\text{ MB}$ | **Gatekeeper**: High-throughput binary attack filtering |
| **Tier 3** | [`ml/saved_models/multiclass_lightgbm_model.joblib`](../../../ml/saved_models/multiclass_lightgbm_model.joblib) | $4.51\text{ MB}$ | **SOC Attribution**: Multi-family cyber threat categorization |
| **Metadata** | [`ml/saved_models/label_encoder.joblib`](../../../ml/saved_models/label_encoder.joblib) | $< 1\text{ KB}$ | Class label mapping dictionary |
