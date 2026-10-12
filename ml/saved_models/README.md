# SentinelAI Saved Models Directory

This directory stores all serialized machine learning models, scalers, and label encoders for SentinelAI. The directory is structured into **Production** (the active 20.4M production deployment models) and **Benchmarks** (the fast-iterate 1M experimental models).

---

## 📁 Directory Structure

```text
ml/saved_models/
│
├── production/                          <-- 🚀 Active Production Models (Trained on 18.4M / 20.4M Flows)
│   ├── tier1_anomaly_detector.joblib    <-- Tier 1: Unsupervised Zero-Day Anomaly Detector (Isolation Forest)
│   ├── tier2_binary_gatekeeper.joblib   <-- Tier 2: Supervised Binary Gatekeeper (LightGBM, 99.18% ROC-AUC)
│   ├── tier3_threat_classifier.joblib   <-- Tier 3: Multi-Class MITRE Threat Family Classifier (LightGBM)
│   ├── label_encoder.joblib             <-- Target Encoder (9 Canonical MITRE Attack Families)
│   └── feature_scaler.joblib            <-- Leak-Free RobustScaler for Flow Features
│
└── benchmarks_1m/                       <-- 🧪 Development & Baseline Models (1M Benchmark Split)
    ├── tier1_anomaly_detector_1m.joblib <-- Tier 1 Fitted on 290k Benign Flows
    ├── tier2_binary_gatekeeper_1m.joblib<-- Tier 2 Fitted on 700k Train Split (0.51 MB)
    ├── tier3_threat_classifier_1m.joblib<-- Tier 3 Fitted on 700k Train Split (4.51 MB)
    └── class_weights_1m.json            <-- Inverse Class Loss Weights for 1M Split
```

---

## 🚀 Active Production Models (`production/`)

These are the primary models used by the **FastAPI inference engine** (`backend/`) and **real-time packet sniffer** (`network/`).

| File | Tier | Algorithm | Training Corpus | Key Metrics | Role in Pipeline |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`tier1_anomaly_detector.joblib`** | **Tier 1** | Isolation Forest ($150$ iTrees) | Pure Benign Normal Traffic | Calibrated @ $1\%$ and $5\%$ FPR | Catches **Zero-Day** attacks and behavioral anomalies with zero signature matching. |
| **`tier2_binary_gatekeeper.joblib`** | **Tier 2** | LightGBM Binary Booster ($150$ trees, $63$ leaves) | $18,389,537$ flows | **ROC-AUC: `0.99183`**<br>Recall: `95.01%`<br>FPR: `0.0576%`<br>Latency: `57 µs` | High-speed line-rate gatekeeper. Allows $99.94\%$ clean traffic through in microseconds; alarms on intrusions. |
| **`tier3_threat_classifier.joblib`** | **Tier 3** | LightGBM Multi-Class ($1,350$ trees, $9$ classes) | $18,389,537$ flows (Weighted) | **Macro F1: `0.7861`**<br>DDoS Recall: `100.0%`<br>Botnet Recall: `99.99%`<br>Web Exploit: `97.51%` | Pinpoints the exact MITRE threat category to issue targeted automated firewall / SOC mitigation rules. |
| **`label_encoder.joblib`** | N/A | Scikit-Learn `LabelEncoder` | 9 Canonical Classes | 9 Classes Mapped | Translates model integer outputs (`0` to `8`) into human-readable attack family names. |
| **`feature_scaler.joblib`** | N/A | Scikit-Learn `RobustScaler` | Train Partition | Leak-Free Quantiles | Normalizes flow continuous features without outlier distortion. |

---

## 🧪 1M Benchmark Models (`benchmarks_1m/`)

These models were developed during the rapid-iteration research phase (Stage 05 & 06) and evaluated for TreeSHAP explainability and dual-benchmark domain transfer:

* **`tier1_anomaly_detector_1m.joblib`**: Evaluated on $92,844$ unseen UNSW-NB15 flows with only $1.48\%$ degradation.
* **`tier2_binary_gatekeeper_1m.joblib`**: Achieved `0.95234` in-distribution ROC-AUC and `0.99889` zero-shot ROC-AUC.
* **`tier3_threat_classifier_1m.joblib`**: Formally profiled via TreeSHAP feature attribution.
* **`class_weights_1m.json`**: Pre-computed inverse loss weight multipliers.
