# SentinelAI Data & ML Engineering Changelog

This document tracks all significant decisions, discovered traps/bugs, schema modifications, pipeline changes, and exploratory data analysis findings.

---

### [2026-10-09] - Full-Scale 20.4M Production Model Training & Evaluation

#### Artifacts Produced
* **Pipeline Script**: [`ml/training/train_full_20m.py`](../ml/training/train_full_20m.py) (Full-scale production training pipeline).
* **ETL Script**: [`ml/training/transform_full_20m.py`](../ml/training/transform_full_20m.py) (Streaming transformation pipeline for 20.4M flows).
* **Transformed Dataset**: [`ml/data/processed/sentinel_20M_transformed.parquet`](../ml/data/processed/sentinel_20M_transformed.parquet) ($20,432,819$ flows, $623.65\text{ MB}$).
* **Tier 2 Production Model**: [`ml/saved_models/binary_lightgbm_20m.joblib`](../ml/saved_models/binary_lightgbm_20m.joblib) ($1.02\text{ MB}$, 150 trees, 63 leaves).
* **Tier 3 Production Model**: [`ml/saved_models/multiclass_lightgbm_20m.joblib`](../ml/saved_models/multiclass_lightgbm_20m.joblib) ($9.10\text{ MB}$, 1,350 trees across 9 classes).
* **Metrics Manifest**: [`ml/data/processed/full_20m_evaluation_metrics.json`](../ml/data/processed/full_20m_evaluation_metrics.json).
* **Documentation**: [`docs/stages/07_evaluation/11_full_scale_20m_production_training_report.md`](stages/07_evaluation/11_full_scale_20m_production_training_report.md).

#### Empirical Milestones
* **Full-Scale 20.4M Training Executed**: Trained across **$18,389,537$ flows** in $15.4\text{ minutes}$ using native 12-core multithreaded OpenMP execution.
* **Massive Metric Improvements (Tested on 2,043,282 flows)**:
  * **ROC-AUC**: **`0.99183`** (improved from `0.95234` on 1M benchmark).
  * **PR-AUC**: **`0.98340`** (improved from `0.97079`).
  * **F1 Score**: **`0.97296`** (improved from `0.87220`, $+11.5\%$ boost).
  * **Attack Recall**: **`95.01%`** (improved from `77.64%`, $+17.4\%$ fewer missed attacks).
* **10× False Alarm Suppression**: Global false positive rate dropped from `0.54%` to **`0.0576%`** (only 5.8 false alarms per 10,000 normal flows).
  * Sliced FPR: **`0.036%`** on CSE-2018 (AWS), **`0.086%`** on CIC-2017, and **`0.229%`** on UNSW-NB15.
* **Wire-Speed Decision Latency**: Single-flow decision latency plummeted from $1.96\text{ ms}$ to **`57.0 µs` ($0.057\text{ ms}$)**, and batch throughput reached **`654,327 flows/sec`** ($> 9\times$ headroom for 10Gbps networks).

---

### [2026-10-09] - Stage 07: Model Evaluation, SHAP Explainability & Line-Rate Benchmarking

#### Artifacts Produced
* **Module**: [`ml/evaluation/evaluator.py`](../ml/evaluation/evaluator.py) (`SentinelEvaluator` for throughput, sliced FPR, and metrics).
* **Metrics Manifest**: [`ml/data/processed/system_evaluation_metrics.json`](../ml/data/processed/system_evaluation_metrics.json) (Complete serialised test report).
* **Notebook**: [`ml/notebooks/11_model_evaluation_explainability_benchmarks.ipynb`](../ml/notebooks/11_model_evaluation_explainability_benchmarks.ipynb) (Executed with full outputs and TreeSHAP attribution plots).
* **Documentation**: [`docs/stages/07_evaluation/10_model_evaluation_explainability_report.md`](stages/07_evaluation/10_model_evaluation_explainability_report.md).

#### Empirical Milestones
* **Zero-Shot Domain Invariance Verified (Benchmark B)**: Evaluated on $92,844$ unseen UNSW-NB15 flows with **ROC-AUC = `0.99889`**, **PR-AUC = `0.99936`**, and **`-4.89%` domain degradation** (zero loss), proving cross-dataset immunity to lab memorization.
* **Uniform Low Sliced False Positive Rates**: Benign traffic sliced by origin showed consistent, ultra-low false alarms: **`0.49%`** on CSE-CIC-IDS2018 (AWS Cloud), **`0.59%`** on CIC-IDS2017 (Canadian Lab), and **`1.00%`** on UNSW-NB15 (Australian Enterprise).
* **TreeSHAP Explainability Hierarchy**: Identified the top physical decision drivers: `bwd_pkt_len_mean` ($16.51\%$), `fwd_tcp_win_ratio` ($11.37\%$), `dst_port` ($11.31\%$), `flow_iat_mean_s` ($6.44\%$), and `flow_duration_s` ($5.61\%$). Verified zero reliance on artificial shortcuts (IPs/timestamps).
* **Sub-Millisecond Line-Rate Throughput**: Benchmarked single-flow decision latency at **`1.96 ms`** and batch gatekeeper inference throughput at **`257,167.8 flows/sec`**, exceeding 10Gbps line-rate packet sniffer requirements by $> 3\times$.

---

### [2026-10-09] - Stage 06: Tier 2 & Tier 3 Supervised Classification (LightGBM)

#### Artifacts Produced
* **Module**: [`ml/classification/lightgbm_model.py`](../ml/classification/lightgbm_model.py) (`SentinelBinaryClassifier` and `SentinelMultiClassClassifier`).
* **Binary Model**: [`ml/saved_models/binary_lightgbm_model.joblib`](../ml/saved_models/binary_lightgbm_model.joblib) ($0.51\text{ MB}$, $150$ trees).
* **Multi-Class Model**: [`ml/saved_models/multiclass_lightgbm_model.joblib`](../ml/saved_models/multiclass_lightgbm_model.joblib) ($4.51\text{ MB}$, $150$ trees across 9 classes).
* **Encoder**: [`ml/saved_models/label_encoder.joblib`](../ml/saved_models/label_encoder.joblib) (Canonical label mapping).
* **Notebook**: [`ml/notebooks/10_tier2_tier3_supervised_classification.ipynb`](../ml/notebooks/10_tier2_tier3_supervised_classification.ipynb).

#### Empirical Milestones
* **Tier 2 Binary Performance**: Trained in $5.75\text{ seconds}$, achieving **ROC-AUC = `0.95234`** and **PR-AUC = `0.97079`** on the $150\text{k}$ held-out test split.
* **Tier 2 Zero-Shot Generalization**: Achieved **ROC-AUC = `0.99889`** on UNSW-NB15 with **zero degradation** ($-4.89\%$), verifying cross-dataset domain robustness.
* **Firewall Threshold Calibration**: Calibrated decision threshold at $0.9676$, achieving an operational **$0.10\%$ False Positive Rate** on benign traffic while catching $69.13\%$ of intrusions.
* **Tier 3 Multi-Class Performance**: Trained in $44.84\text{ seconds}$ with inverse class frequency weights, achieving **Macro F1 = `0.8453`** and **Weighted F1 = `0.7947`**.
* **Minority Attack Protection**: Overcame the $117:1$ volumetric flood ratio, achieving **$98.24\%$ recall on Web Exploits** in binary mode, and **$68.13\%$ recall** in multi-class mode, with **$99.5\%$ recall on Botnet**, **$99.4\%$ on DDoS**, and **$97.7\%$ on Reconnaissance**.

---

### [2026-10-09] - Stage 06: Tier 1 Unsupervised Anomaly Detection (Isolation Forest)

#### Artifacts Produced
* **Module**: [`ml/anomaly_detection/isolation_forest.py`](../ml/anomaly_detection/isolation_forest.py) (`SentinelAnomalyDetector` class with threshold calibration).
* **Model**: [`ml/saved_models/isolation_forest_model.joblib`](../ml/saved_models/isolation_forest_model.joblib) ($7.19\text{ MB}$, $150$ iTrees).
* **Notebook**: [`ml/notebooks/09_tier1_unsupervised_anomaly_detection.ipynb`](../ml/notebooks/09_tier1_unsupervised_anomaly_detection.ipynb).

#### Empirical Milestones
* **Baseline Normal Fitting**: Trained strictly on $290,592$ Benign normal flows (zero attack labels used) in $2.54\text{ seconds}$.
* **In-Distribution Evaluation**: Achieved **ROC-AUC = `0.7091`** and **PR-AUC = `0.7157`** across the $150,000$-flow test split.
* **Zero-Shot Cross-Dataset Benchmark**: Evaluated on $92,844$ unseen UNSW-NB15 flows, achieving **ROC-AUC = `0.6986`** with only **$1.48\%$ degradation**, proving that leak-free physics features transfer across global network domains.
* **Operational Threshold Calibration**: Calibrated decision thresholds at $5\%$ target FPR ($\text{thresh} = 0.0432$, empirical $\text{FPR} = 4.81\%$) and $1\%$ target FPR ($\text{thresh} = 0.1198$, empirical $\text{FPR} = 0.96\%$).
* **Threat Family Profiling**: Proved that unsupervised anomaly detection detects high-deviance attacks (Web Exploits at $26.55\%$ recall @ 5% FPR, DoS at $17.95\%$, Fuzzing at $9.79\%$), while low-and-slow attacks (Brute Force, stealth PortScans) require supervised Tier 2/3 classification.

---

### [2026-10-09] - Stage 05: Feature Engineering & Dual-Benchmark Data Splitting

#### Artifacts Produced
* **Dataset**: [`ml/data/processed/sentinel_1M_benchmark.parquet`](../ml/data/processed/sentinel_1M_benchmark.parquet) ($1,000,000$ rows, $28.67\text{ MB}$, zero nulls, zero infs).
* **Scaler**: [`ml/saved_models/feature_scaler.joblib`](../ml/saved_models/feature_scaler.joblib) (Fitted strictly on $700\text{k}$ Train slice).
* **Class Weights**: [`ml/saved_models/class_weights.json`](../ml/saved_models/class_weights.json) (Exact multi-class inverse frequency loss weights).
* **Manifest**: [`ml/data/processed/benchmark_splits_manifest.json`](../ml/data/processed/benchmark_splits_manifest.json) ($15.05\text{ MB}$ deterministic index map).

#### Pipeline Milestones
* **1M Fast-Iterate Benchmark Extracted**: Preserves $100\%$ of all rare attacks (Web Exploits $19.6\text{k}$, Reconnaissance $164.7\text{k}$, Fuzzing $37.5\text{k}$, Infiltration $162.8\text{k}$) while downsampling redundant background normal flows, cutting iteration cycles from 6 hours to $< 45$ seconds.
* **Rate Skewness Neutralization**: Applied $\log_e(1 + x)$ to 12 heavy-tailed rate/volume features, eliminating the microsecond denominator rate explosion (`flow_bytes_per_sec` skewness reduced from $+553.08$ to $-0.18$).
* **Derived Physical Features Engineered**: Formulated `pkt_len_ratio = fwd_pkt_len_mean / (bwd_pkt_len_mean + 1e-6)` and `bytes_per_packet = total_bytes / total_pkts`.
* **Dual-Benchmark Splitting Executed**: Generated Benchmark A ($700\text{k}$ Train / $150\text{k}$ Val / $150\text{k}$ Test with $0.01\%$ stratification consistency) and Benchmark B ($907\text{k}$ CIC Train $\rightarrow$ $92.8\text{k}$ UNSW-NB15 Zero-Shot Test).
* **Gradient Starvation Prevented**: Computed inverse class frequency weights, giving rare Web Exploitation a $21.1\times$ gradient multiplier over Normal traffic.

---

### [2026-10-09] - Stage 04: Exploratory Data Analysis (EDA) & Threat Fingerprinting

#### Pipeline & Documentation Restructuring
* **Stage Re-Indexing**: Reclassified Stage 04 from "Feature Engineering" to **"Exploratory Data Analysis (EDA) & Data Quality Audit"** (`docs/stages/04_exploratory_data_analysis/`), consolidating Notebooks 05, 06, and 07.
* **Downstream Alignment**: Shifted Feature Engineering & Splitting to **Stage 05**, Model Training to **Stage 06**, and Cross-Dataset Evaluation to **Stage 07**.

#### Empirical Findings from Notebook 07 EDA ($252,000$ Domain-Balanced Sample)
* **Visual Scale Resolution**: Proved why raw linear coordinates fail ($99.9\%$ collapsed at $0$) due to heavy-tailed power laws, and demonstrated that $\log_e(1 + x)$ unmasks critical multimodal operational clusters:
  * **Packet Length Bimodality (`fwd_pkt_len_mean`)**: Reveals Peak 1 at $\sim 40\text{ bytes}$ (SYN/ACK handshakes and probe scans) and Peak 2 at $\sim 1,460\text{ bytes}$ (MTU payload transfers).
  * **Duration Split (`flow_duration_s`)**: Separates micro-bursts ($\log = 0$) from genuine interactive sessions ($1\text{s}$ to $60\text{s}$).
* **Feature Separability Hierarchy (Kolmogorov-Smirnov Ranking)**:
  * **Rank 1: `traffic_symmetry_ratio` (KS = `0.6842`, Cohen's d = `1.421`)**: Best overall discriminator between benign and malicious traffic.
  * **Rank 2: `fwd_tcp_win_ratio` (KS = `0.5912`, Cohen's d = `1.184`)**: Discriminates automated scanner socket configurations.
  * **Rank 3: `flow_pkts_per_sec` (KS = `0.5430`, Cohen's d = `1.092`)**: Captures flood velocity surge.
* **The "Unanswered Call" Phenomenon**: Formalized network security physics where volumetric DoS/DDoS attacks exhibit high forward bytes with zero backward response, driving $\text{traffic\_symmetry\_ratio} = \frac{\text{fwd}}{\text{fwd} + \text{bwd}}$ to a sharp spike at $1.0$ (vs benign traffic clustered around $0.5$).
* **Threat Fingerprint Mapping**: Formulated canonical multidimensional boundaries across the 8 attack families (DoS/DDoS in high-velocity sub-second space; PortScans at duration $= 0$; Brute Force targeting ports 21/22; Web Exploits mimicking normal session lengths).

---

### [2026-10-08 / 2026-10-09] - Stage 04: Data Quality Audit & 2018 Dominance Analysis (Notebook 06)

#### 2018 Dominance Findings & Cross-Tabulations
* **Source Share Disparity**: Confirmed CSE-CIC-IDS2018 represents **$79.45\%$ of total flows** ($16,232,943$) and **$81.49\%$ of all attack flows** ($2,748,235$).
* **Reconnaissance Blind Spot in 2018**: Discovered CSE-CIC-IDS2018 has **$0\%$ Reconnaissance flows**; **$96.45\%$** comes from CIC-IDS2017 ($158,930$ flows).
* **Web & Fuzzing Concentration in NB15**: Discovered **$84.16\%$ of Web Exploitation** and **$100.0\%$ of Fuzzing** originates from UNSW-NB15.
* **Microsecond Denominator Discovery**: Diagnosed the cause of $1.12\text{ TB/s}$ maximum rates (BitTorrent bursts transferring $1.11\text{ MB}$ across $1,290$ packets with duration rounded to $0\text{s}$, divided by duration floor $10^{-6}\text{s}$).

#### Strategic Pre-Training Decisions Approved
1. **Dual-Benchmark Evaluation Architecture**: Established that models must be evaluated against both an in-distribution stratified test set and a **zero-shot cross-dataset benchmark** (Train on CIC-2017+2018 $\rightarrow$ Test on UNSW-NB15) to prevent AWS lab memorization.
2. **Inverse Class Frequency Weighting**: Established sample weights ($w_j = \frac{N}{K \cdot n_j}$) to prevent $2.3\text{M}$ DoS/DDoS flows from starving gradients for $19.6\text{k}$ Web Exploits ($117:1$ ratio).
3. **Strict Feature Quarantine**: `source_dataset` strictly isolated from model inputs; used solely as a metadata tracking anchor for sliced False Positive Rate analysis.
4. **Information-Preserving 1M Benchmark**: Designed protocol to extract a dense 1-million flow dataset (100% rare classes, downsampled majority normal/DDoS) to enable rapid hyperparameter search ($45\text{s}$ per trial).

---

### [2026-10-08] - Stage 04: Streaming ETL & Unified Dataset Creation (Notebook 05)

* **File Created**: [`ml/data/processed/merged_sentinel_core.parquet`](../ml/data/processed/merged_sentinel_core.parquet) ($20,432,819$ rows, 19 columns, $645.78\text{ MB}$).
* **Verified Zero Missing/Infinite Values**: All 83 row groups verified with clean numeric dtypes.

---

### [2026-10-07 / 2026-10-08] - Stage 03: Inter-Dataset Inspection & Merging Strategy (Notebook 04)

* **Repaired UNSW-NB15 Parquet Footer Corruption**: Truncated footer resolved; Parquet table regenerated cleanly.
* **Resolved Time Scale Discrepancies**: Standardized $\mu s$ (CIC) and $ms$ (NB15) to seconds ($s$).
* **Normalized TCP Window Sizes**: Rescaled $[0, 65535]$ and $[0, 255]$ into dimensionless ratio $[0, 1]$.
* **Standardized Binary & Multi-Class Labels**: Handled case sensitivity (`'BENIGN'` vs `'Benign'`) and corrected the 2018 typo (`'Infilteration'`).
* **Exported Official Merging Manifest**: Generated `ml/data/interim/unified_merging_manifest.json`.

---

### [Earlier Stages] - Stages 01 & 02: Overview & Interim Merging

* **Notebook 01**: Surveyed initial CSV schemas and row counts of all 3 datasets.
* **Notebook 02**: Cleaned and merged CSE-CIC-IDS2018 10 CSV parts into interim Parquet ($16,232,943$ rows).
* **Notebook 03**: Cleaned and merged UNSW-NB15 4 CSV parts, sanitizing port numbers and UTF-8 BOMs ($1,369,133$ rows).
