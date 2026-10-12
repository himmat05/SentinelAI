# SentinelAI: Feature Engineering & Dual-Benchmark Data Splitting Report

**Stage**: 05 — Feature Engineering & Data Splitting  
**Notebook**: [`ml/notebooks/08_feature_engineering_and_splits.ipynb`](../../../ml/notebooks/08_feature_engineering_and_splits.ipynb)  
**Fast-Iterate Corpus**: [`ml/data/processed/sentinel_1M_benchmark.parquet`](../../../ml/data/processed/sentinel_1M_benchmark.parquet) ($1,000,000$ flows, $28.67\text{ MB}$)  
**Master Corpus**: `ml/data/processed/merged_sentinel_core.parquet` ($20,432,819$ flows, $677.15\text{ MB}$)  
**Artifacts Generated**:  
* `ml/saved_models/feature_scaler.joblib` (Leak-free `RobustScaler` fitted strictly on Train partition)  
* `ml/saved_models/class_weights.json` (Exact multi-class inverse frequency loss weights)  
* `ml/data/processed/benchmark_splits_manifest.json` (Deterministic partition index mapping)  
**Status**: ✅ Completed & Verified

---

## 🎯 Executive Summary

Stage 05 translates the theoretical and statistical findings from **Stage 04 Exploratory Data Analysis & Quality Audit** into production machine learning components:

1. **Extraction of the 1-Million Fast-Iterate Benchmark**: Extracted a representative $1,000,000$-flow Parquet dataset in $28.78$ seconds, preserving **$100\%$ of all rare attacks** (Web Exploitation, Reconnaissance, Fuzzing, Infiltration) while downsampling redundant background normal flows.
2. **Elimination of Extreme Rate Skewness**: Applied $\log_e(1 + x)$ (`np.log1p`) to all heavy-tailed features, dropping `flow_bytes_per_sec` skewness from **$+553.08$** to **$-0.18$** and `flow_pkts_per_sec` skewness from **$+528.83$** to **$-0.15$**.
3. **Engineering of Derived Physical Features**: Formulated `pkt_len_ratio` (directional payload asymmetry) and `bytes_per_packet` (packet density).
4. **Implementation of the Dual-Benchmark Architecture**:
   * **Benchmark A (In-Distribution Stratified Split)**: $700,000$ Train / $150,000$ Val / $150,000$ Test, achieving exact cross-split class proportions down to $0.01\%$.
   * **Benchmark B (Zero-Shot Cross-Dataset Benchmark)**: $907,156$ flows (CIC-17 + CIC-18) for Training $\rightarrow$ $92,844$ flows (UNSW-NB15) for Zero-Shot Testing.
5. **Leak-Free Robust Scaling & Loss Weighting**: Serialized a `RobustScaler` fitted strictly on the $700\text{k}$ training slice, and generated inverse class frequency weights giving Web Exploitation a **$21.1\times$ gradient multiplier** over Normal traffic.

---

## 📊 1-Million Fast-Iterate Benchmark Architecture

To allow hyperparameter search and rapid prototyping in **$< 45\text{ seconds}$** instead of $6\text{ hours}$, the $1\text{M}$ benchmark was extracted directly from `merged_sentinel_core.parquet` using streaming binary search offset sampling:

| Canonical Threat Family | 20.4M Master Corpus | 1M Benchmark Corpus | Retention Rate in Benchmark | Physical Network Role |
| :--- | :---: | :---: | :---: | :--- |
| **Normal (Benign)** | $17,060,373$ | $415,132$ | $2.43\%$ (Downsampled) | Realistic background operational traffic |
| **Reconnaissance (PortScan)** | $164,782$ | **`164,782`** | **$\mathbf{100.00\%}$ (Complete)** | Port sweeps and stealth reconnaissance |
| **Infiltration** | $162,865$ | **`162,865`** | **$\mathbf{100.00\%}$ (Complete)** | Lateral movement and post-exploitation |
| **Other / Fuzzing** | $37,535$ | **`37,535`** | **$\mathbf{100.00\%}$ (Complete)** | Protocol fuzzing and invalid state packets |
| **Web & Exploitation** | $19,686$ | **`19,686`** | **$\mathbf{100.00\%}$ (Complete)** | SQLi, XSS, and command injection |
| **Botnet** | $288,157$ | $50,000$ | $17.35\%$ | C2 command and control beacons |
| **Brute Force** | $394,784$ | $50,000$ | $12.67\%$ | SSH/FTP credential attacks on ports 21/22 |
| **DoS** | $912,677$ | $50,000$ | $5.48\%$ | Slowloris, Hulk, GoldenEye connection floods |
| **DDoS** | $1,391,960$ | $50,000$ | $3.59\%$ | High-volume UDP/SYN volumetric floods |
| **TOTAL** | **`20,432,819`** | **`1,000,000`** | **$4.89\%$** | — |

* **Attack Share in Benchmark**: $58.49\%$ Attack ($584,868$ flows) vs $41.51\%$ Benign ($415,132$ flows).
* **Source Dataset Shares**: CSE-CIC-IDS2018 ($67.01\%$), CIC-IDS2017 ($23.70\%$), UNSW-NB15 ($9.28\%$).

---

## 🔬 Non-Linear Transformation Results (`np.log1p`)

Applying $\log_e(1 + x)$ dramatically compressed power-law tails into stable Gaussian distributions suitable for gradient descent and tree split criteria:

| Feature Name | Skewness Before | Skewness After `np.log1p` | Skewness Reduction | Distributional Outcome |
| :--- | :---: | :---: | :---: | :--- |
| **`flow_bytes_per_sec`** | **`553.08`** | **`-0.18`** | **`553.26`** | Symmetrical bell curve; zero rate explosion |
| **`flow_pkts_per_sec`** | **`528.83`** | **`-0.15`** | **`528.99`** | Perfectly centered packet velocity curve |
| **`bwd_bytes`** | **`156.91`** | **`0.49`** | **`156.43`** | Normalized return payload volume |
| **`bwd_packets`** | **`154.57`** | **`1.49`** | **`153.08`** | Tamed backward packet counts |
| **`fwd_packets`** | **`111.11`** | **`1.94`** | **`109.16`** | Tamed forward packet counts |
| **`fwd_bytes`** | **`110.89`** | **`0.26`** | **`110.62`** | Near-normal forward byte volume |
| **`pkt_len_ratio` (Derived)** | **`22.21`** | **`2.89`** | **`19.32`** | Compressed extreme payload ratios |
| **`bwd_iat_mean_s`** | **`14.38`** | **`4.19`** | **`10.19`** | Stabilized backward timing delays |
| **`fwd_pkt_len_mean`** | **`9.56`** | **`-0.06`** | **`9.62`** | Preserves 40B vs 1460B MTU bimodality |
| **`flow_iat_mean_s`** | **`7.30`** | **`3.80`** | **`3.51`** | Linearized inter-arrival delays |
| **`bytes_per_packet` (Derived)** | **`4.48`** | **`-0.10`** | **`4.57`** | Gaussian-like packet density |

> **Unchanged Features**: `traffic_symmetry_ratio`, `fwd_tcp_win_ratio`, and `bwd_tcp_win_ratio` were kept untouched in their native $[0.0, 1.0]$ space to preserve the critical peak at $1.0$ (the *"Unanswered Call"* phenomenon).

---

## ⚖️ Inverse Class Frequency Weighting Matrix

To prevent $100\text{k}$ volumetric floods from starving loss gradients for $19.6\text{k}$ Web Exploitation flows, exact inverse weights were calculated:
$$w_j = \frac{N}{K \cdot n_j}$$
where $N = 700,000$ training flows, $K = 8$ canonical classes, and $n_j$ is the class frequency:

| Canonical Attack Family | Training Flows ($n_j$) | Exact Inverse Weight ($w_j$) | Effective Gradient Multiplier vs Normal |
| :--- | :---: | :---: | :---: |
| **Web & Exploitation** | **`13,780`** | **`5.6443`** | **$\mathbf{21.1x}$** |
| **Other / Fuzzing** | **`26,275`** | **`2.9601`** | **$\mathbf{11.1x}$** |
| **Botnet** | **`35,000`** | **`2.2222`** | **$\mathbf{8.3x}$** |
| **Brute Force** | **`35,000`** | **`2.2222`** | **$\mathbf{8.3x}$** |
| **DDoS** | **`35,000`** | **`2.2222`** | **$\mathbf{8.3x}$** |
| **DoS** | **`35,000`** | **`2.2222`** | **$\mathbf{8.3x}$** |
| **Infiltration** | **`114,006`** | **`0.6822`** | **$\mathbf{2.5x}$** |
| **Reconnaissance** | **`115,347`** | **`0.6743`** | **$\mathbf{2.5x}$** |
| **Normal** | **`290,592`** | **`0.2677`** | **$\mathbf{1.0x}$ (Baseline)** |

* Saved to: [`ml/saved_models/class_weights.json`](file:///c:/Users/himma/Desktop/Projects/AI%20project/SentinelAI/ml/saved_models/class_weights.json)

---

## 🧪 Dual-Benchmark Partition Verification

### Benchmark A: In-Distribution Stratified Split
* **Train**: $700,000$ flows ($70.0\%$)
* **Validation**: $150,000$ flows ($15.0\%$)
* **Test**: $150,000$ flows ($15.0\%$)
* **Stratification Result**: The percentage share of every single class between Train and Test matches to within **$0.01\%$**.

### Benchmark B: Zero-Shot Cross-Dataset Benchmark
* **Train Partition**: **$907,156$ flows** from **CIC-IDS2017 + CSE-CIC-IDS2018**
* **Test Partition**: **$92,844$ flows** from **UNSW-NB15**
* **Evaluation Metric**: During Stage 07, cross-dataset generalization will be assessed via the **Degradation Ratio**:
  $$\text{Degradation} = 1 - \frac{\text{F1}_{\text{Cross-Dataset}}}{\text{F1}_{\text{In-Distribution}}}$$

---

## 🛠️ Ready for Stage 06: Model Training

With all feature transformations fitted, class weights computed, and partitions deterministically serialized in [`benchmark_splits_manifest.json`](file:///c:/Users/himma/Desktop/Projects/AI%20project/SentinelAI/ml/data/processed/benchmark_splits_manifest.json), the project is fully primed for **Stage 06: Anomaly Detection & Threat Classification Model Training**.
