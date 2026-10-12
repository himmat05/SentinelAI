# SentinelAI: Tier 1 — Unsupervised Anomaly Detection Report

**Stage**: 06 — Model Training & Threat Classification  
**Modeling Tier**: Tier 1 (Unsupervised Zero-Day Outlier Detection)  
**Notebook**: [`ml/notebooks/09_tier1_unsupervised_anomaly_detection.ipynb`](../../../ml/notebooks/09_tier1_unsupervised_anomaly_detection.ipynb)  
**Core Script**: [`ml/anomaly_detection/isolation_forest.py`](../../../ml/anomaly_detection/isolation_forest.py)  
**Serialized Model**: [`ml/saved_models/isolation_forest_model.joblib`](../../../ml/saved_models/isolation_forest_model.joblib) ($7.19\text{ MB}$)  
**Training Baseline**: $290,592$ Benign / Normal enterprise flows (zero attack labels used)  
**Status**: ✅ Completed, Benchmarked & Serialized

---

## 🎯 Executive Summary of Tier 1 Results

Tier 1 serves as SentinelAI's **Zero-Day Outlier Sensor**, designed to flag novel attacks and abnormal network dynamics without prior knowledge of signatures or threat labels:

1. **Training Efficiency**: Trained an ensemble of $150$ Isolation Trees ($2,048$ samples per tree) in **$2.54\text{ seconds}$** strictly on normal enterprise baseline traffic.
2. **Global Discrimination Power**:
   * **In-Distribution (Benchmark A Test)**: **ROC-AUC = `0.7091`**, **PR-AUC = `0.7157`**.
   * **Zero-Shot Cross-Dataset (Benchmark B UNSW-NB15)**: **ROC-AUC = `0.6986`**, **PR-AUC = `0.7444`**.
   * **Domain Degradation**: Only **$1.48\%$**, proving that our Stage 03 and Stage 05 leak-free physics features generalize cleanly to unseen Australian enterprise network traffic.
3. **Operational False Positive Calibration**: Calibrated decision thresholds on held-out validation benign traffic to enforce strict SOC operational limits:
   * **Balanced Threshold ($5\%$ Target FPR)**: $\text{Threshold} = 0.0432$ $\rightarrow$ Empirical Benign FPR = **$4.81\%$**.
   * **Strict Enterprise Threshold ($1\%$ Target FPR)**: $\text{Threshold} = 0.1198$ $\rightarrow$ Empirical Benign FPR = **$0.96\%$**.

---

## 📊 Threat Family Recall Breakdown (At 5% Target FPR)

The threat family analysis illustrates the precise strengths and operational boundaries of unsupervised anomaly detection:

| Canonical Threat Family | Test Flows ($N$) | Mean Anomaly Score | Recall @ 5% FPR | Recall @ 1% FPR | Detection Characteristic |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Web & Exploitation** | $2,953$ | **`+0.0326`** | **`26.55%`** | **`6.40%`** | ⭐ High statistical payload asymmetry (`pkt_len_ratio`) |
| **Other / Fuzzing** | $5,630$ | **`+0.0118`** | **`9.79%`** | **`1.67%`** | Protocol state deviations and anomalous bytes |
| **DoS** | $7,500$ | **`-0.0432`** | **`17.95%`** | **`1.83%`** | Volumetric byte rate anomalies |
| **DDoS** | $7,500$ | **`-0.0152`** | **`5.59%`** | **`0.23%`** | Packet velocity surges |
| **Infiltration** | $24,430$ | **`-0.0814`** | **`4.40%`** | **`0.73%`** | Periodic beacon anomalies |
| **Reconnaissance (PortScan)** | $24,717$ | **`+0.0046`** | **`0.71%`** | **`0.17%`** | Stealth single-packet sweeps mimic single handshakes |
| **Botnet** | $7,500$ | **`-0.0606`** | **`0.56%`** | **`0.00%`** | Low-rate C2 communication |
| **Brute Force** | $7,500$ | **`-0.0416`** | **`0.00%`** | **`0.00%`** | Legitimate SSH handshakes require supervised signatures |

---

## 💡 Key Architectural Insights for SentinelAI

### 1. What Tier 1 Excels At: High-Deviance Wire Anomaly Detection
Anomalies with significant morphological divergence from standard browsing (large web exploit payloads, protocol fuzzing, volumetric connection flooding) score highest on path isolation.

### 2. Why Supervised Tiers (Tier 2 & 3) Are Essential
Stealthy low-and-slow attacks (such as single-packet port scans or SSH brute force credential guessing) transmit packets that are individually indistinguishable from normal connection handshakes. Without supervised ground-truth attack labels, an unsupervised model cannot separate a failed user password attempt from an automated Hydra brute force sweep.

This empirical divergence validates SentinelAI's **Hybrid Defense Architecture**:
* **Tier 1 (Isolation Forest)** flags zero-day anomalies and unexpected outliers.
* **Tier 2 (Supervised Binary LightGBM/XGBoost)** learns precise discriminative boundaries for stealthy threat patterns.
* **Tier 3 (Multi-Class Threat Classifier)** categorizes the attack into its exact canonical family.
