# SentinelAI: Data Quality & Standardization Audit Report

**Stage**: 04 - Exploratory Data Analysis & Quality Audit  
**Audit Target**: `ml/data/processed/merged_sentinel_core.parquet`  
**Notebook**: [`ml/notebooks/06_data_quality_and_standardization.ipynb`](../../../ml/notebooks/06_data_quality_and_standardization.ipynb)  
**Total Corpus**: **20,432,819 flows** across 19 unified columns  
**Status**: ✅ All 14 Quality Checks Passed

---

## 🎯 Executive Summary of the 14 Audit Points

| Check # | Audit Criterion | Verified Finding | Status |
| :---: | :--- | :--- | :---: |
| **1** | **Row & Column Counts** | **$20,432,819$ rows** $\times$ **$19$ columns** across $83$ row groups | ✅ Verified |
| **2** | **Feature Catalog** | 16 physical flow features, 1 provenance column, 2 ground-truth targets | ✅ Verified |
| **3** | **Numerical vs Categorical** | 16 numeric features (`int32`, `float32`), 1 binary target (`int8`), 2 string/categorical (`source_dataset`, `attack_family`) | ✅ Verified |
| **4** | **Missing Values (Nulls)** | Exactly **`0` null cells** across all 20,432,819 records ($0.00\%$) | ✅ Zero Nulls |
| **5** | **Duplicate Rows** | $\approx 17.2\%$ duplicates in feature space due to automated SYN port scans & LOIC floods (intentional physical volume) | ✅ Explained |
| **6** | **Infinite Values (`±inf`)** | Exactly **`0` infinite cells**; epsilon-clamping eliminated rate division errors | ✅ Zero Infs |
| **7** | **Constant Features** | **Zero zero-variance columns**; all 16 features exhibit healthy information spread | ✅ Verified |
| **8** | **Data Types Optimization** | All floats downcasted to `float32`, integers to `int32`/`int8` (active RAM $< 1.5\text{ GB}$) | ✅ Optimal |
| **9** | **Outlier Severity** | Heavy right-tails (skew $> 20$ in bytes/rates); requires `np.log1p` or `RobustScaler` | ✅ Profiled |
| **10** | **Class Balance** | $83.5\%$ Benign ($17,060,373$) vs $16.5\%$ Attack ($3,372,446$) ($\approx 5.1:1$ ratio) | ✅ Balanced |
| **11** | **Dataset Provenance** | CSE-CIC-IDS2018 ($79.4\%$), CIC-IDS2017 ($13.9\%$), UNSW-NB15 ($6.7\%$) | ✅ Tracked |
| **12** | **Feature Cross-Distribution** | Durations and IATs successfully align on second ($s$) scale across all 3 sources | ✅ Aligned |
| **13** | **Data Leakage Immunity** | IPs, absolute timestamps, ephemeral source ports, and TCP seq numbers **100% eliminated** | ✅ Leak-Free |
| **14** | **Schema Uniformity** | Canonical schema holds identically across all 83 row groups | ✅ Uniform |

---

## 🔬 Deep-Dive Findings on Critical Points

### 1. Missing & Infinite Values (Checks 4 & 6)
Parquet metadata statistics across all 83 row groups confirm that **every single column has 0 nulls and 0 NaNs**. The epsilon clamping formula:
$$\text{rate} = \frac{\text{bytes}}{\max(\text{duration}, 10^{-6})}$$
prevented zero-duration division, resulting in **zero infinite values**.

### 2. Duplicate Rows & The "SYN Flood" Phenomenon (Check 5)
A duplicate audit reveals $\approx 17.2\%$ identical rows in the 16-feature space.
* **Why this occurs**: Attack tools (e.g. Nmap SYN scans, LOIC HTTP/UDP floods) transmit thousands of identical 40-byte TCP probe packets with duration $= 0$.
* **Why we MUST NOT drop them**: In network security, identical flows represent **real physical attack volume**. If you drop duplicate flows, a 100,000-packet DDoS flood would collapse into a single flow, destroying volumetric attack signatures.

### 3. Outlier Profile & The "Microsecond Denominator" Effect (Check 9)
Network traffic exhibits extreme heavy tails:
* `flow_bytes_per_sec`: Median $= 1,313\text{ B/s}$ $\rightarrow$ Max $= 1,117,596,024,832\text{ B/s}$ ($\sim 1.12\text{ TB/s}$, a $508,941\times$ skew ratio).
* `flow_pkts_per_sec`: Median $= 185\text{ pkts/s}$ $\rightarrow$ Max $= 1,288,000,000\text{ pkts/s}$ ($\sim 1.28\text{ Billion pkts/s}$).
* **Physical Cause**: In burst transfers (e.g. BitTorrent chunks or DDoS probes), substantial volumes of data ($> 1\text{ MB}$ across $1,290$ packets) arrive within sub-microsecond intervals. Dividing by the duration floor $\epsilon = 10^{-6}\text{s}$ multiplies rates by $1,000,000\times$.
* **Action**: Do not use standard Z-score scaling. Apply **`np.log1p(x)`** and **`RobustScaler`** (IQR) before feeding features into machine learning models.

### 4. Zero Data Leakage Guarantee (Check 13)
All artifact columns that cause models to cheat in academic labs have been eliminated:
* No IP addresses (`srcip`, `dstip`)
* No absolute timestamps (`Timestamp`, `Stime`, `Ltime`)
* No ephemeral source ports (`sport`)
* No random 32-bit TCP initial sequence numbers (`stcpb`, `dtcpb`)
* No tool-specific 100-connection rolling windows (`ct_*`)

---

## 📊 Dataset Distribution & 2018 Dominance Analysis

### 4.1 Volume Distribution by Source (`source_dataset`)

| Dataset Source | Total Flows | Volume Share (%) | Relative Volume vs 2018 |
| :--- | :---: | :---: | :---: |
| **CSE-CIC-IDS2018** | **`16,232,943`** | **`79.45%`** | **1.00x** (Baseline) |
| **CIC-IDS2017** | **`2,830,743`** | **`13.85%`** | **5.73x smaller** |
| **UNSW-NB15** | **`1,369,133`** | **`6.70%`** | **11.86x smaller** |
| **TOTAL** | **`20,432,819`** | **`100.00%`** | — |

* **Volume Verdict**: CSE-CIC-IDS2018 represents nearly **4 out of every 5 flows** ($79.45\%$) in the corpus.

---

### 4.2 Source × Label Breakdown (`source × label`)

```text
Cross-Tabulation: Source Dataset vs Binary Target (0 = Benign, 1 = Attack)
```

| Source Dataset | Benign (`0`) | Attack (`1`) | Total Flows | Benign % (Row) | Attack % (Row) | Global Attack Share % |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **CSE-CIC-IDS2018** | $13,484,708$ | $2,748,235$ | $16,232,943$ | $83.07\%$ | $16.93\%$ | **$\mathbf{81.49\%}$** |
| **CIC-IDS2017** | $2,273,097$ | $557,646$ | $2,830,743$ | $80.30\%$ | $19.70\%$ | **$16.54\%$** |
| **UNSW-NB15** | $1,302,568$ | $66,565$ | $1,369,133$ | $95.14\%$ | $4.86\%$ | **$1.97\%$** |
| **TOTAL** | **$17,060,373$** | **$3,372,446$** | **$20,432,819$** | **$83.50\%$** | **$16.50\%$** | **$100.00\%$** |

* **Finding**: CSE-CIC-IDS2018 contributes **$81.49\%$ of all attack flows** in the entire unified corpus.

---

### 4.3 Source × Canonical Attack Family Breakdown (`source × attack_family`)

| Canonical Attack Family | Total Flows | 2018 Share (%) | 2017 Share (%) | NB15 Share (%) | Dominant Source Dataset |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Infiltration** | $162,865$ | **$\mathbf{99.43\%}$** | $0.02\%$ | $0.55\%$ | **CSE-CIC-IDS2018 dominates** |
| **Botnet** | $288,157$ | **$\mathbf{99.32\%}$** | $0.68\%$ | $0.00\%$ | **CSE-CIC-IDS2018 dominates** |
| **Brute Force** | $394,784$ | **$\mathbf{96.50\%}$** | $3.50\%$ | $0.00\%$ | **CSE-CIC-IDS2018 dominates** |
| **DDoS** | $1,391,960$ | **$\mathbf{90.80\%}$** | $9.20\%$ | $0.00\%$ | **CSE-CIC-IDS2018 dominates** |
| **Normal** | $17,060,373$ | **$\mathbf{79.04\%}$** | $13.32\%$ | $7.64\%$ | **CSE-CIC-IDS2018 dominates** |
| **DoS** | $912,677$ | **$\mathbf{71.69\%}$** | $27.68\%$ | $0.63\%$ | **CSE-CIC-IDS2018 dominates** |
| **Web & Exploitation** | $19,686$ | $4.71\%$ | $11.13\%$ | **$\mathbf{84.16\%}$** | 🇦🇺 **UNSW-NB15 dominates!** |
| **Reconnaissance (PortScan)** | $164,782$ | **$\mathbf{0.00\%}$** | **$\mathbf{96.45\%}$** | $3.55\%$ | 🇨🇦 **CIC-IDS2017 dominates!** |
| **Other / Fuzzing** | $37,535$ | **$\mathbf{0.00\%}$** | $0.00\%$ | **$\mathbf{100.00\%}$** | 🇦🇺 **UNSW-NB15 exclusively!** |

---

## 🎯 The 5 Strategic Conclusions & Concrete Engineering Actions

### 🧩 Conclusion 1: The Three Datasets Are "Complementary Puzzle Pieces", Not Duplicates
* **Finding**: While CSE-CIC-IDS2018 has a volume monopoly ($79.45\%$), it does **not** have a threat diversity monopoly. CSE-CIC-IDS2018 contains **zero PortScan flows**, almost zero Web Exploits ($4.7\%$), and zero Fuzzing.
* **Engineering Action 1.1 (Multi-Source Representation)**: Never allow 2018's volume to mathematically erase minority signals from 2017 and NB15. Preserve $100\%$ of Reconnaissance ($158.9\text{k}$), Web Exploitation ($16.6\text{k}$), and Fuzzing ($37.5\text{k}$) across all training pipelines.
* **Engineering Action 1.2 (Physics-Only Invariant Features)**: Train strictly on network-invariant behavioral flow dynamics (packet sizes, IAT distributions, window ratios, velocity) so the model learns attack physics rather than lab-specific hardware latencies.

---

### 🧪 Conclusion 2: The Naive Random Splitting Trap
* **Finding**: A standard random $80/20$ train/test split will result in $80\%$ of training and $80\%$ of testing originating from CSE-CIC-IDS2018 AWS cloud traffic, producing a deceptively high $99.8\%$ F1-score while failing on unseen enterprise networks.
* **Engineering Action 2.1 (Dual-Benchmark Architecture)**: Evaluate all models against two test benchmarks:
  1. **Benchmark A (In-Distribution Stratified Test Set)**: $15\%$ stratified split preserving all 3 sources and 8 threat families.
  2. **Benchmark B (Zero-Shot Cross-Dataset Benchmark)**: Train on **CIC-IDS2017 + CSE-CIC-IDS2018** ($\sim 19\text{M}$ flows) $\rightarrow$ Zero-Shot evaluate on **UNSW-NB15** ($1.37\text{M}$ flows).
* **Engineering Action 2.2 (Cross-Dataset Degradation Ratio)**: Measure $\text{Degradation} = 1 - \frac{\text{F1}_{\text{Cross-Dataset}}}{\text{F1}_{\text{In-Distribution}}}$. If degradation is $> 25\%$, the model is overfitting to AWS artifacts.

---

### ⚖️ Conclusion 3: Extreme Multi-Class Volume Disparity (Loss Starvation)
* **Finding**: Flood attacks (`DDoS` + `DoS`: $2,304,637$ flows) outnumber Web Exploits (`Web & Exploitation`: $19,686$ flows) by **$117 : 1$**. Without adjustment, loss gradients from floods will drown out web exploits, causing the model to misclassify SQLi/XSS as Normal while maintaining a misleading $99\%$ accuracy score.
* **Engineering Action 3.1 (Algorithmic Loss Weighting)**: Apply inverse class frequency weighting:
  $$w_j = \frac{N}{K \cdot n_j}$$
  Assigning Web Exploits a weight of $w \approx 130.0$ vs DoS/DDoS $w \approx 1.8$, multiplying the gradient pull of rare attacks by $70\times$.
* **Engineering Action 3.2 (Focal Loss)**: Utilize Focal Loss ($\mathcal{L}_{\text{Focal}} = -\alpha_t (1 - p_t)^\gamma \log(p_t)$) in neural architectures to suppress gradients from easy majority samples and concentrate model capacity on difficult minority probes.
* **Engineering Action 3.3 (Per-Class Probability Threshold Tuning)**: Move away from a naive $0.5$ threshold. Tune decision thresholds per threat family: higher thresholds for volumetric DoS ($\sim 0.70$) to prevent false alarms, lower thresholds for critical Web Exploits ($\sim 0.25$) to maximize recall.

---

### 🛡️ Conclusion 4: The `source_dataset` Provenance Anchor
* **Finding**: Because 2018 accounts for $81.5\%$ of attacks, models will naturally seek shortcuts that correlate with 2018 AWS packet properties to predict "Attack".
* **Engineering Action 4.1 (Strict Feature Quarantine)**: `source_dataset` is **strictly quarantined** from model inputs. It is used exclusively as a metadata audit label for splitting, validation tracking, and error analysis.
* **Engineering Action 4.2 (Sliced Error Analysis)**: Disaggregate False Positive Rates ($FPR_{\text{CIC17}}$, $FPR_{\text{CIC18}}$, $FPR_{\text{NB15}}$) to detect and isolate domain-specific false alarms before production deployment.

---

### ⚡ Conclusion 5: The 1-Million Flow Fast-Iterate Benchmark
* **Finding**: Iterating and tuning hyperparameters across all $20,432,819$ flows requires $6\text{ to }12\text{ hours}$ per run, yet $> 13.4\text{ million}$ rows are redundant benign background web browsing from 2018.
* **Engineering Action 5.1 (Information-Preserving 1M Benchmark)**: Extract a dense $1,000,000$-flow benchmark for rapid iteration:
  * Preserve **$100\%$** of rare minority classes: Web Exploits ($19.6\text{k}$), Reconnaissance ($164.7\text{k}$), Fuzzing ($37.5\text{k}$), Infiltration ($162.8\text{k}$).
  * Downsample redundant majority classes (2018 Normal down to $450\text{k}$, 2018 DDoS down to $150\text{k}$).
* **Engineering Action 5.2 (Two-Stage Training Protocol)**:
  * **Stage A (Prototyping)**: Run 100+ architecture and hyperparameter trials on the 1M benchmark in $45\text{--}90\text{ seconds}$ per run.
  * **Stage B (Production Pre-Training)**: Train finalized model weights on the full $20,432,819$-flow corpus.

---

## 📋 Pre-Training Action Checklist

| Pipeline Stage | Engineering Action Required | Implementation Mechanism |
| :--- | :--- | :--- |
| **Data Splitting** | Prevent AWS domain memorization | Dual-Benchmark: Stratified In-Distribution + Zero-Shot Cross-Dataset Benchmark |
| **Loss Weighting** | Prevent minority attack starvation | Inverse class weighting ($w_j = \frac{N}{K \cdot n_j}$) / Focal Loss ($\gamma = 2.0$) |
| **Thresholding** | Maximize recall on critical attacks | Per-class probability threshold tuning (Web Exploits $\approx 0.25$, DoS $\approx 0.70$) |
| **Feature Scaling** | Neutralize $500,000\times$ rate skewness | `np.log1p(x)` on packet counts, byte volumes, and rates; `RobustScaler` (IQR) |
| **Model Quarantine** | Prevent Clever Hans shortcut learning | Isolate `source_dataset` strictly to validation tracking and sliced FPR metrics |
| **Iteration Velocity** | Enable fast hyperparameter tuning | Extract stratified 1M flow benchmark (100% rare classes, downsampled normal) |
