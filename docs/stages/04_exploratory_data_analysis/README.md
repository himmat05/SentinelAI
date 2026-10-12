# Stage 04: Exploratory Data Analysis (EDA) & Data Quality Audit

**Location**: `docs/stages/04_exploratory_data_analysis/`  
**Pipeline Notebooks**: 
* [`ml/notebooks/05_create_unified_dataset.ipynb`](../../../ml/notebooks/05_create_unified_dataset.ipynb) — Zero-OOM Streaming PyArrow Merge Pipeline
* [`ml/notebooks/06_data_quality_and_standardization.ipynb`](../../../ml/notebooks/06_data_quality_and_standardization.ipynb) — 14-Point Quality Audit & 2018 Dominance Analysis
* [`ml/notebooks/07_exploratory_data_analysis.ipynb`](../../../ml/notebooks/07_exploratory_data_analysis.ipynb) — Distribution Analysis, Threat Fingerprinting & Separability Ranking  
**Target Dataset**: [`ml/data/processed/merged_sentinel_core.parquet`](../../../ml/data/processed/merged_sentinel_core.parquet)  
**Status**: ✅ Complete & Synthesized

---

## 📑 Stage Overview & Documentation Index

Stage 04 establishes empirical ground truth for the unified cross-dataset corpus ($20,432,819$ flows). This directory contains two deep-dive technical reports covering our data quality audit, source composition analysis, statistical distribution modeling, and discriminative feature rankings:

1. **[05_data_quality_and_standardization_report.md](05_data_quality_and_standardization_report.md)**:
   * **14-Point Data Quality Audit**: Complete verification of row/column dimensions, zero nulls, zero infs, duplicate flow preservation, and data leakage elimination.
   * **Dataset Distribution & 2018 Dominance Analysis**: Source volume shares, source $\times$ binary label cross-tabulation, and source $\times$ attack family cross-tabulation.
   * **The 5 Strategic Conclusions & Concrete Engineering Actions**: Dual-Benchmark evaluation, inverse loss weighting, feature quarantine, and the 1-Million Flow Fast-Iterate Benchmark.

2. **[06_exploratory_data_analysis_report.md](06_exploratory_data_analysis_report.md)**:
   * **The 4 EDA Pillars**: Univariate scale dynamics, bivariate class separability, canonical threat family fingerprints, and traffic symmetry physics.
   * **Kolmogorov-Smirnov (KS) Separability Rankings**: Quantitative benchmark ranking all 16 flow features by their mathematical ability to separate Benign from Attack traffic.
   * **The "Unanswered Call" Phenomenon**: Mathematical and physical explanation of DoS/DDoS symmetry ratio spiking at $1.0$.

---

## 📊 Final Unified Dataset Architecture

| Metric | Verified Empirical Value | Operational Context |
| :--- | :---: | :--- |
| **Total Flows** | **`20,432,819`** | $100\%$ of flows streamed across all three source datasets without dropping records |
| **Total Features** | **`19`** | 16 physical flow features, 1 provenance column (`source_dataset`), 2 targets |
| **Storage Footprint** | **`645.78 MB`** | Compressed columnar Parquet (down from $> 7.65\text{ GB}$ of raw CSVs) |
| **Row Groups** | **`83`** | Formatted in $250,000$-row chunks for fast parallel out-of-core reading |
| **Missing Values (Nulls)** | **`0`** | Complete zero-null integrity across all 20M rows |
| **Infinite Values (`±inf`)** | **`0`** | Eliminated rate division errors via epsilon-clamping ($\max(\text{duration}, 10^{-6}\text{s})$) |
| **Target Distribution** | **$83.50\%$ Benign / $16.50\%$ Attack** | $17,060,373$ Benign flows vs $3,372,446$ Attack flows ($\approx 5.06 : 1$ ratio) |

---

## 🔬 Core Insights from Data Quality & Inspection

### 1. The Duplicate Flow Reality (SYN Floods & Scans)
* An audit of identical rows in the 16-feature space revealed $\approx 17.2\%$ duplicates.
* **Network Reality**: Attack tools (e.g. Nmap SYN scans, LOIC floods) deliberately blast thousands of identical 40-byte probe packets with duration $= 0\text{s}$.
* **Decision**: **Do not drop duplicate flows**. In network security, flow volume *is* the attack signature. Dropping duplicates collapses a 100,000-packet flood into a single benign-looking packet.

### 2. The "Microsecond Denominator" Effect & Rate Skewness
* Maximum recorded rates reach extreme values (`flow_bytes_per_sec` $\sim 1.12\text{ TB/s}$, `flow_pkts_per_sec` $\sim 1.28\text{ Billion pkts/s}$, skew $> 500,000\times$).
* **Root Cause**: High-throughput micro-bursts (e.g. BitTorrent chunks transferring $1.11\text{ MB}$ across $1,290$ packets) have duration recorded as $0.0\text{s}$. Dividing by the safety floor $\epsilon = 10^{-6}\text{s}$ multiplies rates by $1,000,000\times$.
* **Mandate**: Never use naive Z-score standardization. Features must undergo **$\log_e(1 + x)$ transformation** and **`RobustScaler`** (IQR).

### 3. Absolute Data Leakage Immunity
* Eliminated all spurious lab artifacts: no IP addresses (`srcip`, `dstip`), no timestamps (`Timestamp`, `Stime`), no ephemeral source ports (`sport`), no random TCP initial sequence numbers (`stcpb`, `dtcpb`), and no tool-specific rolling windows (`ct_*`).

---

## 🌐 Dataset Distribution & 2018 Dominance Analysis

```text
Source Volume Breakdown:
CSE-CIC-IDS2018: 16,232,943 flows (79.45%)  ████████████████████████████████████
CIC-IDS2017:      2,830,743 flows (13.85%)  ██████
UNSW-NB15:        1,369,133 flows  (6.70%)  ███
```

### The "Complementary Puzzle Pieces" Discovery
While CSE-CIC-IDS2018 represents **$79.45\%$ of total flows** and **$81.49\%$ of attacks**, cross-tabulations reveal critical blind spots:
* **Reconnaissance (PortScan)**: CSE-CIC-IDS2018 contains **$0.00\%$ Reconnaissance flows**; **$96.45\%$** comes from CIC-IDS2017 ($158,930$ flows).
* **Web Exploitation**: UNSW-NB15 contributes **$84.16\%$** ($16,568$ flows) of all Web Exploits (SQLi, XSS, Command Injection).
* **Fuzzing**: UNSW-NB15 provides **$100.00\%$** ($37,535$ flows) of all Fuzzing attacks.

> [!IMPORTANT]
> All three datasets are non-redundant and mandatory. Without CIC-IDS2017, the model is blind to Port Scans. Without UNSW-NB15, the model is blind to Web Attacks and Fuzzing.

---

## 📈 Exploratory Data Analysis (EDA) Highlights

### 1. Univariate Dynamics: Linear Failure vs Log Scale Success
Network flow features follow extreme heavy-tailed power laws. On raw linear scales, $99.9\%$ of data collapses into a single bar at $0$. Applying $\log_e(1 + x)$ reveals clear physical operational modes:
* **Packet Size (`fwd_pkt_len_mean`)**: Unmasks two distinct physical peaks:
  1. $\sim 40\text{ bytes}$ ($\log \approx 3.7$): TCP Handshakes (SYN, ACK), Keep-Alives, and probe scans.
  2. $\sim 1,460\text{ bytes}$ ($\log \approx 7.3$): Maximum Transmission Unit (MTU) payload packets (HTTP downloads, media streams).
* **Duration (`flow_duration_s`)**: Unmasks sub-microsecond micro-bursts ($\log = 0$) versus long interactive sessions ($1\text{s}$ to $60\text{s}$, $\log \approx 1\text{--}4$).

### 2. Kolmogorov-Smirnov (KS) Separability Rankings

Top features ranked by mathematical ability to distinguish Benign from Attack traffic:

| Rank | Feature | KS Distance | Cohen's d | Physical Discriminative Reason |
| :---: | :--- | :---: | :---: | :--- |
| **1** | **`traffic_symmetry_ratio`** | **`0.6842`** | `1.421` | Attacks exhibit "The Unanswered Call" (forward bytes high, backward bytes 0). |
| **2** | **`fwd_tcp_win_ratio`** | **`0.5912`** | `1.184` | Attack tools forge fixed or extreme window sizes ($0$ or $65535$). |
| **3** | **`flow_pkts_per_sec`** | **`0.5430`** | `1.092` | Volumetric DoS/DDoS packet velocity spikes $1,000\times$ baseline. |
| **4** | **`bwd_tcp_win_ratio`** | **`0.4821`** | `0.965` | Target servers fail to respond with window updates. |
| **5** | **`fwd_pkt_len_mean`** | **`0.4215`** | `0.843` | Scans use tiny 40-byte probe packets lacking application data. |

### 3. Threat Family Behavioral Signatures
* **DoS / DDoS Floods**: Clustered at extreme velocities ($> 10^5\text{ pkts/s}$), sub-second duration, and symmetry ratio $\approx 1.0$.
* **Reconnaissance (PortScan)**: Concentrated tightly at $\log(\text{duration}) = 0$, sending 40-byte probe packets across diverse destination ports.
* **Brute Force (SSH/FTP)**: Repeated short handshakes targeting ports 21 and 22 with small payload exchanges.
* **Web Exploitation**: Emulates normal user session lengths and packet sizes; separated primarily through directional byte ratios and window metrics.

---

## 🛠️ Next Steps: Transitioning to Stage 05

With data quality verified and statistical distributions profiled, the project advances to **Stage 05: Feature Engineering & Data Splitting**:
1. **Apply Transformations**: Implement `np.log1p(x)` on all 8 heavy-tailed volume, rate, and duration features.
2. **Engineer Derived Features**: Create `pkt_len_ratio = fwd_pkt_len_mean / (bwd_pkt_len_mean + 1e-6)`.
3. **Dual-Benchmark Partitioning**: Construct the Stratified In-Distribution split ($70/15/15$) and the Zero-Shot Cross-Dataset split (Train on CIC-17+18 $\rightarrow$ Test on UNSW-NB15).
4. **Extract 1M Fast-Iterate Benchmark**: Downsample majority classes while preserving $100\%$ of rare attack flows for rapid prototyping.
5. **Fit Scalers**: Fit `RobustScaler` / `StandardScaler` strictly on training data to prevent test leakage.
