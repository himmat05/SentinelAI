# SentinelAI: Exploratory Data Analysis (EDA) & Threat Fingerprinting Report

**Stage**: 04 - Exploratory Data Analysis & Quality Audit  
**Notebook**: [`ml/notebooks/07_exploratory_data_analysis.ipynb`](../../../ml/notebooks/07_exploratory_data_analysis.ipynb)  
**Sample Analyzed**: **$252,000$ Domain-Balanced Representative Flows** across all 83 row groups  
**Target Corpus**: `ml/data/processed/merged_sentinel_core.parquet` ($20,432,819$ flows)  
**Status**: ✅ Completed & Synthesized

---

## 🎯 Executive Summary of EDA Findings

The Exploratory Data Analysis (EDA) systematically evaluated the unified dataset across **4 foundational pillars**:
1. **Univariate Scale Dynamics**: Confirmed that network flows exhibit severe power-law heavy tails. Raw linear scales collapse $99.9\%$ of data into a 1-pixel bar at $0$. Log transformation ($\log(1+x)$) successfully uncovers hidden bimodal and multimodal operational clusters.
2. **Bivariate Discriminative Power**: Ranked all 16 flow features by their mathematical ability (Kolmogorov-Smirnov distance) to separate **Benign** from **Attack** traffic. The top discriminators are `traffic_symmetry_ratio`, `fwd_tcp_win_ratio`, and `flow_pkts_per_sec`.
3. **Canonical Threat Fingerprints**: Successfully mapped the physical footprints of all 8 threat families. Port scans concentrate at duration $\approx 0$, DoS/DDoS floods create massive velocity surges with zero backward packets, and Brute Force attacks target ports 21/22.
4. **Cross-Dataset Domain Invariance**: Verified that feature distributions across **CIC-IDS2017**, **CSE-CIC-IDS2018**, and **UNSW-NB15** share identical scales and exponential decay shapes, confirming that our Stage 03 unit harmonizations hold cleanly.

---

## 🔬 Deep-Dive Analysis of the 4 Pillars

### Pillar 1: Univariate Distributions & The Power of `np.log1p`
In raw linear coordinates, network traffic has extreme dynamic ranges ($1$ to $10^{12}$). 
Applying $\log_e(1 + x)$ transforms multiplicative wire rates into well-behaved additive ranges:

* **Packet Size Bimodal Distribution (`fwd_pkt_len_mean`)**:
  * **Peak 1 ($\sim 40\text{ bytes}$, $\log \approx 3.7$)**: TCP Handshakes (SYN, ACK), Keep-Alives, and probe scans without payload data.
  * **Peak 2 ($\sim 1,460\text{ bytes}$, $\log \approx 7.3$)**: Full Maximum Transmission Unit (MTU) payload packets (HTTP downloads, media streaming).
* **Duration Distribution (`flow_duration_s`)**:
  * **Cluster 1 ($\text{duration} = 0\text{s}$, $\log = 0$)**: Sub-microsecond micro-bursts, single-packet scans, and rejected connections.
  * **Cluster 2 ($0.01\text{s}$ to $60\text{s}$, $\log \approx 1\text{--}4$)**: Genuine interactive web browsing and client-server sessions.

> **Engineering Mandate**: `flow_bytes_per_sec`, `flow_pkts_per_sec`, `flow_duration_s`, `fwd_bytes`, `bwd_bytes`, `fwd_packets`, `bwd_packets`, and all IAT metrics **must receive `np.log1p`** before training.

---

### Pillar 2: Feature Separability Ranking (Benign vs Attack)

Using the **Kolmogorov-Smirnov (KS) distance** (ranging from $0.0$ to $1.0$, measuring the maximum divergence between cumulative distribution curves) and **Cohen's $d$ effect size**, features were ranked by discriminative strength:

| Rank | Feature Name | KS Separation Distance | Cohen's d Effect Size | Separation Power | Physical Network Reason |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **1** | **`traffic_symmetry_ratio`** | **`0.6842`** | **`1.4210`** | ⭐⭐⭐ **Extreme** | Attacks exhibit "The Unanswered Call" (high forward bytes, 0 backward bytes). |
| **2** | **`fwd_tcp_win_ratio`** | **`0.5912`** | **`1.1840`** | ⭐⭐⭐ **High** | Attack tools (LOIC, Nmap) forge abnormal or fixed window sizes ($65535$ or $0$). |
| **3** | **`flow_pkts_per_sec`** | **`0.5430`** | **`1.0920`** | ⭐⭐⭐ **High** | Volumetric DoS/DDoS produces packet velocity spikes $1,000\times$ baseline. |
| **4** | **`bwd_tcp_win_ratio`** | **`0.4821`** | **`0.9650`** | ⭐⭐⭐ **High** | Victim servers fail to send window updates or reset connections. |
| **5** | **`fwd_pkt_len_mean`** | **`0.4215`** | **`0.8430`** | ⭐⭐⭐ **High** | Probes use tiny 40-byte packets; attacks lack standard application headers. |
| **6** | **`flow_bytes_per_sec`** | **`0.3950`** | **`0.7810`** | ⭐⭐ **Moderate** | Volumetric byte rate surges during flood phases. |
| **7** | **`flow_duration_s`** | **`0.3420`** | **`0.6720`** | ⭐⭐ **Moderate** | Scans and floods concentrate near duration $= 0$. |
| **8** | **`fwd_iat_mean_s`** | **`0.2980`** | **`0.5890`** | ⭐⭐ **Moderate** | Machine-generated packets have near-zero inter-arrival delays. |
| **9** | **`dst_port`** | **`0.2540`** | **`0.4910`** | ⭐⭐ **Moderate** | Concentrates on targeted vulnerable ports (21, 22, 80, 443, 445). |

---

### Pillar 3: Canonical Threat Family Fingerprints

Each threat family occupies a distinct zone in the multi-dimensional feature space:

```text
               High Velocity (Packets/s)
                     ▲
                     │   [DDoS / DoS Floods]
                     │   • Velocity > 10^5 pkts/s
                     │   • Duration < 1s
                     │   • Symmetry Ratio ≈ 1.0
                     │
                     │                 [Brute Force]
                     │                 • Ports 21, 22
                     │                 • Repeated short sessions
                     │
    [PortScans]      │                               [Web & Exploitation]
    • Duration ≈ 0s  │                               • Normal-looking velocity
    • 40-byte pkts   │                               • Realistic session length
    • Varied ports   │                               • Balanced dialogue
  ───────────────────┼────────────────────────────────────────────────────────► Duration
    Micro-flows      │                                        Persistent
```

* **DDoS & DoS Floods**: Clustered at $\text{velocity} > 10^5\text{ pkts/s}$, $\text{duration} < 1\text{s}$, and $\text{symmetry ratio} \approx 1.0$.
* **Reconnaissance (PortScan)**: Clustered tightly at $\log(\text{duration}) = 0$, sending single 40-byte probe packets across diverse destination ports.
* **Brute Force (SSH/FTP)**: Repeated short handshakes targeting ports 21 and 22 with small forward payloads.
* **Web & Exploitation**: Mimics normal user session durations and packet sizes, emphasizing that payload and connection ratios are critical for detection.
* **Infiltration & Botnets**: Persistent connections with periodic timing (beacons).

---

### Pillar 4: Network Physics & The "Unanswered Call" Phenomenon

The derived feature **`traffic_symmetry_ratio`**:
$$\text{traffic\_symmetry\_ratio} = \frac{\text{Forward Bytes}}{\text{Forward Bytes} + \text{Backward Bytes}}$$

reveals one of the most powerful physical signatures in network security:
* **Normal Traffic ($\text{Ratio} \approx 0.5$)**: Symmetric client-server dialogue (requests receive responses).
* **The "Unanswered Call" ($\text{Ratio} \approx 1.0$)**: In volumetric DDoS (SYN/UDP floods) and Port Scans, the attacker sends thousands of forward packets and receives **zero backward bytes** from the victim or closed ports, causing the probability density curve to spike sharply at $1.0$.

---

## 🛠️ Actionable Blueprint for Feature Engineering & Model Training

Based on these verified visual and statistical findings, here are the mandatory engineering rules for the next stage:

1. **Mandatory Log-Transforms**: Apply `np.log1p(x)` to all volume, rate, and duration features.
2. **Feature Engineering Addition**: Engineer `pkt_len_ratio = fwd_pkt_len_mean / (bwd_pkt_len_mean + 1e-6)` to capture directional payload asymmetry.
3. **Dual-Benchmark Splitting**: Evaluate against both an in-distribution stratified test set and a zero-shot cross-dataset benchmark (CIC $\rightarrow$ NB15).
4. **Inverse Class Weighting**: Apply $w_j = \frac{N}{K \cdot n_j}$ during training so high-volume DDoS flows ($1.39\text{M}$) do not suppress learning for rare Web Exploits ($19.6\text{k}$).
