# Stage 05: Feature Engineering & Dual-Benchmark Data Splitting

**Location**: `docs/stages/05_feature_engineering_and_splitting/`  
**Pipeline Notebook**: [`ml/notebooks/08_feature_engineering_and_splits.ipynb`](../../../ml/notebooks/08_feature_engineering_and_splits.ipynb)  
**Fast-Iterate Dataset**: [`ml/data/processed/sentinel_1M_benchmark.parquet`](../../../ml/data/processed/sentinel_1M_benchmark.parquet) ($1,000,000$ flows, $28.67\text{ MB}$)  
**Master Corpus**: `ml/data/processed/merged_sentinel_core.parquet` ($20,432,819$ flows, $677.15\text{ MB}$)  
**Status**: ✅ Completed & Verified

---

## 📑 Stage Documentation & Reports

* 📄 **[07_feature_engineering_and_splitting_report.md](07_feature_engineering_and_splitting_report.md)**:
  * Complete report on the 1-Million Fast-Iterate Benchmark extraction.
  * Quantitative skewness reduction tables across all 12 log-transformed features.
  * Inverse class frequency weighting matrix and relative gradient multipliers.
  * Dual-Benchmark partition verification (Benchmark A Stratified vs Benchmark B Cross-Dataset).

---

## 🔬 Core Achievements in Stage 05

1. **Extraction of the 1-Million Fast-Iterate Benchmark**:
   * Extracted `sentinel_1M_benchmark.parquet` ($28.67\text{ MB}$) in $28.78$ seconds.
   * Preserves **$100\%$ of all rare minority attack flows**: Web Exploits ($19.6\text{k}$), Reconnaissance ($164.7\text{k}$), Fuzzing ($37.5\text{k}$), Infiltration ($162.8\text{k}$).
   * Reduces training trial cycle from 6 hours to **$< 45$ seconds**.

2. **Non-Linear Rate & Volume Transformation**:
   * Applied `np.log1p` to 12 heavy-tailed rate and volume features.
   * `flow_bytes_per_sec` skewness dropped from **$+553.08$** to **$-0.18$**.
   * `flow_pkts_per_sec` skewness dropped from **$+528.83$** to **$-0.15$**.

3. **Engineering of Derived Physical Features**:
   * **`pkt_len_ratio`**: $\frac{\text{fwd\_pkt\_len\_mean}}{\text{bwd\_pkt\_len\_mean} + 10^{-6}}$ (captures directional payload asymmetry in web attacks).
   * **`bytes_per_packet`**: $\frac{\text{fwd\_bytes} + \text{bwd\_bytes}}{\text{fwd\_packets} + \text{bwd\_packets}}$ (packet byte density).

4. **Dual-Benchmark Splitting Architecture**:
   * **Benchmark A (In-Distribution Stratified Split)**: $700\text{k}$ Train, $150\text{k}$ Val, $150\text{k}$ Test stratified on `attack_family` (identical class proportions within $0.01\%$).
   * **Benchmark B (Zero-Shot Cross-Dataset Benchmark)**: $907,156$ flows (CIC-17 + CIC-18) $\rightarrow$ $92,844$ flows (UNSW-NB15) to evaluate domain transferability.

5. **Leak-Free Scaler Pipeline & Class Weights**:
   * Serialized fitted `RobustScaler` to [`ml/saved_models/feature_scaler.joblib`](../../../ml/saved_models/feature_scaler.joblib).
   * Computed exact inverse class frequency weights giving Web Exploits a **$21.1\times$** gradient multiplier over Normal traffic, saved to [`ml/saved_models/class_weights.json`](../../../ml/saved_models/class_weights.json).
   * Serialized deterministic partition index map to [`ml/data/processed/benchmark_splits_manifest.json`](../../../ml/data/processed/benchmark_splits_manifest.json).
