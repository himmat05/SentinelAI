# Stage 07: Model Evaluation, Explainability & Cross-Dataset Benchmarks

**Location**: `docs/stages/07_evaluation/`  
**Evaluation Notebook**: [`ml/notebooks/11_model_evaluation_explainability_benchmarks.ipynb`](../../../ml/notebooks/11_model_evaluation_explainability_benchmarks.ipynb)  
**Evaluator Module**: [`ml/evaluation/evaluator.py`](../../../ml/evaluation/evaluator.py)  
**System Metrics**: [`ml/data/processed/system_evaluation_metrics.json`](../../../ml/data/processed/system_evaluation_metrics.json)  
**Status**: ✅ Completed & Verified

---

## 📑 Stage Documentation & Reports

* 📄 **[10_model_evaluation_explainability_report.md](10_model_evaluation_explainability_report.md)**:
  * **Dual-Benchmark Evaluation**: Comparison of Benchmark A (In-Distribution $150\text{k}$ test flows) vs Benchmark B (Zero-Shot Cross-Dataset on $92.8\text{k}$ UNSW-NB15 flows).
  * **Degradation Ratio**: Confirmed **`-4.89%` degradation** (zero loss on unseen Australian enterprise traffic).
  * **Sliced False Positive Rates**: Uniform FPR between $0.49\%$ and $1.00\%$ across all three origin datasets.
  * **TreeSHAP Explainability**: Global feature attribution hierarchy and per-family decision drivers.
  * **Throughput Latency Benchmark**: Measured **$257,167\text{ flows/sec}$** line-rate throughput.

* 📄 **[11_full_scale_20m_production_training_report.md](11_full_scale_20m_production_training_report.md)**:
  * **Full 20.4M Scale-Up**: Trained across **$18,389,537$ flows** in $15.4\text{ minutes}$ across 12 OpenMP CPU threads.
  * **2.04 Million Held-Out Test Evaluation**: Demonstrated a jump from `0.9523` to **`0.9918` ROC-AUC**, `0.8722` to **`0.9730` F1**, and `77.6%` to **`95.0%` attack recall**.
  * **10× False Alarm Suppression**: Reduced global false alarm rate from $0.54\%$ down to **`0.0576%`** ($0.036\%$ on AWS, $0.086\%$ on Canadian Lab, $0.229\%$ on Australian Enterprise).
  * **Sub-100µs Decision Latency**: Single-flow decision latency cut to **`57.0 µs` ($0.057\text{ ms}$)** with batch throughput reaching **`654,327 flows/sec`**.

---

## 🔬 Core System Benchmarks (Full 20.4M Production Models)

| Benchmark Dimension | Measured Result (2.04M Test Set) | Operational Assessment |
| :--- | :---: | :--- |
| **Production Binary ROC-AUC** | **`0.99183`** | Near-perfect discrimination on $2.04\text{M}$ test flows |
| **Production Binary PR-AUC** | **`0.98340`** | Flawless precision at extreme recall thresholds |
| **Production Binary F1** | **`0.97296`** | Exceptional harmonic balance |
| **Attack Detection Recall** | **`95.01%`** | Only $4.99\%$ missed intrusions out of $337\text{k}$ attack test flows |
| **Global Benign FPR** | **`0.0576%` (5.8 per 10k)** | **$99.94\%$ Benign Cleanliness** (Prevents alert fatigue) |
| **Sliced Benign FPR** | **`0.036% - 0.229%`** | Ultra-clean across AWS, Canadian Lab & Australian Enterprise |
| **Batch Line-Rate Speed** | **`654,327 flows/sec`** | $> 9\times$ headroom for 10Gbps wire rates |
| **Single-Flow Decision Latency** | **`57.0 microseconds`** | Wire-speed inline inspection ($0.057\text{ ms}$) |
