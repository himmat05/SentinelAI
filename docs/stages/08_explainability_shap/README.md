# Stage 08: Explainable AI (XAI) with SHAP

**Location**: `docs/stages/08_explainability_shap/`  
**Interactive Notebook**: [`ml/notebooks/12_shap_explainability.ipynb`](../../../ml/notebooks/12_shap_explainability.ipynb)  
**Production Explainer**: [`ml/explainability/shap_explainer.py`](../../../ml/explainability/shap_explainer.py)  
**Visual Artifacts**: [`ml/reports/shap/`](../../../ml/reports/shap/)  
**Status**: Completed & Verified

---

## 1. Overview & Architectural Role

SentinelAI implements **TreeSHAP (SHapley Additive exPlanations)** natively across all 3 tiers of its autonomous defense pipeline:

1. **Tier 1 (Behavioral Anomaly)**: Explains unsupervised outlier deviance in isolation tree path length space on RobustScaled features.
2. **Tier 2 (Binary Gatekeeper)**: Explains wire-speed binary intrusion decisions in margin log-odds space, ranking the features pushing toward attack ($+ \phi$) versus benign ($- \phi$).
3. **Tier 3 (Threat Attribution)**: Explains multi-class MITRE classification across 9 attack families (DDoS, Botnet, Infiltration, Brute Force, etc.).

---

## 2. Generated Visual Artifacts (`ml/reports/shap/`)

| Artifact | File | Description |
|---|---|---|
| **Global Importance** | `global_feature_importance.png` | Ranks all 18 features by mean absolute SHAP impact ($\frac{1}{N}\sum \|\phi_i\|$) across 436,541 flows. |
| **Global Beeswarm** | `global_beeswarm.png` | Feature value distribution (red = high, blue = low) vs. impact on attack score. |
| **Tier 1 Anomaly** | `tier1_anomaly_importance.png` | Path length deviance ranking on baseline network physics. |
| **Tier 3 Attribution** | `tier3_family_comparison.png` | Contrasting decision drivers for DDoS, Infiltration, Botnet, and Reconnaissance. |
| **DDoS Waterfall** | `individual_alert_waterfall.png` | Step-by-step log-odds accumulation for a representative DDoS attack. |
| **Infiltration Waterfall**| `infiltration_alert_waterfall.png`| Step-by-step log-odds accumulation for a stealth SMB Infiltration attack. |
| **Clean Flow Waterfall** | `clean_flow_waterfall.png` | Step-by-step log-odds accumulation for verified benign HTTPS traffic. |
| **Alert Contributions** | `alert_feature_contributions.csv` | Structured CSV report of feature-by-feature SHAP attributions. |

---

## 3. Mathematical Additive Validation

TreeSHAP guarantees exact additive local explanation:

$$\text{Margin Score} = \text{base\_value} + \sum_{i=1}^{18} \phi_i$$

$$\text{Probability} = \frac{1}{1 + e^{-\text{Margin Score}}}$$

* **Base Value**: `-3.6732` (log-odds)
* **Sum of SHAP Values ($\sum \phi_i$)**: `+10.7928`
* **Reconstructed Margin**: `+7.1196`
* **True Booster Raw Score**: `+7.1196`
* **Discrepancy / Error**: `1.776e-15` (**Zero numerical loss**, exact floating-point match)
* **Predicted Probability**: `99.92%` (Matched to LightGBM output)

---

## 4. Production Integration: Microservice Endpoints

* **On-Demand Explanation**: `POST /api/explain`
  * Accepts a single flow vector.
  * Returns JSON payload with top-K decisive features, directions, percentage importances, and human-readable narrative.
* **Inline Explanation**: `POST /api/predict?explain=true`
  * Attaches full `FlowExplanationResponse` directly to the security verdict.
* **WebSocket Alerts**: `WS /api/ws/alerts`
  * Automatically embeds `top_decisive_factors` (e.g. `["Symmetry (+2.17)", "Dst Port (+1.61)"]`) into real-time SOC alerts.
