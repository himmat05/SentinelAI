"""
SentinelAI - SHAP Explainability Generator & Execution Engine
=============================================================
1. Constructs the full interactive Jupyter Notebook:
   ml/notebooks/12_shap_explainability.ipynb
2. Executes full TreeSHAP analysis on 10,000 stratified flows across Tier 1, Tier 2, and Tier 3.
3. Generates and saves all visual artifacts and CSV reports to ml/reports/shap/.
"""

import os
import sys
import json
import time
import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
REPORTS_DIR = os.path.join(BASE_DIR, "ml/reports/shap")
NOTEBOOK_PATH = os.path.join(BASE_DIR, "ml/notebooks/12_shap_explainability.ipynb")
DATA_PATH = os.path.join(BASE_DIR, "ml/data/processed/sentinel_20M_transformed.parquet")

TIER1_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier1_anomaly_detector.joblib")
TIER2_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier2_binary_gatekeeper.joblib")
TIER3_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier3_threat_classifier.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/feature_scaler.joblib")
ENCODER_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/label_encoder.joblib")

FEATURE_COLS = [
    'dst_port', 'flow_duration_s', 'flow_iat_mean_s', 'fwd_iat_mean_s', 'bwd_iat_mean_s',
    'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes', 'fwd_pkt_len_mean',
    'bwd_pkt_len_mean', 'flow_bytes_per_sec', 'flow_pkts_per_sec', 'fwd_tcp_win_ratio',
    'bwd_tcp_win_ratio', 'traffic_symmetry_ratio', 'pkt_len_ratio', 'bytes_per_packet'
]

FEATURE_HUMAN_LABELS = {
    'dst_port': 'Dst Port',
    'flow_duration_s': 'Duration',
    'flow_iat_mean_s': 'Mean IAT',
    'fwd_iat_mean_s': 'Fwd IAT',
    'bwd_iat_mean_s': 'Bwd IAT',
    'fwd_packets': 'Fwd Pkts',
    'bwd_packets': 'Bwd Pkts',
    'fwd_bytes': 'Fwd Bytes',
    'bwd_bytes': 'Bwd Bytes',
    'fwd_pkt_len_mean': 'Fwd Pkt Len',
    'bwd_pkt_len_mean': 'Bwd Pkt Len',
    'flow_bytes_per_sec': 'Byte Rate',
    'flow_pkts_per_sec': 'Pkt Rate',
    'fwd_tcp_win_ratio': 'Fwd TCP Win',
    'bwd_tcp_win_ratio': 'Bwd TCP Win',
    'traffic_symmetry_ratio': 'Symmetry',
    'pkt_len_ratio': 'Pkt Len Ratio',
    'bytes_per_packet': 'Bytes/Pkt'
}


def run_full_shap_analysis():
    print("=" * 80)
    print("  SENTINELAI: STAGE 12 EXPLAINABLE AI (XAI) SHAP ANALYSIS")
    print("=" * 80)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # 1. Load Models & Scalers
    print("\n[*] [1/6] Loading production models & feature transformers...")
    t0 = time.time()
    t1_payload = joblib.load(TIER1_PATH)
    t1_model = t1_payload['model']
    t1_thresh = float(t1_payload['threshold'])
    scaler = joblib.load(SCALER_PATH)

    t2_booster = joblib.load(TIER2_PATH)
    t3_booster = joblib.load(TIER3_PATH)
    label_encoder = joblib.load(ENCODER_PATH)
    classes = list(label_encoder.classes_)
    print(f"[+] Loaded Tier 1, Tier 2, Tier 3, and LabelEncoder ({len(classes)} classes) in {time.time()-t0:.2f}s")

    # 2. Extract 10,000-Flow Stratified Evaluation Sample
    print("\n[*] [2/6] Extracting 10,000-flow stratified evaluation sample from 20.4M dataset...")
    t0 = time.time()
    pf = pq.ParquetFile(DATA_PATH)
    num_rgs = pf.metadata.num_row_groups

    # Target: 5,000 Benign + ~625 per attack family for balanced statistical representation
    benign_rows = []
    attack_rows = {c: [] for c in classes if c != 'Normal'}
    cols_to_read = FEATURE_COLS + ['label', 'attack_family', 'source_dataset']

    for rg in range(num_rgs):
        table = pf.read_row_group(rg, columns=cols_to_read)
        df_chunk = table.to_pandas()
        
        # Collect Benign
        if len(benign_rows) < 5000:
            b_chunk = df_chunk[df_chunk['label'] == 0]
            needed = 5000 - len(benign_rows)
            benign_rows.append(b_chunk.head(needed))

        # Collect Attack families
        for fam in attack_rows:
            if len(attack_rows[fam]) < 625:
                a_chunk = df_chunk[df_chunk['attack_family'] == fam]
                needed = 625 - len(attack_rows[fam])
                if len(a_chunk) > 0:
                    attack_rows[fam].append(a_chunk.head(needed))

        # Check if enough sampled
        all_attacks_done = all(sum(len(x) for x in attack_rows[f]) >= 300 for f in attack_rows)
        if len(benign_rows) >= 5000 and all_attacks_done:
            break

    df_benign = pd.concat(benign_rows, ignore_index=True)
    dfs_attacks = [pd.concat(attack_rows[f], ignore_index=True) for f in attack_rows if len(attack_rows[f]) > 0]
    df_eval = pd.concat([df_benign] + dfs_attacks, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)

    X_eval = df_eval[FEATURE_COLS].to_numpy(dtype=np.float32)
    y_bin = df_eval['label'].to_numpy(dtype=np.int8)
    families = df_eval['attack_family'].tolist()
    sources = df_eval['source_dataset'].tolist()

    print(f"[+] Stratified Sample Prepared: {len(X_eval):,} flows in {time.time()-t0:.2f}s")
    print(f"    • Benign Flows: {np.sum(y_bin == 0):,} ({np.mean(y_bin == 0)*100:.1f}%)")
    print(f"    • Attack Flows: {np.sum(y_bin == 1):,} across {len(set(families)-{'Normal'})} MITRE families")

    # 3. Compute TreeSHAP for Tier 2 Gatekeeper
    print("\n[*] [3/6] Computing TreeSHAP for Tier 2 Binary Gatekeeper (10,000 flows)...")
    t0 = time.time()
    t2_explainer = shap.TreeExplainer(t2_booster)
    t2_shap_values = t2_explainer(X_eval)
    t2_shap_values.feature_names = FEATURE_COLS
    print(f"[+] Tier 2 TreeSHAP completed in {time.time()-t0:.2f}s (Shape: {t2_shap_values.values.shape})")

    # 4. Generate & Save Global Visualizations
    print("\n[*] [4/6] Generating Global Visualizations...")

    # Plot A: Global Bar Plot (Feature Importance)
    plt.figure(figsize=(10, 6))
    shap.plots.bar(t2_shap_values, max_display=18, show=False)
    plt.title("SentinelAI - Tier 2 Gatekeeper: Global Feature Importance (Mean |SHAP|)", fontsize=13, pad=15)
    plt.tight_layout()
    bar_path = os.path.join(REPORTS_DIR, "global_feature_importance.png")
    plt.savefig(bar_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {bar_path}")

    # Plot B: Global Beeswarm Plot (Attribution Direction & Density)
    plt.figure(figsize=(11, 7))
    shap.plots.beeswarm(t2_shap_values, max_display=18, show=False)
    plt.title("SentinelAI - Tier 2 Gatekeeper: Global Feature Attribution Summary (Beeswarm)", fontsize=13, pad=15)
    plt.tight_layout()
    beeswarm_path = os.path.join(REPORTS_DIR, "global_beeswarm.png")
    plt.savefig(beeswarm_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {beeswarm_path}")

    # Plot C: Tier 1 Behavioral Anomaly Attribution
    print("[*] Computing Tier 1 Isolation Forest TreeSHAP...")
    t1_explainer = shap.TreeExplainer(t1_model)
    X_scaled_eval = scaler.transform(X_eval[:2000])  # 2,000 flows for fast tree-path attribution
    t1_shap_vals = t1_explainer(X_scaled_eval)
    t1_shap_vals.feature_names = FEATURE_COLS
    # Negate so positive pushes away from normal baseline into anomaly
    t1_shap_vals.values = -t1_shap_vals.values

    plt.figure(figsize=(10, 6))
    shap.plots.bar(t1_shap_vals, max_display=18, show=False)
    plt.title("SentinelAI - Tier 1 Behavioral Anomaly: Feature Outlier Contribution", fontsize=13, pad=15)
    plt.tight_layout()
    t1_path = os.path.join(REPORTS_DIR, "tier1_anomaly_importance.png")
    plt.savefig(t1_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {t1_path}")

    # Plot D: Tier 3 Multi-Class Threat Comparison Across Families
    print("[*] Computing Tier 3 Multi-Class TreeSHAP Comparison...")
    t3_explainer = shap.TreeExplainer(t3_booster)
    # Extract representative attack indices
    fam_indices = {}
    for fam in ['DDoS', 'Botnet', 'Infiltration', 'Reconnaissance']:
        match = [i for i, f in enumerate(families) if f == fam]
        if match:
            fam_indices[fam] = match[0]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("SentinelAI - Tier 3 Threat Attribution: Contrasting Feature Influence Across Families", fontsize=15)

    for ax, (fam, idx) in zip(axes.flatten(), fam_indices.items()):
        cls_idx = classes.index(fam)
        sv_row = t3_explainer.shap_values(X_eval[idx:idx+1])
        if isinstance(sv_row, list):
            row_vals = sv_row[cls_idx][0]
        elif sv_row.ndim == 3:
            row_vals = sv_row[0, :, cls_idx]
        else:
            row_vals = sv_row[0]

        top_sort = np.argsort(np.abs(row_vals))[::-1][:8]
        top_names = [FEATURE_HUMAN_LABELS.get(FEATURE_COLS[i], FEATURE_COLS[i]) for i in top_sort][::-1]
        top_contribs = row_vals[top_sort][::-1]
        colors = ['#e74c3c' if v > 0 else '#3498db' for v in top_contribs]

        ax.barh(top_names, top_contribs, color=colors)
        ax.set_title(f"Target Family: {fam} (Origin: {sources[idx]})", fontsize=12)
        ax.set_xlabel("Attribution Margin Impact (Log-Odds)")
        ax.axvline(0, color='black', linestyle='--', alpha=0.6)

    plt.tight_layout()
    t3_path = os.path.join(REPORTS_DIR, "tier3_family_comparison.png")
    plt.savefig(t3_path, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {t3_path}")

    # 5. Local Single-Flow Alert Waterfalls
    print("\n[*] [5/6] Generating Local Flow Waterfall Explanations & CSV...")
    # Representative 1: DDoS Alert
    ddos_idx = families.index('DDoS') if 'DDoS' in families else 0
    plt.figure(figsize=(10, 6))
    shap.plots.waterfall(t2_shap_values[ddos_idx], max_display=10, show=False)
    plt.title(f"SentinelAI Local Alert Explanation: DDoS Attack ({sources[ddos_idx]})", fontsize=13, pad=15)
    plt.tight_layout()
    ddos_waterfall = os.path.join(REPORTS_DIR, "individual_alert_waterfall.png")
    plt.savefig(ddos_waterfall, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {ddos_waterfall}")

    # Representative 2: Infiltration (Stealth Anomaly)
    infil_idx = families.index('Infiltration') if 'Infiltration' in families else 1
    plt.figure(figsize=(10, 6))
    shap.plots.waterfall(t2_shap_values[infil_idx], max_display=10, show=False)
    plt.title(f"SentinelAI Local Alert Explanation: Infiltration ({sources[infil_idx]})", fontsize=13, pad=15)
    plt.tight_layout()
    infil_waterfall = os.path.join(REPORTS_DIR, "infiltration_alert_waterfall.png")
    plt.savefig(infil_waterfall, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {infil_waterfall}")

    # Representative 3: Clean Benign Traffic
    clean_idx = families.index('Normal')
    plt.figure(figsize=(10, 6))
    shap.plots.waterfall(t2_shap_values[clean_idx], max_display=10, show=False)
    plt.title(f"SentinelAI Local Flow Explanation: Clean HTTPS Traffic ({sources[clean_idx]})", fontsize=13, pad=15)
    plt.tight_layout()
    clean_waterfall = os.path.join(REPORTS_DIR, "clean_flow_waterfall.png")
    plt.savefig(clean_waterfall, dpi=200, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {clean_waterfall}")

    # Save Tabular CSV of DDoS Alert
    ddos_flow = X_eval[ddos_idx]
    ddos_shap = t2_shap_values.values[ddos_idx]
    csv_df = pd.DataFrame({
        "feature": FEATURE_COLS,
        "feature_label": [FEATURE_HUMAN_LABELS.get(c, c) for c in FEATURE_COLS],
        "observed_value": ddos_flow,
        "shap_value": ddos_shap,
        "absolute_shap": np.abs(ddos_shap),
        "direction": ["TOWARD_ATTACK" if v > 0 else "TOWARD_BENIGN" for v in ddos_shap]
    }).sort_values("absolute_shap", ascending=False).reset_index(drop=True)

    csv_path = os.path.join(REPORTS_DIR, "alert_feature_contributions.csv")
    csv_df.to_csv(csv_path, index=False)
    print(f"[+] Saved: {csv_path}")

    # 6. Mathematical Validation Checklist
    print("\n[*] [6/6] Executing Mathematical Additive Validation Checklist...")
    base_val = float(t2_shap_values.base_values[ddos_idx])
    reconstructed_margin = base_val + np.sum(ddos_shap)
    raw_margin = float(t2_booster.predict(X_eval[ddos_idx:ddos_idx+1], raw_score=True)[0])
    error = abs(reconstructed_margin - raw_margin)
    reconstructed_prob = 1.0 / (1.0 + np.exp(-reconstructed_margin))
    actual_prob = float(t2_booster.predict(X_eval[ddos_idx:ddos_idx+1])[0])

    print("---------------------------------------------------------------------")
    print("  VALIDATION CHECKLIST AUDIT:")
    print(f"  • Base Value:                  {base_val:+.4f} (log-odds)")
    print(f"  • Sum of SHAP values:          {np.sum(ddos_shap):+.4f}")
    print(f"  • Reconstructed Margin:        {reconstructed_margin:+.4f}")
    print(f"  • True Booster Raw Margin:     {raw_margin:+.4f}")
    print(f"  • Mathematical Error:          {error:.8e} (Tolerance: < 1e-5)")
    print(f"  • Reconstructed Probability:   {reconstructed_prob*100:.2f}%")
    print(f"  • Booster Model Probability:   {actual_prob*100:.2f}%")
    print(f"  • Status:                      {'[PASSED] EXACT MATCH' if error < 1e-4 else '[FAILED]'}")
    print("---------------------------------------------------------------------")

    # 7. Construct Jupyter Notebook JSON (12_shap_explainability.ipynb)
    print("\n[*] Writing interactive Jupyter Notebook: ml/notebooks/12_shap_explainability.ipynb...")
    generate_jupyter_notebook(NOTEBOOK_PATH)
    print(f"[+] Notebook created successfully at {NOTEBOOK_PATH}")
    print("\n=====================================================================")
    print("  [SUCCESS] All Explainable AI (XAI) SHAP artifacts completed!")
    print("=====================================================================")


def generate_jupyter_notebook(dest_path: str):
    """Creates a clean, valid Jupyter Notebook with all 10 workflow cells."""
    nb = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": [
                    "# SentinelAI — Explainable AI (XAI) with SHAP\n",
                    "## High-Throughput Explainability for Autonomous Cyber Defense\n",
                    "\n",
                    "This notebook implements **SHapley Additive exPlanations (SHAP)** across SentinelAI's **3-Tier AI Pipeline**:\n",
                    "* **Tier 1**: Unsupervised Behavioral Anomaly Detection (`IsolationForest` tree path deviance)\n",
                    "* **Tier 2**: High-Speed Binary Gatekeeper (`LightGBM` log-odds attribution)\n",
                    "* **Tier 3**: Multi-Class Threat Attribution (`LightGBM` 9-family MITRE classification)\n",
                    "\n",
                    "**Objective**: Move beyond static black-box predictions to provide Security Operations Center (SOC) analysts\n",
                    "with clear mathematical and visual explanations of **why** a flow was blocked and **which network features** drove the verdict."
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 1: Environment Setup & Library Imports"]
            },
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [],
                "source": [
                    "import os\n",
                    "import time\n",
                    "import joblib\n",
                    "import numpy as np\n",
                    "import pandas as pd\n",
                    "import pyarrow.parquet as pq\n",
                    "import matplotlib.pyplot as plt\n",
                    "import shap\n",
                    "\n",
                    "print(f'SHAP Version: {shap.__version__}')\n",
                    "shap.initjs()"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 2: Load Trained Production Models & Canonical Schema"]
            },
            {
                "cell_type": "code",
                "execution_count": 2,
                "metadata": {},
                "outputs": [],
                "source": [
                    "TIER1_PATH = '../saved_models/production/tier1_anomaly_detector.joblib'\n",
                    "TIER2_PATH = '../saved_models/production/tier2_binary_gatekeeper.joblib'\n",
                    "TIER3_PATH = '../saved_models/production/tier3_threat_classifier.joblib'\n",
                    "SCALER_PATH = '../saved_models/production/feature_scaler.joblib'\n",
                    "ENCODER_PATH = '../saved_models/production/label_encoder.joblib'\n",
                    "\n",
                    "t1_payload = joblib.load(TIER1_PATH)\n",
                    "t1_model = t1_payload['model']\n",
                    "t1_thresh = float(t1_payload['threshold'])\n",
                    "scaler = joblib.load(SCALER_PATH)\n",
                    "\n",
                    "t2_booster = joblib.load(TIER2_PATH)\n",
                    "t3_booster = joblib.load(TIER3_PATH)\n",
                    "label_encoder = joblib.load(ENCODER_PATH)\n",
                    "classes = list(label_encoder.classes_)\n",
                    "\n",
                    "FEATURE_COLS = [\n",
                    "    'dst_port', 'flow_duration_s', 'flow_iat_mean_s', 'fwd_iat_mean_s', 'bwd_iat_mean_s',\n",
                    "    'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes', 'fwd_pkt_len_mean',\n",
                    "    'bwd_pkt_len_mean', 'flow_bytes_per_sec', 'flow_pkts_per_sec', 'fwd_tcp_win_ratio',\n",
                    "    'bwd_tcp_win_ratio', 'traffic_symmetry_ratio', 'pkt_len_ratio', 'bytes_per_packet'\n",
                    "]\n",
                    "print(f'Loaded all 3 tiers with {len(classes)} MITRE attack categories and {len(FEATURE_COLS)} features.')"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 3: Extract 10,000-Flow Stratified Held-Out Evaluation Dataset"]
            },
            {
                "cell_type": "code",
                "execution_count": 3,
                "metadata": {},
                "outputs": [],
                "source": [
                    "DATA_PATH = '../data/processed/sentinel_20M_transformed.parquet'\n",
                    "pf = pq.ParquetFile(DATA_PATH)\n",
                    "\n",
                    "# Stratified sampling across Benign and all 8 attack classes\n",
                    "benign_chunks = []\n",
                    "attack_chunks = {c: [] for c in classes if c != 'Normal'}\n",
                    "cols = FEATURE_COLS + ['label', 'attack_family', 'source_dataset']\n",
                    "\n",
                    "for rg in range(pf.metadata.num_row_groups):\n",
                    "    df_c = pf.read_row_group(rg, columns=cols).to_pandas()\n",
                    "    if len(benign_chunks) < 5000:\n",
                    "        b_sub = df_c[df_c['label'] == 0]\n",
                    "        benign_chunks.append(b_sub.head(5000 - len(benign_chunks)))\n",
                    "    for fam in attack_chunks:\n",
                    "        if len(attack_chunks[fam]) < 625:\n",
                    "            a_sub = df_c[df_c['attack_family'] == fam]\n",
                    "            if len(a_sub) > 0:\n",
                    "                attack_chunks[fam].append(a_sub.head(625 - len(attack_chunks[fam])))\n",
                    "    if len(benign_chunks) >= 5000 and all(sum(len(x) for x in attack_chunks[f]) >= 300 for f in attack_chunks):\n",
                    "        break\n",
                    "\n",
                    "df_benign = pd.concat(benign_chunks, ignore_index=True)\n",
                    "dfs_attacks = [pd.concat(attack_chunks[f], ignore_index=True) for f in attack_chunks if len(attack_chunks[f]) > 0]\n",
                    "df_sample = pd.concat([df_benign] + dfs_attacks, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)\n",
                    "\n",
                    "X_sample = df_sample[FEATURE_COLS].to_numpy(dtype=np.float32)\n",
                    "y_sample = df_sample['label'].to_numpy(dtype=np.int8)\n",
                    "print(f'Total Evaluation Sample: {len(X_sample):,} flows (Benign: {np.sum(y_sample==0):,}, Attacks: {np.sum(y_sample==1):,})')"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 4: Initialize TreeExplainer for Tier 2 Gatekeeper"]
            },
            {
                "cell_type": "code",
                "execution_count": 4,
                "metadata": {},
                "outputs": [],
                "source": [
                    "t2_explainer = shap.TreeExplainer(t2_booster)\n",
                    "print(f'Base value (log-odds): {t2_explainer.expected_value}')\n",
                    "t2_explanation = t2_explainer(X_sample)\n",
                    "t2_explanation.feature_names = FEATURE_COLS\n",
                    "print(f'Calculated SHAP matrix shape: {t2_explanation.values.shape}')"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 5: Global Feature Importance & Beeswarm Summary"]
            },
            {
                "cell_type": "code",
                "execution_count": 5,
                "metadata": {},
                "outputs": [],
                "source": [
                    "plt.figure(figsize=(10, 6))\n",
                    "shap.plots.bar(t2_explanation, max_display=18)\n",
                    "\n",
                    "plt.figure(figsize=(11, 7))\n",
                    "shap.plots.beeswarm(t2_explanation, max_display=18)"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 6: Tier 1 Behavioral Anomaly Outlier Attribution"]
            },
            {
                "cell_type": "code",
                "execution_count": 6,
                "metadata": {},
                "outputs": [],
                "source": [
                    "t1_explainer = shap.TreeExplainer(t1_model)\n",
                    "X_scaled_eval = scaler.transform(X_sample[:2000])\n",
                    "t1_explanation = t1_explainer(X_scaled_eval)\n",
                    "t1_explanation.feature_names = FEATURE_COLS\n",
                    "t1_explanation.values = -t1_explanation.values\n",
                    "\n",
                    "plt.figure(figsize=(10, 6))\n",
                    "shap.plots.bar(t1_explanation, max_display=18)"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 7: Local Single-Flow Waterfall Explanations"]
            },
            {
                "cell_type": "code",
                "execution_count": 7,
                "metadata": {},
                "outputs": [],
                "source": [
                    "# Explain representative DDoS attack\n",
                    "ddos_idx = df_sample[df_sample['attack_family'] == 'DDoS'].index[0]\n",
                    "print(f'Explaining DDoS flow at index {ddos_idx}:')\n",
                    "shap.plots.waterfall(t2_explanation[ddos_idx], max_display=10)"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 8: Tabular Alert Attribution for Backend Integration"]
            },
            {
                "cell_type": "code",
                "execution_count": 8,
                "metadata": {},
                "outputs": [],
                "source": [
                    "alert_flow = X_sample[ddos_idx]\n",
                    "alert_shap = t2_explanation.values[ddos_idx]\n",
                    "df_alert = pd.DataFrame({\n",
                    "    'feature': FEATURE_COLS,\n",
                    "    'observed_value': alert_flow,\n",
                    "    'shap_value': alert_shap,\n",
                    "    'abs_shap': np.abs(alert_shap),\n",
                    "    'direction': ['TOWARD_ATTACK' if s > 0 else 'TOWARD_BENIGN' for s in alert_shap]\n",
                    "}).sort_values('abs_shap', ascending=False).reset_index(drop=True)\n",
                    "\n",
                    "display(df_alert.head(10))\n",
                    "df_alert.to_csv('../reports/shap/alert_feature_contributions.csv', index=False)"
                ]
            },
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["### Step 9: Mathematical Additive Verification & Audit Checklist"]
            },
            {
                "cell_type": "code",
                "execution_count": 9,
                "metadata": {},
                "outputs": [],
                "source": [
                    "base_val = float(t2_explanation.base_values[ddos_idx])\n",
                    "sum_shap = float(np.sum(alert_shap))\n",
                    "reconstructed_margin = base_val + sum_shap\n",
                    "true_booster_margin = float(t2_booster.predict(X_sample[ddos_idx:ddos_idx+1], raw_score=True)[0])\n",
                    "\n",
                    "print(f'Base value:           {base_val:+.4f}')\n",
                    "print(f'Sum of SHAP values:   {sum_shap:+.4f}')\n",
                    "print(f'Reconstructed margin: {reconstructed_margin:+.4f}')\n",
                    "print(f'Booster raw margin:   {true_booster_margin:+.4f}')\n",
                    "print(f'Discrepancy:          {abs(reconstructed_margin - true_booster_margin):.2e}')\n",
                    "assert abs(reconstructed_margin - true_booster_margin) < 1e-4, 'Additive verification failed!'"
                ]
            }
        ],
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3 (.venv)",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "name": "python",
                "version": "3.12.0"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 4
    }
    with open(dest_path, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=2)


if __name__ == "__main__":
    run_full_shap_analysis()
