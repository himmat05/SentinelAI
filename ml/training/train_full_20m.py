"""
SentinelAI - Full Scale 20,432,819 Flow Production Model Training
=================================================================
Trains Tier 2 Binary Gatekeeper and Tier 3 Multi-Class Threat Classifier
across the full 20.4M dataset with leak-free 90/10 stratified splitting,
memory-optimized streaming arrays, and line-rate hardware evaluation.
"""

import os
import sys
import time
import json
import joblib
import numpy as np
import pyarrow.parquet as pq
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    confusion_matrix,
    classification_report
)

DATA_PATH = "ml/data/processed/sentinel_20M_transformed.parquet"
ENCODER_PATH = "ml/saved_models/production/label_encoder.joblib"
BINARY_MODEL_OUT = "ml/saved_models/production/tier2_binary_gatekeeper.joblib"
MULTICLASS_MODEL_OUT = "ml/saved_models/production/tier3_threat_classifier.joblib"
METRICS_OUT = "ml/data/processed/full_20m_evaluation_metrics.json"

FEATURE_COLS = [
    'dst_port',
    'flow_duration_s',
    'flow_iat_mean_s',
    'fwd_iat_mean_s',
    'bwd_iat_mean_s',
    'fwd_packets',
    'bwd_packets',
    'fwd_bytes',
    'bwd_bytes',
    'fwd_pkt_len_mean',
    'bwd_pkt_len_mean',
    'flow_bytes_per_sec',
    'flow_pkts_per_sec',
    'fwd_tcp_win_ratio',
    'bwd_tcp_win_ratio',
    'traffic_symmetry_ratio',
    'pkt_len_ratio',
    'bytes_per_packet'
]


def train_production_models():
    print("=" * 70, flush=True)
    print("  SENTINELAI: FULL-SCALE 20.4M PRODUCTION MODEL TRAINING", flush=True)
    print("=" * 70, flush=True)
    t_global_0 = time.time()

    # 1. Load label encoder
    label_encoder = joblib.load(ENCODER_PATH)
    classes = list(label_encoder.classes_)
    print(f"Loaded LabelEncoder with {len(classes)} classes: {classes}", flush=True)

    # 2. Fast column-oriented load
    print("\n[Step 1/5] Loading 20,432,819 flows from parquet...", flush=True)
    t0 = time.time()
    pq_file = pq.ParquetFile(DATA_PATH)
    num_total_rows = pq_file.metadata.num_rows
    print(f"Total Rows: {num_total_rows:,} | Total Row Groups: {pq_file.metadata.num_row_groups}", flush=True)

    # Read feature columns and target columns
    read_cols = FEATURE_COLS + ['label', 'attack_family', 'source_dataset']
    table = pq_file.read(columns=read_cols)
    load_time = time.time() - t0
    print(f"Loaded PyArrow table in {load_time:.2f}s", flush=True)

    # Construct memory-efficient arrays
    t0 = time.time()
    X = np.column_stack([table.column(col).to_numpy() for col in FEATURE_COLS]).astype(np.float32)
    y_bin = table.column('label').to_numpy().astype(np.int8)
    
    # Map attack families to integer codes
    raw_families = table.column('attack_family').to_pylist()
    y_multi = label_encoder.transform(raw_families).astype(np.int8)
    
    source_datasets = table.column('source_dataset').to_pylist()
    del table  # Free PyArrow table from memory
    
    print(f"Feature matrix X shape: {X.shape} | RAM: {X.nbytes / (1024**2):.1f} MB (prepared in {time.time()-t0:.2f}s)", flush=True)
    print(f"Binary distribution: Benign={np.sum(y_bin == 0):,} ({np.mean(y_bin == 0)*100:.2f}%), "
          f"Attack={np.sum(y_bin == 1):,} ({np.mean(y_bin == 1)*100:.2f}%)", flush=True)

    # 3. Stratified 90% Train / 10% Test Splitting
    print("\n[Step 2/5] Creating stratified 90% Train / 10% Test split across 20.4M flows...", flush=True)
    t0 = time.time()
    train_idx, test_idx = train_test_split(
        np.arange(num_total_rows, dtype=np.int32),
        test_size=0.10,
        stratify=y_multi,
        random_state=42
    )
    split_time = time.time() - t0
    print(f"Split completed in {split_time:.2f}s:")
    print(f"    Train Partition: {len(train_idx):,} flows (90.0%)")
    print(f"    Test Partition:  {len(test_idx):,} flows (10.0%)", flush=True)

    # 4. Train Tier 2: Supervised Binary LightGBM Gatekeeper
    print("\n" + "=" * 70, flush=True)
    print("  [Step 3/5] Training Tier 2: Binary LightGBM Gatekeeper (18.4M Flows)", flush=True)
    print("=" * 70, flush=True)
    
    t0 = time.time()
    lgb_train_bin = lgb.Dataset(
        X[train_idx],
        label=y_bin[train_idx],
        feature_name=FEATURE_COLS,
        free_raw_data=False
    )
    
    bin_params = {
        'objective': 'binary',
        'metric': ['binary_logloss', 'auc'],
        'learning_rate': 0.08,
        'num_leaves': 63,
        'max_depth': 8,
        'subsample': 0.8,
        'subsample_freq': 1,
        'colsample_bytree': 0.8,
        'num_threads': 12,
        'random_state': 42,
        'verbose': -1
    }
    
    print("Starting booster training (150 trees, 12 threads)...", flush=True)
    bin_booster = lgb.train(
        bin_params,
        lgb_train_bin,
        num_boost_round=150
    )
    bin_train_time = time.time() - t0
    print(f"  Tier 2 Binary Gatekeeper trained in {bin_train_time:.2f}s ({bin_train_time/60:.2f} mins)", flush=True)
    
    # Save binary booster
    joblib.dump(bin_booster, BINARY_MODEL_OUT)
    print(f"Saved binary model to {BINARY_MODEL_OUT} ({os.path.getsize(BINARY_MODEL_OUT)/(1024*1024):.2f} MB)", flush=True)
    del lgb_train_bin

    # 5. Train Tier 3: Multi-Class MITRE Threat Classifier
    print("\n" + "=" * 70, flush=True)
    print("  [Step 4/5] Training Tier 3: Multi-Class Threat Classifier (9 Classes)", flush=True)
    print("=" * 70, flush=True)
    
    # Compute inverse class frequency sample weights
    class_counts = np.bincount(y_multi[train_idx], minlength=len(classes))
    total_train = len(train_idx)
    num_classes = len(classes)
    class_weights = total_train / (num_classes * np.maximum(class_counts, 1).astype(np.float64))
    sample_weights_multi = class_weights[y_multi[train_idx]]
    
    print("Inverse class weights for gradient balance:")
    for cls_name, weight, count in zip(classes, class_weights, class_counts):
        print(f"    {cls_name:20s}: weight = {weight:7.3f} (N = {count:,})")
        
    t0 = time.time()
    lgb_train_multi = lgb.Dataset(
        X[train_idx],
        label=y_multi[train_idx],
        weight=sample_weights_multi,
        feature_name=FEATURE_COLS,
        free_raw_data=False
    )
    
    multi_params = {
        'objective': 'multiclass',
        'num_class': num_classes,
        'metric': 'multi_logloss',
        'learning_rate': 0.08,
        'num_leaves': 63,
        'max_depth': 8,
        'subsample': 0.8,
        'subsample_freq': 1,
        'colsample_bytree': 0.8,
        'num_threads': 12,
        'random_state': 42,
        'verbose': -1
    }
    
    print("\nStarting multi-class booster training (150 trees x 9 classes, 12 threads)...", flush=True)
    multi_booster = lgb.train(
        multi_params,
        lgb_train_multi,
        num_boost_round=150
    )
    multi_train_time = time.time() - t0
    print(f"  Tier 3 Multi-Class Classifier trained in {multi_train_time:.2f}s ({multi_train_time/60:.2f} mins)", flush=True)
    
    # Save multi booster
    joblib.dump(multi_booster, MULTICLASS_MODEL_OUT)
    print(f"Saved multi-class model to {MULTICLASS_MODEL_OUT} ({os.path.getsize(MULTICLASS_MODEL_OUT)/(1024*1024):.2f} MB)", flush=True)
    del lgb_train_multi

    # 6. Evaluation on Held-Out Test Set (2,043,282 flows)
    print("\n" + "=" * 70, flush=True)
    print(f"  [Step 5/5] Evaluating on Held-Out Test Split ({len(test_idx):,} Flows)", flush=True)
    print("=" * 70, flush=True)
    
    X_test = X[test_idx]
    y_test_bin = y_bin[test_idx]
    y_test_multi = y_multi[test_idx]
    sources_test = [source_datasets[i] for i in test_idx]

    # Tier 2 Binary Predictions
    t0 = time.time()
    y_bin_pred_proba = bin_booster.predict(X_test, num_iteration=bin_booster.best_iteration)
    y_bin_pred = (y_bin_pred_proba >= 0.5).astype(np.int8)
    bin_infer_time = time.time() - t0
    bin_throughput = len(test_idx) / bin_infer_time

    bin_roc_auc = float(roc_auc_score(y_test_bin, y_bin_pred_proba))
    bin_pr_auc = float(average_precision_score(y_test_bin, y_bin_pred_proba))
    bin_f1 = float(f1_score(y_test_bin, y_bin_pred))
    bin_precision = float(precision_score(y_test_bin, y_bin_pred, zero_division=0))
    bin_recall = float(recall_score(y_test_bin, y_bin_pred))
    
    tn, fp, fn, tp = confusion_matrix(y_test_bin, y_bin_pred).ravel()
    bin_fpr = float(fp / (fp + tn))

    print("\n--- Tier 2 Binary Gatekeeper Test Results (2.04M Flows) ---")
    print(f"    ROC-AUC:    {bin_roc_auc:.5f}")
    print(f"    PR-AUC:     {bin_pr_auc:.5f}")
    print(f"    F1 Score:   {bin_f1:.5f}")
    print(f"    Precision:  {bin_precision:.4%}")
    print(f"    Recall:     {bin_recall:.4%}")
    print(f"    Global FPR: {bin_fpr:.4%} (FP={fp:,} / Benign={fp+tn:,})")
    print(f"    Throughput: {bin_throughput:,.0f} flows/sec")

    # Sliced FPR across source datasets
    print("\n--- Sliced False Positive Rate by Origin Network ---")
    sources_test_arr = np.array(sources_test)
    sliced_fpr = {}
    for src in sorted(list(set(sources_test))):
        mask_src = (sources_test_arr == src) & (y_test_bin == 0)
        total_benign_src = np.sum(mask_src)
        if total_benign_src > 0:
            fp_src = int(np.sum(y_bin_pred[mask_src] == 1))
            fpr_pct = float((fp_src / total_benign_src) * 100)
            sliced_fpr[src] = {
                "benign_flows": int(total_benign_src),
                "false_positives": fp_src,
                "fpr_pct": round(fpr_pct, 4)
            }
            print(f"    {src:25s}: FPR = {fpr_pct:.3f}% (FP={fp_src:,} / Benign={total_benign_src:,})")

    # Tier 3 Multi-Class Predictions
    t0 = time.time()
    y_multi_pred_proba = multi_booster.predict(X_test, num_iteration=multi_booster.best_iteration)
    y_multi_pred = np.argmax(y_multi_pred_proba, axis=1).astype(np.int8)
    multi_infer_time = time.time() - t0
    multi_throughput = len(test_idx) / multi_infer_time

    macro_f1 = float(f1_score(y_test_multi, y_multi_pred, average='macro'))
    weighted_f1 = float(f1_score(y_test_multi, y_multi_pred, average='weighted'))
    
    print("\n--- Tier 3 Multi-Class Classification Report (2.04M Flows) ---")
    print(f"    Macro F1:    {macro_f1:.4f}")
    print(f"    Weighted F1: {weighted_f1:.4f}")
    print(f"    Throughput:  {multi_throughput:,.0f} flows/sec\n")
    
    clf_rep_dict = classification_report(
        y_test_multi,
        y_multi_pred,
        target_names=classes,
        digits=4,
        output_dict=True
    )
    print(classification_report(y_test_multi, y_multi_pred, target_names=classes, digits=4))

    # Single flow latency benchmark
    sample_flows = X_test[:1000]
    latencies = []
    for i in range(1000):
        t_single_0 = time.perf_counter()
        _ = bin_booster.predict(sample_flows[i:i+1])
        latencies.append((time.perf_counter() - t_single_0) * 1_000_000)
    median_latency_us = float(np.median(latencies))
    print(f"Median Single-Flow Decision Latency: {median_latency_us:.1f}  s ({median_latency_us/1000:.3f} ms)")

    # 7. Serialize Metrics Manifest
    metrics_manifest = {
        "metadata": {
            "timestamp": "2026-10-09",
            "total_dataset_flows": int(num_total_rows),
            "train_flows": int(len(train_idx)),
            "test_flows": int(len(test_idx)),
            "training_hardware": "12-Core CPU (OpenMP Multi-threading)",
            "binary_train_duration_s": round(bin_train_time, 2),
            "multiclass_train_duration_s": round(multi_train_time, 2),
        },
        "tier2_binary_metrics": {
            "roc_auc": round(bin_roc_auc, 5),
            "pr_auc": round(bin_pr_auc, 5),
            "f1_score": round(bin_f1, 5),
            "precision": round(bin_precision, 5),
            "recall": round(bin_recall, 5),
            "empirical_fpr": round(bin_fpr, 5),
            "throughput_flows_per_sec": round(bin_throughput, 1),
            "median_single_flow_latency_us": round(median_latency_us, 1)
        },
        "sliced_fpr_by_dataset": sliced_fpr,
        "tier3_multiclass_metrics": {
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "throughput_flows_per_sec": round(multi_throughput, 1),
            "per_class_performance": {
                c: {
                    "precision": round(clf_rep_dict[c]["precision"], 4),
                    "recall": round(clf_rep_dict[c]["recall"], 4),
                    "f1_score": round(clf_rep_dict[c]["f1-score"], 4),
                    "support": int(clf_rep_dict[c]["support"])
                }
                for c in classes
            }
        }
    }

    with open(METRICS_OUT, 'w') as f:
        json.dump(metrics_manifest, f, indent=2)
    print(f"\n  Serialized complete evaluation metrics to {METRICS_OUT}")
    
    total_elapsed = time.time() - t_global_0
    print(f"\n  FULL 20.4M TRAINING RUN COMPLETED IN {total_elapsed:.1f}s ({total_elapsed/60:.2f} minutes)!")


if __name__ == "__main__":
    train_production_models()
