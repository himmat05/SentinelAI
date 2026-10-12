"""
SentinelAI - Stage 07: Model Evaluation & Line-Rate Benchmarking
================================================================
Production evaluator module for cross-dataset generalization metrics,
sliced False Positive Rates (FPR), and throughput latency benchmarking.
"""

import os
import json
import time
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from sklearn.metrics import (
    roc_auc_score, average_precision_score, f1_score,
    precision_score, recall_score, confusion_matrix, classification_report
)


class SentinelEvaluator:
    """
    Standard evaluation and benchmarking engine for SentinelAI models.
    """
    
    def __init__(self, binary_model_path: str, multiclass_model_path: str, label_encoder_path: str):
        self.bin_payload = joblib.load(binary_model_path)
        self.bin_model = self.bin_payload["model"]
        self.bin_thresh = self.bin_payload.get("threshold", 0.5)
        
        self.mc_payload = joblib.load(multiclass_model_path)
        self.mc_model = self.mc_payload["model"]
        self.le = joblib.load(label_encoder_path)

    def evaluate_binary(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        threshold: Optional[float] = None
    ) -> Dict[str, float]:
        thresh = threshold if threshold is not None else self.bin_thresh
        probs = self.bin_model.predict_proba(X_test)[:, 1]
        preds = (probs >= thresh).astype(int)
        
        roc_auc = float(roc_auc_score(y_test, probs))
        pr_auc = float(average_precision_score(y_test, probs))
        fpr = float(np.mean(preds[y_test == 0]))
        recall = float(recall_score(y_test, preds))
        precision = float(precision_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds))
        
        return {
            "roc_auc": round(roc_auc, 5),
            "pr_auc": round(pr_auc, 5),
            "threshold": round(thresh, 4),
            "fpr": round(fpr, 5),
            "recall": round(recall, 5),
            "precision": round(precision, 5),
            "f1": round(f1, 5)
        }

    def evaluate_multiclass(
        self,
        X_test: np.ndarray,
        y_test_mc: np.ndarray
    ) -> Dict[str, Any]:
        preds = self.mc_model.predict(X_test)
        macro_f1 = float(f1_score(y_test_mc, preds, average="macro"))
        weighted_f1 = float(f1_score(y_test_mc, preds, average="weighted"))
        
        report = classification_report(
            y_test_mc, preds, target_names=self.le.classes_, output_dict=True, zero_division=0
        )
        
        return {
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "per_class": report
        }

    def evaluate_throughput(self, X_sample: np.ndarray, n_warmup: int = 100) -> Dict[str, float]:
        """Measures single-flow latency and batch throughput."""
        # Warmup
        _ = self.bin_model.predict_proba(X_sample[:n_warmup])
        
        # Single flow latency (median of 500 individual runs)
        single_times = []
        for i in range(min(500, len(X_sample))):
            row = X_sample[i:i+1]
            t0 = time.perf_counter()
            _ = self.bin_model.predict_proba(row)
            single_times.append(time.perf_counter() - t0)
        single_us = float(np.median(single_times) * 1e6)
        
        # Batch throughput
        batch = X_sample[:min(50000, len(X_sample))]
        t0 = time.perf_counter()
        _ = self.bin_model.predict_proba(batch)
        batch_duration = time.perf_counter() - t0
        flows_per_sec = float(len(batch) / max(batch_duration, 1e-6))
        
        return {
            "single_flow_latency_microseconds": round(single_us, 2),
            "batch_flows_per_second": round(flows_per_sec, 1)
        }
