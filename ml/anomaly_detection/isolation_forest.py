"""
SentinelAI - Tier 1: Unsupervised Anomaly Detection
===================================================
Production-grade Isolation Forest module designed for zero-day threat
hunting and unsupervised baseline behavioral modeling.

Learns normal enterprise traffic patterns and flags anomalous deviations
without requiring attack labels.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Optional, Dict, Any, Union
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, average_precision_score


class SentinelAnomalyDetector:
    """
    Unsupervised network flow anomaly detector based on Isolation Forests.
    
    Trained strictly on benign / normal baseline network flows to detect
    novel, unmodeled zero-day intrusions based on path-length isolation in
    high-dimensional feature space.
    """
    
    def __init__(
        self,
        n_estimators: int = 150,
        max_samples: Union[int, float] = 2048,
        contamination: Union[str, float] = "auto",
        random_state: int = 42,
        n_jobs: int = -1
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.n_jobs = n_jobs
        
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=self.n_jobs
        )
        self.threshold: Optional[float] = None
        self.feature_names: Optional[list] = None
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, feature_names: Optional[list] = None) -> "SentinelAnomalyDetector":
        """
        Fits the Isolation Forest on baseline network traffic.
        """
        if feature_names is not None:
            self.feature_names = list(feature_names)
            
        self.model.fit(X)
        self.is_fitted = True
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Computes continuous anomaly scores.
        Higher score = more anomalous / higher risk.
        Normalized so that higher values indicate outliers.
        """
        if not self.is_fitted:
            raise ValueError("Model is not fitted yet. Call fit() first.")
        # decision_function: lower means more anomalous.
        # Negate it so higher score = higher anomaly probability.
        raw_scores = self.model.decision_function(X)
        return -raw_scores

    def calibrate_threshold(self, X_val_normal: np.ndarray, target_fpr: float = 0.05) -> float:
        """
        Calibrates the binary decision threshold on held-out benign traffic
        to guarantee an operational False Positive Rate (FPR <= target_fpr).
        """
        normal_scores = self.score_samples(X_val_normal)
        # Threshold at (1 - target_fpr) percentile of benign scores
        percentile = (1.0 - target_fpr) * 100.0
        self.threshold = float(np.percentile(normal_scores, percentile))
        return self.threshold

    def predict(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        """
        Predicts binary anomaly labels (0 = Normal, 1 = Anomaly / Intrusion).
        """
        active_thresh = threshold if threshold is not None else self.threshold
        if active_thresh is None:
            # Fall back to default model offset
            return np.where(self.model.predict(X) == -1, 1, 0)
        
        scores = self.score_samples(X)
        return np.where(scores >= active_thresh, 1, 0)

    def evaluate(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray,
        attack_families: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Evaluates detector performance across binary AUC and per-family recall.
        """
        scores = self.score_samples(X_test)
        roc_auc = float(roc_auc_score(y_test, scores))
        pr_auc = float(average_precision_score(y_test, scores))
        
        results = {
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "calibrated_threshold": self.threshold
        }
        
        if self.threshold is not None:
            preds = self.predict(X_test)
            normal_mask = (y_test == 0)
            actual_fpr = float(np.mean(preds[normal_mask]))
            attack_recall = float(np.mean(preds[~normal_mask]))
            results["empirical_fpr"] = round(actual_fpr, 4)
            results["overall_attack_recall"] = round(attack_recall, 4)
            
            if attack_families is not None:
                family_recall = {}
                for fam in np.unique(attack_families):
                    if fam == "Normal":
                        continue
                    mask = (attack_families == fam)
                    family_recall[fam] = {
                        "recall": round(float(np.mean(preds[mask])), 4),
                        "total_flows": int(np.sum(mask))
                    }
                results["family_recall"] = family_recall
                
        return results

    def save(self, filepath: str):
        """Serializes detector weights and calibrated threshold."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        payload = {
            "model": self.model,
            "threshold": self.threshold,
            "feature_names": self.feature_names,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": self.contamination
        }
        joblib.dump(payload, filepath)

    @classmethod
    def load(cls, filepath: str) -> "SentinelAnomalyDetector":
        """Loads serialized detector."""
        payload = joblib.load(filepath)
        detector = cls(
            n_estimators=payload["n_estimators"],
            max_samples=payload["max_samples"],
            contamination=payload["contamination"]
        )
        detector.model = payload["model"]
        detector.threshold = payload.get("threshold")
        detector.feature_names = payload.get("feature_names")
        detector.is_fitted = True
        return detector
