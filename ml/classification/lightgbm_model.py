"""
SentinelAI - Tier 2 & Tier 3: LightGBM Classifiers
===================================================
Production-grade binary and multi-class LightGBM classifiers for
high-throughput tabular network intrusion detection.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Optional, Dict, Any, List
import lightgbm as lgb
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score, classification_report


class SentinelBinaryClassifier:
    """
    Tier 2: Supervised binary intrusion detector (0 = Normal, 1 = Attack).
    """
    
    def __init__(
        self,
        n_estimators: int = 150,
        learning_rate: float = 0.08,
        num_leaves: int = 31,
        random_state: int = 42,
        n_jobs: int = -1
    ):
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.num_leaves = num_leaves
        self.random_state = random_state
        self.n_jobs = n_jobs
        
        self.model = lgb.LGBMClassifier(
            n_estimators=self.n_estimators,
            learning_rate=self.learning_rate,
            num_leaves=self.num_leaves,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            verbose=-1
        )
        self.threshold: float = 0.5
        self.feature_names: Optional[List[str]] = None
        self.is_fitted: bool = False

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> "SentinelBinaryClassifier":
        if feature_names is not None:
            self.feature_names = list(feature_names)
        self.model.fit(X_train, y_train)
        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model is not fitted.")
        return self.model.predict_proba(X)[:, 1]

    def calibrate_threshold_for_fpr(self, X_val_normal: np.ndarray, target_fpr: float = 0.005) -> float:
        """Calibrates probability threshold to enforce low operational FPR."""
        normal_probs = self.predict_proba(X_val_normal)
        percentile = (1.0 - target_fpr) * 100.0
        self.threshold = float(np.percentile(normal_probs, percentile))
        return self.threshold

    def predict(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        t = threshold if threshold is not None else self.threshold
        probs = self.predict_proba(X)
        return (probs >= t).astype(int)

    def save(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "threshold": self.threshold,
            "feature_names": self.feature_names
        }, filepath)

    @classmethod
    def load(cls, filepath: str) -> "SentinelBinaryClassifier":
        payload = joblib.load(filepath)
        clf = cls()
        clf.model = payload["model"]
        clf.threshold = payload.get("threshold", 0.5)
        clf.feature_names = payload.get("feature_names")
        clf.is_fitted = True
        return clf


class SentinelMultiClassClassifier:
    """
    Tier 3: Multi-class threat family classifier (8 Canonical Threat Families).
    """
    
    def __init__(
        self,
        n_estimators: int = 150,
        learning_rate: float = 0.08,
        num_leaves: int = 31,
        random_state: int = 42,
        n_jobs: int = -1
    ):
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.num_leaves = num_leaves
        self.random_state = random_state
        self.n_jobs = n_jobs
        
        self.model = lgb.LGBMClassifier(
            n_estimators=self.n_estimators,
            learning_rate=self.learning_rate,
            num_leaves=self.num_leaves,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            verbose=-1
        )
        self.classes_: Optional[np.ndarray] = None
        self.feature_names: Optional[List[str]] = None
        self.is_fitted: bool = False

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        sample_weight: Optional[np.ndarray] = None,
        classes: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None
    ) -> "SentinelMultiClassClassifier":
        if feature_names is not None:
            self.feature_names = list(feature_names)
        if classes is not None:
            self.classes_ = np.array(classes)
        self.model.fit(X_train, y_train, sample_weight=sample_weight)
        if self.classes_ is None:
            self.classes_ = self.model.classes_
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model is not fitted.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model is not fitted.")
        return self.model.predict_proba(X)

    def save(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({
            "model": self.model,
            "classes_": self.classes_,
            "feature_names": self.feature_names
        }, filepath)

    @classmethod
    def load(cls, filepath: str) -> "SentinelMultiClassClassifier":
        payload = joblib.load(filepath)
        clf = cls()
        clf.model = payload["model"]
        clf.classes_ = payload.get("classes_")
        clf.feature_names = payload.get("feature_names")
        clf.is_fitted = True
        return clf
