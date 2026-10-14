"""
SentinelAI - Production Explainable AI (XAI) Engine with SHAP
=============================================================
Provides line-rate sub-millisecond local and global explanations
across Tier 1 (Behavioral Anomaly), Tier 2 (Binary Gatekeeper),
and Tier 3 (MITRE Threat Attribution).

Translates raw TreeSHAP mathematical attributions into actionable
Security Operations Center (SOC) intelligence and English narratives.
"""

import os
import time
import warnings
import joblib
import numpy as np
import shap
from typing import Dict, Any, List, Optional, Tuple, Union

warnings.filterwarnings("ignore")

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
TIER1_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier1_anomaly_detector.joblib")
TIER2_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier2_binary_gatekeeper.joblib")
TIER3_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier3_threat_classifier.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/feature_scaler.joblib")
ENCODER_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/label_encoder.joblib")

FEATURE_NAMES = [
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

LOG_COLS_INDICES = [11, 12, 1, 2, 3, 4, 7, 8, 5, 6, 9, 10, 16, 17]

FEATURE_HUMAN_LABELS = {
    'dst_port': 'Destination Port',
    'flow_duration_s': 'Flow Duration (sec)',
    'flow_iat_mean_s': 'Mean Inter-Arrival Time (sec)',
    'fwd_iat_mean_s': 'Forward Inter-Arrival Time (sec)',
    'bwd_iat_mean_s': 'Backward Inter-Arrival Time (sec)',
    'fwd_packets': 'Total Forward Packets',
    'bwd_packets': 'Total Backward Packets',
    'fwd_bytes': 'Total Forward Volume (bytes)',
    'bwd_bytes': 'Total Backward Volume (bytes)',
    'fwd_pkt_len_mean': 'Mean Forward Packet Size',
    'bwd_pkt_len_mean': 'Mean Backward Packet Size',
    'flow_bytes_per_sec': 'Throughput (bytes/sec)',
    'flow_pkts_per_sec': 'Packet Rate (pkts/sec)',
    'fwd_tcp_win_ratio': 'Forward TCP Window Ratio',
    'bwd_tcp_win_ratio': 'Backward TCP Window Ratio',
    'traffic_symmetry_ratio': 'Traffic Symmetry Ratio',
    'pkt_len_ratio': 'Packet Length Asymmetry Ratio',
    'bytes_per_packet': 'Average Bytes Per Packet'
}


class SentinelShapExplainer:
    """
    Production-grade singleton SHAP explainability engine.
    Pre-computes and caches TreeExplainer instances in memory for
    line-rate explainability on individual security alerts.
    """
    _instance: Optional["SentinelShapExplainer"] = None

    def __init__(self):
        self.t1_model = None
        self.t1_threshold = 0.0432
        self.scaler = None
        self.t2_booster = None
        self.t3_booster = None
        self.label_encoder = None
        self.classes: List[str] = []

        self.t1_explainer: Optional[shap.TreeExplainer] = None
        self.t2_explainer: Optional[shap.TreeExplainer] = None
        self.t3_explainer: Optional[shap.TreeExplainer] = None

        self.t2_expected_value: float = -3.673
        self.t1_expected_value: float = 18.0
        self.t3_expected_values: np.ndarray = np.zeros(9)

        self.is_loaded = False
        self._load_models_and_explainers()

    @classmethod
    def get_instance(cls) -> "SentinelShapExplainer":
        if cls._instance is None:
            cls._instance = SentinelShapExplainer()
        return cls._instance

    def _load_models_and_explainers(self):
        t0 = time.time()
        print("[*] SentinelShapExplainer: Initializing TreeExplainers for Tier 1, Tier 2, and Tier 3...", flush=True)

        # 1. Load trained models & encoders
        t1_payload = joblib.load(TIER1_PATH)
        self.t1_model = t1_payload['model']
        self.t1_threshold = float(t1_payload['threshold'])
        self.scaler = joblib.load(SCALER_PATH)

        self.t2_booster = joblib.load(TIER2_PATH)
        self.t3_booster = joblib.load(TIER3_PATH)
        self.label_encoder = joblib.load(ENCODER_PATH)
        self.classes = list(self.label_encoder.classes_)

        # 2. Build TreeExplainer for Tier 2 Binary Gatekeeper (sub-millisecond)
        self.t2_explainer = shap.TreeExplainer(self.t2_booster)
        ev2 = self.t2_explainer.expected_value
        self.t2_expected_value = float(ev2[0]) if isinstance(ev2, (list, np.ndarray)) else float(ev2)

        # 3. Build TreeExplainer for Tier 1 Isolation Forest Anomaly Detector
        self.t1_explainer = shap.TreeExplainer(self.t1_model)
        ev1 = self.t1_explainer.expected_value
        self.t1_expected_value = float(ev1[0]) if isinstance(ev1, (list, np.ndarray)) else float(ev1)

        # 4. Build TreeExplainer for Tier 3 Multi-Class Threat Classifier
        self.t3_explainer = shap.TreeExplainer(self.t3_booster)
        ev3 = self.t3_explainer.expected_value
        self.t3_expected_values = np.array(ev3) if isinstance(ev3, (list, np.ndarray)) else np.zeros(len(self.classes))

        self.is_loaded = True
        elapsed = time.time() - t0
        print(f"[+] SentinelShapExplainer: Armed in {elapsed:.2f}s (T2 Base Value: {self.t2_expected_value:.3f})", flush=True)

    def preprocess_vector(self, raw_features: Union[np.ndarray, List[float]]) -> np.ndarray:
        """
        Applies log1p transformations to formulate strict 18-element feature vector.
        """
        arr = np.array(raw_features, dtype=np.float32).copy()
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        # Apply log1p on heavy-tailed columns if not already log-scaled
        for idx in LOG_COLS_INDICES:
            val = arr[0, idx]
            if val > 50.0:  # Raw unscaled value
                arr[0, idx] = np.log1p(max(val, 0.0))
        return arr

    def explain_tier2_binary(
        self,
        X: np.ndarray,
        raw_feature_values: Optional[Dict[str, float]] = None,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Explains why a flow was classified as an attack vs clean by Tier 2 Gatekeeper.
        Fast sub-millisecond execution (< 1 ms).
        """
        t0 = time.perf_counter()
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Compute SHAP values in log-odds space
        shap_values = self.t2_explainer.shap_values(X)
        if isinstance(shap_values, list):
            sv = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        else:
            sv = shap_values
        
        row_shap = sv[0] if sv.ndim > 1 else sv
        base_value = self.t2_expected_value
        margin_score = float(base_value + np.sum(row_shap))
        pred_prob = float(1.0 / (1.0 + np.exp(-margin_score)))

        # Rank features by absolute magnitude
        abs_order = np.argsort(np.abs(row_shap))[::-1]
        top_indices = abs_order[:top_k]

        total_abs_shap = float(np.sum(np.abs(row_shap))) + 1e-9
        contributions = []

        for idx in top_indices:
            feat_name = FEATURE_NAMES[idx]
            feat_human = FEATURE_HUMAN_LABELS.get(feat_name, feat_name)
            s_val = float(row_shap[idx])
            obs_val = float(X[0, idx]) if raw_feature_values is None else float(raw_feature_values.get(feat_name, X[0, idx]))
            direction = "TOWARD_ATTACK" if s_val > 0 else "TOWARD_BENIGN"
            rel_pct = round((abs(s_val) / total_abs_shap) * 100.0, 1)

            contributions.append({
                "feature": feat_name,
                "label": feat_human,
                "observed_value": round(obs_val, 4),
                "shap_value": round(s_val, 4),
                "direction": direction,
                "relative_importance_pct": rel_pct
            })

        # Generate contextual natural-language narrative
        push_attack = [c for c in contributions if c['direction'] == 'TOWARD_ATTACK']
        push_benign = [c for c in contributions if c['direction'] == 'TOWARD_BENIGN']

        if pred_prob >= 0.50:
            top_drivers = ", ".join([f"{c['label']} (+{c['shap_value']:.2f})" for c in push_attack[:2]])
            narrative = (
                f"Flagged as malicious with {pred_prob*100:.1f}% confidence. "
                f"Prediction driven primarily by abnormal {top_drivers}."
            )
        else:
            top_clean = ", ".join([f"{c['label']} ({c['shap_value']:.2f})" for c in push_benign[:2]])
            narrative = (
                f"Verified clean ({ (1.0-pred_prob)*100:.1f}% benign confidence). "
                f"Normal operational patterns confirmed in {top_clean}."
            )

        calc_time_us = (time.perf_counter() - t0) * 1_000_000

        return {
            "tier": "Tier 2: Supervised Binary Gatekeeper",
            "base_value_log_odds": round(base_value, 4),
            "margin_score": round(margin_score, 4),
            "predicted_probability": round(pred_prob, 4),
            "verdict": "ATTACK" if pred_prob >= 0.50 else "BENIGN",
            "explanation_latency_us": round(calc_time_us, 1),
            "top_contributions": contributions,
            "narrative": narrative
        }

    def explain_tier1_anomaly(
        self,
        X: np.ndarray,
        raw_feature_values: Optional[Dict[str, float]] = None,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Explains why a zero-day or stealth flow was flagged as a behavioral anomaly
        by Tier 1 Isolation Forest.
        """
        t0 = time.perf_counter()
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Scale features using RobustScaler (calibrated space for Isolation Forest)
        X_scaled = self.scaler.transform(X)
        shap_values = self.t1_explainer.shap_values(X_scaled)
        row_shap = shap_values[0] if shap_values.ndim > 1 else shap_values

        # In Isolation Forest TreeSHAP, lower tree path length = more anomalous
        # Negate values so positive indicates outlier contribution
        anomaly_attribution = -row_shap
        abs_order = np.argsort(np.abs(anomaly_attribution))[::-1]
        top_indices = abs_order[:top_k]

        total_abs = float(np.sum(np.abs(anomaly_attribution))) + 1e-9
        contributions = []

        for idx in top_indices:
            feat_name = FEATURE_NAMES[idx]
            feat_human = FEATURE_HUMAN_LABELS.get(feat_name, feat_name)
            s_val = float(anomaly_attribution[idx])
            obs_val = float(X[0, idx]) if raw_feature_values is None else float(raw_feature_values.get(feat_name, X[0, idx]))
            direction = "ANOMALOUS_DEVIATION" if s_val > 0 else "CONSISTENT_WITH_BASELINE"
            rel_pct = round((abs(s_val) / total_abs) * 100.0, 1)

            contributions.append({
                "feature": feat_name,
                "label": feat_human,
                "observed_value": round(obs_val, 4),
                "shap_value": round(s_val, 4),
                "direction": direction,
                "relative_importance_pct": rel_pct
            })

        outliers = [c for c in contributions if c['direction'] == 'ANOMALOUS_DEVIATION']
        top_outliers = ", ".join([f"{c['label']}" for c in outliers[:2]]) if outliers else "generalized deviation"
        narrative = (
            f"Behavioral anomaly sensor detected statistical outlier. "
            f"Deviations isolated in {top_outliers} differing from enterprise baseline."
        )

        calc_time_us = (time.perf_counter() - t0) * 1_000_000

        return {
            "tier": "Tier 1: Unsupervised Anomaly Detector",
            "base_value_path_length": round(self.t1_expected_value, 2),
            "top_contributions": contributions,
            "explanation_latency_us": round(calc_time_us, 1),
            "narrative": narrative
        }

    def explain_tier3_attribution(
        self,
        X: np.ndarray,
        target_family: Optional[str] = None,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Explains why a threat was attributed to a specific MITRE attack family
        (e.g., DDoS vs Infiltration vs Botnet).
        """
        t0 = time.perf_counter()
        if X.ndim == 1:
            X = X.reshape(1, -1)

        # Get Tier 3 predictions
        t3_probs = self.t3_booster.predict(X)[0]
        if target_family and target_family in self.classes:
            target_idx = self.classes.index(target_family)
        else:
            target_idx = int(np.argmax(t3_probs))
            target_family = self.classes[target_idx]

        confidence_pct = float(t3_probs[target_idx]) * 100.0

        # Compute multi-class SHAP values
        sv = self.t3_explainer.shap_values(X)
        if isinstance(sv, list):
            class_shap = sv[target_idx][0]
        elif sv.ndim == 3:
            class_shap = sv[0, :, target_idx]
        else:
            class_shap = sv[0]

        abs_order = np.argsort(np.abs(class_shap))[::-1]
        top_indices = abs_order[:top_k]
        total_abs = float(np.sum(np.abs(class_shap))) + 1e-9

        contributions = []
        for idx in top_indices:
            feat_name = FEATURE_NAMES[idx]
            s_val = float(class_shap[idx])
            obs_val = float(X[0, idx])
            direction = f"TOWARD_{target_family.upper()}" if s_val > 0 else "AGAINST"
            rel_pct = round((abs(s_val) / total_abs) * 100.0, 1)

            contributions.append({
                "feature": feat_name,
                "label": FEATURE_HUMAN_LABELS.get(feat_name, feat_name),
                "observed_value": round(obs_val, 4),
                "shap_value": round(s_val, 4),
                "direction": direction,
                "relative_importance_pct": rel_pct
            })

        calc_time_us = (time.perf_counter() - t0) * 1_000_000

        top_drivers = ", ".join([c['label'] for c in contributions[:2]])
        narrative = (
            f"Threat attributed to {target_family} ({confidence_pct:.1f}% confidence). "
            f"Distinguishing signatures identified in {top_drivers}."
        )

        return {
            "tier": "Tier 3: Multi-Class Threat Attribution",
            "attributed_family": target_family,
            "confidence_pct": round(confidence_pct, 1),
            "top_contributions": contributions,
            "explanation_latency_us": round(calc_time_us, 1),
            "narrative": narrative
        }

    def explain_flow(
        self,
        X_flow: np.ndarray,
        is_threat: bool,
        threat_category: str = "Normal (Clean)",
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Unified high-level explanation router.
        Executes Tier 2 binary gatekeeper explanation, and adds
        Tier 3 attribution explanation if a threat is detected.
        """
        t0 = time.perf_counter()
        tier2_exp = self.explain_tier2_binary(X_flow, top_k=top_k)

        attribution_exp = None
        anomaly_exp = None

        if is_threat:
            if threat_category in self.classes and threat_category != "Normal":
                attribution_exp = self.explain_tier3_attribution(X_flow, target_family=threat_category, top_k=top_k)
            if threat_category == "Infiltration" or not tier2_exp['predicted_probability'] >= 0.50:
                anomaly_exp = self.explain_tier1_anomaly(X_flow, top_k=top_k)

        total_latency_us = (time.perf_counter() - t0) * 1_000_000

        return {
            "flow_verdict": "BLOCKED" if is_threat else "ALLOWED",
            "threat_category": threat_category,
            "total_xai_latency_us": round(total_latency_us, 1),
            "primary_decision": tier2_exp,
            "threat_attribution": attribution_exp,
            "behavioral_anomaly": anomaly_exp
        }
