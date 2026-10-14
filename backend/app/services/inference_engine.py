"""
SentinelAI - Real-Time Multi-Tier Inference Engine
===================================================
Hosts Tier 1 (Behavioral Anomaly), Tier 2 (Binary Gatekeeper),
and Tier 3 (MITRE Threat Attribution) with Knob 1 active synergy
for line-rate autonomous network defense.
"""

import os
import time
import warnings
import joblib
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from collections import deque
from backend.app.schemas.flow import FlowData, PredictionResponse, BatchPredictionResponse

warnings.filterwarnings("ignore")

# Paths relative to project root
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
TIER1_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier1_anomaly_detector.joblib")
TIER2_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier2_binary_gatekeeper.joblib")
TIER3_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/tier3_threat_classifier.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/feature_scaler.joblib")
ENCODER_PATH = os.path.join(BASE_DIR, "ml/saved_models/production/label_encoder.joblib")

LOG_COLS_INDICES = [11, 12, 1, 2, 3, 4, 7, 8, 5, 6, 9, 10, 16, 17]


class SentinelInferenceEngine:
    """
    Singleton production engine running Tier 1 + Tier 2 + Tier 3 pipeline.
    """
    _instance: Optional["SentinelInferenceEngine"] = None

    def __init__(self, tier2_threshold: float = 0.50):
        self.tier2_threshold = tier2_threshold
        self.t1_model = None
        self.t1_threshold = 0.0432
        self.scaler = None
        self.t2_booster = None
        self.t3_booster = None
        self.label_encoder = None
        self.classes: List[str] = []
        self.is_loaded = False
        
        # Telemetry counters
        self.total_flows_inspected = 0
        self.total_threats_blocked = 0
        self.total_clean_allowed = 0
        self.threat_counts: Dict[str, int] = {}
        self.latencies_us = deque(maxlen=1000)
        self.start_time = time.time()

        self._load_models()

    @classmethod
    def get_instance(cls) -> "SentinelInferenceEngine":
        if cls._instance is None:
            cls._instance = SentinelInferenceEngine()
        return cls._instance

    def _load_models(self):
        t0 = time.time()
        print("[*] SentinelInferenceEngine: Loading production models...", flush=True)

        if not os.path.exists(TIER2_PATH):
            raise FileNotFoundError(f"Model path not found: {TIER2_PATH}. Ensure models are in ml/saved_models/production/.")

        # 1. Tier 1: Isolation Forest & Calibrated Feature Scaler
        t1_payload = joblib.load(TIER1_PATH)
        self.t1_model = t1_payload['model']
        self.t1_threshold = float(t1_payload['threshold'])
        self.scaler = joblib.load(SCALER_PATH)

        # 2. Tier 2: Binary LightGBM Booster
        self.t2_booster = joblib.load(TIER2_PATH)

        # 3. Tier 3: Multi-Class LightGBM Booster
        self.t3_booster = joblib.load(TIER3_PATH)

        # 4. Target LabelEncoder
        self.label_encoder = joblib.load(ENCODER_PATH)
        self.classes = list(self.label_encoder.classes_)

        for c in self.classes:
            self.threat_counts[c] = 0

        self.is_loaded = True
        elapsed = time.time() - t0
        print(f"[+] SentinelInferenceEngine: All 3 Tiers loaded in {elapsed:.2f}s ({len(self.classes)} classes mapped)", flush=True)

    def preprocess_flow(self, flow: FlowData) -> np.ndarray:
        """
        Calculates physical invariant ratios and applies log1p transformations.
        Returns exact 18-element float32 feature vector.
        """
        # 1. Derived physical ratios
        pkt_len_ratio = float(flow.fwd_pkt_len_mean / (flow.bwd_pkt_len_mean + 1e-6))
        bytes_per_packet = float((flow.fwd_bytes + flow.bwd_bytes) / (flow.fwd_packets + flow.bwd_packets + 1e-6))

        # 2. Formulate 18 features in strict model column order
        raw_feats = np.array([
            flow.dst_port,
            flow.flow_duration_s,
            flow.flow_iat_mean_s,
            flow.fwd_iat_mean_s,
            flow.bwd_iat_mean_s,
            flow.fwd_packets,
            flow.bwd_packets,
            flow.fwd_bytes,
            flow.bwd_bytes,
            flow.fwd_pkt_len_mean,
            flow.bwd_pkt_len_mean,
            flow.flow_bytes_per_sec,
            flow.flow_pkts_per_sec,
            flow.fwd_tcp_win_ratio,
            flow.bwd_tcp_win_ratio,
            flow.traffic_symmetry_ratio,
            pkt_len_ratio,
            bytes_per_packet
        ], dtype=np.float32)

        # 3. Apply log1p on the 14 heavy-tailed features
        for idx in LOG_COLS_INDICES:
            raw_feats[idx] = np.log1p(max(float(raw_feats[idx]), 0.0))

        return raw_feats.reshape(1, -1)

    def preprocess_batch(self, flows: List[FlowData]) -> np.ndarray:
        """Vectorized batch preprocessing for packet capture queues."""
        n = len(flows)
        X = np.empty((n, 18), dtype=np.float32)
        for i, f in enumerate(flows):
            X[i] = self.preprocess_flow(f)[0]
        return X

    def inspect_flow(self, flow: FlowData) -> PredictionResponse:
        """
        High-speed single flow inspection pipeline with Knob 1 Multi-Tier Synergy.
        """
        t0 = time.perf_counter()
        X = self.preprocess_flow(flow)

        # Step 1: Tier 2 Binary Gatekeeper (Wire speed on raw/log1p features)
        t2_prob = float(self.t2_booster.predict(X)[0])
        t2_flag = bool(t2_prob >= self.tier2_threshold)

        # Step 2: Tier 1 Behavioral Anomaly Detector (Spatial isolation on scaled features)
        X_scaled = self.scaler.transform(X)
        t1_score = float(-self.t1_model.decision_function(X_scaled)[0])
        t1_anomaly_flag = bool(t1_score >= self.t1_threshold)

        # Step 3: Knob 1 Multi-Tier Synergy
        # Flow is quarantined if flagged by EITHER Tier 2 OR Tier 1
        is_threat = t2_flag or t1_anomaly_flag

        # Step 4: Threat Attribution (Tier 3)
        if is_threat:
            t3_probs = self.t3_booster.predict(X)[0]
            pred_idx = int(np.argmax(t3_probs))
            predicted_family = self.classes[pred_idx]
            confidence_pct = float(t3_probs[pred_idx]) * 100.0

            # If Tier 2 had low score but Tier 1 caught behavioral anomaly
            if not t2_flag and t1_anomaly_flag:
                if predicted_family == "Normal":
                    predicted_family = "Infiltration"  # Stealth internal lateral movement
                    confidence_pct = 95.0

            verdict = "BLOCKED"
            mitigation_action = self._assign_mitigation(predicted_family)
            self.total_threats_blocked += 1
            self.threat_counts[predicted_family] = self.threat_counts.get(predicted_family, 0) + 1
        else:
            verdict = "ALLOWED"
            predicted_family = "Normal (Clean)"
            confidence_pct = float(1.0 - t2_prob) * 100.0
            mitigation_action = "ALLOW"
            self.total_clean_allowed += 1

        t_end = time.perf_counter()
        latency_us = (t_end - t0) * 1_000_000
        self.latencies_us.append(latency_us)
        self.total_flows_inspected += 1

        return PredictionResponse(
            verdict=verdict,
            is_threat=is_threat,
            tier2_score=round(t2_prob, 5),
            tier2_flag=t2_flag,
            tier1_anomaly_flag=t1_anomaly_flag,
            tier1_anomaly_score=round(t1_score, 5),
            threat_category=predicted_family,
            confidence_pct=round(confidence_pct, 2),
            mitigation_action=mitigation_action,
            latency_us=round(latency_us, 1)
        )

    def inspect_batch(self, flows: List[FlowData]) -> BatchPredictionResponse:
        """High-throughput batch inspection."""
        t0 = time.perf_counter()
        n = len(flows)
        if n == 0:
            return BatchPredictionResponse(
                total_flows=0, threats_blocked=0, clean_allowed=0,
                batch_latency_ms=0.0, throughput_flows_per_sec=0.0, results=[]
            )

        X = self.preprocess_batch(flows)

        # Batch Tier 2 predictions
        t2_probs = self.t2_booster.predict(X)
        t2_flags = t2_probs >= self.tier2_threshold

        # Batch Tier 1 predictions (Scaled features)
        X_scaled = self.scaler.transform(X)
        t1_scores = -self.t1_model.decision_function(X_scaled)
        t1_flags = t1_scores >= self.t1_threshold

        # Knob 1 Synergy
        threat_mask = t2_flags | t1_flags

        # Batch Tier 3 for threats
        threat_indices = np.where(threat_mask)[0]
        results = []
        threats_count = 0
        clean_count = 0

        t3_predictions = {}
        if len(threat_indices) > 0:
            X_threats = X[threat_indices]
            t3_probs_all = self.t3_booster.predict(X_threats)
            t3_pred_indices = np.argmax(t3_probs_all, axis=1)
            for idx_in_threats, orig_idx in enumerate(threat_indices):
                pred_cls_idx = t3_pred_indices[idx_in_threats]
                conf = float(t3_probs_all[idx_in_threats, pred_cls_idx]) * 100
                cls_name = self.classes[pred_cls_idx]
                if not t2_flags[orig_idx] and t1_flags[orig_idx] and cls_name == "Normal":
                    cls_name = "Infiltration"
                    conf = 95.0
                t3_predictions[orig_idx] = (cls_name, conf)

        for i in range(n):
            is_th = bool(threat_mask[i])
            t2_p = float(t2_probs[i])
            t1_s = float(t1_scores[i])

            if is_th:
                threats_count += 1
                cls_name, conf = t3_predictions[i]
                action = self._assign_mitigation(cls_name)
                verdict = "BLOCKED"
                self.threat_counts[cls_name] = self.threat_counts.get(cls_name, 0) + 1
            else:
                clean_count += 1
                verdict = "ALLOWED"
                cls_name = "Normal (Clean)"
                conf = float(1.0 - t2_p) * 100
                action = "ALLOW"

            results.append(PredictionResponse(
                verdict=verdict,
                is_threat=is_th,
                tier2_score=round(t2_p, 5),
                tier2_flag=bool(t2_flags[i]),
                tier1_anomaly_flag=bool(t1_flags[i]),
                tier1_anomaly_score=round(t1_s, 5),
                threat_category=cls_name,
                confidence_pct=round(conf, 2),
                mitigation_action=action,
                latency_us=0.0
            ))

        t_end = time.perf_counter()
        batch_latency_ms = (t_end - t0) * 1000.0
        throughput = n / (t_end - t0) if (t_end - t0) > 0 else 0.0

        self.total_flows_inspected += n
        self.total_threats_blocked += threats_count
        self.total_clean_allowed += clean_count

        return BatchPredictionResponse(
            total_flows=n,
            threats_blocked=threats_count,
            clean_allowed=clean_count,
            batch_latency_ms=round(batch_latency_ms, 2),
            throughput_flows_per_sec=round(throughput, 1),
            results=results
        )

    def _assign_mitigation(self, threat_category: str) -> str:
        """Maps MITRE threat families to automated mitigation actions."""
        mapping = {
            "DDoS": "DROP_PACKETS",
            "DoS": "DROP_PACKETS",
            "Botnet": "BLOCK_IP",
            "Brute Force": "RATE_LIMIT_PORT",
            "Web & Exploitation": "TCP_RESET",
            "Reconnaissance": "BLACKHOLE_IP",
            "Infiltration": "QUARANTINE_HOST",
            "Other / Fuzzing": "DROP_PACKETS",
            "Normal": "ALLOW"
        }
        return mapping.get(threat_category, "BLOCK_IP")

    def get_telemetry(self) -> Dict[str, Any]:
        """Provides real-time SOC health metrics."""
        lat_arr = list(self.latencies_us)
        return {
            "status": "HEALTHY" if self.is_loaded else "STARTING",
            "uptime_seconds": round(time.time() - self.start_time, 1),
            "tier2_threshold": self.tier2_threshold,
            "tier1_threshold": self.t1_threshold,
            "total_flows_inspected": self.total_flows_inspected,
            "total_threats_blocked": self.total_threats_blocked,
            "total_clean_allowed": self.total_clean_allowed,
            "block_rate_pct": round(
                (self.total_threats_blocked / self.total_flows_inspected * 100.0)
                if self.total_flows_inspected > 0 else 0.0, 2
            ),
            "latency_p50_us": round(float(np.percentile(lat_arr, 50)), 1) if lat_arr else 0.0,
            "latency_p95_us": round(float(np.percentile(lat_arr, 95)), 1) if lat_arr else 0.0,
            "threat_distribution": self.threat_counts
        }
