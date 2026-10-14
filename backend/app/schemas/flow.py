from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time


class FlowData(BaseModel):
    """
    Standard 18-Feature Network Flow Input Payload.
    Supports optional 5-tuple socket metadata for real-time firewall mitigation.
    """
    # 5-Tuple Network Metadata (Optional, used for active mitigation)
    src_ip: Optional[str] = Field(default="0.0.0.0", description="Source IP Address")
    dst_ip: Optional[str] = Field(default="0.0.0.0", description="Destination IP Address")
    src_port: Optional[int] = Field(default=0, description="Source Port")
    protocol: Optional[str] = Field(default="TCP", description="Transport Protocol (TCP/UDP/ICMP)")

    # Model Input Features (16 raw transport fields)
    dst_port: int = Field(..., description="Target service destination port (e.g., 80, 443, 22)")
    flow_duration_s: float = Field(..., ge=0.0, description="Total active flow session duration in seconds")
    flow_iat_mean_s: float = Field(..., ge=0.0, description="Mean inter-arrival time between packets in seconds")
    fwd_iat_mean_s: float = Field(..., ge=0.0, description="Mean forward inter-arrival time in seconds")
    bwd_iat_mean_s: float = Field(..., ge=0.0, description="Mean backward inter-arrival time in seconds")
    fwd_packets: float = Field(..., ge=0.0, description="Total packets transmitted in forward direction")
    bwd_packets: float = Field(..., ge=0.0, description="Total packets received in backward direction")
    fwd_bytes: float = Field(..., ge=0.0, description="Total payload bytes transmitted forward")
    bwd_bytes: float = Field(..., ge=0.0, description="Total payload bytes received backward")
    fwd_pkt_len_mean: float = Field(..., ge=0.0, description="Mean forward packet length in bytes")
    bwd_pkt_len_mean: float = Field(..., ge=0.0, description="Mean backward packet length in bytes")
    flow_bytes_per_sec: float = Field(..., ge=0.0, description="Transfer rate in bytes per second")
    flow_pkts_per_sec: float = Field(..., ge=0.0, description="Transfer velocity in packets per second")
    fwd_tcp_win_ratio: float = Field(..., ge=0.0, le=1.0, description="Forward TCP window size normalized [0, 1]")
    bwd_tcp_win_ratio: float = Field(..., ge=0.0, le=1.0, description="Backward TCP window size normalized [0, 1]")
    traffic_symmetry_ratio: float = Field(..., ge=0.0, le=1.0, description="Ratio of fwd_bytes / (fwd_bytes + bwd_bytes) [0, 1]")


class BatchFlowInput(BaseModel):
    """Batch ingestion request for packet capture queues."""
    flows: List[FlowData]


class FeatureContribution(BaseModel):
    """Detailed SHAP mathematical attribution for a single network feature."""
    feature: str = Field(..., description="Canonical feature column name")
    label: str = Field(..., description="Human-readable feature name for SOC analysts")
    observed_value: float = Field(..., description="Observed value of the feature")
    shap_value: float = Field(..., description="Shapley value in log-odds / margin space")
    direction: str = Field(..., description="Attribution direction ('TOWARD_ATTACK', 'TOWARD_BENIGN', etc.)")
    relative_importance_pct: float = Field(..., description="Normalized percentage contribution")


class TierExplanation(BaseModel):
    """Explainability payload for a specific AI tier."""
    tier: str
    narrative: str
    explanation_latency_us: float
    top_contributions: List[FeatureContribution]


class FlowExplanationResponse(BaseModel):
    """Unified multi-tier XAI explanation bundle."""
    flow_verdict: str
    threat_category: str
    total_xai_latency_us: float
    primary_decision: Optional[TierExplanation] = None
    threat_attribution: Optional[TierExplanation] = None
    behavioral_anomaly: Optional[TierExplanation] = None


class PredictionResponse(BaseModel):
    """Detailed real-time multi-tier security verdict."""
    verdict: str = Field(..., description="Final security action: 'ALLOWED' or 'BLOCKED'")
    is_threat: bool = Field(..., description="True if detected as an active intrusion")
    
    # Tier 2: Supervised Gatekeeper
    tier2_score: float = Field(..., description="Attack probability score [0.0, 1.0]")
    tier2_flag: bool = Field(..., description="True if Tier 2 score exceeds decision threshold")
    
    # Tier 1: Behavioral Anomaly Detector
    tier1_anomaly_flag: bool = Field(..., description="True if flow violates normal baseline transport physics")
    tier1_anomaly_score: float = Field(..., description="Calculated behavioral deviance score")
    
    # Tier 3: MITRE Threat Attribution
    threat_category: str = Field(..., description="Canonical MITRE threat family (e.g., 'DDoS', 'Botnet', 'Normal')")
    confidence_pct: float = Field(..., description="Attribution certainty percentage")
    
    # Automated Active Mitigation
    mitigation_action: str = Field(..., description="Autonomous firewall action: 'ALLOW', 'DROP_PACKETS', 'BLOCK_IP', 'RATE_LIMIT_PORT', 'TCP_RESET'")
    
    # Performance & Audit Telemetry
    latency_us: float = Field(..., description="Single-flow decision latency in microseconds")
    timestamp: str = Field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    flow_id: Optional[str] = None
    
    # Optional Explainable AI (XAI) Attribution
    explanation: Optional[FlowExplanationResponse] = None


class BatchPredictionResponse(BaseModel):
    """Batch prediction results with throughput telemetry."""
    total_flows: int
    threats_blocked: int
    clean_allowed: int
    batch_latency_ms: float
    throughput_flows_per_sec: float
    results: List[PredictionResponse]


class ThreatAlert(BaseModel):
    """Real-time WebSocket threat event broadcast."""
    event_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    threat_category: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    tier2_confidence: float
    tier1_anomaly_detected: bool
    mitigation_action: str
    details: str
    top_decisive_factors: Optional[List[str]] = None


class AlertListResponse(BaseModel):
    """Paginated list of stored security alerts."""
    total_stored: int
    count_returned: int
    alerts: List[ThreatAlert]


