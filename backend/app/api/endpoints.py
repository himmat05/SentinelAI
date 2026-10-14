"""
SentinelAI - API Endpoints
==========================
REST routes and WebSocket connection manager for real-time inference,
batch line-rate inspection, telemetry, and live threat alert broadcasting.
"""

import os
import json
import time
from typing import List, Set, Optional, Dict
from collections import deque
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Query
from backend.app.schemas.flow import (
    FlowData,
    BatchFlowInput,
    PredictionResponse,
    BatchPredictionResponse,
    ThreatAlert,
    AlertListResponse,
    FlowExplanationResponse
)
from backend.app.services.inference_engine import SentinelInferenceEngine
from ml.explainability.shap_explainer import SentinelShapExplainer

router = APIRouter()

ALERTS_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/alerts_history.jsonl"))


class AlertStore:
    """Persistent and in-memory storage for detected threat alerts."""
    def __init__(self, maxlen: int = 2000):
        self.alerts: deque = deque(maxlen=maxlen)
        self.alerts_by_id: Dict[str, ThreatAlert] = {}
        self._load_from_disk()

    def _load_from_disk(self):
        if os.path.exists(ALERTS_FILE):
            try:
                with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            alert = ThreatAlert(**data)
                            self.alerts.appendleft(alert)
                            self.alerts_by_id[alert.event_id] = alert
            except Exception as e:
                print(f"[!] Warning loading alerts from disk: {e}")

    def add(self, alert: ThreatAlert):
        self.alerts.appendleft(alert)
        self.alerts_by_id[alert.event_id] = alert
        # Append to persistent JSONL log
        try:
            os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)
            with open(ALERTS_FILE, "a", encoding="utf-8") as f:
                f.write(alert.model_dump_json() + "\n")
        except Exception as e:
            print(f"[!] Warning persisting alert to disk: {e}")

    def get_all(
        self,
        limit: int = 50,
        threat_category: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[ThreatAlert]:
        results = []
        for alert in self.alerts:
            if threat_category and alert.threat_category.lower() != threat_category.lower():
                continue
            if severity and alert.severity.upper() != severity.upper():
                continue
            results.append(alert)
            if len(results) >= limit:
                break
        return results

    def get_by_id(self, event_id: str) -> Optional[ThreatAlert]:
        return self.alerts_by_id.get(event_id)

    def clear(self):
        self.alerts.clear()
        self.alerts_by_id.clear()
        if os.path.exists(ALERTS_FILE):
            try:
                os.remove(ALERTS_FILE)
            except Exception:
                pass


alert_store = AlertStore()


class AlertConnectionManager:
    """Manages active WebSocket connections for live threat alert broadcasting."""
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast_alert(self, alert: ThreatAlert):
        if not self.active_connections:
            return
        payload = alert.model_dump_json()
        disconnected = set()
        for conn in self.active_connections:
            try:
                await conn.send_text(payload)
            except Exception:
                disconnected.add(conn)
        for conn in disconnected:
            self.active_connections.discard(conn)


alert_manager = AlertConnectionManager()



@router.post("/predict", response_model=PredictionResponse, tags=["Inference"])
async def predict_flow(
    flow: FlowData,
    explain: bool = Query(default=False, description="Compute on-demand TreeSHAP feature attributions")
):
    """
    Inspect a single network flow in real-time (sub-100 microsecond wire speed).
    Evaluates Tier 1 + Tier 2 in parallel, routes intrusions to Tier 3,
    and optionally computes SHAP explainability narratives.
    """
    engine = SentinelInferenceEngine.get_instance()
    result = engine.inspect_flow(flow)

    explanation_payload = None
    top_decisive = None

    if explain or result.is_threat:
        try:
            explainer = SentinelShapExplainer.get_instance()
            X_vec = engine.preprocess_flow(flow)
            exp_dict = explainer.explain_flow(
                X_flow=X_vec,
                is_threat=result.is_threat,
                threat_category=result.threat_category,
                top_k=5
            )
            if explain:
                explanation_payload = FlowExplanationResponse(**exp_dict)
            
            # Extract top 3 drivers for alert payload
            if exp_dict.get('primary_decision') and exp_dict['primary_decision'].get('top_contributions'):
                top_decisive = [
                    f"{c['label']} ({c['shap_value']:+.2f})"
                    for c in exp_dict['primary_decision']['top_contributions'][:3]
                ]
        except Exception as e:
            # Fallback gracefully to keep line-rate stability
            print(f"[!] Warning: SHAP explanation generation skipped: {e}")

    result.explanation = explanation_payload

    # If intrusion detected, record alert and broadcast live via WebSocket
    if result.is_threat:
        severity = "CRITICAL" if result.threat_category in ["DDoS", "Botnet"] else "HIGH"
        alert = ThreatAlert(
            event_id=f"EVT-{int(time.time()*1000)}",
            timestamp=result.timestamp,
            src_ip=flow.src_ip or "0.0.0.0",
            dst_ip=flow.dst_ip or "0.0.0.0",
            dst_port=flow.dst_port,
            threat_category=result.threat_category,
            severity=severity,
            tier2_confidence=result.tier2_score,
            tier1_anomaly_detected=result.tier1_anomaly_flag,
            mitigation_action=result.mitigation_action,
            details=f"Threat {result.threat_category} intercepted ({result.confidence_pct}% certainty). Action: {result.mitigation_action}.",
            top_decisive_factors=top_decisive
        )
        alert_store.add(alert)
        await alert_manager.broadcast_alert(alert)

    return result


@router.get("/alerts", response_model=AlertListResponse, tags=["Alerts"])
async def get_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Max alerts to retrieve"),
    threat_category: Optional[str] = Query(default=None, description="Filter by attack family"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (CRITICAL, HIGH)")
):
    """
    Retrieve stored security alerts with their mitigation actions,
    severity scores, and top SHAP decisive factors.
    """
    alerts = alert_store.get_all(limit=limit, threat_category=threat_category, severity=severity)
    return AlertListResponse(
        total_stored=len(alert_store.alerts),
        count_returned=len(alerts),
        alerts=alerts
    )


@router.get("/alerts/{event_id}", response_model=ThreatAlert, tags=["Alerts"])
async def get_alert_by_id(event_id: str):
    """Retrieve a specific security alert by its event ID."""
    alert = alert_store.get_by_id(event_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {event_id} not found.")
    return alert


@router.delete("/alerts", tags=["Alerts"])
async def clear_alerts():
    """Clear stored alert history."""
    alert_store.clear()
    return {"status": "SUCCESS", "message": "Alert history cleared."}


@router.post("/explain", response_model=FlowExplanationResponse, tags=["Explainability (XAI)"])
async def explain_flow(flow: FlowData, top_k: int = Query(default=5, ge=1, le=18)):
    """
    On-demand Explainable AI (XAI) endpoint powered by TreeSHAP.
    Computes mathematical Shapley attributions across Tier 1, Tier 2, and Tier 3,
    returning exact feature contributions, directional pushes, and human narratives.
    """
    engine = SentinelInferenceEngine.get_instance()
    explainer = SentinelShapExplainer.get_instance()

    pred = engine.inspect_flow(flow)
    X_vec = engine.preprocess_flow(flow)

    exp_dict = explainer.explain_flow(
        X_flow=X_vec,
        is_threat=pred.is_threat,
        threat_category=pred.threat_category,
        top_k=top_k
    )
    return FlowExplanationResponse(**exp_dict)



@router.post("/predict/batch", response_model=BatchPredictionResponse, tags=["Inference"])
async def predict_batch(payload: BatchFlowInput):
    """
    High-throughput batch inspection endpoint for packet sniffer queues
    capable of processing >600,000 flows/sec.
    """
    engine = SentinelInferenceEngine.get_instance()
    batch_resp = engine.inspect_batch(payload.flows)

    # Store any threats detected in the batch
    for flow_input, result in zip(payload.flows, batch_resp.results):
        if result.is_threat:
            sev = "CRITICAL" if result.threat_category in ["DDoS", "Botnet"] else "HIGH"
            a = ThreatAlert(
                event_id=f"EVT-{int(time.time()*1000)}-{id(flow_input)%1000}",
                timestamp=result.timestamp,
                src_ip=flow_input.src_ip or "0.0.0.0",
                dst_ip=flow_input.dst_ip or "0.0.0.0",
                dst_port=flow_input.dst_port,
                threat_category=result.threat_category,
                severity=sev,
                tier2_confidence=result.tier2_score,
                tier1_anomaly_detected=result.tier1_anomaly_flag,
                mitigation_action=result.mitigation_action,
                details=f"Threat {result.threat_category} intercepted ({result.confidence_pct}% certainty)."
            )
            alert_store.add(a)

    return batch_resp



@router.get("/health", tags=["Telemetry"])
async def health_check():
    """Verify backend status and model load health."""
    engine = SentinelInferenceEngine.get_instance()
    return {
        "status": "ONLINE",
        "models_loaded": engine.is_loaded,
        "engine": "SentinelAI Autonomous Defense",
        "pipeline": "3-Tier (Tier 1 Anomaly + Tier 2 Gatekeeper + Tier 3 Attribution)",
        "active_classes": engine.classes,
        "tier2_threshold": engine.tier2_threshold,
        "active_soc_websockets": len(alert_manager.active_connections)
    }


@router.get("/metrics", tags=["Telemetry"])
async def get_metrics():
    """Real-time Security Operations Center (SOC) telemetry and audit counters."""
    engine = SentinelInferenceEngine.get_instance()
    return engine.get_telemetry()


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    Live WebSocket feed broadcasting threat alerts to the SOC security dashboard
    the moment an attack is detected and neutralized.
    """
    await alert_manager.connect(websocket)
    try:
        # Send initial handshake message
        handshake = {
            "type": "HANDSHAKE",
            "message": "Connected to SentinelAI Live Threat Broadcast Stream",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        await websocket.send_text(json.dumps(handshake))
        while True:
            # Keep connection alive; handle client pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        alert_manager.disconnect(websocket)
    except Exception:
        alert_manager.disconnect(websocket)
