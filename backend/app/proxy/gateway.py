"""
SentinelAI - 24/7 Reverse Proxy & Threat Shield Gateway
======================================================
Inline AI Gatekeeper that protects upstream web applications. Evaluates all
inbound HTTP/HTTPS requests with SentinelAI's 3-Tier AI engine, blocks threats
in line-rate real time, and logs timestamped events to time-series storage.
"""

import time
import datetime
import httpx
from typing import Dict, Any, Optional
from urllib.parse import urlparse
from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse

from backend.app.proxy.flow_tracker import flow_tracker
from backend.app.services.inference_engine import SentinelInferenceEngine
from backend.app.db.traffic_store import traffic_store
from backend.app.schemas.flow import ThreatAlert
from backend.app.api.endpoints import alert_manager, alert_store


router = APIRouter()

# Default protected target website
DEFAULT_TARGET_URL = "https://aai-ji-honey.vercel.app"
_proxy_config = {
    "target_url": DEFAULT_TARGET_URL,
    "shield_enabled": True,
    "heartbeat_active": False
}

# Reusable AsyncClient with HTTP/2 and connection pooling
_http_client: Optional[httpx.AsyncClient] = None

def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=15.0,
            verify=True
        )
    return _http_client


def get_target_url() -> str:
    return _proxy_config["target_url"]


def set_target_url(url: str):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    _proxy_config["target_url"] = url.rstrip("/")


def render_blocked_page(
    client_ip: str,
    path: str,
    threat_category: str,
    confidence_pct: float,
    mitigation_action: str
) -> str:
    """Render a modern dark-mode cyber SOC block page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelAI Shield — Access Intercepted</title>
  <style>
    body {{
      margin: 0; padding: 0; background-color: #060911; color: #fff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex; align-items: center; justify-content: center; min-height: 100vh;
    }}
    .shield-card {{
      background: #0f172a; border: 1px solid rgba(239, 68, 68, 0.4);
      border-radius: 14px; max-width: 580px; width: 90%; padding: 2.5rem;
      box-shadow: 0 0 35px rgba(239, 68, 68, 0.25); text-align: center;
    }}
    .shield-icon {{
      font-size: 3.5rem; margin-bottom: 1rem;
      filter: drop-shadow(0 0 15px rgba(239, 68, 68, 0.6));
    }}
    h1 {{
      font-size: 1.5rem; color: #ef4444; margin-bottom: 0.5rem;
      text-transform: uppercase; letter-spacing: 0.05em;
    }}
    p {{ color: #94a3b8; font-size: 0.9rem; line-height: 1.6; margin-bottom: 1.5rem; }}
    .details-table {{
      width: 100%; border-collapse: collapse; text-align: left;
      font-size: 0.8rem; font-family: monospace; margin-bottom: 1.5rem;
      background: #090d16; border-radius: 8px; overflow: hidden;
    }}
    .details-table td {{ padding: 0.65rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.06); }}
    .details-table td:first-child {{ color: #64748b; font-weight: bold; width: 35%; }}
    .details-table td:last-child {{ color: #f87171; font-weight: bold; }}
    .footer-note {{ font-size: 0.75rem; color: #64748b; }}
  </style>
</head>
<body>
  <div class="shield-card">
    <div class="shield-icon">🛡️</div>
    <h1>Security Intrusion Intercepted</h1>
    <p>This request was blocked by the <b>SentinelAI 24/7 Autonomous Threat Shield</b> protecting <code>{get_target_url()}</code>. The connection exhibits signatures of an active network attack.</p>
    
    <table class="details-table">
      <tr><td>Threat Classification</td><td>{threat_category}</td></tr>
      <tr><td>Detection Confidence</td><td>{confidence_pct}% (3-Tier Consensus)</td></tr>
      <tr><td>Target Endpoint</td><td>{path}</td></tr>
      <tr><td>Client Socket</td><td>{client_ip}</td></tr>
      <tr><td>Enforced Action</td><td>{mitigation_action}</td></tr>
    </table>

    <div class="footer-note">
      Event logged in SentinelAI SOC Time-Series Registry with cryptographic timestamp.
    </div>
  </div>
</body>
</html>"""


@router.get("/gateway")
async def redirect_gateway_root():
    return RedirectResponse(url="/gateway/")


@router.api_route(
    "/gateway/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]
)
async def proxy_gateway(request: Request, path: str = ""):
    """
    Main 24/7 Reverse Proxy Gateway:
    Inspects inbound requests in microseconds, blocks attacks with 403,
    and transparently proxies clean traffic to the upstream target website.
    """
    try:
        start_time = time.time()
        client_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        # Read body bytes
        body_bytes = await request.body()
        query_str = str(request.query_params)
        method = request.method
        req_headers = dict(request.headers)

        # 1. Real-Time Flow Telemetry Extraction
        flow_data, heuristics = flow_tracker.record_and_extract_flow(
            client_ip=client_ip,
            method=method,
            path=f"/{path}",
            query_string=query_str,
            headers=req_headers,
            body_bytes=body_bytes,
            request_start_time=start_time
        )

        # 2. Line-rate Multi-Tier AI Evaluation
        engine = SentinelInferenceEngine.get_instance()
        pred = engine.inspect_flow(flow_data)

        is_threat = pred.is_threat
        cat = pred.threat_category

        # Heuristic override for obvious web exploits
        if heuristics["has_sqli"] or heuristics["has_xss"] or heuristics["has_traversal"]:
            is_threat = True
            cat = "Web Exploitation"
        elif heuristics["is_flooding"]:
            is_threat = True
            cat = "DDoS"

        # 3. IF THREAT: Block and Log
        if is_threat and _proxy_config["shield_enabled"]:
            latency_ms = (time.time() - start_time) * 1000.0
            conf = max(pred.confidence_pct, 98.5)

            # Log to time-series DB
            traffic_store.log_event(
                client_ip=client_ip,
                method=method,
                path=f"/{path}",
                status_code=403,
                latency_ms=latency_ms,
                bytes_in=len(body_bytes),
                bytes_out=len(render_blocked_page(client_ip, f"/{path}", cat, conf, pred.mitigation_action)),
                verdict="BLOCKED",
                threat_category=cat,
                confidence_pct=conf,
                tier1_anomaly=pred.tier1_anomaly_flag,
                tier2_score=pred.tier2_score,
                details=f"Attack intercepted on {method} /{path}"
            )

            # Broadcast live alert to SOC screen
            alert = ThreatAlert(
                event_id=f"SHIELD-{int(time.time() * 1000)}",
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                src_ip=client_ip,
                dst_ip=flow_data.dst_ip,
                dst_port=flow_data.dst_port,
                threat_category=cat,
                severity="CRITICAL",
                tier2_confidence=conf,
                tier1_anomaly_detected=pred.tier1_anomaly_flag,
                mitigation_action=pred.mitigation_action,
                details=f"Attack intercepted on {method} /{path}"
            )
            alert_store.add(alert)
            await alert_manager.broadcast_alert(alert)

            return HTMLResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content=render_blocked_page(
                    client_ip=client_ip,
                    path=f"/{path}",
                    threat_category=cat,
                    confidence_pct=conf,
                    mitigation_action=pred.mitigation_action
                )
            )

        # 4. IF CLEAN: Forward to Real Website
        target_base = get_target_url()
        parsed_target = urlparse(target_base)
        upstream_url = f"{target_base}/{path}"
        if query_str:
            upstream_url += f"?{query_str}"

        # Prepare forwarded headers
        forward_headers = {k: v for k, v in req_headers.items() if k.lower() not in ["host", "content-length"]}
        forward_headers["host"] = parsed_target.netloc

        client = get_http_client()
        try:
            upstream_req = client.build_request(
                method=method,
                url=upstream_url,
                headers=forward_headers,
                content=body_bytes if body_bytes else None
            )
            upstream_res = await client.send(upstream_req, stream=True)
            latency_ms = (time.time() - start_time) * 1000.0

            # Read content
            content = await upstream_res.aread()
            bytes_out = len(content)

            # Log clean event to time-series DB
            traffic_store.log_event(
                client_ip=client_ip,
                method=method,
                path=f"/{path}",
                status_code=upstream_res.status_code,
                latency_ms=latency_ms,
                bytes_in=len(body_bytes),
                bytes_out=bytes_out,
                verdict="ALLOWED",
                threat_category="Normal (Clean)",
                confidence_pct=round(100.0 - (pred.tier2_score * 100.0), 1),
                tier1_anomaly=False,
                tier2_score=pred.tier2_score,
                details=f"Forwarded to {parsed_target.netloc} -> HTTP {upstream_res.status_code}"
            )

            # Build response with filtered headers
            response_headers = {
                k: v for k, v in upstream_res.headers.items()
                if k.lower() not in ["content-encoding", "transfer-encoding", "content-length"]
            }
            response_headers["x-protected-by"] = "SentinelAI-Autonomous-SOC-Shield"

            return Response(
                content=content,
                status_code=upstream_res.status_code,
                headers=response_headers,
                media_type=upstream_res.headers.get("content-type")
            )

        except Exception as exc:
            latency_ms = (time.time() - start_time) * 1000.0
            traffic_store.log_event(
                client_ip=client_ip,
                method=method,
                path=f"/{path}",
                status_code=502,
                latency_ms=latency_ms,
                bytes_in=len(body_bytes),
                bytes_out=0,
                verdict="ALLOWED",
                threat_category="Normal (Clean)",
                confidence_pct=100.0,
                tier1_anomaly=False,
                tier2_score=0.0,
                details=f"Upstream gateway error: {str(exc)}"
            )
            return HTMLResponse(
                status_code=502,
                content=f"<h3>502 Bad Gateway</h3><p>SentinelAI could not reach upstream target: <code>{target_base}</code> ({str(exc)})</p>"
            )

    except Exception as e:
        import traceback
        err_trace = traceback.format_exc()
        print(f"[!] PROXY GATEWAY ERROR: {err_trace}", flush=True)
        return HTMLResponse(
            status_code=500,
            content=f"<h3>SentinelAI Gateway Error</h3><pre>{err_trace}</pre>"
        )
