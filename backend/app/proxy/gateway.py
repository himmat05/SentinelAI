"""
SentinelAI - 24/7 Reverse Proxy & Autonomous Threat Shield Gateway
==================================================================
Inline AI Gatekeeper & WAF protecting upstream web applications.
Supports persistent SQLite configuration, Shadow vs Enforce modes, IP allowlisting,
multi-stage de-obfuscation WAF inspection, persistent IP Quarantine Jail, SPA HTML
asset rewriting, and background SOC webhook notifications.
"""

import datetime
import html
import os
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse

from backend.app.api.endpoints import alert_manager, alert_store
from backend.app.core.security import validate_upstream_url
from backend.app.db.traffic_store import traffic_store
from backend.app.proxy.flow_tracker import flow_tracker, quarantine_manager
from backend.app.schemas.flow import ThreatAlert
from backend.app.services.alert_notifier import webhook_notifier
from backend.app.services.inference_engine import SentinelInferenceEngine

router = APIRouter()

DEFAULT_TARGET_URL = os.environ.get("SENTINEL_TARGET_URL", "https://aai-ji-honey.vercel.app").rstrip("/")

# Rewrite root-relative HTML attributes like href="/foo" -> href="/gateway/foo" (skipping "//cdn...")
_HTML_ROOT_ATTR_RE = re.compile(r'(\b(?:href|src|action)=["\'])/(?!/)', re.IGNORECASE)

# Reusable AsyncClient (injectable for isolated unit tests)
_http_client: Optional[httpx.AsyncClient] = None


def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=True)
    return _http_client


def set_http_client(client: Optional[httpx.AsyncClient]) -> None:
    """Allow dependency injection of an httpx.AsyncClient (e.g. MockTransport in tests)."""
    global _http_client
    _http_client = client


def load_proxy_config() -> Dict[str, Any]:
    """Load persistent proxy configuration from SQLite with safe defaults."""
    settings = traffic_store.get_all_settings()
    return {
        "target_url": settings.get("target_url", DEFAULT_TARGET_URL),
        "shield_enabled": settings.get("shield_enabled", "true").lower() == "true",
        "shield_mode": settings.get("shield_mode", "enforce") if settings.get("shield_mode") in ("enforce", "shadow") else "enforce",
        "heartbeat_active": settings.get("heartbeat_active", "false").lower() == "true",
        "rewrite_html": settings.get("rewrite_html", "true").lower() == "true",
        "webhook_url": settings.get("webhook_url", ""),
        "webhook_enabled": settings.get("webhook_enabled", "false").lower() == "true",
    }


def _persist_config_state(cfg: Dict[str, Any]) -> None:
    for key, val in cfg.items():
        if isinstance(val, bool):
            traffic_store.set_setting(key, "true" if val else "false")
        else:
            traffic_store.set_setting(key, str(val))


_proxy_config: Dict[str, Any] = load_proxy_config()


def get_target_url() -> str:
    return _proxy_config["target_url"]


def set_target_url(url: str) -> str:
    validated = validate_upstream_url(url)
    _proxy_config["target_url"] = validated
    traffic_store.set_setting("target_url", validated)
    return validated


def update_proxy_settings(**kwargs: Any) -> Dict[str, Any]:
    """Validate and persist proxy configuration changes into SQLite."""
    if "target_url" in kwargs and kwargs["target_url"] is not None:
        set_target_url(kwargs["target_url"])
    if "shield_enabled" in kwargs and kwargs["shield_enabled"] is not None:
        _proxy_config["shield_enabled"] = bool(kwargs["shield_enabled"])
    if "shield_mode" in kwargs and kwargs["shield_mode"] is not None:
        mode = str(kwargs["shield_mode"]).lower().strip()
        if mode not in ("enforce", "shadow"):
            raise ValueError("shield_mode must be 'enforce' or 'shadow'.")
        _proxy_config["shield_mode"] = mode
    if "heartbeat_active" in kwargs and kwargs["heartbeat_active"] is not None:
        _proxy_config["heartbeat_active"] = bool(kwargs["heartbeat_active"])
    if "rewrite_html" in kwargs and kwargs["rewrite_html"] is not None:
        _proxy_config["rewrite_html"] = bool(kwargs["rewrite_html"])
    if "webhook_url" in kwargs and kwargs["webhook_url"] is not None:
        wh = str(kwargs["webhook_url"]).strip()
        _proxy_config["webhook_url"] = validate_upstream_url(wh) if wh else ""
    if "webhook_enabled" in kwargs and kwargs["webhook_enabled"] is not None:
        _proxy_config["webhook_enabled"] = bool(kwargs["webhook_enabled"])

    _persist_config_state(_proxy_config)
    return dict(_proxy_config)


def _extract_client_ip(request: Request) -> str:
    """Resolve visitor IP cleanly, respecting trusted proxy headers if present."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def render_blocked_page(
    client_ip: str,
    path: str,
    threat_category: str,
    confidence_pct: float,
    mitigation_action: str,
    threat_reason: str = "",
) -> str:
    """Render XSS-escaped dark-mode cyber SOC block page."""
    safe_target = html.escape(get_target_url())
    safe_cat = html.escape(threat_category)
    safe_path = html.escape(path)
    safe_ip = html.escape(client_ip)
    safe_action = html.escape(mitigation_action)
    safe_reason = html.escape(threat_reason or "Confirmed malicious request signature")

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
      border-radius: 14px; max-width: 600px; width: 90%; padding: 2.5rem;
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
    .details-table td {{ padding: 0.65rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.06); word-break: break-word; }}
    .details-table td:first-child {{ color: #64748b; font-weight: bold; width: 35%; }}
    .details-table td:last-child {{ color: #f87171; font-weight: bold; }}
    .footer-note {{ font-size: 0.75rem; color: #64748b; }}
  </style>
</head>
<body>
  <div class="shield-card">
    <div class="shield-icon">🛡️</div>
    <h1>Security Intrusion Intercepted</h1>
    <p>This request was blocked by the <b>SentinelAI 24/7 Autonomous Threat Shield</b> protecting <code>{safe_target}</code>.</p>

    <table class="details-table">
      <tr><td>Threat Classification</td><td>{safe_cat}</td></tr>
      <tr><td>Inspection Finding</td><td>{safe_reason}</td></tr>
      <tr><td>Detection Confidence</td><td>{confidence_pct:.1f}%</td></tr>
      <tr><td>Target Endpoint</td><td>{safe_path}</td></tr>
      <tr><td>Client Socket</td><td>{safe_ip}</td></tr>
      <tr><td>Enforced Action</td><td>{safe_action}</td></tr>
    </table>

    <div class="footer-note">
      Event persisted in SentinelAI SOC Time-Series Registry.
    </div>
  </div>
</body>
</html>"""


def render_quarantine_page(client_ip: str, ban_info: Dict[str, Any]) -> str:
    """Render XSS-escaped dedicated SOC Quarantine Jail response page."""
    remaining = int(ban_info.get("remaining_seconds", 0))
    safe_reason = html.escape(str(ban_info.get("reason", "Malicious activity detected")))
    safe_cat = html.escape(str(ban_info.get("threat_category", "Security Violation")))
    safe_banned_at = html.escape(str(ban_info.get("banned_at", "Just now")))
    safe_ip = html.escape(client_ip)
    safe_target = html.escape(get_target_url())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelAI — Socket Quarantined</title>
  <style>
    body {{
      margin: 0; padding: 0; background-color: #060911; color: #fff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex; align-items: center; justify-content: center; min-height: 100vh;
    }}
    .jail-card {{
      background: #0f172a; border: 1px solid rgba(245, 158, 11, 0.4);
      border-radius: 14px; max-width: 600px; width: 90%; padding: 2.5rem;
      box-shadow: 0 0 35px rgba(245, 158, 11, 0.2); text-align: center;
    }}
    .jail-icon {{
      font-size: 3.5rem; margin-bottom: 1rem;
      filter: drop-shadow(0 0 15px rgba(245, 158, 11, 0.6));
    }}
    h1 {{
      font-size: 1.5rem; color: #f59e0b; margin-bottom: 0.5rem;
      text-transform: uppercase; letter-spacing: 0.05em;
    }}
    p {{ color: #94a3b8; font-size: 0.9rem; line-height: 1.6; margin-bottom: 1.5rem; }}
    .details-table {{
      width: 100%; border-collapse: collapse; text-align: left;
      font-size: 0.8rem; font-family: monospace; margin-bottom: 1.5rem;
      background: #090d16; border-radius: 8px; overflow: hidden;
    }}
    .details-table td {{ padding: 0.65rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.06); word-break: break-word; }}
    .details-table td:first-child {{ color: #64748b; font-weight: bold; width: 35%; }}
    .details-table td:last-child {{ color: #fbbf24; font-weight: bold; }}
    .countdown {{
      font-family: monospace; font-size: 1.1rem; color: #fbbf24;
      background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3);
      padding: 0.5rem 1rem; border-radius: 6px; display: inline-block; margin-bottom: 1rem;
    }}
    .footer-note {{ font-size: 0.75rem; color: #64748b; }}
  </style>
</head>
<body>
  <div class="jail-card">
    <div class="jail-icon">⛓️</div>
    <h1>Perimeter IP Quarantine Active</h1>
    <p>Your client IP address has been placed in an <b>Autonomous Security Jail</b> after confirmed exploitation attempts against <code>{safe_target}</code>.</p>

    <div class="countdown">
      Ban Remaining: <b>{remaining} seconds</b>
    </div>

    <table class="details-table">
      <tr><td>Quarantined IP</td><td>{safe_ip}</td></tr>
      <tr><td>Trigger Category</td><td>{safe_cat}</td></tr>
      <tr><td>Violation Reason</td><td>{safe_reason}</td></tr>
      <tr><td>Banned Timestamp</td><td>{safe_banned_at}</td></tr>
      <tr><td>Autonomous Policy</td><td>Active Defense Quarantine (HTTP 403 Perimeter Drop)</td></tr>
    </table>

    <div class="footer-note">
      This incident is permanently recorded in SentinelAI's persistent SOC registry.
    </div>
  </div>
</body>
</html>"""


@router.get("/gateway")
async def redirect_gateway_root():
    return RedirectResponse(url="/gateway/")


@router.api_route(
    "/gateway/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
)
async def proxy_gateway(request: Request, path: str = ""):
    """
    Main 24/7 Reverse Proxy Gateway:
    Inspects inbound requests with anti-evasion WAF normalization + 3-Tier ML AI,
    blocks & quarantines threats (Enforce Mode) or audits silently (Shadow Mode),
    and transparently proxies clean traffic to the upstream website.
    """
    try:
        start_time = time.time()
        client_ip = _extract_client_ip(request)
        body_bytes = await request.body()
        query_str = str(request.query_params)
        method = request.method
        req_headers = dict(request.headers)

        # Pass browser CORS OPTIONS preflights cleanly without triggering rate-limits
        if method == "OPTIONS":
            return Response(status_code=204)

        shield_enabled = _proxy_config["shield_enabled"]
        shield_mode = _proxy_config["shield_mode"]
        is_allowlisted = quarantine_manager.is_allowlisted(client_ip)

        # 0. Active Defense: Perimeter Quarantine Check (Enforce mode, non-allowlisted IPs)
        if shield_enabled and shield_mode == "enforce" and not is_allowlisted:
            is_banned, ban_info = quarantine_manager.is_quarantined(client_ip)
            if is_banned and ban_info:
                quarantine_manager.record_jail_hit(client_ip)
                latency_ms = (time.time() - start_time) * 1000.0
                jail_content = render_quarantine_page(client_ip, ban_info)
                traffic_store.log_event(
                    client_ip=client_ip,
                    method=method,
                    path=f"/{path}",
                    status_code=403,
                    latency_ms=latency_ms,
                    bytes_in=len(body_bytes),
                    bytes_out=len(jail_content),
                    verdict="QUARANTINED",
                    threat_category=ban_info.get("threat_category", "Quarantined IP"),
                    confidence_pct=100.0,
                    tier1_anomaly=True,
                    tier2_score=1.0,
                    details=f"Perimeter IP Jail: {ban_info.get('remaining_seconds')}s left. Reason: {ban_info.get('reason')}",
                )
                return HTMLResponse(status_code=status.HTTP_403_FORBIDDEN, content=jail_content)

        target_base = get_target_url()
        parsed_target = urlparse(target_base)
        target_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)

        # 1. Real-Time Telemetry Extraction & Anti-Evasion Normalization
        flow_data, heuristics = flow_tracker.record_and_extract_flow(
            client_ip=client_ip,
            method=method,
            path=f"/{path}",
            query_string=query_str,
            headers=req_headers,
            body_bytes=body_bytes,
            target_host=parsed_target.hostname or "aai-ji-honey.vercel.app",
            target_port=target_port,
            request_start_time=start_time,
        )

        # 2. Multi-Tier AI Evaluation
        engine = SentinelInferenceEngine.get_instance()
        pred = engine.inspect_flow(flow_data)

        # Consensus Decision (L7 WAF Signatures + Volumetric Rate/Scan + Supervised Tier-2 Confirmation)
        # Note: Unsupervised L4 IsolationForest outliers alone do NOT trigger HTTP 403/IP bans in L7 reverse proxy mode
        is_threat = False
        cat = "Normal (Clean)"
        threat_reason = ""

        if heuristics.get("is_malicious", False):
            is_threat = True
            cat = heuristics.get("detected_category", "Web Exploitation")
            threat_reason = heuristics.get("threat_reason", "Confirmed malicious attack signature detected.")
        elif heuristics.get("is_flooding", False):
            is_threat = True
            cat = "DDoS"
            threat_reason = heuristics.get("threat_reason", "Volumetric request flooding rate-limit exceeded.")
        elif pred.tier2_flag and pred.tier2_score >= 0.85 and pred.threat_category != "Normal (Clean)":
            is_threat = True
            cat = pred.threat_category
            threat_reason = f"High-confidence {cat} flow flagged by Supervised Gatekeeper (P={pred.tier2_score:.2f})."

        # Allowlisted IPs are never blocked/quarantined
        shadow_alert_header: Optional[str] = None
        if is_threat and shield_enabled and not is_allowlisted:
            conf = max(pred.confidence_pct, 99.2)

            if shield_mode == "enforce":
                latency_ms = (time.time() - start_time) * 1000.0
                quarantine_manager.quarantine_ip(
                    client_ip=client_ip,
                    threat_category=cat,
                    reason=threat_reason,
                    ban_seconds=900,
                )

                blocked_page_content = render_blocked_page(
                    client_ip=client_ip,
                    path=f"/{path}",
                    threat_category=cat,
                    confidence_pct=conf,
                    mitigation_action=pred.mitigation_action,
                    threat_reason=threat_reason,
                )

                traffic_store.log_event(
                    client_ip=client_ip,
                    method=method,
                    path=f"/{path}",
                    status_code=403,
                    latency_ms=latency_ms,
                    bytes_in=len(body_bytes),
                    bytes_out=len(blocked_page_content),
                    verdict="BLOCKED",
                    threat_category=cat,
                    confidence_pct=conf,
                    tier1_anomaly=pred.tier1_anomaly_flag,
                    tier2_score=pred.tier2_score,
                    details=f"{threat_reason} (IP quarantined)",
                )

                alert = ThreatAlert(
                    event_id=f"SHIELD-{int(time.time() * 1000)}",
                    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    src_ip=client_ip,
                    dst_ip=flow_data.dst_ip or "upstream",
                    dst_port=flow_data.dst_port,
                    threat_category=cat,
                    severity="CRITICAL",
                    tier2_confidence=conf,
                    tier1_anomaly_detected=pred.tier1_anomaly_flag,
                    mitigation_action=pred.mitigation_action,
                    details=f"{threat_reason} (IP quarantined for 15m)",
                )
                alert_store.add(alert)
                await alert_manager.broadcast_alert(alert)

                if _proxy_config.get("webhook_enabled") and _proxy_config.get("webhook_url"):
                    webhook_notifier.dispatch_background(
                        webhook_url=_proxy_config["webhook_url"],
                        client_ip=client_ip,
                        threat_category=cat,
                        reason=threat_reason,
                        path=f"/{path}",
                        target_url=target_base,
                        shield_mode="enforce",
                    )

                return HTMLResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content=blocked_page_content,
                )

            # Shadow Mode: Log detection & trigger webhook, but DO NOT block request
            shadow_alert_header = cat
            shadow_latency_ms = (time.time() - start_time) * 1000.0
            traffic_store.log_event(
                client_ip=client_ip,
                method=method,
                path=f"/{path}",
                status_code=200,
                latency_ms=shadow_latency_ms,
                bytes_in=len(body_bytes),
                bytes_out=0,
                verdict="SHADOW_BLOCKED",
                threat_category=cat,
                confidence_pct=conf,
                tier1_anomaly=pred.tier1_anomaly_flag,
                tier2_score=pred.tier2_score,
                details=f"[SHADOW AUDIT] {threat_reason} (Allowed upstream)",
            )
            if _proxy_config.get("webhook_enabled") and _proxy_config.get("webhook_url"):
                webhook_notifier.dispatch_background(
                    webhook_url=_proxy_config["webhook_url"],
                    client_ip=client_ip,
                    threat_category=cat,
                    reason=threat_reason,
                    path=f"/{path}",
                    target_url=target_base,
                    shield_mode="shadow",
                )

        # 3. Forward Request to Upstream Target Website
        upstream_url = f"{target_base}/{path}"
        if query_str:
            upstream_url += f"?{query_str}"

        forward_headers = {
            k: v
            for k, v in req_headers.items()
            if k.lower() not in ["host", "content-length", "x-sentinel-token", "x-sentinel-origin-secret"]
        }
        forward_headers["host"] = parsed_target.netloc
        origin_secret = os.environ.get("SENTINEL_ORIGIN_SECRET", "").strip()
        if origin_secret:
            forward_headers["x-sentinel-origin-secret"] = origin_secret

        client = get_http_client()
        try:
            upstream_req = client.build_request(
                method=method,
                url=upstream_url,
                headers=forward_headers,
                content=body_bytes if body_bytes else None,
            )
            upstream_res = await client.send(upstream_req, stream=True)
            latency_ms = (time.time() - start_time) * 1000.0

            content = await upstream_res.aread()
            content_type = upstream_res.headers.get("content-type", "")

            # Rewrite root-relative SPA asset links when rendering HTML inside /gateway/
            if _proxy_config.get("rewrite_html", True) and "text/html" in content_type.lower():
                try:
                    html_str = content.decode("utf-8", errors="ignore")
                    rewritten = _HTML_ROOT_ATTR_RE.sub(r"\1/gateway/", html_str)
                    content = rewritten.encode("utf-8")
                except Exception:
                    pass

            bytes_out = len(content)

            if not shadow_alert_header:
                note = " [Allowlisted IP]" if is_allowlisted else ""
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
                    details=f"Forwarded to {parsed_target.netloc} -> HTTP {upstream_res.status_code}{note}",
                )

            response_headers = {
                k: v
                for k, v in upstream_res.headers.items()
                if k.lower() not in [
                    "content-encoding",
                    "transfer-encoding",
                    "content-length",
                    "x-powered-by",
                    "server",
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-allow-methods",
                    "access-control-allow-headers",
                    "access-control-expose-headers",
                ]
            }
            response_headers["x-protected-by"] = "SentinelAI-Autonomous-SOC-Shield"
            response_headers["x-sentinel-mode"] = shield_mode
            if shadow_alert_header:
                response_headers["x-sentinel-shadow-alert"] = shadow_alert_header

            return Response(
                content=content,
                status_code=upstream_res.status_code,
                headers=response_headers,
                media_type=content_type or None,
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
                threat_category="Upstream Error",
                confidence_pct=100.0,
                tier1_anomaly=False,
                tier2_score=0.0,
                details=f"Upstream gateway error: {str(exc)}",
            )
            return HTMLResponse(
                status_code=502,
                content=f"<h3>502 Bad Gateway</h3><p>SentinelAI could not reach upstream target: <code>{html.escape(target_base)}</code> ({html.escape(str(exc))})</p>",
            )

    except Exception as e:
        import traceback

        err_trace = traceback.format_exc()
        print(f"[!] PROXY GATEWAY ERROR: {err_trace}", flush=True)
        return HTMLResponse(
            status_code=500,
            content=f"<h3>SentinelAI Gateway Error</h3><pre>{html.escape(err_trace)}</pre>",
        )
