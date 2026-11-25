"""
SentinelAI - 24/7 Live Monitoring, Active Quarantine, RAG Triage & Ops API
===========================================================================
REST endpoints driving 24/7 website monitoring, persistent proxy/shield settings,
IP quarantine & allowlist management, RAG incident briefs, firewall rule exports,
and webhook notifications—protected by operator auth and SSRF guards.
"""

import asyncio
import datetime
import time
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from backend.app.core.security import (
    extract_request_token,
    get_configured_admin_token,
    is_local_dev_client,
    require_operator_auth,
)
from backend.app.db.traffic_store import traffic_store
from backend.app.proxy.flow_tracker import quarantine_manager
from backend.app.proxy.gateway import (
    _proxy_config,
    get_target_url,
    update_proxy_settings,
)
from backend.app.services.alert_notifier import webhook_notifier
from intelligence.agent.report_generator import IncidentReportGenerator
from intelligence.agent.workflow import IncidentInvestigationWorkflow

router = APIRouter()

_heartbeat_task: Optional[asyncio.Task] = None
_workflow_instance: Optional[IncidentInvestigationWorkflow] = None


def _get_workflow() -> IncidentInvestigationWorkflow:
    global _workflow_instance
    if _workflow_instance is None:
        _workflow_instance = IncidentInvestigationWorkflow()
    return _workflow_instance


class ProxyConfigUpdate(BaseModel):
    target_url: Optional[str] = None
    shield_enabled: Optional[bool] = None
    shield_mode: Optional[str] = None
    heartbeat_active: Optional[bool] = None
    rewrite_html: Optional[bool] = None
    webhook_url: Optional[str] = None
    webhook_enabled: Optional[bool] = None


class UnbanRequest(BaseModel):
    client_ip: str


class AllowlistRequest(BaseModel):
    client_ip: str
    note: str = "Trusted Operator IP"


class InvestigateEventRequest(BaseModel):
    llm_provider: str = "deterministic"
    llm_model: Optional[str] = None
    api_key: Optional[str] = None


async def _run_heartbeat_loop(app: Any):
    """Background loop pinging /gateway/ via in-process ASGI transport for continuous telemetry."""
    transport = httpx.ASGITransport(app=app)
    while _proxy_config.get("heartbeat_active", False):
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://sentinel.local", timeout=10.0) as client:
                await client.get("/gateway/")
        except Exception:
            pass
        await asyncio.sleep(6.0)


def _public_config_payload() -> Dict[str, Any]:
    webhook_url = _proxy_config.get("webhook_url", "")
    masked_webhook = ""
    if webhook_url:
        masked_webhook = webhook_url[:28] + "..." if len(webhook_url) > 32 else webhook_url
    return {
        "target_url": get_target_url(),
        "shield_enabled": _proxy_config["shield_enabled"],
        "shield_mode": _proxy_config["shield_mode"],
        "heartbeat_active": _proxy_config["heartbeat_active"],
        "rewrite_html": _proxy_config["rewrite_html"],
        "webhook_enabled": _proxy_config["webhook_enabled"],
        "webhook_configured": bool(webhook_url),
        "webhook_preview": masked_webhook,
        "gateway_url": "/gateway/",
    }


@router.get("/auth-status")
async def get_auth_status(
    request: Request,
    x_sentinel_token: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Report whether operator authentication is enforced and if the caller is authenticated."""
    import hmac

    configured = get_configured_admin_token()
    provided = extract_request_token(x_sentinel_token, authorization)

    if configured:
        authenticated = bool(provided and hmac.compare_digest(provided, configured))
        return {"auth_required": True, "authenticated": authenticated, "mode": "token"}

    is_local = is_local_dev_client(request)
    return {"auth_required": not is_local, "authenticated": is_local, "mode": "localhost-dev" if is_local else "token-required"}


@router.get("/config")
async def get_monitoring_config() -> Dict[str, Any]:
    """Retrieve persistent 24/7 shield monitoring settings."""
    return _public_config_payload()


@router.post("/config")
async def update_monitoring_config(
    cfg: ProxyConfigUpdate,
    request: Request,
    _auth: str = Depends(require_operator_auth),
) -> Dict[str, Any]:
    """Update protected target URL, Enforce/Shadow mode, webhook, or heartbeat."""
    global _heartbeat_task

    try:
        update_proxy_settings(
            target_url=cfg.target_url,
            shield_enabled=cfg.shield_enabled,
            shield_mode=cfg.shield_mode,
            heartbeat_active=cfg.heartbeat_active,
            rewrite_html=cfg.rewrite_html,
            webhook_url=cfg.webhook_url,
            webhook_enabled=cfg.webhook_enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    if cfg.heartbeat_active is not None:
        if _proxy_config["heartbeat_active"]:
            if _heartbeat_task is None or _heartbeat_task.done():
                _heartbeat_task = asyncio.create_task(_run_heartbeat_loop(request.app))
        else:
            if _heartbeat_task and not _heartbeat_task.done():
                _heartbeat_task.cancel()

    return {"status": "updated", "config": _public_config_payload()}


@router.get("/stats")
async def get_monitoring_stats() -> Dict[str, Any]:
    """Return persistent rolling defense metrics."""
    summary = traffic_store.get_summary()
    summary["target_url"] = get_target_url()
    summary["shield_status"] = (
        f"ACTIVE ({_proxy_config['shield_mode'].upper()})" if _proxy_config["shield_enabled"] else "BYPASS"
    )
    summary["shield_mode"] = _proxy_config["shield_mode"]
    summary["active_bans"] = len(quarantine_manager.get_all_active_bans())
    return summary


@router.get("/chart")
async def get_chart_data(points: int = 30) -> Dict[str, Any]:
    """Return chronological time-series buckets for rolling chart."""
    buckets = traffic_store.get_chart_data(limit_points=points)
    return {"points": buckets, "count": len(buckets)}


@router.get("/logs")
async def get_recent_traffic_logs(limit: int = 50, threat_only: bool = False) -> Dict[str, Any]:
    """Fetch latest timestamped HTTP flows inspected by SentinelAI."""
    logs = traffic_store.get_recent_events(limit=limit, threat_only=threat_only)
    return {"logs": logs, "total": len(logs)}


@router.get("/quarantine")
async def get_active_quarantine_bans() -> Dict[str, Any]:
    """Return all currently quarantined IPs from persistent SQLite storage."""
    bans = quarantine_manager.get_all_active_bans()
    return {"quarantined_ips": bans, "count": len(bans)}


@router.post("/quarantine/unban")
async def release_quarantined_ip(
    req: UnbanRequest,
    _auth: str = Depends(require_operator_auth),
) -> Dict[str, Any]:
    """Release an IP from the persistent quarantine jail."""
    success = quarantine_manager.unban_ip(req.client_ip.strip())
    return {
        "client_ip": req.client_ip.strip(),
        "unbanned": success,
        "message": (
            f"IP {req.client_ip.strip()} released from quarantine"
            if success
            else f"IP {req.client_ip.strip()} was not quarantined"
        ),
    }


@router.get("/allowlist")
async def get_allowlist_ips() -> Dict[str, Any]:
    """Return all operator-allowlisted IPs."""
    items = quarantine_manager.get_allowlist()
    return {"allowlist": items, "count": len(items)}


@router.post("/allowlist")
async def add_allowlist_ip(
    req: AllowlistRequest,
    _auth: str = Depends(require_operator_auth),
) -> Dict[str, Any]:
    """Whitelist a trusted IP (releases from quarantine if currently banned)."""
    clean_ip = req.client_ip.strip()
    if not clean_ip:
        raise HTTPException(status_code=400, detail="client_ip is required.")
    entry = quarantine_manager.allow_ip(clean_ip, note=req.note)
    return {"status": "added", "entry": entry}


@router.delete("/allowlist/{client_ip}")
async def delete_allowlist_ip(
    client_ip: str,
    _auth: str = Depends(require_operator_auth),
) -> Dict[str, Any]:
    """Remove an IP from the trusted allowlist."""
    removed = quarantine_manager.remove_allowed_ip(client_ip.strip())
    return {"removed": removed, "client_ip": client_ip.strip()}


@router.post("/investigate-event/{event_id}")
async def investigate_logged_event(
    event_id: int,
    req: Optional[InvestigateEventRequest] = None,
    _auth: str = Depends(require_operator_auth),
) -> Dict[str, Any]:
    """
    Correlate a live blocked/shadowed gateway event with ChromaDB threat intelligence
    (MITRE ATT&CK, CISA KEV, OWASP) and generate an executive Markdown incident brief.
    """
    event = traffic_store.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Traffic event ID {event_id} not found.")

    body = req or InvestigateEventRequest()
    wf = _get_workflow()
    report = wf.investigate_alert(
        attack_family=event.get("threat_category") or "Web Exploitation",
        confidence=min(max(float(event.get("confidence_pct", 99.0)) / 100.0, 0.0), 1.0),
        src_ip=event.get("client_ip"),
        dst_ip=get_target_url(),
        dst_port=443 if get_target_url().startswith("https") else 80,
        decisive_features=[
            f"HTTP {event.get('method')} {event.get('path')}",
            f"Finding: {event.get('details', '')[:120]}",
        ],
        anomaly_score=1.0 if event.get("tier1_anomaly") else None,
        llm_provider=body.llm_provider,
        llm_model=body.llm_model,
        api_key=body.api_key,
    )

    gen = IncidentReportGenerator()
    report["markdown_brief"] = gen.generate_markdown(report)
    report["source_event"] = event
    return report


@router.get("/export-rules")
async def export_firewall_rules(
    format: str = Query(default="nginx", pattern="^(nginx|iptables|cloudflare)$"),
    _auth: str = Depends(require_operator_auth),
):
    """Export active quarantined IPs as ready-to-deploy firewall / WAF configuration rules."""
    bans = quarantine_manager.get_all_active_bans()
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if format == "nginx":
        lines = [
            f"# SentinelAI Autonomous Edge Deny Rules (Generated: {generated_at})",
            f"# Place inside Nginx http/server/location block protecting {get_target_url()}",
        ]
        if not bans:
            lines.append("# No active quarantined IPs at this moment.")
        for b in bans:
            lines.append(f"deny {b['client_ip']}; # {b['threat_category']} ({b['remaining_seconds']}s left)")
        content = "\n".join(lines) + "\n"
        return PlainTextResponse(content=content, media_type="text/plain")

    if format == "iptables":
        lines = [
            "#!/usr/bin/env bash",
            f"# SentinelAI iptables Perimeter Drop Rules (Generated: {generated_at})",
        ]
        if not bans:
            lines.append("# No active quarantined IPs at this moment.")
        for b in bans:
            lines.append(
                f"iptables -I INPUT -s {b['client_ip']} -j DROP  # {b['threat_category']} - {b['banned_at']}"
            )
        content = "\n".join(lines) + "\n"
        return PlainTextResponse(content=content, media_type="text/plain")

    # Cloudflare WAF Custom Rule expression
    if not bans:
        expr = '(http.request.uri.path contains "/.env") or (http.request.uri.path contains "/.git")'
    else:
        ips_joined = " ".join(b["client_ip"] for b in bans)
        expr = f"(ip.src in {{{ips_joined}}})"

    return {
        "format": "cloudflare_waf_expression",
        "generated_at": generated_at,
        "quarantined_count": len(bans),
        "action": "block",
        "expression": expr,
        "quarantined_ips": [b["client_ip"] for b in bans],
    }


@router.post("/webhook/test")
async def test_webhook_delivery(_auth: str = Depends(require_operator_auth)) -> Dict[str, Any]:
    """Send a test security alert to the configured Slack/Discord/HTTP webhook."""
    wh_url = _proxy_config.get("webhook_url", "")
    if not wh_url:
        raise HTTPException(status_code=400, detail="No webhook_url is configured yet.")

    result = await webhook_notifier.send_alert(
        webhook_url=wh_url,
        client_ip="203.0.113.42",
        threat_category="Web Exploitation (TEST)",
        reason="Operator-initiated webhook connectivity verification",
        path="/gateway/test-webhook",
        target_url=get_target_url(),
        shield_mode=_proxy_config["shield_mode"],
        force=True,
    )
    return result


@router.post("/simulate-attack")
async def simulate_attack_on_gateway(
    request: Request,
    attack_type: str = "sqli",
    _auth: str = Depends(require_operator_auth),
) -> Dict[str, Any]:
    """
    Fire a controlled adversarial probe through the internal ASGI gateway pipeline
    to verify WAF de-obfuscation, blocking, and persistent IP quarantine.
    Uses a dedicated simulated attacker IP (203.0.113.99) so the operator's browser
    session does not lock itself out of normal browsing.
    """
    sim_ip = "203.0.113.99"
    # Ensure previous simulation ban for synthetic IP resets cleanly unless testing repeat hit
    if attack_type != "jail_repeat":
        quarantine_manager.unban_ip(sim_ip)

    headers: Dict[str, str] = {"x-forwarded-for": sim_ip}
    method = "GET"
    json_body = None

    if attack_type == "scanner":
        target_path = "/gateway/api/products"
        headers["user-agent"] = "sqlmap/1.7#stable (http://sqlmap.org)"
    elif attack_type == "sensitive_probe":
        target_path = "/gateway/.env"
    elif attack_type == "rce":
        target_path = "/gateway/api/system?cmd=%3Bcat%20/etc/passwd"
    elif attack_type == "traversal":
        target_path = "/gateway/static/../../etc/passwd"
    elif attack_type == "double_encoded":
        target_path = "/gateway/files/%252e%252e%252f%252e%252e%252fetc/passwd"
    elif attack_type == "xss":
        target_path = "/gateway/search?q=%26%23x3c%3Bscript%26%23x3e%3Balert(1)%26%23x3c%3B%2Fscript%26%23x3e%3B"
    elif attack_type == "json_sqli":
        method = "POST"
        target_path = "/gateway/api/search"
        json_body = {"filter": "honey' UNION/**/SELECT username,password FROM users--"}
    elif attack_type == "flood":
        target_path = "/gateway/api/ping"
        transport = httpx.ASGITransport(app=request.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://sentinel.local", timeout=10.0) as client:
            res = None
            for _ in range(50):
                res = await client.get(target_path, headers=headers)
        status_code = res.status_code if res else 500
        return {
            "simulated_attack": "flood",
            "attacker_ip": sim_ip,
            "sent_url": target_path,
            "response_status": status_code,
            "blocked": status_code == 403,
            "message": "Volumetric Flood detected and throttled!" if status_code == 403 else "Flood transmitted (Shadow Mode or disabled)",
        }
    else:  # sqli
        target_path = "/gateway/api/products?id=1%27%20OR%20%271%27=%271%27%20UNION%20SELECT%20username,password%20FROM%20users--"

    transport = httpx.ASGITransport(app=request.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://sentinel.local", timeout=10.0) as client:
        if method == "POST":
            res = await client.post(target_path, json=json_body, headers=headers)
        else:
            res = await client.get(target_path, headers=headers)

    return {
        "simulated_attack": attack_type,
        "attacker_ip": sim_ip,
        "sent_url": target_path,
        "response_status": res.status_code,
        "blocked": res.status_code == 403,
        "shield_mode": _proxy_config["shield_mode"],
        "message": (
            f"Attack blocked (HTTP 403) & {sim_ip} quarantined!"
            if res.status_code == 403
            else f"Shadow Mode logged threat while forwarding (HTTP {res.status_code})"
        ),
    }


@router.post("/test-clean")
async def test_clean_request(request: Request) -> Dict[str, Any]:
    """Verify clean proxying to upstream protected target using in-process ASGI transport."""
    transport = httpx.ASGITransport(app=request.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://sentinel.local", timeout=15.0) as client:
        res = await client.get("/gateway/", headers={"x-forwarded-for": "198.51.100.10"})

    return {
        "target": get_target_url(),
        "proxy_status": res.status_code,
        "upstream_protected": res.headers.get("x-protected-by") == "SentinelAI-Autonomous-SOC-Shield",
        "bytes_received": len(res.content),
        "message": f"Successfully proxied to {get_target_url()} with HTTP {res.status_code}",
    }


@router.post("/clear-logs")
async def clear_traffic_logs(_auth: str = Depends(require_operator_auth)) -> Dict[str, Any]:
    """Clear historical time-series logs."""
    traffic_store.clear()
    return {"status": "cleared"}
