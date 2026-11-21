"""
SentinelAI - 24/7 Live Monitoring & Target Website API
======================================================
REST endpoints and telemetry providers for real-time website monitoring,
time-series charts, proxy configuration, and live simulation triggers.
"""

import asyncio
import httpx
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from backend.app.db.traffic_store import traffic_store
from backend.app.proxy.gateway import _proxy_config, set_target_url, get_target_url


router = APIRouter()

# Background heartbeat task handle
_heartbeat_task: Optional[asyncio.Task] = None


class ProxyConfigUpdate(BaseModel):
    target_url: Optional[str] = None
    shield_enabled: Optional[bool] = None
    heartbeat_active: Optional[bool] = None


async def _run_heartbeat_loop():
    """Background loop that periodically pings the protected website through SentinelAI."""
    while _proxy_config.get("heartbeat_active", False):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Ping the local gateway endpoint to generate continuous live flow metrics
                await client.get("http://127.0.0.1:8000/gateway/")
        except Exception:
            pass
        await asyncio.sleep(6.0)


@router.get("/config")
async def get_monitoring_config() -> Dict[str, Any]:
    """Retrieve current website monitoring parameters."""
    return {
        "target_url": get_target_url(),
        "shield_enabled": _proxy_config["shield_enabled"],
        "heartbeat_active": _proxy_config["heartbeat_active"],
        "gateway_url": "http://127.0.0.1:8000/gateway/"
    }


@router.post("/config")
async def update_monitoring_config(cfg: ProxyConfigUpdate) -> Dict[str, Any]:
    """Update upstream target website or toggle automated 24/7 heartbeat."""
    global _heartbeat_task

    if cfg.target_url is not None:
        set_target_url(cfg.target_url)

    if cfg.shield_enabled is not None:
        _proxy_config["shield_enabled"] = cfg.shield_enabled

    if cfg.heartbeat_active is not None:
        _proxy_config["heartbeat_active"] = cfg.heartbeat_active
        if cfg.heartbeat_active:
            if _heartbeat_task is None or _heartbeat_task.done():
                _heartbeat_task = asyncio.create_task(_run_heartbeat_loop())
        else:
            if _heartbeat_task and not _heartbeat_task.done():
                _heartbeat_task.cancel()

    return {
        "status": "updated",
        "config": {
            "target_url": get_target_url(),
            "shield_enabled": _proxy_config["shield_enabled"],
            "heartbeat_active": _proxy_config["heartbeat_active"],
            "gateway_url": "http://127.0.0.1:8000/gateway/"
        }
    }


@router.get("/stats")
async def get_monitoring_stats() -> Dict[str, Any]:
    """Return rolling aggregate defense metrics from time-series storage."""
    summary = traffic_store.get_summary()
    summary["target_url"] = get_target_url()
    summary["shield_status"] = "ACTIVE" if _proxy_config["shield_enabled"] else "BYPASS"
    return summary


@router.get("/chart")
async def get_chart_data(points: int = 30) -> Dict[str, Any]:
    """Return chronological time-series buckets for the live rolling frontend graph."""
    buckets = traffic_store.get_chart_data(limit_points=points)
    return {
        "points": buckets,
        "count": len(buckets)
    }


@router.get("/logs")
async def get_recent_traffic_logs(limit: int = 50, threat_only: bool = False) -> Dict[str, Any]:
    """Fetch the latest timestamped HTTP flows inspected by SentinelAI."""
    logs = traffic_store.get_recent_events(limit=limit, threat_only=threat_only)
    return {
        "logs": logs,
        "total": len(logs)
    }


@router.post("/simulate-attack")
async def simulate_attack_on_gateway(attack_type: str = "sqli") -> Dict[str, Any]:
    """
    Test Trigger:
    Fires an adversarial request against http://127.0.0.1:8000/gateway/
    to test the live AI shield and demonstrate immediate 403 containment.
    """
    payloads = {
        "sqli": "/gateway/api/products?id=1%27%20OR%20%271%27=%271%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        "traversal": "/gateway/static/../../etc/passwd",
        "xss": "/gateway/search?q=%3Cscript%3Ealert(%27pwned%27)%3C/script%3E"
    }
    target_path = payloads.get(attack_type, payloads["sqli"])
    url = f"http://127.0.0.1:8000{target_path}"

    async with httpx.AsyncClient(timeout=5.0) as client:
        res = await client.get(url)

    return {
        "simulated_attack": attack_type,
        "sent_url": url,
        "response_status": res.status_code,
        "blocked": res.status_code == 403,
        "message": "Attack intercepted and blocked by SentinelAI Shield!" if res.status_code == 403 else "Response received"
    }


@router.post("/test-clean")
async def test_clean_request() -> Dict[str, Any]:
    """
    Test Trigger:
    Fires a normal clean request through http://127.0.0.1:8000/gateway/
    to verify live transparent proxying to https://aai-ji-honey.vercel.app/.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.get("http://127.0.0.1:8000/gateway/")

    return {
        "target": get_target_url(),
        "proxy_status": res.status_code,
        "upstream_protected": True,
        "bytes_received": len(res.content),
        "message": f"Successfully proxied to {get_target_url()} with HTTP {res.status_code}"
    }


@router.post("/clear-logs")
async def clear_traffic_logs() -> Dict[str, Any]:
    """Clear historical time-series logs."""
    traffic_store.clear()
    return {"status": "cleared"}
