"""
SentinelAI - Asynchronous SOC Webhook Dispatcher
================================================
Dispatches real-time security notifications to Slack, Discord, or custom HTTP webhooks
whenever SentinelAI blocks an intrusion or quarantines a malicious client IP.
Includes SSRF protection and per-IP cooldown deduplication to prevent webhook storms.
"""

import asyncio
import time
from typing import Any, Dict, Optional

import httpx

from backend.app.core.security import validate_upstream_url


class WebhookNotifier:
    """Non-blocking alert dispatcher with anti-spam cooldown per source IP."""

    def __init__(self, cooldown_seconds: float = 60.0):
        self.cooldown_seconds = cooldown_seconds
        self._last_sent: Dict[str, float] = {}

    def _build_payload(
        self,
        webhook_url: str,
        client_ip: str,
        threat_category: str,
        reason: str,
        path: str,
        target_url: str,
        shield_mode: str,
    ) -> Dict[str, Any]:
        """Format payload cleanly for Discord, Slack, or generic webhook consumers."""
        mode_tag = "[SHADOW]" if shield_mode == "shadow" else "[BLOCKED & QUARANTINED]"
        headline = f"🛡️ SentinelAI {mode_tag}: {threat_category}"
        details_text = (
            f"**Target:** {target_url}\n"
            f"**Attacker IP:** `{client_ip}`\n"
            f"**Path:** `{path}`\n"
            f"**Reason:** {reason}"
        )

        lower_url = webhook_url.lower()
        if "discord.com/api/webhooks" in lower_url or "discordapp.com/api/webhooks" in lower_url:
            return {
                "username": "SentinelAI Autonomous SOC",
                "embeds": [
                    {
                        "title": headline,
                        "description": details_text,
                        "color": 15158332 if shield_mode != "shadow" else 15105570,
                    }
                ],
            }

        # Slack and generic webhooks both understand "text" + rich structured JSON fields
        return {
            "text": f"{headline}\n{details_text}",
            "event": "SENTINELAI_THREAT_INTERCEPTED",
            "shield_mode": shield_mode,
            "client_ip": client_ip,
            "threat_category": threat_category,
            "path": path,
            "target_url": target_url,
            "reason": reason,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    async def send_alert(
        self,
        webhook_url: str,
        client_ip: str,
        threat_category: str,
        reason: str,
        path: str,
        target_url: str,
        shield_mode: str = "enforce",
        force: bool = False,
    ) -> Dict[str, Any]:
        return await self._dispatch(
            webhook_url=webhook_url,
            client_ip=client_ip,
            threat_category=threat_category,
            reason=reason,
            path=path,
            target_url=target_url,
            shield_mode=shield_mode,
            force=force,
        )

    async def _dispatch(
        self,
        webhook_url: str,
        client_ip: str,
        threat_category: str,
        reason: str,
        path: str,
        target_url: str,
        shield_mode: str,
        force: bool,
    ) -> Dict[str, Any]:
        clean_url = (webhook_url or "").strip()
        if not clean_url:
            return {"sent": False, "reason": "No webhook URL configured."}

        now = time.time()
        dedup_key = f"{client_ip}:{threat_category}"
        if not force and (now - self._last_sent.get(dedup_key, 0.0)) < self.cooldown_seconds:
            return {"sent": False, "reason": "Suppressed by per-IP alert cooldown."}

        try:
            validated_url = validate_upstream_url(clean_url)
        except ValueError as exc:
            return {"sent": False, "reason": f"Webhook URL rejected by SSRF guard: {exc}"}

        payload = self._build_payload(
            webhook_url=validated_url,
            client_ip=client_ip,
            threat_category=threat_category,
            reason=reason,
            path=path,
            target_url=target_url,
            shield_mode=shield_mode,
        )

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(validated_url, json=payload)
            self._last_sent[dedup_key] = now
            return {
                "sent": 200 <= res.status_code < 300,
                "status_code": res.status_code,
            }
        except Exception as exc:
            return {"sent": False, "reason": str(exc)}

    def dispatch_background(
        self,
        webhook_url: str,
        client_ip: str,
        threat_category: str,
        reason: str,
        path: str,
        target_url: str,
        shield_mode: str = "enforce",
    ) -> None:
        """Fire-and-forget webhook delivery without stalling proxy request latency."""
        if not webhook_url:
            return
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                self._dispatch(
                    webhook_url=webhook_url,
                    client_ip=client_ip,
                    threat_category=threat_category,
                    reason=reason,
                    path=path,
                    target_url=target_url,
                    shield_mode=shield_mode,
                    force=False,
                )
            )
        except RuntimeError:
            pass


webhook_notifier = WebhookNotifier()
