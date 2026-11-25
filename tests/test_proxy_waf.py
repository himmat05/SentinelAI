"""
SentinelAI - Reverse Proxy, Anti-Evasion WAF & Shadow/Enforce Integration Tests
Uses FastAPI TestClient + mocked httpx transport so tests run isolated and offline.
"""

import os
import tempfile
import unittest

import httpx
from fastapi.testclient import TestClient

from backend.app.db.traffic_store import TrafficStore
from backend.app.main import app
from backend.app.proxy import flow_tracker as ft_module
from backend.app.proxy import gateway as gw_module
from backend.app.api import monitoring as mon_module


def _mock_upstream_handler(request: httpx.Request) -> httpx.Response:
    html_body = (
        "<!doctype html><html><head>"
        '<link rel="stylesheet" href="/assets/style.css">'
        '<script src="/assets/app.js"></script>'
        '<script src="https://cdn.example.com/lib.js"></script>'
        "</head><body><h1>Aai-Ji Honey Upstream</h1></body></html>"
    )
    return httpx.Response(
        status_code=200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "x-powered-by": "Express",
            "access-control-allow-origin": "https://aai-ji-honey.vercel.app",
            "x-echo-origin-secret": request.headers.get("x-sentinel-origin-secret", ""),
        },
        text=html_body,
    )


class TestProxyAndWaf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = os.path.join(cls.tmp_dir.name, "test_traffic.db")
        cls.store = TrafficStore(db_path=cls.db_path)

        # Swap store references for full test isolation
        gw_module.traffic_store = cls.store
        mon_module.traffic_store = cls.store
        ft_module.flow_tracker = ft_module.ClientFlowTracker(store=cls.store)
        ft_module.quarantine_manager = ft_module.flow_tracker.quarantine
        gw_module.flow_tracker = ft_module.flow_tracker
        gw_module.quarantine_manager = ft_module.quarantine_manager
        mon_module.quarantine_manager = ft_module.quarantine_manager

        gw_module._proxy_config.update({
            "target_url": "https://aai-ji-honey.vercel.app",
            "shield_enabled": True,
            "shield_mode": "enforce",
            "heartbeat_active": False,
            "rewrite_html": True,
            "webhook_url": "",
            "webhook_enabled": False,
        })

        # Inject offline httpx MockTransport
        cls.mock_client = httpx.AsyncClient(transport=httpx.MockTransport(_mock_upstream_handler))
        gw_module.set_http_client(cls.mock_client)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        gw_module.set_http_client(None)
        cls.tmp_dir.cleanup()

    def setUp(self):
        self.store.clear()
        for ban in list(self.store.list_active_quarantines()):
            self.store.remove_quarantine(ban["client_ip"])
        for al in list(self.store.list_allowlist_ips()):
            self.store.remove_allowlist_ip(al["client_ip"])
        gw_module.update_proxy_settings(shield_enabled=True, shield_mode="enforce", rewrite_html=True)

    def test_clean_request_and_html_rewriting(self):
        os.environ["SENTINEL_ORIGIN_SECRET"] = "option-b-secret"
        try:
            res = self.client.get(
                "/gateway/",
                headers={"x-forwarded-for": "198.51.100.1", "origin": "https://aai-ji-honey.vercel.app"},
            )
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.headers.get("x-protected-by"), "SentinelAI-Autonomous-SOC-Shield")
            self.assertEqual(res.headers.get("x-echo-origin-secret"), "option-b-secret")
            self.assertNotIn("x-powered-by", res.headers)
            # Root-relative assets must be rewritten under /gateway/, while external URLs stay untouched
            self.assertIn('href="/gateway/assets/style.css"', res.text)
            self.assertIn('src="/gateway/assets/app.js"', res.text)
            self.assertIn('src="https://cdn.example.com/lib.js"', res.text)
        finally:
            os.environ.pop("SENTINEL_ORIGIN_SECRET", None)

    def test_blocks_inline_comment_sqli_and_jails_ip(self):
        attacker = "203.0.113.10"
        res = self.client.get(
            "/gateway/products?id=1'%20UNION/**/SELECT%20username,password%20FROM%20users--",
            headers={"x-forwarded-for": attacker},
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("Security Intrusion Intercepted", res.text)

        # Immediate clean follow-up from attacker IP must be dropped by Quarantine Jail
        res_repeat = self.client.get("/gateway/", headers={"x-forwarded-for": attacker})
        self.assertEqual(res_repeat.status_code, 403)
        self.assertIn("Perimeter IP Quarantine Active", res_repeat.text)

    def test_blocks_double_encoded_traversal_and_escapes_xss_in_block_page(self):
        attacker = "203.0.113.11"
        res = self.client.get(
            "/gateway/files/%252e%252e%252f%252e%252e%252fetc/passwd",
            headers={"x-forwarded-for": attacker},
        )
        self.assertEqual(res.status_code, 403)

        attacker_xss = "203.0.113.12"
        res_xss = self.client.get(
            "/gateway/search?q=%26%23x3c%3Bscript%26%23x3e%3Balert(1)%26%23x3c%3B%2Fscript%26%23x3e%3B",
            headers={"x-forwarded-for": attacker_xss},
        )
        self.assertEqual(res_xss.status_code, 403)
        self.assertNotIn("<script>alert(1)</script>", res_xss.text)

    def test_blocks_json_body_sqli_and_rce_and_env_and_scanners(self):
        vectors = [
            ("203.0.113.21", "POST", "/gateway/api/search", {"json": {"q": "honey' UNION SELECT * FROM users--"}}, {}),
            ("203.0.113.22", "GET", "/gateway/api/run?cmd=%3Bcat%20/etc/passwd", {}, {}),
            ("203.0.113.23", "GET", "/gateway/.env", {}, {}),
            ("203.0.113.24", "GET", "/gateway/items", {}, {"user-agent": "sqlmap/1.7.10"}),
            ("203.0.113.25", "GET", "/gateway/fetch?url=http://169.254.169.254/latest/meta-data", {}, {}),
        ]
        for ip, method, path, kw, hdrs in vectors:
            headers = {"x-forwarded-for": ip, **hdrs}
            res = self.client.request(method, path, headers=headers, **kw)
            self.assertEqual(res.status_code, 403, f"Expected 403 for vector {path}")

    def test_shadow_mode_audits_without_blocking(self):
        gw_module.update_proxy_settings(shield_mode="shadow")
        shadow_ip = "203.0.113.55"
        res = self.client.get(
            "/gateway/.env",
            headers={"x-forwarded-for": shadow_ip},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("x-sentinel-mode"), "shadow")
        self.assertEqual(res.headers.get("x-sentinel-shadow-alert"), "Infiltration")

        # Should not quarantine IP in shadow mode
        is_banned, _ = ft_module.quarantine_manager.is_quarantined(shadow_ip)
        self.assertFalse(is_banned)

        # Verify SQLite recorded SHADOW_BLOCKED event
        logs = self.store.get_recent_events(limit=5, threat_only=True)
        self.assertTrue(any(l["verdict"] == "SHADOW_BLOCKED" for l in logs))

    def test_allowlist_bypasses_quarantine_and_drops(self):
        trusted_ip = "198.51.100.250"
        self.store.add_allowlist_ip(trusted_ip, note="SOC Admin IP")
        res = self.client.get("/gateway/.env", headers={"x-forwarded-for": trusted_ip})
        self.assertEqual(res.status_code, 200)
        is_banned, _ = ft_module.quarantine_manager.is_quarantined(trusted_ip)
        self.assertFalse(is_banned)

    def test_real_spa_polling_and_review_text_never_falsely_jailed(self):
        shopper_ip = "157.48.231.82"
        big_headers = {
            "x-forwarded-for": shopper_ip,
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "authorization": "Bearer " + ("x" * 350),
            "cookie": "session=" + ("y" * 500),
        }
        # First burst of page load API calls
        for p in ["/gateway/api/cart", "/gateway/messages/unread-count", "/gateway/reviews", "/gateway/gallery"]:
            res = self.client.get(p, headers=big_headers)
            self.assertEqual(res.status_code, 200)

        # Simulate 9-second user pause before polling /products (regression test for Render false positive!)
        ft_module.flow_tracker.ip_history[shopper_ip][-1] -= 9.0
        res_products = self.client.get("/gateway/products", headers=big_headers)
        self.assertEqual(res_products.status_code, 200)

        # Simulate normal natural-language review containing words like "select ... from" or "--"
        res_review = self.client.post(
            "/gateway/reviews",
            json={"rating": 5, "comment": "Select pure organic honey from wild forests -- great quality!"},
            headers=big_headers,
        )
        self.assertEqual(res_review.status_code, 200)
        is_banned, _ = ft_module.quarantine_manager.is_quarantined(shopper_ip)
        self.assertFalse(is_banned)


if __name__ == "__main__":
    unittest.main()
