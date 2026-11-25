"""
SentinelAI - SSRF Guard, Operator Auth, Persistence & Firewall Export Tests
"""

import os
import tempfile
import unittest

from fastapi.testclient import TestClient

from backend.app.core.security import validate_upstream_url
from backend.app.db.traffic_store import TrafficStore
from backend.app.main import app
from backend.app.proxy.flow_tracker import IPQuarantineManager
from backend.app.proxy import flow_tracker as ft_module
from backend.app.proxy import gateway as gw_module
from backend.app.api import monitoring as mon_module


class TestSecurityAndPersistence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = os.path.join(cls.tmp_dir.name, "persist_test.db")
        cls.store = TrafficStore(db_path=cls.db_path)

        gw_module.traffic_store = cls.store
        mon_module.traffic_store = cls.store
        ft_module.flow_tracker = ft_module.ClientFlowTracker(store=cls.store)
        ft_module.quarantine_manager = ft_module.flow_tracker.quarantine
        gw_module.flow_tracker = ft_module.flow_tracker
        gw_module.quarantine_manager = ft_module.quarantine_manager
        mon_module.quarantine_manager = ft_module.quarantine_manager

        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("SENTINEL_ADMIN_TOKEN", None)
        cls.tmp_dir.cleanup()

    def tearDown(self):
        os.environ.pop("SENTINEL_ADMIN_TOKEN", None)

    def test_ssrf_guard_rejects_internal_and_metadata_urls(self):
        unsafe_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8000/admin",
            "http://localhost:8080",
            "http://10.0.0.5/internal",
            "http://192.168.1.1",
            "ftp://example.com/resource",
            "https://user:pass@example.com",
            "http://metadata.google.internal",
        ]
        for bad_url in unsafe_urls:
            with self.assertRaises(ValueError, msg=f"SSRF guard failed to block {bad_url}"):
                validate_upstream_url(bad_url, allow_private=False)

        safe = validate_upstream_url("https://aai-ji-honey.vercel.app/", allow_private=False)
        self.assertEqual(safe, "https://aai-ji-honey.vercel.app")

    def test_quarantine_survives_manager_reinstantiation(self):
        mgr1 = IPQuarantineManager(store=self.store)
        mgr1.quarantine_ip("203.0.113.77", threat_category="Web Exploitation", reason="SQLi", ban_seconds=600)

        # Simulate server restart with a brand new IPQuarantineManager pointing at same SQLite DB
        mgr2 = IPQuarantineManager(store=TrafficStore(db_path=self.db_path))
        is_banned, info = mgr2.is_quarantined("203.0.113.77")
        self.assertTrue(is_banned)
        self.assertEqual(info["threat_category"], "Web Exploitation")

        self.assertTrue(mgr2.unban_ip("203.0.113.77"))
        still_banned, _ = mgr2.is_quarantined("203.0.113.77")
        self.assertFalse(still_banned)

    def test_operator_token_auth_enforcement_and_rule_exports(self):
        os.environ["SENTINEL_ADMIN_TOKEN"] = "sentinel-test-secret-token"

        # Unauthenticated mutation must be rejected (401)
        res_no_auth = self.client.post("/api/monitoring/config", json={"shield_mode": "shadow"})
        self.assertEqual(res_no_auth.status_code, 401)

        # Wrong token rejected (401)
        res_bad_auth = self.client.post(
            "/api/monitoring/config",
            json={"shield_mode": "shadow"},
            headers={"X-Sentinel-Token": "wrong-token"},
        )
        self.assertEqual(res_bad_auth.status_code, 401)

        # Valid token succeeds (200)
        auth_headers = {"X-Sentinel-Token": "sentinel-test-secret-token"}
        res_ok = self.client.post(
            "/api/monitoring/config",
            json={"shield_mode": "enforce"},
            headers=auth_headers,
        )
        self.assertEqual(res_ok.status_code, 200)

        # SSRF URL attempt through authenticated endpoint returns 400
        res_ssrf = self.client.post(
            "/api/monitoring/config",
            json={"target_url": "http://169.254.169.254/latest/meta-data"},
            headers=auth_headers,
        )
        self.assertEqual(res_ssrf.status_code, 400)

        # Add a ban and verify Nginx, iptables, and Cloudflare rule exports
        ft_module.quarantine_manager.quarantine_ip("198.51.100.88", "DDoS", "HTTP Flood", ban_seconds=300)

        res_nginx = self.client.get("/api/monitoring/export-rules?format=nginx", headers=auth_headers)
        self.assertEqual(res_nginx.status_code, 200)
        self.assertIn("deny 198.51.100.88;", res_nginx.text)

        res_ipt = self.client.get("/api/monitoring/export-rules?format=iptables", headers=auth_headers)
        self.assertEqual(res_ipt.status_code, 200)
        self.assertIn("iptables -I INPUT -s 198.51.100.88 -j DROP", res_ipt.text)

        res_cf = self.client.get("/api/monitoring/export-rules?format=cloudflare", headers=auth_headers)
        self.assertEqual(res_cf.status_code, 200)
        self.assertIn("198.51.100.88", res_cf.json()["expression"])


if __name__ == "__main__":
    unittest.main()
