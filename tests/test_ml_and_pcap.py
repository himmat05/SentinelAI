"""
SentinelAI - ML Inference, Pure-Python PCAP Parser & RAG Event Triage Tests
"""

import os
import socket
import struct
import tempfile
import unittest

from fastapi.testclient import TestClient

from backend.app.db.traffic_store import TrafficStore
from backend.app.main import app
from backend.app.schemas.flow import FlowData
from backend.app.services.inference_engine import SentinelInferenceEngine
from backend.app.api import monitoring as mon_module
from intelligence.agent.workflow import IncidentInvestigationWorkflow
from network.flow_extraction.pcap_parser import parse_pcap_bytes


class _MockSecurityTools:
    """Offline RAG retriever stub for deterministic unit testing in CI & sandboxes."""

    def search_threat_intel(self, query: str, category=None, top_k: int = 2):
        return [
            {
                "identifier": "T1190",
                "title": "Exploit Public-Facing Application",
                "source": "mitre_attack",
                "score": 0.94,
                "text": "Adversaries may attempt to exploit weaknesses in Internet-facing applications.",
            }
        ]

    def get_playbook_for_attack(self, attack_family: str, top_k: int = 3):
        return [
            {
                "identifier": "OWASP-A03",
                "title": "Injection Prevention Cheat Sheet",
                "source": "owasp_top10",
                "score": 0.92,
                "text": "Use parameterized queries, prepared statements, and strict input normalization.",
            }
        ]


def _build_synthetic_tcp_pcap() -> bytes:
    """Build a valid in-memory libpcap (.pcap) buffer containing a 4-packet bidirectional TCP flow."""
    # Global header: magic 0xa1b2c3d4 (LE), v2.4, zone=0, sigfigs=0, snaplen=65535, Ethernet=1
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    def make_eth_ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes, ts_s: int, ts_us: int) -> bytes:
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        tcp_len = 20 + len(payload)
        ip_total_len = 20 + tcp_len
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, ip_total_len, 1, 0, 64, 6, 0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            sport, dport, 1000, 2000, (5 << 4), 0x18, 32768, 0, 0,
        )
        frame = eth + ip_hdr + tcp_hdr + payload
        pkt_hdr = struct.pack("<IIII", ts_s, ts_us, len(frame), len(frame))
        return pkt_hdr + frame

    pkts = b"".join([
        make_eth_ipv4_tcp("192.168.1.105", "142.250.190.46", 52310, 443, b"A" * 180, 1700000000, 0),
        make_eth_ipv4_tcp("142.250.190.46", "192.168.1.105", 443, 52310, b"B" * 1200, 1700000000, 60000),
        make_eth_ipv4_tcp("192.168.1.105", "142.250.190.46", 52310, 443, b"C" * 150, 1700000000, 120000),
        make_eth_ipv4_tcp("142.250.190.46", "192.168.1.105", 443, 52310, b"D" * 1200, 1700000000, 190000),
    ])
    return global_hdr + pkts


class TestMlPcapAndRag(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = os.path.join(cls.tmp_dir.name, "ml_rag_test.db")
        cls.store = TrafficStore(db_path=cls.db_path)
        mon_module.traffic_store = cls.store
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def test_ml_engine_clean_vs_attack_flows(self):
        engine = SentinelInferenceEngine.get_instance()
        clean = FlowData(
            src_ip="192.168.1.105", dst_ip="142.250.190.46", src_port=52310, protocol="TCP", dst_port=443,
            flow_duration_s=1.250, flow_iat_mean_s=0.065, fwd_iat_mean_s=0.055, bwd_iat_mean_s=0.075,
            fwd_packets=12, bwd_packets=16, fwd_bytes=1850, bwd_bytes=14200,
            fwd_pkt_len_mean=154.2, bwd_pkt_len_mean=887.5,
            flow_bytes_per_sec=12840.0, flow_pkts_per_sec=22.4,
            fwd_tcp_win_ratio=0.55, bwd_tcp_win_ratio=0.60, traffic_symmetry_ratio=0.115,
        )
        res_clean = engine.inspect_flow(clean)
        self.assertFalse(res_clean.is_threat)

        ddos = FlowData(
            src_ip="203.0.113.5", dst_ip="10.0.0.10", src_port=44444, protocol="TCP", dst_port=80,
            flow_duration_s=0.05, flow_iat_mean_s=0.0005, fwd_iat_mean_s=0.0004, bwd_iat_mean_s=0.01,
            fwd_packets=80, bwd_packets=2, fwd_bytes=64000, bwd_bytes=120,
            fwd_pkt_len_mean=800.0, bwd_pkt_len_mean=60.0,
            flow_bytes_per_sec=1282400.0, flow_pkts_per_sec=1640.0,
            fwd_tcp_win_ratio=0.10, bwd_tcp_win_ratio=0.90, traffic_symmetry_ratio=0.998,
        )
        res_ddos = engine.inspect_flow(ddos)
        self.assertTrue(res_ddos.is_threat)

    def test_pcap_parser_and_upload_endpoint(self):
        pcap_bytes = _build_synthetic_tcp_pcap()
        flows = parse_pcap_bytes(pcap_bytes)
        self.assertEqual(len(flows), 1)
        f = flows[0]
        self.assertEqual(f.protocol, "TCP")
        self.assertEqual(f.dst_port, 443)
        self.assertEqual(f.fwd_packets, 2.0)
        self.assertEqual(f.bwd_packets, 2.0)

        res = self.client.post(
            "/api/predict/pcap",
            files={"file": ("sample_capture.pcap", pcap_bytes, "application/octet-stream")},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_flows_extracted"], 1)
        self.assertEqual(len(data["flows"]), 1)

    def test_investigate_logged_gateway_event_with_rag(self):
        orig_wf = mon_module._workflow_instance
        mon_module._workflow_instance = IncidentInvestigationWorkflow(tools=_MockSecurityTools())
        try:
            logged = self.store.log_event(
                client_ip="203.0.113.99",
                method="GET",
                path="/api/products?id=1 UNION SELECT",
                status_code=403,
                latency_ms=1.4,
                bytes_in=0,
                bytes_out=1200,
                verdict="BLOCKED",
                threat_category="Web Exploitation",
                confidence_pct=99.4,
                tier1_anomaly=False,
                tier2_score=0.99,
                details="SQL Injection attempt detected",
            )
            token = os.environ.get("SENTINEL_ADMIN_TOKEN", "").strip()
            headers = {"X-Sentinel-Token": token} if token else {}
            res = self.client.post(f"/api/monitoring/investigate-event/{logged['id']}", headers=headers)
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertEqual(body["threat_family"], "Web Exploitation")
            self.assertIn("T1190", str(body["mitre_attribution"]))
            self.assertIn("markdown_brief", body)
            self.assertIn("SentinelAI Security Incident Brief", body["markdown_brief"])
        finally:
            mon_module._workflow_instance = orig_wf


if __name__ == "__main__":
    unittest.main()
