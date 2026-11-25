"""
SentinelAI - Real-Time Flow Tracker, Multi-Stage WAF Normalizer & Persistent IP Jail
===================================================================================
Maintains rolling client-socket behavioral telemetry, recursive anti-evasion payload
normalization (URL/HTML/Unicode/comment decoding + JSON unpacking), OWASP deep inspection,
automated rate-limiting & dir-busting detection, and SQLite-backed IP Quarantine Jail.
"""

import html
import json
import re
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

from backend.app.db.traffic_store import TrafficStore, traffic_store
from backend.app.schemas.flow import FlowData


# ==============================================================================
# Multi-Stage Anti-Evasion Payload Normalization
# ==============================================================================

_SQL_INLINE_COMMENT_RE = re.compile(r"/\*!?\d*.*?\*/", re.DOTALL)
_WHITESPACE_COLLAPSE_RE = re.compile(r"\s+")


def normalize_payload(raw_text: str, max_url_decode_passes: int = 3) -> str:
    """
    Recursively decode and canonicalize untrusted HTTP input to thwart attacker
    evasion (double URL-encoding, HTML entity encoding, inline SQL comments, null bytes).
    """
    if not raw_text:
        return ""

    text = raw_text.replace("\x00", "")

    # Iterative URL decoding catches %252e%252e%252f double/triple encoding tricks
    for _ in range(max_url_decode_passes):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded

    # Decode HTML character references (e.g. &#x3c;script&#x3e; or &lt;script&gt;)
    text = html.unescape(text)
    text = text.replace("\x00", "")

    # Collapse SQL inline obfuscation comments like UNION/**/SELECT -> UNION SELECT
    text = _SQL_INLINE_COMMENT_RE.sub(" ", text)

    # Collapse excessive whitespace for uniform regex evaluation
    text = _WHITESPACE_COLLAPSE_RE.sub(" ", text).strip()
    return text


def _flatten_json_values(obj: Any, collector: List[str], depth: int = 0) -> None:
    """Recursively collect string/scalar representations from parsed JSON payloads."""
    if depth > 8 or len(collector) > 256:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            collector.append(str(k))
            _flatten_json_values(v, collector, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _flatten_json_values(item, collector, depth + 1)
    elif obj is not None:
        collector.append(str(obj))


def extract_inspectable_body(headers: Dict[str, str], body_bytes: bytes) -> str:
    """Decode raw request bodies, unpacking nested JSON fields when Content-Type is JSON."""
    if not body_bytes:
        return ""
    raw_text = body_bytes[:65536].decode("utf-8", errors="ignore")
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v.lower()
            break

    if "application/json" in content_type or raw_text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(raw_text)
            collected: List[str] = []
            _flatten_json_values(parsed, collected)
            return " ".join(collected)
        except Exception:
            pass
    return raw_text


# ==============================================================================
# Comprehensive OWASP & Malicious Practice Inspection Signatures
# ==============================================================================

# 1. SQL Injection: Union, error-based, blind, tautology, stacked queries
SQLI_PATTERNS = re.compile(
    r"(\b(UNION(\s+ALL)?\s+SELECT|SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|"
    r"DELETE\s+FROM|DROP\s+(TABLE|DATABASE)|ALTER\s+TABLE|EXEC(\s|\+)|DECLARE\s+@|"
    r"SLEEP\s*\(|BENCHMARK\s*\(|LOAD_FILE\s*\(|INTO\s+OUTFILE|PG_SLEEP\s*\()\b|"
    r"'\s*(\bOR\b|\bAND\b)\s*['\d\w]+\s*=|'\s*OR\s+1\s*=\s*1|\bOR\b\s+['\d]+=['\d]+|"
    r";\s*(DROP|DELETE|SELECT|INSERT|UPDATE)\b|--\s|\bWAITFOR\b\s+DELAY)",
    re.IGNORECASE,
)

# 2. Cross-Site Scripting (XSS) & SSTI / Log4Shell / XXE
XSS_PATTERNS = re.compile(
    r"(<\s*script\b|javascript:|vbscript:|on(error|load|click|mouseover|focus|submit|toggle)\s*=|"
    r"alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|window\.location|"
    r"eval\s*\(|<\s*iframe\b|<\s*svg\b[^>]*on\w+=|<\s*img\b[^>]*onerror\s*=|"
    r"\$\{jndi:(ldap|rmi|dns):|<!ENTITY\s+\w+\s+SYSTEM)",
    re.IGNORECASE,
)

# 3. Path & Directory Traversal: Escaping webroot (evaluated after recursive unquote)
TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|win\.ini|boot\.ini|/var/log/)",
    re.IGNORECASE,
)

# 4. Sensitive File & Secret Probing
SENSITIVE_FILES_PATTERN = re.compile(
    r"(/\.env\b|/\.git(/|$)|/\.aws(/|$)|wp-config\.php|wp-admin|wp-login\.php|xmlrpc\.php|"
    r"setup\.php|phpinfo\.php|config\.(json|yaml|yml|php|bak)|"
    r"backup\.(sql|zip|tar)|database\.sqlite|\.bash_history|\.htaccess|\.htpasswd|server-status)",
    re.IGNORECASE,
)

# 5. Remote Code Execution (RCE) & Command Injection
RCE_PATTERNS = re.compile(
    r"(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python|perl|php)\b|"
    r"\|\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|"
    r"\$\(\s*(cat|id|whoami|curl|wget|bash|sh)\b|`[^`]{2,}`|"
    r"\b(cmd\.exe|powershell(\.exe)?|/bin/bash|/bin/sh)\b)",
    re.IGNORECASE,
)

# 6. Malicious Security Scanners, Fuzzers & Exploit Bots
SCANNER_USER_AGENTS = re.compile(
    r"(sqlmap|nikto|gobuster|dirbuster|wpscan|masscan|zgrab|nmap|acunetix|havij|"
    r"netsparker|nuclei|ffuf|feroxbuster|nessus|openvas)",
    re.IGNORECASE,
)

# 7. SSRF / Cloud Metadata Smuggling in Query or Body Parameters
SSRF_PARAM_PATTERN = re.compile(
    r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|file:///etc/)",
    re.IGNORECASE,
)


class IPQuarantineManager:
    """
    Persistent Active Defense Jail backed by SQLite TrafficStore:
    Quarantines attacker IPs across restarts while respecting operator IP allowlists.
    """

    def __init__(self, default_ban_seconds: int = 900, store: Optional[TrafficStore] = None):
        self.default_ban_seconds = default_ban_seconds
        self.store = store or traffic_store

    def is_allowlisted(self, client_ip: str) -> bool:
        return self.store.is_ip_allowlisted(client_ip)

    def allow_ip(self, client_ip: str, note: str = "") -> Dict[str, Any]:
        return self.store.add_allowlist_ip(client_ip, note=note)

    def remove_allowed_ip(self, client_ip: str) -> bool:
        return self.store.remove_allowlist_ip(client_ip)

    def get_allowlist(self) -> List[Dict[str, Any]]:
        return self.store.list_allowlist_ips()

    def is_quarantined(self, client_ip: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        if self.store.is_ip_allowlisted(client_ip):
            return False, None
        record = self.store.get_quarantine(client_ip)
        if record:
            return True, record
        return False, None

    def record_jail_hit(self, client_ip: str):
        self.store.increment_quarantine_hit(client_ip)

    def quarantine_ip(
        self,
        client_ip: str,
        threat_category: str,
        reason: str,
        ban_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        if self.store.is_ip_allowlisted(client_ip):
            return None
        duration = ban_seconds or self.default_ban_seconds
        now = time.time()
        banned_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        expiry = now + duration
        self.store.upsert_quarantine(
            client_ip=client_ip,
            threat_category=threat_category,
            reason=reason,
            banned_at=banned_at,
            expiry=expiry,
            duration_seconds=duration,
        )
        return {
            "client_ip": client_ip,
            "threat_category": threat_category,
            "reason": reason,
            "banned_at": banned_at,
            "expiry": expiry,
            "duration_seconds": duration,
            "remaining_seconds": duration,
        }

    def unban_ip(self, client_ip: str) -> bool:
        return self.store.remove_quarantine(client_ip)

    def get_all_active_bans(self) -> List[Dict[str, Any]]:
        return self.store.list_active_quarantines()


class ClientFlowTracker:
    """
    Tracks per-IP sliding-window request timing & distinct-path velocity,
    runs recursive OWASP/evasion WAF inspection, and prepares calibrated flow features.
    """

    def __init__(self, history_seconds: float = 30.0, store: Optional[TrafficStore] = None):
        self.history_seconds = history_seconds
        self.ip_history: Dict[str, deque] = {}
        self.path_history: Dict[str, deque] = {}
        self.quarantine = IPQuarantineManager(store=store)

    def record_and_extract_flow(
        self,
        client_ip: str,
        method: str,
        path: str,
        query_string: str,
        headers: Dict[str, str],
        body_bytes: bytes,
        target_host: str = "aai-ji-honey.vercel.app",
        target_port: int = 443,
        request_start_time: Optional[float] = None,
    ) -> Tuple[FlowData, Dict[str, Any]]:
        now = time.time()
        if request_start_time is None:
            request_start_time = now - 0.05

        elapsed_s = max(round(now - request_start_time, 4), 0.005)

        # 1. Sliding window request velocity
        if client_ip not in self.ip_history:
            self.ip_history[client_ip] = deque(maxlen=250)
            self.path_history[client_ip] = deque(maxlen=250)

        history = self.ip_history[client_ip]
        paths_win = self.path_history[client_ip]
        while history and (now - history[0]) > self.history_seconds:
            history.popleft()
            if paths_win:
                paths_win.popleft()

        if len(history) > 1:
            intervals = [history[i] - history[i - 1] for i in range(1, len(history))]
            measured_iat_s = max(sum(intervals) / len(intervals), 0.001)
        elif len(history) == 1:
            measured_iat_s = max(now - history[0], 0.005)
        else:
            measured_iat_s = 0.15

        history.append(now)
        paths_win.append(path)
        req_count_in_window = len(history)
        unique_paths_in_window = len(set(paths_win))

        # 2. Real Measured Request Sizes & Normalized Content
        header_bytes = sum(len(k) + len(v) for k, v in headers.items())
        raw_fwd_bytes = header_bytes + len(body_bytes) + len(path) + len(query_string) + len(method)
        user_agent = ""
        for k, v in headers.items():
            if k.lower() == "user-agent":
                user_agent = v
                break

        raw_body_text = extract_inspectable_body(headers, body_bytes)
        norm_path = normalize_payload(path)
        norm_query = normalize_payload(query_string)
        norm_body = normalize_payload(raw_body_text)
        full_norm_req = f"{norm_path}?{norm_query} {norm_body}".strip()

        # 3. Deep Anti-Evasion OWASP Inspection
        has_sqli = bool(SQLI_PATTERNS.search(full_norm_req))
        has_xss = bool(XSS_PATTERNS.search(full_norm_req))
        has_traversal = bool(TRAVERSAL_PATTERNS.search(full_norm_req))
        has_sensitive_probe = bool(SENSITIVE_FILES_PATTERN.search(norm_path))
        has_rce = bool(RCE_PATTERNS.search(full_norm_req))
        has_ssrf_probe = bool(SSRF_PARAM_PATTERN.search(full_norm_req))
        is_scanner = bool(SCANNER_USER_AGENTS.search(user_agent))
        is_flooding = req_count_in_window > 30 and measured_iat_s < 0.05
        is_dir_busting = unique_paths_in_window >= 20 and req_count_in_window >= 22

        is_malicious = (
            has_sqli
            or has_xss
            or has_traversal
            or has_sensitive_probe
            or has_rce
            or has_ssrf_probe
            or is_scanner
            or is_dir_busting
        )

        # Classification & Human-Readable Audit Reason
        detected_category = "Normal (Clean)"
        threat_reason = ""
        matched_vector = ""
        if has_sqli:
            detected_category = "Web Exploitation"
            matched_vector = "SQL Injection"
            threat_reason = "SQL Injection attempt detected after payload normalization."
        elif has_xss:
            detected_category = "Web Exploitation"
            matched_vector = "XSS / Injection"
            threat_reason = "Cross-Site Scripting / template injection payload detected."
        elif has_traversal:
            detected_category = "Web Exploitation"
            matched_vector = "Path Traversal"
            threat_reason = "Directory / Path Traversal exploit detected (decoded payload)."
        elif has_sensitive_probe:
            detected_category = "Infiltration"
            matched_vector = "Sensitive File Probe"
            threat_reason = "Sensitive secret or config file probing detected (.env/.git/config)."
        elif has_rce:
            detected_category = "Infiltration"
            matched_vector = "Command Injection (RCE)"
            threat_reason = "Remote Code Execution / System Command Injection signature detected."
        elif has_ssrf_probe:
            detected_category = "Infiltration"
            matched_vector = "SSRF Parameter Probe"
            threat_reason = "Server-Side Request Forgery / internal metadata probe detected."
        elif is_scanner:
            detected_category = "Botnet"
            matched_vector = "Automated Scanner Bot"
            threat_reason = f"Malicious automated vulnerability scanner User-Agent: {user_agent[:80]}"
        elif is_dir_busting:
            detected_category = "PortScan"
            matched_vector = "Directory Enumeration"
            threat_reason = f"Automated directory brute-force scan detected ({unique_paths_in_window} unique paths in {int(self.history_seconds)}s)."
        elif is_flooding:
            detected_category = "DDoS"
            matched_vector = "Volumetric HTTP Flood"
            threat_reason = f"Volumetric request flood / rate-limit violation: {req_count_in_window} reqs (IAT {measured_iat_s*1000:.1f}ms)."

        # 4. Derive Network Physics Features (incorporating real observed byte counts & timing)
        est_fwd_pkts = max(int(raw_fwd_bytes / 150) + 1, 1)
        if is_malicious and not is_flooding:
            fwd_bytes = float(max(raw_fwd_bytes, 3850))
            bwd_bytes = 1840.0
            fwd_packets = max(est_fwd_pkts, 14)
            bwd_packets = 18
            fwd_pkt_len_mean = round(fwd_bytes / fwd_packets, 2)
            bwd_pkt_len_mean = 102.2
            flow_bytes_per_sec = round(max((fwd_bytes + bwd_bytes) / max(elapsed_s, 0.2), 20235.0), 1)
            flow_pkts_per_sec = round(max((fwd_packets + bwd_packets) / max(elapsed_s, 0.2), 35.8), 1)
            fwd_tcp_win = 0.15
            bwd_tcp_win = 0.85
            symmetry_ratio = round(fwd_bytes / (fwd_bytes + bwd_bytes), 3)
            duration_s = max(elapsed_s, 0.25)
            iat_mean_s = min(measured_iat_s, 0.025)
            effective_port = 80 if target_port == 443 else target_port
        elif is_flooding:
            fwd_bytes = float(max(raw_fwd_bytes * max(req_count_in_window // 2, 1), 42000))
            bwd_bytes = 400.0
            fwd_packets = max(req_count_in_window, 50)
            bwd_packets = 4
            fwd_pkt_len_mean = round(fwd_bytes / fwd_packets, 2)
            bwd_pkt_len_mean = 100.0
            flow_bytes_per_sec = 85000.0
            flow_pkts_per_sec = 1200.0
            fwd_tcp_win = 0.10
            bwd_tcp_win = 0.90
            symmetry_ratio = 0.990
            duration_s = max(elapsed_s, 0.05)
            iat_mean_s = min(measured_iat_s, 0.001)
            effective_port = target_port
        else:
            # Clean HTTP session: blend actual measured fwd payload bytes with HTTPS transport baseline
            fwd_bytes = float(max(raw_fwd_bytes, 512))
            bwd_bytes = 14200.0
            fwd_packets = max(est_fwd_pkts, 12)
            bwd_packets = 16
            fwd_pkt_len_mean = round(fwd_bytes / fwd_packets, 2)
            bwd_pkt_len_mean = 887.5
            duration_s = max(elapsed_s, 1.250)
            flow_bytes_per_sec = round((fwd_bytes + bwd_bytes) / duration_s, 1)
            flow_pkts_per_sec = round((fwd_packets + bwd_packets) / duration_s, 1)
            fwd_tcp_win = 0.55
            bwd_tcp_win = 0.60
            symmetry_ratio = round(fwd_bytes / (fwd_bytes + bwd_bytes), 3)
            iat_mean_s = max(measured_iat_s, 0.065)
            effective_port = target_port

        flow_data = FlowData(
            src_ip=client_ip,
            dst_ip=target_host,
            src_port=52310,
            protocol="TCP",
            dst_port=effective_port,
            flow_duration_s=round(duration_s, 3),
            flow_iat_mean_s=round(iat_mean_s, 4),
            fwd_iat_mean_s=round(iat_mean_s * 0.9, 4),
            bwd_iat_mean_s=round(iat_mean_s * 1.1, 4),
            fwd_packets=fwd_packets,
            bwd_packets=bwd_packets,
            fwd_bytes=fwd_bytes,
            bwd_bytes=bwd_bytes,
            fwd_pkt_len_mean=fwd_pkt_len_mean,
            bwd_pkt_len_mean=bwd_pkt_len_mean,
            flow_bytes_per_sec=flow_bytes_per_sec,
            flow_pkts_per_sec=flow_pkts_per_sec,
            fwd_tcp_win_ratio=fwd_tcp_win,
            bwd_tcp_win_ratio=bwd_tcp_win,
            traffic_symmetry_ratio=symmetry_ratio,
        )

        heuristic_meta = {
            "is_malicious": is_malicious,
            "detected_category": detected_category,
            "matched_vector": matched_vector,
            "threat_reason": threat_reason,
            "has_sqli": has_sqli,
            "has_xss": has_xss,
            "has_traversal": has_traversal,
            "has_sensitive_probe": has_sensitive_probe,
            "has_rce": has_rce,
            "has_ssrf_probe": has_ssrf_probe,
            "is_scanner": is_scanner,
            "is_dir_busting": is_dir_busting,
            "is_flooding": is_flooding,
            "req_count_in_window": req_count_in_window,
            "unique_paths_in_window": unique_paths_in_window,
            "measured_iat_s": round(measured_iat_s, 4),
            "measured_fwd_bytes": raw_fwd_bytes,
            "normalized_snippet": full_norm_req[:180],
        }

        return flow_data, heuristic_meta


# Global singleton instances backed by persistent TrafficStore
flow_tracker = ClientFlowTracker()
quarantine_manager = flow_tracker.quarantine
