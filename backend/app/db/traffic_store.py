"""
SentinelAI - Persistent Time-Series & Security State Database
=============================================================
Lightweight, WAL-mode SQLite storage persisting:
  1. Time-series inspected traffic telemetry (traffic_events)
  2. Active Perimeter IP Quarantine Jail (quarantined_ips) with synchronized read cache
  3. Trusted Operator IP Allowlist (ip_allowlist) with synchronized read cache
  4. Reverse Proxy & Shield Configuration (proxy_settings)
"""

import contextlib
import datetime
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set

DEFAULT_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../data/traffic.db"))


class TrafficStore:
    """SQLite persistence layer with synchronized write-through cache for sub-millisecond reads."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("SENTINEL_DB_PATH", DEFAULT_DB_PATH)
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._allowlist_cache: Set[str] = set()
        self._quarantine_cache: Dict[str, Dict[str, Any]] = {}
        self._init_db()
        self._warm_caches()

    @contextlib.contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous = NORMAL;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    bytes_in INTEGER NOT NULL,
                    bytes_out INTEGER NOT NULL,
                    verdict TEXT NOT NULL,
                    threat_category TEXT NOT NULL,
                    confidence_pct REAL NOT NULL,
                    tier1_anomaly INTEGER NOT NULL,
                    tier2_score REAL NOT NULL,
                    details TEXT
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_events(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_verdict ON traffic_events(verdict);")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantined_ips (
                    client_ip TEXT PRIMARY KEY,
                    threat_category TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    banned_at TEXT NOT NULL,
                    expiry REAL NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_expiry ON quarantined_ips(expiry);")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_allowlist (
                    client_ip TEXT PRIMARY KEY,
                    note TEXT DEFAULT '',
                    added_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS proxy_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.commit()
        finally:
            conn.close()

    def _warm_caches(self):
        """Hydrate in-memory allowlist and active quarantine caches from SQLite."""
        now = time.time()
        with self._get_connection() as conn:
            allow_rows = conn.execute("SELECT client_ip FROM ip_allowlist;").fetchall()
            self._allowlist_cache = {r["client_ip"] for r in allow_rows}

            conn.execute("DELETE FROM quarantined_ips WHERE expiry <= ?;", (now,))
            q_rows = conn.execute("SELECT * FROM quarantined_ips;").fetchall()
            self._quarantine_cache = {r["client_ip"]: dict(r) for r in q_rows}

    # ------------------------------------------------------------------
    # Time-Series Traffic Telemetry
    # ------------------------------------------------------------------
    def log_event(
        self,
        client_ip: str,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        bytes_in: int,
        bytes_out: int,
        verdict: str,
        threat_category: str,
        confidence_pct: float,
        tier1_anomaly: bool,
        tier2_score: float,
        details: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an inspected live HTTP flow into persistent SQLite storage."""
        if not timestamp:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO traffic_events (
                    timestamp, client_ip, method, path, status_code,
                    latency_ms, bytes_in, bytes_out, verdict,
                    threat_category, confidence_pct, tier1_anomaly,
                    tier2_score, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    timestamp,
                    client_ip,
                    method,
                    path,
                    status_code,
                    round(latency_ms, 2),
                    bytes_in,
                    bytes_out,
                    verdict,
                    threat_category,
                    round(confidence_pct, 2),
                    1 if tier1_anomaly else 0,
                    round(tier2_score, 4),
                    details or "",
                ),
            )
            event_id = cur.lastrowid

        return {
            "id": event_id,
            "timestamp": timestamp,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "latency_ms": round(latency_ms, 2),
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "verdict": verdict,
            "threat_category": threat_category,
            "confidence_pct": round(confidence_pct, 2),
            "tier1_anomaly": bool(tier1_anomaly),
            "tier2_score": round(tier2_score, 4),
            "details": details or "",
        }

    def get_event_by_id(self, event_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific logged traffic event by primary key ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM traffic_events WHERE id = ?;", (event_id,)).fetchone()
            return dict(row) if row else None

    def get_recent_events(self, limit: int = 50, threat_only: bool = False) -> List[Dict[str, Any]]:
        """Fetch the most recent timestamped traffic events."""
        with self._get_connection() as conn:
            if threat_only:
                cur = conn.execute(
                    """
                    SELECT * FROM traffic_events
                    WHERE verdict IN ('BLOCKED', 'QUARANTINED', 'SHADOW_BLOCKED')
                    ORDER BY id DESC LIMIT ?;
                    """,
                    (limit,),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM traffic_events ORDER BY id DESC LIMIT ?;",
                    (limit,),
                )
            return [dict(r) for r in cur.fetchall()]

    def get_summary(self) -> Dict[str, Any]:
        """Return rolling aggregate defense metrics."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*) as total_requests,
                    SUM(CASE WHEN verdict IN ('BLOCKED', 'QUARANTINED') THEN 1 ELSE 0 END) as threats_blocked,
                    SUM(CASE WHEN verdict = 'SHADOW_BLOCKED' THEN 1 ELSE 0 END) as shadow_detections,
                    SUM(CASE WHEN verdict = 'ALLOWED' THEN 1 ELSE 0 END) as clean_allowed,
                    AVG(latency_ms) as avg_latency_ms,
                    MAX(timestamp) as last_activity
                FROM traffic_events;
            """).fetchone()

            total = row["total_requests"] or 0
            blocked = row["threats_blocked"] or 0
            shadow = row["shadow_detections"] or 0
            clean = row["clean_allowed"] or 0
            avg_lat = row["avg_latency_ms"] or 0.0

            return {
                "total_requests": total,
                "threats_blocked": blocked,
                "shadow_detections": shadow,
                "clean_allowed": clean,
                "avg_latency_ms": round(avg_lat, 2),
                "last_activity": row["last_activity"],
                "shield_health_pct": round(((clean / total) * 100), 1) if total > 0 else 100.0,
            }

    def get_chart_data(self, limit_points: int = 30) -> List[Dict[str, Any]]:
        """Return rolling timeline buckets for real-time frontend charts."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT
                    strftime('%H:%M:%S', timestamp) as time_label,
                    COUNT(*) as count_total,
                    SUM(CASE WHEN verdict IN ('BLOCKED', 'QUARANTINED', 'SHADOW_BLOCKED') THEN 1 ELSE 0 END) as count_blocked,
                    SUM(CASE WHEN verdict = 'ALLOWED' THEN 1 ELSE 0 END) as count_clean,
                    AVG(latency_ms) as avg_latency
                FROM (
                    SELECT * FROM traffic_events ORDER BY id DESC LIMIT 200
                )
                GROUP BY time_label
                ORDER BY time_label ASC
                LIMIT ?;
                """,
                (limit_points,),
            )
            return [
                {
                    "time": r["time_label"],
                    "total": r["count_total"],
                    "clean": r["count_clean"] or 0,
                    "blocked": r["count_blocked"] or 0,
                    "latency": round(r["avg_latency"] or 0, 1),
                }
                for r in cur.fetchall()
            ]

    def clear(self):
        """Purge historical traffic logs."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM traffic_events;")

    # ------------------------------------------------------------------
    # Persistent IP Quarantine Jail (Write-Through Cache)
    # ------------------------------------------------------------------
    def upsert_quarantine(
        self,
        client_ip: str,
        threat_category: str,
        reason: str,
        banned_at: str,
        expiry: float,
        duration_seconds: int,
    ):
        """Persist or extend an attacker IP ban in SQLite and update read cache."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO quarantined_ips (client_ip, threat_category, reason, banned_at, expiry, duration_seconds, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(client_ip) DO UPDATE SET
                    threat_category = excluded.threat_category,
                    reason = excluded.reason,
                    banned_at = excluded.banned_at,
                    expiry = excluded.expiry,
                    duration_seconds = excluded.duration_seconds,
                    hit_count = quarantined_ips.hit_count + 1;
                """,
                (client_ip, threat_category, reason, banned_at, expiry, duration_seconds),
            )
        prev = self._quarantine_cache.get(client_ip)
        self._quarantine_cache[client_ip] = {
            "client_ip": client_ip,
            "threat_category": threat_category,
            "reason": reason,
            "banned_at": banned_at,
            "expiry": expiry,
            "duration_seconds": duration_seconds,
            "hit_count": (prev.get("hit_count", 0) + 1) if prev else 1,
        }

    def get_quarantine(self, client_ip: str) -> Optional[Dict[str, Any]]:
        """O(1) cached active quarantine check with automatic expiry pruning."""
        record = self._quarantine_cache.get(client_ip)
        if not record:
            return None
        now = time.time()
        if now >= record["expiry"]:
            self.remove_quarantine(client_ip)
            return None
        return {**record, "remaining_seconds": max(1, int(record["expiry"] - now))}

    def increment_quarantine_hit(self, client_ip: str):
        """Increment perimeter drop hit count in cache & SQLite."""
        if client_ip in self._quarantine_cache:
            self._quarantine_cache[client_ip]["hit_count"] = self._quarantine_cache[client_ip].get("hit_count", 1) + 1
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE quarantined_ips SET hit_count = hit_count + 1 WHERE client_ip = ?;",
                (client_ip,),
            )

    def remove_quarantine(self, client_ip: str) -> bool:
        """Unban an IP from cache and persistent storage."""
        self._quarantine_cache.pop(client_ip, None)
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM quarantined_ips WHERE client_ip = ?;", (client_ip,))
            return cur.rowcount > 0

    def list_active_quarantines(self) -> List[Dict[str, Any]]:
        """Purge expired entries and return all currently banned IPs."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute("DELETE FROM quarantined_ips WHERE expiry <= ?;", (now,))
            rows = conn.execute("SELECT * FROM quarantined_ips ORDER BY expiry DESC;").fetchall()
            results = []
            fresh_cache: Dict[str, Dict[str, Any]] = {}
            for r in rows:
                d = dict(r)
                fresh_cache[d["client_ip"]] = d
                results.append({**d, "remaining_seconds": max(1, int(d["expiry"] - now))})
            self._quarantine_cache = fresh_cache
            return results

    # ------------------------------------------------------------------
    # Persistent Trusted IP Allowlist (Write-Through Cache)
    # ------------------------------------------------------------------
    def add_allowlist_ip(self, client_ip: str, note: str = "") -> Dict[str, Any]:
        """Add or update an IP in the operator allowlist."""
        added_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO ip_allowlist (client_ip, note, added_at)
                VALUES (?, ?, ?)
                ON CONFLICT(client_ip) DO UPDATE SET note = excluded.note, added_at = excluded.added_at;
                """,
                (client_ip, note, added_at),
            )
            conn.execute("DELETE FROM quarantined_ips WHERE client_ip = ?;", (client_ip,))
        self._allowlist_cache.add(client_ip)
        self._quarantine_cache.pop(client_ip, None)
        return {"client_ip": client_ip, "note": note, "added_at": added_at}

    def remove_allowlist_ip(self, client_ip: str) -> bool:
        self._allowlist_cache.discard(client_ip)
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM ip_allowlist WHERE client_ip = ?;", (client_ip,))
            return cur.rowcount > 0

    def is_ip_allowlisted(self, client_ip: str) -> bool:
        return client_ip in self._allowlist_cache

    def list_allowlist_ips(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM ip_allowlist ORDER BY added_at DESC;").fetchall()
            self._allowlist_cache = {r["client_ip"] for r in rows}
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Persistent Proxy & Shield Settings
    # ------------------------------------------------------------------
    def set_setting(self, key: str, value: str):
        updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO proxy_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
                """,
                (key, str(value), updated_at),
            )

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT value FROM proxy_settings WHERE key = ?;", (key,)).fetchone()
            return row["value"] if row else default

    def get_all_settings(self) -> Dict[str, str]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT key, value FROM proxy_settings;").fetchall()
            return {r["key"]: r["value"] for r in rows}


# Global singleton instance
traffic_store = TrafficStore()
