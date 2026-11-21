"""
SentinelAI - Persistent Time-Series Traffic Database
===================================================
Lightweight, zero-maintenance SQLite time-series storage for 24/7 continuous
website monitoring, real-time audit trails, and rolling SOC timeline metrics.
"""

import os
import sqlite3
import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../data/traffic.db"))


class TrafficStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        # WAL mode enables blazing fast concurrent reads & writes
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
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
            conn.commit()

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
        timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Record an inspected live network request into time-series storage."""
        if not timestamp:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._get_connection() as conn:
            cur = conn.execute("""
                INSERT INTO traffic_events (
                    timestamp, client_ip, method, path, status_code,
                    latency_ms, bytes_in, bytes_out, verdict,
                    threat_category, confidence_pct, tier1_anomaly,
                    tier2_score, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                timestamp, client_ip, method, path, status_code,
                round(latency_ms, 2), bytes_in, bytes_out, verdict,
                threat_category, round(confidence_pct, 2),
                1 if tier1_anomaly else 0, round(tier2_score, 4),
                details or ""
            ))
            conn.commit()
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
            "details": details or ""
        }

    def get_recent_events(self, limit: int = 50, threat_only: bool = False) -> List[Dict[str, Any]]:
        """Fetch the most recent timestamped traffic events."""
        with self._get_connection() as conn:
            if threat_only:
                cur = conn.execute("""
                    SELECT * FROM traffic_events 
                    WHERE verdict = 'BLOCKED' 
                    ORDER BY id DESC LIMIT ?;
                """, (limit,))
            else:
                cur = conn.execute("""
                    SELECT * FROM traffic_events 
                    ORDER BY id DESC LIMIT ?;
                """, (limit,))
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def get_summary(self) -> Dict[str, Any]:
        """Return rolling aggregate defense metrics."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT 
                    COUNT(*) as total_requests,
                    SUM(CASE WHEN verdict = 'BLOCKED' THEN 1 ELSE 0 END) as threats_blocked,
                    SUM(CASE WHEN verdict = 'ALLOWED' THEN 1 ELSE 0 END) as clean_allowed,
                    AVG(latency_ms) as avg_latency_ms,
                    MAX(timestamp) as last_activity
                FROM traffic_events;
            """).fetchone()

            total = row["total_requests"] or 0
            blocked = row["threats_blocked"] or 0
            clean = row["clean_allowed"] or 0
            avg_lat = row["avg_latency_ms"] or 0.0

            return {
                "total_requests": total,
                "threats_blocked": blocked,
                "clean_allowed": clean,
                "avg_latency_ms": round(avg_lat, 2),
                "last_activity": row["last_activity"],
                "shield_health_pct": round(((clean / total) * 100), 1) if total > 0 else 100.0
            }

    def get_chart_data(self, limit_points: int = 30) -> List[Dict[str, Any]]:
        """Return rolling timeline buckets for real-time frontend charts."""
        with self._get_connection() as conn:
            # Fetch last N events grouped into chronological slots
            cur = conn.execute("""
                SELECT 
                    strftime('%H:%M:%S', timestamp) as time_label,
                    COUNT(*) as count_total,
                    SUM(CASE WHEN verdict = 'BLOCKED' THEN 1 ELSE 0 END) as count_blocked,
                    SUM(CASE WHEN verdict = 'ALLOWED' THEN 1 ELSE 0 END) as count_clean,
                    AVG(latency_ms) as avg_latency
                FROM (
                    SELECT * FROM traffic_events ORDER BY id DESC LIMIT 200
                )
                GROUP BY time_label
                ORDER BY time_label ASC
                LIMIT ?;
            """, (limit_points,))
            rows = cur.fetchall()
            return [
                {
                    "time": r["time_label"],
                    "total": r["count_total"],
                    "clean": r["count_clean"] or 0,
                    "blocked": r["count_blocked"] or 0,
                    "latency": round(r["avg_latency"] or 0, 1)
                }
                for r in rows
            ]

    def clear(self):
        """Purge historical traffic logs."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM traffic_events;")
            conn.commit()


# Global singleton instance
traffic_store = TrafficStore()
