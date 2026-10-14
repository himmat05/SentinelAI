# SentinelAI - Stage 08: Real-Time Inference Microservice

High-performance, asynchronous REST & WebSocket inference microservice powering SentinelAI's autonomous defense engine.

---

## Architecture Overview

The backend microservice hosts the **3-Tier AI Defense Pipeline** with active **Knob 1 Multi-Tier Synergy**:

```
           Incoming Network Flow
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  Tier 1: Behavioral       Tier 2: Binary
   Anomaly Detector          Gatekeeper
  (Isolation Forest)         (LightGBM)
   [RobustScaler]          [Sub-100 µs]
         │                       │
         └───────────┬───────────┘
                     │
          Threat Detected (Either)?
            ├── No  ──> [VERDICT: ALLOWED] (Clean Normal Traffic)
            └── Yes ──> Tier 3: MITRE Threat Attribution
                             (LightGBM Inverse-Weighted)
                                 │
                         Attributed Category
                         (DDoS, Botnet, Infiltration, etc.)
                                 │
                         Automated Mitigation
                         (QUARANTINE_HOST, DROP_PACKETS, etc.)
                                 │
                         Live WebSocket Broadcast
                         (SOC Security Dashboard)
```

---

## Production Synergy: Knob 1 Active Policy

* **Supervised Gatekeeper (Tier 2)**: Intercepts high-volume, structural, volumetric, and signature attacks at wire speed (sub-100 µs).
* **Unsupervised Anomaly Detector (Tier 1)**: Catches stealthy, low-and-slow zero-day intrusions and internal lateral movement (e.g. SMB `Infiltration`) that blend into normal protocols.
* **Combined Synergy**: Any flow triggering either Tier 2 ($P \ge 0.50$) **OR** Tier 1 (Anomaly Score $\ge 0.0432$) is quarantined and forwarded to Tier 3 for threat attribution and autonomous mitigation.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Service health status, active classes, loaded models |
| `POST` | `/api/predict` | Wire-speed single flow inspection (sub-100 µs) |
| `POST` | `/api/predict/batch` | High-throughput batch flow queue inspection (>600k flows/s) |
| `GET` | `/api/metrics` | Real-time SOC telemetry, block rates, p50/p95 latencies |
| `WS` | `/api/ws/alerts` | Live WebSocket streaming threat alerts to SOC dashboard |

---

## Starting the Server

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive Swagger documentation is available at: `http://localhost:8000/docs`
