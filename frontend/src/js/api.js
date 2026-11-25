/**
 * SentinelAI - API Client
 * Interfaces with the FastAPI Autonomous Cyber Defense backend.
 */

import { getOperatorHeaders } from "./security_utils.js";

// Determine base API endpoint
const API_BASE = window.location.port === "8000" 
  ? "" 
  : "http://localhost:8000";

const WS_BASE = window.location.port === "8000"
  ? `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}`
  : "ws://localhost:8000";

export class SentinelAPI {
  /**
   * Health and System State check
   */
  static async getHealth() {
    try {
      const res = await fetch(`${API_BASE}/api/health`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn("SentinelAI Health check failed:", e);
      return null;
    }
  }

  /**
   * Real-time SOC Telemetry and Counters
   */
  static async getMetrics() {
    try {
      const res = await fetch(`${API_BASE}/api/metrics`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      console.warn("Metrics fetch failed:", e);
      return null;
    }
  }

  /**
   * Inspect a single network flow in real-time
   */
  static async inspectFlow(flowData, options = {}) {
    const {
      explain = true,
      investigate = true,
      llmProvider = "deterministic",
      llmModel = null,
      apiKey = null
    } = options;

    const params = new URLSearchParams({
      explain: String(explain),
      investigate: String(investigate),
      llm_provider: llmProvider
    });

    if (llmModel) params.append("llm_model", llmModel);
    if (apiKey) params.append("api_key", apiKey);

    const url = `${API_BASE}/api/predict?${params.toString()}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(flowData)
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Inference failed (HTTP ${res.status}): ${errText}`);
    }

    return await res.json();
  }

  /**
   * Inspect batch of flows at line-rate speed
   */
  static async inspectBatch(flows) {
    const res = await fetch(`${API_BASE}/api/predict/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ flows })
    });

    if (!res.ok) throw new Error(`Batch inference failed: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Upload and analyze a classic .pcap packet capture
   */
  static async analyzePcap(file) {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch(`${API_BASE}/api/predict/pcap`, {
      method: "POST",
      headers: getOperatorHeaders(),
      body: formData
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errBody.detail || `PCAP analysis failed (${res.status})`);
    }
    return await res.json();
  }

  /**
   * Semantic Vector Search over ChromaDB 3,774 chunks
   */
  static async searchThreatIntel(query, options = {}) {
    const { category, source, limit = 6 } = options;
    const params = new URLSearchParams({
      q: query,
      limit: String(limit)
    });
    if (category && category !== "ALL") params.append("category", category);
    if (source && source !== "ALL") params.append("source", source);

    const res = await fetch(`${API_BASE}/api/threat-intel/search?${params.toString()}`);
    if (!res.ok) throw new Error(`Search failed: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Standalone incident investigation simulator
   */
  static async investigateAlert(payload) {
    const res = await fetch(`${API_BASE}/api/investigate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error(`Investigation triage failed: ${res.statusText}`);
    return await res.json();
  }

  /**
   * Get stored security alerts
   */
  static async getStoredAlerts(limit = 50) {
    try {
      const res = await fetch(`${API_BASE}/api/alerts?limit=${limit}`);
      if (!res.ok) return [];
      const data = await res.json();
      return data.alerts || [];
    } catch (e) {
      return [];
    }
  }

  /**
   * Live WebSocket Alert Subscriber
   */
  static connectAlertWebSocket(onAlert, onStatusChange) {
    let ws = null;
    let reconnectTimer = null;

    function connect() {
      try {
        ws = new WebSocket(`${WS_BASE}/api/ws/alerts`);
        
        ws.onopen = () => {
          if (onStatusChange) onStatusChange("CONNECTED");
          // Heartbeat ping
          setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send("ping");
            }
          }, 25000);
        };

        ws.onmessage = (event) => {
          if (event.data === "pong") return;
          try {
            const alert = JSON.parse(event.data);
            if (alert.event_type !== "HANDSHAKE" && onAlert) {
              onAlert(alert);
            }
          } catch (e) {
            console.error("Malformed alert WS payload:", event.data);
          }
        };

        ws.onclose = () => {
          if (onStatusChange) onStatusChange("DISCONNECTED");
          reconnectTimer = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          if (onStatusChange) onStatusChange("ERROR");
          ws.close();
        };
      } catch (e) {
        if (onStatusChange) onStatusChange("ERROR");
        reconnectTimer = setTimeout(connect, 4000);
      }
    }

    connect();

    return {
      disconnect: () => {
        if (reconnectTimer) clearTimeout(reconnectTimer);
        if (ws) ws.close();
      }
    };
  }
}
