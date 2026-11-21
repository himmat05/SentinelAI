/**
 * SentinelAI - Master Application Controller
 * Unifies tabs, live metrics polling, reasoning state, and sub-controllers.
 */

import { SentinelAPI } from "./api.js";
import { FlowInspector } from "./flow_inspector.js";
import { BatchStreamSimulator } from "./batch_stream.js";
import { ThreatIntelController } from "./threat_intel.js";
import { LiveAlertsController } from "./live_alerts.js";
import { LiveMonitorController } from "./live_monitor.js";

class AppState {
  constructor() {
    this.reasoningProvider = "deterministic";
    this.reasoningModel = "gemini-flash-lite-latest";
    this.apiKey = "";
    this.metrics = null;
  }

  getReasoningConfig() {
    return {
      provider: this.reasoningProvider,
      model: this.reasoningModel,
      apiKey: this.apiKey || null
    };
  }
}

class SentinelApp {
  constructor() {
    this.state = new AppState();
    this.init();
  }

  async init() {
    this.initTabs();
    this.initReasoningControls();
    this.initControllers();
    this.startMetricsPolling();
    this.checkHealth();
  }

  initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    const panels = document.querySelectorAll(".tab-panel");

    tabBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        const targetId = btn.dataset.tab;

        tabBtns.forEach(b => b.classList.remove("active"));
        panels.forEach(p => p.classList.remove("active"));

        btn.classList.add("active");
        const targetPanel = document.getElementById(targetId);
        if (targetPanel) targetPanel.classList.add("active");
      });
    });
  }

  initReasoningControls() {
    const provSelect = document.getElementById("reasoning-provider-select");
    const geminiModal = document.getElementById("gemini-config-group");
    const modelSelect = document.getElementById("reasoning-model-select");
    const apiKeyInput = document.getElementById("gemini-api-key-input");

    if (provSelect) {
      provSelect.addEventListener("change", (e) => {
        this.state.reasoningProvider = e.target.value;
        if (geminiModal) {
          geminiModal.style.display = e.target.value === "gemini" ? "flex" : "none";
        }
      });
    }

    if (modelSelect) {
      modelSelect.addEventListener("change", (e) => {
        this.state.reasoningModel = e.target.value;
      });
    }

    if (apiKeyInput) {
      apiKeyInput.addEventListener("input", (e) => {
        this.state.apiKey = e.target.value.trim();
      });
    }
  }

  initControllers() {
    this.flowInspector = new FlowInspector(this.state);
    this.batchSimulator = new BatchStreamSimulator();
    this.threatIntel = new ThreatIntelController(this.state);
    this.liveAlerts = new LiveAlertsController();
    this.liveMonitor = new LiveMonitorController();
  }

  async checkHealth() {
    const health = await SentinelAPI.getHealth();
    const pill = document.getElementById("system-health-pill");
    if (!pill) return;

    if (health && health.status === "ONLINE") {
      pill.innerHTML = `<span class="pulse-dot"></span> SYSTEM ARMED (3-TIER)`;
      pill.style.color = "var(--accent-green)";
    } else {
      pill.innerHTML = `<span class="pulse-dot" style="background-color: var(--accent-red);"></span> ENGINE OFFLINE`;
      pill.style.color = "var(--accent-red)";
    }
  }

  startMetricsPolling() {
    const poll = async () => {
      const data = await SentinelAPI.getMetrics();
      if (data) {
        this.state.metrics = data;
        this.updateKpis(data);
      }
    };

    poll();
    setInterval(poll, 4000);
  }

  updateKpis(m) {
    const setTxt = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setTxt("kpi-total-inspected", (m.total_inspected || 0).toLocaleString());
    setTxt("kpi-threats-blocked", (m.threats_blocked || 0).toLocaleString());
    setTxt("kpi-clean-allowed", (m.clean_allowed || 0).toLocaleString());

    const avgLat = m.avg_latency_us ? `${m.avg_latency_us.toFixed(1)} µs` : "<150 µs";
    setTxt("kpi-avg-latency", avgLat);
  }
}

// Bootstrap on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  window.sentinelApp = new SentinelApp();
});
