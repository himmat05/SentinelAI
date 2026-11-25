/**
 * SentinelAI - Live WebSocket Threat Alert Stream & Telemetry
 */

import { SentinelAPI } from "./api.js";
import { escapeHtml } from "./security_utils.js";

export class LiveAlertsController {
  constructor() {
    this.alerts = [];
    this.maxAlerts = 50;
    this.init();
  }

  init() {
    this.loadInitialAlerts();
    this.connectWebSocket();
  }

  async loadInitialAlerts() {
    const historical = await SentinelAPI.getStoredAlerts(20);
    this.alerts = historical;
    this.renderAlertFeed();
  }

  connectWebSocket() {
    const statusPill = document.getElementById("ws-connection-status");

    SentinelAPI.connectAlertWebSocket(
      (newAlert) => {
        this.addAlert(newAlert);
      },
      (status) => {
        if (!statusPill) return;
        if (status === "CONNECTED") {
          statusPill.innerHTML = `<span class="pulse-dot"></span> LIVE BROADCAST ARMED`;
          statusPill.style.color = "var(--accent-green)";
        } else {
          statusPill.innerHTML = `<span class="pulse-dot" style="background-color: var(--accent-amber);"></span> RECONNECTING...`;
          statusPill.style.color = "var(--accent-amber)";
        }
      }
    );
  }

  addAlert(alert) {
    this.alerts.unshift(alert);
    if (this.alerts.length > this.maxAlerts) {
      this.alerts.pop();
    }
    this.renderAlertFeed();
    this.triggerAlertPulse();
  }

  triggerAlertPulse() {
    const banner = document.getElementById("soc-navbar");
    if (banner) {
      banner.style.boxShadow = "0 0 35px rgba(239, 68, 68, 0.4)";
      setTimeout(() => {
        banner.style.boxShadow = "none";
      }, 800);
    }
  }

  renderAlertFeed() {
    const tableBody = document.getElementById("live-alert-rows");
    const countEl = document.getElementById("live-alert-count");
    if (!tableBody) return;

    if (countEl) countEl.textContent = String(this.alerts.length);

    if (this.alerts.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">
            Awaiting live telemetry... Trigger an attack in Flow Inspector, Batch Stream, or 24/7 Website Shield.
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = this.alerts.map(a => {
      const isCrit = a.severity === "CRITICAL";
      const timeStr = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
      return `
        <tr class="alert-feed-row">
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(timeStr)}</td>
          <td><span class="tier-badge ${isCrit ? 'alert' : 'ok'}">${escapeHtml(a.severity || 'HIGH')}</span></td>
          <td><b style="color: var(--accent-red);">${escapeHtml(a.threat_category || 'Attack')}</b></td>
          <td style="font-family: var(--font-mono);">${escapeHtml(a.src_ip || 'N/A')}</td>
          <td style="font-family: var(--font-mono);">${escapeHtml(a.dst_ip || '0.0.0.0')}:${escapeHtml(a.dst_port ?? '')}</td>
          <td><code>${escapeHtml(a.mitigation_action || 'DROP_PACKETS')}</code></td>
        </tr>
      `;
    }).join("");
  }
}
