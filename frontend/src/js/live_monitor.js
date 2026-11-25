/**
 * SentinelAI - 24/7 Live Website Monitor, Active WAF & Ops Controller
 * Drives persistent telemetry, Shadow/Enforce switching, XSS-safe rendering,
 * IP quarantine/allowlist management, firewall rule export, webhooks, and RAG briefs.
 */

import {
  escapeHtml,
  getOperatorHeaders,
  getOperatorToken,
  setOperatorToken,
  showToast
} from "./security_utils.js";

export class LiveMonitorController {
  constructor() {
    this.pollInterval = null;
    this.targetUrl = "https://aai-ji-honey.vercel.app";
    this.shieldMode = "enforce";
    this.heartbeatActive = false;
    this.lastIncidentMarkdown = "";
    this.lastIncidentId = "incident-report";
    this.init();
  }

  init() {
    this.bindEvents();
    this.loadConfig();
    this.checkAuthStatus();
    this.refreshData();
    this.pollInterval = setInterval(() => this.refreshData(), 2500);
  }

  bindEvents() {
    const bind = (id, event, fn) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener(event, fn);
    };

    bind("btn-save-target-url", "click", () => this.saveTargetUrl());
    bind("monitor-shield-mode-select", "change", (e) => this.updateShieldMode(e.target.value));
    bind("btn-toggle-heartbeat", "click", () => this.toggleHeartbeat());
    bind("btn-test-clean-traffic", "click", () => this.testCleanTraffic());
    bind("btn-clear-traffic-logs", "click", () => this.clearLogs());

    // Operator Token Management
    const tokenInput = document.getElementById("monitor-operator-token-input");
    if (tokenInput) {
      tokenInput.value = getOperatorToken();
    }
    bind("btn-save-operator-token", "click", () => {
      const val = document.getElementById("monitor-operator-token-input")?.value || "";
      setOperatorToken(val);
      this.checkAuthStatus();
      showToast("Operator Token Updated", val ? "Stored in sessionStorage for admin API requests." : "Cleared operator token.", "info");
    });

    // Webhook Configuration
    bind("btn-save-webhook", "click", () => this.saveWebhookConfig());
    bind("btn-test-webhook", "click", () => this.testWebhook());

    // IP Allowlist
    bind("btn-add-allowlist", "click", () => this.addAllowlistIp());
    bind("monitor-allowlist-tbody", "click", (e) => {
      const btn = e.target.closest(".btn-remove-allowlist");
      if (btn) this.removeAllowlistIp(btn.dataset.ip);
    });

    // Firewall / WAF Rule Exports
    bind("btn-export-nginx", "click", () => this.exportRules("nginx"));
    bind("btn-export-iptables", "click", () => this.exportRules("iptables"));
    bind("btn-export-cloudflare", "click", () => this.exportRules("cloudflare"));
    bind("btn-copy-rules", "click", () => {
      const code = document.getElementById("rules-export-code")?.textContent || "";
      navigator.clipboard?.writeText(code);
      showToast("Copied to Clipboard", "Firewall rules ready to paste into edge config.", "success");
    });
    bind("btn-close-rules", "click", () => {
      const box = document.getElementById("rules-export-preview-box");
      if (box) box.style.display = "none";
    });

    // Multi-Vector Attack Simulators
    document.querySelectorAll(".btn-sim-attack").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const type = e.currentTarget.dataset.type || "sqli";
        this.simulateAttack(type, e.currentTarget);
      });
    });

    // Quarantine Jail Actions (Unban / Allowlist)
    bind("monitor-quarantine-tbody", "click", (e) => {
      const unbanBtn = e.target.closest(".btn-unban-ip");
      if (unbanBtn) {
        this.unbanIp(unbanBtn.dataset.ip);
        return;
      }
      const allowBtn = e.target.closest(".btn-jail-allowlist");
      if (allowBtn) {
        this.quickAllowlist(allowBtn.dataset.ip);
      }
    });

    // Traffic Feed -> Investigate with RAG
    bind("monitor-logs-tbody", "click", (e) => {
      const btn = e.target.closest(".btn-investigate-event");
      if (btn) {
        this.investigateTrafficEvent(btn.dataset.eventId, btn);
      }
    });

    // Incident Modal Controls
    bind("btn-close-incident-modal", "click", () => {
      const modal = document.getElementById("monitor-incident-modal");
      if (modal) modal.style.display = "none";
    });
    bind("btn-download-incident-md", "click", () => this.downloadIncidentMarkdown());
  }

  async _apiJson(url, options = {}) {
    const mergedHeaders = getOperatorHeaders(options.headers || {});
    const res = await fetch(url, { ...options, headers: mergedHeaders });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.detail || `HTTP ${res.status} Error`);
    }
    return data;
  }

  async checkAuthStatus() {
    try {
      const data = await this._apiJson("/api/monitoring/auth-status");
      const badge = document.getElementById("monitor-auth-status-badge");
      if (!badge) return;

      if (data.authenticated) {
        badge.textContent = data.mode === "token" ? "🔐 TOKEN VERIFIED" : "🔓 LOCALHOST DEV";
        badge.style.color = "var(--accent-green)";
        badge.style.borderColor = "rgba(16, 185, 129, 0.4)";
      } else {
        badge.textContent = "🔒 OPERATOR TOKEN REQUIRED";
        badge.style.color = "var(--accent-red)";
        badge.style.borderColor = "rgba(239, 68, 68, 0.4)";
      }
    } catch {
      // ignore
    }
  }

  async loadConfig() {
    try {
      const data = await this._apiJson("/api/monitoring/config");
      this.targetUrl = data.target_url;
      this.shieldMode = data.shield_mode || "enforce";
      this.heartbeatActive = data.heartbeat_active;

      const input = document.getElementById("monitor-target-url-input");
      if (input) input.value = this.targetUrl;

      const modeSelect = document.getElementById("monitor-shield-mode-select");
      if (modeSelect) modeSelect.value = this.shieldMode;

      const gwInput = document.getElementById("monitor-gateway-url-input");
      if (gwInput) gwInput.value = `${window.location.origin}/gateway/`;

      const gwLink = document.getElementById("monitor-gateway-link");
      if (gwLink) gwLink.href = `${window.location.origin}/gateway/`;

      const whCheck = document.getElementById("monitor-webhook-enabled-checkbox");
      if (whCheck) whCheck.checked = Boolean(data.webhook_enabled);

      const whInput = document.getElementById("monitor-webhook-url-input");
      if (whInput && data.webhook_configured && !whInput.value) {
        whInput.placeholder = `Configured: ${data.webhook_preview}`;
      }

      this._updateStatusBadge();

      const hbBtn = document.getElementById("btn-toggle-heartbeat");
      if (hbBtn) {
        hbBtn.textContent = this.heartbeatActive ? "⏹️ Stop 24/7 Heartbeat" : "▶️ Start 24/7 Heartbeat";
        hbBtn.className = this.heartbeatActive ? "btn-cyber btn-cyber-amber" : "btn-cyber";
      }
    } catch (err) {
      console.warn("Could not load monitoring config:", err);
    }
  }

  _updateStatusBadge() {
    const badge = document.getElementById("monitor-shield-status-badge");
    if (!badge) return;
    const isShadow = this.shieldMode === "shadow";
    badge.innerHTML = `<span class="pulse-dot" style="background:${isShadow ? '#f59e0b' : '#10b981'};"></span> ${isShadow ? 'SHADOW AUDIT' : 'ENFORCING'}: ${escapeHtml(this.targetUrl)}`;
    badge.style.color = isShadow ? "#fbbf24" : "var(--accent-green)";
  }

  async saveTargetUrl() {
    const val = document.getElementById("monitor-target-url-input")?.value.trim();
    if (!val) return;
    try {
      const data = await this._apiJson("/api/monitoring/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: val })
      });
      this.targetUrl = data.config.target_url;
      this._updateStatusBadge();
      showToast("Target Saved", `Now protecting ${this.targetUrl} (persisted in SQLite).`, "success");
    } catch (err) {
      showToast("Target Rejected", err.message, "error");
    }
  }

  async updateShieldMode(mode) {
    try {
      const data = await this._apiJson("/api/monitoring/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ shield_mode: mode })
      });
      this.shieldMode = data.config.shield_mode;
      this._updateStatusBadge();
      showToast(
        `Shield Mode: ${this.shieldMode.toUpperCase()}`,
        this.shieldMode === "shadow"
          ? "Shadow mode logs attacks silently without blocking visitors."
          : "Enforce mode actively returns 403 and quarantines attackers.",
        this.shieldMode === "shadow" ? "warning" : "success"
      );
    } catch (err) {
      showToast("Mode Update Failed", err.message, "error");
    }
  }

  async saveWebhookConfig() {
    const webhookUrl = document.getElementById("monitor-webhook-url-input")?.value.trim();
    const webhookEnabled = Boolean(document.getElementById("monitor-webhook-enabled-checkbox")?.checked);
    const payload = { webhook_enabled: webhookEnabled };
    if (webhookUrl) payload.webhook_url = webhookUrl;

    try {
      await this._apiJson("/api/monitoring/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      showToast("Webhook Settings Saved", webhookEnabled ? "Active alerting armed." : "Webhook alerts disabled.", "success");
    } catch (err) {
      showToast("Webhook Rejected", err.message, "error");
    }
  }

  async testWebhook() {
    try {
      const res = await this._apiJson("/api/monitoring/webhook/test", { method: "POST" });
      if (res.sent) {
        showToast("Webhook Delivered", `HTTP ${res.status_code} accepted by endpoint.`, "success");
      } else {
        showToast("Webhook Not Sent", res.reason || "Check URL configuration.", "warning");
      }
    } catch (err) {
      showToast("Webhook Test Failed", err.message, "error");
    }
  }

  async toggleHeartbeat() {
    try {
      const data = await this._apiJson("/api/monitoring/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ heartbeat_active: !this.heartbeatActive })
      });
      this.heartbeatActive = data.config.heartbeat_active;
      const hbBtn = document.getElementById("btn-toggle-heartbeat");
      if (hbBtn) {
        hbBtn.textContent = this.heartbeatActive ? "⏹️ Stop 24/7 Heartbeat" : "▶️ Start 24/7 Heartbeat";
        hbBtn.className = this.heartbeatActive ? "btn-cyber btn-cyber-amber" : "btn-cyber";
      }
      showToast("24/7 Heartbeat", this.heartbeatActive ? "Periodic upstream probing started." : "Heartbeat paused.", "info");
    } catch (err) {
      showToast("Heartbeat Toggle Failed", err.message, "error");
    }
  }

  async testCleanTraffic() {
    const btn = document.getElementById("btn-test-clean-traffic");
    const old = btn.innerHTML;
    btn.innerHTML = `<span class="pulse-dot"></span> Proxying...`;
    btn.disabled = true;

    try {
      const data = await this._apiJson("/api/monitoring/test-clean", { method: "POST" });
      await this.refreshData();
      showToast("Clean Visit Allowed", `${data.message} (${data.bytes_received} bytes)`, "success");
    } catch (err) {
      showToast("Clean Proxy Error", err.message, "error");
    } finally {
      btn.innerHTML = old;
      btn.disabled = false;
    }
  }

  async simulateAttack(attackType = "sqli", triggerBtn = null) {
    const old = triggerBtn ? triggerBtn.innerHTML : null;
    if (triggerBtn) {
      triggerBtn.innerHTML = `<span class="pulse-dot"></span> Probing...`;
      triggerBtn.disabled = true;
    }

    try {
      const data = await this._apiJson(
        `/api/monitoring/simulate-attack?attack_type=${encodeURIComponent(attackType)}`,
        { method: "POST" }
      );
      await this.refreshData();
      showToast(
        data.blocked ? "Intrusion Intercepted (403)" : "Shadow Detection Logged",
        `Vector: [${attackType.toUpperCase()}]\n${data.message}`,
        data.blocked ? "error" : "warning"
      );
    } catch (err) {
      showToast("Attack Simulation Failed", err.message, "error");
    } finally {
      if (triggerBtn) {
        triggerBtn.innerHTML = old;
        triggerBtn.disabled = false;
      }
    }
  }

  async unbanIp(ip) {
    if (!ip) return;
    try {
      const data = await this._apiJson("/api/monitoring/quarantine/unban", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_ip: ip })
      });
      await this.refreshData();
      showToast("IP Released", data.message, "success");
    } catch (err) {
      showToast("Unban Failed", err.message, "error");
    }
  }

  async quickAllowlist(ip) {
    if (!ip) return;
    try {
      await this._apiJson("/api/monitoring/allowlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_ip: ip, note: "Promoted from Quarantine UI" })
      });
      await this.refreshData();
      showToast("IP Allowlisted", `${ip} released from jail and added to trusted allowlist.`, "success");
    } catch (err) {
      showToast("Allowlist Error", err.message, "error");
    }
  }

  async addAllowlistIp() {
    const ipEl = document.getElementById("allowlist-ip-input");
    const noteEl = document.getElementById("allowlist-note-input");
    const ip = ipEl?.value.trim();
    const note = noteEl?.value.trim() || "Trusted Operator IP";
    if (!ip) return;

    try {
      await this._apiJson("/api/monitoring/allowlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_ip: ip, note })
      });
      if (ipEl) ipEl.value = "";
      await this.refreshData();
      showToast("Trusted IP Added", `${ip} will bypass quarantine & WAF drops.`, "success");
    } catch (err) {
      showToast("Allowlist Error", err.message, "error");
    }
  }

  async removeAllowlistIp(ip) {
    if (!ip) return;
    try {
      await this._apiJson(`/api/monitoring/allowlist/${encodeURIComponent(ip)}`, { method: "DELETE" });
      await this.refreshData();
      showToast("Allowlist Updated", `Removed ${ip} from trusted allowlist.`, "info");
    } catch (err) {
      showToast("Remove Failed", err.message, "error");
    }
  }

  async exportRules(format) {
    try {
      const headers = getOperatorHeaders();
      const res = await fetch(`/api/monitoring/export-rules?format=${encodeURIComponent(format)}`, { headers });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      let outputText = "";
      if (format === "cloudflare") {
        const json = await res.json();
        outputText = JSON.stringify(json, null, 2);
      } else {
        outputText = await res.text();
      }
      const box = document.getElementById("rules-export-preview-box");
      const code = document.getElementById("rules-export-code");
      if (box && code) {
        code.textContent = outputText;
        box.style.display = "block";
      }
      showToast("Firewall Rules Generated", `Prepared ${format.toUpperCase()} block rules for active bans.`, "info");
    } catch (err) {
      showToast("Export Failed", err.message, "error");
    }
  }

  async investigateTrafficEvent(eventId, btn) {
    const oldText = btn.textContent;
    btn.textContent = "⏳...";
    btn.disabled = true;

    try {
      const report = await this._apiJson(`/api/monitoring/investigate-event/${encodeURIComponent(eventId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ llm_provider: "deterministic" })
      });
      this.lastIncidentMarkdown = report.markdown_brief || "";
      this.lastIncidentId = report.incident_id || `event-${eventId}`;
      this._showIncidentModal(report);
    } catch (err) {
      showToast("RAG Investigation Failed", err.message, "error");
    } finally {
      btn.textContent = oldText;
      btn.disabled = false;
    }
  }

  _showIncidentModal(rep) {
    const modal = document.getElementById("monitor-incident-modal");
    const body = document.getElementById("monitor-incident-body");
    if (!modal || !body) return;

    const containment = rep.immediate_containment || {};
    const reasoning = rep.reasoning || {};
    const attributions = rep.mitre_attribution || [];
    const playbooks = rep.recommended_playbooks || [];

    body.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
        <span style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan);">${escapeHtml(rep.incident_id)}</span>
        <span class="tier-badge alert">${escapeHtml(rep.severity)} — ${escapeHtml(rep.threat_family)}</span>
      </div>
      <div style="background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.35); padding:0.75rem; border-radius:8px; margin-bottom:1rem;">
        <b style="color:#fca5a5;">Containment Policy (${escapeHtml(containment.action)}):</b>
        <div style="font-size:0.82rem; color:var(--text-secondary); margin-top:4px;">${escapeHtml(containment.description)}</div>
      </div>
      <div style="margin-bottom:0.9rem;">
        <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Attack Narrative</div>
        <p style="font-size:0.84rem; line-height:1.5; color:var(--text-primary);">${escapeHtml(reasoning.narrative || "")}</p>
      </div>
      <div style="margin-bottom:0.9rem;">
        <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">MITRE ATT&amp;CK / CISA Correlation</div>
        <ul style="font-size:0.8rem; padding-left:1.25rem; color:var(--text-secondary);">
          ${attributions.map(a => `<li><b>${escapeHtml(a.identifier)}</b>: ${escapeHtml(a.title)} (${escapeHtml(a.source)})</li>`).join("") || "<li>No direct TTP matches.</li>"}
        </ul>
      </div>
      <div>
        <div style="font-size:0.72rem; text-transform:uppercase; color:var(--text-muted); font-weight:700;">OWASP / SOC Mitigation Playbooks</div>
        ${playbooks.map(pb => `
          <div style="margin-top:0.5rem; padding:0.6rem; background:rgba(15,23,42,0.8); border:1px solid var(--border-subtle); border-radius:6px; font-size:0.78rem;">
            <b style="color:var(--accent-cyan);">[${escapeHtml((pb.source || "").toUpperCase())}] ${escapeHtml(pb.title)}</b>
            <div style="color:var(--text-secondary); margin-top:3px;">${escapeHtml(pb.guidance)}</div>
          </div>
        `).join("")}
      </div>
    `;
    modal.style.display = "flex";
  }

  downloadIncidentMarkdown() {
    if (!this.lastIncidentMarkdown) return;
    const blob = new Blob([this.lastIncidentMarkdown], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${this.lastIncidentId}.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async clearLogs() {
    try {
      await this._apiJson("/api/monitoring/clear-logs", { method: "POST" });
      await this.refreshData();
      showToast("Telemetry Cleared", "Traffic event history purged.", "info");
    } catch (err) {
      showToast("Clear Failed", err.message, "error");
    }
  }

  async refreshData() {
    try {
      const [statsRes, chartRes, logsRes, qRes, allowRes] = await Promise.all([
        fetch("/api/monitoring/stats"),
        fetch("/api/monitoring/chart?points=25"),
        fetch("/api/monitoring/logs?limit=30"),
        fetch("/api/monitoring/quarantine"),
        fetch("/api/monitoring/allowlist")
      ]);

      if (statsRes.ok) this.updateStatsUI(await statsRes.json());
      if (chartRes.ok) {
        const c = await chartRes.json();
        this.renderChart(c.points || []);
      }
      if (logsRes.ok) {
        const l = await logsRes.json();
        this.renderLogsTable(l.logs || []);
      }
      if (qRes.ok) {
        const q = await qRes.json();
        this.renderQuarantineTable(q.quarantined_ips || []);
      }
      if (allowRes.ok) {
        const a = await allowRes.json();
        this.renderAllowlistTable(a.allowlist || []);
      }
    } catch {
      // Quiet background poll tolerance
    }
  }

  updateStatsUI(s) {
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setVal("stat-mon-total", s.total_requests || 0);
    setVal("stat-mon-clean", s.clean_allowed || 0);
    setVal("stat-mon-blocked", s.threats_blocked || 0);
    setVal("stat-mon-shadow", s.shadow_detections || 0);
    setVal("stat-mon-latency", `${s.avg_latency_ms || 0} ms`);
    setVal("stat-mon-health", `${s.shield_health_pct ?? 100}%`);
  }

  renderQuarantineTable(bans) {
    const tbody = document.getElementById("monitor-quarantine-tbody");
    const badge = document.getElementById("quarantine-count-badge");
    if (badge) {
      badge.textContent = `${bans.length} QUARANTINED ${bans.length === 1 ? "IP" : "IPS"}`;
      badge.style.color = bans.length > 0 ? "var(--accent-red)" : "#fbbf24";
      badge.style.borderColor = bans.length > 0 ? "rgba(239, 68, 68, 0.4)" : "rgba(245, 158, 11, 0.4)";
    }
    if (!tbody) return;

    if (bans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.25rem;">No IP sockets currently quarantined. Perimeter clear.</td></tr>`;
      return;
    }

    tbody.innerHTML = bans.map(b => {
      const remainingMin = Math.ceil(b.remaining_seconds / 60);
      return `
        <tr>
          <td><span style="font-family: var(--font-mono); font-weight: 700; color: #f87171;">${escapeHtml(b.client_ip)}</span></td>
          <td><span class="tier-badge alert">${escapeHtml(b.threat_category)}</span></td>
          <td style="font-size: 0.8rem; color: var(--text-muted); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(b.reason)}">
            ${escapeHtml(b.reason)}
          </td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(b.banned_at || "--")}</td>
          <td>
            <span style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: bold; color: #fbbf24;">
              ⏳ ${escapeHtml(b.remaining_seconds)}s (~${remainingMin}m) · Hits: ${escapeHtml(b.hit_count || 1)}
            </span>
          </td>
          <td style="text-align: right; white-space: nowrap;">
            <button class="btn-cyber btn-unban-ip" data-ip="${escapeHtml(b.client_ip)}" style="font-size: 0.72rem; padding: 0.25rem 0.6rem; color: #6ee7b7; border-color: rgba(16, 185, 129, 0.4);">
              🔓 Unban
            </button>
            <button class="btn-cyber btn-jail-allowlist" data-ip="${escapeHtml(b.client_ip)}" style="font-size: 0.72rem; padding: 0.25rem 0.6rem; color: #93c5fd; border-color: rgba(59, 130, 246, 0.4);">
              ✅ Trust
            </button>
          </td>
        </tr>
      `;
    }).join("");
  }

  renderAllowlistTable(items) {
    const tbody = document.getElementById("monitor-allowlist-tbody");
    if (!tbody) return;
    if (items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 0.85rem;">No allowlisted IPs configured.</td></tr>`;
      return;
    }

    tbody.innerHTML = items.map(item => `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);">${escapeHtml(item.client_ip)}</td>
        <td style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(item.note)}</td>
        <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(item.added_at)}</td>
        <td style="text-align: right;">
          <button class="btn-cyber btn-remove-allowlist" data-ip="${escapeHtml(item.client_ip)}" style="font-size: 0.7rem; padding: 0.2rem 0.55rem; color: #fca5a5;">
            Remove
          </button>
        </td>
      </tr>
    `).join("");
  }

  renderChart(points) {
    const canvas = document.getElementById("live-traffic-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const w = canvas.width = canvas.parentElement.clientWidth || 800;
    const h = canvas.height = 200;

    ctx.clearRect(0, 0, w, h);

    if (points.length < 2) {
      ctx.fillStyle = "#64748b";
      ctx.font = "12px sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("Waiting for incoming website traffic to populate timeline...", w / 2, h / 2);
      return;
    }

    const padding = 30;
    const drawW = w - padding * 2;
    const drawH = h - padding * 2;
    const maxVal = Math.max(...points.map(p => Math.max(p.clean, p.blocked, p.total)), 5);

    const getX = (idx) => padding + (idx / (points.length - 1)) * drawW;
    const getY = (val) => h - padding - (val / maxVal) * drawH;

    ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padding + (i / 4) * drawH;
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(w - padding, y);
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.strokeStyle = "#10b981";
    ctx.lineWidth = 2.5;
    points.forEach((p, idx) => {
      const x = getX(idx);
      const y = getY(p.clean);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.beginPath();
    ctx.strokeStyle = "#ef4444";
    ctx.lineWidth = 2.5;
    points.forEach((p, idx) => {
      const x = getX(idx);
      const y = getY(p.blocked);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    ctx.font = "10px monospace";
    ctx.fillStyle = "#64748b";
    ctx.textAlign = "center";
    const step = Math.max(Math.floor(points.length / 6), 1);
    points.forEach((p, idx) => {
      const x = getX(idx);
      if (idx % step === 0 || idx === points.length - 1) {
        ctx.fillText(p.time || "", x, h - 8);
      }
    });
  }

  renderLogsTable(logs) {
    const tbody = document.getElementById("monitor-logs-tbody");
    if (!tbody) return;

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No traffic logged yet. Click "Test Clean Visit" or simulate an attack above.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const isBlocked = l.verdict === "BLOCKED" || l.verdict === "QUARANTINED";
      const isShadow = l.verdict === "SHADOW_BLOCKED";
      const timeStr = l.timestamp ? l.timestamp.split("T")[1].slice(0, 8) : "--:--:--";
      const statusColor = l.status_code === 200 ? "var(--accent-green)" : (l.status_code === 403 ? "var(--accent-red)" : "var(--accent-amber)");

      let verdictBadge = `<span class="tier-badge ok">🛡️ CLEAN</span>`;
      if (isBlocked) {
        verdictBadge = `<span class="tier-badge alert">🚨 ${escapeHtml(l.threat_category)}</span>`;
      } else if (isShadow) {
        verdictBadge = `<span class="tier-badge" style="background:rgba(245,158,11,0.18); color:#fbbf24; border:1px solid rgba(245,158,11,0.4);">👁️ SHADOW: ${escapeHtml(l.threat_category)}</span>`;
      }

      const triageBtn = (isBlocked || isShadow)
        ? `<button class="btn-cyber btn-investigate-event" data-event-id="${escapeHtml(l.id)}" style="font-size:0.7rem; padding:0.2rem 0.55rem; color:var(--accent-cyan); border-color:rgba(56,189,248,0.4);">🔍 Brief</button>`
        : `<span style="color:var(--text-muted); font-size:0.72rem;">—</span>`;

      return `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(timeStr)}</td>
          <td><span style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary);">${escapeHtml(l.client_ip)}</span></td>
          <td><span class="tier-badge ${l.method === 'GET' ? 'ok' : 'alert'}" style="font-size: 0.65rem;">${escapeHtml(l.method)}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(l.details)}">
            ${escapeHtml(l.path)}
          </td>
          <td><b style="color: ${statusColor}; font-family: var(--font-mono);">${escapeHtml(l.status_code)}</b></td>
          <td>${verdictBadge}</td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--accent-cyan); text-align: right;">
            ${escapeHtml(l.latency_ms)} ms
          </td>
          <td style="text-align: right;">${triageBtn}</td>
        </tr>
      `;
    }).join("");
  }
}
