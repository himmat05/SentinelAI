/**
/**
 * SentinelAI - 24/7 Live Website Monitor & Shield Controller
 * Drives real-time proxy telemetry, rolling time-series charts, and live threat interception.
 */

export class LiveMonitorController {
  constructor() {
    this.pollInterval = null;
    this.targetUrl = "https://aai-ji-honey.vercel.app";
    this.heartbeatActive = false;
    this.init();
  }

  init() {
    this.bindEvents();
    this.loadConfig();
    this.refreshData();
    // Start 2.5s polling loop for 24/7 real-time feed
    this.pollInterval = setInterval(() => this.refreshData(), 2500);
  }

  bindEvents() {
    // Save target URL
    const btnSaveTarget = document.getElementById("btn-save-target-url");
    if (btnSaveTarget) {
      btnSaveTarget.addEventListener("click", () => this.saveTargetUrl());
    }

    // Toggle Heartbeat
    const btnHeartbeat = document.getElementById("btn-toggle-heartbeat");
    if (btnHeartbeat) {
      btnHeartbeat.addEventListener("click", () => this.toggleHeartbeat());
    }

    // Test Clean Visit
    const btnClean = document.getElementById("btn-test-clean-traffic");
    if (btnClean) {
      btnClean.addEventListener("click", () => this.testCleanTraffic());
    }

    // Multi-Vector Attack Simulators
    document.querySelectorAll(".btn-sim-attack").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const type = e.currentTarget.dataset.type || "sqli";
        this.simulateAttack(type, e.currentTarget);
      });
    });

    // Event Delegation for Quarantine Jail Unban Actions
    const qTbody = document.getElementById("monitor-quarantine-tbody");
    if (qTbody) {
      qTbody.addEventListener("click", (e) => {
        const btn = e.target.closest(".btn-unban-ip");
        if (btn) {
          const ip = btn.dataset.ip;
          this.unbanIp(ip);
        }
      });
    }

    // Clear Logs
    const btnClear = document.getElementById("btn-clear-traffic-logs");
    if (btnClear) {
      btnClear.addEventListener("click", () => this.clearLogs());
    }
  }

  async loadConfig() {
    try {
      const res = await fetch("/api/monitoring/config");
      if (!res.ok) return;
      const data = await res.json();
      this.targetUrl = data.target_url;
      this.heartbeatActive = data.heartbeat_active;

      const input = document.getElementById("monitor-target-url-input");
      if (input) input.value = this.targetUrl;

      const gwInput = document.getElementById("monitor-gateway-url-input");
      if (gwInput) gwInput.value = `${window.location.origin}/gateway/`;

      const gwLink = document.getElementById("monitor-gateway-link");
      if (gwLink) gwLink.href = `${window.location.origin}/gateway/`;

      const badge = document.getElementById("monitor-shield-status-badge");
      if (badge) {
        badge.innerHTML = `<span class="pulse-dot"></span> PROTECTING: ${this.targetUrl}`;
      }

      const hbBtn = document.getElementById("btn-toggle-heartbeat");
      if (hbBtn) {
        hbBtn.textContent = this.heartbeatActive ? "⏹️ Stop 24/7 Heartbeat" : "▶️ Start 24/7 Heartbeat";
        hbBtn.className = this.heartbeatActive ? "btn-cyber btn-cyber-amber" : "btn-cyber";
      }
    } catch (err) {
      console.warn("Could not load monitoring config:", err);
    }
  }

  async saveTargetUrl() {
    const input = document.getElementById("monitor-target-url-input");
    const val = input?.value.trim();
    if (!val) return;

    try {
      const res = await fetch("/api/monitoring/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: val })
      });
      if (res.ok) {
        const data = await res.json();
        this.targetUrl = data.config.target_url;
        const badge = document.getElementById("monitor-shield-status-badge");
        if (badge) badge.innerHTML = `<span class="pulse-dot"></span> PROTECTING: ${this.targetUrl}`;
        alert(`Target updated to ${this.targetUrl}!\nProtected gateway: http://127.0.0.1:8000/gateway/`);
      }
    } catch (err) {
      alert(`Failed to update target: ${err.message}`);
    }
  }

  async toggleHeartbeat() {
    try {
      const res = await fetch("/api/monitoring/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ heartbeat_active: !this.heartbeatActive })
      });
      if (res.ok) {
        const data = await res.json();
        this.heartbeatActive = data.config.heartbeat_active;
        const hbBtn = document.getElementById("btn-toggle-heartbeat");
        if (hbBtn) {
          hbBtn.textContent = this.heartbeatActive ? "⏹️ Stop 24/7 Heartbeat" : "▶️ Start 24/7 Heartbeat";
          hbBtn.className = this.heartbeatActive ? "btn-cyber btn-cyber-amber" : "btn-cyber";
        }
      }
    } catch (err) {
      console.error(err);
    }
  }

  async testCleanTraffic() {
    const btn = document.getElementById("btn-test-clean-traffic");
    const old = btn.innerHTML;
    btn.innerHTML = `<span class="pulse-dot"></span> Proxying to Vercel...`;
    btn.disabled = true;

    try {
      const res = await fetch("/api/monitoring/test-clean", { method: "POST" });
      const data = await res.json();
      this.refreshData();
      alert(`✅ Clean Traffic Allowed!\n${data.message}\nReceived ${data.bytes_received} bytes from Vercel.`);
    } catch (err) {
      alert(`Clean test error: ${err.message}`);
    } finally {
      btn.innerHTML = old;
      btn.disabled = false;
    }
  }

  async simulateAttack(attackType = "sqli", triggerBtn = null) {
    const old = triggerBtn ? triggerBtn.innerHTML : null;
    if (triggerBtn) {
      triggerBtn.innerHTML = `<span class="pulse-dot"></span> In flight...`;
      triggerBtn.disabled = true;
    }

    try {
      const res = await fetch(`/api/monitoring/simulate-attack?attack_type=${encodeURIComponent(attackType)}`, { method: "POST" });
      const data = await res.json();
      await this.refreshData();
      alert(`🛡️ Intrusion Intercepted!\nAttack Vector: [${attackType.toUpperCase()}]\nStatus: HTTP ${data.response_status} FORBIDDEN\n${data.message}`);
    } catch (err) {
      alert(`Simulation error: ${err.message}`);
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
      const res = await fetch("/api/monitoring/quarantine/unban", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ client_ip: ip })
      });
      const data = await res.json();
      await this.refreshData();
      alert(`🔓 IP Released!\n${data.message}`);
    } catch (err) {
      alert(`Failed to unban IP: ${err.message}`);
    }
  }

  async clearLogs() {
    if (!confirm("Clear historical traffic logs?")) return;
    try {
      await fetch("/api/monitoring/clear-logs", { method: "POST" });
      this.refreshData();
    } catch (err) {
      console.error(err);
    }
  }

  async refreshData() {
    try {
      // 1. Fetch Stats
      const statsRes = await fetch("/api/monitoring/stats");
      if (statsRes.ok) {
        const s = await statsRes.json();
        this.updateStatsUI(s);
      }

      // 2. Fetch Chart Points
      const chartRes = await fetch("/api/monitoring/chart?points=25");
      if (chartRes.ok) {
        const c = await chartRes.json();
        this.renderChart(c.points || []);
      }

      // 3. Fetch Recent Logs
      const logsRes = await fetch("/api/monitoring/logs?limit=30");
      if (logsRes.ok) {
        const l = await logsRes.json();
        this.renderLogsTable(l.logs || []);
      }

      // 4. Fetch Active Quarantine Jail
      const qRes = await fetch("/api/monitoring/quarantine");
      if (qRes.ok) {
        const q = await qRes.json();
        this.renderQuarantineTable(q.quarantined_ips || []);
      }
    } catch (err) {
      // Background poll failure (quiet)
    }
  }

  renderQuarantineTable(bans) {
    const tbody = document.getElementById("monitor-quarantine-tbody");
    const badge = document.getElementById("quarantine-count-badge");
    if (badge) {
      badge.textContent = `${bans.length} QUARANTINED ${bans.length === 1 ? 'IP' : 'IPS'}`;
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
          <td><span style="font-family: var(--font-mono); font-weight: 700; color: #f87171;">${b.client_ip}</span></td>
          <td><span class="tier-badge alert">${b.threat_category}</span></td>
          <td style="font-size: 0.8rem; color: var(--text-muted); max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${b.reason}
          </td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${b.banned_at || '--'}</td>
          <td>
            <span style="font-family: var(--font-mono); font-size: 0.8rem; font-weight: bold; color: #fbbf24;">
              ⏳ ${b.remaining_seconds}s (~${remainingMin}m)
            </span>
          </td>
          <td style="text-align: right;">
            <button class="btn-cyber btn-unban-ip" data-ip="${b.client_ip}" style="font-size: 0.72rem; padding: 0.25rem 0.65rem; color: #6ee7b7; border-color: rgba(16, 185, 129, 0.4);">
              🔓 Unban IP
            </button>
          </td>
        </tr>
      `;
    }).join("");
  }

  updateStatsUI(s) {
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    };

    setVal("stat-mon-total", s.total_requests || 0);
    setVal("stat-mon-clean", s.clean_allowed || 0);
    setVal("stat-mon-blocked", s.threats_blocked || 0);
    setVal("stat-mon-latency", `${s.avg_latency_ms || 0} ms`);
    setVal("stat-mon-health", `${s.shield_health_pct || 100}%`);
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

    // Grid lines
    ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padding + (i / 4) * drawH;
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(w - padding, y);
      ctx.stroke();
    }

    // Draw Clean Traffic (Green)
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

    // Draw Blocked Threats (Red)
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

    // Draw data points & X-labels
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
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No traffic logged yet. Visit <a href="/gateway/" target="_blank" style="color: var(--accent-cyan);">http://127.0.0.1:8000/gateway/</a> to generate live traffic!</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
      const isBlocked = l.verdict === "BLOCKED";
      const timeStr = l.timestamp ? l.timestamp.split("T")[1].slice(0, 8) : "--:--:--";
      const statusColor = l.status_code === 200 ? "var(--accent-green)" : (l.status_code === 403 ? "var(--accent-red)" : "var(--accent-amber)");

      return `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${timeStr}</td>
          <td><span style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary);">${l.client_ip}</span></td>
          <td><span class="tier-badge ${l.method === 'GET' ? 'ok' : 'alert'}" style="font-size: 0.65rem;">${l.method}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${l.path}
          </td>
          <td><b style="color: ${statusColor}; font-family: var(--font-mono);">${l.status_code}</b></td>
          <td>
            <span class="tier-badge ${isBlocked ? 'alert' : 'ok'}">
              ${isBlocked ? `🚨 ${l.threat_category}` : '🛡️ CLEAN'}
            </span>
          </td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--accent-cyan); text-align: right;">
            ${l.latency_ms} ms
          </td>
        </tr>
      `;
    }).join("");
  }
}
