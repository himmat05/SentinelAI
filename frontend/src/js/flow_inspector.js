/**
 * SentinelAI - Flow Inspector Controller
 * Drives real-time single-flow multi-tier inspection, TreeSHAP visualization,
 * and AI autonomous reasoning.
 */

import { FLOW_PRESETS } from "./presets.js";
import { SentinelAPI } from "./api.js";
import { escapeHtml, showToast } from "./security_utils.js";

export class FlowInspector {
  constructor(appState) {
    this.appState = appState;
    this.currentPreset = "infiltration_smb";
    this.init();
  }

  init() {
    this.renderPresets();
    this.loadPreset(this.currentPreset);
    this.bindEvents();
  }

  renderPresets() {
    const container = document.getElementById("preset-chips-container");
    if (!container) return;

    container.innerHTML = Object.values(FLOW_PRESETS).map(p => `
      <button class="preset-chip ${p.id === this.currentPreset ? 'active' : ''}" data-id="${p.id}">
        <span>${p.icon}</span> ${p.name}
      </button>
    `).join("");

    container.querySelectorAll(".preset-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        const id = chip.dataset.id;
        container.querySelectorAll(".preset-chip").forEach(c => c.classList.remove("active"));
        chip.classList.add("active");
        this.loadPreset(id);
      });
    });
  }

  loadPreset(presetId) {
    const p = FLOW_PRESETS[presetId];
    if (!p) return;
    this.currentPreset = presetId;

    const d = p.data;
    const setVal = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.value = val;
    };

    setVal("flow-src-ip", d.src_ip);
    setVal("flow-dst-ip", d.dst_ip);
    setVal("flow-dst-port", d.dst_port);
    setVal("flow-duration", d.flow_duration_s);
    setVal("flow-iat-mean", d.flow_iat_mean_s);
    setVal("flow-fwd-iat-mean", d.fwd_iat_mean_s);
    setVal("flow-bwd-iat-mean", d.bwd_iat_mean_s);
    setVal("flow-fwd-packets", d.fwd_packets);
    setVal("flow-bwd-packets", d.bwd_packets);
    setVal("flow-fwd-bytes", d.fwd_bytes);
    setVal("flow-bwd-bytes", d.bwd_bytes);
    setVal("flow-fwd-len-mean", d.fwd_pkt_len_mean);
    setVal("flow-bwd-len-mean", d.bwd_pkt_len_mean);
    setVal("flow-bytes-sec", d.flow_bytes_per_sec);
    setVal("flow-pkts-sec", d.flow_pkts_per_sec);
    setVal("flow-fwd-win", d.fwd_tcp_win_ratio);
    setVal("flow-bwd-win", d.bwd_tcp_win_ratio);
    setVal("flow-symmetry", d.traffic_symmetry_ratio);

    const symLabel = document.getElementById("symmetry-val");
    if (symLabel) symLabel.textContent = Number(d.traffic_symmetry_ratio).toFixed(3);
  }

  getFormData() {
    const num = (id) => parseFloat(document.getElementById(id)?.value || "0");
    const str = (id) => document.getElementById(id)?.value || "";

    return {
      src_ip: str("flow-src-ip"),
      dst_ip: str("flow-dst-ip"),
      src_port: 49152,
      protocol: "TCP",
      dst_port: parseInt(num("flow-dst-port"), 10),
      flow_duration_s: num("flow-duration"),
      flow_iat_mean_s: num("flow-iat-mean"),
      fwd_iat_mean_s: num("flow-fwd-iat-mean"),
      bwd_iat_mean_s: num("flow-bwd-iat-mean"),
      fwd_packets: num("flow-fwd-packets"),
      bwd_packets: num("flow-bwd-packets"),
      fwd_bytes: num("flow-fwd-bytes"),
      bwd_bytes: num("flow-bwd-bytes"),
      fwd_pkt_len_mean: num("flow-fwd-len-mean"),
      bwd_pkt_len_mean: num("flow-bwd-len-mean"),
      flow_bytes_per_sec: num("flow-bytes-sec"),
      flow_pkts_per_sec: num("flow-pkts-sec"),
      fwd_tcp_win_ratio: num("flow-fwd-win"),
      bwd_tcp_win_ratio: num("flow-bwd-win"),
      traffic_symmetry_ratio: num("flow-symmetry")
    };
  }

  bindEvents() {
    // Slider listener
    const symSlider = document.getElementById("flow-symmetry");
    const symLabel = document.getElementById("symmetry-val");
    if (symSlider && symLabel) {
      symSlider.addEventListener("input", (e) => {
        symLabel.textContent = parseFloat(e.target.value).toFixed(3);
      });
    }

    // Execute button
    const btnInspect = document.getElementById("btn-execute-inspection");
    if (btnInspect) {
      btnInspect.addEventListener("click", () => this.executeInspection());
    }
  }

  async executeInspection() {
    const btn = document.getElementById("btn-execute-inspection");
    const originalText = btn.innerHTML;
    btn.innerHTML = `<span class="pulse-dot"></span> Inspecting Line-Rate Flow...`;
    btn.disabled = true;

    try {
      const flowData = this.getFormData();
      const reasoningState = this.appState.getReasoningConfig();

      const result = await SentinelAPI.inspectFlow(flowData, {
        explain: true,
        investigate: true,
        llmProvider: reasoningState.provider,
        llmModel: reasoningState.model,
        apiKey: reasoningState.apiKey
      });

      this.renderResults(result);
    } catch (err) {
      console.error("Inspection error:", err);
      showToast("Inspection Failed", `${err.message}. Check SentinelAI backend status.`, "error");
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }

  renderResults(res) {
    const resultsContainer = document.getElementById("inspection-results");
    if (!resultsContainer) return;
    resultsContainer.style.display = "block";

    const isThreat = res.is_threat;
    const cat = res.threat_category;
    const conf = res.confidence_pct ? res.confidence_pct.toFixed(1) : "0.0";
    const latency = res.latency_us ? res.latency_us.toFixed(1) : "150.0";

    // 1. Verdict Hero Banner
    const banner = document.getElementById("verdict-hero-banner");
    banner.className = `verdict-banner ${isThreat ? 'blocked' : 'allowed'}`;
    banner.innerHTML = `
      <div class="verdict-header">
        <div class="verdict-icon">
          ${isThreat ? '🚨' : '🛡️'}
        </div>
        <div class="verdict-text">
          <h2>${isThreat ? `BLOCKED — ${escapeHtml(cat.toUpperCase())}` : 'ALLOWED — BENIGN SESSION'}</h2>
          <p>${isThreat ? `Intrusion intercepted and neutralized by line-rate gatekeeper.` : 'Normal baseline network transport dynamics verified.'}</p>
        </div>
      </div>
      <div class="verdict-metric-group">
        <div class="verdict-metric-val">${isThreat ? `${conf}%` : 'CLEAN'}</div>
        <div class="verdict-metric-label">${isThreat ? 'Detection Certainty' : 'Action: ALLOW'}</div>
        <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; font-family: var(--font-mono);">
          ⚡ Wire Latency: ${latency} µs
        </div>
      </div>
    `;

    // 2. 3-Tier Defense Pipeline Cards
    const t1Flag = res.tier1_anomaly_flag;
    const t2Flag = res.tier2_flag;
    document.getElementById("tier-cards-container").innerHTML = `
      <div class="tier-card">
        <div class="tier-name">
          <span>Tier 1: Behavioral Anomaly</span>
          <span class="tier-badge ${t1Flag ? 'alert' : 'ok'}">${t1Flag ? 'OUTLIER' : 'NORMAL'}</span>
        </div>
        <div class="tier-stat">${res.tier1_anomaly_score ? res.tier1_anomaly_score.toFixed(4) : '0.0120'}</div>
        <div class="tier-subtext">Isolation Forest Deviance (Threshold: 0.0432)</div>
      </div>

      <div class="tier-card">
        <div class="tier-name">
          <span>Tier 2: Binary Gatekeeper</span>
          <span class="tier-badge ${t2Flag ? 'alert' : 'ok'}">${t2Flag ? 'ATTACK' : 'CLEAN'}</span>
        </div>
        <div class="tier-stat">${res.tier2_score ? res.tier2_score.toFixed(4) : '0.0021'}</div>
        <div class="tier-subtext">Supervised LightGBM Attack Probability</div>
      </div>

      <div class="tier-card">
        <div class="tier-name">
          <span>Tier 3: Threat Attribution</span>
          <span class="tier-badge ${isThreat ? 'alert' : 'ok'}">${escapeHtml(res.threat_category)}</span>
        </div>
        <div class="tier-stat">${conf}%</div>
        <div class="tier-subtext">Action: <code>${escapeHtml(res.mitigation_action)}</code></div>
      </div>
    `;

    // 3. TreeSHAP Decision Factors
    this.renderShapExplanation(res.explanation);

    // 4. Autonomous AI Reasoning & RAG Mitigation
    this.renderAiInvestigation(res.investigation);
  }

  renderShapExplanation(explanation) {
    const tableBody = document.getElementById("shap-waterfall-rows");
    const narrativeEl = document.getElementById("shap-narrative-text");
    if (!tableBody) return;

    if (!explanation || !explanation.primary_decision) {
      tableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No local SHAP attributions generated for clean flow.</td></tr>`;
      if (narrativeEl) narrativeEl.textContent = "Flow parameters fall within verified benign transport thresholds.";
      return;
    }

    const dec = explanation.primary_decision;
    if (narrativeEl) narrativeEl.textContent = dec.narrative || "Multi-tier feature analysis.";

    const contribs = dec.top_contributions || [];
    tableBody.innerHTML = contribs.map(c => {
      const isAttack = c.direction === "TOWARD_ATTACK";
      const absVal = Math.abs(c.shap_value);
      const widthPct = Math.min(Math.round((absVal / 4.0) * 100), 100);

      return `
        <tr>
          <td><span class="feature-pill">${c.label}</span></td>
          <td style="font-family: var(--font-mono);">${c.observed_value.toLocaleString()}</td>
          <td style="font-family: var(--font-mono); font-weight: 700; color: ${isAttack ? 'var(--accent-red)' : 'var(--accent-blue)'};">
            ${c.shap_value > 0 ? '+' : ''}${c.shap_value.toFixed(2)}
          </td>
          <td class="shap-bar-cell">
            <div class="shap-bar-track">
              <div class="shap-bar-fill ${isAttack ? 'push-attack' : 'push-normal'}" style="width: ${widthPct}%;"></div>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  renderAiInvestigation(inv) {
    const container = document.getElementById("ai-investigation-container");
    if (!container) return;

    if (!inv) {
      container.style.display = "none";
      return;
    }
    container.style.display = "block";

    const containment = inv.immediate_containment || {};
    const attributions = inv.mitre_attribution || [];
    const playbooks = inv.recommended_playbooks || [];
    const reasoning = inv.reasoning || {};

    // Provider Badge
    const provBadge = document.getElementById("ai-provider-badge");
    if (provBadge) {
      const p = (reasoning.provider || "Deterministic").toUpperCase();
      const m = reasoning.model || "Rules";
      provBadge.textContent = `${p} (${m})`;
    }

    // Fallback notice
    const fallbackBox = document.getElementById("ai-fallback-notice");
    if (fallbackBox) {
      if (reasoning.is_fallback) {
        fallbackBox.style.display = "block";
        fallbackBox.innerHTML = `⚠️ <b>Provider Notice:</b> ${escapeHtml(reasoning.fallback_reason || 'Fallback to deterministic rules.')}`;
      } else {
        fallbackBox.style.display = "none";
      }
    }

    // Narrative & Root Cause
    const narrativeEl = document.getElementById("ai-narrative-text");
    if (narrativeEl) narrativeEl.textContent = reasoning.narrative || "No narrative available.";

    const rootCauseEl = document.getElementById("ai-root-cause-text");
    if (rootCauseEl) rootCauseEl.textContent = reasoning.root_cause_analysis || "No root cause data.";

    // Checklist
    const checklistContainer = document.getElementById("ai-checklist-container");
    if (checklistContainer) {
      const items = reasoning.containment_checklist || [];
      checklistContainer.innerHTML = items.map((item, idx) => `
        <div class="checklist-item">
          <div class="checklist-num">${idx + 1}</div>
          <div>${escapeHtml(item)}</div>
        </div>
      `).join("");
    }

    // Containment policy box
    const policyBox = document.getElementById("ai-containment-policy");
    if (policyBox) {
      policyBox.innerHTML = `
        <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--accent-red); font-weight: 700; margin-bottom: 4px;">
          Enforced Firewall Rule:
        </div>
        <div style="font-size: 1.05rem; font-weight: 800; font-family: var(--font-mono); color: var(--text-primary); margin-bottom: 4px;">
          ${escapeHtml(containment.action || 'LOG_AND_MONITOR')}
        </div>
        <div style="font-size: 0.85rem; color: var(--text-secondary);">
          ${escapeHtml(containment.description || 'Standard monitoring.')}
        </div>
      `;
    }

    // Playbooks
    const pbContainer = document.getElementById("ai-playbooks-container");
    if (pbContainer) {
      pbContainer.innerHTML = playbooks.map((pb, idx) => `
        <div class="playbook-card">
          <div class="playbook-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
            <div class="playbook-title">
              <span>📘</span> [${escapeHtml((pb.source || '').toUpperCase())}] ${escapeHtml(pb.title)}
            </div>
            <span style="font-size: 0.75rem; color: var(--accent-cyan); font-weight: 600;">View Guidance ▾</span>
          </div>
          <div class="playbook-body" style="display: ${idx === 0 ? 'block' : 'none'};">
            ${escapeHtml(pb.guidance)}
          </div>
        </div>
      `).join("");
    }
  }
}
