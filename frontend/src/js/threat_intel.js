/**
 * SentinelAI - Threat Intelligence Explorer & Incident Simulator
 * Searches 3,774 ChromaDB vectors across MITRE ATT&CK, CISA KEV, OWASP 2025, and NVD.
 */

import { SentinelAPI } from "./api.js";

export class ThreatIntelController {
  constructor(appState) {
    this.appState = appState;
    this.init();
  }

  init() {
    // Search button
    const btnSearch = document.getElementById("btn-search-threat-intel");
    if (btnSearch) {
      btnSearch.addEventListener("click", () => this.executeSearch());
    }

    // Enter key on search input
    const searchInput = document.getElementById("threat-search-query");
    if (searchInput) {
      searchInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") this.executeSearch();
      });
    }

    // Incident Simulator trigger
    const btnSimulate = document.getElementById("btn-run-simulation");
    if (btnSimulate) {
      btnSimulate.addEventListener("click", () => this.executeSimulation());
    }
  }

  async executeSearch() {
    const queryInput = document.getElementById("threat-search-query");
    const q = queryInput?.value.trim();
    if (!q) return;

    const sourceFilter = document.getElementById("threat-filter-source")?.value || "ALL";
    const catFilter = document.getElementById("threat-filter-category")?.value || "ALL";

    const btn = document.getElementById("btn-search-threat-intel");
    const resultsContainer = document.getElementById("threat-search-results");

    btn.disabled = true;
    btn.innerHTML = `<span class="pulse-dot"></span> Searching Vectors...`;

    try {
      const data = await SentinelAPI.searchThreatIntel(q, {
        source: sourceFilter,
        category: catFilter,
        limit: 8
      });

      this.renderSearchResults(data);
    } catch (err) {
      console.error("Threat search failed:", err);
      alert(`Search failed: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<span>🔎</span> Search Vector Base`;
    }
  }

  renderSearchResults(data) {
    const container = document.getElementById("threat-search-results");
    if (!container) return;

    const hits = data.results || [];
    if (hits.length === 0) {
      container.innerHTML = `
        <div style="padding: 2rem; text-align: center; color: var(--text-muted);">
          No matching threat intelligence vectors found for this query.
        </div>
      `;
      return;
    }

    container.innerHTML = hits.map((hit, idx) => {
      const sev = hit.severity || "MEDIUM";
      const sevColor = sev === "CRITICAL" ? "var(--accent-red)" : (sev === "HIGH" ? "var(--accent-amber)" : "var(--accent-cyan)");
      
      return `
        <div class="playbook-card">
          <div class="playbook-header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'">
            <div class="playbook-title">
              <span style="color: ${sevColor}; font-weight: 800;">[${(hit.source || '').toUpperCase()}]</span>
              <span>${hit.identifier}: ${hit.title}</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <span class="tier-badge ok" style="font-family: var(--font-mono);">Match: ${(hit.score || 0).toFixed(4)}</span>
              <span style="font-size: 0.75rem; color: var(--text-muted);">Details ▾</span>
            </div>
          </div>
          <div class="playbook-body" style="display: ${idx < 2 ? 'block' : 'none'};">
            <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.5rem;">
              <b>Knowledge Source:</b> <code>${hit.source}</code> | 
              <b>Attack Family:</b> <code>${hit.category}</code> | 
              <b>Severity:</b> <b style="color: ${sevColor};">${sev}</b>
            </div>
            <div style="white-space: pre-line;">${hit.text}</div>
          </div>
        </div>
      `;
    }).join("");
  }

  async executeSimulation() {
    const btn = document.getElementById("btn-run-simulation");
    const originalText = btn.innerHTML;
    btn.innerHTML = `<span class="pulse-dot"></span> Synthesizing Incident Brief...`;
    btn.disabled = true;

    try {
      const family = document.getElementById("sim-attack-family")?.value || "Infiltration";
      const conf = parseFloat(document.getElementById("sim-confidence")?.value || "0.98");
      const port = parseInt(document.getElementById("sim-port")?.value || "445", 10);
      const srcIp = document.getElementById("sim-src-ip")?.value || "192.168.10.55";
      const dstIp = document.getElementById("sim-dst-ip")?.value || "10.0.0.12";
      const feature = document.getElementById("sim-shap-feature")?.value || "traffic_symmetry_ratio (+2.14)";

      const reasoningConfig = this.appState.getReasoningConfig();

      const payload = {
        threat_family: family,
        confidence: conf,
        src_ip: srcIp,
        dst_ip: dstIp,
        dst_port: port,
        decisive_features: [feature],
        llm_provider: reasoningConfig.provider,
        llm_model: reasoningConfig.model,
        api_key: reasoningConfig.apiKey
      };

      const report = await SentinelAPI.investigateAlert(payload);
      this.renderSimulationReport(report);
    } catch (err) {
      console.error("Simulation failed:", err);
      alert(`Simulation failed: ${err.message}`);
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }

  renderSimulationReport(rep) {
    const container = document.getElementById("sim-report-output");
    if (!container) return;
    container.style.display = "block";

    const reasoning = rep.reasoning || {};
    const containment = rep.immediate_containment || {};
    const attributions = rep.mitre_attribution || [];
    const playbooks = rep.recommended_playbooks || [];

    document.getElementById("sim-report-id").textContent = rep.incident_id || "INC-UNKNOWN";
    document.getElementById("sim-report-sev").textContent = rep.severity || "HIGH";
    document.getElementById("sim-report-action").textContent = `${containment.action || 'LOG_AND_MONITOR'}: ${containment.description || ''}`;

    document.getElementById("sim-narrative-text").textContent = reasoning.narrative || "No narrative generated.";
    document.getElementById("sim-root-cause-text").textContent = reasoning.root_cause_analysis || "No root cause generated.";

    const checklistEl = document.getElementById("sim-checklist-items");
    if (checklistEl) {
      const items = reasoning.containment_checklist || [];
      checklistEl.innerHTML = items.map((c, i) => `
        <div class="checklist-item">
          <div class="checklist-num">${i + 1}</div>
          <div>${c}</div>
        </div>
      `).join("");
    }

    const ttpContainer = document.getElementById("sim-ttps-container");
    if (ttpContainer) {
      ttpContainer.innerHTML = attributions.map(a => `
        <li style="margin-bottom: 0.35rem;">
          <b>${a.identifier}</b>: ${a.title} 
          <span style="color: var(--text-muted); font-size: 0.75rem;">(Match: ${(a.relevance_score || 0).toFixed(4)})</span>
        </li>
      `).join("");
    }
  }
}
