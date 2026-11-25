/**
 * SentinelAI - High-Throughput Batch & PCAP Stress Simulation
 * Streams hundreds of flows or uploaded .pcap captures to benchmark wire-speed ML defense.
 */

import { FLOW_PRESETS } from "./presets.js";
import { SentinelAPI } from "./api.js";
import { escapeHtml, showToast } from "./security_utils.js";

export class BatchStreamSimulator {
  constructor() {
    this.init();
  }

  init() {
    const btn = document.getElementById("btn-run-batch");
    if (btn) {
      btn.addEventListener("click", () => this.runBatchSimulation());
    }

    const btnPcap = document.getElementById("btn-analyze-pcap");
    if (btnPcap) {
      btnPcap.addEventListener("click", () => this.analyzePcapUpload());
    }
  }

  generateBatchFlows(size) {
    const flows = [];
    const presetKeys = Object.keys(FLOW_PRESETS);

    for (let i = 0; i < size; i++) {
      const isAttack = Math.random() < 0.35;
      const key = isAttack
        ? presetKeys[Math.floor(Math.random() * (presetKeys.length - 1))]
        : "normal_https";

      const base = { ...FLOW_PRESETS[key].data };
      const jitter = 0.9 + Math.random() * 0.2;
      base.flow_duration_s = Number((base.flow_duration_s * jitter).toFixed(4));
      base.fwd_packets = Math.max(1, Math.round(base.fwd_packets * jitter));
      base.bwd_packets = Math.max(0, Math.round(base.bwd_packets * jitter));
      base.fwd_bytes = Math.max(40, Math.round(base.fwd_bytes * jitter));
      base.bwd_bytes = Math.max(0, Math.round(base.bwd_bytes * jitter));
      base.src_ip = `192.168.${Math.floor(Math.random() * 250) + 1}.${Math.floor(Math.random() * 250) + 1}`;

      flows.push(base);
    }

    return flows;
  }

  async runBatchSimulation() {
    const btn = document.getElementById("btn-run-batch");
    const slider = document.getElementById("batch-size-slider");
    const count = parseInt(slider?.value || "200", 10);

    const originalText = btn.innerHTML;
    btn.innerHTML = `<span class="pulse-dot"></span> Ingesting ${count} Flows...`;
    btn.disabled = true;

    try {
      const flows = this.generateBatchFlows(count);
      const t0 = performance.now();
      const response = await SentinelAPI.inspectBatch(flows);
      const wallTimeMs = performance.now() - t0;

      this.renderBatchResults(response, wallTimeMs);
    } catch (err) {
      console.error("Batch simulation failed:", err);
      showToast("Batch Test Failed", err.message, "error");
    } finally {
      btn.innerHTML = originalText;
      btn.disabled = false;
    }
  }

  async analyzePcapUpload() {
    const input = document.getElementById("pcap-file-input");
    const file = input?.files?.[0];
    if (!file) {
      showToast("No File Selected", "Choose a classic .pcap packet capture file first.", "warning");
      return;
    }

    const btn = document.getElementById("btn-analyze-pcap");
    const orig = btn.innerHTML;
    btn.innerHTML = `<span class="pulse-dot"></span> Extracting Flows...`;
    btn.disabled = true;

    try {
      const data = await SentinelAPI.analyzePcap(file);
      this.renderPcapResults(data);
      showToast(
        "PCAP Analysis Complete",
        `Extracted ${data.total_flows_extracted} flows (${data.threats_detected} threats detected).`,
        data.threats_detected > 0 ? "warning" : "success"
      );
    } catch (err) {
      showToast("PCAP Parsing Error", err.message, "error");
    } finally {
      btn.innerHTML = orig;
      btn.disabled = false;
    }
  }

  renderPcapResults(data) {
    const container = document.getElementById("pcap-results-container");
    const tbody = document.getElementById("pcap-flows-tbody");
    const summaryEl = document.getElementById("pcap-summary-banner");
    if (!container || !tbody) return;
    container.style.display = "block";

    if (summaryEl) {
      summaryEl.innerHTML = `
        <span>File: <b>${escapeHtml(data.filename)}</b></span> |
        <span>Extracted Sessions: <b>${data.total_flows_extracted}</b></span> |
        <span style="color: var(--accent-red);">Threats: <b>${data.threats_detected}</b></span> |
        <span style="color: var(--accent-green);">Clean: <b>${data.clean_flows}</b></span> |
        <span style="color: var(--accent-cyan);">ML Latency: <b>${data.batch_latency_ms} ms</b></span>
      `;
    }

    const flows = data.flows || [];
    tbody.innerHTML = flows.map(f => {
      const isThreat = f.verdict === "BLOCKED";
      return `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 0.78rem;">${escapeHtml(f.src_ip)} → ${escapeHtml(f.dst_ip)}:${escapeHtml(f.dst_port)}</td>
          <td><span class="tier-badge ok">${escapeHtml(f.protocol)}</span></td>
          <td style="font-family: var(--font-mono);">${escapeHtml(f.fwd_packets)} / ${escapeHtml(f.bwd_packets)}</td>
          <td><span class="tier-badge ${isThreat ? 'alert' : 'ok'}">${escapeHtml(f.threat_category)}</span></td>
          <td><code>${escapeHtml(f.mitigation_action)}</code></td>
          <td style="text-align: right; font-family: var(--font-mono);">${escapeHtml(f.confidence_pct)}%</td>
        </tr>
      `;
    }).join("");
  }

  renderBatchResults(res, wallTimeMs) {
    const resultsContainer = document.getElementById("batch-results-container");
    if (!resultsContainer) return;
    resultsContainer.style.display = "block";

    const total = res.total_flows || 0;
    const blocked = res.threats_blocked || 0;
    const clean = res.clean_allowed || 0;
    const batchLatency = res.batch_latency_ms || wallTimeMs;
    const throughput = total > 0 ? Math.round(total / (batchLatency / 1000)) : 0;

    document.getElementById("batch-stat-total").textContent = total.toLocaleString();
    document.getElementById("batch-stat-blocked").textContent = blocked.toLocaleString();
    document.getElementById("batch-stat-clean").textContent = clean.toLocaleString();
    document.getElementById("batch-stat-throughput").textContent = `${throughput.toLocaleString()} fps`;
    document.getElementById("batch-stat-latency").textContent = `${batchLatency.toFixed(2)} ms`;

    const categoryCounts = {};
    (res.results || []).forEach(r => {
      const cat = r.threat_category || "Normal";
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
    });

    const breakdownTable = document.getElementById("batch-breakdown-rows");
    if (breakdownTable) {
      breakdownTable.innerHTML = Object.entries(categoryCounts).map(([cat, cnt]) => {
        const isMal = cat !== "Normal" && cat !== "Normal (Clean)";
        const pct = ((cnt / total) * 100).toFixed(1);
        return `
          <tr>
            <td><b style="color: ${isMal ? 'var(--accent-red)' : 'var(--accent-green)'};">${escapeHtml(cat)}</b></td>
            <td><span class="tier-badge ${isMal ? 'alert' : 'ok'}">${isMal ? 'BLOCKED' : 'ALLOWED'}</span></td>
            <td style="font-family: var(--font-mono); font-weight: 700;">${cnt}</td>
            <td style="font-family: var(--font-mono);">${pct}%</td>
          </tr>
        `;
      }).join("");
    }
  }
}
