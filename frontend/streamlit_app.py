"""
SentinelAI - Real-Time Autonomous Cyber Defense & XAI Console
=============================================================
Interactive Streamlit dashboard for testing the 3-Tier AI pipeline,
verifying Knob 1 multi-tier synergy, and inspecting live SHAP explanations.
"""

import os
import sys
import time
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app.schemas.flow import FlowData
from backend.app.services.inference_engine import SentinelInferenceEngine
from ml.explainability.shap_explainer import SentinelShapExplainer, FEATURE_HUMAN_LABELS, FEATURE_NAMES

# Page configuration
st.set_page_config(
    page_title="SentinelAI — Autonomous Defense & XAI Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .reportview-container {
        background: #0E1117;
    }
    .metric-card {
        background: #1A1F2C;
        border: 1px solid #2D3748;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }
    .verdict-blocked {
        background: linear-gradient(135deg, rgba(231,76,60,0.2) 0%, rgba(192,57,43,0.3) 100%);
        border: 2px solid #E74C3C;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        color: #FF6B6B;
    }
    .verdict-allowed {
        background: linear-gradient(135deg, rgba(46,204,113,0.2) 0%, rgba(39,174,96,0.3) 100%);
        border: 2px solid #2ECC71;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        color: #2ECC71;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def load_sentinel_engines():
    """Initializes and caches the inference and explainability singletons."""
    with st.spinner("🚀 Arming SentinelAI 3-Tier AI Pipeline and TreeExplainers..."):
        engine = SentinelInferenceEngine.get_instance()
        explainer = SentinelShapExplainer.get_instance()
    return engine, explainer


engine, explainer = load_sentinel_engines()

# Header
st.title("🛡️ SentinelAI: Autonomous Defense & XAI Console")
st.caption("Sub-100 µs Multi-Tier Threat Neutralization with Mathematical SHAP Attribution")

# Predefined attack presets
PRESETS = {
    "💥 High-Volume DDoS Attack (HTTP Flood)": {
        "src_ip": "10.0.0.99", "dst_ip": "192.168.1.50", "dst_port": 80,
        "flow_duration_s": 0.0012, "flow_iat_mean_s": 0.0001, "fwd_iat_mean_s": 0.0001, "bwd_iat_mean_s": 0.0,
        "fwd_packets": 850, "bwd_packets": 0, "fwd_bytes": 54400, "bwd_bytes": 0,
        "fwd_pkt_len_mean": 64.0, "bwd_pkt_len_mean": 0.0,
        "flow_bytes_per_sec": 45333333.0, "flow_pkts_per_sec": 708333.0,
        "fwd_tcp_win_ratio": 1.0, "bwd_tcp_win_ratio": 0.0, "traffic_symmetry_ratio": 0.0
    },
    "🕵️ Stealth Infiltration (SMB Lateral Copy)": {
        "src_ip": "192.168.1.140", "dst_ip": "192.168.1.200", "dst_port": 445,
        "flow_duration_s": 14.5, "flow_iat_mean_s": 0.12, "fwd_iat_mean_s": 0.11, "bwd_iat_mean_s": 0.13,
        "fwd_packets": 65, "bwd_packets": 58, "fwd_bytes": 98000, "bwd_bytes": 4500,
        "fwd_pkt_len_mean": 1507.0, "bwd_pkt_len_mean": 77.0,
        "flow_bytes_per_sec": 7068.0, "flow_pkts_per_sec": 8.4,
        "fwd_tcp_win_ratio": 0.5, "bwd_tcp_win_ratio": 0.5, "traffic_symmetry_ratio": 0.95
    },
    "🤖 Botnet Command & Control (Beaconing)": {
        "src_ip": "192.168.1.112", "dst_ip": "185.220.101.5", "dst_port": 8080,
        "flow_duration_s": 30.0, "flow_iat_mean_s": 2.5, "fwd_iat_mean_s": 2.5, "bwd_iat_mean_s": 2.5,
        "fwd_packets": 12, "bwd_packets": 12, "fwd_bytes": 1440, "bwd_bytes": 2880,
        "fwd_pkt_len_mean": 120.0, "bwd_pkt_len_mean": 240.0,
        "flow_bytes_per_sec": 144.0, "flow_pkts_per_sec": 0.8,
        "fwd_tcp_win_ratio": 0.5, "bwd_tcp_win_ratio": 0.5, "traffic_symmetry_ratio": 0.33
    },
    "🔨 SSH Brute Force (Credential Spraying)": {
        "src_ip": "45.33.32.156", "dst_ip": "192.168.1.10", "dst_port": 22,
        "flow_duration_s": 0.05, "flow_iat_mean_s": 0.005, "fwd_iat_mean_s": 0.005, "bwd_iat_mean_s": 0.006,
        "fwd_packets": 14, "bwd_packets": 10, "fwd_bytes": 1800, "bwd_bytes": 1200,
        "fwd_pkt_len_mean": 128.0, "bwd_pkt_len_mean": 120.0,
        "flow_bytes_per_sec": 60000.0, "flow_pkts_per_sec": 480.0,
        "fwd_tcp_win_ratio": 1.0, "bwd_tcp_win_ratio": 0.8, "traffic_symmetry_ratio": 0.6
    },
    "🌐 Normal Enterprise HTTPS (Google/AWS)": {
        "src_ip": "192.168.1.105", "dst_ip": "142.250.190.46", "dst_port": 443,
        "flow_duration_s": 1.25, "flow_iat_mean_s": 0.05, "fwd_iat_mean_s": 0.045, "bwd_iat_mean_s": 0.055,
        "fwd_packets": 10, "bwd_packets": 14, "fwd_bytes": 1600, "bwd_bytes": 5200,
        "fwd_pkt_len_mean": 160.0, "bwd_pkt_len_mean": 371.4,
        "flow_bytes_per_sec": 5440.0, "flow_pkts_per_sec": 19.2,
        "fwd_tcp_win_ratio": 0.5, "bwd_tcp_win_ratio": 0.5, "traffic_symmetry_ratio": 0.235
    },
    "🔍 Normal DNS Resolution": {
        "src_ip": "192.168.1.105", "dst_ip": "8.8.8.8", "dst_port": 53,
        "flow_duration_s": 0.02, "flow_iat_mean_s": 0.02, "fwd_iat_mean_s": 0.0, "bwd_iat_mean_s": 0.0,
        "fwd_packets": 1, "bwd_packets": 1, "fwd_bytes": 68, "bwd_bytes": 142,
        "fwd_pkt_len_mean": 68.0, "bwd_pkt_len_mean": 142.0,
        "flow_bytes_per_sec": 10500.0, "flow_pkts_per_sec": 100.0,
        "fwd_tcp_win_ratio": 0.0, "bwd_tcp_win_ratio": 0.0, "traffic_symmetry_ratio": 0.32
    },
    "⚙️ Custom Flow Parameters": None
}

# Sidebar
with st.sidebar:
    st.subheader("🎛️ Flow Simulator Controls")
    preset_choice = st.selectbox("Select Traffic Preset:", list(PRESETS.keys()), index=0)

    st.markdown("---")
    st.subheader("⚙️ Defense Knobs")
    tier2_thresh = st.slider("Tier 2 Gatekeeper Threshold:", 0.10, 0.90, 0.50, 0.05)
    engine.tier2_threshold = tier2_thresh

    st.markdown(f"**Tier 1 Baseline Anomaly Threshold:** `{engine.t1_threshold:.4f}`")
    st.markdown("**Synergy Active:** Knob 1 (Tier 1 OR Tier 2 Trigger)")

    st.markdown("---")
    st.subheader("📊 Engine Status")
    st.success("🟢 Tier 1: Behavioral Anomaly Sensor (Armed)")
    st.success("🟢 Tier 2: Binary Gatekeeper (Armed)")
    st.success(f"🟢 Tier 3: MITRE Threat Classifier ({len(engine.classes)} Armed)")
    st.info("⚡ TreeSHAP XAI: Sub-millisecond Engine Active")


# Flow Data Input setup
preset_data = PRESETS[preset_choice]

tab_inspect, tab_batch, tab_global = st.tabs([
    "🔍 Real-Time Flow Inspection & XAI",
    "⚡ Batch Simulation (500 Flows)",
    "📈 Global Intelligence & Benchmarks"
])

# TAB 1: Single Flow Inspection & XAI
with tab_inspect:
    col_input, col_results = st.columns([1, 1])

    with col_input:
        st.subheader("1. Inbound Network Flow Telemetry")

        if preset_data is not None:
            c1, c2 = st.columns(2)
            with c1:
                src_ip = st.text_input("Source IP:", value=preset_data["src_ip"])
                dst_ip = st.text_input("Destination IP:", value=preset_data["dst_ip"])
                dst_port = st.number_input("Destination Port:", value=int(preset_data["dst_port"]), min_value=0, max_value=65535)
                fwd_pkts = st.number_input("Forward Packets:", value=int(preset_data["fwd_packets"]), min_value=0)
                bwd_pkts = st.number_input("Backward Packets:", value=int(preset_data["bwd_packets"]), min_value=0)
                fwd_bytes = st.number_input("Forward Bytes:", value=int(preset_data["fwd_bytes"]), min_value=0)
                bwd_bytes = st.number_input("Backward Bytes:", value=int(preset_data["bwd_bytes"]), min_value=0)
            with c2:
                duration = st.number_input("Duration (s):", value=float(preset_data["flow_duration_s"]), format="%.4f")
                flow_iat = st.number_input("Flow IAT Mean (s):", value=float(preset_data["flow_iat_mean_s"]), format="%.4f")
                pkt_rate = st.number_input("Packet Rate (pkts/s):", value=float(preset_data["flow_pkts_per_sec"]), format="%.1f")
                byte_rate = st.number_input("Byte Rate (bytes/s):", value=float(preset_data["flow_bytes_per_sec"]), format="%.1f")
                fwd_len = st.number_input("Fwd Packet Mean Size:", value=float(preset_data["fwd_pkt_len_mean"]), format="%.1f")
                bwd_len = st.number_input("Bwd Packet Mean Size:", value=float(preset_data["bwd_pkt_len_mean"]), format="%.1f")
                symmetry = st.slider("Traffic Symmetry Ratio:", 0.0, 1.0, float(preset_data["traffic_symmetry_ratio"]), 0.01)

            flow_payload = FlowData(
                src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                flow_duration_s=duration, flow_iat_mean_s=flow_iat,
                fwd_iat_mean_s=preset_data["fwd_iat_mean_s"], bwd_iat_mean_s=preset_data["bwd_iat_mean_s"],
                fwd_packets=fwd_pkts, bwd_packets=bwd_pkts, fwd_bytes=fwd_bytes, bwd_bytes=bwd_bytes,
                fwd_pkt_len_mean=fwd_len, bwd_pkt_len_mean=bwd_len,
                flow_bytes_per_sec=byte_rate, flow_pkts_per_sec=pkt_rate,
                fwd_tcp_win_ratio=preset_data["fwd_tcp_win_ratio"], bwd_tcp_win_ratio=preset_data["bwd_tcp_win_ratio"],
                traffic_symmetry_ratio=symmetry
            )
        else:
            # Custom sliders
            st.info("Configure custom network physics parameters below:")
            c1, c2 = st.columns(2)
            with c1:
                dst_port = st.number_input("Destination Port:", value=443)
                duration = st.number_input("Duration (s):", value=1.0)
                fwd_pkts = st.number_input("Forward Packets:", value=10)
                bwd_pkts = st.number_input("Backward Packets:", value=12)
                fwd_bytes = st.number_input("Forward Bytes:", value=1500)
                bwd_bytes = st.number_input("Backward Bytes:", value=4200)
            with c2:
                flow_iat = st.number_input("Mean IAT (s):", value=0.05)
                pkt_rate = st.number_input("Packet Rate (pkts/s):", value=22.0)
                byte_rate = st.number_input("Byte Rate (bytes/s):", value=5700.0)
                fwd_len = st.number_input("Fwd Packet Mean Size:", value=150.0)
                bwd_len = st.number_input("Bwd Packet Mean Size:", value=350.0)
                symmetry = st.slider("Traffic Symmetry Ratio:", 0.0, 1.0, 0.8)

            flow_payload = FlowData(
                dst_port=dst_port, flow_duration_s=duration, flow_iat_mean_s=flow_iat,
                fwd_iat_mean_s=0.04, bwd_iat_mean_s=0.06,
                fwd_packets=fwd_pkts, bwd_packets=bwd_pkts, fwd_bytes=fwd_bytes, bwd_bytes=bwd_bytes,
                fwd_pkt_len_mean=fwd_len, bwd_pkt_len_mean=bwd_len,
                flow_bytes_per_sec=byte_rate, flow_pkts_per_sec=pkt_rate,
                fwd_tcp_win_ratio=0.5, bwd_tcp_win_ratio=0.5, traffic_symmetry_ratio=symmetry
            )

        btn_inspect = st.button("🛡️ Execute Multi-Tier Inspection & SHAP Attribution", type="primary", use_container_width=True)

    with col_results:
        st.subheader("2. Real-Time Autonomous Verdict")
        
        # Execute inspection
        pred_res = engine.inspect_flow(flow_payload)
        X_vec = engine.preprocess_flow(flow_payload)
        xai_res = explainer.explain_flow(X_vec, pred_res.is_threat, pred_res.threat_category, top_k=6)

        # Verdict banner
        if pred_res.verdict == "BLOCKED":
            st.markdown(f"""
            <div class="verdict-blocked">
                <h2>🚨 VERDICT: BLOCKED (INTRUSION NEUTRALIZED)</h2>
                <h3>Category: <b>{pred_res.threat_category}</b> &nbsp;|&nbsp; Certainty: <b>{pred_res.confidence_pct:.1f}%</b></h3>
                <h4>Action Executed: <code>{pred_res.mitigation_action}</code></h4>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="verdict-allowed">
                <h2>🟢 VERDICT: ALLOWED (CLEAN TRAFFIC)</h2>
                <h3>Classification: <b>{pred_res.threat_category}</b> &nbsp;|&nbsp; Confidence: <b>{pred_res.confidence_pct:.1f}%</b></h3>
                <h4>Action: <code>{pred_res.mitigation_action}</code></h4>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # 4 Metric Cards
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Decision Latency", f"{pred_res.latency_us:.1f} µs")
        m2.metric("Tier 2 Score", f"{pred_res.tier2_score:.4f}", delta=f"{'Triggered' if pred_res.tier2_flag else 'Clean'}", delta_color="inverse")
        m3.metric("Tier 1 Anomaly", f"{pred_res.tier1_anomaly_score:.4f}", delta=f"{'Anomaly' if pred_res.tier1_anomaly_flag else 'Normal'}", delta_color="inverse")
        m4.metric("XAI Speed", f"{xai_res['total_xai_latency_us']:.1f} µs")

        st.markdown("---")
        st.subheader("3-Tier Defense Pipeline Breakdown")
        t_col1, t_col2, t_col3 = st.columns(3)
        with t_col1:
            st.markdown("**Tier 1: Behavioral Anomaly**")
            st.write(f"Deviance: `{pred_res.tier1_anomaly_score:.4f}`")
            st.write(f"Threshold: `{engine.t1_threshold:.4f}`")
            st.write(f"Status: `{'🚨 OUTLIER' if pred_res.tier1_anomaly_flag else '🟢 NORMAL'}`")
        with t_col2:
            st.markdown("**Tier 2: Binary Gatekeeper**")
            st.write(f"Attack Prob: `{pred_res.tier2_score:.4f}`")
            st.write(f"Threshold: `{engine.tier2_threshold:.2f}`")
            st.write(f"Status: `{'🚨 ATTACK' if pred_res.tier2_flag else '🟢 CLEAN'}`")
        with t_col3:
            st.markdown("**Tier 3: Threat Attribution**")
            st.write(f"Attributed: `{pred_res.threat_category}`")
            st.write(f"Confidence: `{pred_res.confidence_pct:.1f}%`")
            st.write(f"Mitigation: `{pred_res.mitigation_action}`")

    # XAI SHAP Explanation Section
    st.markdown("---")
    st.header("🔬 Explainable AI (XAI): Why Did SentinelAI Make This Decision?")

    primary_dec = xai_res.get("primary_decision", {})
    st.info(f"**Executive SOC Narrative:** {primary_dec.get('narrative', 'N/A')}")

    # Plotly Waterfall Plot
    if "top_contributions" in primary_dec:
        top_contribs = primary_dec["top_contributions"]
        base_val = primary_dec.get("base_value_log_odds", -3.673)
        
        feat_labels = [c["label"] for c in top_contribs]
        shap_vals = [c["shap_value"] for c in top_contribs]
        obs_vals = [c["observed_value"] for c in top_contribs]

        # Horizontal bar chart of contributions
        colors = ['#E74C3C' if v > 0 else '#3498DB' for v in shap_vals]
        fig_waterfall = go.Figure(go.Bar(
            x=shap_vals,
            y=feat_labels,
            orientation='h',
            marker_color=colors,
            text=[f"{v:+.2f} ({c['direction'].replace('_', ' ')})" for v, c in zip(shap_vals, top_contribs)],
            textposition='auto'
        ))
        fig_waterfall.update_layout(
            title="Local SHAP Feature Contributions (Red = Pushes Toward Attack, Blue = Pushes Toward Normal)",
            xaxis_title="SHAP Value (Log-Odds Impact on Attack Probability)",
            yaxis=dict(autorange="reversed"),
            height=380,
            template="plotly_dark",
            margin=dict(l=20, r=20, t=50, b=30)
        )
        st.plotly_chart(fig_waterfall, use_container_width=True)

        # Tabular contribution breakdown
        df_xai = pd.DataFrame([
            {
                "Feature Name": c["label"],
                "Observed Metric Value": c["observed_value"],
                "SHAP Impact (Log-Odds)": f"{c['shap_value']:+.4f}",
                "Influence Direction": "🚨 TOWARD ATTACK" if c["direction"] == "TOWARD_ATTACK" else "🟢 TOWARD BENIGN",
                "Relative Weight (%)": f"{c['relative_importance_pct']}%"
            }
            for c in top_contribs
        ])
        st.dataframe(df_xai, use_container_width=True)


# TAB 2: Batch Simulation
with tab_batch:
    st.header("⚡ High-Throughput Batch Stress Test Simulation")
    st.write("Streams held-out flows from the 20.4M production dataset to test line-rate batch latency and detection accuracy.")

    batch_size = st.slider("Select Stream Volume:", 50, 1000, 200, 50)
    if st.button("🚀 Stream & Neutralize Inbound Traffic Batch", type="primary"):
        with st.spinner(f"Processing {batch_size} line-rate network flows..."):
            # Sample from parquet
            from ml.evaluation.test_unseen_data import DATA_PATH, FEATURE_COLS
            import pyarrow.parquet as pq
            
            pf = pq.ParquetFile(DATA_PATH)
            table = pf.read_row_group(0, columns=FEATURE_COLS + ['label', 'attack_family'])
            df_b = table.to_pandas().sample(n=batch_size, random_state=int(time.time()) % 1000).reset_index(drop=True)

            flows_list = []
            for _, r in df_b.iterrows():
                flows_list.append(FlowData(
                    dst_port=int(r['dst_port']),
                    flow_duration_s=float(r['flow_duration_s']),
                    flow_iat_mean_s=float(r['flow_iat_mean_s']),
                    fwd_iat_mean_s=float(r['fwd_iat_mean_s']),
                    bwd_iat_mean_s=float(r['bwd_iat_mean_s']),
                    fwd_packets=int(r['fwd_packets']),
                    bwd_packets=int(r['bwd_packets']),
                    fwd_bytes=int(r['fwd_bytes']),
                    bwd_bytes=int(r['bwd_bytes']),
                    fwd_pkt_len_mean=float(r['fwd_pkt_len_mean']),
                    bwd_pkt_len_mean=float(r['bwd_pkt_len_mean']),
                    flow_bytes_per_sec=float(r['flow_bytes_per_sec']),
                    flow_pkts_per_sec=float(r['flow_pkts_per_sec']),
                    fwd_tcp_win_ratio=float(r['fwd_tcp_win_ratio']),
                    bwd_tcp_win_ratio=float(r['bwd_tcp_win_ratio']),
                    traffic_symmetry_ratio=float(r['traffic_symmetry_ratio'])
                ))

            t_b0 = time.perf_counter()
            batch_resp = engine.inspect_batch(flows_list)
            batch_time = time.perf_counter() - t_b0

        st.success(f"✅ Processed {batch_size} flows in {batch_time*1000:.1f} ms ({batch_resp.throughput_flows_per_sec:,.0f} flows/sec)")

        b1, b2, b3, b4 = st.columns(4)
        b1.metric("Total Flows", batch_resp.total_flows)
        b2.metric("Intrusions Blocked", batch_resp.threats_blocked, delta="Neutralized", delta_color="inverse")
        b3.metric("Clean Allowed", batch_resp.clean_allowed, delta="Passed Clean")
        b4.metric("Throughput", f"{batch_resp.throughput_flows_per_sec:,.0f} / sec")

        # Distribution Pie Chart
        threat_cats = [r.threat_category for r in batch_resp.results]
        cat_counts = pd.Series(threat_cats).value_counts().reset_index()
        cat_counts.columns = ["Category", "Count"]

        fig_pie = px.pie(cat_counts, values="Count", names="Category", title="Inbound Traffic Threat Breakdown",
                         color_discrete_sequence=px.colors.sequential.RdBu)
        fig_pie.update_layout(template="plotly_dark", height=400)
        st.plotly_chart(fig_pie, use_container_width=True)


# TAB 3: Global Model Intelligence & Benchmarks
with tab_global:
    st.header("📈 Global Model Intelligence & Benchmark Analytics")
    st.write("Visual explanations generated from the 436,541-flow stratified evaluation dataset.")

    g_col1, g_col2 = st.columns(2)
    with g_col1:
        st.subheader("Global Feature Importance (Mean |SHAP|)")
        bar_img_path = os.path.join(BASE_DIR, "ml/reports/shap/global_feature_importance.png")
        if os.path.exists(bar_img_path):
            st.image(bar_img_path, caption="Tier 2 Gatekeeper Global Feature Hierarchy", use_container_width=True)
        else:
            st.info("Run Stage 12 SHAP analysis to generate this plot.")

    with g_col2:
        st.subheader("Global Beeswarm Attribution Summary")
        bee_img_path = os.path.join(BASE_DIR, "ml/reports/shap/global_beeswarm.png")
        if os.path.exists(bee_img_path):
            st.image(bee_img_path, caption="Feature Value Distribution vs Attack Margin Push", use_container_width=True)
        else:
            st.info("Run Stage 12 SHAP analysis to generate this plot.")

    st.markdown("---")
    g_col3, g_col4 = st.columns(2)
    with g_col3:
        st.subheader("Tier 1 Behavioral Anomaly Outlier Hierarchy")
        t1_img_path = os.path.join(BASE_DIR, "ml/reports/shap/tier1_anomaly_importance.png")
        if os.path.exists(t1_img_path):
            st.image(t1_img_path, caption="Isolation Forest Tree-Path Deviance Ranking", use_container_width=True)

    with g_col4:
        st.subheader("Tier 3 MITRE Attack Family Contrasts")
        t3_img_path = os.path.join(BASE_DIR, "ml/reports/shap/tier3_family_comparison.png")
        if os.path.exists(t3_img_path):
            st.image(t3_img_path, caption="Contrasting Feature Drivers Across MITRE Attack Families", use_container_width=True)
