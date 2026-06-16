"""
ATT&CK Coverage Page — Tactic heatmap, Navigator layer download, technique table.
"""

import streamlit as st
import plotly.graph_objects as go
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_all_detections

# ── Custom Header ─────────────────────────────────────────────
st.markdown("""
<div class="hero-banner" style="padding: 24px;">
    <h1 class="hero-title" style="font-size: 2.2rem;">ATT&CK Coverage</h1>
    <p class="hero-subtitle">Technique-level detection results mapped to the MITRE ATT&CK framework</p>
</div>
""", unsafe_allow_html=True)

try:
    detections = get_all_detections()
except Exception:
    detections = []

if not detections:
    st.info("No detection data found. Run the pipeline first.")
    st.stop()

# ── ATT&CK Heatmap (Tactic × Technique matrix) ─────────────
import pandas as pd

# Build per-technique latest results
latest = {}
for d in detections:
    tid = d.get("technique_id", "")
    if tid not in latest:
        latest[tid] = d

records = []
for tid, d in sorted(latest.items()):
    records.append({
        "Technique": tid,
        "Name": d.get("technique_name", ""),
        "Tactic": d.get("tactic", "Unknown"),
        "Result": d.get("detection_result", "MISSED"),
        "Severity": d.get("severity", "MEDIUM"),
    })

df = pd.DataFrame(records)

# ── Metrics ──────────────────────────────────────────────────
tech_cov = len(df)
tac_cov = df["Tactic"].nunique()
detected_pct = round(len(df[df["Result"] == "DETECTED"]) / len(df) * 100, 1) if len(df) > 0 else 0

st.markdown(f"""
<div class="metric-grid">
    <div class="metric-card">
        <div class="metric-label">Techniques Covered</div>
        <div class="metric-value" style="color: var(--neon-cyan);">{tech_cov}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Tactics Covered</div>
        <div class="metric-value" style="color: var(--neon-purple);">{tac_cov}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Fully Detected</div>
        <div class="metric-value" style="color: var(--neon-emerald);">{detected_pct}%</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Technique × Result Treemap ────────────────────────────────
RESULT_COLORS = {"DETECTED": "#10b981", "PARTIAL": "#f59e0b", "MISSED": "#f43f5e"}

parents = []
labels = []
values = []
colors = []

for _, row in df.iterrows():
    tactic = row["Tactic"]
    tid = row["Technique"]
    result = row["Result"]

    if tactic not in labels:
        labels.append(tactic)
        parents.append("")
        values.append(0)
        colors.append("#0f172a")

    labels.append(f"{tid}")
    parents.append(tactic)
    values.append(1)
    colors.append(RESULT_COLORS.get(result, "#64748b"))

fig = go.Figure(go.Treemap(
    labels=labels,
    parents=parents,
    values=values,
    marker=dict(colors=colors, line=dict(width=3, color="#030712")),
    textfont=dict(size=14, family="Outfit", color="#f8fafc", weight="bold"),
    hovertemplate="<b>%{label}</b><extra></extra>",
    pathbar=dict(visible=False),
))

fig.update_layout(
    title=dict(text="TECHNIQUE COVERAGE MAP", font=dict(size=11, color="#64748b", family="Outfit")),
    height=480,
    margin=dict(l=0, r=0, t=40, b=0),
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Outfit", color="#94a3b8"),
)

st.markdown('<div class="chart-container">', unsafe_allow_html=True)
st.plotly_chart(fig, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# ── Detailed Table ───────────────────────────────────────────
st.markdown('<div class="section-title">Technique Details</div>', unsafe_allow_html=True)

from Dashboard.components.tables import styled_detections_table

st.markdown('<div class="chart-container" style="padding:0; overflow:hidden;">', unsafe_allow_html=True)
st.dataframe(
    styled_detections_table(df),
    use_container_width=True,
    hide_index=True,
    height=min(len(df) * 45 + 40, 600),
)
st.markdown('</div>', unsafe_allow_html=True)

# ── Navigator Layer Download ─────────────────────────────────
col_nav, col_info = st.columns([1, 2])
layer_path = Path("attack_coverage/coverage_layer.json")

with col_nav:
    st.markdown('<div class="chart-container" style="height:100%;">', unsafe_allow_html=True)
    st.markdown('<div class="section-title" style="font-size:1rem;">Navigator Layer</div>', unsafe_allow_html=True)
    if layer_path.exists():
        layer_json = layer_path.read_text(encoding="utf-8")
        layer_data = json.loads(layer_json)
        tech_len = len(layer_data.get("techniques", []))
        st.markdown(f'<div style="font-size:2rem; font-weight:700; color:var(--neon-cyan); margin-bottom:16px;">{tech_len} <span style="font-size:1rem;color:var(--text-muted);font-weight:400;">Layer Rules</span></div>', unsafe_allow_html=True)
        st.download_button(
            label="Download JSON Layer",
            data=layer_json,
            file_name="coverage_layer.json",
            mime="application/json",
            use_container_width=True
        )
    else:
        st.warning("Layer not yet generated.")
    st.markdown('</div>', unsafe_allow_html=True)

with col_info:
    st.markdown('<div class="chart-container" style="height:100%;">', unsafe_allow_html=True)
    st.markdown('<div class="section-title" style="font-size:1rem;">How to Use</div>', unsafe_allow_html=True)
    st.markdown("""
    1. Download the Navigator layer JSON file.
    2. Go to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
    3. Click **Open Existing Layer** → **Upload from local**.
    4. Select the downloaded `coverage_layer.json`.
    5. View your detection coverage heatmap mapping!
    """)
    st.markdown('</div>', unsafe_allow_html=True)