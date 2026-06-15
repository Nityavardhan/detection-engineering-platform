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

st.markdown("### 🗺️ ATT&CK Coverage")
st.caption("Technique-level detection results mapped to the MITRE ATT&CK framework")

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
c1, c2, c3 = st.columns(3)
c1.metric("Techniques Covered", len(df))
c2.metric("Tactics Covered", df["Tactic"].nunique())
detected_pct = round(len(df[df["Result"] == "DETECTED"]) / len(df) * 100, 1) if len(df) > 0 else 0
c3.metric("Fully Detected", f"{detected_pct}%")

st.markdown("---")

# ── Technique × Result Treemap ────────────────────────────────
RESULT_COLORS = {"DETECTED": "#10b981", "PARTIAL": "#f59e0b", "MISSED": "#ef4444"}

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
        colors.append("#1e293b")

    labels.append(f"{tid}")
    parents.append(tactic)
    values.append(1)
    colors.append(RESULT_COLORS.get(result, "#64748b"))

fig = go.Figure(go.Treemap(
    labels=labels,
    parents=parents,
    values=values,
    marker=dict(colors=colors, line=dict(width=2, color="#0a0e17")),
    textfont=dict(size=12, family="Inter", color="white"),
    hovertemplate="<b>%{label}</b><extra></extra>",
    pathbar=dict(visible=False),
))

fig.update_layout(
    title=dict(text="TECHNIQUE COVERAGE MAP", font=dict(size=12, color="#64748b", family="Inter")),
    height=450,
    margin=dict(l=8, r=8, t=50, b=8),
    plot_bgcolor="rgba(0,0,0,0)",
    paper_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter", color="#94a3b8"),
)

st.plotly_chart(fig, use_container_width=True)

# ── Detailed Table ───────────────────────────────────────────
st.markdown("---")

st.markdown("### Technique Details")

from Dashboard.components.tables import styled_detections_table
st.dataframe(
    styled_detections_table(df),
    use_container_width=True,
    hide_index=True,
    height=min(len(df) * 40 + 50, 600),
)

# ── Navigator Layer Download ─────────────────────────────────
st.markdown("---")

col_nav, col_info = st.columns([1, 2])
layer_path = Path("attack_coverage/coverage_layer.json")

with col_nav:
    st.markdown("### Navigator Layer")
    if layer_path.exists():
        layer_json = layer_path.read_text(encoding="utf-8")
        layer_data = json.loads(layer_json)
        st.metric("Techniques in Layer", len(layer_data.get("techniques", [])))
        st.download_button(
            label="Download Navigator Layer",
            data=layer_json,
            file_name="coverage_layer.json",
            mime="application/json",
        )
    else:
        st.warning("Layer not yet generated.")

with col_info:
    st.markdown("### How to Use")
    st.markdown("""
1. Download the Navigator layer JSON file
2. Go to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
3. Click **Open Existing Layer** → **Upload from local**
4. Select the downloaded `coverage_layer.json`
5. View your detection coverage heatmap
    """)