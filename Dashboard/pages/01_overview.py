"""
Overview Page — Tactic coverage, timeline, and radar visualizations.
"""

import streamlit as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_all_detections, get_summary_stats
from Dashboard.components.charts import (
    tactic_coverage_bar, detection_timeline, technique_radar
)

# ── Custom Header ─────────────────────────────────────────────
st.markdown("""
<div class="hero-banner" style="padding: 24px;">
    <h1 class="hero-title" style="font-size: 2.2rem;">Overview & Analytics</h1>
    <p class="hero-subtitle">Detection coverage across all validated ATT&CK tactics and techniques</p>
</div>
""", unsafe_allow_html=True)

try:
    detections = get_all_detections()
    stats = get_summary_stats()
except Exception:
    detections = []
    stats = {}

if not detections:
    st.info("No detection data available. Run `python launch.py` first.")
    st.stop()

# ── Metrics Row ─────────────────────────────────────────────
total = stats.get("total_techniques", 0)
detected = stats.get("detected", 0)
missed = total - detected
rate = stats.get("detection_rate", 0)

st.markdown(f"""
<div class="metric-grid">
    <div class="metric-card">
        <div class="metric-label">Total Techniques</div>
        <div class="metric-value" style="color: var(--neon-blue);">{total}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Detected</div>
        <div class="metric-value" style="color: var(--neon-emerald);">{detected}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Missed</div>
        <div class="metric-value" style="color: var(--neon-rose);">{missed}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Detection Rate</div>
        <div class="metric-value" style="color: var(--neon-purple);">{rate}%</div>
    </div>
</div>
""", unsafe_allow_html=True)


# ── Build tactic data ──────────────────────────────────────
tactic_data = {}
for d in detections:
    tactic = d.get("tactic", "Unknown")
    result = d.get("detection_result", "MISSED")
    if tactic not in tactic_data:
        tactic_data[tactic] = {"DETECTED": 0, "PARTIAL": 0, "MISSED": 0}
    if result in tactic_data[tactic]:
        tactic_data[tactic][result] += 1

# ── Charts in Tabs ──────────────────────────────────────────
st.markdown('<div class="chart-container" style="padding:0; border:none; background:transparent; box-shadow:none;">', unsafe_allow_html=True)
tab_bar, tab_radar, tab_timeline = st.tabs([
    "Tactic Coverage", "Coverage Radar", "Timeline"
])

with tab_bar:
    if tactic_data:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.plotly_chart(tactic_coverage_bar(tactic_data), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

with tab_radar:
    if tactic_data:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.plotly_chart(technique_radar(tactic_data), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

with tab_timeline:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.plotly_chart(detection_timeline(detections), use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)
