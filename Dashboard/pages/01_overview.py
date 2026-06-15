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

st.markdown("### 📊 Overview")
st.caption("Detection coverage across all validated ATT&CK tactics and techniques")

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
m1, m2, m3, m4 = st.columns(4)
total = stats.get("total_techniques", 0)
detected = stats.get("detected", 0)
missed = total - detected
m1.metric("Total Techniques", total)
m2.metric("Detected", detected)
m3.metric("Missed", missed)
m4.metric("Detection Rate", f"{stats.get('detection_rate', 0)}%")

st.markdown("---")

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
tab_bar, tab_radar, tab_timeline = st.tabs([
    "📊 Tactic Coverage", "🎯 Coverage Radar", "📈 Timeline"
])

with tab_bar:
    if tactic_data:
        st.plotly_chart(tactic_coverage_bar(tactic_data), use_container_width=True)

with tab_radar:
    if tactic_data:
        st.plotly_chart(technique_radar(tactic_data), use_container_width=True)

with tab_timeline:
    st.plotly_chart(detection_timeline(detections), use_container_width=True)
