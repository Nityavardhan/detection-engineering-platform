"""
Overview Page — Detection summary, timeline, and tactic coverage charts.
"""

import streamlit as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_all_detections, get_summary_stats

st.title("📊 Overview")

try:
    detections = get_all_detections()
    stats = get_summary_stats()
except Exception:
    detections = []
    stats = {"total_techniques": 0, "detected": 0, "detection_rate": 0,
             "severity_distribution": {}, "tactic_distribution": {}}

if not detections:
    st.info("No detection data available. Run the pipeline first.")
    st.stop()

# Key metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Techniques", stats.get("total_techniques", 0))
col2.metric("Detected", stats.get("detected", 0))
col3.metric("Detection Rate", f"{stats.get('detection_rate', 0)}%")
col4.metric("Tactics Covered", len(stats.get("tactic_distribution", {})))

st.markdown("---")

# Tactic coverage chart
from Dashboard.components.charts import tactic_coverage_bar, detection_timeline

tactic_data = {}
for d in detections:
    tactic = d.get("tactic", "Unknown")
    result = d.get("detection_result", "MISSED")
    if tactic not in tactic_data:
        tactic_data[tactic] = {"DETECTED": 0, "PARTIAL": 0, "MISSED": 0}
    if result in tactic_data[tactic]:
        tactic_data[tactic][result] += 1

if tactic_data:
    fig = tactic_coverage_bar(tactic_data)
    st.plotly_chart(fig, width="stretch")

st.markdown("---")

# Detection timeline
st.subheader("Detection Timeline")
fig = detection_timeline(detections)
st.plotly_chart(fig, width="stretch")
