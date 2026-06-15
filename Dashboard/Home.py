"""
Detection Engineering Platform — Streamlit Dashboard
Main entry point. Renders the home page with hero section,
key metrics, charts, and the recent detections table.
"""

import streamlit as st
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

st.set_page_config(
    page_title="Detection Engineering Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load CSS
css_path = Path(__file__).parent / "assets" / "style.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text(encoding='utf-8')}</style>",
                unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────────
st.sidebar.markdown("""
<div style="text-align:center; padding: 16px 0 8px 0;">
    <div style="font-size:2.2rem; margin-bottom:4px;">🛡️</div>
    <div style="font-size:1rem; font-weight:700; color:#f1f5f9; letter-spacing:-0.3px;">
        Detection Platform
    </div>
    <div style="font-size:0.7rem; color:#64748b; text-transform:uppercase; letter-spacing:1.5px; margin-top:4px;">
        Security Operations
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")



# ── Data Loading ─────────────────────────────────────────────────
from core.db_manager import get_summary_stats, get_all_detections

try:
    stats = get_summary_stats()
    detections = get_all_detections()
except Exception:
    stats = {"total_techniques": 0, "detected": 0, "detection_rate": 0,
             "severity_distribution": {}, "tactic_distribution": {}}
    detections = []

# ── Hero Section ─────────────────────────────────────────────────
st.markdown("""
<div style="margin-bottom: 8px;">
    <h1 style="margin-bottom:4px !important; font-size:2.2rem !important;">
        Detection Engineering & IR Platform
    </h1>
    <p class="hero-subtitle" style="margin-top:0 !important;">
        ATT&CK Simulation &rarr; Detection Validation &rarr; Playbook Generation
    </p>
</div>
""", unsafe_allow_html=True)

# ── Key Metrics ──────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
m1.metric("Techniques Validated", stats.get("total_techniques", 0))
m2.metric("Detected", stats.get("detected", 0))
m3.metric("Detection Rate", f"{stats.get('detection_rate', 0)}%")
m4.metric("Tactics Covered", len(stats.get("tactic_distribution", {})))

st.markdown("")  # spacer

if not detections:
    st.markdown("---")
    st.info("**No detection data yet.** Run the pipeline to populate the dashboard:\n\n"
            "```\npython launch.py\n```")
    st.stop()

# ── Charts Row ───────────────────────────────────────────────────
from Dashboard.components.charts import detection_rate_gauge, severity_donut

col_gauge, col_donut = st.columns(2)
with col_gauge:
    st.plotly_chart(detection_rate_gauge(stats.get("detection_rate", 0)),
                    use_container_width=True)

severity_dist = stats.get("severity_distribution", {})
if severity_dist:
    with col_donut:
        st.plotly_chart(severity_donut(severity_dist), use_container_width=True)

# ── Recent Detections Table ──────────────────────────────────────
st.markdown("---")
st.markdown("### Recent Detections")

import pandas as pd

df = pd.DataFrame(detections)
display_cols = ["technique_id", "technique_name", "tactic",
                "detection_result", "severity", "test_timestamp"]
available = [c for c in display_cols if c in df.columns]
df_display = df[available].copy()
col_names = ["Technique", "Name", "Tactic", "Result", "Severity", "Validated"]
df_display.columns = col_names[:len(available)]

# Deduplicate — show only the latest run per technique
if "Technique" in df_display.columns and "Validated" in df_display.columns:
    df_display = df_display.sort_values("Validated", ascending=False)
    df_display = df_display.drop_duplicates(subset=["Technique"], keep="first")
    df_display = df_display.sort_values("Technique")

from Dashboard.components.tables import styled_detections_table
st.dataframe(
    styled_detections_table(df_display),
    use_container_width=True,
    hide_index=True,
    height=min(len(df_display) * 40 + 50, 600),
)