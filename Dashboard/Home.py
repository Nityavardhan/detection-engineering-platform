"""
Detection Engineering Platform — Streamlit Dashboard
Main entry point. Renders the home page with hero section,
key metrics, charts, and the recent detections table.
"""

import streamlit as st
import sys
from pathlib import Path

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
<div style="text-align:center; padding: 24px 0 16px 0;">
    <div style="font-size:3rem; margin-bottom:12px; filter: drop-shadow(0 0 10px rgba(34, 211, 238, 0.5));">🛡️</div>
    <div style="font-size:1.4rem; font-weight:800; color:var(--text-main); letter-spacing:-0.5px;">
        NUCLEUS
    </div>
    <div style="font-size:0.75rem; color:var(--neon-cyan); text-transform:uppercase; letter-spacing:2px; font-weight:600; margin-top:4px;">
        Detection & IR
    </div>
</div>
<hr style="border-color: rgba(255,255,255,0.05); margin: 10px 0 20px 0;">
""", unsafe_allow_html=True)


# ── Data Loading ─────────────────────────────────────────────────
from core.db_manager import get_summary_stats, get_all_detections

try:
    stats = get_summary_stats()
    detections = get_all_detections()
except Exception:
    stats = {"total_techniques": 0, "detected": 0, "detection_rate": 0,
             "severity_distribution": {}, "tactic_distribution": {}}
    detections = []

# ── Custom HTML Hero Section ──────────────────────────────────────
st.markdown("""
<div class="hero-banner">
    <h1 class="hero-title">Platform Command Center</h1>
    <p class="hero-subtitle">
        Automated ATT&CK Simulation, Detection Validation & Playbook Engineering
    </p>
</div>
""", unsafe_allow_html=True)

# ── Custom HTML Metric Cards ──────────────────────────────────────
total = stats.get("total_techniques", 0)
detected = stats.get("detected", 0)
rate = stats.get("detection_rate", 0)
tactics = len(stats.get("tactic_distribution", {}))

st.markdown(f"""
<div class="metric-grid">
    <div class="metric-card">
        <div class="metric-label">Techniques Validated</div>
        <div class="metric-value" style="color: var(--neon-blue);">{total}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Successful Detections</div>
        <div class="metric-value" style="color: var(--neon-emerald);">{detected}</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Overall Detection Rate</div>
        <div class="metric-value" style="color: var(--neon-purple);">{rate}%</div>
    </div>
    <div class="metric-card">
        <div class="metric-label">Tactics Covered</div>
        <div class="metric-value" style="color: var(--neon-cyan);">{tactics}</div>
    </div>
</div>
""", unsafe_allow_html=True)


if not detections:
    st.markdown("""
    <div class="chart-container" style="text-align:center; padding: 60px 20px;">
        <h3 style="color: var(--neon-cyan);">No Pipeline Data Found</h3>
        <p style="color: var(--text-muted);">Run the pipeline from your terminal to populate the dashboard.</p>
        <code style="background: rgba(0,0,0,0.5); padding: 12px 24px; border-radius: 8px; font-size: 1.1rem; color: #fff;">python launch.py</code>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ── Charts Section ───────────────────────────────────────────────
from Dashboard.components.charts import detection_rate_gauge, severity_donut

st.markdown('<div class="section-title">Detection Analytics</div>', unsafe_allow_html=True)

col1, col2 = st.columns(2)
with col1:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.plotly_chart(detection_rate_gauge(stats.get("detection_rate", 0)), use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

severity_dist = stats.get("severity_distribution", {})
if severity_dist:
    with col2:
        st.markdown('<div class="chart-container">', unsafe_allow_html=True)
        st.plotly_chart(severity_donut(severity_dist), use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

# ── Recent Detections Table ──────────────────────────────────────
st.markdown('<div class="section-title">Validation Ledger</div>', unsafe_allow_html=True)

import pandas as pd
df = pd.DataFrame(detections)
display_cols = ["technique_id", "technique_name", "tactic",
                "detection_result", "severity", "test_timestamp"]
available = [c for c in display_cols if c in df.columns]
df_display = df[available].copy()
col_names = ["Technique", "Name", "Tactic", "Result", "Severity", "Validated At"]
df_display.columns = col_names[:len(available)]

# Deduplicate
if "Technique" in df_display.columns and "Validated At" in df_display.columns:
    df_display = df_display.sort_values("Validated At", ascending=False)
    df_display = df_display.drop_duplicates(subset=["Technique"], keep="first")
    df_display = df_display.sort_values("Technique")

from Dashboard.components.tables import styled_detections_table

st.markdown('<div class="chart-container" style="padding: 0; overflow: hidden;">', unsafe_allow_html=True)
st.dataframe(
    styled_detections_table(df_display),
    use_container_width=True,
    hide_index=True,
    height=min(len(df_display) * 45 + 40, 600),
)
st.markdown('</div>', unsafe_allow_html=True)