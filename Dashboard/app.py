"""
Detection Engineering Platform — Streamlit Dashboard

Main application entry point. Loads custom CSS styling and renders
the home page with key metrics and recent detection results.

Usage:
    streamlit run Dashboard/app.py
"""

import streamlit as st
import sys
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

st.set_page_config(
    page_title="Detection Engineering Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Load custom CSS
css_path = Path(__file__).parent / "assets" / "style.css"
if css_path.exists():
    with open(css_path, encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

st.sidebar.title("🛡️ Detection Platform")
st.sidebar.markdown("---")
st.sidebar.markdown("""
**Nityavardhan**  
B.Tech CS (Cybersecurity)  
UPES Dehradun
""")

st.title("🛡️ Detection Engineering & IR Validation Platform")
st.subheader("ATT&CK Simulation → Detection Validation → IR Playbook Generation")

from core.db_manager import get_summary_stats, get_all_detections

try:
    stats = get_summary_stats()
except Exception:
    stats = {"total_techniques": 0, "detected": 0, "detection_rate": 0,
             "severity_distribution": {}, "tactic_distribution": {}}

col1, col2, col3, col4 = st.columns(4)
col1.metric("Techniques Validated", stats.get("total_techniques", 0))
col2.metric("Detected", stats.get("detected", 0))
col3.metric("Detection Rate", f"{stats.get('detection_rate', 0)}%")
col4.metric("Tactics Covered", len(stats.get("tactic_distribution", {})))

st.markdown("---")

# Detection rate gauge
from Dashboard.components.charts import detection_rate_gauge, severity_donut

col_gauge, col_donut = st.columns(2)
with col_gauge:
    fig = detection_rate_gauge(stats.get("detection_rate", 0))
    st.plotly_chart(fig, width="stretch")

severity_dist = stats.get("severity_distribution", {})
if severity_dist:
    with col_donut:
        fig = severity_donut(severity_dist)
        st.plotly_chart(fig, width="stretch")

st.markdown("---")
st.subheader("Recent Detections")

try:
    detections = get_all_detections()
except Exception:
    detections = []

if detections:
    import pandas as pd

    df = pd.DataFrame(detections)
    display_cols = ["technique_id", "technique_name", "tactic",
                    "detection_result", "severity", "test_timestamp"]
    available = [c for c in display_cols if c in df.columns]
    df_display = df[available].copy()
    df_display.columns = ["ID", "Name", "Tactic", "Result", "Severity", "Date"][:len(available)]

    from Dashboard.components.tables import styled_detections_table
    st.dataframe(
        styled_detections_table(df_display),
        width="stretch",
        hide_index=True,
    )
else:
    st.info("No detections yet. Run the pipeline to populate data:\n\n"
            "```bash\npython run_pipeline.py --technique T1059.001 --skip-collection\n```")