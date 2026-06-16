"""
Compliance Coverage Page — Framework breakdown with charts and pivot table.
"""

import streamlit as st
import pandas as pd
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_compliance_coverage
from Dashboard.components.charts import compliance_coverage_bar

# ── Custom Header ─────────────────────────────────────────────
st.markdown("""
<div class="hero-banner" style="padding: 24px;">
    <h1 class="hero-title" style="font-size: 2.2rem;">Compliance Coverage</h1>
    <p class="hero-subtitle">Detection coverage mapped to NIST CSF, CIS Controls v8, and ISO 27001:2022</p>
</div>
""", unsafe_allow_html=True)

try:
    coverage = get_compliance_coverage()
except Exception:
    coverage = []

if not coverage:
    st.info("No compliance data found. Run the pipeline first.")
    st.stop()

df = pd.DataFrame(coverage)

# ── Summary Metrics ──────────────────────────────────────────
frameworks = df["framework"].unique()

metric_html = '<div class="metric-grid">'
colors = ["var(--neon-blue)", "var(--neon-emerald)", "var(--neon-purple)", "var(--neon-cyan)"]
for i, fw in enumerate(frameworks):
    fdf = df[df["framework"] == fw]
    c = colors[i % len(colors)]
    metric_html += f"""
    <div class="metric-card">
        <div class="metric-label">{fw}</div>
        <div class="metric-value" style="color: {c}; font-size:2rem;">{len(fdf)}</div>
        <div style="color:var(--text-muted); font-size:0.8rem; margin-top:4px;">Controls</div>
    </div>
    """
metric_html += "</div>"

st.markdown(metric_html, unsafe_allow_html=True)


# ── Coverage Chart ───────────────────────────────────────────
st.markdown('<div class="section-title">Framework Analytics</div>', unsafe_allow_html=True)
st.markdown('<div class="chart-container">', unsafe_allow_html=True)
st.plotly_chart(compliance_coverage_bar(coverage), use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)


# ── Per-Framework Tables ─────────────────────────────────────
st.markdown('<div class="section-title">Framework Details</div>', unsafe_allow_html=True)

st.markdown('<div class="chart-container" style="padding:0; background:transparent; border:none; box-shadow:none;">', unsafe_allow_html=True)
tabs = st.tabs([f"{fw}" for fw in frameworks])

for i, fw in enumerate(frameworks):
    with tabs[i]:
        st.markdown('<div class="chart-container" style="margin-top:10px;">', unsafe_allow_html=True)
        fdf = df[df["framework"] == fw].copy()

        # Summary row
        c1, c2 = st.columns([1, 3])
        with c1:
            st.markdown(f"""
            <div style="margin-bottom:20px;">
                <div style="font-size:0.85rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">Controls Covered</div>
                <div style="font-size:2rem; font-weight:800; color:var(--neon-cyan);">{len(fdf)}</div>
            </div>
            <div>
                <div style="font-size:0.85rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">Techniques Mapped</div>
                <div style="font-size:2rem; font-weight:800; color:var(--neon-purple);">{int(fdf["technique_count"].sum())}</div>
            </div>
            """, unsafe_allow_html=True)

        with c2:
            display_df = fdf[["control_id", "control_name", "technique_count"]].rename(columns={
                "control_id": "Control ID",
                "control_name": "Control Name",
                "technique_count": "Techniques",
            })
            
            # Use raw dataframe since no special coloring needed, but standard styling applies
            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True,
                height=min(len(display_df) * 45 + 40, 450),
            )
        st.markdown('</div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)