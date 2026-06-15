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

st.markdown("### 📋 Compliance Coverage")
st.caption("Detection coverage mapped to NIST CSF, CIS Controls v8, and ISO 27001:2022")

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
cols = st.columns(len(frameworks))
for i, fw in enumerate(frameworks):
    fdf = df[df["framework"] == fw]
    cols[i].metric(fw, f"{len(fdf)} controls")

st.markdown("---")

# ── Coverage Chart ───────────────────────────────────────────
st.plotly_chart(compliance_coverage_bar(coverage), use_container_width=True)

st.markdown("---")

# ── Per-Framework Tables ─────────────────────────────────────
st.markdown("### Framework Details")

tabs = st.tabs([f"📋 {fw}" for fw in frameworks])

for i, fw in enumerate(frameworks):
    with tabs[i]:
        fdf = df[df["framework"] == fw].copy()

        # Summary row
        c1, c2 = st.columns([1, 3])
        with c1:
            st.metric("Controls Covered", len(fdf))
            st.metric("Techniques Mapped", int(fdf["technique_count"].sum()))

        with c2:
            display_df = fdf[["control_id", "control_name", "technique_count"]].rename(columns={
                "control_id": "Control ID",
                "control_name": "Control Name",
                "technique_count": "Techniques",
            })
            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True,
                height=min(len(display_df) * 40 + 50, 500),
            )