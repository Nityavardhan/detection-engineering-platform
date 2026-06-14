import streamlit as st
import plotly.express as px
import pandas as pd
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_compliance_coverage

st.title("📋 Compliance Coverage")

coverage = get_compliance_coverage()

if not coverage:
    st.warning("No compliance data found. Run the pipeline first.")
    st.stop()

df = pd.DataFrame(coverage)

# Per-framework breakdown
for framework in df["framework"].unique():
    fdf = df[df["framework"] == framework]
    st.subheader(f"**{framework}**")
    
    col1, col2 = st.columns([1, 3])
    col1.metric("Controls Covered", len(fdf))
    col1.metric("Techniques Mapped", int(fdf["technique_count"].sum()))
    
    with col2:
        st.dataframe(
            fdf[["control_id", "control_name", "technique_count"]].rename(columns={
                "control_id": "Control ID",
                "control_name": "Control Name",
                "technique_count": "Techniques"
            }),
            width="stretch"
        )
    
    st.markdown("---")