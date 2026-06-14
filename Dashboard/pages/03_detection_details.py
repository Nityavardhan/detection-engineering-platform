import streamlit as st
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_all_detections, get_detection_by_technique

st.title("🔍 Detection Details")

detections = get_all_detections()
if not detections:
    st.warning("No detections found.")
    st.stop()

technique_ids = sorted(set(d["technique_id"] for d in detections))
selected = st.selectbox("Select Technique", technique_ids)

if selected:
    det = get_detection_by_technique(selected)
    if det:
        col1, col2, col3 = st.columns(3)
        col1.metric("Result", det["detection_result"])
        col2.metric("Severity", det["severity"])
        col3.metric("False Positive Risk", det.get("false_positive_risk", "N/A"))
        
        st.markdown("---")
        
        import json
        rules = json.loads(det.get("triggered_rules", "[]"))
        eids = json.loads(det.get("event_ids_observed", "[]"))
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Triggered Rules")
            for r in rules:
                st.write(f"✅ `{r}`")
        with col2:
            st.subheader("Event IDs Observed")
            for e in eids:
                st.write(f"📋 EID {e}")
        
        st.markdown("---")
        
        # Playbook viewer
        playbook_path = Path(det.get("playbook_path", ""))
        if playbook_path.exists():
            st.subheader("📖 IR Playbook")
            st.markdown(playbook_path.read_text(encoding="utf-8"))
            with open(playbook_path) as f:
                st.download_button(
                    "⬇️ Download Playbook",
                    f.read(),
                    file_name=playbook_path.name
                )
        
        # Report viewer
        report_path = Path(det.get("report_path", ""))
        if report_path.exists():
            with st.expander("📄 Full Detection Report"):
                st.markdown(report_path.read_text(encoding="utf-8"))