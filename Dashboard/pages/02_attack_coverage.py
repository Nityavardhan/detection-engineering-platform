import streamlit as st
import plotly.graph_objects as go
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_all_detections

st.title("📊 ATT&CK Coverage")

detections = get_all_detections()

if not detections:
    st.warning("No detection data found. Run the pipeline first.")
    st.stop()

# Tactic coverage bar chart
tactic_data = {}
for d in detections:
    tactic = d.get("tactic", "Unknown")
    result = d.get("detection_result", "MISSED")
    if tactic not in tactic_data:
        tactic_data[tactic] = {"DETECTED": 0, "PARTIAL": 0, "MISSED": 0}
    tactic_data[tactic][result] = tactic_data[tactic].get(result, 0) + 1

tactics = list(tactic_data.keys())
detected_counts = [tactic_data[t]["DETECTED"] for t in tactics]
partial_counts = [tactic_data[t]["PARTIAL"] for t in tactics]
missed_counts = [tactic_data[t]["MISSED"] for t in tactics]

fig = go.Figure(data=[
    go.Bar(name="Detected", x=tactics, y=detected_counts,
           marker_color="#2ecc71"),
    go.Bar(name="Partial", x=tactics, y=partial_counts,
           marker_color="#f39c12"),
    go.Bar(name="Missed", x=tactics, y=missed_counts,
           marker_color="#e74c3c"),
])

fig.update_layout(
    barmode="stack",
    title="Detection Coverage by ATT&CK Tactic",
    xaxis_title="Tactic",
    yaxis_title="Techniques",
    height=400
)

st.plotly_chart(fig, width="stretch")

# Navigator Layer download
st.markdown("---")
st.subheader("ATT&CK Navigator Layer")

layer_path = Path("attack_coverage/coverage_layer.json")
if layer_path.exists():
    with open(layer_path) as f:
        layer_json = f.read()
    
    st.download_button(
        label="⬇️ Download Navigator Layer (JSON)",
        data=layer_json,
        file_name="coverage_layer.json",
        mime="application/json"
    )
    st.info("Import this file at https://mitre-attack.github.io/attack-navigator/")
    
    layer_data = json.loads(layer_json)
    st.metric("Techniques in Layer", len(layer_data.get("techniques", [])))
else:
    st.warning("Navigator layer not yet generated. Run the pipeline first.")