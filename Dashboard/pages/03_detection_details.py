"""
Detection Details Page — Deep-dive into individual technique results.
"""

import streamlit as st
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_all_detections, get_detection_by_technique

st.markdown("### 🔍 Detection Details")
st.caption("Deep-dive into individual technique detection results, rules, and playbooks")

try:
    detections = get_all_detections()
except Exception:
    detections = []

if not detections:
    st.info("No detections found. Run the pipeline first.")
    st.stop()

# ── Technique Selector ──────────────────────────────────────
technique_ids = sorted(set(d["technique_id"] for d in detections))
technique_names = {}
for d in detections:
    technique_names[d["technique_id"]] = d.get("technique_name", "")

options = [f"{tid} — {technique_names.get(tid, '')}" for tid in technique_ids]
selected_option = st.selectbox("Select Technique", options, label_visibility="collapsed")
selected = selected_option.split(" — ")[0] if selected_option else None

if not selected:
    st.stop()

det = get_detection_by_technique(selected)
if not det:
    st.warning(f"No detection record found for {selected}.")
    st.stop()

# ── Result Badge HTML ────────────────────────────────────────
result = det["detection_result"]
severity = det.get("severity", "MEDIUM")
result_class = result.lower()
severity_class = severity.lower()

st.markdown(f"""
<div style="display:flex; gap:12px; align-items:center; margin: 12px 0 20px 0;">
    <span class="status-badge badge-{result_class}">{result}</span>
    <span class="status-badge badge-{severity_class}">{severity}</span>
    <span style="color:#64748b; font-size:0.8rem; margin-left:8px;">
        FP Risk: {det.get('false_positive_risk', 'N/A')}
    </span>
</div>
""", unsafe_allow_html=True)

# ── Details Grid ─────────────────────────────────────────────
col_rules, col_eids = st.columns(2)

rules = json.loads(det.get("triggered_rules", "[]"))
eids = json.loads(det.get("event_ids_observed", "[]"))

with col_rules:
    st.markdown("##### Triggered Rules")
    if rules:
        for r in rules:
            st.markdown(f"""
            <div style="background:rgba(16,185,129,0.08); border:1px solid rgba(16,185,129,0.2);
                        border-radius:8px; padding:10px 14px; margin-bottom:6px;
                        font-family:'JetBrains Mono',monospace; font-size:0.82rem; color:#10b981;">
                ✓ {r}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("<p style='color:#64748b; font-size:0.85rem;'>No rules triggered</p>",
                    unsafe_allow_html=True)

with col_eids:
    st.markdown("##### Event IDs Observed")
    if eids:
        eid_html = " ".join(
            f'<span style="display:inline-block; background:rgba(99,102,241,0.12); '
            f'border:1px solid rgba(99,102,241,0.25); border-radius:6px; '
            f'padding:6px 14px; margin:3px; font-family:\'JetBrains Mono\',monospace; '
            f'font-size:0.85rem; color:#a78bfa;">EID {e}</span>'
            for e in eids
        )
        st.markdown(eid_html, unsafe_allow_html=True)
    else:
        st.markdown("<p style='color:#64748b; font-size:0.85rem;'>No event IDs recorded</p>",
                    unsafe_allow_html=True)

st.markdown("---")

# ── Playbook & Report Viewers ────────────────────────────────
tab_playbook, tab_report = st.tabs(["📖 IR Playbook", "📄 Detection Report"])

with tab_playbook:
    playbook_path = Path(det.get("playbook_path", ""))
    if playbook_path.exists():
        content = playbook_path.read_text(encoding="utf-8")
        st.markdown(content)
        st.download_button(
            "Download Playbook",
            content,
            file_name=playbook_path.name,
            mime="text/markdown",
        )
    else:
        st.info("Playbook not found for this technique. Re-run the pipeline.")

with tab_report:
    report_path = Path(det.get("report_path", ""))
    if report_path.exists():
        content = report_path.read_text(encoding="utf-8")
        st.markdown(content)
        st.download_button(
            "Download Report",
            content,
            file_name=report_path.name,
            mime="text/markdown",
        )
    else:
        st.info("Report not found for this technique. Re-run the pipeline.")