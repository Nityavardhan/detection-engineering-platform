"""
Detection Details Page — Deep-dive into individual technique results.
"""

import streamlit as st
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.db_manager import get_all_detections, get_detection_by_technique

# ── Custom Header ─────────────────────────────────────────────
st.markdown("""
<div class="hero-banner" style="padding: 24px;">
    <h1 class="hero-title" style="font-size: 2.2rem;">Detection Details</h1>
    <p class="hero-subtitle">Deep-dive into individual technique detection results, rules, and playbooks</p>
</div>
""", unsafe_allow_html=True)

try:
    detections = get_all_detections()
except Exception:
    detections = []

if not detections:
    st.info("No detections found. Run the pipeline first.")
    st.stop()

# ── Technique Selector ──────────────────────────────────────
st.markdown('<div class="section-title">Select Technique</div>', unsafe_allow_html=True)

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
<div class="chart-container" style="padding: 20px; display:flex; gap:16px; align-items:center; margin-bottom:24px;">
    <span class="status-badge badge-{result_class}">{result}</span>
    <span class="status-badge badge-{severity_class}">{severity}</span>
    <span style="color:var(--text-muted); font-size:0.9rem; margin-left:auto; font-weight:500;">
        FP Risk: <span style="color:var(--text-main);">{det.get('false_positive_risk', 'N/A')}</span>
    </span>
</div>
""", unsafe_allow_html=True)

# ── Details Grid ─────────────────────────────────────────────
col_rules, col_eids = st.columns(2)

rules = json.loads(det.get("triggered_rules", "[]"))
eids = json.loads(det.get("event_ids_observed", "[]"))

with col_rules:
    st.markdown('<div class="section-title" style="font-size:1rem;">Triggered Rules</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-container" style="min-height: 150px;">', unsafe_allow_html=True)
    if rules:
        for r in rules:
            st.markdown(f"""
            <div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.3);
                        border-radius:6px; padding:12px 16px; margin-bottom:8px;
                        font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:var(--neon-emerald);
                        box-shadow: 0 2px 10px rgba(0,0,0,0.2);">
                <span style="margin-right:8px; font-weight:bold;">✓</span> {r}
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("<p style='color:var(--text-faint); font-size:0.9rem;'>No rules triggered.</p>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_eids:
    st.markdown('<div class="section-title" style="font-size:1rem;">Event IDs Observed</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-container" style="min-height: 150px;">', unsafe_allow_html=True)
    if eids:
        eid_html = " ".join(
            f'<span style="display:inline-block; background:rgba(168, 85, 247, 0.15); '
            f'border:1px solid rgba(168, 85, 247, 0.4); border-radius:6px; '
            f'padding:8px 16px; margin:4px; font-family:\'JetBrains Mono\',monospace; '
            f'font-size:0.9rem; font-weight:600; color:var(--neon-purple);'
            f'box-shadow: 0 2px 10px rgba(0,0,0,0.2);">EID {e}</span>'
            for e in eids
        )
        st.markdown(eid_html, unsafe_allow_html=True)
    else:
        st.markdown("<p style='color:var(--text-faint); font-size:0.9rem;'>No event IDs recorded.</p>", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ── Playbook & Report Viewers ────────────────────────────────
st.markdown('<div class="section-title">Artifacts</div>', unsafe_allow_html=True)
st.markdown('<div class="chart-container" style="padding:0; background:transparent; border:none; box-shadow:none;">', unsafe_allow_html=True)

tab_playbook, tab_report = st.tabs(["IR Playbook", "Detection Report"])

with tab_playbook:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    playbook_path = Path(det.get("playbook_path", ""))
    if playbook_path.exists():
        content = playbook_path.read_text(encoding="utf-8")
        st.download_button(
            "⬇ Download Playbook",
            content,
            file_name=playbook_path.name,
            mime="text/markdown",
        )
        st.markdown("<hr style='border-color:rgba(255,255,255,0.05);'>", unsafe_allow_html=True)
        st.markdown(content)
    else:
        st.info("Playbook not found for this technique.")
    st.markdown('</div>', unsafe_allow_html=True)

with tab_report:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    report_path = Path(det.get("report_path", ""))
    if report_path.exists():
        content = report_path.read_text(encoding="utf-8")
        st.download_button(
            "⬇ Download Report",
            content,
            file_name=report_path.name,
            mime="text/markdown",
        )
        st.markdown("<hr style='border-color:rgba(255,255,255,0.05);'>", unsafe_allow_html=True)
        st.markdown(content)
    else:
        st.info("Report not found for this technique.")
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)