"""
IR Playbooks Page — Browse, read, and bulk-download generated playbooks.
"""

import streamlit as st
from pathlib import Path
import zipfile
import io

# ── Custom Header ─────────────────────────────────────────────
st.markdown("""
<div class="hero-banner" style="padding: 24px;">
    <h1 class="hero-title" style="font-size: 2.2rem;">IR Playbooks</h1>
    <p class="hero-subtitle">Generated Incident Response playbooks for all validated techniques</p>
</div>
""", unsafe_allow_html=True)

playbooks_dir = Path("playbooks/generated")

if not playbooks_dir.exists() or not list(playbooks_dir.glob("*.md")):
    st.info("No playbooks generated yet. Run `python launch.py` first.")
    st.stop()

playbook_files = sorted(playbooks_dir.glob("*.md"))

# ── Metrics + Download ───────────────────────────────────────
col_metric, col_dl = st.columns([2, 1])

with col_metric:
    st.markdown(f"""
    <div class="metric-grid" style="margin-bottom:0;">
        <div class="metric-card" style="padding:20px;">
            <div class="metric-label">Total Playbooks</div>
            <div class="metric-value" style="color: var(--neon-cyan); font-size:2rem;">{len(playbook_files)}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_dl:
    st.markdown('<div class="chart-container" style="height:100%; display:flex; flex-direction:column; justify-content:center; align-items:center; padding:20px;">', unsafe_allow_html=True)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for pb in playbook_files:
            zf.write(pb, pb.name)
    st.download_button(
        "⬇ Download All (ZIP)",
        zip_buffer.getvalue(),
        file_name="ir_playbooks.zip",
        mime="application/zip",
        use_container_width=True
    )
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Playbook Browser ─────────────────────────────────────────
st.markdown('<div class="section-title">Playbook Browser</div>', unsafe_allow_html=True)

# Build display names: "T1059.001 — PowerShell" style
display_names = {}
for f in playbook_files:
    stem = f.stem.replace("_playbook", "")
    display_names[f"{stem}"] = f

selected_key = st.selectbox(
    "Select Playbook",
    list(display_names.keys()),
    label_visibility="collapsed",
)

if selected_key:
    pb_path = display_names[selected_key]
    content = pb_path.read_text(encoding="utf-8")

    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    # Individual download
    st.download_button(
        f"⬇ Download {selected_key}",
        content,
        file_name=pb_path.name,
        mime="text/markdown",
    )

    st.markdown("<hr style='border-color:rgba(255,255,255,0.05); margin: 20px 0;'>", unsafe_allow_html=True)
    st.markdown(content)
    st.markdown('</div>', unsafe_allow_html=True)