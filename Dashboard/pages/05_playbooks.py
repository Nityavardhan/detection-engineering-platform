"""
IR Playbooks Page — Browse, read, and bulk-download generated playbooks.
"""

import streamlit as st
from pathlib import Path
import zipfile
import io

st.markdown("### 📖 IR Playbooks")
st.caption("Generated Incident Response playbooks for all validated techniques")

playbooks_dir = Path("playbooks/generated")

if not playbooks_dir.exists() or not list(playbooks_dir.glob("*.md")):
    st.info("No playbooks generated yet. Run `python launch.py` first.")
    st.stop()

playbook_files = sorted(playbooks_dir.glob("*.md"))

# ── Metrics + Download ───────────────────────────────────────
col_metric, col_dl = st.columns([2, 1])

with col_metric:
    st.metric("Total Playbooks", len(playbook_files))

with col_dl:
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for pb in playbook_files:
            zf.write(pb, pb.name)
    st.download_button(
        "Download All (ZIP)",
        zip_buffer.getvalue(),
        file_name="ir_playbooks.zip",
        mime="application/zip",
    )

st.markdown("---")

# ── Playbook Browser ─────────────────────────────────────────
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

    # Individual download
    st.download_button(
        f"Download {selected_key}",
        content,
        file_name=pb_path.name,
        mime="text/markdown",
    )

    st.markdown("---")
    st.markdown(content)