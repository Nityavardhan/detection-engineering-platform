import streamlit as st
from pathlib import Path
import zipfile
import io

st.title("📖 IR Playbooks")

playbooks_dir = Path("playbooks/generated")

if not playbooks_dir.exists() or not list(playbooks_dir.glob("*.md")):
    st.warning("No playbooks generated yet. Run the pipeline first.")
    st.stop()

playbook_files = sorted(playbooks_dir.glob("*.md"))

st.metric("Total Playbooks", len(playbook_files))

# Download all as ZIP
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
    for pb in playbook_files:
        zf.write(pb, pb.name)

st.download_button(
    "⬇️ Download All Playbooks (ZIP)",
    zip_buffer.getvalue(),
    file_name="ir_playbooks.zip",
    mime="application/zip"
)

st.markdown("---")

# Individual viewer
selected_pb = st.selectbox(
    "View Playbook",
    [f.stem for f in playbook_files]
)

if selected_pb:
    pb_path = playbooks_dir / f"{selected_pb}.md"
    content = pb_path.read_text(encoding="utf-8")
    st.markdown(content)
    st.download_button(
        f"⬇️ Download {selected_pb}",
        content,
        file_name=f"{selected_pb}.md"
    )