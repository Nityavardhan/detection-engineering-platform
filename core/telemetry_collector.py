import subprocess
import shutil
from pathlib import Path
from datetime import datetime
import json
from rich.console import Console
import yaml

console = Console()

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)


def collect_evtx(technique_id: str, channels: list = None) -> dict:
    """
    Export EVTX files for the specified log channels.
    Returns dict with paths to exported files.
    """
    if channels is None:
        channels = list(CONFIG["lab"]["windows_log_channels"].values())
    
    # Create evidence directory
    evidence_dir = Path(CONFIG["paths"]["evidence_base"]) / technique_id / "raw"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
    exported = {}
    timestamp = datetime.now().isoformat()
    
    for channel_name, channel_path in CONFIG["lab"]["windows_log_channels"].items():
        safe_name = channel_path.replace("/", "_").replace("-", "_")
        output_file = evidence_dir / f"{safe_name}.evtx"
        
        console.print(f"  [cyan]Collecting:[/cyan] {channel_path}")
        
        result = subprocess.run(
            ["wevtutil.exe", "epl", channel_path, str(output_file)],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            exported[channel_name] = str(output_file)
            console.print(f"  [green]✓[/green] {channel_name}")
        else:
            console.print(f"  [red]✗[/red] {channel_name}: {result.stderr.strip()}")
    
    # Write metadata
    metadata = {
        "technique_id": technique_id,
        "collection_timestamp": timestamp,
        "exported_channels": exported,
        "evidence_directory": str(evidence_dir.parent)
    }
    
    metadata_path = evidence_dir.parent / "metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    
    console.print(f"[green]✓ Telemetry collected → {evidence_dir.parent}[/green]")
    return exported


def copy_existing_evtx(technique_id: str, source_paths: list) -> dict:
    """
    Alternative: copy already-exported EVTX files into the evidence directory.
    Use this if you exported EVTX manually before running the pipeline.
    """
    evidence_dir = Path(CONFIG["paths"]["evidence_base"]) / technique_id / "raw"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
    copied = {}
    for src in source_paths:
        src_path = Path(src)
        dst_path = evidence_dir / src_path.name
        shutil.copy2(src_path, dst_path)
        copied[src_path.stem] = str(dst_path)
        console.print(f"  [green]✓ Copied:[/green] {src_path.name}")
    
    return copied