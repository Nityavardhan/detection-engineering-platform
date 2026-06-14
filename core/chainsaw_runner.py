import subprocess
import json
from pathlib import Path
from rich.console import Console
import yaml

console = Console()

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)


def run_chainsaw(evtx_dir: str, technique_id: str, sigma_rules_dir: str = None) -> dict:
    """
    Run Chainsaw against an EVTX directory using Sigma rules.
    Returns parsed detection results.
    """
    if sigma_rules_dir is None:
        sigma_rules_dir = CONFIG["paths"]["sigma_rules_dir"]
    
    chainsaw_exe = CONFIG["paths"]["chainsaw_exe"]
    output_dir = Path(CONFIG["paths"]["evidence_base"]) / technique_id / "detections"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "chainsaw_results.json"

    evtx_path = Path(evtx_dir)
    if not evtx_path.exists() or not any(evtx_path.glob("*.evtx")):
        demo_hits = generate_demo_hits(technique_id)
        if demo_hits:
            console.print("  [green]Offline demo mode enabled: generated synthetic detections from the local rule set.[/green]")
            return {"hits": demo_hits, "rule_count": len(demo_hits), "output_path": str(output_file), "offline_mode": True}

        console.print("  [yellow]No EVTX telemetry is available in this environment; continuing in offline mode.[/yellow]")
        return {"hits": [], "rule_count": 0, "output_path": str(output_file), "offline_mode": True}

    if not Path(chainsaw_exe).exists():
        demo_hits = generate_demo_hits(technique_id)
        if demo_hits:
            console.print("  [green]Offline demo mode enabled: generated synthetic detections from the local rule set.[/green]")
            return {"hits": demo_hits, "rule_count": len(demo_hits), "output_path": str(output_file), "offline_mode": True}

        console.print("  [yellow]Chainsaw is not available in this environment; continuing in offline mode.[/yellow]")
        return {"hits": [], "rule_count": 0, "output_path": str(output_file), "offline_mode": True}

    if sigma_rules_dir and not Path(sigma_rules_dir).exists():
        demo_hits = generate_demo_hits(technique_id)
        if demo_hits:
            console.print("  [green]Offline demo mode enabled: generated synthetic detections from the local rule set.[/green]")
            return {"hits": demo_hits, "rule_count": len(demo_hits), "output_path": str(output_file), "offline_mode": True}

        console.print("  [yellow]Sigma rules are not available in this environment; continuing in offline mode.[/yellow]")
        return {"hits": [], "rule_count": 0, "output_path": str(output_file), "offline_mode": True}

    console.print(f"  [cyan]Running Chainsaw...[/cyan]")

    cmd = [
        chainsaw_exe,
        "hunt",
        evtx_dir,
        "--sigma", sigma_rules_dir,
        "--mapping", "mappings/sigma-event-logs-all.yml",  # Chainsaw mapping file
        "--output", str(output_file),
        "--format", "json",
        "--quiet"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0 and "error" in result.stderr.lower():
        console.print(f"  [red]Chainsaw error:[/red] {result.stderr.strip()}")
        return {"hits": [], "error": result.stderr.strip(), "raw_output": ""}
    
    # Parse output
    if output_file.exists():
        with open(output_file, "r") as f:
            raw_data = f.read().strip()
        
        if not raw_data:
            return {"hits": [], "rule_count": 0, "output_path": str(output_file)}
        
        try:
            data = json.loads(raw_data)
        except json.JSONDecodeError:
            # Chainsaw sometimes outputs JSONL (one JSON per line)
            lines = [l for l in raw_data.splitlines() if l.strip()]
            data = [json.loads(l) for l in lines]
        
        hits = parse_chainsaw_output(data)
        
        console.print(f"  [green]✓ Chainsaw complete:[/green] {len(hits)} rule(s) triggered")
        return {
            "hits": hits,
            "rule_count": len(hits),
            "output_path": str(output_file)
        }
    else:
        console.print(f"  [yellow]⚠ No output file produced[/yellow]")
        return {"hits": [], "rule_count": 0}


def generate_demo_hits(technique_id: str) -> list:
    """Create deterministic demo detections from local Sigma rule files when lab tools are unavailable."""
    rule_dir = Path("detections") / technique_id / "sigma_rules"
    if not rule_dir.exists():
        return []

    demo_hits = []
    for rule_file in sorted(rule_dir.glob("*.yml")):
        try:
            with open(rule_file, "r", encoding="utf-8") as fh:
                rule = yaml.safe_load(fh) or {}
        except Exception:
            continue

        event_id = "0"
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})
        if isinstance(selection, dict):
            event_id = next((str(v) for v in selection.values() if isinstance(v, (int, str))), "0")

        demo_hits.append({
            "rule_name": rule.get("title", rule_file.stem),
            "rule_level": rule.get("level", "medium"),
            "rule_tags": rule.get("tags", []),
            "event_id": str(event_id),
            "timestamp": "2026-06-14T00:00:00Z",
            "computer": "LOCAL-DEMO-HOST",
            "matched_fields": {"DemoMode": "offline simulation", "TechniqueID": technique_id},
            "raw": {"demo": True, "rule_file": str(rule_file)}
        })

    return demo_hits[:3]


def parse_chainsaw_output(data) -> list:
    """
    Parse Chainsaw JSON output into a normalized list of hits.
    Handles both list and dict formats.
    """
    hits = []
    
    if isinstance(data, dict):
        data = [data]
    
    for item in data:
        # Chainsaw hit structure varies by version
        # This handles the common formats
        hit = {
            "rule_name": item.get("name", item.get("rule_name", "Unknown Rule")),
            "rule_level": item.get("level", "medium"),
            "rule_tags": item.get("tags", []),
            "event_id": extract_event_id(item),
            "timestamp": item.get("timestamp", ""),
            "computer": item.get("Computer", ""),
            "matched_fields": extract_matched_fields(item),
            "raw": item
        }
        hits.append(hit)
    
    return hits


def extract_event_id(item: dict) -> str:
    """Extract EventID from Chainsaw hit."""
    # Try common paths
    paths = [
        ["EventID"],
        ["event_data", "EventID"],
        ["System", "EventID"],
        ["document", "System", "EventID", "#text"]
    ]
    for path in paths:
        val = item
        for key in path:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                break
        if val and val != item:
            return str(val)
    return "Unknown"


def extract_matched_fields(item: dict) -> dict:
    """Extract the fields that caused the rule to match."""
    fields = {}
    event_data = item.get("event_data", item.get("EventData", {}))
    if isinstance(event_data, dict):
        for key in ["CommandLine", "Image", "ParentImage", "ScriptBlockText",
                    "TargetFilename", "DestinationIp", "TargetObject"]:
            if key in event_data:
                fields[key] = event_data[key]
    return fields