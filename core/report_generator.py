from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from rich.console import Console
import yaml

console = Console()


def generate_detection_report(technique_id: str, detection_result: dict,
                               attack_metadata: dict, chainsaw_results: dict) -> str:
    """
    Generate a full detection report Markdown file.
    Returns path to the generated file.
    """
    output_dir = Path("reports/generated")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    env = Environment(
        loader=FileSystemLoader("reports/templates"),
        trim_blocks=True,
        lstrip_blocks=True
    )
    template = env.get_template("detection_report_template.md")
    
    # Load detection card for additional detail
    detection_card = load_detection_card(technique_id)
    
    hits = chainsaw_results.get("hits", [])
    
    context = {
        "technique_id": technique_id,
        "technique_name": attack_metadata.get("name", ""),
        "tactic": attack_metadata.get("tactic", ""),
        "description": attack_metadata.get("description", "")[:500] + "...",
        "severity": detection_result.get("severity", "MEDIUM"),
        "detection_result": detection_result.get("detection_result", "UNKNOWN"),
        "triggered_rules": detection_result.get("triggered_rules", []),
        "event_ids": detection_result.get("event_ids_observed", []),
        "false_positive_risk": detection_result.get("false_positive_risk", "UNKNOWN"),
        "report_date": datetime.now().strftime("%Y-%m-%d"),
        "generation_time": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        "attack_url": attack_metadata.get("url", ""),
        "platforms": attack_metadata.get("platforms", []),
        "data_sources": attack_metadata.get("data_sources", []),
        "chainsaw_hits": hits,
        "hit_count": len(hits),
        "evidence_path": f"evidence/{technique_id}/",
        "detection_card": detection_card,
    }
    
    rendered = template.render(**context)
    output_path = output_dir / f"{technique_id}_detection_report.md"
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    
    console.print(f"  [green]✓ Report generated:[/green] {output_path}")
    return str(output_path)


def load_detection_card(technique_id: str) -> str:
    """Load the detection card Markdown content."""
    card_path = Path("detections") / technique_id / "detection_card.md"
    if card_path.exists():
        return card_path.read_text(encoding="utf-8")
    return "Detection card not found."