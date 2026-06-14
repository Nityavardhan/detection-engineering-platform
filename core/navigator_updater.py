import json
from pathlib import Path
from datetime import datetime
from rich.console import Console

console = Console()

# Color scheme for Navigator
COLORS = {
    "DETECTED": "#2ecc71",     # green
    "PARTIAL": "#f39c12",      # orange
    "MISSED": "#e74c3c",       # red
    "NOT_TESTED": "#95a5a6"    # grey
}


def load_base_layer() -> dict:
    """Load the base Navigator layer template."""
    base_path = Path("data/attack_navigator_base.json")
    
    if base_path.exists():
        with open(base_path, "r") as f:
            return json.load(f)
    
    # Create base layer if it doesn't exist
    return {
        "name": "Detection Engineering Platform Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Validated detection coverage from automated ATT&CK simulation lab",
        "filters": {
            "platforms": ["Windows"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "annotated"
        },
        "hideDisabled": False,
        "techniques": [],
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [
            {"label": "Detected", "color": "#2ecc71"},
            {"label": "Partial", "color": "#f39c12"},
            {"label": "Missed", "color": "#e74c3c"}
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }


def update_navigator_layer(technique_id: str, detection_result: str,
                            score: int = None) -> str:
    """
    Add or update a technique in the ATT&CK Navigator layer.
    Reads the existing coverage_layer.json for cumulative updates.
    Falls back to base layer template if coverage file doesn't exist yet.
    Returns path to updated layer file.
    """
    output_path = Path("attack_coverage/coverage_layer.json")
    if output_path.exists():
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                layer = json.load(f)
        except (json.JSONDecodeError, OSError):
            layer = load_base_layer()
    else:
        layer = load_base_layer()
    color = COLORS.get(detection_result, COLORS["NOT_TESTED"])
    
    if score is None:
        score_map = {"DETECTED": 100, "PARTIAL": 50, "MISSED": 0}
        score = score_map.get(detection_result, 0)
    
    # Check if technique already in layer
    existing = None
    for i, tech in enumerate(layer["techniques"]):
        if tech.get("techniqueID") == technique_id:
            existing = i
            break
    
    entry = {
        "techniqueID": technique_id,
        "score": score,
        "color": color,
        "comment": f"Validated {datetime.now().strftime('%Y-%m-%d')} | Result: {detection_result}",
        "enabled": True,
        "metadata": [
            {"name": "result", "value": detection_result},
            {"name": "validated_date", "value": datetime.now().strftime("%Y-%m-%d")}
        ],
        "links": [],
        "showSubtechniques": False
    }
    
    if existing is not None:
        layer["techniques"][existing] = entry
    else:
        layer["techniques"].append(entry)
    
    # Save
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w") as f:
        json.dump(layer, f, indent=2)
    
    console.print(f"  [green]✓ Navigator layer updated:[/green] {technique_id} → {detection_result}")
    return str(output_path)


def generate_coverage_report(all_detections: list) -> str:
    """Generate a Markdown coverage report from all detection records."""
    output_path = Path("attack_coverage/coverage_report.md")
    
    total = len(all_detections)
    detected = sum(1 for d in all_detections if d.get("detection_result") == "DETECTED")
    partial = sum(1 for d in all_detections if d.get("detection_result") == "PARTIAL")
    missed = sum(1 for d in all_detections if d.get("detection_result") == "MISSED")
    
    rate = round((detected / total * 100), 1) if total > 0 else 0
    
    lines = [
        "# ATT&CK Coverage Report",
        f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
        f"\n## Summary\n",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Techniques Validated | {total} |",
        f"| Detected | {detected} |",
        f"| Partial | {partial} |",
        f"| Missed | {missed} |",
        f"| Detection Rate | {rate}% |",
        f"\n## Technique Results\n",
        "| Technique ID | Name | Tactic | Result | Severity |",
        "|-------------|------|--------|--------|----------|"
    ]
    
    for d in sorted(all_detections, key=lambda x: x.get("technique_id", "")):
        lines.append(
            f"| {d.get('technique_id','')} | {d.get('technique_name','')} | "
            f"{d.get('tactic','')} | {d.get('detection_result','')} | "
            f"{d.get('severity','')} |"
        )
    
    output_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]✓ Coverage report generated[/green]")
    return str(output_path)