from pathlib import Path
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import yaml
from rich.console import Console

console = Console()


def load_response_data(technique_id: str) -> dict:
    """Load the response YAML for a technique."""
    yaml_path = Path("detections") / technique_id / "response_data.yaml"
    
    if not yaml_path.exists():
        console.print(f"  [yellow]⚠ No response_data.yaml for {technique_id}[/yellow]")
        return get_default_response_data(technique_id)
    
    with open(yaml_path, "r") as f:
        return yaml.safe_load(f)


def get_default_response_data(technique_id: str) -> dict:
    """Fallback response data when YAML not found."""
    return {
        "technique_id": technique_id,
        "technique_name": "Unknown Technique",
        "tactic": "Unknown",
        "severity": "MEDIUM",
        "containment_steps": "1. Isolate the affected host\n2. Preserve evidence\n3. Notify IR team",
        "investigation_steps": "1. Review relevant event logs\n2. Check for lateral movement\n3. Identify scope",
        "evidence_checklist": "- [ ] Event logs exported\n- [ ] Memory preserved\n- [ ] Network traffic captured",
        "remediation_steps": "1. Remove malicious artifacts\n2. Reset compromised credentials\n3. Patch vulnerability",
        "compliance_notes": "NIST CSF: DE.CM-1, RS.AN-1",
        "false_positive_scenarios": "None documented.",
        "adversary_context": "No adversary context documented."
    }


def generate_playbook(technique_id: str, detection_result: dict,
                       attack_metadata: dict) -> str:
    """
    Generate an IR playbook Markdown file.
    Returns path to the generated file.
    """
    output_dir = Path("playbooks/generated")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load template
    env = Environment(
        loader=FileSystemLoader("playbooks/templates"),
        trim_blocks=True,
        lstrip_blocks=True
    )
    template = env.get_template("playbook_template.md")
    
    # Load technique-specific response data
    response_data = load_response_data(technique_id)
    
    # Build context for template
    context = {
        "technique_id": technique_id,
        "technique_name": attack_metadata.get("name", response_data.get("technique_name", "")),
        "tactic": attack_metadata.get("tactic", response_data.get("tactic", "")),
        "severity": detection_result.get("severity", response_data.get("severity", "MEDIUM")),
        "detection_result": detection_result.get("detection_result", "UNKNOWN"),
        "triggered_rules": detection_result.get("triggered_rules", []),
        "event_ids": detection_result.get("event_ids_observed", []),
        "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        "attack_url": attack_metadata.get("url", ""),
        "threat_groups": attack_metadata.get("threat_groups", []),
        "data_sources": attack_metadata.get("data_sources", []),
        # From response YAML
        "containment_steps": response_data.get("containment_steps", ""),
        "investigation_steps": response_data.get("investigation_steps", ""),
        "evidence_checklist": response_data.get("evidence_checklist", ""),
        "remediation_steps": response_data.get("remediation_steps", ""),
        "compliance_notes": response_data.get("compliance_notes", ""),
        "false_positive_scenarios": response_data.get("false_positive_scenarios", ""),
        "adversary_context": response_data.get("adversary_context", ""),
    }
    
    rendered = template.render(**context)
    
    output_path = output_dir / f"{technique_id}_playbook.md"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    
    console.print(f"  [green]✓ Playbook generated:[/green] {output_path}")
    return str(output_path)