#! python
"""
Detection Engineering Platform — Master Pipeline
Usage: python run_pipeline.py --technique T1059.001
       python run_pipeline.py --technique T1059.001 --skip-collection
       python run_pipeline.py --technique T1059.001 --evtx-dir C:/Temp/myevtx
"""

import typer
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import yaml
import json

# Core modules
from core.db_manager import initialize_database, insert_technique, insert_detection, insert_compliance_mappings
from core.telemetry_collector import collect_evtx, copy_existing_evtx
from core.chainsaw_runner import run_chainsaw
from core.attack_mapper import get_technique_metadata, get_threat_groups_for_technique
from core.playbook_generator import generate_playbook
from core.report_generator import generate_detection_report
from core.navigator_updater import update_navigator_layer
from core.compliance_mapper import get_mappings_for_technique

app = typer.Typer(
    help="Detection Engineering & IR Validation Platform",
    no_args_is_help=True,
    invoke_without_command=True,
)
console = Console()

with open("config.yaml") as f:
    CONFIG = yaml.safe_load(f)


def print_banner():
    console.print(Panel.fit(
        "[bold blue]Detection Engineering Platform[/bold blue]\n"
        "[dim]ATT&CK Simulation -> Detection Validation -> IR Playbook Generation[/dim]",
        border_style="blue"
    ))


def show_preflight_check():
    """Display current runtime readiness for the lab environment."""
    console.rule("[bold yellow]Preflight Check[/bold yellow]")

    stix_path = Path(CONFIG["paths"].get("attack_stix_data", "data/enterprise-attack.json"))
    chainsaw_path = Path(CONFIG["paths"].get("chainsaw_exe", ""))
    sigma_dir = Path(CONFIG["paths"].get("sigma_rules_dir", ""))

    console.print(f"  ATT&CK STIX file: {'OK' if stix_path.exists() else 'MISSING'} -> {stix_path}")
    console.print(f"  Chainsaw executable: {'OK' if chainsaw_path.exists() else 'MISSING'} -> {chainsaw_path}")
    console.print(f"  Sigma rules directory: {'OK' if sigma_dir.exists() else 'MISSING'} -> {sigma_dir}")

    evidence_base = Path(CONFIG["paths"].get("evidence_base", "evidence"))
    console.print(f"  Evidence base folder: {'OK' if evidence_base.exists() else 'MISSING'} -> {evidence_base}")


def determine_detection_result(chainsaw_results: dict, technique_id: str) -> dict:
    """
    Determine DETECTED / PARTIAL / MISSED based on Chainsaw results.
    Also extract key metadata from hits.
    """
    hits = chainsaw_results.get("hits", [])
    
    if not hits:
        return {
            "technique_id": technique_id,
            "detection_result": "MISSED",
            "severity": "UNKNOWN",
            "triggered_rules": [],
            "event_ids_observed": [],
            "false_positive_risk": "UNKNOWN"
        }
    
    # Extract rule names and event IDs
    triggered_rules = list(set(h.get("rule_name", "Unknown") for h in hits))
    event_ids = list(set(h.get("event_id", "") for h in hits if h.get("event_id")))
    
    # Determine severity from highest hit level
    level_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    max_level = max(
        (level_priority.get(h.get("rule_level", "medium").lower(), 2) for h in hits),
        default=2
    )
    severity_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFORMATIONAL"}
    severity = severity_map.get(max_level, "MEDIUM")
    
    # Load expected rules from detection card / sigma_rules dir
    sigma_dir = Path("detections") / technique_id / "sigma_rules"
    expected_count = len(list(sigma_dir.glob("*.yml"))) if sigma_dir.exists() else 1
    
    if len(hits) >= expected_count:
        result = "DETECTED"
    elif len(hits) > 0:
        result = "PARTIAL"
    else:
        result = "MISSED"
    
    # Load FP risk from response_data.yaml if exists
    fp_risk = "LOW"
    response_yaml = Path("detections") / technique_id / "response_data.yaml"
    if response_yaml.exists():
        with open(response_yaml) as f:
            rd = yaml.safe_load(f)
            fp_risk = rd.get("false_positive_risk", "LOW")
    
    return {
        "technique_id": technique_id,
        "detection_result": result,
        "severity": severity,
        "triggered_rules": triggered_rules,
        "event_ids_observed": event_ids,
        "false_positive_risk": fp_risk
    }


def execute_pipeline(
    technique: str,
    skip_collection: bool = False,
    evtx_dir: Optional[str] = None,
    sigma_rules: Optional[str] = None,
    notes: str = "",
    quiet: bool = False,
):
    if quiet:
        console.quiet = True
    else:
        console.quiet = False

    print_banner()
    show_preflight_check()
    start_time = datetime.now()
    
    console.print(f"\n[bold]Starting pipeline for:[/bold] [yellow]{technique}[/yellow]")
    console.print(f"[dim]{start_time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
    
    # ── Step 1: Initialize Database ──────────────────────────────────────
    console.rule("[bold blue]Step 1/7 — Database[/bold blue]")
    initialize_database()
    
    # ── Step 2: ATT&CK Metadata ──────────────────────────────────────────
    console.rule("[bold blue]Step 2/7 — ATT&CK Enrichment[/bold blue]")
    attack_metadata = get_technique_metadata(technique)
    threat_groups = get_threat_groups_for_technique(technique)
    attack_metadata["threat_groups"] = threat_groups
    
    console.print(f"  Technique: [bold]{attack_metadata.get('name', 'Unknown')}[/bold]")
    console.print(f"  Tactic:    [bold]{attack_metadata.get('tactic', 'Unknown')}[/bold]")
    if threat_groups:
        console.print(f"  Groups:    {', '.join(threat_groups[:5])}")
    
    # Insert technique to DB
    insert_technique({
        "technique_id": technique,
        "name": attack_metadata.get("name", ""),
        "tactic": attack_metadata.get("tactic", ""),
        "description": attack_metadata.get("description", ""),
        "threat_groups": threat_groups
    })
    
    # ── Step 3: Telemetry Collection ─────────────────────────────────────
    console.rule("[bold blue]Step 3/7 — Telemetry Collection[/bold blue]")
    
    evidence_dir = Path(CONFIG["paths"]["evidence_base"]) / technique / "raw"
    
    if evtx_dir:
        evtx_path = Path(evtx_dir)
        if not evtx_path.exists():
            console.print(f"  [red]✗ EVTX directory not found: {evtx_path}[/red]")
            if quiet: console.quiet = False
            raise typer.Exit(1)

        console.print(f"  Using provided EVTX directory: {evtx_path}")
        evtx_files = list(evtx_path.glob("*.evtx"))
        if not evtx_files:
            console.print(f"  [yellow]⚠ No EVTX files found in {evtx_path}; continuing with no detections.[/yellow]")
        copy_existing_evtx(technique, [str(f) for f in evtx_files])
    elif skip_collection:
        console.print(f"  [yellow]Skipping collection — using existing:[/yellow] {evidence_dir}")
        if not evidence_dir.exists():
            evidence_dir.mkdir(parents=True, exist_ok=True)
            console.print(f"  [yellow]⚠ Evidence directory was missing; created: {evidence_dir}[/yellow]")
    else:
        collect_evtx(technique)
    
    # ── Step 4: Chainsaw Detection Validation ────────────────────────────
    console.rule("[bold blue]Step 4/7 — Detection Validation[/bold blue]")
    
    local_sigma_dir = Path("detections") / technique / "sigma_rules"
    configured_sigma_dir = Path(CONFIG["paths"].get("sigma_rules_dir", ""))

    if sigma_rules:
        sigma_dir = sigma_rules
    elif local_sigma_dir.exists() and any(local_sigma_dir.glob("*.yml")):
        sigma_dir = str(local_sigma_dir)
    elif configured_sigma_dir.exists() and any(configured_sigma_dir.glob("*.yml")):
        sigma_dir = str(configured_sigma_dir)
        console.print(f"  [yellow]Using configured Sigma rules: {sigma_dir}[/yellow]")
    else:
        sigma_dir = None
        console.print("  [yellow]No Sigma rules available; continuing in offline mode.[/yellow]")
    
    chainsaw_results = run_chainsaw(
        evtx_dir=str(evidence_dir),
        technique_id=technique,
        sigma_rules_dir=sigma_dir
    )
    
    # ── Step 5: Determine Detection Result ───────────────────────────────
    detection_result = determine_detection_result(chainsaw_results, technique)
    detection_result["test_timestamp"] = start_time.isoformat()
    detection_result["notes"] = notes
    
    # Print result prominently
    result_color = {"DETECTED": "green", "PARTIAL": "yellow", "MISSED": "red"}
    color = result_color.get(detection_result["detection_result"], "white")
    console.print(f"\n  Result: [{color}][bold]{detection_result['detection_result']}[/bold][/{color}]")
    console.print(f"  Severity: {detection_result['severity']}")
    
    # ── Step 6: Generate Playbook + Report ───────────────────────────────
    console.rule("[bold blue]Step 5/7 — Playbook & Report Generation[/bold blue]")
    
    playbook_path = generate_playbook(technique, detection_result, attack_metadata)
    
    detection_result["playbook_path"] = playbook_path
    detection_result["evidence_path"] = str(Path(CONFIG["paths"]["evidence_base"]) / technique)
    
    report_path = generate_detection_report(technique, detection_result, attack_metadata, chainsaw_results)
    detection_result["report_path"] = report_path
    
    # ── Step 7: Compliance Mapping ───────────────────────────────────────
    console.rule("[bold blue]Step 6/7 — Compliance Mapping[/bold blue]")
    
    mappings = get_mappings_for_technique(technique)
    if mappings:
        insert_compliance_mappings(technique, mappings)
        console.print(f"  [green]✓ {len(mappings)} compliance mapping(s) stored[/green]")
    else:
        console.print(f"  [yellow]⚠ No compliance mappings found for {technique}[/yellow]")
    
    # ── Store to Database ────────────────────────────────────────────────
    console.rule("[bold blue]Step 7/7 — Database + Navigator[/bold blue]")
    
    insert_detection(detection_result)
    console.print(f"  [green]✓ Detection stored to database[/green]")
    
    update_navigator_layer(technique, detection_result["detection_result"])
    
    # ── Final Summary ────────────────────────────────────────────────────
    elapsed = (datetime.now() - start_time).seconds
    
    console.print("\n")
    
    summary_table = Table(title=f"Pipeline Complete — {technique}", border_style="green")
    summary_table.add_column("Field", style="bold")
    summary_table.add_column("Value")
    
    summary_table.add_row("Technique", f"{technique} — {attack_metadata.get('name', '')}")
    summary_table.add_row("Tactic", attack_metadata.get("tactic", ""))
    summary_table.add_row("Result", f"[{color}]{detection_result['detection_result']}[/{color}]")
    summary_table.add_row("Severity", detection_result["severity"])
    summary_table.add_row("Rules Triggered", str(len(detection_result["triggered_rules"])))
    summary_table.add_row("Playbook", playbook_path)
    summary_table.add_row("Report", report_path)
    summary_table.add_row("Duration", f"{elapsed}s")
    
    console.print(summary_table)

    if quiet:
        console.quiet = False
        
    return detection_result


@app.command()
def run(
    technique: str = typer.Option(..., "--technique", "-t", help="ATT&CK technique ID, e.g. T1059.001"),
    skip_collection: bool = typer.Option(False, "--skip-collection", help="Skip EVTX collection (use existing evidence)"),
    evtx_dir: str = typer.Option(None, "--evtx-dir", help="Path to existing EVTX directory"),
    sigma_rules: str = typer.Option(None, "--sigma-rules", help="Override Sigma rules directory"),
    notes: str = typer.Option("", "--notes", help="Optional notes for this run")
):
    """Run the full detection validation pipeline for one ATT&CK technique."""
    execute_pipeline(technique, skip_collection, evtx_dir, sigma_rules, notes)


@app.callback()
def main(
    ctx: typer.Context,
    technique: Optional[str] = typer.Option(None, "--technique", "-t", help="ATT&CK technique ID, e.g. T1059.001"),
    skip_collection: bool = typer.Option(False, "--skip-collection", help="Skip EVTX collection (use existing evidence)"),
    evtx_dir: Optional[str] = typer.Option(None, "--evtx-dir", help="Path to existing EVTX directory"),
    sigma_rules: Optional[str] = typer.Option(None, "--sigma-rules", help="Override Sigma rules directory"),
    notes: str = typer.Option("", "--notes", help="Optional notes for this run"),
):
    """Run the pipeline directly or show help when no subcommand is provided."""
    if ctx.invoked_subcommand is not None:
        return

    if technique:
        execute_pipeline(technique, skip_collection, evtx_dir, sigma_rules, notes)
        raise typer.Exit()

    typer.echo(ctx.get_help())
    raise typer.Exit()


@app.command()
def run_all(
    skip_collection: bool = typer.Option(False, "--skip-collection")
):
    """Run pipeline for all techniques with existing evidence."""
    techniques = [d.name for d in Path("detections").iterdir() if d.is_dir()]
    
    console.print(f"[bold]Running pipeline for {len(techniques)} techniques[/bold]\n")
    
    for tech in sorted(techniques):
        console.print(f"\n{'='*60}")
        console.print(f"Processing: [yellow]{tech}[/yellow]")
        try:
            run(technique=tech, skip_collection=True,
                evtx_dir=None, sigma_rules=None, notes="batch run")
        except Exception as e:
            console.print(f"[red]✗ Failed: {e}[/red]")


if __name__ == "__main__":
    app()