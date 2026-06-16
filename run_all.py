#!/usr/bin/env python
"""
Run All Techniques — Batch Pipeline Executor

Iterates over all technique folders in detections/ and runs the pipeline
for each using --skip-collection mode. Prints a highly professional 
summary dashboard at the end.

Usage:
    python run_all.py
"""

import sys
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich import print as rprint

console = Console()

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))


def main():
    """Run the detection pipeline for all techniques with existing evidence."""
    from run_pipeline import execute_pipeline
    from core.attack_mapper import get_technique_metadata

    detections_dir = PROJECT_ROOT / "detections"
    if not detections_dir.exists():
        console.print("[red]✗ detections/ directory not found[/red]")
        sys.exit(1)

    techniques = sorted([
        d.name for d in detections_dir.iterdir()
        if d.is_dir() and d.name.startswith("T")
    ])

    if not techniques:
        console.print("[yellow]⚠ No technique directories found in detections/[/yellow]")
        sys.exit(1)

    console.print()
    console.print(Panel.fit(
        f"[bold cyan]Automated Detection Validation Pipeline[/bold cyan]\n"
        f"[dim]Executing analysis for {len(techniques)} mapped techniques[/dim]",
        border_style="cyan"
    ))
    console.print()

    results = []
    start_time = datetime.now()

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold blue"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="green", finished_style="bold green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        
        main_task = progress.add_task("[bold white]Running Pipeline...", total=len(techniques))
        
        for tech in techniques:
            meta = get_technique_metadata(tech)
            tech_name = meta.get("name", "Unknown")
            
            progress.update(main_task, description=f"[bold white]Analyzing:[/bold white] [cyan]{tech} - {tech_name}[/cyan]")
            
            try:
                res = execute_pipeline(
                    technique=tech,
                    skip_collection=True,
                    evtx_dir=None,
                    sigma_rules=None,
                    notes="batch run via run_all.py",
                    quiet=True  # Suppress internal prints
                )
                
                result_status = res.get("detection_result", "UNKNOWN")
                severity = res.get("severity", "UNKNOWN")
                rules_triggered = len(res.get("triggered_rules", []))
                
                results.append({
                    "technique": tech, 
                    "name": tech_name,
                    "status": result_status,
                    "severity": severity,
                    "rules": rules_triggered,
                    "error": ""
                })
            except Exception as exc:
                results.append({
                    "technique": tech, 
                    "name": tech_name,
                    "status": "ERROR", 
                    "severity": "N/A",
                    "rules": 0,
                    "error": str(exc)
                })
            
            progress.advance(main_task)

    # ── Final Summary Dashboard ──────────────────────────────────────────
    elapsed = (datetime.now() - start_time).total_seconds()
    
    console.print("\n")
    
    # Define color maps
    status_colors = {
        "DETECTED": "[bold green]✅ DETECTED[/bold green]",
        "PARTIAL": "[bold yellow]⚠️ PARTIAL[/bold yellow]",
        "MISSED": "[bold red]❌ MISSED[/bold red]",
        "ERROR": "[bold red]🔥 ERROR[/bold red]"
    }
    
    severity_colors = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[bold orange3]HIGH[/bold orange3]",
        "MEDIUM": "[bold yellow]MEDIUM[/bold yellow]",
        "LOW": "[bold cyan]LOW[/bold cyan]",
        "INFORMATIONAL": "[dim white]INFO[/dim white]",
        "N/A": "[dim]N/A[/dim]"
    }

    # Create the summary table
    summary = Table(
        title="[bold]Detection Pipeline Validation Report[/bold]", 
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True
    )
    
    summary.add_column("Technique", style="white", justify="left")
    summary.add_column("Technique Name", style="dim white", justify="left")
    summary.add_column("Validation Result", justify="center")
    summary.add_column("Severity", justify="center")
    summary.add_column("Rules Triggered", justify="right")

    success_count = 0
    partial_count = 0
    missed_count = 0
    
    for r in results:
        t_status = r["status"]
        if t_status == "DETECTED": success_count += 1
        elif t_status == "PARTIAL": partial_count += 1
        elif t_status == "MISSED": missed_count += 1
        
        status_fmt = status_colors.get(t_status, f"[{t_status}]")
        sev_fmt = severity_colors.get(r["severity"], r["severity"])
        
        # Add error to name if failed
        name_display = r["name"]
        if r["error"]:
            name_display += f"\n[dim red]Error: {r['error']}[/dim red]"
            
        summary.add_row(
            r["technique"], 
            name_display, 
            status_fmt, 
            sev_fmt, 
            str(r["rules"])
        )

    console.print(summary)
    
    # ── Metrics Panel ────────────────────────────────────────────────────
    detection_rate = 0
    if len(results) > 0:
        # Partial counts as 0.5 for detection rate
        detection_rate = ((success_count + (partial_count * 0.5)) / len(results)) * 100

    metrics_text = (
        f"[bold white]Total Validated:[/bold white] [cyan]{len(results)}[/cyan] techniques\n"
        f"[bold white]Full Detections:[/bold white] [green]{success_count}[/green]\n"
        f"[bold white]Partial Detections:[/bold white] [yellow]{partial_count}[/yellow]\n"
        f"[bold white]Missed Attacks:[/bold white] [red]{missed_count}[/red]\n"
        f"[bold white]Execution Time:[/bold white] [cyan]{elapsed:.2f} seconds[/cyan]\n\n"
        f"[bold white]Overall Detection Score:[/bold white] "
    )
    
    if detection_rate >= 80:
        metrics_text += f"[bold green]{detection_rate:.1f}%[/bold green]"
    elif detection_rate >= 50:
        metrics_text += f"[bold yellow]{detection_rate:.1f}%[/bold yellow]"
    else:
        metrics_text += f"[bold red]{detection_rate:.1f}%[/bold red]"

    console.print()
    console.print(Panel(
        metrics_text,
        title="[bold]Executive Metrics[/bold]",
        border_style="green",
        expand=False
    ))
    console.print()


if __name__ == "__main__":
    main()
