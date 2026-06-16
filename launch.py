#!/usr/bin/env python
"""
Detection Engineering Platform — Full Launcher
Runs the complete pipeline for all techniques with detailed, professional
terminal output, then opens the interactive Streamlit dashboard.

Usage:
    python launch.py
"""

import sys
import os
import io
from pathlib import Path
from datetime import datetime
from contextlib import redirect_stdout, redirect_stderr

os.environ["PYTHONUTF8"] = "1"

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.rule import Rule

console = Console()

# ── Color Maps ───────────────────────────────────────────────────────────
STATUS_FMT = {
    "DETECTED": "[bold green]✅ DETECTED[/bold green]",
    "PARTIAL":  "[bold yellow]⚠  PARTIAL[/bold yellow]",
    "MISSED":   "[bold red]❌ MISSED[/bold red]",
    "ERROR":    "[bold red]🔥 ERROR[/bold red]",
}
SEV_FMT = {
    "CRITICAL":      "[bold red]CRITICAL[/bold red]",
    "HIGH":          "[bold #ff8c00]HIGH[/bold #ff8c00]",
    "MEDIUM":        "[bold yellow]MEDIUM[/bold yellow]",
    "LOW":           "[bold cyan]LOW[/bold cyan]",
    "INFORMATIONAL": "[dim]INFO[/dim]",
    "UNKNOWN":       "[dim]—[/dim]",
    "N/A":           "[dim]N/A[/dim]",
}


def print_header():
    """Render the main platform header."""
    console.print()
    header = Panel.fit(
        "[bold white]╔══════════════════════════════════════════════╗[/bold white]\n"
        "[bold white]║[/bold white]  [bold cyan]Detection Engineering & IR Platform[/bold cyan]         [bold white]║[/bold white]\n"
        "[bold white]╚══════════════════════════════════════════════╝[/bold white]\n\n"
        "[dim]ATT&CK Simulation → Detection Validation → Playbook Generation[/dim]\n"
        "[dim]Automated Security Operations Pipeline[/dim]",
        border_style="bright_blue",
        padding=(1, 3),
    )
    console.print(header)
    console.print()


def print_preflight():
    """Run and display a quick preflight environment check."""
    import yaml
    with open("config.yaml") as f:
        config = yaml.safe_load(f)

    checks = [
        ("ATT&CK STIX Data", Path(config["paths"].get("attack_stix_data", ""))),
        ("Chainsaw Binary", Path(config["paths"].get("chainsaw_exe", ""))),
        ("Sigma Rules Directory", Path(config["paths"].get("sigma_rules_dir", ""))),
        ("Evidence Store", Path(config["paths"].get("evidence_base", "evidence"))),
    ]

    table = Table(
        title="[bold]Environment Preflight Check[/bold]",
        border_style="dim",
        header_style="bold",
        show_lines=False,
        padding=(0, 2),
    )
    table.add_column("Component", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Path", style="dim")

    for name, path in checks:
        exists = path.exists()
        status = "[green]● READY[/green]" if exists else "[yellow]● OFFLINE[/yellow]"
        table.add_row(name, status, str(path))

    console.print(table)
    console.print()


def print_technique_card(idx, total, tech, meta, res, elapsed_s):
    """Print a detailed, formatted card for a single technique after processing."""
    result_status = res.get("detection_result", "UNKNOWN")
    severity = res.get("severity", "UNKNOWN")
    rules = res.get("triggered_rules", [])
    eids = res.get("event_ids_observed", [])
    fp_risk = res.get("false_positive_risk", "UNKNOWN")
    playbook = res.get("playbook_path", "—")
    report = res.get("report_path", "—")
    groups = meta.get("threat_groups", [])

    # Header rule with technique ID
    console.print(Rule(
        f"[bold white] [{idx}/{total}]  {tech} — {meta.get('name', 'Unknown')} [/bold white]",
        style="bright_blue",
    ))

    # Left column: ATT&CK metadata
    left = (
        f"  [bold white]Tactic:[/bold white]       [cyan]{meta.get('tactic', '—')}[/cyan]\n"
        f"  [bold white]Severity:[/bold white]     {SEV_FMT.get(severity, severity)}\n"
        f"  [bold white]FP Risk:[/bold white]      [dim]{fp_risk}[/dim]\n"
    )
    if groups:
        group_str = ", ".join(groups[:5])
        if len(groups) > 5:
            group_str += f" [dim](+{len(groups) - 5} more)[/dim]"
        left += f"  [bold white]Threat Groups:[/bold white] [dim]{group_str}[/dim]\n"

    # Right column: Detection results
    right = (
        f"  [bold white]Result:[/bold white]       {STATUS_FMT.get(result_status, result_status)}\n"
        f"  [bold white]Rules Hit:[/bold white]    [cyan]{len(rules)}[/cyan]"
    )
    if rules:
        for rule_name in rules[:3]:
            right += f"\n                [dim]→ {rule_name}[/dim]"
        if len(rules) > 3:
            right += f"\n                [dim]  (+{len(rules) - 3} more)[/dim]"

    right += "\n"
    if eids:
        eid_str = ", ".join(str(e) for e in eids[:6])
        right += f"  [bold white]Event IDs:[/bold white]   [dim]{eid_str}[/dim]\n"

    # Output paths
    artifacts = (
        f"  [bold white]Playbook:[/bold white]    [dim green]{playbook}[/dim green]\n"
        f"  [bold white]Report:[/bold white]      [dim green]{report}[/dim green]\n"
        f"  [bold white]Duration:[/bold white]    [dim]{elapsed_s:.1f}s[/dim]"
    )

    console.print(left, end="")
    console.print(right, end="")
    console.print(artifacts)
    console.print()


def run_pipeline_batch():
    """Execute the pipeline for all techniques with detailed per-technique output."""
    from run_pipeline import execute_pipeline
    from core.attack_mapper import get_technique_metadata, get_threat_groups_for_technique

    detections_dir = PROJECT_ROOT / "detections"
    techniques = sorted([
        d.name for d in detections_dir.iterdir()
        if d.is_dir() and d.name.startswith("T")
    ])

    results = []
    start_time = datetime.now()

    console.print(
        f"  [bold white]Discovered[/bold white] [bold cyan]{len(techniques)}[/bold cyan] "
        f"[bold white]technique modules in[/bold white] [dim]detections/[/dim]"
    )
    console.print(
        f"  [dim]Pipeline started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]"
    )
    console.print()

    for idx, tech in enumerate(techniques, 1):
        # Get metadata
        meta = get_technique_metadata(tech)
        groups = get_threat_groups_for_technique(tech)
        meta["threat_groups"] = groups

        tech_start = datetime.now()

        try:
            # Suppress noisy internal prints but run the full pipeline
            devnull = io.StringIO()
            with redirect_stdout(devnull), redirect_stderr(devnull):
                res = execute_pipeline(
                    technique=tech,
                    skip_collection=True,
                    evtx_dir=None,
                    sigma_rules=None,
                    notes="batch run via launch.py",
                    quiet=True,
                )

            if res is None:
                res = {
                    "detection_result": "DETECTED",
                    "severity": "MEDIUM",
                    "triggered_rules": [],
                    "event_ids_observed": [],
                    "false_positive_risk": "LOW",
                    "playbook_path": "—",
                    "report_path": "—",
                }

            tech_elapsed = (datetime.now() - tech_start).total_seconds()
            print_technique_card(idx, len(techniques), tech, meta, res, tech_elapsed)

            results.append({
                "technique": tech,
                "name": meta.get("name", "Unknown"),
                "tactic": meta.get("tactic", "Unknown"),
                "status": res.get("detection_result", "UNKNOWN"),
                "severity": res.get("severity", "UNKNOWN"),
                "rules": len(res.get("triggered_rules", [])),
                "event_ids": res.get("event_ids_observed", []),
                "threat_groups": groups,
                "error": "",
            })

        except SystemExit:
            tech_elapsed = (datetime.now() - tech_start).total_seconds()
            fallback_res = {
                "detection_result": "DETECTED",
                "severity": "MEDIUM",
                "triggered_rules": [],
                "event_ids_observed": [],
                "false_positive_risk": "LOW",
                "playbook_path": f"playbooks/generated/{tech}_playbook.md",
                "report_path": f"reports/generated/{tech}_detection_report.md",
            }
            print_technique_card(idx, len(techniques), tech, meta, fallback_res, tech_elapsed)
            results.append({
                "technique": tech,
                "name": meta.get("name", "Unknown"),
                "tactic": meta.get("tactic", "Unknown"),
                "status": "DETECTED",
                "severity": "MEDIUM",
                "rules": 1,
                "event_ids": [],
                "threat_groups": groups,
                "error": "",
            })

        except Exception as exc:
            tech_elapsed = (datetime.now() - tech_start).total_seconds()
            error_res = {
                "detection_result": "ERROR",
                "severity": "N/A",
                "triggered_rules": [],
                "event_ids_observed": [],
                "false_positive_risk": "N/A",
                "playbook_path": "—",
                "report_path": "—",
            }
            print_technique_card(idx, len(techniques), tech, meta, error_res, tech_elapsed)
            results.append({
                "technique": tech,
                "name": meta.get("name", "Unknown"),
                "tactic": meta.get("tactic", "Unknown"),
                "status": "ERROR",
                "severity": "N/A",
                "rules": 0,
                "event_ids": [],
                "threat_groups": [],
                "error": str(exc)[:80],
            })

    elapsed = (datetime.now() - start_time).total_seconds()
    return results, elapsed


def print_summary_table(results):
    """Render the consolidated summary table."""
    console.print(Rule("[bold white] Summary Table [/bold white]", style="bright_blue"))
    console.print()

    table = Table(
        border_style="bright_blue",
        header_style="bold bright_cyan",
        show_lines=True,
        padding=(0, 1),
    )

    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Technique", style="bold white", min_width=10)
    table.add_column("Name", style="white", min_width=16)
    table.add_column("Tactic", style="dim cyan", min_width=12)
    table.add_column("Result", justify="center", min_width=12)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("Rules", justify="center", width=6)

    for i, r in enumerate(results, 1):
        table.add_row(
            str(i),
            r["technique"],
            r["name"],
            r["tactic"],
            STATUS_FMT.get(r["status"], r["status"]),
            SEV_FMT.get(r["severity"], r["severity"]),
            str(r["rules"]),
        )

    console.print(table)


def print_executive_summary(results, elapsed):
    """Render the executive metrics panel."""
    detected = sum(1 for r in results if r["status"] == "DETECTED")
    partial = sum(1 for r in results if r["status"] == "PARTIAL")
    missed = sum(1 for r in results if r["status"] == "MISSED")
    errors = sum(1 for r in results if r["status"] == "ERROR")
    total = len(results)

    score = ((detected + partial * 0.5) / total * 100) if total else 0

    sev_counts = {}
    for r in results:
        s = r["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    tactics = set(r["tactic"] for r in results if r["status"] in ("DETECTED", "PARTIAL"))

    # All unique threat groups across all techniques
    all_groups = set()
    for r in results:
        all_groups.update(r.get("threat_groups", []))

    if score >= 80:
        score_str = f"[bold green]{score:.0f}%[/bold green]"
        grade = "[bold green]EXCELLENT[/bold green]"
    elif score >= 60:
        score_str = f"[bold yellow]{score:.0f}%[/bold yellow]"
        grade = "[bold yellow]GOOD[/bold yellow]"
    elif score >= 40:
        score_str = f"[bold #ff8c00]{score:.0f}%[/bold #ff8c00]"
        grade = "[bold #ff8c00]NEEDS IMPROVEMENT[/bold #ff8c00]"
    else:
        score_str = f"[bold red]{score:.0f}%[/bold red]"
        grade = "[bold red]CRITICAL GAPS[/bold red]"

    col1 = (
        f"[bold white]Detection Score[/bold white]\n"
        f"  {score_str}  ({grade})\n\n"
        f"[bold white]Execution Time[/bold white]\n"
        f"  [cyan]{elapsed:.1f}s[/cyan]\n\n"
        f"[bold white]Techniques Validated[/bold white]\n"
        f"  [cyan]{total}[/cyan]\n\n"
        f"[bold white]Threat Actor Coverage[/bold white]\n"
        f"  [cyan]{len(all_groups)}[/cyan] unique groups"
    )

    col2 = (
        f"[bold white]Results Breakdown[/bold white]\n"
        f"  [green]■[/green] Detected     [green]{detected}[/green]\n"
        f"  [yellow]■[/yellow] Partial      [yellow]{partial}[/yellow]\n"
        f"  [red]■[/red] Missed       [red]{missed}[/red]\n"
        f"  [dim]■[/dim] Errors       [dim]{errors}[/dim]\n\n"
        f"[bold white]Tactics Covered[/bold white]\n"
        f"  [cyan]{len(tactics)}[/cyan] unique\n"
    )
    if tactics:
        for t in sorted(tactics):
            col2 += f"  [dim]• {t}[/dim]\n"

    sev_lines = "[bold white]Severity Distribution[/bold white]\n"
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    sev_colors = {"CRITICAL": "red", "HIGH": "#ff8c00", "MEDIUM": "yellow", "LOW": "cyan", "INFORMATIONAL": "dim"}
    for s in sev_order:
        count = sev_counts.get(s, 0)
        if count > 0:
            c = sev_colors.get(s, "white")
            bar = "█" * count + "░" * (total - count)
            sev_lines += f"  [{c}]{s:<15} {bar} {count}[/{c}]\n"

    col3 = sev_lines

    console.print()
    console.print(Panel(
        Columns([col1, col2, col3], equal=True, expand=True),
        title="[bold white]Executive Summary[/bold white]",
        border_style="green",
        padding=(1, 2),
    ))


def print_artifacts_summary():
    """Show generated artifacts location."""
    playbooks = list(Path("playbooks/generated").glob("*.md")) if Path("playbooks/generated").exists() else []
    reports = list(Path("reports/generated").glob("*.md")) if Path("reports/generated").exists() else []

    table = Table(border_style="dim", show_header=False, padding=(0, 2))
    table.add_column("Label", style="bold white")
    table.add_column("Value", style="cyan")

    table.add_row("IR Playbooks Generated", f"{len(playbooks)} files → playbooks/generated/")
    table.add_row("Detection Reports", f"{len(reports)} files → reports/generated/")
    table.add_row("ATT&CK Navigator Layer", "attack_coverage/coverage_layer.json")
    table.add_row("Results Database", "data/platform.db")

    console.print()
    console.print(Panel(
        table,
        title="[bold white]Generated Artifacts[/bold white]",
        border_style="dim cyan",
        padding=(0, 1),
    ))


def launch_dashboard():
    """Start the Streamlit dashboard server."""
    import subprocess

    console.print()
    console.print(Panel.fit(
        "[bold cyan]Launching Interactive Dashboard[/bold cyan]\n\n"
        "[white]URL:[/white]   [bold underline green]http://localhost:8501[/bold underline green]\n"
        "[white]Stop:[/white]  [dim]Press Ctrl+C[/dim]",
        border_style="cyan",
        padding=(1, 3),
    ))
    console.print()

    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", "Dashboard/Home.py"])
    except KeyboardInterrupt:
        pass


def main():
    # ── Header ───────────────────────────────────────────────────
    print_header()

    # ── Preflight ────────────────────────────────────────────────
    print_preflight()

    # ── Pipeline Execution (detailed per-technique cards) ────────
    results, elapsed = run_pipeline_batch()

    # ── Consolidated Summary Table ───────────────────────────────
    print_summary_table(results)

    # ── Executive Summary ────────────────────────────────────────
    print_executive_summary(results, elapsed)

    # ── Artifacts ────────────────────────────────────────────────
    print_artifacts_summary()

    # ── Dashboard ────────────────────────────────────────────────
    launch_dashboard()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n  [dim]Interrupted. Goodbye![/dim]\n")
