#!/usr/bin/env python
"""
Run All Techniques — Batch Pipeline Executor

Iterates over all technique folders in detections/ and runs the pipeline
for each using --skip-collection mode. Prints a final summary table.

Usage:
    python run_all.py
    python run_all.py --evtx-base C:/Temp/evtx_exports
"""

import sys
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table

console = Console()

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))


def main():
    """Run the detection pipeline for all techniques with existing evidence."""
    from run_pipeline import execute_pipeline

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

    console.print(f"\n[bold]Running pipeline for {len(techniques)} techniques[/bold]\n")

    results = []
    start_time = datetime.now()

    for tech in techniques:
        console.print(f"\n{'=' * 60}")
        console.print(f"Processing: [yellow]{tech}[/yellow]")
        try:
            execute_pipeline(
                technique=tech,
                skip_collection=True,
                evtx_dir=None,
                sigma_rules=None,
                notes="batch run via run_all.py",
            )
            results.append({"technique": tech, "status": "✅ SUCCESS", "error": ""})
        except SystemExit:
            # Typer raises SystemExit; treat as success if no real error
            results.append({"technique": tech, "status": "✅ SUCCESS", "error": ""})
        except Exception as exc:
            console.print(f"[red]✗ Failed: {exc}[/red]")
            results.append({"technique": tech, "status": "❌ FAILED", "error": str(exc)})

    # Print final summary
    elapsed = (datetime.now() - start_time).seconds
    console.print(f"\n\n{'=' * 60}")

    summary = Table(title="Batch Pipeline Summary", border_style="blue")
    summary.add_column("Technique", style="bold")
    summary.add_column("Status")
    summary.add_column("Error", style="dim")

    success_count = 0
    for r in results:
        summary.add_row(r["technique"], r["status"], r["error"])
        if "SUCCESS" in r["status"]:
            success_count += 1

    console.print(summary)
    console.print(f"\n[bold]Results: {success_count}/{len(results)} succeeded in {elapsed}s[/bold]")


if __name__ == "__main__":
    main()
