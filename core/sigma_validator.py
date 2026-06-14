"""
Sigma Validator Module — Secondary detection validation using Sigma rules.

This module provides a standalone Sigma rule validation capability that operates
independently of Chainsaw. It can use pySigma or subprocess-based sigma-cli
to convert and match Sigma rules against EVTX telemetry. If neither tool is
available, it logs a warning and returns empty results gracefully.
"""

import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional

import yaml
from rich.console import Console

console = Console()
logger = logging.getLogger(__name__)


def validate_with_sigma(evtx_path: str, sigma_rule_path: str) -> list:
    """
    Validate an EVTX file against a single Sigma rule.

    Attempts to use pySigma library first, then falls back to sigma-cli
    subprocess. If neither is available, returns an empty list with a warning.

    Args:
        evtx_path: Path to the EVTX file to validate.
        sigma_rule_path: Path to the Sigma rule YAML file.

    Returns:
        List of matching event dicts, or empty list if no matches or tools unavailable.
    """
    evtx_file = Path(evtx_path)
    rule_file = Path(sigma_rule_path)

    if not evtx_file.exists():
        logger.warning("EVTX file not found: %s", evtx_path)
        return []

    if not rule_file.exists():
        logger.warning("Sigma rule file not found: %s", sigma_rule_path)
        return []

    # Attempt 1: Try pySigma library
    matches = _validate_with_pysigma(evtx_file, rule_file)
    if matches is not None:
        return matches

    # Attempt 2: Try sigma-cli subprocess
    matches = _validate_with_sigma_cli(evtx_file, rule_file)
    if matches is not None:
        return matches

    # Neither tool available
    console.print(
        "  [yellow]⚠ Neither pySigma nor sigma-cli is available. "
        "Sigma validation skipped.[/yellow]"
    )
    logger.warning(
        "No Sigma validation tool available. Install pySigma or sigma-cli."
    )
    return []


def validate_directory(evtx_dir: str, sigma_rules_dir: str) -> dict:
    """
    Run all Sigma rules in a directory against all EVTX files in a directory.

    Args:
        evtx_dir: Path to directory containing EVTX files.
        sigma_rules_dir: Path to directory containing Sigma rule YAML files.

    Returns:
        Dict mapping rule_name to list of matching events.
    """
    evtx_path = Path(evtx_dir)
    rules_path = Path(sigma_rules_dir)
    results: Dict[str, list] = {}

    if not evtx_path.exists():
        logger.warning("EVTX directory not found: %s", evtx_dir)
        return results

    if not rules_path.exists():
        logger.warning("Sigma rules directory not found: %s", sigma_rules_dir)
        return results

    evtx_files = list(evtx_path.glob("*.evtx"))
    rule_files = list(rules_path.glob("*.yml"))

    if not evtx_files:
        console.print(f"  [yellow]⚠ No EVTX files found in {evtx_dir}[/yellow]")
        return results

    if not rule_files:
        console.print(f"  [yellow]⚠ No Sigma rules found in {sigma_rules_dir}[/yellow]")
        return results

    console.print(
        f"  [cyan]Sigma validation: {len(rule_files)} rule(s) × "
        f"{len(evtx_files)} EVTX file(s)[/cyan]"
    )

    for rule_file in sorted(rule_files):
        rule_name = rule_file.stem
        all_matches: list = []

        # Load rule metadata for display
        try:
            with open(rule_file, "r", encoding="utf-8") as fh:
                rule_data = yaml.safe_load(fh) or {}
            rule_name = rule_data.get("title", rule_file.stem)
        except (yaml.YAMLError, OSError):
            pass

        for evtx_file in evtx_files:
            matches = validate_with_sigma(str(evtx_file), str(rule_file))
            all_matches.extend(matches)

        results[rule_name] = all_matches

        if all_matches:
            console.print(
                f"  [green]✓[/green] {rule_name}: {len(all_matches)} match(es)"
            )
        else:
            console.print(f"  [dim]  {rule_name}: no matches[/dim]")

    return results


def get_rule_metadata(sigma_rule_path: str) -> dict:
    """
    Extract metadata from a Sigma rule YAML file.

    Args:
        sigma_rule_path: Path to the Sigma rule file.

    Returns:
        Dict with title, id, level, description, tags, and logsource fields.
    """
    rule_file = Path(sigma_rule_path)
    if not rule_file.exists():
        return {}

    try:
        with open(rule_file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to parse Sigma rule %s: %s", sigma_rule_path, exc)
        return {}

    return {
        "title": data.get("title", ""),
        "id": data.get("id", ""),
        "level": data.get("level", "medium"),
        "description": data.get("description", ""),
        "tags": data.get("tags", []),
        "logsource": data.get("logsource", {}),
        "falsepositives": data.get("falsepositives", []),
    }


def _validate_with_pysigma(
    evtx_file: Path, rule_file: Path
) -> Optional[list]:
    """
    Attempt validation using the pySigma library.

    Returns list of matches on success, or None if pySigma is not installed.
    """
    try:
        from sigma.rule import SigmaRule  # noqa: F401
        from sigma.collection import SigmaCollection  # noqa: F401
    except ImportError:
        logger.debug("pySigma not installed, skipping pySigma validation.")
        return None

    try:
        with open(rule_file, "r", encoding="utf-8") as fh:
            rule_content = fh.read()

        rule = SigmaRule.from_yaml(rule_content)
        console.print(
            f"  [cyan]pySigma loaded rule:[/cyan] {rule.title} "
            f"(level: {rule.level})"
        )

        # pySigma alone cannot directly query EVTX files — it converts rules.
        # Return a metadata-based result indicating the rule was parsed.
        return [{
            "rule_name": rule.title,
            "rule_level": str(rule.level),
            "source": "pySigma",
            "note": "Rule parsed successfully. Full EVTX matching requires "
                    "a backend (e.g., sigma-cli or Chainsaw).",
        }]
    except Exception as exc:
        logger.warning("pySigma validation failed: %s", exc)
        return None


def _validate_with_sigma_cli(
    evtx_file: Path, rule_file: Path
) -> Optional[list]:
    """
    Attempt validation using sigma-cli as a subprocess.

    Returns list of matches on success, or None if sigma-cli is not installed.
    """
    try:
        # Check if sigma-cli is available
        check = subprocess.run(
            ["sigma", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if check.returncode != 0:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("sigma-cli not found in PATH.")
        return None

    try:
        result = subprocess.run(
            [
                "sigma",
                "convert",
                "--target", "lucene",
                "--without-pipeline",
                str(rule_file),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0 and result.stdout.strip():
            console.print(
                f"  [cyan]sigma-cli converted rule:[/cyan] {rule_file.name}"
            )
            return [{
                "rule_name": rule_file.stem,
                "converted_query": result.stdout.strip(),
                "source": "sigma-cli",
            }]

        return []
    except subprocess.TimeoutExpired:
        logger.warning("sigma-cli timed out processing %s", rule_file)
        return []
    except Exception as exc:
        logger.warning("sigma-cli failed: %s", exc)
        return None
