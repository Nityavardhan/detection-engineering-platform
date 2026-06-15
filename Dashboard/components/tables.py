"""
Dashboard Table Components — Reusable styled dataframe functions.
"""

import pandas as pd


def styled_detections_table(df: pd.DataFrame) -> "pd.io.formats.style.Styler":
    """Apply professional color styling to detection result and severity columns."""

    def _color_result(val):
        val_clean = str(val).strip()
        color_map = {
            "DETECTED": "background-color: rgba(16,185,129,0.15); color: #10b981; font-weight:600;",
            "PARTIAL": "background-color: rgba(245,158,11,0.15); color: #f59e0b; font-weight:600;",
            "MISSED": "background-color: rgba(239,68,68,0.15); color: #ef4444; font-weight:600;",
        }
        return color_map.get(val_clean, "")

    def _color_severity(val):
        val_clean = str(val).strip()
        color_map = {
            "CRITICAL": "color: #ef4444; font-weight: 700;",
            "HIGH": "color: #f97316; font-weight: 600;",
            "MEDIUM": "color: #f59e0b;",
            "LOW": "color: #6366f1;",
            "INFORMATIONAL": "color: #64748b;",
        }
        return color_map.get(val_clean, "")

    styled = df.style

    # Try both column name conventions
    for result_col in ["Result", "detection_result"]:
        if result_col in df.columns:
            styled = styled.map(_color_result, subset=[result_col])
            break

    for sev_col in ["Severity", "severity"]:
        if sev_col in df.columns:
            styled = styled.map(_color_severity, subset=[sev_col])
            break

    return styled


def compliance_pivot_table(mappings: list) -> pd.DataFrame:
    """Pivot compliance mappings into technique x framework matrix."""
    if not mappings:
        return pd.DataFrame()

    df = pd.DataFrame(mappings)
    if df.empty or "technique_id" not in df.columns:
        return pd.DataFrame()

    grouped = df.groupby(["technique_id", "framework"])["control_id"].apply(
        lambda x: ", ".join(sorted(x.unique()))
    ).reset_index()

    pivot = grouped.pivot(
        index="technique_id", columns="framework", values="control_id",
    ).fillna("—")
    pivot.index.name = "Technique"
    return pivot
