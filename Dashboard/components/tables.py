"""
Dashboard Table Components — Reusable dataframe display functions.

Provides styled tables and pivot formatters for the Streamlit dashboard.
"""

import pandas as pd


def styled_detections_table(df: pd.DataFrame) -> "pd.io.formats.style.Styler":
    """Apply color styling to detection result column."""
    def _color_result(val):
        """Return CSS style for detection result cells."""
        color_map = {
            "DETECTED": "background-color: rgba(46,204,113,0.3); color: #2ecc71;",
            "PARTIAL": "background-color: rgba(243,156,18,0.3); color: #f39c12;",
            "MISSED": "background-color: rgba(231,76,60,0.3); color: #e74c3c;",
        }
        return color_map.get(val, "")

    def _color_severity(val):
        """Return CSS style for severity cells."""
        color_map = {
            "CRITICAL": "color: #c0392b; font-weight: bold;",
            "HIGH": "color: #e74c3c;",
            "MEDIUM": "color: #f39c12;",
            "LOW": "color: #3498db;",
            "INFORMATIONAL": "color: #95a5a6;",
        }
        return color_map.get(val, "")

    styled = df.style
    if "Result" in df.columns:
        styled = styled.map(_color_result, subset=["Result"])
    if "Severity" in df.columns:
        styled = styled.map(_color_severity, subset=["Severity"])

    return styled


def compliance_pivot_table(mappings: list) -> pd.DataFrame:
    """
    Pivot compliance mappings into a technique × framework matrix.

    Args:
        mappings: List of dicts with 'technique_id', 'framework', 'control_id'.

    Returns:
        DataFrame with techniques as rows, frameworks as columns,
        and control IDs as cell values.
    """
    if not mappings:
        return pd.DataFrame()

    df = pd.DataFrame(mappings)

    if df.empty or "technique_id" not in df.columns:
        return pd.DataFrame()

    # Group controls by technique and framework
    grouped = df.groupby(["technique_id", "framework"])["control_id"].apply(
        lambda x: ", ".join(sorted(x.unique()))
    ).reset_index()

    pivot = grouped.pivot(
        index="technique_id",
        columns="framework",
        values="control_id",
    ).fillna("—")

    pivot.index.name = "Technique"
    return pivot


def format_detection_summary(detections: list) -> pd.DataFrame:
    """
    Format detection data into a clean summary table.

    Args:
        detections: List of detection dicts from the database.

    Returns:
        DataFrame ready for display with emoji result indicators.
    """
    if not detections:
        return pd.DataFrame()

    df = pd.DataFrame(detections)

    # Select and rename columns
    display_cols = {
        "technique_id": "Technique ID",
        "technique_name": "Name",
        "tactic": "Tactic",
        "detection_result": "Result",
        "severity": "Severity",
        "test_timestamp": "Last Validated",
    }

    available_cols = {k: v for k, v in display_cols.items() if k in df.columns}
    result_df = df[list(available_cols.keys())].rename(columns=available_cols)

    # Add emoji indicators
    emoji_map = {"DETECTED": "✅", "PARTIAL": "⚠️", "MISSED": "❌"}
    if "Result" in result_df.columns:
        result_df["Result"] = result_df["Result"].apply(
            lambda x: f"{emoji_map.get(x, '❓')} {x}"
        )

    return result_df
