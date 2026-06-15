"""
Dashboard Chart Components — Premium Plotly chart functions.

Consistent dark-theme styling across all visualizations with
gradient fills, glow effects, and refined typography.
"""

import plotly.graph_objects as go

# ── Color System ──────────────────────────────────────────────────
COLORS = {
    "DETECTED": "#10b981",
    "PARTIAL": "#f59e0b",
    "MISSED": "#ef4444",
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#6366f1",
    "INFORMATIONAL": "#64748b",
}

BG = "rgba(0,0,0,0)"
GRID_COLOR = "rgba(148, 163, 184, 0.08)"
FONT = dict(family="Inter, sans-serif", color="#94a3b8")
TITLE_FONT = dict(family="Inter, sans-serif", color="#f1f5f9", size=15)

CHART_LAYOUT = dict(
    plot_bgcolor=BG,
    paper_bgcolor=BG,
    font=FONT,
    margin=dict(l=0, r=0, t=50, b=0),
)


def detection_rate_gauge(rate: float) -> go.Figure:
    """Large gauge showing overall detection rate."""
    color = (COLORS["DETECTED"] if rate >= 70 else
             COLORS["PARTIAL"] if rate >= 40 else COLORS["MISSED"])

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=rate,
        number={"suffix": "%", "font": {"size": 48, "color": "#f1f5f9", "family": "Inter"}},
        title={"text": "DETECTION RATE", "font": {"size": 12, "color": "#64748b", "family": "Inter"}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 0, "tickcolor": "#1e293b",
                     "tickfont": {"size": 10, "color": "#475569"}},
            "bar": {"color": color, "thickness": 0.75},
            "bgcolor": "rgba(30, 41, 59, 0.5)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 40], "color": "rgba(239,68,68,0.08)"},
                {"range": [40, 70], "color": "rgba(245,158,11,0.08)"},
                {"range": [70, 100], "color": "rgba(16,185,129,0.08)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.85,
                "value": rate,
            },
        },
    ))

    fig.update_layout(
        height=260,
        **CHART_LAYOUT,
    )
    return fig


def severity_donut(severity_counts: dict) -> go.Figure:
    """Donut chart for severity distribution with center text."""
    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    colors = [COLORS.get(label, "#64748b") for label in labels]
    total = sum(values)

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.65,
        marker=dict(colors=colors, line=dict(color="#0a0e17", width=3)),
        textinfo="label+value",
        textfont=dict(size=11, family="Inter"),
        textposition="outside",
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>",
        pull=[0.03] * len(labels),
        rotation=90,
    ))

    fig.add_annotation(
        text=f"<b>{total}</b><br><span style='font-size:10px;color:#64748b'>TOTAL</span>",
        x=0.5, y=0.5, showarrow=False,
        font=dict(size=28, color="#f1f5f9", family="Inter"),
    )

    fig.update_layout(
        title=dict(text="SEVERITY DISTRIBUTION", font=dict(size=12, color="#64748b")),
        height=300,
        showlegend=False,
        **CHART_LAYOUT,
    )
    return fig


def tactic_coverage_bar(tactic_data: dict) -> go.Figure:
    """Horizontal stacked bar chart: tactics on Y-axis, color-coded by result."""
    tactics = list(tactic_data.keys())
    detected = [tactic_data[t].get("DETECTED", 0) for t in tactics]
    partial = [tactic_data[t].get("PARTIAL", 0) for t in tactics]
    missed = [tactic_data[t].get("MISSED", 0) for t in tactics]

    fig = go.Figure(data=[
        go.Bar(
            name="Detected", y=tactics, x=detected, orientation="h",
            marker=dict(color=COLORS["DETECTED"], cornerradius=4),
            hovertemplate="<b>%{y}</b><br>Detected: %{x}<extra></extra>",
        ),
        go.Bar(
            name="Partial", y=tactics, x=partial, orientation="h",
            marker=dict(color=COLORS["PARTIAL"], cornerradius=4),
            hovertemplate="<b>%{y}</b><br>Partial: %{x}<extra></extra>",
        ),
        go.Bar(
            name="Missed", y=tactics, x=missed, orientation="h",
            marker=dict(color=COLORS["MISSED"], cornerradius=4),
            hovertemplate="<b>%{y}</b><br>Missed: %{x}<extra></extra>",
        ),
    ])

    fig.update_layout(
        barmode="stack",
        title=dict(text="DETECTION COVERAGE BY TACTIC", font=dict(size=12, color="#64748b")),
        xaxis=dict(title="", showgrid=True, gridcolor=GRID_COLOR, zeroline=False),
        yaxis=dict(title="", autorange="reversed"),
        height=max(300, len(tactics) * 50),
        legend=dict(orientation="h", y=-0.15, x=0.5, xanchor="center",
                    font=dict(size=11)),
        **CHART_LAYOUT,
    )
    return fig


def detection_timeline(detections: list) -> go.Figure:
    """Scatter plot showing detection results across time."""
    timestamps = [d.get("test_timestamp", "") for d in detections]
    results = [d.get("detection_result", "MISSED") for d in detections]
    technique_ids = [d.get("technique_id", "") for d in detections]
    names = [d.get("technique_name", "") for d in detections]

    result_to_score = {"DETECTED": 100, "PARTIAL": 50, "MISSED": 0}
    scores = [result_to_score.get(r, 0) for r in results]
    colors = [COLORS.get(r, "#64748b") for r in results]
    sizes = [14 if r == "DETECTED" else 11 for r in results]

    fig = go.Figure()

    # Add connecting line
    fig.add_trace(go.Scatter(
        x=timestamps, y=scores, mode="lines",
        line=dict(color="rgba(99, 102, 241, 0.2)", width=1.5, dash="dot"),
        showlegend=False, hoverinfo="skip",
    ))

    # Add scatter points
    fig.add_trace(go.Scatter(
        x=timestamps, y=scores, mode="markers",
        marker=dict(size=sizes, color=colors,
                    line=dict(width=2, color="#0a0e17"),
                    opacity=0.9),
        text=[f"{tid}<br>{name}" for tid, name in zip(technique_ids, names)],
        hovertemplate="<b>%{text}</b><br>Score: %{y}<extra></extra>",
        showlegend=False,
    ))

    fig.update_layout(
        title=dict(text="DETECTION TIMELINE", font=dict(size=12, color="#64748b")),
        xaxis=dict(title="", showgrid=True, gridcolor=GRID_COLOR),
        yaxis=dict(range=[-10, 115], tickvals=[0, 50, 100],
                   ticktext=["MISSED", "PARTIAL", "DETECTED"],
                   showgrid=True, gridcolor=GRID_COLOR),
        height=320,
        **CHART_LAYOUT,
    )
    return fig


def compliance_coverage_bar(coverage_data: list) -> go.Figure:
    """Bar chart showing controls per compliance framework with gradient colors."""
    from collections import defaultdict
    framework_counts = defaultdict(int)
    for item in coverage_data:
        framework_counts[item.get("framework", "Unknown")] += 1

    frameworks = list(framework_counts.keys())
    counts = list(framework_counts.values())
    bar_colors = ["#6366f1", "#10b981", "#a78bfa", "#f59e0b", "#22d3ee"]

    fig = go.Figure(go.Bar(
        x=frameworks, y=counts,
        marker=dict(color=bar_colors[:len(frameworks)], cornerradius=6,
                    line=dict(width=0)),
        text=counts, textposition="outside",
        textfont=dict(size=14, color="#f1f5f9", family="Inter"),
        hovertemplate="<b>%{x}</b><br>Controls: %{y}<extra></extra>",
    ))

    fig.update_layout(
        title=dict(text="CONTROLS COVERED PER FRAMEWORK", font=dict(size=12, color="#64748b")),
        xaxis=dict(title="", tickfont=dict(size=11)),
        yaxis=dict(title="", showgrid=True, gridcolor=GRID_COLOR),
        height=350,
        **CHART_LAYOUT,
    )
    return fig


def technique_radar(tactic_data: dict) -> go.Figure:
    """Radar/spider chart showing coverage completeness per tactic."""
    tactics = list(tactic_data.keys())
    total_per_tactic = []
    detected_per_tactic = []
    for t in tactics:
        total = sum(tactic_data[t].values())
        det = tactic_data[t].get("DETECTED", 0)
        total_per_tactic.append(total)
        detected_per_tactic.append(det / total * 100 if total > 0 else 0)

    # Close the radar polygon
    tactics_closed = tactics + [tactics[0]]
    vals_closed = detected_per_tactic + [detected_per_tactic[0]]

    fig = go.Figure()

    fig.add_trace(go.Scatterpolar(
        r=vals_closed, theta=tactics_closed,
        fill="toself",
        fillcolor="rgba(99, 102, 241, 0.15)",
        line=dict(color="#6366f1", width=2),
        marker=dict(size=6, color="#a78bfa"),
        name="Coverage %",
        hovertemplate="<b>%{theta}</b><br>Coverage: %{r:.0f}%<extra></extra>",
    ))

    fig.update_layout(
        polar=dict(
            bgcolor="rgba(0,0,0,0)",
            radialaxis=dict(visible=True, range=[0, 100], showline=False,
                            gridcolor=GRID_COLOR, tickfont=dict(size=9, color="#475569")),
            angularaxis=dict(gridcolor=GRID_COLOR,
                             tickfont=dict(size=10, color="#94a3b8")),
        ),
        title=dict(text="TACTIC COVERAGE RADAR", font=dict(size=12, color="#64748b")),
        height=400,
        showlegend=False,
        **CHART_LAYOUT,
    )
    return fig
