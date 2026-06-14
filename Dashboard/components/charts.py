"""
Dashboard Chart Components — Reusable Plotly chart functions.

Each function takes a pandas DataFrame or dict and returns a
plotly.graph_objects.Figure ready for display in Streamlit.
"""

import plotly.graph_objects as go

# Color palette
COLORS = {
    "DETECTED": "#2ecc71",
    "PARTIAL": "#f39c12",
    "MISSED": "#e74c3c",
    "CRITICAL": "#c0392b",
    "HIGH": "#e74c3c",
    "MEDIUM": "#f39c12",
    "LOW": "#3498db",
    "INFORMATIONAL": "#95a5a6",
}

TRANSPARENT = "rgba(0,0,0,0)"


def detection_rate_gauge(rate: float) -> go.Figure:
    """Gauge chart showing detection rate percentage."""
    color = COLORS["DETECTED"] if rate >= 70 else (
        COLORS["PARTIAL"] if rate >= 40 else COLORS["MISSED"]
    )

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=rate,
        number={"suffix": "%", "font": {"size": 40}},
        title={"text": "Detection Rate", "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": color},
            "bgcolor": "rgba(255,255,255,0.1)",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 40], "color": "rgba(231,76,60,0.15)"},
                {"range": [40, 70], "color": "rgba(243,156,18,0.15)"},
                {"range": [70, 100], "color": "rgba(46,204,113,0.15)"},
            ],
            "threshold": {
                "line": {"color": "white", "width": 2},
                "thickness": 0.8,
                "value": rate,
            },
        },
    ))

    fig.update_layout(
        height=250,
        margin=dict(l=20, r=20, t=40, b=20),
        plot_bgcolor=TRANSPARENT,
        paper_bgcolor=TRANSPARENT,
        font={"color": "#ecf0f1"},
    )
    return fig


def severity_donut(severity_counts: dict) -> go.Figure:
    """Donut chart showing distribution of CRITICAL/HIGH/MEDIUM/LOW detections."""
    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    colors = [COLORS.get(label, "#95a5a6") for label in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color="#2c3e50", width=2)),
        textinfo="label+value",
        textfont=dict(size=12),
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Percent: %{percent}<extra></extra>",
    ))

    fig.update_layout(
        title=dict(text="Severity Distribution", font=dict(size=16)),
        height=300,
        margin=dict(l=20, r=20, t=50, b=20),
        plot_bgcolor=TRANSPARENT,
        paper_bgcolor=TRANSPARENT,
        font={"color": "#ecf0f1"},
        showlegend=True,
        legend=dict(font=dict(size=11)),
    )
    return fig


def tactic_coverage_bar(tactic_data: dict) -> go.Figure:
    """Stacked bar chart: tactics on X axis, DETECTED/PARTIAL/MISSED stacked."""
    tactics = list(tactic_data.keys())
    detected = [tactic_data[t].get("DETECTED", 0) for t in tactics]
    partial = [tactic_data[t].get("PARTIAL", 0) for t in tactics]
    missed = [tactic_data[t].get("MISSED", 0) for t in tactics]

    fig = go.Figure(data=[
        go.Bar(
            name="Detected", x=tactics, y=detected,
            marker_color=COLORS["DETECTED"],
            hovertemplate="<b>%{x}</b><br>Detected: %{y}<extra></extra>",
        ),
        go.Bar(
            name="Partial", x=tactics, y=partial,
            marker_color=COLORS["PARTIAL"],
            hovertemplate="<b>%{x}</b><br>Partial: %{y}<extra></extra>",
        ),
        go.Bar(
            name="Missed", x=tactics, y=missed,
            marker_color=COLORS["MISSED"],
            hovertemplate="<b>%{x}</b><br>Missed: %{y}<extra></extra>",
        ),
    ])

    fig.update_layout(
        barmode="stack",
        title=dict(text="Detection Coverage by ATT&CK Tactic", font=dict(size=16)),
        xaxis_title="Tactic",
        yaxis_title="Techniques",
        height=400,
        margin=dict(l=40, r=20, t=50, b=80),
        plot_bgcolor=TRANSPARENT,
        paper_bgcolor=TRANSPARENT,
        font={"color": "#ecf0f1"},
        legend=dict(orientation="h", y=-0.2),
        xaxis=dict(tickangle=-30),
    )
    return fig


def detection_timeline(detections: list) -> go.Figure:
    """Line/scatter chart showing detections over time."""
    timestamps = [d.get("test_timestamp", "") for d in detections]
    results = [d.get("detection_result", "MISSED") for d in detections]
    technique_ids = [d.get("technique_id", "") for d in detections]

    result_to_score = {"DETECTED": 100, "PARTIAL": 50, "MISSED": 0}
    scores = [result_to_score.get(r, 0) for r in results]
    colors = [COLORS.get(r, "#95a5a6") for r in results]

    fig = go.Figure(go.Scatter(
        x=timestamps,
        y=scores,
        mode="markers+lines",
        marker=dict(size=10, color=colors, line=dict(width=1, color="#2c3e50")),
        text=technique_ids,
        hovertemplate=(
            "<b>%{text}</b><br>"
            "Time: %{x}<br>"
            "Score: %{y}<extra></extra>"
        ),
        line=dict(color="rgba(52,152,219,0.5)", width=1),
    ))

    fig.update_layout(
        title=dict(text="Detection Timeline", font=dict(size=16)),
        xaxis_title="Time",
        yaxis_title="Score",
        yaxis=dict(range=[-10, 110], tickvals=[0, 50, 100],
                   ticktext=["MISSED", "PARTIAL", "DETECTED"]),
        height=350,
        margin=dict(l=60, r=20, t=50, b=40),
        plot_bgcolor=TRANSPARENT,
        paper_bgcolor=TRANSPARENT,
        font={"color": "#ecf0f1"},
    )
    return fig


def compliance_coverage_bar(coverage_data: list) -> go.Figure:
    """Bar chart showing controls covered per compliance framework."""
    from collections import defaultdict
    framework_counts = defaultdict(int)
    for item in coverage_data:
        framework_counts[item.get("framework", "Unknown")] += 1

    frameworks = list(framework_counts.keys())
    counts = list(framework_counts.values())
    colors = ["#3498db", "#2ecc71", "#9b59b6", "#e74c3c", "#f39c12"]

    fig = go.Figure(go.Bar(
        x=frameworks,
        y=counts,
        marker_color=colors[:len(frameworks)],
        text=counts,
        textposition="auto",
        hovertemplate="<b>%{x}</b><br>Controls: %{y}<extra></extra>",
    ))

    fig.update_layout(
        title=dict(text="Controls Covered per Framework", font=dict(size=16)),
        xaxis_title="Framework",
        yaxis_title="Controls Covered",
        height=350,
        margin=dict(l=40, r=20, t=50, b=40),
        plot_bgcolor=TRANSPARENT,
        paper_bgcolor=TRANSPARENT,
        font={"color": "#ecf0f1"},
    )
    return fig
