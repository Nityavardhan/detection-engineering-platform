import sqlite3
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console

console = Console()

DB_PATH = Path("data/platform.db")
SCHEMA_PATH = Path("data/db_schema.sql")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Create tables if they don't exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    with open(SCHEMA_PATH, "r") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    console.print("[green]✓ Database initialized[/green]")


def insert_technique(technique_data: dict):
    """Insert or update a technique record."""
    conn = get_connection()
    conn.execute("""
        INSERT OR REPLACE INTO techniques 
        (technique_id, name, tactic, description, threat_groups)
        VALUES (?, ?, ?, ?, ?)
    """, (
        technique_data["technique_id"],
        technique_data["name"],
        technique_data["tactic"],
        technique_data.get("description", ""),
        json.dumps(technique_data.get("threat_groups", []))
    ))
    conn.commit()
    conn.close()


def insert_detection(detection_data: dict) -> int:
    """Insert a detection result. Returns the new row id."""
    conn = get_connection()
    cursor = conn.execute("""
        INSERT INTO detections 
        (technique_id, test_timestamp, detection_result, severity,
         triggered_rules, event_ids_observed, false_positive_risk,
         evidence_path, playbook_path, report_path, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        detection_data["technique_id"],
        detection_data.get("test_timestamp", datetime.now().isoformat()),
        detection_data["detection_result"],
        detection_data.get("severity", "MEDIUM"),
        json.dumps(detection_data.get("triggered_rules", [])),
        json.dumps(detection_data.get("event_ids_observed", [])),
        detection_data.get("false_positive_risk", "UNKNOWN"),
        detection_data.get("evidence_path", ""),
        detection_data.get("playbook_path", ""),
        detection_data.get("report_path", ""),
        detection_data.get("notes", "")
    ))
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def insert_compliance_mappings(technique_id: str, mappings: list):
    """Insert compliance mappings for a technique."""
    conn = get_connection()
    for mapping in mappings:
        conn.execute("""
            INSERT INTO compliance_mappings
            (technique_id, framework, control_id, control_name, mapping_note)
            VALUES (?, ?, ?, ?, ?)
        """, (
            technique_id,
            mapping["framework"],
            mapping["control_id"],
            mapping.get("control_name", ""),
            mapping.get("mapping_note", "")
        ))
    conn.commit()
    conn.close()


def get_all_detections() -> list:
    """Return all detection records as list of dicts."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT d.*, t.name as technique_name, t.tactic
        FROM detections d
        LEFT JOIN techniques t ON d.technique_id = t.technique_id
        ORDER BY d.test_timestamp DESC
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_detection_by_technique(technique_id: str) -> dict | None:
    """Return the most recent detection for a technique."""
    conn = get_connection()
    row = conn.execute("""
        SELECT d.*, t.name as technique_name, t.tactic
        FROM detections d
        LEFT JOIN techniques t ON d.technique_id = t.technique_id
        WHERE d.technique_id = ?
        ORDER BY d.test_timestamp DESC
        LIMIT 1
    """, (technique_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_summary_stats() -> dict:
    """Return high-level stats for the dashboard."""
    conn = get_connection()
    
    total = conn.execute(
        "SELECT COUNT(DISTINCT technique_id) FROM detections"
    ).fetchone()[0]
    
    detected = conn.execute(
        "SELECT COUNT(DISTINCT technique_id) FROM detections WHERE detection_result = 'DETECTED'"
    ).fetchone()[0]
    
    severity_counts = conn.execute("""
        SELECT severity, COUNT(*) as count 
        FROM detections 
        GROUP BY severity
    """).fetchall()
    
    tactic_counts = conn.execute("""
        SELECT t.tactic, COUNT(DISTINCT d.technique_id) as count
        FROM detections d
        LEFT JOIN techniques t ON d.technique_id = t.technique_id
        GROUP BY t.tactic
    """).fetchall()
    
    conn.close()
    
    return {
        "total_techniques": total,
        "detected": detected,
        "detection_rate": round((detected / total * 100), 1) if total > 0 else 0,
        "severity_distribution": {row[0]: row[1] for row in severity_counts},
        "tactic_distribution": {row[0]: row[1] for row in tactic_counts}
    }


def get_compliance_coverage() -> list:
    """Return compliance coverage grouped by framework."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT framework, control_id, control_name, COUNT(DISTINCT technique_id) as technique_count
        FROM compliance_mappings
        GROUP BY framework, control_id
        ORDER BY framework, control_id
    """).fetchall()
    conn.close()
    return [dict(row) for row in rows]