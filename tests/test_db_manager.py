"""
Tests for core.db_manager module.

Tests database initialization, insertion, and query operations
using a temporary SQLite file.
"""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import db_manager


@pytest.fixture(autouse=True)
def temp_database(tmp_path):
    """Use a temporary SQLite file for each test, not the real platform.db."""
    temp_db = tmp_path / "test_platform.db"
    schema_path = Path(__file__).parent.parent / "data" / "db_schema.sql"

    with mock.patch.object(db_manager, 'DB_PATH', temp_db), \
         mock.patch.object(db_manager, 'SCHEMA_PATH', schema_path):
        yield temp_db


class TestInitializeDatabase:
    """Tests for initialize_database()."""

    def test_creates_all_tables(self):
        """initialize_database() creates all four tables."""
        db_manager.initialize_database()
        conn = db_manager.get_connection()

        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        table_names = sorted([t[0] for t in tables])
        conn.close()

        assert "techniques" in table_names
        assert "detections" in table_names
        assert "compliance_mappings" in table_names
        assert "hunts" in table_names


class TestInsertAndQuery:
    """Tests for insert and query operations."""

    def test_insert_technique_and_get_all_detections_roundtrip(self):
        """insert_technique() + insert_detection() + get_all_detections() round trip."""
        db_manager.initialize_database()

        db_manager.insert_technique({
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
            "description": "Test description",
            "threat_groups": ["APT29"],
        })

        row_id = db_manager.insert_detection({
            "technique_id": "T1059.001",
            "detection_result": "DETECTED",
            "severity": "HIGH",
            "triggered_rules": ["rule1"],
            "event_ids_observed": ["4104"],
        })

        assert row_id is not None
        assert row_id > 0

        detections = db_manager.get_all_detections()
        assert len(detections) >= 1
        assert detections[0]["technique_id"] == "T1059.001"

    def test_insert_detection_returns_valid_row_id(self):
        """insert_detection() returns a valid row id."""
        db_manager.initialize_database()

        db_manager.insert_technique({
            "technique_id": "T1003.001",
            "name": "LSASS Memory",
            "tactic": "Credential Access",
        })

        row_id = db_manager.insert_detection({
            "technique_id": "T1003.001",
            "detection_result": "DETECTED",
            "severity": "CRITICAL",
        })

        assert isinstance(row_id, int)
        assert row_id >= 1

    def test_get_summary_stats_correct_detection_rate(self):
        """get_summary_stats() returns correct detection_rate when 1 of 1 detected."""
        db_manager.initialize_database()

        db_manager.insert_technique({
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
        })

        db_manager.insert_detection({
            "technique_id": "T1059.001",
            "detection_result": "DETECTED",
        })

        stats = db_manager.get_summary_stats()
        assert stats["total_techniques"] == 1
        assert stats["detected"] == 1
        assert stats["detection_rate"] == 100.0

    def test_get_detection_by_technique_returns_most_recent(self):
        """get_detection_by_technique() returns most recent when multiple exist."""
        db_manager.initialize_database()

        db_manager.insert_technique({
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "tactic": "Execution",
        })

        db_manager.insert_detection({
            "technique_id": "T1059.001",
            "detection_result": "MISSED",
            "test_timestamp": "2024-01-01T00:00:00",
        })

        db_manager.insert_detection({
            "technique_id": "T1059.001",
            "detection_result": "DETECTED",
            "test_timestamp": "2024-06-01T00:00:00",
        })

        det = db_manager.get_detection_by_technique("T1059.001")
        assert det is not None
        assert det["detection_result"] == "DETECTED"
