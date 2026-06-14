"""
Tests for core.playbook_generator module.

Tests response data loading, playbook generation, and template rendering.
"""

import os
import shutil
from pathlib import Path
from unittest import mock

import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.playbook_generator import load_response_data, generate_playbook


FIXTURES = Path(__file__).parent / "fixtures"


class TestLoadResponseData:
    """Tests for load_response_data()."""

    def test_returns_default_when_yaml_missing(self):
        """load_response_data() returns default data when YAML missing."""
        result = load_response_data("T9999.999")
        assert result["technique_id"] == "T9999.999"
        assert "containment_steps" in result
        assert "investigation_steps" in result

    def test_loads_existing_yaml(self):
        """load_response_data() reads existing response_data.yaml."""
        result = load_response_data("T1059.001")
        assert result["technique_id"] == "T1059.001"
        assert result["technique_name"] == "PowerShell"
        assert result["severity"] == "HIGH"


class TestGeneratePlaybook:
    """Tests for generate_playbook()."""

    def test_creates_file_at_expected_path(self, tmp_path):
        """generate_playbook() creates file at expected path."""
        # Patch the output directory
        output_dir = tmp_path / "playbooks" / "generated"
        with mock.patch(
            "core.playbook_generator.Path",
            side_effect=lambda x: tmp_path / x if "playbooks" in str(x) else Path(x)
        ):
            pass

        # Use actual function with real templates
        detection_result = {
            "detection_result": "DETECTED",
            "severity": "HIGH",
            "triggered_rules": ["test_rule"],
            "event_ids_observed": ["4104"],
        }
        attack_metadata = {
            "name": "PowerShell",
            "tactic": "Execution",
            "url": "https://attack.mitre.org/techniques/T1059/001/",
            "threat_groups": ["APT29"],
            "data_sources": ["Process Creation"],
        }

        path = generate_playbook("T1059.001", detection_result, attack_metadata)
        assert Path(path).exists()
        assert "T1059.001" in path

    def test_generated_playbook_contains_technique_id(self):
        """Generated playbook contains technique_id in content."""
        detection_result = {
            "detection_result": "DETECTED",
            "severity": "HIGH",
            "triggered_rules": [],
            "event_ids_observed": [],
        }
        attack_metadata = {
            "name": "PowerShell",
            "tactic": "Execution",
            "url": "",
            "threat_groups": [],
            "data_sources": [],
        }

        path = generate_playbook("T1059.001", detection_result, attack_metadata)
        content = Path(path).read_text(encoding="utf-8")
        assert "T1059.001" in content

    def test_jinja2_template_renders_without_error(self):
        """Jinja2 template renders without error given minimal valid context."""
        detection_result = {
            "detection_result": "MISSED",
            "severity": "MEDIUM",
            "triggered_rules": [],
            "event_ids_observed": [],
        }
        attack_metadata = {
            "name": "Test Technique",
            "tactic": "Test Tactic",
            "url": "",
            "threat_groups": [],
            "data_sources": [],
        }

        # Should not raise any exception
        path = generate_playbook("T9999.999", detection_result, attack_metadata)
        assert Path(path).exists()

        # Clean up
        Path(path).unlink(missing_ok=True)
