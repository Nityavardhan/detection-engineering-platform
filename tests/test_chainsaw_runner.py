"""
Tests for core.chainsaw_runner module.

Tests parsing, event ID extraction, and matched field extraction
from Chainsaw JSON output in various formats.
"""

import json
from pathlib import Path

import pytest

# Ensure project root is importable
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.chainsaw_runner import parse_chainsaw_output, extract_event_id, extract_matched_fields


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_chainsaw_list():
    """Load the sample Chainsaw output fixture as a list."""
    with open(FIXTURES / "sample_chainsaw_output.json", "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def sample_chainsaw_dict():
    """Return a single Chainsaw hit as a dict (not list)."""
    with open(FIXTURES / "sample_chainsaw_output.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    return data[0]


class TestParseChainsawOutput:
    """Tests for parse_chainsaw_output()."""

    def test_list_input_returns_correct_count(self, sample_chainsaw_list):
        """parse_chainsaw_output() with list input returns correct number of hits."""
        hits = parse_chainsaw_output(sample_chainsaw_list)
        assert len(hits) == 2

    def test_dict_input_returns_single_hit(self, sample_chainsaw_dict):
        """parse_chainsaw_output() with dict input handles single hit correctly."""
        hits = parse_chainsaw_output(sample_chainsaw_dict)
        assert len(hits) == 1

    def test_empty_list_returns_empty(self):
        """parse_chainsaw_output() with empty list returns empty list."""
        hits = parse_chainsaw_output([])
        assert hits == []

    def test_hit_has_required_fields(self, sample_chainsaw_list):
        """Each parsed hit should have all required fields."""
        hits = parse_chainsaw_output(sample_chainsaw_list)
        required_fields = ["rule_name", "rule_level", "rule_tags",
                           "event_id", "timestamp", "computer",
                           "matched_fields", "raw"]
        for hit in hits:
            for field in required_fields:
                assert field in hit, f"Missing field: {field}"


class TestExtractEventId:
    """Tests for extract_event_id()."""

    def test_known_structure_returns_correct_id(self):
        """extract_event_id() with known structure returns correct ID."""
        item = {"EventID": 4104}
        assert extract_event_id(item) == "4104"

    def test_nested_structure(self):
        """extract_event_id() handles nested EventID paths."""
        item = {"System": {"EventID": "1"}}
        assert extract_event_id(item) == "1"

    def test_missing_event_id(self):
        """extract_event_id() returns 'Unknown' when no EventID found."""
        item = {"some_field": "value"}
        assert extract_event_id(item) == "Unknown"


class TestExtractMatchedFields:
    """Tests for extract_matched_fields()."""

    def test_returns_commandline(self):
        """extract_matched_fields() returns CommandLine when present."""
        item = {
            "event_data": {
                "CommandLine": "powershell.exe -enc ABC123",
                "Image": "C:\\Windows\\System32\\powershell.exe"
            }
        }
        fields = extract_matched_fields(item)
        assert "CommandLine" in fields
        assert "Image" in fields

    def test_empty_event_data(self):
        """extract_matched_fields() handles missing event_data gracefully."""
        item = {"no_event_data": True}
        fields = extract_matched_fields(item)
        assert fields == {}
