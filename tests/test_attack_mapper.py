"""
Tests for core.attack_mapper module.

Tests technique metadata retrieval, tactic extraction, and STIX
data caching behavior.
"""

from pathlib import Path
from unittest import mock

import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import attack_mapper


@pytest.fixture(autouse=True)
def reset_cache():
    """Reset the global STIX data cache before each test."""
    attack_mapper._ATTACK_DATA = None
    yield
    attack_mapper._ATTACK_DATA = None


class TestGetTechniqueMetadata:
    """Tests for get_technique_metadata()."""

    def test_returns_fallback_when_stix_missing(self, tmp_path):
        """get_technique_metadata() returns fallback dict when STIX file missing."""
        with mock.patch.object(
            attack_mapper, 'load_attack_data', return_value={}
        ):
            result = attack_mapper.get_technique_metadata("T9999.999")

        assert result["technique_id"] == "T9999.999"
        assert result["name"] == "Unknown"
        assert result["tactic"] == "Unknown"
        assert "url" in result


class TestExtractTactic:
    """Tests for extract_tactic()."""

    def test_extracts_tactic_from_kill_chain(self):
        """extract_tactic() correctly extracts and formats tactic name."""
        obj = {
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "credential-access"
                }
            ]
        }
        result = attack_mapper.extract_tactic(obj)
        assert result == "Credential Access"

    def test_handles_empty_kill_chain(self):
        """extract_tactic() handles empty kill_chain_phases gracefully."""
        obj = {"kill_chain_phases": []}
        result = attack_mapper.extract_tactic(obj)
        assert result == "Unknown"

    def test_handles_missing_kill_chain(self):
        """extract_tactic() handles missing kill_chain_phases key."""
        obj = {}
        result = attack_mapper.extract_tactic(obj)
        assert result == "Unknown"


class TestLoadAttackData:
    """Tests for load_attack_data() caching behavior."""

    def test_caches_result_on_second_call(self):
        """load_attack_data() returns cached result on second call."""
        # Set cache directly
        test_data = {"T1059.001": {"name": "PowerShell", "tactic": "Execution"}}
        attack_mapper._ATTACK_DATA = test_data

        result = attack_mapper.load_attack_data()
        assert result == test_data
        assert result is test_data  # Same object, not a copy
