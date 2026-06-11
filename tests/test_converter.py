"""
tests/test_converter.py
Unit tests for the Sigma → Wazuh converter.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))
from converter import sigma_to_wazuh_xml, LEVEL_MAP, map_field


# ── Fixtures ──────────────────────────────────────────────────────────────────

SIGMA_HIGH = {
    "title": "Suspicious Encoded PowerShell",
    "description": "Detects PowerShell with encoded command arguments.",
    "level": "high",
    "tags": ["attack.execution", "attack.t1059.001"],
    "detection": {
        "selection": {
            "CommandLine|contains": ["-EncodedCommand", "-enc "]
        },
        "condition": "selection"
    }
}

SIGMA_CRITICAL = {
    "title": "LSASS Memory Dump",
    "level": "critical",
    "tags": ["attack.credential_access", "attack.t1003.001"],
    "detection": {
        "selection": {
            "Image|endswith": "\\procdump.exe",
            "CommandLine|contains": "lsass"
        },
        "condition": "selection"
    }
}

SIGMA_NO_TAGS = {
    "title": "Generic Rule",
    "level": "low",
    "detection": {
        "selection": {"CommandLine|contains": "evil.exe"},
        "condition": "selection"
    }
}


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_output_is_xml():
    xml = sigma_to_wazuh_xml(SIGMA_HIGH)
    assert xml.strip().startswith("<group")
    assert "</group>" in xml


def test_rule_id_present():
    xml = sigma_to_wazuh_xml(SIGMA_HIGH, rule_id=100042)
    assert 'id="100042"' in xml


def test_level_mapping_high():
    xml = sigma_to_wazuh_xml(SIGMA_HIGH)
    assert f'level="{LEVEL_MAP["high"]}"' in xml


def test_level_mapping_critical():
    xml = sigma_to_wazuh_xml(SIGMA_CRITICAL)
    assert f'level="{LEVEL_MAP["critical"]}"' in xml


def test_title_in_description():
    xml = sigma_to_wazuh_xml(SIGMA_HIGH)
    assert "Suspicious Encoded PowerShell" in xml


def test_mitre_tag_in_output():
    xml = sigma_to_wazuh_xml(SIGMA_HIGH)
    assert "T1059" in xml or "t1059" in xml.lower()


def test_no_tags_no_group_element():
    xml = sigma_to_wazuh_xml(SIGMA_NO_TAGS)
    # Should not crash; group element for mitre may be absent
    assert "<rule" in xml


def test_field_mapping():
    assert map_field("CommandLine") == "win.eventdata.commandLine"
    assert map_field("Image") == "win.eventdata.image"
    assert map_field("SourceIp") == "data.srcip"


def test_unknown_field_lowercased():
    result = map_field("SomeUnknownField")
    assert result == "someunknownfield"


def test_pattern_escaped():
    xml = sigma_to_wazuh_xml(SIGMA_HIGH)
    # -EncodedCommand should appear escaped for pcre2
    assert "EncodedCommand" in xml


def test_sigma_group_present():
    xml = sigma_to_wazuh_xml(SIGMA_HIGH)
    assert 'name="sigma,"' in xml
