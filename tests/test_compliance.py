"""
Tests for core/compliance.py

Covers:
- COMPLIANCE_MAP contains all expected categories
- get_compliance_mapping returns correct frameworks
- get_compliance_mapping: title routing, protocol routing, no-match
- enrich_finding_compliance mutates dict in-place
- enrich_finding_compliance returns same dict
- All framework values are non-empty lists
"""
import pytest

from core.compliance import (
    COMPLIANCE_MAP,
    get_compliance_mapping,
    enrich_finding_compliance,
)

REQUIRED_CATEGORIES = [
    "weak_credentials", "default_credentials", "brute_force",
    "telnet", "mqtt_anonymous", "mqtt_tls", "upnp", "snmp",
    "ftp", "http_admin", "missing_security_headers", "cve_exploit",
]

EXPECTED_FRAMEWORKS = [
    "OWASP_IoT_2018", "IEC_62443_3_3", "NIST_SP_800_82",
    "ETSI_EN_303_645", "NIST_CSF_2",
]


class TestComplianceMap:
    def test_required_categories_present(self):
        for cat in REQUIRED_CATEGORIES:
            assert cat in COMPLIANCE_MAP, f"Missing category: {cat}"

    def test_all_categories_have_required_frameworks(self):
        for cat, mapping in COMPLIANCE_MAP.items():
            for fw in EXPECTED_FRAMEWORKS:
                assert fw in mapping, f"Category '{cat}' missing framework '{fw}'"

    def test_all_framework_values_are_nonempty_lists(self):
        for cat, mapping in COMPLIANCE_MAP.items():
            for fw, controls in mapping.items():
                assert isinstance(controls, list), f"{cat}/{fw} not a list"
                assert len(controls) > 0, f"{cat}/{fw} is empty"


class TestGetComplianceMapping:
    def test_telnet_title_matches(self):
        m = get_compliance_mapping("Telnet Service Exposed")
        assert "OWASP_IoT_2018" in m
        assert any("I3" in c for c in m["OWASP_IoT_2018"])

    def test_default_credentials_title_matches(self):
        m = get_compliance_mapping("Default Credentials Found on Router")
        assert "ETSI_EN_303_645" in m

    def test_cve_in_title_matches(self):
        m = get_compliance_mapping("CVE-2021-36260 Hikvision RCE")
        assert "NIST_CSF_2" in m

    def test_no_match_returns_empty_dict(self):
        m = get_compliance_mapping("Completely Unrelated Finding Title XYZ")
        assert m == {}

    def test_case_insensitive_match(self):
        m = get_compliance_mapping("telnet open port")
        assert m != {}

    def test_brute_force_match(self):
        m = get_compliance_mapping("Brute Force Attack Detected")
        assert "IEC_62443_3_3" in m


class TestEnrichFindingCompliance:
    def test_adds_compliance_mapping_key(self, sample_finding):
        enrich_finding_compliance(sample_finding)
        assert "compliance_mapping" in sample_finding

    def test_returns_same_dict(self, sample_finding):
        result = enrich_finding_compliance(sample_finding)
        assert result is sample_finding

    def test_telnet_finding_enriched(self):
        finding = {"title": "Telnet Enabled", "protocol": "tcp"}
        enrich_finding_compliance(finding)
        assert "OWASP_IoT_2018" in finding["compliance_mapping"]

    def test_unknown_finding_gets_empty_mapping(self):
        finding = {"title": "Mystery Finding ZZZ99", "protocol": ""}
        enrich_finding_compliance(finding)
        assert finding["compliance_mapping"] == {}

    def test_idempotent(self, sample_finding):
        enrich_finding_compliance(sample_finding)
        first = dict(sample_finding["compliance_mapping"])
        enrich_finding_compliance(sample_finding)
        assert sample_finding["compliance_mapping"] == first
