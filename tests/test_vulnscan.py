"""Offline tests for the vulnerability-check dispatcher and CVE client.

Check functions and HTTP calls are mocked. Nothing is sent to a host.
"""

from unittest.mock import MagicMock, patch

from modules.vulnscan.cve_lookup import CVELookup, cvss_to_severity
from modules.vulnscan.vulnscan import Finding, VulnScanner


class TestFinding:
    def test_to_dict_round_trip(self):
        finding = Finding(
            title="Example",
            severity="LOW",
            description="Descriptive text",
            target="203.0.113.10",
            port=80,
            protocol="tcp",
            cvss_score=3.1,
            cve_ids=["CVE-2099-0001"],
            remediation="Close the service.",
        )
        data = finding.to_dict()
        assert data["title"] == "Example"
        assert data["cve_ids"] == ["CVE-2099-0001"]
        assert data["port"] == 80


class TestCvssSeverity:
    def test_standard_bands(self):
        assert cvss_to_severity(0.0) == "NONE"
        assert cvss_to_severity(3.9) == "LOW"
        assert cvss_to_severity(4.0) == "MEDIUM"
        assert cvss_to_severity(8.95) == "HIGH"
        assert cvss_to_severity(9.0) == "CRITICAL"
        assert cvss_to_severity(10) == "CRITICAL"

    def test_out_of_range_and_missing(self):
        assert cvss_to_severity(None) == "UNKNOWN"
        assert cvss_to_severity(-0.1) == "UNKNOWN"
        assert cvss_to_severity(10.1) == "UNKNOWN"


class TestVulnScannerDispatch:
    def test_only_requested_check_runs(self, config):
        scanner = VulnScanner(config)
        finding = Finding("T", "INFO", "d", "203.0.113.10")
        with patch.object(scanner, "_check_telnet", return_value=finding) as telnet, \
             patch.object(scanner, "_check_ssh") as ssh:
            results = scanner.run("203.0.113.10", checks=["telnet"], cve_lookup=False)
        telnet.assert_called_once_with("203.0.113.10")
        ssh.assert_not_called()
        assert results[0]["title"] == "T"

    def test_unknown_check_is_ignored(self, config):
        scanner = VulnScanner(config)
        with patch.object(scanner, "_check_telnet") as telnet:
            assert scanner.run("203.0.113.10", checks=["not-a-check"]) == []
        telnet.assert_not_called()

    def test_check_exception_does_not_abort(self, config):
        scanner = VulnScanner(config)
        with patch.object(scanner, "_check_ftp", side_effect=RuntimeError("boom")):
            assert scanner.run("203.0.113.10", checks=["ftp"]) == []

    def test_cve_enrichment_only_when_requested(self, config):
        scanner = VulnScanner(config)
        finding = Finding("T", "LOW", "d", "203.0.113.10")
        with patch.object(scanner, "_check_snmp", return_value=finding), \
             patch.object(scanner, "_enrich_with_cve") as enrich:
            scanner.run("203.0.113.10", checks=["snmp"], cve_lookup=False)
            enrich.assert_not_called()
            scanner.run("203.0.113.10", checks=["snmp"], cve_lookup=True)
            enrich.assert_called_once()


class TestCveLookupMocked:
    def test_get_by_id_parses_mocked_response_and_caches(self, config):
        lookup = CVELookup(config)
        body = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2099-0001",
                    "descriptions": [{"lang": "en", "value": "Synthetic record for a unit test."}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 8.95, "vectorString": "CVSS:3.1/AV:N"}
                        }]
                    },
                    "published": "2099-01-01T00:00:00.000",
                }
            }]
        }
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = body
        with patch("modules.vulnscan.cve_lookup.requests.get", return_value=response) as get, \
             patch("modules.vulnscan.cve_lookup.time.sleep"):
            first = lookup.get_by_id("CVE-2099-0001")
            second = lookup.get_by_id("CVE-2099-0001")
        assert get.call_count == 1
        assert first["id"] == "CVE-2099-0001"
        assert first["severity"] == "HIGH"
        assert second is first
        assert "services.nvd.nist.gov" in get.call_args.args[0]
