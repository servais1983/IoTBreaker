"""
Tests for modules/reporting/siem.py

Covers:
- _to_cef produces valid CEF-formatted string
- _to_ecs produces valid ECS document dict
- export_ecs writes NDJSON file with correct structure
- export_splunk_hec sends POST to mock HEC endpoint
- export_cef sends UDP datagram to mock syslog receiver
- _cef_escape handles special characters
"""
import json
import socket
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from modules.reporting.siem import SiemExporter, _cef_escape, _finding_flat
from core.config import Config


@pytest.fixture
def exporter(config) -> SiemExporter:
    return SiemExporter(config)


@pytest.fixture
def finding():
    return {
        "title":       "Telnet Enabled",
        "severity":    "HIGH",
        "cvss_score":  7.5,
        "target":      "192.168.1.10",
        "port":        23,
        "protocol":    "tcp",
        "cve_ids":     ["CVE-2023-9999"],
        "description": "Telnet is exposed.",
        "remediation": "Disable Telnet.",
    }


# ------------------------------------------------------------------ #
# CEF helpers                                                          #
# ------------------------------------------------------------------ #

class TestCefEscape:
    def test_pipe_escaped(self):
        assert "\\|" in _cef_escape("foo|bar")

    def test_equals_escaped(self):
        assert "\\=" in _cef_escape("a=b")

    def test_backslash_escaped(self):
        assert "\\\\" in _cef_escape("a\\b")

    def test_plain_string_unchanged(self):
        assert _cef_escape("hello world") == "hello world"


class TestToCef:
    def test_starts_with_cef_header(self, exporter, finding):
        msg = exporter._to_cef(finding, "sess_001")
        assert "CEF:0|IoTBreaker|IoTBreaker|4.0.0" in msg

    def test_contains_severity(self, exporter, finding):
        msg = exporter._to_cef(finding, "sess_001")
        assert "HIGH" in msg or "cs1=HIGH" in msg

    def test_contains_target_ip(self, exporter, finding):
        msg = exporter._to_cef(finding, "sess_001")
        assert "192.168.1.10" in msg

    def test_contains_session_id(self, exporter, finding):
        msg = exporter._to_cef(finding, "sess_001")
        assert "sess_001" in msg

    def test_critical_severity_is_10(self, exporter):
        f = {"title": "X", "severity": "CRITICAL", "cvss_score": 9.8,
             "target": "1.1.1.1", "port": 80, "protocol": "tcp",
             "cve_ids": [], "description": "", "remediation": ""}
        msg = exporter._to_cef(f, "s")
        # CEF field 7 (severity) should be 10
        assert "|10|" in msg


# ------------------------------------------------------------------ #
# ECS document                                                         #
# ------------------------------------------------------------------ #

class TestToEcs:
    def test_required_fields(self, exporter, finding):
        doc = exporter._to_ecs(finding, "sess_001")
        for key in ("@timestamp", "ecs", "event", "host", "vulnerability", "message"):
            assert key in doc, f"ECS doc missing '{key}'"

    def test_ecs_version_field(self, exporter, finding):
        doc = exporter._to_ecs(finding, "sess_001")
        assert doc["ecs"]["version"].startswith("8.")

    def test_host_ip_set(self, exporter, finding):
        doc = exporter._to_ecs(finding, "sess_001")
        assert "192.168.1.10" in doc["host"]["ip"]

    def test_severity_label(self, exporter, finding):
        doc = exporter._to_ecs(finding, "sess_001")
        assert doc["vulnerability"]["severity"] == "high"

    def test_risk_score_high_for_critical(self, exporter):
        f = dict(title="X", severity="CRITICAL", cvss_score=9.8,
                 target="1.1.1.1", port=80, protocol="tcp",
                 cve_ids=[], description="", remediation="")
        doc = exporter._to_ecs(f, "s")
        assert doc["event"]["risk_score"] == 99


# ------------------------------------------------------------------ #
# export_ecs (file writer)                                             #
# ------------------------------------------------------------------ #

class TestExportEcs:
    def test_creates_ndjson_file(self, exporter, finding, tmp_dir):
        path = exporter.export_ecs([finding], "sess_ecs", str(tmp_dir))
        assert Path(path).exists()

    def test_file_has_ndjson_extension(self, exporter, finding, tmp_dir):
        path = exporter.export_ecs([finding], "sess_ecs2", str(tmp_dir))
        assert path.endswith(".ndjson")

    def test_each_line_is_valid_json(self, exporter, finding, tmp_dir):
        path = exporter.export_ecs([finding, finding], "sess_ecs3", str(tmp_dir))
        lines = Path(path).read_text().strip().splitlines()
        assert len(lines) == 2
        for line in lines:
            doc = json.loads(line)
            assert "@timestamp" in doc

    def test_empty_findings_creates_empty_file(self, exporter, tmp_dir):
        path = exporter.export_ecs([], "sess_empty", str(tmp_dir))
        assert Path(path).exists()
        assert Path(path).read_text().strip() == ""


# ------------------------------------------------------------------ #
# export_splunk_hec (mocked HTTP)                                      #
# ------------------------------------------------------------------ #

class TestExportSplunkHec:
    def test_sends_post_request(self, exporter, finding):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        with patch.object(exporter.session, "post", return_value=mock_resp) as mock_post:
            result = exporter.export_splunk_hec(
                [finding], "sess_hec",
                hec_url="https://splunk.example:8088",
                hec_token="Splunk TEST_TOKEN",
            )
        assert result is True
        mock_post.assert_called_once()

    def test_authorization_header_set(self, exporter, finding):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        with patch.object(exporter.session, "post", return_value=mock_resp) as mock_post:
            exporter.export_splunk_hec(
                [finding], "sess_hec2",
                hec_url="https://splunk.example:8088",
                hec_token="TOKEN123",
            )
        _, kwargs = mock_post.call_args
        assert kwargs["headers"]["Authorization"] == "Splunk TOKEN123"

    def test_returns_false_on_network_error(self, exporter, finding):
        with patch.object(exporter.session, "post", side_effect=ConnectionError("down")):
            result = exporter.export_splunk_hec(
                [finding], "sess_hec3",
                hec_url="https://splunk.example:8088",
                hec_token="Splunk TOKEN",
            )
        assert result is False


# ------------------------------------------------------------------ #
# export_cef (UDP syslog — mocked)                                     #
# ------------------------------------------------------------------ #

class TestExportCef:
    def test_udp_send_called(self, exporter, finding):
        with patch.object(SiemExporter, "_send_udp") as mock_udp:
            sent = exporter.export_cef([finding], "sess_cef",
                                       syslog_host="127.0.0.1", syslog_port=514)
        assert sent == 1
        mock_udp.assert_called_once()

    def test_tcp_send_called_when_use_tcp(self, exporter, finding):
        with patch.object(SiemExporter, "_send_tcp") as mock_tcp:
            exporter.export_cef([finding], "sess_cef2",
                                syslog_host="127.0.0.1", syslog_port=601,
                                use_tcp=True)
        mock_tcp.assert_called_once()

    def test_returns_zero_on_all_failures(self, exporter, finding):
        with patch.object(SiemExporter, "_send_udp", side_effect=OSError("refused")):
            sent = exporter.export_cef([finding], "sess_fail",
                                       syslog_host="127.0.0.1", syslog_port=514)
        assert sent == 0


# ------------------------------------------------------------------ #
# _finding_flat helper                                                  #
# ------------------------------------------------------------------ #

class TestFindingFlat:
    def test_flat_dict_has_expected_keys(self, finding):
        flat = _finding_flat(finding)
        for key in ("title", "severity", "cvss_score", "target", "port",
                    "protocol", "cve_ids", "description", "remediation"):
            assert key in flat

    def test_cve_ids_joined(self, finding):
        flat = _finding_flat(finding)
        assert "CVE-2023-9999" in flat["cve_ids"]
