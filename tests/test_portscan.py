"""Offline tests for PortScanner.

Probe methods are patched. No sockets are opened.
"""

from unittest.mock import patch

from modules.scanner.portscan import PortScanner


class TestScanDispatch:
    def test_results_sorted_and_udp_skipped_by_default(self, config):
        scanner = PortScanner(config)
        tcp_rows = [
            {"port": 80, "state": "open", "protocol": "tcp"},
            {"port": 22, "state": "open", "protocol": "tcp"},
        ]
        with patch.object(scanner, "_tcp_scan", return_value=tcp_rows) as tcp, \
             patch.object(scanner, "_udp_scan") as udp:
            results = scanner.scan("203.0.113.10", [80, 22], udp=False, banner=False)
        tcp.assert_called_once_with("203.0.113.10", [80, 22], False)
        udp.assert_not_called()
        assert [row["port"] for row in results] == [22, 80]

    def test_udp_flag_calls_udp_scan(self, config):
        scanner = PortScanner(config)
        with patch.object(scanner, "_tcp_scan", return_value=[]), \
             patch.object(scanner, "_udp_scan", return_value=[{"port": 161, "state": "open"}]) as udp:
            results = scanner.scan("203.0.113.10", [161], udp=True, banner=False)
        udp.assert_called_once()
        assert results[0]["port"] == 161


class TestExtractVersion:
    def test_openssh_banner(self, config):
        scanner = PortScanner(config)
        assert scanner._extract_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu") == "8.9p1"

    def test_empty_banner(self, config):
        scanner = PortScanner(config)
        assert scanner._extract_version("") == ""

    def test_unrecognized_banner(self, config):
        scanner = PortScanner(config)
        assert scanner._extract_version("hello") == ""
