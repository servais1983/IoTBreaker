"""Parser tests for iotbreaker.build_parser.

These tests only construct argparse namespaces. They do not call main()
and they do not open sockets.
"""

import pytest

from iotbreaker import build_parser


@pytest.fixture
def parser():
    return build_parser()


class TestGlobalOptions:
    def test_serve_defaults_bind_locally(self, parser):
        args = parser.parse_args(["--serve", "--no-banner"])
        assert args.serve is True
        assert args.host == "127.0.0.1"
        assert args.port == 8888
        assert args.module is None

    def test_scope_and_engagement_flags(self, parser):
        args = parser.parse_args([
            "--scope-file", "scope.txt",
            "--engagement", "engagement.yml",
            "--db", "results.db",
            "--no-banner",
            "firmware",
            "--file", "image.bin",
        ])
        assert args.scope_file == "scope.txt"
        assert args.engagement == "engagement.yml"
        assert args.db == "results.db"
        assert args.file == "image.bin"


class TestSubcommands:
    def test_discover_requires_network(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["discover"])

    def test_discover_defaults(self, parser):
        args = parser.parse_args(["discover", "--network", "203.0.113.0/24"])
        assert args.module == "discover"
        assert args.network == "203.0.113.0/24"
        assert args.method == "all"
        assert args.exclude is None

    def test_scan_defaults_do_not_enable_udp(self, parser):
        args = parser.parse_args(["scan", "--target", "203.0.113.10"])
        assert args.module == "scan"
        assert args.ports == "iot-common"
        assert args.udp is False
        assert args.banner is True

    def test_fingerprint_deep_flag(self, parser):
        args = parser.parse_args([
            "fingerprint", "--target", "203.0.113.10", "--deep", "--mac", "08:00:27:00:00:01",
        ])
        assert args.deep is True
        assert args.mac == "08:00:27:00:00:01"

    def test_vuln_defaults_leave_checks_off(self, parser):
        args = parser.parse_args(["vuln", "--target", "203.0.113.10"])
        assert args.all is False
        assert args.telnet is False
        assert args.cve is False

    def test_firmware_requires_file(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["firmware"])

    def test_unknown_module_rejected(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["not-a-module"])

    def test_exploit_list_still_requires_a_target(self, parser):
        with pytest.raises(SystemExit):
            parser.parse_args(["exploit", "--list"])
