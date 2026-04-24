"""
Tests for core/engine.py

Covers:
- Engine initialises with expected attributes
- load_scope: valid file loaded, missing file handled gracefully,
  comments/blanks skipped, invalid CIDR skipped
- _is_in_scope: in-scope / out-of-scope / no scope allows all / hostname passes
- _apply_module_thread_cap: caps threads correctly
- MODULE_THREAD_CAPS contains expected modules
- session_id format
- _parse_ports: iot-common, individual ports, ranges, comma list
"""
import ipaddress
import pytest
from pathlib import Path
from unittest.mock import patch

from core.engine import Engine, MODULE_THREAD_CAPS
from core.config import Config


@pytest.fixture
def engine(config) -> Engine:
    return Engine(config)


# ------------------------------------------------------------------ #
# Initialisation                                                       #
# ------------------------------------------------------------------ #

class TestEngineInit:
    def test_findings_empty_list(self, engine):
        assert engine.findings == []

    def test_devices_empty_list(self, engine):
        assert engine.devices == []

    def test_scope_networks_empty(self, engine):
        assert engine.scope_networks == []

    def test_engagement_none(self, engine):
        assert engine.engagement is None

    def test_session_id_format(self, engine):
        # Expected: YYYYMMDD_HHMMSS (15 chars)
        assert len(engine.session_id) == 15
        assert engine.session_id[8] == "_"

    def test_start_time_is_float(self, engine):
        import time
        assert isinstance(engine.start_time, float)
        assert engine.start_time <= time.time()


# ------------------------------------------------------------------ #
# MODULE_THREAD_CAPS                                                   #
# ------------------------------------------------------------------ #

class TestModuleThreadCaps:
    EXPECTED_MODULES = ["discover", "scan", "fingerprint", "vuln", "brute", "exploit", "audit"]

    def test_all_expected_modules_capped(self):
        for m in self.EXPECTED_MODULES:
            assert m in MODULE_THREAD_CAPS, f"No thread cap for module '{m}'"

    def test_caps_are_positive_ints(self):
        for m, cap in MODULE_THREAD_CAPS.items():
            assert isinstance(cap, int) and cap > 0

    def test_brute_cap_le_discover_cap(self):
        assert MODULE_THREAD_CAPS["brute"] <= MODULE_THREAD_CAPS["discover"]


# ------------------------------------------------------------------ #
# load_scope                                                           #
# ------------------------------------------------------------------ #

class TestLoadScope:
    def test_loads_valid_cidrs(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("192.168.1.0/24\n10.0.0.0/8\n")
        engine.load_scope(str(f))
        assert len(engine.scope_networks) == 2

    def test_skips_comments(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("# comment\n192.168.1.0/24\n")
        engine.load_scope(str(f))
        assert len(engine.scope_networks) == 1

    def test_skips_blank_lines(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("\n\n192.168.1.0/24\n\n")
        engine.load_scope(str(f))
        assert len(engine.scope_networks) == 1

    def test_skips_invalid_cidr(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("not_a_cidr\n192.168.1.0/24\n")
        engine.load_scope(str(f))
        assert len(engine.scope_networks) == 1

    def test_missing_file_handled_gracefully(self, engine):
        engine.load_scope("/no/such/file.txt")   # must not raise
        assert engine.scope_networks == []


# ------------------------------------------------------------------ #
# _is_in_scope                                                         #
# ------------------------------------------------------------------ #

class TestIsInScope:
    def test_no_scope_allows_all(self, engine):
        assert engine._is_in_scope("1.2.3.4") is True

    def test_ip_in_scope(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("192.168.1.0/24\n")
        engine.load_scope(str(f))
        assert engine._is_in_scope("192.168.1.100") is True

    def test_ip_not_in_scope(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("192.168.1.0/24\n")
        engine.load_scope(str(f))
        assert engine._is_in_scope("10.0.0.1") is False

    def test_hostname_passes_through(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("192.168.1.0/24\n")
        engine.load_scope(str(f))
        assert engine._is_in_scope("camera.local") is True

    def test_exact_network_address_in_scope(self, engine, tmp_dir):
        f = tmp_dir / "scope.txt"
        f.write_text("10.0.0.0/8\n")
        engine.load_scope(str(f))
        assert engine._is_in_scope("10.255.255.255") is True


# ------------------------------------------------------------------ #
# _apply_module_thread_cap                                             #
# ------------------------------------------------------------------ #

class TestApplyModuleThreadCap:
    def test_cap_applied_when_over_limit(self, engine):
        engine.config.set("threads", 999)
        engine._apply_module_thread_cap("brute")
        assert engine.config.get("threads") == MODULE_THREAD_CAPS["brute"]

    def test_cap_not_applied_when_under_limit(self, engine):
        engine.config.set("threads", 1)
        engine._apply_module_thread_cap("discover")
        assert engine.config.get("threads") == 1   # stays at 1

    def test_unknown_module_no_change(self, engine):
        engine.config.set("threads", 50)
        engine._apply_module_thread_cap("unknown_module")
        assert engine.config.get("threads") == 50


# ------------------------------------------------------------------ #
# _parse_ports                                                         #
# ------------------------------------------------------------------ #

class TestParsePorts:
    def test_single_port(self):
        assert Engine._parse_ports("80") == [80]

    def test_comma_list(self):
        assert Engine._parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        ports = Engine._parse_ports("20-25")
        assert ports == list(range(20, 26))

    def test_mixed(self):
        ports = Engine._parse_ports("22,80-82,443")
        assert 22 in ports and 80 in ports and 82 in ports and 443 in ports

    def test_iot_common_returns_nonempty_list(self):
        from core.config import IOT_COMMON_PORTS
        ports = Engine._parse_ports("iot-common")
        assert ports == IOT_COMMON_PORTS
        assert len(ports) > 10
