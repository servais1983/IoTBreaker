"""
Tests for core/engagement.py

Covers:
- Engagement created from dict
- validate_window: in-window / outside-window / no dates
- is_in_scope: in-scope / out-of-scope CIDRs
- summary() returns required keys
- load_engagement() from YAML file
- Invalid CIDR skipped with warning
"""
import pytest
from datetime import date, timedelta
from pathlib import Path

from core.engagement import Engagement, load_engagement


def _future(days=5):
    return (date.today() + timedelta(days=days)).isoformat()

def _past(days=5):
    return (date.today() - timedelta(days=days)).isoformat()


# ------------------------------------------------------------------ #
# Construction                                                         #
# ------------------------------------------------------------------ #

class TestEngagementConstruction:
    def test_fields_populated(self):
        eng = Engagement({
            "client": "Acme", "operator": "alice",
            "sow_reference": "SOW-01",
            "start_date": _past(), "end_date": _future(),
            "authorized_cidrs": ["192.168.1.0/24"],
        })
        assert eng.client == "Acme"
        assert eng.operator == "alice"
        assert eng.sow_reference == "SOW-01"
        assert len(eng.authorized_cidrs) == 1

    def test_invalid_cidr_skipped(self):
        eng = Engagement({
            "authorized_cidrs": ["not_a_cidr", "10.0.0.0/8"],
        })
        assert len(eng.authorized_cidrs) == 1

    def test_empty_dict_defaults(self):
        eng = Engagement({})
        assert eng.client == "Unknown"
        assert eng.authorized_cidrs == []

    def test_multiple_cidrs(self):
        eng = Engagement({
            "authorized_cidrs": ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
        })
        assert len(eng.authorized_cidrs) == 3


# ------------------------------------------------------------------ #
# validate_window                                                      #
# ------------------------------------------------------------------ #

class TestValidateWindow:
    def test_within_window(self):
        eng = Engagement({
            "start_date": _past(3),
            "end_date":   _future(3),
        })
        assert eng.validate_window() is True

    def test_before_window_start(self):
        eng = Engagement({
            "start_date": _future(2),
            "end_date":   _future(5),
        })
        assert eng.validate_window() is False

    def test_after_window_end(self):
        eng = Engagement({
            "start_date": _past(10),
            "end_date":   _past(2),
        })
        assert eng.validate_window() is False

    def test_no_dates_returns_true(self):
        eng = Engagement({})
        assert eng.validate_window() is True

    def test_start_equals_today(self):
        eng = Engagement({
            "start_date": date.today().isoformat(),
            "end_date":   _future(7),
        })
        assert eng.validate_window() is True


# ------------------------------------------------------------------ #
# is_in_scope                                                          #
# ------------------------------------------------------------------ #

class TestIsInScope:
    def test_ip_in_scope(self):
        eng = Engagement({"authorized_cidrs": ["192.168.1.0/24"]})
        assert eng.is_in_scope("192.168.1.100") is True

    def test_ip_not_in_scope(self):
        eng = Engagement({"authorized_cidrs": ["192.168.1.0/24"]})
        assert eng.is_in_scope("10.0.0.1") is False

    def test_no_cidrs_allows_all(self):
        eng = Engagement({})
        assert eng.is_in_scope("1.2.3.4") is True

    def test_multiple_cidrs_any_match(self):
        eng = Engagement({"authorized_cidrs": ["10.0.0.0/8", "192.168.0.0/16"]})
        assert eng.is_in_scope("192.168.5.5") is True
        assert eng.is_in_scope("172.16.0.1") is False


# ------------------------------------------------------------------ #
# summary()                                                            #
# ------------------------------------------------------------------ #

class TestSummary:
    def test_required_keys(self):
        eng = Engagement({"client": "Test", "operator": "bob"})
        s = eng.summary()
        assert isinstance(s, dict)
        for key in ("client", "operator", "sow_reference"):
            assert key in s


# ------------------------------------------------------------------ #
# load_engagement from YAML                                            #
# ------------------------------------------------------------------ #

class TestLoadEngagement:
    def test_loads_yaml(self, tmp_dir):
        f = tmp_dir / "eng.yml"
        f.write_text(
            "client: TestCorp\noperator: alice\n"
            f"start_date: {_past()}\nend_date: {_future()}\n"
            "authorized_cidrs:\n  - 10.0.0.0/8\n"
        )
        eng = load_engagement(str(f))
        assert eng.client == "TestCorp"
        assert len(eng.authorized_cidrs) == 1

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_engagement("/no/such/file.yml")
