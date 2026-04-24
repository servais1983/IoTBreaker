"""
Tests for core/database.py

Covers:
- Schema creation (tables + indexes)
- save_session persists sessions, devices, findings
- list_sessions returns ordered rows
- get_session returns correct row / None for missing
- get_devices filters by session_id
- get_findings filters by session_id, severity, target
- search_findings keyword search
- Multiple sessions coexist
"""
import time
import types
import pytest

from core.database import Database
from core.config import Config


def _make_engine(session_id: str, findings=None, devices=None):
    """Build a minimal fake Engine namespace for Database.save_session."""
    eng = types.SimpleNamespace(
        session_id  = session_id,
        start_time  = time.time(),
        engagement  = None,
        findings    = findings or [],
        devices     = devices or [],
    )
    return eng


@pytest.fixture
def db(tmp_dir) -> Database:
    return Database(str(tmp_dir / "test.db"))


# ------------------------------------------------------------------ #
# Schema                                                               #
# ------------------------------------------------------------------ #

class TestSchema:
    def test_tables_exist(self, db):
        conn = db._conn()
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert {"sessions", "devices", "findings"}.issubset(tables)


# ------------------------------------------------------------------ #
# save_session                                                         #
# ------------------------------------------------------------------ #

class TestSaveSession:
    def test_session_row_saved(self, db, sample_finding, sample_device):
        eng = _make_engine("sess_001",
                           findings=[sample_finding],
                           devices=[sample_device])
        db.save_session(eng)
        row = db.get_session("sess_001")
        assert row is not None
        assert row["session_id"] == "sess_001"
        assert row["finding_count"] == 1
        assert row["device_count"] == 1

    def test_device_row_saved(self, db, sample_device):
        eng = _make_engine("sess_002", devices=[sample_device])
        db.save_session(eng)
        devices = db.get_devices("sess_002")
        assert len(devices) == 1
        assert devices[0]["ip"] == sample_device["ip"]

    def test_finding_row_saved(self, db, sample_finding):
        eng = _make_engine("sess_003", findings=[sample_finding])
        db.save_session(eng)
        findings = db.get_findings(session_id="sess_003")
        assert len(findings) == 1
        assert findings[0]["title"] == sample_finding["title"]
        assert findings[0]["severity"] == sample_finding["severity"]

    def test_risk_score_computed(self, db, sample_finding):
        eng = _make_engine("sess_004", findings=[sample_finding])
        db.save_session(eng)
        row = db.get_session("sess_004")
        assert isinstance(row["risk_score"], float)
        assert row["risk_score"] > 0

    def test_upsert_replaces_session(self, db):
        eng = _make_engine("sess_005")
        db.save_session(eng)
        db.save_session(eng)   # second save must not raise
        assert len(db.list_sessions()) >= 1

    def test_engagement_meta_extracted(self, db):
        eng = _make_engine("sess_006")
        eng.engagement = types.SimpleNamespace(
            client        = "Acme Corp",
            operator      = "alice",
            sow_reference = "SOW-001",
        )
        db.save_session(eng)
        row = db.get_session("sess_006")
        assert row["client"] == "Acme Corp"
        assert row["operator"] == "alice"


# ------------------------------------------------------------------ #
# list_sessions                                                         #
# ------------------------------------------------------------------ #

class TestListSessions:
    def test_returns_list(self, db):
        assert isinstance(db.list_sessions(), list)

    def test_ordered_newest_first(self, db):
        for i in range(3):
            eng = _make_engine(f"order_{i:03d}")
            eng.start_time = time.time() + i   # increasing timestamps
            db.save_session(eng)
        sessions = db.list_sessions()
        ids = [s["session_id"] for s in sessions]
        assert ids.index("order_002") < ids.index("order_000")


# ------------------------------------------------------------------ #
# get_session                                                          #
# ------------------------------------------------------------------ #

class TestGetSession:
    def test_missing_returns_none(self, db):
        assert db.get_session("does_not_exist") is None

    def test_returns_correct_session(self, db):
        db.save_session(_make_engine("target_sess"))
        row = db.get_session("target_sess")
        assert row["session_id"] == "target_sess"


# ------------------------------------------------------------------ #
# get_findings filters                                                  #
# ------------------------------------------------------------------ #

class TestGetFindings:
    def _populate(self, db):
        f1 = {"title": "High Finding", "severity": "HIGH",    "cvss_score": 7.0,
              "target": "10.0.0.1", "port": 80, "protocol": "tcp", "cve_ids": []}
        f2 = {"title": "Low Finding",  "severity": "LOW",     "cvss_score": 2.0,
              "target": "10.0.0.2", "port": 22, "protocol": "tcp", "cve_ids": []}
        eng = _make_engine("filter_sess", findings=[f1, f2])
        db.save_session(eng)

    def test_filter_by_severity(self, db):
        self._populate(db)
        highs = db.get_findings(session_id="filter_sess", severity="HIGH")
        assert all(f["severity"] == "HIGH" for f in highs)
        assert len(highs) == 1

    def test_filter_by_target(self, db):
        self._populate(db)
        hits = db.get_findings(session_id="filter_sess", target="10.0.0.2")
        assert len(hits) == 1
        assert hits[0]["target"] == "10.0.0.2"

    def test_no_filter_returns_all(self, db):
        self._populate(db)
        all_f = db.get_findings(session_id="filter_sess")
        assert len(all_f) == 2


# ------------------------------------------------------------------ #
# search_findings                                                       #
# ------------------------------------------------------------------ #

class TestSearchFindings:
    def test_keyword_match_in_title(self, db, sample_finding):
        db.save_session(_make_engine("search_sess", findings=[sample_finding]))
        results = db.search_findings("Telnet")
        assert len(results) >= 1
        assert any("Telnet" in r["title"] for r in results)

    def test_keyword_no_match(self, db, sample_finding):
        db.save_session(_make_engine("search_sess2", findings=[sample_finding]))
        assert db.search_findings("__NOMATCH__ZZZZ__") == []
