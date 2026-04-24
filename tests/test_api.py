"""
Tests for core/api.py (REST API — Flask)

Covers:
- GET /api/v1/health returns 200 + {"status": "ok"}
- GET /api/v1/sessions without DB returns 503
- GET /api/v1/sessions with DB returns list
- GET /api/v1/sessions/<id> not found returns 404
- GET /api/v1/sessions/<id> found returns session data
- GET /api/v1/findings with keyword query
- POST /api/v1/scan missing module returns 400
- POST /api/v1/scan valid body returns 202 + job_id
- GET /api/v1/scan/<job_id> not found returns 404
- GET /api/v1/scan/<job_id> found returns job dict
"""
import json
import time
import types
import pytest
from unittest.mock import patch, MagicMock

from core.config import Config


# ------------------------------------------------------------------ #
# Flask available check                                                #
# ------------------------------------------------------------------ #
flask = pytest.importorskip("flask", reason="flask not installed — skip API tests")


from core.api import create_app


@pytest.fixture
def app(config):
    return create_app(config, db_path="")


@pytest.fixture
def client(app):
    app.config["TESTING"] = True
    return app.test_client()


# ------------------------------------------------------------------ #
# Health                                                               #
# ------------------------------------------------------------------ #

class TestHealth:
    def test_returns_200(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200

    def test_body_has_status_ok(self, client):
        r = client.get("/api/v1/health")
        data = json.loads(r.data)
        assert data["status"] == "ok"

    def test_body_has_version(self, client):
        r = client.get("/api/v1/health")
        data = json.loads(r.data)
        assert "version" in data


# ------------------------------------------------------------------ #
# Sessions (no DB configured)                                          #
# ------------------------------------------------------------------ #

class TestSessionsNoDb:
    def test_sessions_without_db_returns_503(self, client):
        r = client.get("/api/v1/sessions")
        assert r.status_code == 503

    def test_single_session_without_db_returns_503(self, client):
        r = client.get("/api/v1/sessions/test_id")
        assert r.status_code == 503


# ------------------------------------------------------------------ #
# Sessions (with mocked DB)                                            #
# ------------------------------------------------------------------ #

@pytest.fixture
def app_with_db(config, tmp_dir):
    from core.database import Database
    db_path = str(tmp_dir / "api_test.db")
    db = Database(db_path)
    # Seed a session
    eng = types.SimpleNamespace(
        session_id="api_sess_001",
        start_time=time.time(),
        engagement=None,
        findings=[{
            "title": "Telnet Enabled", "severity": "HIGH", "cvss_score": 7.5,
            "target": "192.168.1.1", "port": 23, "protocol": "tcp",
            "cve_ids": [], "description": "desc", "remediation": "fix",
        }],
        devices=[{"ip": "192.168.1.1", "mac": "", "hostname": "",
                  "vendor": "", "device_type": "", "open_ports": [23]}],
    )
    db.save_session(eng)
    return create_app(config, db_path=db_path), db_path


class TestSessionsWithDb:
    def test_list_sessions_returns_list(self, app_with_db):
        app, _ = app_with_db
        app.config["TESTING"] = True
        c = app.test_client()
        r = c.get("/api/v1/sessions")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_session_found(self, app_with_db):
        app, _ = app_with_db
        app.config["TESTING"] = True
        c = app.test_client()
        r = c.get("/api/v1/sessions/api_sess_001")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["session_id"] == "api_sess_001"
        assert "findings" in data
        assert "devices" in data

    def test_get_session_not_found(self, app_with_db):
        app, _ = app_with_db
        app.config["TESTING"] = True
        c = app.test_client()
        r = c.get("/api/v1/sessions/__no_such_session__")
        assert r.status_code == 404


# ------------------------------------------------------------------ #
# Findings                                                             #
# ------------------------------------------------------------------ #

class TestFindings:
    def test_findings_with_db_returns_list(self, app_with_db):
        app, _ = app_with_db
        app.config["TESTING"] = True
        c = app.test_client()
        r = c.get("/api/v1/findings?session=api_sess_001")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, list)

    def test_findings_keyword_search(self, app_with_db):
        app, _ = app_with_db
        app.config["TESTING"] = True
        c = app.test_client()
        r = c.get("/api/v1/findings?q=Telnet")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert any("Telnet" in f["title"] for f in data)

    def test_findings_no_db_returns_503(self, client):
        r = client.get("/api/v1/findings")
        assert r.status_code == 503


# ------------------------------------------------------------------ #
# Scan jobs                                                            #
# ------------------------------------------------------------------ #

class TestScanJobs:
    def test_missing_module_returns_400(self, client):
        r = client.post("/api/v1/scan",
                        data=json.dumps({"target": "192.168.1.1"}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_valid_scan_returns_202_and_job_id(self, client):
        # Patch engine.run to avoid actual network scanning
        with patch("core.engine.Engine.run", return_value=0):
            r = client.post("/api/v1/scan",
                            data=json.dumps({"module": "vuln", "target": "127.0.0.1"}),
                            content_type="application/json")
        assert r.status_code == 202
        data = json.loads(r.data)
        assert "job_id" in data
        assert data["status"] == "queued"

    def test_poll_unknown_job_returns_404(self, client):
        r = client.get("/api/v1/scan/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_poll_known_job_returns_job(self, client):
        with patch("core.engine.Engine.run", return_value=0):
            post_r = client.post(
                "/api/v1/scan",
                data=json.dumps({"module": "discover", "target": "127.0.0.1"}),
                content_type="application/json",
            )
        job_id = json.loads(post_r.data)["job_id"]
        poll_r = client.get(f"/api/v1/scan/{job_id}")
        assert poll_r.status_code == 200
        data = json.loads(poll_r.data)
        assert data["id"] == job_id
        assert "status" in data
