"""
Tests for modules/reporting/report.py

Covers:
- generate_json writes valid JSON with expected keys
- generate_html writes file containing HTML tags
- generate_txt writes non-empty file
- generate_delta produces correct new/resolved/changed sections
- _esc escapes HTML special characters
- risk_score and statistics are computed
"""
import json
import pytest
from pathlib import Path

from modules.reporting.report import ReportGenerator
from core.config import Config


def _rg(session_id="test_sess", devices=None, findings=None, config=None):
    c = config or Config()
    return ReportGenerator(
        session_id=session_id,
        devices=devices or [],
        findings=findings or [],
        config=c,
    )


# ------------------------------------------------------------------ #
# JSON report                                                          #
# ------------------------------------------------------------------ #

class TestGenerateJson:
    def test_creates_file(self, tmp_dir, sample_finding, sample_device):
        rg = _rg(findings=[sample_finding], devices=[sample_device])
        path = rg.generate_json(tmp_dir)
        assert Path(path).exists()

    def test_json_valid(self, tmp_dir, sample_finding):
        rg = _rg(findings=[sample_finding])
        path = rg.generate_json(tmp_dir)
        with open(path) as f:
            data = json.load(f)
        assert "findings" in data
        assert "devices" in data
        assert "session_id" in data
        assert "risk_score" in data
        assert "statistics" in data

    def test_json_contains_finding(self, tmp_dir, sample_finding):
        rg = _rg(findings=[sample_finding])
        path = rg.generate_json(tmp_dir)
        data = json.loads(Path(path).read_text())
        titles = [f["title"] for f in data["findings"]]
        assert sample_finding["title"] in titles

    def test_engagement_meta_in_json(self, tmp_dir):
        c = Config()
        c.set("engagement_meta", {"client": "Acme", "operator": "alice"})
        rg = _rg(config=c)
        path = rg.generate_json(tmp_dir)
        data = json.loads(Path(path).read_text())
        assert data["engagement"]["client"] == "Acme"

    def test_empty_findings_risk_score_zero(self, tmp_dir):
        rg = _rg()
        path = rg.generate_json(tmp_dir)
        data = json.loads(Path(path).read_text())
        assert data["risk_score"] == 0.0


# ------------------------------------------------------------------ #
# HTML report                                                          #
# ------------------------------------------------------------------ #

class TestGenerateHtml:
    def test_creates_file(self, tmp_dir, sample_finding):
        rg = _rg(findings=[sample_finding])
        path = rg.generate_html(tmp_dir)
        assert Path(path).exists()

    def test_is_html(self, tmp_dir, sample_finding):
        rg = _rg(findings=[sample_finding])
        path = rg.generate_html(tmp_dir)
        content = Path(path).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content or "<html" in content.lower()

    def test_xss_characters_escaped(self, tmp_dir):
        evil = {
            "title":    "<script>alert('xss')</script>",
            "severity": "HIGH", "cvss_score": 5.0,
            "target":   "1.2.3.4", "port": 80, "protocol": "tcp",
            "cve_ids":  [], "description": "desc", "remediation": "fix",
        }
        rg = _rg(findings=[evil])
        path = rg.generate_html(tmp_dir)
        content = Path(path).read_text(encoding="utf-8")
        assert "<script>alert(" not in content


# ------------------------------------------------------------------ #
# TXT report                                                           #
# ------------------------------------------------------------------ #

class TestGenerateTxt:
    def test_creates_nonempty_file(self, tmp_dir, sample_finding):
        rg = _rg(findings=[sample_finding])
        path = rg.generate_txt(tmp_dir)
        assert Path(path).exists()
        assert Path(path).stat().st_size > 0


# ------------------------------------------------------------------ #
# Delta report                                                         #
# ------------------------------------------------------------------ #

class TestGenerateDelta:
    def _write_baseline(self, tmp_dir, findings):
        """Write a baseline JSON report to disk and return its path."""
        baseline = {
            "session_id": "baseline_sess",
            "findings": findings,
        }
        path = tmp_dir / "baseline.json"
        path.write_text(json.dumps(baseline))
        return str(path)

    def test_new_finding_detected(self, tmp_dir, sample_finding):
        baseline_path = self._write_baseline(tmp_dir, [])  # empty baseline
        rg = _rg(session_id="curr", findings=[sample_finding])
        delta_path = rg.generate_delta(baseline_path, tmp_dir)
        delta = json.loads(Path(delta_path).read_text())
        assert delta["summary"]["new_count"] == 1
        assert delta["summary"]["resolved_count"] == 0

    def test_resolved_finding_detected(self, tmp_dir, sample_finding):
        baseline_path = self._write_baseline(tmp_dir, [sample_finding])
        rg = _rg(session_id="curr2", findings=[])  # finding gone
        delta_path = rg.generate_delta(baseline_path, tmp_dir)
        delta = json.loads(Path(delta_path).read_text())
        assert delta["summary"]["resolved_count"] == 1

    def test_changed_finding_detected(self, tmp_dir, sample_finding):
        baseline_path = self._write_baseline(tmp_dir, [sample_finding])
        changed = dict(sample_finding)
        changed["severity"] = "CRITICAL"
        rg = _rg(session_id="curr3", findings=[changed])
        delta_path = rg.generate_delta(baseline_path, tmp_dir)
        delta = json.loads(Path(delta_path).read_text())
        assert delta["summary"]["changed_count"] == 1

    def test_missing_baseline_raises(self, tmp_dir):
        rg = _rg()
        with pytest.raises(FileNotFoundError):
            rg.generate_delta("/no/such/file.json", tmp_dir)

    def test_delta_file_named_correctly(self, tmp_dir):
        baseline_path = self._write_baseline(tmp_dir, [])
        rg = _rg(session_id="mysession")
        path = rg.generate_delta(baseline_path, tmp_dir)
        assert "mysession_delta" in path


# ------------------------------------------------------------------ #
# Statistics                                                           #
# ------------------------------------------------------------------ #

class TestStatistics:
    def test_severity_counts(self):
        findings = [
            {"title": "A", "severity": "HIGH",     "cvss_score": 7.0, "target": "1.1.1.1",
             "port": 80, "protocol": "tcp", "cve_ids": [], "description": "", "remediation": ""},
            {"title": "B", "severity": "HIGH",     "cvss_score": 7.5, "target": "1.1.1.1",
             "port": 22, "protocol": "tcp", "cve_ids": [], "description": "", "remediation": ""},
            {"title": "C", "severity": "CRITICAL", "cvss_score": 9.8, "target": "1.1.1.1",
             "port": 23, "protocol": "tcp", "cve_ids": [], "description": "", "remediation": ""},
        ]
        rg = _rg(findings=findings)
        assert rg.statistics.get("HIGH", 0) == 2
        assert rg.statistics.get("CRITICAL", 0) == 1

    def test_risk_score_increases_with_severity(self):
        low_rg  = _rg(findings=[{
            "title": "L", "severity": "LOW", "cvss_score": 2.0, "target": "1.1.1.1",
            "port": 80, "protocol": "tcp", "cve_ids": [], "description": "", "remediation": ""}])
        high_rg = _rg(findings=[{
            "title": "H", "severity": "CRITICAL", "cvss_score": 9.8, "target": "1.1.1.1",
            "port": 80, "protocol": "tcp", "cve_ids": [], "description": "", "remediation": ""}])
        assert high_rg.risk_score > low_rg.risk_score
