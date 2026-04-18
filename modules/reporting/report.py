#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Professional Reporting Module

Generates comprehensive penetration test reports in multiple formats:
  - JSON  : Machine-readable structured output
  - HTML  : Professional standalone report with dark theme
  - PDF   : Printable report via WeasyPrint or wkhtmltopdf
  - TXT   : Plain-text summary for logging

Reports include:
  - Executive summary with risk score
  - Findings table with CVSS v3.1 scores
  - Affected hosts inventory
  - Remediation recommendations
  - Scan metadata and statistics
"""

import json
import os
import re
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.logger import get_logger
from core.output import Console
from core.config import Config

logger = get_logger(__name__)

VERSION = "4.0.0"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#27ae60",
    "INFO":     "#2980b9",
    "UNKNOWN":  "#7f8c8d",
}


class ReportGenerator:
    """
    Multi-format penetration test report generator.

    Aggregates scan results, findings, and host data into
    professional reports suitable for client delivery.
    """

    def __init__(
        self,
        session_id: str,
        devices: List[Dict],
        findings: List[Dict],
        config: Config
    ):
        self.session_id = session_id
        self.devices = devices
        self.findings = self._normalize_findings(findings)
        self.config = config
        self.generated_at = datetime.datetime.now().isoformat()
        self.statistics = self._compute_statistics(self.findings)
        self.risk_score = self._compute_risk_score(self.findings)

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def generate_json(self, output_dir: Path) -> str:
        """Generate JSON report."""
        path = output_dir / f"iotbreaker_{self.session_id}.json"
        data = {
            "session_id":   self.session_id,
            "generated_at": self.generated_at,
            "tool_version": VERSION,
            "risk_score":   self.risk_score,
            "statistics":   self.statistics,
            "devices":      self.devices,
            "findings":     self.findings,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        return str(path)

    def generate_html(self, output_dir: Path) -> str:
        """Generate HTML report."""
        path = output_dir / f"iotbreaker_{self.session_id}.html"
        html = self._build_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(path)

    def generate_pdf(self, output_dir: Path) -> str:
        """Generate PDF report via WeasyPrint or wkhtmltopdf."""
        html_path = output_dir / f"iotbreaker_{self.session_id}.html"
        pdf_path  = output_dir / f"iotbreaker_{self.session_id}.pdf"

        # Ensure HTML exists
        if not html_path.exists():
            self.generate_html(output_dir)

        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            return str(pdf_path)
        except ImportError:
            pass

        try:
            import subprocess
            result = subprocess.run(
                ["wkhtmltopdf", "--quiet", str(html_path), str(pdf_path)],
                capture_output=True, timeout=60
            )
            if result.returncode == 0:
                return str(pdf_path)
        except FileNotFoundError:
            pass

        Console.warning("PDF generation requires WeasyPrint or wkhtmltopdf.")
        Console.info("Install: pip install weasyprint  OR  apt install wkhtmltopdf")
        return str(html_path)

    def generate_txt(self, output_dir: Path) -> str:
        """Generate plain-text summary report."""
        path = output_dir / f"iotbreaker_{self.session_id}.txt"
        lines = []
        sep = "=" * 80

        lines.extend([
            sep,
            "IOTBREAKER PENETRATION TEST REPORT",
            f"Version {VERSION}",
            sep,
            f"Session ID : {self.session_id}",
            f"Generated  : {self.generated_at}",
            f"Risk Score : {self.risk_score}/10",
            "",
            "SUMMARY",
            "-" * 40,
        ])

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.statistics.get(sev, 0)
            if count > 0:
                lines.append(f"  {sev:<12}: {count}")

        lines.append("")
        lines.append("FINDINGS")
        lines.append("-" * 40)

        for i, f in enumerate(self.findings, 1):
            lines.extend([
                f"\n[{i}] {f.get('title', 'N/A')}",
                f"    Severity : {f.get('severity', 'N/A')}",
                f"    CVSS     : {f.get('cvss_score', 'N/A')}",
                f"    Target   : {f.get('target', 'N/A')}",
                f"    CVE(s)   : {', '.join(f.get('cve_ids', [])) or 'N/A'}",
                f"    Evidence : {f.get('evidence', 'N/A')}",
                f"    Fix      : {f.get('remediation', 'N/A')}",
            ])

        lines.extend(["", sep, "END OF REPORT", sep])

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return str(path)

    # ------------------------------------------------------------------ #
    # HTML builder                                                         #
    # ------------------------------------------------------------------ #

    def _build_html(self) -> str:
        """Build the complete HTML report string."""
        findings = self.findings
        stats = self.statistics
        risk_score = self.risk_score
        hosts = self.devices

        # Build findings rows
        findings_rows = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "UNKNOWN")
            color = SEVERITY_COLORS.get(sev, "#7f8c8d")
            cvss = f.get("cvss_score", "N/A")
            cves = ", ".join(f.get("cve_ids", [])) or "N/A"
            port_info = f"{f.get('port')}/{f.get('protocol','tcp')}" if f.get("port") else "N/A"
            findings_rows += f"""
            <tr>
              <td class="text-center font-mono text-sm">{i}</td>
              <td class="font-semibold">{self._esc(f.get('title',''))}</td>
              <td><span class="badge" style="background:{color}">{sev}</span></td>
              <td class="text-center font-mono">{cvss}</td>
              <td class="font-mono text-sm">{self._esc(str(f.get('target','N/A')))}</td>
              <td class="text-center font-mono text-sm">{port_info}</td>
              <td class="font-mono text-sm">{self._esc(cves)}</td>
            </tr>
            <tr class="detail-row">
              <td colspan="7">
                <div class="detail-box">
                  <div class="detail-section">
                    <strong>Description</strong>
                    <p>{self._esc(f.get('description',''))}</p>
                  </div>
                  <div class="detail-section">
                    <strong>Evidence</strong>
                    <code>{self._esc(f.get('evidence','N/A'))}</code>
                  </div>
                  <div class="detail-section remediation">
                    <strong>Remediation</strong>
                    <p>{self._esc(f.get('remediation','N/A'))}</p>
                  </div>
                </div>
              </td>
            </tr>"""

        # Build host rows
        host_rows = ""
        for h in hosts:
            open_ports = ", ".join(str(p) for p in h.get("open_ports", [])[:10])
            host_rows += f"""
            <tr>
              <td class="font-mono">{self._esc(h.get('ip',''))}</td>
              <td>{self._esc(h.get('hostname','N/A'))}</td>
              <td>{self._esc(h.get('manufacturer','N/A'))}</td>
              <td>{self._esc(h.get('device_type','N/A'))}</td>
              <td>{self._esc(h.get('os','N/A'))}</td>
              <td class="font-mono text-sm">{open_ports or 'N/A'}</td>
            </tr>"""

        # Risk score color
        if risk_score >= 8:
            risk_color = "#c0392b"
        elif risk_score >= 6:
            risk_color = "#e67e22"
        elif risk_score >= 4:
            risk_color = "#f39c12"
        else:
            risk_color = "#27ae60"

        host_section = ""
        if hosts:
            host_section = f"""
  <div class="section">
    <h2>Host Inventory</h2>
    <div class="card">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>IP Address</th><th>Hostname</th><th>Manufacturer</th>
              <th>Device Type</th><th>OS</th><th>Open Ports</th>
            </tr>
          </thead>
          <tbody>{host_rows}</tbody>
        </table>
      </div>
    </div>
  </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoTBreaker - Penetration Test Report</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg:      #0d1117;
      --surface: #161b22;
      --border:  #30363d;
      --text:    #e6edf3;
      --muted:   #8b949e;
      --accent:  #1f6feb;
      --mono:    'Cascadia Code','Fira Code','Consolas',monospace;
    }}
    body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; font-size:14px; line-height:1.6; }}
    .container {{ max-width:1280px; margin:0 auto; padding:0 24px; }}
    .section {{ margin-bottom:40px; }}
    header {{ background:linear-gradient(135deg,#0d1117,#161b22); border-bottom:1px solid var(--border); padding:32px 0; margin-bottom:40px; }}
    .header-inner {{ display:flex; justify-content:space-between; align-items:center; }}
    .header-title {{ font-size:28px; font-weight:700; letter-spacing:-0.5px; }}
    .header-title span {{ color:var(--accent); }}
    .header-meta {{ text-align:right; color:var(--muted); font-size:13px; line-height:1.8; }}
    .card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:24px; margin-bottom:24px; }}
    .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:16px; margin-bottom:24px; }}
    .stat-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:20px; text-align:center; }}
    .stat-number {{ font-size:36px; font-weight:700; line-height:1; }}
    .stat-label {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:0.8px; margin-top:6px; }}
    .risk-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:24px; display:flex; align-items:center; gap:24px; margin-bottom:24px; }}
    .risk-score {{ font-size:56px; font-weight:800; line-height:1; color:{risk_color}; }}
    .risk-info h3 {{ font-size:18px; margin-bottom:4px; }}
    .risk-info p {{ color:var(--muted); font-size:13px; }}
    .table-wrap {{ overflow-x:auto; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    thead th {{ background:#1c2128; color:var(--muted); font-weight:600; text-transform:uppercase; letter-spacing:0.5px; font-size:11px; padding:10px 14px; text-align:left; border-bottom:1px solid var(--border); }}
    tbody tr {{ border-bottom:1px solid var(--border); transition:background 0.15s; }}
    tbody tr:hover {{ background:rgba(255,255,255,0.03); }}
    tbody td {{ padding:12px 14px; vertical-align:top; }}
    .detail-row {{ background:#0d1117 !important; }}
    .detail-box {{ padding:16px; border-left:3px solid var(--accent); }}
    .detail-section {{ margin-bottom:10px; }}
    .detail-section strong {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:0.5px; display:block; margin-bottom:4px; }}
    .detail-section p, .detail-section code {{ color:var(--text); }}
    .detail-section code {{ font-family:var(--mono); font-size:12px; background:#1c2128; padding:6px 10px; border-radius:4px; word-break:break-all; display:block; }}
    .remediation p {{ color:#2ecc71; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; color:#fff; text-transform:uppercase; letter-spacing:0.5px; }}
    .font-mono {{ font-family:var(--mono); }}
    .font-semibold {{ font-weight:600; }}
    .text-center {{ text-align:center; }}
    .text-sm {{ font-size:12px; }}
    h2 {{ font-size:20px; font-weight:700; margin-bottom:16px; }}
    footer {{ border-top:1px solid var(--border); padding:24px 0; text-align:center; color:var(--muted); font-size:12px; margin-top:60px; }}
  </style>
</head>
<body>
<header>
  <div class="container">
    <div class="header-inner">
      <div>
        <div class="header-title">IoT<span>Breaker</span></div>
        <div style="color:var(--muted);font-size:13px;margin-top:4px;">IoT Penetration Testing Framework v{VERSION}</div>
      </div>
      <div class="header-meta">
        <div>Session: {self.session_id}</div>
        <div>Generated: {self.generated_at}</div>
        <div>Findings: {len(findings)} | Hosts: {len(hosts)}</div>
      </div>
    </div>
  </div>
</header>
<div class="container">
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="risk-card">
      <div class="risk-score">{risk_score:.1f}</div>
      <div class="risk-info">
        <h3>Overall Risk Score</h3>
        <p>Calculated from CVSS v3.1 base scores of all findings.<br>Scale: 0.0 (no risk) to 10.0 (critical risk).</p>
      </div>
    </div>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-number" style="color:{SEVERITY_COLORS['CRITICAL']}">{stats.get('CRITICAL',0)}</div><div class="stat-label">Critical</div></div>
      <div class="stat-card"><div class="stat-number" style="color:{SEVERITY_COLORS['HIGH']}">{stats.get('HIGH',0)}</div><div class="stat-label">High</div></div>
      <div class="stat-card"><div class="stat-number" style="color:{SEVERITY_COLORS['MEDIUM']}">{stats.get('MEDIUM',0)}</div><div class="stat-label">Medium</div></div>
      <div class="stat-card"><div class="stat-number" style="color:{SEVERITY_COLORS['LOW']}">{stats.get('LOW',0)}</div><div class="stat-label">Low</div></div>
      <div class="stat-card"><div class="stat-number" style="color:var(--muted)">{len(findings)}</div><div class="stat-label">Total</div></div>
      <div class="stat-card"><div class="stat-number" style="color:var(--accent)">{len(hosts)}</div><div class="stat-label">Hosts</div></div>
    </div>
  </div>
  <div class="section">
    <h2>Security Findings</h2>
    <div class="card">
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>#</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Target</th><th>Port</th><th>CVE(s)</th></tr>
          </thead>
          <tbody>
            {findings_rows if findings_rows else '<tr><td colspan="7" class="text-center" style="padding:32px;color:var(--muted)">No findings recorded.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {host_section}
</div>
<footer>
  <div class="container">
    IoTBreaker v{VERSION} &mdash; For authorized security testing only. &mdash; {self.generated_at}
  </div>
</footer>
</body>
</html>"""

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _normalize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Sort and normalize findings by severity."""
        for f in findings:
            if not f.get("severity"):
                score = f.get("cvss_score") or 0
                if score >= 9.0:
                    f["severity"] = "CRITICAL"
                elif score >= 7.0:
                    f["severity"] = "HIGH"
                elif score >= 4.0:
                    f["severity"] = "MEDIUM"
                elif score > 0:
                    f["severity"] = "LOW"
                else:
                    f["severity"] = "INFO"
        return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 99))

    def _compute_statistics(self, findings: List[Dict]) -> Dict:
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO")
            stats[sev] = stats.get(sev, 0) + 1
        return stats

    def _compute_risk_score(self, findings: List[Dict]) -> float:
        if not findings:
            return 0.0
        scores = [f.get("cvss_score") or 0 for f in findings]
        scores = [s for s in scores if s > 0]
        if not scores:
            sev_scores = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}
            scores = [sev_scores.get(f.get("severity", "INFO"), 0) for f in findings]
        if not scores:
            return 0.0
        max_score = max(scores)
        avg_score = sum(scores) / len(scores)
        critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        risk = (max_score * 0.5) + (avg_score * 0.3) + min(critical_count * 0.5 + high_count * 0.2, 2.0)
        return round(min(risk, 10.0), 1)

    def _esc(self, text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))
