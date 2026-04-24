#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - SIEM / SOAR Export Module

4.4: Produces structured event output in three formats so findings can be
shipped directly to enterprise security platforms without manual conversion:

  - Splunk HEC  : JSON bulk payload, POST to /services/collector/event
  - Syslog CEF  : ArcSight Common Event Format over UDP/TCP syslog
  - Elastic ECS : Elastic Common Schema v8 (NDJSON), ready for _bulk ingest

Usage
-----
    from modules.reporting.siem import SiemExporter
    exporter = SiemExporter(config)
    exporter.export_splunk_hec(findings, session_id, hec_url, hec_token)
    exporter.export_cef(findings, session_id, syslog_host, syslog_port)
    exporter.export_ecs(findings, session_id, output_dir)
"""

import json
import logging
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.config import Config
from core.http import make_session
from core.logger import get_logger

logger = get_logger(__name__)

# CEF severity map  (IoTBreaker severity → CEF 0-10)
_CEF_SEVERITY: Dict[str, int] = {
    "CRITICAL": 10,
    "HIGH":     7,
    "MEDIUM":   5,
    "LOW":      3,
    "INFO":     0,
}

# ECS risk score map
_ECS_RISK: Dict[str, float] = {
    "CRITICAL": 99,
    "HIGH":     73,
    "MEDIUM":   47,
    "LOW":      21,
    "INFO":     0,
}


class SiemExporter:
    """
    Export IoTBreaker findings to SIEM / SOAR platforms.

    All three export methods can be used independently.
    """

    VENDOR  = "IoTBreaker"
    PRODUCT = "IoTBreaker"
    VERSION = "4.0.0"

    def __init__(self, config: Config):
        self.config  = config
        self.session = make_session(config)

    # ------------------------------------------------------------------ #
    # Splunk HEC                                                           #
    # ------------------------------------------------------------------ #

    def export_splunk_hec(
        self,
        findings: List[Dict],
        session_id: str,
        hec_url: str,
        hec_token: str,
        index: str = "iotbreaker",
        source_type: str = "iotbreaker:finding",
    ) -> bool:
        """
        POST findings to a Splunk HTTP Event Collector endpoint.

        Parameters
        ----------
        hec_url    : str  — e.g. "https://splunk.corp.example:8088"
        hec_token  : str  — HEC token (starts with Splunk)
        index      : str  — Splunk index name
        source_type: str  — Splunk source type

        Returns True on success.
        """
        events = []
        for finding in findings:
            events.append({
                "time":       _epoch_now(),
                "index":      index,
                "sourcetype": source_type,
                "source":     f"iotbreaker:{session_id}",
                "event": {
                    "session_id": session_id,
                    **_finding_flat(finding),
                },
            })

        url = hec_url.rstrip("/") + "/services/collector/event"
        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type":  "application/json",
        }
        # Splunk accepts newline-delimited JSON objects (NDJSON) in a single POST
        body = "\n".join(json.dumps(e) for e in events)

        try:
            resp = self.session.post(url, data=body, headers=headers, timeout=10)
            resp.raise_for_status()
            logger.info(f"Splunk HEC: {len(events)} events sent → {url}")
            return True
        except Exception as exc:
            logger.error(f"Splunk HEC export failed: {exc}")
            return False

    # ------------------------------------------------------------------ #
    # Syslog CEF                                                           #
    # ------------------------------------------------------------------ #

    def export_cef(
        self,
        findings: List[Dict],
        session_id: str,
        syslog_host: str = "127.0.0.1",
        syslog_port: int = 514,
        use_tcp: bool = False,
    ) -> int:
        """
        Send findings as CEF syslog messages.

        Returns the number of successfully sent messages.
        """
        sent = 0
        for finding in findings:
            msg = self._to_cef(finding, session_id)
            try:
                if use_tcp:
                    self._send_tcp(syslog_host, syslog_port, msg)
                else:
                    self._send_udp(syslog_host, syslog_port, msg)
                sent += 1
            except Exception as exc:
                logger.error(f"CEF syslog send failed: {exc}")
        logger.info(f"CEF export: {sent}/{len(findings)} events → {syslog_host}:{syslog_port}")
        return sent

    def _to_cef(self, finding: Dict, session_id: str) -> str:
        """Render a finding as a CEF syslog string."""
        sev         = finding.get("severity", "INFO").upper()
        cef_sev     = _CEF_SEVERITY.get(sev, 5)
        title       = _cef_escape(finding.get("title", "Unknown Finding"))
        description = _cef_escape(finding.get("description", ""))

        # CEF header: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|
        header = (
            f"CEF:0|{self.VENDOR}|{self.PRODUCT}|{self.VERSION}"
            f"|{_cef_escape(finding.get('title', 'finding'))}|{title}|{cef_sev}"
        )

        # Extension key=value pairs
        ext_pairs: List[str] = [
            f"src={finding.get('target', '')}",
            f"dpt={finding.get('port', 0)}",
            f"proto={_cef_escape(finding.get('protocol', ''))}",
            f"cs1={_cef_escape(sev)}",
            f"cs1Label=Severity",
            f"cs2={_cef_escape(','.join(finding.get('cve_ids', [])))}",
            f"cs2Label=CVE_IDs",
            f"cs3={_cef_escape(session_id)}",
            f"cs3Label=SessionID",
            f"msg={_cef_escape(description)[:512]}",
        ]
        cvss = finding.get("cvss_score")
        if cvss is not None:
            ext_pairs.append(f"cn1={cvss}")
            ext_pairs.append("cn1Label=CVSS")

        extension = " ".join(ext_pairs)
        # RFC-5424 syslog priority: facility 16 (local0) + severity 5 (notice) → 133
        syslog_pri = f"<134>1 {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} "
        return f"{syslog_pri}iotbreaker - - - {header}|{extension}"

    @staticmethod
    def _send_udp(host: str, port: int, message: str):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode("utf-8", errors="replace"), (host, port))

    @staticmethod
    def _send_tcp(host: str, port: int, message: str):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((host, port))
            sock.sendall((message + "\n").encode("utf-8", errors="replace"))

    # ------------------------------------------------------------------ #
    # Elastic ECS (NDJSON)                                                 #
    # ------------------------------------------------------------------ #

    def export_ecs(
        self,
        findings: List[Dict],
        session_id: str,
        output_dir: str = "./reports",
    ) -> str:
        """
        Write findings as Elastic Common Schema NDJSON.
        Each line is an ECS document ready for `/_bulk` ingest.

        Returns the path to the written file.
        """
        out_path = Path(output_dir) / f"iotbreaker_{session_id}_ecs.ndjson"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as fh:
            for finding in findings:
                doc = self._to_ecs(finding, session_id)
                fh.write(json.dumps(doc, default=str) + "\n")

        logger.info(f"ECS NDJSON: {len(findings)} documents → {out_path}")
        return str(out_path)

    def _to_ecs(self, finding: Dict, session_id: str) -> Dict:
        """Convert a finding dict to an ECS v8 document."""
        sev      = finding.get("severity", "INFO").upper()
        now_iso  = datetime.now(timezone.utc).isoformat()
        return {
            "@timestamp": now_iso,
            "ecs":        {"version": "8.11.0"},
            "event": {
                "kind":     "alert",
                "category": ["vulnerability"],
                "type":     ["info"],
                "severity": _CEF_SEVERITY.get(sev, 5),
                "dataset":  "iotbreaker.findings",
                "module":   "iotbreaker",
                "provider": "IoTBreaker",
                "risk_score": _ECS_RISK.get(sev, 0),
            },
            "host": {
                "ip": [finding.get("target", "")],
            },
            "network": {
                "transport": finding.get("protocol", ""),
            },
            "destination": {
                "port": finding.get("port"),
            },
            "vulnerability": {
                "id":          ",".join(finding.get("cve_ids", [])),
                "score":       {"base": finding.get("cvss_score")},
                "severity":    sev.lower(),
                "description": finding.get("description", ""),
            },
            "message":  finding.get("title", ""),
            "tags":     ["iotbreaker", session_id],
            "labels": {
                "session_id": session_id,
                "remediation": finding.get("remediation", ""),
            },
        }


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _epoch_now() -> float:
    return datetime.now(timezone.utc).timestamp()


def _cef_escape(text: str) -> str:
    """CEF requires | = \\ to be escaped in extension values."""
    return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


def _finding_flat(finding: Dict) -> Dict:
    """Return a flat dict from a finding (safe for Splunk indexing)."""
    return {
        "title":       finding.get("title", ""),
        "severity":    finding.get("severity", "INFO"),
        "cvss_score":  finding.get("cvss_score"),
        "target":      finding.get("target", ""),
        "port":        finding.get("port"),
        "protocol":    finding.get("protocol", ""),
        "cve_ids":     ",".join(finding.get("cve_ids", [])),
        "description": finding.get("description", ""),
        "remediation": finding.get("remediation", ""),
    }
