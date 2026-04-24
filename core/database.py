#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - SQLite Persistence Layer

G2: Provides a queryable local database for sessions, devices, and findings
so that results persist between runs and can be compared, trended, and
searched without re-scanning.

Schema
------
sessions  : one row per run (session_id, timestamp, client, operator, risk_score)
devices   : discovered hosts linked to a session
findings  : vulnerability findings linked to a session
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logger import get_logger

logger = get_logger(__name__)

# Thread-local storage for connections (safe in multi-threaded engine)
_local = threading.local()


class Database:
    """
    Lightweight SQLite persistence for IoTBreaker sessions.

    Usage
    -----
    from core.database import Database

    db = Database("./reports/iotbreaker.db")
    db.save_session(engine)        # call after engine.run()
    sessions = db.list_sessions()
    findings = db.get_findings(session_id="20260424_143200")
    """

    def __init__(self, db_path: str = "./reports/iotbreaker.db"):
        self.db_path = str(Path(db_path).resolve())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------ #
    # Connection                                                           #
    # ------------------------------------------------------------------ #

    def _conn(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection (created on first use)."""
        if not getattr(_local, "conn", None) or _local.db_path != self.db_path:
            _local.conn     = sqlite3.connect(self.db_path, check_same_thread=False)
            _local.conn.row_factory = sqlite3.Row
            _local.conn.execute("PRAGMA journal_mode=WAL")
            _local.conn.execute("PRAGMA foreign_keys=ON")
            _local.db_path  = self.db_path
        return _local.conn

    # ------------------------------------------------------------------ #
    # Schema                                                               #
    # ------------------------------------------------------------------ #

    def _init_schema(self):
        """Create tables if they don't already exist."""
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id   TEXT PRIMARY KEY,
                started_at   TEXT NOT NULL,
                finished_at  TEXT,
                client       TEXT,
                operator     TEXT,
                sow_ref      TEXT,
                risk_score   REAL,
                finding_count INTEGER DEFAULT 0,
                device_count  INTEGER DEFAULT 0,
                tool_version  TEXT
            );

            CREATE TABLE IF NOT EXISTS devices (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL REFERENCES sessions(session_id),
                ip          TEXT,
                mac         TEXT,
                hostname    TEXT,
                vendor      TEXT,
                device_type TEXT,
                open_ports  TEXT,   -- JSON array
                raw         TEXT    -- full JSON blob
            );

            CREATE TABLE IF NOT EXISTS findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id    TEXT NOT NULL REFERENCES sessions(session_id),
                title         TEXT,
                severity      TEXT,
                cvss_score    REAL,
                target        TEXT,
                port          INTEGER,
                protocol      TEXT,
                cve_ids       TEXT,  -- JSON array
                description   TEXT,
                remediation   TEXT,
                compliance    TEXT,  -- JSON object
                raw           TEXT   -- full JSON blob
            );

            CREATE INDEX IF NOT EXISTS idx_findings_session
                ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity
                ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_target
                ON findings(target);
        """)
        conn.commit()

    # ------------------------------------------------------------------ #
    # Write API                                                            #
    # ------------------------------------------------------------------ #

    def save_session(self, engine) -> None:
        """
        Persist an engine's session, devices, and findings to the database.
        Call this after engine.run() completes.
        """
        conn = self._conn()
        now  = datetime.utcnow().isoformat()

        eng_meta = getattr(engine, "engagement", None)
        client   = eng_meta.client   if eng_meta else ""
        operator = eng_meta.operator if eng_meta else ""
        sow_ref  = eng_meta.sow_reference if eng_meta else ""

        risk_score = 0.0
        if engine.findings:
            sev_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
            risk_score = round(
                sum(sev_weights.get(f.get("severity", "INFO"), 0)
                    for f in engine.findings) / max(len(engine.findings), 1),
                2
            )

        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, started_at, finished_at, client, operator, sow_ref,
                risk_score, finding_count, device_count, tool_version)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                engine.session_id,
                datetime.utcfromtimestamp(engine.start_time).isoformat(),
                now,
                client, operator, sow_ref,
                risk_score,
                len(engine.findings),
                len(engine.devices),
                "4.0.0",
            )
        )

        for device in engine.devices:
            conn.execute(
                """INSERT INTO devices
                   (session_id, ip, mac, hostname, vendor, device_type, open_ports, raw)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    engine.session_id,
                    device.get("ip", ""),
                    device.get("mac", ""),
                    device.get("hostname", ""),
                    device.get("vendor", ""),
                    device.get("device_type", ""),
                    json.dumps(device.get("open_ports", [])),
                    json.dumps(device, default=str),
                )
            )

        for finding in engine.findings:
            conn.execute(
                """INSERT INTO findings
                   (session_id, title, severity, cvss_score, target, port,
                    protocol, cve_ids, description, remediation, compliance, raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    engine.session_id,
                    finding.get("title", ""),
                    finding.get("severity", "INFO"),
                    finding.get("cvss_score"),
                    finding.get("target", ""),
                    finding.get("port"),
                    finding.get("protocol", ""),
                    json.dumps(finding.get("cve_ids", [])),
                    finding.get("description", ""),
                    finding.get("remediation", ""),
                    json.dumps(finding.get("compliance_mapping", {})),
                    json.dumps(finding, default=str),
                )
            )

        conn.commit()
        logger.info(f"Session {engine.session_id} persisted to {self.db_path}")

    # ------------------------------------------------------------------ #
    # Read API                                                             #
    # ------------------------------------------------------------------ #

    def list_sessions(self) -> List[Dict]:
        """Return all sessions ordered by start time (newest first)."""
        rows = self._conn().execute(
            "SELECT * FROM sessions ORDER BY started_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Return metadata for a single session."""
        row = self._conn().execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_devices(self, session_id: str) -> List[Dict]:
        """Return all devices for a session."""
        rows = self._conn().execute(
            "SELECT * FROM devices WHERE session_id = ?", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_findings(
        self,
        session_id: Optional[str] = None,
        severity:   Optional[str] = None,
        target:     Optional[str] = None,
    ) -> List[Dict]:
        """
        Query findings with optional filters.
        All filters are AND-combined.
        """
        clauses: List[str] = []
        params:  List[Any] = []

        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity.upper())
        if target:
            clauses.append("target = ?")
            params.append(target)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows  = self._conn().execute(
            f"SELECT * FROM findings {where} ORDER BY cvss_score DESC NULLS LAST",
            params
        ).fetchall()
        return [dict(r) for r in rows]

    def search_findings(self, keyword: str) -> List[Dict]:
        """Full-text search across title and description."""
        rows = self._conn().execute(
            """SELECT * FROM findings
               WHERE title LIKE ? OR description LIKE ?
               ORDER BY cvss_score DESC NULLS LAST""",
            (f"%{keyword}%", f"%{keyword}%")
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        """Close the thread-local connection if open."""
        conn = getattr(_local, "conn", None)
        if conn:
            conn.close()
            _local.conn = None
