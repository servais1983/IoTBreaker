#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - REST API Server

G3: Exposes IoTBreaker capabilities over HTTP so it can be integrated into
CI/CD pipelines, custom dashboards, and SOAR platforms.

Start with:
    python iotbreaker.py --serve [--port 8888] [--db ./reports/iotbreaker.db]

Requires Flask:
    pip install flask

Endpoints
---------
GET  /api/v1/health             — liveness probe
GET  /api/v1/sessions           — list all persisted sessions
GET  /api/v1/sessions/<id>      — full session detail (devices + findings)
GET  /api/v1/findings           — query findings (?session=, ?severity=, ?target=, ?q=)
POST /api/v1/scan               — run a module asynchronously
GET  /api/v1/scan/<job_id>      — poll scan job status
"""

import json
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from core.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# In-memory job store (reset on restart; use DB for persistence)
# ---------------------------------------------------------------------------
_jobs: Dict[str, Dict] = {}
_jobs_lock = threading.Lock()


def _job_create(module: str, args_dict: dict) -> str:
    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _jobs[job_id] = {
            "id":         job_id,
            "module":     module,
            "status":     "queued",
            "created_at": datetime.utcnow().isoformat(),
            "finished_at": None,
            "findings":   [],
            "devices":    [],
            "error":      None,
        }
    return job_id


def _job_run(job_id: str, module: str, request_data: dict, config):
    """Execute a scan in a background thread and update the job store."""
    import argparse

    with _jobs_lock:
        _jobs[job_id]["status"] = "running"

    try:
        from core.engine import Engine
        engine = Engine(config)

        # Build a minimal args namespace from the request body
        ns = argparse.Namespace(
            module=module,
            format="json",
            **request_data,
        )

        engine.run(ns)

        with _jobs_lock:
            _jobs[job_id]["status"]      = "completed"
            _jobs[job_id]["finished_at"] = datetime.utcnow().isoformat()
            _jobs[job_id]["findings"]    = engine.findings
            _jobs[job_id]["devices"]     = engine.devices

    except Exception as e:
        logger.exception(f"API job {job_id} failed")
        with _jobs_lock:
            _jobs[job_id]["status"]      = "failed"
            _jobs[job_id]["finished_at"] = datetime.utcnow().isoformat()
            _jobs[job_id]["error"]       = str(e)


def create_app(config, db_path: str = ""):
    """
    Build and return the Flask application.

    Parameters
    ----------
    config  : IoTBreaker Config instance
    db_path : Path to SQLite DB (empty = no persistence queries)
    """
    try:
        from flask import Flask, jsonify, request, abort
    except ImportError:
        raise ImportError(
            "Flask is required for --serve mode. Install with: pip install flask"
        )

    app = Flask("iotbreaker_api")
    app.config["JSON_SORT_KEYS"] = False

    # ------------------------------------------------------------------ #
    # Health                                                               #
    # ------------------------------------------------------------------ #

    @app.get("/api/v1/health")
    def health():
        return jsonify({"status": "ok", "version": "4.0.0"})

    # ------------------------------------------------------------------ #
    # Sessions (read from SQLite)                                          #
    # ------------------------------------------------------------------ #

    def _get_db():
        if not db_path:
            abort(503, description="Database not configured. Start with --db FILE.")
        from core.database import Database
        return Database(db_path)

    @app.get("/api/v1/sessions")
    def list_sessions():
        db = _get_db()
        return jsonify(db.list_sessions())

    @app.get("/api/v1/sessions/<session_id>")
    def get_session(session_id: str):
        db = _get_db()
        session = db.get_session(session_id)
        if not session:
            abort(404, description=f"Session {session_id} not found")
        session["devices"]  = db.get_devices(session_id)
        session["findings"] = db.get_findings(session_id=session_id)
        return jsonify(session)

    # ------------------------------------------------------------------ #
    # Findings                                                             #
    # ------------------------------------------------------------------ #

    @app.get("/api/v1/findings")
    def query_findings():
        """
        Query findings across sessions.

        Query params:
            session  : filter by session_id
            severity : filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
            target   : filter by target IP
            q        : keyword search in title + description
        """
        db = _get_db()
        sess     = request.args.get("session")
        severity = request.args.get("severity")
        target   = request.args.get("target")
        keyword  = request.args.get("q")

        if keyword:
            return jsonify(db.search_findings(keyword))
        return jsonify(db.get_findings(session_id=sess, severity=severity, target=target))

    # ------------------------------------------------------------------ #
    # Scan jobs                                                            #
    # ------------------------------------------------------------------ #

    @app.post("/api/v1/scan")
    def start_scan():
        """
        Launch a scan asynchronously.

        Body (JSON):
            module   : str  — e.g. "vuln", "brute", "discover"
            target   : str  — target IP (for most modules)
            network  : str  — target CIDR (for discover/audit)
            ... any other module-specific args

        Returns:
            { "job_id": "<uuid>" }
        """
        data = request.get_json(silent=True) or {}
        module = data.pop("module", None)
        if not module:
            abort(400, description="'module' is required in request body")

        job_id = _job_create(module, data)
        t = threading.Thread(
            target=_job_run,
            args=(job_id, module, data, config),
            daemon=True,
            name=f"job-{job_id[:8]}"
        )
        t.start()

        return jsonify({"job_id": job_id, "status": "queued"}), 202

    @app.get("/api/v1/scan/<job_id>")
    def poll_scan(job_id: str):
        """Poll the status of a scan job."""
        with _jobs_lock:
            job = _jobs.get(job_id)
        if not job:
            abort(404, description=f"Job {job_id} not found")
        return jsonify(job)

    return app


def serve(config, host: str = "127.0.0.1", port: int = 8888, db_path: str = ""):
    """Start the Flask development server."""
    app = create_app(config, db_path=db_path)
    logger.info(f"IoTBreaker API server starting on {host}:{port}")
    # Use werkzeug's run_simple for threaded mode
    try:
        from werkzeug.serving import run_simple
        run_simple(host, port, app, threaded=True, use_reloader=False)
    except ImportError:
        app.run(host=host, port=port, threaded=True)
