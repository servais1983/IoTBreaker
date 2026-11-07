# IoTBreaker v4.0.0 — Production gaps

Status date: 2026-11-07.

Eight of the ten gaps tracked here shipped in v4.0.0. Two remain deferred. Each implemented section below describes the code that exists now. Older notes that said the feature was missing have been removed so they no longer contradict the status banner.

## G1 — Engagement management — Implemented

`core/engagement.py` loads a YAML file (`--engagement`) with client, operator, statement-of-work reference, start and end dates, and authorized CIDRs. The engine checks the date window at startup and copies the CIDRs into the scope list. Report JSON includes the engagement summary. See `engagement.yml.example`.

## G2 — Persistent database — Implemented

`core/database.py` stores sessions, devices, and findings in SQLite (stdlib). `--db FILE` turns persistence on. `save_session()` runs after a completed engine run when a path is configured. Readers: `list_sessions()`, `get_session()`, `get_findings()`, `search_findings()`. The connection uses WAL.

PostgreSQL is not implemented. SQLite is the shipped store.

## G3 — REST API — Implemented

`core/api.py` is a Flask app. Endpoints: `GET /api/v1/health`, `GET /api/v1/sessions`, `GET /api/v1/sessions/<id>`, `GET /api/v1/findings`, `POST /api/v1/scan`, `GET /api/v1/scan/<job_id>`. Flags: `--serve`, `--host` (default `127.0.0.1`), `--port` (default `8888`). Flask is a project dependency.

## G4 — Delta reports — Implemented

`ReportGenerator.generate_delta()` compares findings on `(title, target, port)` and writes `iotbreaker_{session}_delta.json` with `new`, `resolved`, and `changed`. `--compare FILE` selects the previous JSON report.

## G5 — Active OT/ICS protocol modules — Deferred

The common port list already names Modbus, Siemens S7, BACnet, DNP3, and OPC-UA ports so a scan can record that those ports are open. There is no protocol client for those services in this release. Adding one needs extra libraries and a lab, and is not part of v4.0.0.

## G6 — Wireless protocols — Deferred

Discovery and scanning are IP-based. Zigbee, Z-Wave, BLE, Wi-Fi, and LoRaWAN are not implemented. They need radios and OS-specific tools, and they are not part of v4.0.0.

## G7 — HTTP proxy — Implemented

`core/http.py` `make_session()` applies `http_proxy` and `verify_ssl` from config. `IOTBREAKER_PROXY` sets the proxy. Fingerprint, vulnerability checks, credential checks, and the exploit registry use that session.

## G8 — MQTT over TLS checks — Implemented

`VulnScanner._check_mqtt_tls()` is on the default check list and in the dispatch table. It inspects certificate verification and deprecated TLS versions on port 8883. The offline tests cover the dispatcher, not a live broker.

## G9 — Exploit plugin loader — Implemented

`ExploitModule` loads extra modules from `plugins/exploits/*.py` when they expose `CVE_ID`, `check`, and `exploit`. The contract is in `plugins/exploits/README.md`. The built-in registry remains in `modules/exploit/exploit.py`.

## G10 — Compliance mapping — Implemented

`core/compliance.py` maps finding titles onto OWASP IoT, IEC 62443, NIST SP 800-82, ETSI EN 303 645, and NIST CSF labels. `enrich_finding_compliance()` runs inside report generation. The mapping is stored on the finding and in SQLite.

## Summary

| ID | Topic | Status |
|---|---|---|
| G1 | Engagement management | Implemented |
| G2 | SQLite persistence | Implemented |
| G3 | Flask API | Implemented |
| G4 | Delta reports | Implemented |
| G5 | Active OT/ICS clients | Deferred |
| G6 | Wireless protocols | Deferred |
| G7 | HTTP proxy on the shared session | Implemented |
| G8 | MQTT TLS checks | Implemented |
| G9 | Exploit plugin loader | Implemented |
| G10 | Compliance labels | Implemented |
