# IoTBreaker v4.0.0 — Production Readiness Gaps

> **Status:** 8/10 gaps resolved — 2026-04-24
> G5 (OT/ICS active testing) and G6 (Wireless) are deferred — see notes below.

---

## ✅ G1 — No Engagement Management — **IMPLEMENTED**

> **Resolution (2026-04-24):** `core/engagement.py` — `Engagement` class + `load_engagement()` function.
> `--engagement FILE` CLI flag loads a YAML file with `client`, `operator`, `sow_reference`,
> `start_date`, `end_date`, `authorized_cidrs`. Date-window validation enforced at startup;
> CIDRs loaded into engine scope. Engagement metadata embedded in JSON reports.
> See `engagement.yml.example` for template.

**Current state:**
There is no concept of an engagement context. Every run is fully stateless. There is no
way to associate a session with a client, a Statement of Work, an authorized CIDR range,
or a start/end date window.

**Impact for enterprise teams:**
- No traceability between scan results and the authorization document
- Operators can accidentally scan out-of-scope assets
- No way to enforce time-boxed testing windows

**Required additions:**
```
Engagement(
    id           : UUID
    client       : str
    authorized_cidrs : List[str]
    start_date   : datetime
    end_date     : datetime
    operator     : str
    sow_reference: str
)
```
Engine validates every target against `authorized_cidrs` and rejects requests outside
the engagement window.

---

## ✅ G2 — No Persistent Backend / Database — **IMPLEMENTED**

> **Resolution (2026-04-24):** `core/database.py` — `Database` class wrapping SQLite via stdlib.
> Schema: `sessions`, `devices`, `findings` with indexes on severity and target.
> `--db FILE` CLI flag activates persistence; `db.save_session(engine)` called automatically
> after each run. Read API: `list_sessions()`, `get_session()`, `get_findings()`, `search_findings()`.
> WAL journal mode for concurrent read/write safety.

**Current state:**
All results exist only in memory during a session and are written to flat files (JSON,
HTML, PDF, TXT) at the end. There is no queryable store.

**Impact for enterprise teams:**
- No historical comparison ("has this device appeared before with different firmware?")
- No trend analysis across multiple engagements
- No deduplication of findings across sessions
- Reports cannot be queried or aggregated by the team

**Required additions:**
- SQLite for single-operator use
- PostgreSQL for multi-operator team deployment
- Schema: `engagements`, `sessions`, `devices`, `findings`, `credentials`

---

## ✅ G3 — No REST API / Headless Mode — **IMPLEMENTED**

> **Resolution (2026-04-24):** `core/api.py` — Flask application with endpoints:
> `GET /api/v1/health`, `GET /api/v1/sessions`, `GET /api/v1/sessions/<id>`,
> `GET /api/v1/findings` (with `?session=`, `?severity=`, `?target=`, `?q=` filters),
> `POST /api/v1/scan` (async job), `GET /api/v1/scan/<job_id>` (poll).
> `--serve`, `--host`, `--port` CLI flags. Requires `pip install flask`.

**Current state:**
IoTBreaker is CLI-only. It cannot be called programmatically without wrapping it in a
`subprocess` call, which provides no structured feedback.

**Impact for enterprise teams:**
- Cannot integrate into CI/CD pipelines or automated workflows
- Cannot build custom dashboards or portals on top of the tool
- Cannot be controlled by orchestration platforms (Ansible, n8n, custom SOAR)

**Required additions:**
A `--serve` flag that starts a FastAPI/Flask server exposing:
```
POST /api/v1/scan          — run a module
GET  /api/v1/sessions      — list past sessions
GET  /api/v1/session/{id}  — get results for a session
GET  /api/v1/findings      — query findings across sessions
```

---

## ✅ G4 — No Differential / Delta Reporting — **IMPLEMENTED**

> **Resolution (2026-04-24):** `ReportGenerator.generate_delta()` in `modules/reporting/report.py`.
> Findings matched by `(title, target, port)` composite key.
> Produces `iotbreaker_{session}_delta.json` with `new`, `resolved`, and `changed` arrays.
> `--compare JSON_FILE` CLI flag triggers delta generation after normal report output.

**Current state:**
Each session produces a standalone report. There is no mechanism to compare two sessions
(e.g., initial assessment vs. re-test after remediation).

**Impact for enterprise teams:**
- Cannot prove to clients which vulnerabilities were fixed between assessments
- Cannot track remediation progress over time
- Manual comparison of JSON files is error-prone

**Required additions:**
A `--compare SESSION_ID` flag that produces a delta report:
- New findings (appeared in current session, not in baseline)
- Resolved findings (present in baseline, absent in current)
- Changed findings (same CVE/title but different CVSS, evidence, or port)

---

## ⏳ G5 — OT/ICS Protocol Depth is Missing — **DEFERRED**

> **Status (2026-04-24):** Deferred — requires optional Linux-native dependencies
> (`pymodbus`, `python-snap7`, `bacpypes3`, `opcua`) and lab hardware for validation.
> Port detection of OT protocols (502/Modbus, 102/S7, 47808/BACnet, 20000/DNP3, 4840/OPC-UA)
> is already present in the scanner. Active testing modules are planned for v4.1.0.

**Current state:**
The tool **detects** OT devices on discovery (port 502 → Modbus, port 102 → Siemens S7,
port 47808 → BACnet, port 20000 → DNP3, port 4840 → OPC-UA) but performs **no active
testing** on these protocols.

**Impact for enterprise teams:**
OT/ICS environments are high-value targets for critical infrastructure assessments.
Without active OT testing, IoTBreaker cannot be used for IEC 62443 compliance audits or
industrial network pen-tests.

**Required additions:**

| Protocol | Library | Test capabilities needed |
|---|---|---|
| Modbus | `pymodbus` | Read coils/registers, function code abuse |
| Siemens S7 | `python-snap7` | CPU state, read/write DB blocks |
| BACnet | `bacpypes3` | Device enumeration, object property read |
| DNP3 | Manual socket | Unauthenticated command testing |
| OPC-UA | `opcua` | Anonymous session, node enumeration |

---

## ⏳ G6 — No Wireless Protocol Support — **DEFERRED**

> **Status (2026-04-24):** Deferred — requires specialized hardware (USB radio adapters)
> and Linux-only kernel interfaces (`bluepy`/`bleak`, `scapy-zigbee`, `hcxtools`).
> Not implementable on Windows. Planned as a separate Linux-based add-on module in v4.2.0.

**Current state:**
All discovery and scanning is IP-network based. IoT devices heavily rely on wireless
protocols that are out of scope for the current tool.

**Missing protocols:**

| Protocol | Attack surface |
|---|---|
| Zigbee (802.15.4) | Key extraction, replay attacks, coordinator impersonation |
| Z-Wave | Network key sniffing, S0/S2 downgrade |
| BLE | GATT enumeration, pairing bypass, firmware OTA interception |
| Wi-Fi (WPA2/WPA3) | PMKID capture, EAPOL handshake, PMKID-less attacks |
| LoRaWAN | DevEUI enumeration, replay, ADR manipulation |

**Required additions:**
- `scapy` + `scapy-zigbee` for Zigbee
- `bluepy` / `bleak` for BLE (Linux)
- Wrapper around `hcxtools`/`hashcat` for Wi-Fi

---

## ✅ G7 — No HTTP Proxy / Traffic Interception Support — **IMPLEMENTED**

> **Resolution (2026-04-24):** `core/http.py` — `make_session(config)` factory creates a
> `requests.Session` with `proxies` and `verify` pre-applied from config.
> `IOTBREAKER_PROXY=http://127.0.0.1:8080` env var or `--http-proxy` config key routes all
> HTTP traffic through Burp Suite / OWASP ZAP automatically.
> Wired into `ExploitModule`, `BruteForceModule`, `VulnScanner`, `FingerprintModule`.

**Current state:**
All HTTP modules (bruteforce, vulnscan, exploit, shodan) use direct `requests.Session`
connections with no proxy configuration.

**Impact for enterprise teams:**
Enterprise pen-testers route all traffic through Burp Suite or OWASP ZAP for:
- Manual inspection and replay of captured requests
- Custom extensions and active scan rules
- Evidence collection for reports

**Required additions:**
```python
# core/config.py
"http_proxy": os.getenv("IOTBREAKER_PROXY", ""),

# Applied to every requests.Session:
if self.config.get("http_proxy"):
    session.proxies = {
        "http":  self.config.get("http_proxy"),
        "https": self.config.get("http_proxy"),
    }
```

---

## ✅ G8 — MQTT TLS Testing Absent — **IMPLEMENTED**

> **Resolution (2026-04-24):** `_check_mqtt_tls()` added to `VulnScanner` in `modules/vulnscan/vulnscan.py`.
> Tests on port 8883: self-signed/expired certificate acceptance (CWE-295),
> TLS 1.0 / TLS 1.1 downgrade acceptance (CWE-326, RFC 8996).
> `mqtt_tls` added to the default check list and dispatch table.

**Current state:**
The MQTT vulnerability module and brute-force module test cleartext MQTT (port 1883)
only. MQTT over TLS (port 8883) is listed in the port map but receives no protocol-aware
testing.

**Missing test cases for port 8883:**
- Expired or self-signed certificate acceptance
- Weak cipher suite negotiation (RC4, 3DES, NULL)
- Client certificate bypass
- TLS 1.0 / 1.1 downgrade

---

## ✅ G9 — Exploit Module is Static (No Plugin Loader) — **IMPLEMENTED**

> **Resolution (2026-04-24):** `_load_plugins()` and `_plugin_handlers` added to `ExploitModule`.
> Plugin files placed in `plugins/exploits/*.py` are auto-discovered at `__init__` time.
> Each plugin exposes `CVE_ID`, `TITLE`, `PRODUCTS`, `CVSS`, `check()`, `exploit()` symbols.
> See `plugins/exploits/README.md` for the full plugin contract and example.

**Current state:**
9 hardcoded exploits defined in a static `EXPLOITS` list in `modules/exploit/exploit.py`.
Adding a new CVE requires modifying framework source code.

**Impact for enterprise teams:**
- New CVEs cannot be added without touching core files
- Cannot maintain a team-specific private exploit library
- No versioning or metadata for individual exploits

**Required additions:**
A plugin loader that discovers exploit modules from a `plugins/exploits/` directory:
```python
# Each plugin is a Python file exposing:
CVE_ID   = "CVE-2024-XXXXX"
TITLE    = "..."
PRODUCTS = "..."
CVSS     = "9.8"

def check(target: str, config: Config) -> bool: ...
def exploit(target: str, payload: str, config: Config) -> dict: ...
```

---

## ✅ G10 — No Compliance Framework Mapping — **IMPLEMENTED**

> **Resolution (2026-04-24):** `core/compliance.py` — static mapping table covering:
> OWASP IoT Top 10 (2018), IEC 62443-3-3, NIST SP 800-82 Rev. 3, ETSI EN 303 645, NIST CSF 2.0.
> `enrich_finding_compliance(finding)` called automatically in `engine._generate_reports()`
> before report files are written. `compliance_mapping` key added to every finding dict
> and persisted to JSON reports and SQLite database.

**Current state:**
Findings include severity, CVSS score, and CVE IDs but are not mapped to any security
standard or compliance framework.

**Impact for enterprise teams:**
Clients operating in regulated industries require findings to be mapped to specific
controls. Without this, report findings must be manually re-mapped before delivery.

**Required mappings:**

| Framework | Scope |
|---|---|
| OWASP IoT Top 10 (2018) | Consumer IoT |
| IEC 62443-3-3 | Industrial automation |
| NIST SP 800-82 Rev. 3 | Industrial control systems |
| ETSI EN 303 645 | Consumer IoT (EU) |
| NIST CSF 2.0 | General enterprise |

**Implementation:**
Add a `compliance_mapping: Dict[str, List[str]]` field to each finding, populated from
a static mapping table keyed by check type.

---

## Gap Summary Table

| ID | Gap | Effort | Impact | Status |
|---|---|---|---|---|
| G1 | No engagement management | High | Critical for team use | ✅ Implemented |
| G2 | No persistent database | High | Critical for team use | ✅ Implemented (SQLite) |
| G3 | No REST API | Medium | High for automation | ✅ Implemented (Flask) |
| G4 | No differential reports | Medium | High for re-tests | ✅ Implemented |
| G5 | No OT/ICS active testing | High | Critical for ICS engagements | ⏳ Deferred v4.1 |
| G6 | No wireless protocol support | Very high | High for IoT assessments | ⏳ Deferred v4.2 |
| G7 | No HTTP proxy support | Low | Medium for teams using Burp | ✅ Implemented |
| G8 | No MQTT TLS testing | Low | Medium | ✅ Implemented |
| G9 | Static exploit list | Medium | Medium | ✅ Implemented (plugin loader) |
| G10 | No compliance mapping | Medium | High for regulated clients | ✅ Implemented |
