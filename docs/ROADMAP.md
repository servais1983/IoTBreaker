# IoTBreaker v4.0.0 — Improvement Roadmap

> Items are grouped by priority tier. All Priority 1 items are **blocking** for
> production enterprise deployment. Priorities 2–4 represent the path to a
> best-in-class IoT pen-test platform.

> **Status as of 2026-04-24:** All Priority 1, 2, and 3 items ✅ DONE. Priority 4 items:
> 4.1 and 4.2 ⏳ deferred (hardware/OS dependency); 4.3 and 4.4 and 4.5 ✅ DONE.

---

## Priority 1 — Security Fixes ✅ ALL DONE

All 10 security fixes resolved 2026-04-24. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

| Ref | Action | File(s) | Status |
|---|---|---|---|
| S1 | Default `verify_ssl: True`; add `--no-verify` flag | `core/config.py`, HTTP modules | ✅ |
| S2 | Validate `--payload` charset before passing to exploit handlers | `modules/exploit/exploit.py` | ✅ |
| S3 | Add `--scope-file CIDR.txt` with engine-level enforcement | `core/engine.py` | ✅ |
| S4 | Mask passwords in console output; add `--reveal-creds` flag | `modules/bruteforce/bruteforce.py` | ✅ |
| S5 | Support OS keyring / Vault for API key storage | `core/config.py` | ✅ |
| S6 | Replace `_esc()` with `html.escape(text, quote=True)` | `modules/reporting/report.py` | ✅ |
| S7 | Remove `--run-as=root` from binwalk call; add post-extraction path validation | `modules/firmware/firmware.py` | ✅ |
| S8 | Default `brute_delay: 0.5`; add `--fast` opt-in flag | `core/config.py` | ✅ |
| S9 | Add per-module thread caps (discover: 50, scan: 10, brute: 3) | `core/engine.py` | ✅ |
| S10 | Always write timestamped `.log` file to output directory | `core/logger.py` | ✅ |

---

## Priority 2 — Operational Hardening ✅ ALL DONE

### ✅ 2.1 HTTP Proxy Support
Add `IOTBREAKER_PROXY` environment variable support in all `requests.Session` instances
to allow traffic routing through Burp Suite or OWASP ZAP.

```python
# core/config.py
"http_proxy": os.getenv("IOTBREAKER_PROXY", ""),

# Every module that uses requests:
if proxy := self.config.get("http_proxy"):
    self._session.proxies = {"http": proxy, "https": proxy}
```

### ✅ 2.2 Rate-Limit and Backoff Awareness

> **Implemented 2026-04-24:** `_attempt_with_backoff()` added to `BruteForceModule`.
> Retries up to 3 times with exponential delay on `ConnectionResetError`.
> Detects HTTP 429 and pauses with increasing back-off before retry.
> Wired into `_attack_http()`.

Add exponential backoff on connection resets. Detect account lockout HTTP responses
(401/403 rate-spikes) and pause automatically.

```python
def _attempt_with_backoff(self, fn, *args, max_retries=3):
    for attempt in range(max_retries):
        try:
            return fn(*args)
        except ConnectionResetError:
            time.sleep(2 ** attempt)
    return None
```

### ✅ 2.3 MQTT TLS Testing

> **Implemented 2026-04-24:** `_check_mqtt_tls()` in `modules/vulnscan/vulnscan.py`.

Extend the MQTT vuln module to test port 8883 for:
- Expired / self-signed certificate acceptance
- Weak cipher suites (RC4, 3DES, NULL)
- TLS 1.0 / 1.1 downgrade acceptance

### ✅ 2.4 Config File Validation

> **Implemented 2026-04-24:** `Config.load_file()` now compares keys against `DEFAULTS`.
> Unknown keys raise `UserWarning` and are silently dropped (not merged into runtime config).

Validate YAML/JSON config keys against the `DEFAULTS` schema at load time and warn on
unknown keys — prevents silent misconfiguration.

---

## Priority 3 — Architecture Evolution ✅ ALL DONE

### ✅ 3.1 Engagement Management Module

Create `core/engagement.py` with a persistent SQLite backend:

```
Engagement
├── id (UUID)
├── client (str)
├── authorized_cidrs (List[str])
├── start_date (datetime)
├── end_date (datetime)
├── operator (str)
└── sow_reference (str)

Session
├── id (str)  — current session_id format
├── engagement_id (FK)
├── started_at
└── completed_at

Finding (persisted)
└── session_id (FK)

Device (persisted)
└── session_id (FK)
```

Enforce scope check in `Engine.run()`:
```python
if not self.engagement.in_scope(target):
    Console.error(f"{target} is outside the authorized scope. Skipping.")
    return False
```

### ✅ 3.2 Plugin Architecture for Exploits

Replace the static `EXPLOITS` list with a directory-based plugin loader:

```
plugins/
├── exploits/
│   ├── cve_2021_36260.py   # Hikvision RCE
│   ├── cve_2024_xxxxx.py   # New CVE (team adds without touching core)
│   └── ...
└── vulnchecks/
    └── mqtt_tls_check.py
```

Each plugin exposes a standard interface:
```python
CVE_ID   = "CVE-2021-36260"
TITLE    = "Hikvision RCE"
PRODUCTS = "Hikvision firmware < 5.5.800"
CVSS     = "9.8"

def check(target: str, config) -> bool: ...
def exploit(target: str, payload: str, config) -> dict: ...
```

### ✅ 3.3 REST API Mode

Add a `--serve [HOST:PORT]` flag that starts a FastAPI server:

```
POST /api/v1/run                 — execute a module
GET  /api/v1/engagements         — list engagements
POST /api/v1/engagements         — create engagement
GET  /api/v1/sessions            — list sessions
GET  /api/v1/sessions/{id}       — get session results
GET  /api/v1/findings            — query findings (filter by severity, CVE, target)
GET  /api/v1/findings/export     — export as JSON/CSV
```

This enables:
- Integration with SOAR platforms
- Custom team dashboards
- CI/CD pipeline embedding

### ✅ 3.4 Differential Reporting

Add `--compare SESSION_ID` flag to `Engine._generate_reports()`:

```python
def _diff_sessions(self, baseline_id: str) -> Dict:
    baseline = self._load_session(baseline_id)
    current  = self.findings

    new_findings      = [f for f in current  if f not in baseline]
    resolved_findings = [f for f in baseline if f not in current]
    changed_findings  = [...]  # same title, different CVSS/evidence

    return {
        "new":      new_findings,
        "resolved": resolved_findings,
        "changed":  changed_findings,
    }
```

Include a delta section in HTML/PDF reports with colour-coded status badges.

### ✅ 3.5 Target Architecture (Current → Target)

```
Current:
  CLI → Engine → Modules → Flat Files

Target:
  CLI / REST API
       │
       ▼
  Engagement Manager (scope, auth, time window)
       │
       ▼
  Engine → Modules (+ plugin loader)
       │
       ▼
  SQLite / PostgreSQL
       │
  ┌────┴───────────────┐
  │                    │
  ▼                    ▼
Reporting          SIEM Export
(JSON/HTML/PDF     (CEF / Splunk HEC
 + delta)           / syslog)
```

---

## Priority 4 — Coverage Expansion

### 🟡 4.1 OT/ICS Active Testing — PARTIALLY DONE

> **Implemented 2026-10-31:** `modules/ot/ot_probe.py` — `OTScanner`, pure-Python
> (stdlib only) **read-only** probes. New `ot` CLI module + optional `--ot` audit phase.
> 42 unit tests in `tests/test_ot.py`. Compliance category `ot_exposure` (IEC 62443,
> NIST SP 800-82). The "tests done now" column below marks what ships today; the library
> column marks the deeper, authenticated interaction still planned.

| Protocol | Library (future deep tests) | Shipped now (read-only) | Deeper tests planned |
|---|---|---|---|
| Modbus | `pymodbus` | ✅ Read Device Identification / FC3 probe | Read coils/registers, illegal function codes |
| Siemens S7 | `python-snap7` | ✅ COTP connection confirm detection | CPU state read, DB block enumeration |
| BACnet | `bacpypes3` | ✅ Who-Is / I-Am enumeration | Object property read |
| DNP3 | raw socket | ✅ Request Link Status probe | Unauthenticated command probe |
| OPC-UA | `opcua` | ✅ Hello/Acknowledge transport handshake | Anonymous session, node browse |
| EtherNet/IP | `pycomm3` | ✅ ListIdentity disclosure | Tag read without auth |

### ⏳ 4.2 Wireless Protocol Support — DEFERRED (v4.2.0)

| Protocol | Library | Tests to add |
|---|---|---|
| Zigbee | `scapy-zigbee` | Key extraction, coordinator impersonation |
| BLE | `bleak` (cross-platform) | GATT enumeration, pairing bypass |
| Wi-Fi | `pywifi` + `hcxtools` | PMKID capture, handshake collection |
| LoRaWAN | raw socket | DevEUI enum, ADR manipulation |

### ✅ 4.3 Compliance Framework Mapping

> **Implemented 2026-04-24:** `core/compliance.py` — OWASP IoT, IEC 62443-3-3, NIST SP 800-82,
> ETSI EN 303 645, NIST CSF 2.0. Auto-applied in `engine._generate_reports()`.

Add a `compliance_mapping` field to every finding, populated from a static lookup table:

```python
COMPLIANCE_MAPPINGS = {
    "default_credentials": {
        "owasp_iot": ["I1 - Weak, Guessable, or Hardcoded Passwords"],
        "iec_62443": ["SR 1.1 - Human User Authentication"],
        "etsi_en_303_645": ["Provision 1 - No universal default passwords"],
        "nist_csf": ["PR.AC-1"],
    },
    "telnet_enabled": {
        "owasp_iot": ["I2 - Insecure Network Services"],
        "iec_62443": ["SR 3.1 - Communication Integrity"],
        ...
    },
}
```

### ✅ 4.4 SIEM / SOAR Export

> **Implemented 2026-04-24:** `modules/reporting/siem.py` — `SiemExporter` class.
> Splunk HEC (NDJSON POST), Syslog CEF (UDP/TCP), Elastic ECS v8 (NDJSON file).
> Activated via `siem:` block in config YAML. Auto-triggered in `engine._generate_reports()`.

Add structured event output compatible with:
- **Splunk HEC** — JSON over HTTP ✅
- **Syslog CEF** — ArcSight Common Event Format ✅
- **Elastic ECS** — Elastic Common Schema for SIEM ingestion ✅
- **STIX 2.1** — Threat intelligence sharing ⏳ (future)

### ✅ 4.5 Enhanced Wordlists

> **Implemented 2026-04-24:** Vendor-specific credential files created under `wordlists/vendors/`.
> Protocol-specific topic/community lists under `wordlists/protocols/`.

```
wordlists/
├── users.txt              — generic IoT usernames
├── passwords.txt          — generic IoT passwords
├── web_paths.txt          — common IoT web paths
├── vendors/
│   ├── hikvision_users.txt / hikvision_passwords.txt  ✅
│   ├── dahua_users.txt / dahua_passwords.txt          ✅
│   ├── dlink_users.txt / dlink_passwords.txt          ✅
│   ├── asus_users.txt / asus_passwords.txt            ✅
│   ├── tp-link_users.txt / tp-link_passwords.txt      ✅
│   ├── ubiquiti_users.txt / ubiquiti_passwords.txt    ✅
│   └── netgear_users.txt / netgear_passwords.txt      ✅
└── protocols/
    ├── snmp_communities.txt                           ✅
    └── mqtt_topics.txt                               ✅
```

---

## Milestone Timeline

| Milestone | Contents | Goal | Status |
|---|---|---|---|
| v4.1 | All Priority 1 security fixes | Minimum viable for team use | ✅ Done |
| v4.2 | Priority 2 hardening + proxy + MQTT TLS | Operationally solid | ✅ Done |
| v5.0 | Priority 3 architecture (DB, API, plugin loader, diff reports) | Enterprise team platform | ✅ Done |
| v5.1 | OT/ICS active testing (Modbus, S7, BACnet) | Industrial assessments | ⏳ Next |
| v5.2 | Wireless support + compliance mapping + SIEM export | Full-spectrum IoT platform | ⏳ Next |
