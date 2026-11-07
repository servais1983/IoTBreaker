# IoTBreaker v4.0.0 — Architecture

## 1. Overview

IoTBreaker is a single-process Python 3.9+ command-line tool. `iotbreaker.py` parses arguments and hands them to `core/engine.py`. The engine keeps the session (`devices`, `findings`), enforces an optional CIDR scope, caps threads per module, and writes reports at the end of a run.

There is no background daemon. Optional pieces are a SQLite file (`--db`) and a local Flask API (`--serve`, bound to `127.0.0.1` by default).

```
iotbreaker.py
│
├── core/
│   ├── engine.py        Module dispatch, scope, thread caps, report trigger
│   ├── config.py        Defaults, YAML/JSON file, environment variables
│   ├── logger.py        stderr logging plus an optional audit log file
│   ├── output.py        Console tables and finding lines (ANSI, no colorama)
│   ├── http.py          Shared requests.Session (proxy, TLS verify, User-Agent)
│   ├── compliance.py    Maps finding titles to control frameworks
│   ├── engagement.py    Client, operator, dates, authorized CIDRs
│   ├── database.py      SQLite sessions, devices, findings
│   ├── api.py           Flask /api/v1 read API and async jobs
│   └── timeutil.py      Aware UTC timestamps
│
└── modules/
    ├── discovery/discovery.py       Host enumeration (TCP, ARP helper, UPnP, mDNS)
    ├── discovery/shodan_intel.py    Shodan client (optional API key)
    ├── scanner/portscan.py          TCP connect scan, optional UDP, banner text
    ├── fingerprint/fingerprint.py   Hostname, OUI, TTL hint, HTTP/UPnP parsers
    ├── vulnscan/vulnscan.py         Protocol checks and finding objects
    ├── vulnscan/cve_lookup.py       NVD API client
    ├── bruteforce/bruteforce.py     Credential attempts with backoff and masking
    ├── exploit/exploit.py           Built-in registry plus plugins/exploits loader
    ├── firmware/firmware.py         Local file typing, hashes, entropy, extraction guard
    └── reporting/
        ├── report.py                JSON, HTML (stdlib escaping), text, delta, PDF
        └── siem.py                  CEF, ECS NDJSON, Splunk HEC
```

## 2. Request flow

```
CLI args
   │
   ▼
Engine.run(args)
   │
   ├─ scope check for targeted modules and for discover/audit CIDRs
   ├─ per-module thread cap
   │
   ├─ discover / scan / fingerprint / vuln / brute / exploit
   ├─ firmware / shodan / cve / audit
   │
   ▼
_generate_reports()
   ├─ compliance enrichment
   ├─ optional Database.save_session()
   └─ JSON / HTML / text / PDF / delta
```

`audit` runs discovery, then scan and fingerprint, then protocol checks. It does not add a separate transport.

## 3. Configuration

Highest priority wins:

1. Hardcoded `DEFAULTS` in `core/config.py`
2. YAML or JSON file (`--config`)
3. Environment variables (`SHODAN_API_KEY`, `NVD_API_KEY`, `IOTBREAKER_*`)
4. CLI flags (`--timeout`, `--threads`, `--output`, `--format`, `--no-verify`)

| Key | Default | Notes |
|---|---|---|
| `timeout` | `5` | Seconds |
| `threads` | `100` | Lowered again by `MODULE_THREAD_CAPS` |
| `verify_ssl` | `True` | `--no-verify` turns it off and prints a warning |
| `brute_delay` | `0.5` | `--fast` sets this to `0` |
| `output_dir` | `./reports` | Created at startup |
| `report_format` | `"all"` | json, html, and text; PDF if a renderer is installed |

## 4. Persistence and API

`core/database.py` opens a SQLite file with tables `sessions`, `devices`, and `findings`. `Database.save_session()` upserts the session row and replaces child rows.

`core/api.py` exposes:

| Method | Path | Role |
|---|---|---|
| GET | `/api/v1/health` | Liveness |
| GET | `/api/v1/sessions` | List stored sessions (503 without `--db`) |
| GET | `/api/v1/sessions/<id>` | One session |
| GET | `/api/v1/findings` | Filter stored findings |
| POST | `/api/v1/scan` | Queue a module job |
| GET | `/api/v1/scan/<job_id>` | Job status |

Jobs call `Engine.run` in a background thread. The unit tests patch that call.

## 5. Scope

`Engine.load_scope()` reads one CIDR per line. With a scope loaded:

- An IP is allowed only when it belongs to a scope network.
- A CIDR is allowed only when it is a subnet of a scope network. A wider prefix is rejected instead of being treated as a hostname.
- A hostname is still allowed, because it is not an address.
- `discover` and `audit` apply the same CIDR rule to `--network` before any module starts.

With no scope file and no engagement CIDRs, targets are not filtered.

## 6. Tests

`tests/` is pytest. `conftest.py` puts the repository root on `sys.path`. External I/O in the suite is mocked or replaced with local files. GitHub Actions workflow `.github/workflows/tests.yml` installs `.[dev]` and runs ruff, mypy, and pytest. It does not run the CLI against a network.

## 7. Ports of interest

`IOT_COMMON_PORTS` in `core/config.py` lists the TCP/UDP ports the default scan set knows about, including FTP, SSH, Telnet, HTTP(S), SNMP, Modbus, RTSP, MQTT, UPnP, CoAP, and several industrial ports. That list is data for the scanner. It is not a procedure.
