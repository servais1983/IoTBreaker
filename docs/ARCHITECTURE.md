# IoTBreaker v4.0.0 — Architecture & Capability Review

## 1. Architecture Overview

```
iotbreaker.py (CLI entry-point)
│
├── core/
│   ├── engine.py      — Module dispatch, session orchestration, report generation
│   ├── config.py      — DEFAULTS dict + YAML/ENV loader (yaml.safe_load ✔)
│   ├── logger.py      — Standard Python logging, optional file handler
│   └── output.py      — Console formatting (table, finding, progress)
│
└── modules/
    ├── discovery/     — ARP sweep, TCP probe, UPnP/SSDP, mDNS
    ├── scanner/       — ThreadPoolExecutor TCP/UDP + banner grab
    ├── fingerprint/   — OUI lookup, TTL, banner, deep HTTP fingerprint
    ├── vulnscan/      — 9-protocol vuln checks + NVD CVE correlation
    ├── bruteforce/    — Telnet, SSH, FTP, HTTP, RTSP, SNMP, MQTT
    ├── exploit/       — 9 hardcoded PoC CVE handlers
    ├── firmware/      — binwalk extraction, regex secret scan, entropy
    ├── reporting/     — JSON / HTML / PDF / TXT multi-format reports
    └── shodan/        — Shodan API client
```

**Pattern:** single-process Python 3.8+, `ThreadPoolExecutor` for concurrency, all state
in `Engine` instance (`self.findings`, `self.devices`), results written to disk at session
end. No daemon, no database, no API server.

---

## 2. Capability Inventory

| Module | What it does | Protocols / Tech |
|---|---|---|
| `discover` | Layer-2/4/7 device enumeration | ARP, TCP probe, UPnP/SSDP, mDNS |
| `scan` | Port scan + banner grab | TCP, UDP (root), IoT common port list |
| `fingerprint` | Device/manufacturer/OS identification | OUI, TTL, HTTP headers, banner regex |
| `vuln` | Protocol-specific weakness checks | Telnet, SSH, MQTT, HTTP, RTSP, CoAP, UPnP, SNMP, FTP + NVD |
| `brute` | Credential brute-force | Telnet, SSH, FTP, HTTP, RTSP, SNMP, MQTT |
| `exploit` | PoC RCE execution | 9 CVEs: Hikvision, Dasan, Huawei, Realtek, NETGEAR, D-Link, Zyxel, TP-Link, QNAP |
| `firmware` | Static firmware analysis | binwalk, regex secrets, entropy, ELF arch |
| `shodan` | Internet exposure intel | Shodan API v1 |
| `cve` | Vulnerability intelligence | NVD API v2.0 |
| `audit` | Full pipeline orchestration | All of the above |

---

## 3. Data Flow

```
CLI args
   │
   ▼
Engine.run(args)
   │
   ├─► _run_discover()   ──► DiscoveryModule   ──► self.devices[]
   ├─► _run_scan()       ──► PortScanner
   ├─► _run_fingerprint()──► FingerprintModule
   ├─► _run_vuln()       ──► VulnScanner        ──► self.findings[]
   ├─► _run_brute()      ──► BruteForceModule   ──► self.findings[]
   ├─► _run_exploit()    ──► ExploitModule      ──► self.findings[]
   ├─► _run_firmware()   ──► FirmwareAnalyzer
   ├─► _run_shodan()     ──► ShodanIntel
   ├─► _run_cve()        ──► CVELookup
   └─► _run_audit()      ──► All of the above (pipeline)
            │
            ▼
     _generate_reports()
            │
            ├─► ReportGenerator.generate_json()
            ├─► ReportGenerator.generate_html()
            ├─► ReportGenerator.generate_pdf()
            └─► ReportGenerator.generate_txt()
```

---

## 4. Configuration System

Configuration is merged in this priority order (highest wins):

1. Hardcoded `DEFAULTS` dict in `core/config.py`
2. YAML or JSON config file (`--config FILE`)
3. Environment variables (`SHODAN_API_KEY`, `NVD_API_KEY`, `IOTBREAKER_TIMEOUT`, etc.)
4. CLI arguments (`--timeout`, `--threads`, `--output`, `--format`)

### Key Default Values

| Key | Default | Notes |
|---|---|---|
| `timeout` | `5` | TCP connection timeout in seconds |
| `threads` | `100` | Global thread pool size |
| `verify_ssl` | `False` | ⚠ See Security Audit |
| `brute_delay` | `0.0` | ⚠ See Security Audit |
| `stop_on_success` | `True` | Stop brute-force after first hit |
| `safe_mode` | `True` | Placeholder — not enforced in code |
| `report_format` | `"all"` | json + html + pdf + txt |

---

## 5. IoT Port Coverage

The `IOT_COMMON_PORTS` list in `core/config.py` covers the following protocols:

| Port | Protocol |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 / 2323 | Telnet |
| 80 / 81 / 8080 / 8081 | HTTP |
| 443 / 8443 / 4433 | HTTPS |
| 161 / 162 | SNMP |
| 502 | Modbus |
| 554 | RTSP |
| 1883 / 8883 | MQTT |
| 1900 | UPnP/SSDP |
| 4840 | OPC-UA |
| 5683 | CoAP |
| 7547 | TR-069 (CWMP) |
| 9100 | JetDirect (printers) |
| 102 | Siemens S7 |
| 20000 | DNP3 |
| 44818 | EtherNet/IP |
| 47808 | BACnet |
| 37777 | Dahua DVR |
