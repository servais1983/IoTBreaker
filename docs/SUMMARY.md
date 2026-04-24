# IoTBreaker v4.0.0 — Enterprise Assessment Summary

> Review date: April 24, 2026
> Reviewer: Enterprise Penetration Testing Team
> Version reviewed: 4.0.0 (main branch)

---

## Overall Scores

| Dimension | Score | Notes |
|---|---|---|
| Feature breadth | 7 / 10 | Good IoT coverage, missing OT/wireless depth |
| Code quality | 7 / 10 | Clean, well-structured, good docstrings |
| Security of the tool itself | 5 / 10 | SSL disabled, no scope enforcement, incomplete HTML escape |
| Production readiness | 4 / 10 | No DB, no engagement management, no API, no audit trail |
| Enterprise team fit | 4 / 10 | CLI-only, no multi-user, no compliance mapping |
| Exploit library | 4 / 10 | 9 static CVEs, no plugin loader, oldest entry from 2014 |

---

## Verdict

IoTBreaker v4.0.0 is a solid **research and solo-operator tool**.

**Strengths:**
- Comprehensive protocol coverage for common IoT vulnerabilities (Telnet, SSH, MQTT, RTSP, CoAP, SNMP, UPnP, FTP, HTTP)
- Clean modular architecture that is easy to extend
- Multi-format reporting (JSON, HTML, PDF, TXT) with professional HTML output
- NVD CVE correlation and Shodan integration
- Firmware static analysis with binwalk and regex secret detection
- Usable default wordlists and IoT-specific port list

**Critical gaps before enterprise deployment:**
1. **10 security vulnerabilities** in the tool itself (SSL disabled, no scope enforcement, credential exposure, stored XSS, path traversal via binwalk)
2. **No engagement management** — no scope, no authorization tracking, no time bounds
3. **No persistent backend** — results exist only during a session; no historical comparison
4. **CLI-only** — cannot be integrated into team workflows, SOAR platforms, or dashboards
5. **No OT/ICS active testing** despite detecting Modbus, S7, BACnet, DNP3 devices
6. **No compliance framework mapping** (OWASP IoT Top 10, IEC 62443, ETSI EN 303 645)

---

## Minimum Requirements for Team Deployment

The following must be completed before IoTBreaker is used by a team in a professional
engagement:

### Must-fix (blocking)
- [ ] S1 — Enable SSL verification by default
- [ ] S2 — Validate exploit payload input
- [ ] S3 — Implement scope file enforcement
- [ ] S4 — Mask credentials in output
- [ ] S6 — Fix HTML escaping (use `html.escape(quote=True)`)
- [ ] S7 — Remove `--run-as=root` from binwalk call
- [ ] S8 — Default brute-force delay to 0.5 seconds
- [ ] S10 — Always write audit log file

### Should-fix (before team use)
- [ ] G1 — Add engagement management with authorized CIDR enforcement
- [ ] G3 — Add `--serve` REST API mode for automation
- [ ] G7 — Add HTTP proxy support for Burp/ZAP integration
- [ ] G9 — Replace static exploit list with plugin loader

### Nice-to-have (next major version)
- [ ] G2 — Persistent SQLite/PostgreSQL backend
- [ ] G4 — Differential/delta reporting
- [ ] G5 — OT/ICS active testing (Modbus, S7, BACnet)
- [ ] G10 — Compliance framework mapping

---

## Document Index

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Code structure, data flow, configuration system, port coverage |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | 10 security vulnerabilities with code-level fix guidance |
| [PRODUCTION_GAPS.md](PRODUCTION_GAPS.md) | 10 enterprise readiness gaps with detailed descriptions |
| [ROADMAP.md](ROADMAP.md) | Prioritized improvement roadmap with milestone targets |

---

## Quick Reference: Risk Matrix

```
                    HIGH IMPACT
                         │
         S3 (scope)  ────┤──── S1 (SSL)
                         │
         G1 (engage) ────┤──── G2 (DB)
                         │
LOW ─────────────────────┼─────────────────── HIGH
EFFORT                   │                    EFFORT
                         │
         S6 (XSS)   ─────┤──── G3 (API)
         S4 (creds)      │
         G7 (proxy)      │
                         │
                    LOW IMPACT
```

**Quick wins (low effort, high impact):** S1, S6, S4, S8, G7
**Strategic investments:** G1, G2, G3, G5
