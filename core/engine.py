#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Core Engine

Central orchestration layer that dispatches CLI arguments to the
appropriate modules and manages the full audit pipeline.
"""

import os
import sys
import json
import time
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from .config import Config
from .logger import get_logger
from .output import Console

logger = get_logger(__name__)

# S9: Per-module thread caps to avoid DoS on embedded devices
MODULE_THREAD_CAPS: Dict[str, int] = {
    "discover":    50,
    "scan":        10,
    "fingerprint": 5,
    "vuln":        5,
    "brute":       3,
    "exploit":     3,
    "audit":       10,
}


class Engine:
    """
    Main orchestration engine for IoTBreaker.

    Responsible for:
    - Module dispatch based on CLI arguments
    - Session state management
    - Result aggregation
    - Report generation coordination
    """

    def __init__(self, config: Config):
        self.config = config
        self.session_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.findings: List[Dict] = []
        self.devices: List[Dict] = []
        self.start_time = time.time()
        # S3: Scope networks — populated from --scope-file or --engagement
        self.scope_networks: List[ipaddress.IPv4Network] = []
        # G1: Engagement context (set by CLI after __init__)
        self.engagement = None

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def load_scope(self, scope_file: str):
        """
        S3: Load authorized target networks from a scope file.

        The file should contain one CIDR per line (# comments supported).
        Every target passed to a module handler will be validated against
        this list. Targets outside scope are silently skipped with a warning.
        """
        p = Path(scope_file)
        if not p.exists():
            Console.error(f"Scope file not found: {scope_file}")
            return
        self.scope_networks = []
        with open(p, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    self.scope_networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    Console.warning(f"Scope file: invalid CIDR '{line}' — skipping")
        Console.info(f"Scope loaded: {len(self.scope_networks)} network(s) authorized")

    def _is_in_scope(self, target: str) -> bool:
        """
        S3: Return True if target is within an authorized scope network.
        If no scope is defined, all targets are permitted (with a warning).
        """
        if not self.scope_networks:
            return True
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return True  # hostnames pass through
        for net in self.scope_networks:
            if addr in net:
                return True
        return False

    def _apply_module_thread_cap(self, module: str):
        """
        S9: Temporarily lower the configured thread count to the per-module
        cap to prevent DoS on embedded devices.
        """
        cap = MODULE_THREAD_CAPS.get(module)
        if cap is not None:
            configured = self.config.get("threads", 100)
            self.config.set("threads", min(configured, cap))

    def run(self, args) -> int:
        """
        Dispatch the parsed arguments to the correct module.

        Returns
        -------
        int
            Exit code (0 = success, 1 = error, 2 = no findings).
        """
        module = args.module

        dispatch = {
            "discover":    self._run_discover,
            "scan":        self._run_scan,
            "fingerprint": self._run_fingerprint,
            "vuln":        self._run_vuln,
            "brute":       self._run_brute,
            "exploit":     self._run_exploit,
            "firmware":    self._run_firmware,
            "shodan":      self._run_shodan,
            "cve":         self._run_cve,
            "audit":       self._run_audit,
        }

        handler = dispatch.get(module)
        if not handler:
            Console.error(f"Unknown module: {module}")
            return 1

        # S9: Apply per-module thread cap
        self._apply_module_thread_cap(module)

        logger.info(f"Starting module: {module} | session: {self.session_id}")
        Console.info(f"Session ID: {self.session_id}")
        Console.info(f"Module: {module.upper()}")
        print()

        try:
            result = handler(args)
        except Exception as e:
            logger.exception(f"Module {module} raised an exception")
            Console.error(str(e))
            return 1

        # Generate reports if findings exist
        if self.findings or self.devices:
            self._generate_reports(args)

        elapsed = time.time() - self.start_time
        Console.info(f"Completed in {elapsed:.1f}s | {len(self.findings)} finding(s)")

        return 0 if result else 2

    # ------------------------------------------------------------------ #
    # Module handlers                                                      #
    # ------------------------------------------------------------------ #

    def _run_discover(self, args) -> bool:
        from modules.discovery.discovery import DiscoveryModule
        mod = DiscoveryModule(self.config)
        self.devices = mod.run(
            network=args.network,
            method=getattr(args, "method", "all"),
            exclude=self._parse_exclude(getattr(args, "exclude", None))
        )
        if self.devices:
            Console.section("DISCOVERED DEVICES")
            headers = ["IP Address", "MAC Address", "Hostname", "Device Type", "Open Ports"]
            rows = [
                [
                    d.get("ip", ""),
                    d.get("mac", "N/A"),
                    d.get("hostname", "N/A"),
                    d.get("device_type", "Unknown"),
                    ", ".join(str(p) for p in d.get("open_ports", [])[:5])
                ]
                for d in self.devices
            ]
            Console.table(headers, rows)
            Console.success(f"Discovered {len(self.devices)} device(s)")
        else:
            Console.warning("No devices discovered on the specified network.")
        return bool(self.devices)

    def _run_scan(self, args) -> bool:
        # S3: Scope check
        target = args.target
        if not self._is_in_scope(target):
            Console.error(f"[SCOPE] {target} is outside the authorized scope. Skipping.")
            return False
        from modules.scanner.portscan import PortScanner
        scanner = PortScanner(self.config)
        ports = self._parse_ports(args.ports)
        results = scanner.scan(
            target=args.target,
            ports=ports,
            udp=getattr(args, "udp", False),
            banner=getattr(args, "banner", True)
        )
        if results:
            Console.section("PORT SCAN RESULTS")
            headers = ["Port", "State", "Protocol", "Service", "Version / Banner"]
            rows = [
                [
                    r.get("port", ""),
                    r.get("state", ""),
                    r.get("protocol", "tcp"),
                    r.get("service", ""),
                    r.get("banner", "")[:60]
                ]
                for r in results if r.get("state") == "open"
            ]
            Console.table(headers, rows)
            open_count = sum(1 for r in results if r.get("state") == "open")
            Console.success(f"{open_count} open port(s) found on {args.target}")
        else:
            Console.warning(f"No open ports found on {args.target}")
        return bool(results)

    def _run_fingerprint(self, args) -> bool:
        # S3: Scope check
        if not self._is_in_scope(args.target):
            Console.error(f"[SCOPE] {args.target} is outside the authorized scope. Skipping.")
            return False
        from modules.fingerprint.fingerprint import FingerprintModule
        fp = FingerprintModule(self.config)
        result = fp.run(
            target=args.target,
            deep=getattr(args, "deep", False),
            mac=getattr(args, "mac", None)
        )
        if result:
            Console.section("DEVICE FINGERPRINT")
            fields = [
                ("IP Address",        result.get("ip", "")),
                ("MAC Address",       result.get("mac", "N/A")),
                ("OUI Vendor",        result.get("oui_vendor", "N/A")),
                ("Hostname",          result.get("hostname", "N/A")),
                ("Device Type",       result.get("device_type", "Unknown")),
                ("Manufacturer",      result.get("manufacturer", "N/A")),
                ("Model",             result.get("model", "N/A")),
                ("Firmware Version",  result.get("firmware_version", "N/A")),
                ("Operating System",  result.get("os", "N/A")),
                ("Open Ports",        ", ".join(str(p) for p in result.get("open_ports", []))),
                ("Services",          ", ".join(result.get("services", []))),
                ("TTL",               str(result.get("ttl", "N/A"))),
            ]
            for label, value in fields:
                if value and value != "N/A":
                    print(f"  {label:<20} {value}")
        return bool(result)

    def _run_vuln(self, args) -> bool:
        # S3: Scope check
        if not self._is_in_scope(args.target):
            Console.error(f"[SCOPE] {args.target} is outside the authorized scope. Skipping.")
            return False
        from modules.vulnscan.vulnscan import VulnScanner
        scanner = VulnScanner(self.config)

        checks = []
        if getattr(args, "all", False):
            checks = ["telnet", "ssh", "mqtt", "http", "rtsp", "coap", "upnp", "snmp", "ftp"]
        else:
            for proto in ["telnet", "ssh", "mqtt", "http", "rtsp", "coap", "upnp", "snmp", "ftp"]:
                if getattr(args, proto, False):
                    checks.append(proto)

        if not checks:
            checks = ["telnet", "ssh", "mqtt", "http", "upnp", "snmp"]

        self.findings = scanner.run(
            target=args.target,
            checks=checks,
            cve_lookup=getattr(args, "cve", False)
        )

        Console.section("VULNERABILITY SCAN RESULTS")
        if self.findings:
            for f in self.findings:
                Console.finding(
                    f.get("severity", "INFO"),
                    f.get("title", "Unknown"),
                    f.get("description", "")
                )
                if f.get("cve_ids"):
                    print(f"         CVE: {', '.join(f['cve_ids'])}")
                if f.get("cvss_score"):
                    print(f"         CVSS: {f['cvss_score']:.1f}")
            Console.result_summary(self.findings)
        else:
            Console.success(f"No vulnerabilities found on {args.target}")

        return bool(self.findings)

    def _run_brute(self, args) -> bool:
        # S3: Scope check
        if not self._is_in_scope(args.target):
            Console.error(f"[SCOPE] {args.target} is outside the authorized scope. Skipping.")
            return False
        from modules.bruteforce.bruteforce import BruteForceModule
        bf = BruteForceModule(self.config)
        results = bf.run(
            target=args.target,
            protocol=args.protocol,
            port=getattr(args, "port", None),
            users_file=getattr(args, "users", None),
            passwords_file=getattr(args, "passwords", None),
            combo_file=getattr(args, "combo", None),
            stop_on_success=getattr(args, "stop_on_success", True),
            delay=getattr(args, "delay", 0.0)
        )
        Console.section("BRUTE-FORCE RESULTS")
        reveal = self.config.get("reveal_creds", False)
        if results:
            for r in results:
                masked_pw = r['password'] if reveal else '*' * len(r['password'])
                Console.finding(
                    "CRITICAL",
                    f"Valid credentials found: {r['username']}:{masked_pw}",
                    f"Protocol: {r['protocol']} | Port: {r['port']}"
                )
            self.findings.extend([{
                "severity": "CRITICAL",
                "title": f"Weak/Default Credentials ({r['protocol'].upper()})",
                "description": f"Valid credentials: {r['username']}:{r['password']}",
                "target": args.target,
                "port": r.get("port"),
                "protocol": r.get("protocol"),
            } for r in results])
        else:
            Console.success("No valid credentials found.")
        return bool(results)

    def _run_exploit(self, args) -> bool:
        # S3: Scope check
        if getattr(args, "target", None) and not self._is_in_scope(args.target):
            Console.error(f"[SCOPE] {args.target} is outside the authorized scope. Skipping.")
            return False
        from modules.exploit.exploit import ExploitModule
        ex = ExploitModule(self.config)

        if getattr(args, "list", False):
            exploits = ex.list_exploits()
            Console.section("AVAILABLE EXPLOITS")
            headers = ["CVE ID", "Title", "Affected Products", "CVSS"]
            rows = [[e["cve"], e["title"], e["products"], e["cvss"]] for e in exploits]
            Console.table(headers, rows)
            return True

        result = ex.run(
            target=args.target,
            cve_id=getattr(args, "cve", None),
            check_only=getattr(args, "check", False),
            payload=getattr(args, "payload", None)
        )
        Console.section("EXPLOIT RESULTS")
        if result:
            for r in result:
                status = "VULNERABLE" if r.get("exploited") else "NOT VULNERABLE"
                Console.finding(
                    "CRITICAL" if r.get("exploited") else "INFO",
                    f"{r.get('cve', 'N/A')} - {status}",
                    r.get("detail", "")
                )
        return bool(result)

    def _run_firmware(self, args) -> bool:
        from modules.firmware.firmware import FirmwareAnalyzer
        fa = FirmwareAnalyzer(self.config)
        result = fa.run(
            firmware_path=args.file,
            extract=getattr(args, "extract", True),
            find_secrets=getattr(args, "secrets", True),
            crypto_analysis=getattr(args, "crypto", False),
            strings_analysis=getattr(args, "strings", False),
            entropy_analysis=getattr(args, "entropy", False)
        )
        Console.section("FIRMWARE ANALYSIS RESULTS")
        if result:
            print(f"  File:        {result.get('file', '')}")
            print(f"  Size:        {result.get('size_human', 'N/A')}")
            print(f"  MD5:         {result.get('md5', 'N/A')}")
            print(f"  SHA256:      {result.get('sha256', 'N/A')}")
            print(f"  File Type:   {result.get('file_type', 'N/A')}")
            print(f"  Architecture:{result.get('architecture', 'N/A')}")
            print()
            secrets = result.get("secrets", [])
            if secrets:
                Console.section("HARDCODED SECRETS")
                for s in secrets:
                    Console.finding("HIGH", s.get("type", "Secret"), s.get("value", ""))
                    print(f"         File: {s.get('file', '')}")
            self.findings.extend([{
                "severity": "HIGH",
                "title": f"Hardcoded {s.get('type', 'Secret')} in Firmware",
                "description": s.get("value", ""),
                "target": args.file,
            } for s in secrets])
        return bool(result)

    def _run_shodan(self, args) -> bool:
        from modules.discovery.shodan_intel import ShodanIntel
        si = ShodanIntel(self.config)

        api_key = getattr(args, "api_key", None) or self.config.get("shodan_api_key")
        if not api_key:
            Console.error("Shodan API key required. Set SHODAN_API_KEY environment variable.")
            return False

        si.set_api_key(api_key)

        if getattr(args, "ip", None):
            result = si.lookup_ip(args.ip)
            Console.section(f"SHODAN INTELLIGENCE: {args.ip}")
            if result:
                print(f"  IP:           {result.get('ip', '')}")
                print(f"  Country:      {result.get('country', 'N/A')}")
                print(f"  Organization: {result.get('org', 'N/A')}")
                print(f"  ISP:          {result.get('isp', 'N/A')}")
                print(f"  Hostnames:    {', '.join(result.get('hostnames', []))}")
                print(f"  Open Ports:   {', '.join(str(p) for p in result.get('ports', []))}")
                print(f"  Vulns (CVE):  {', '.join(result.get('vulns', []))}")
        elif getattr(args, "query", None):
            results = si.search(
                query=args.query,
                limit=getattr(args, "limit", 50),
                facets=getattr(args, "facets", None)
            )
            Console.section(f"SHODAN SEARCH: {args.query}")
            if results:
                headers = ["IP", "Port", "Country", "Org", "Product", "Version"]
                rows = [
                    [r.get("ip",""), r.get("port",""), r.get("country",""),
                     r.get("org","")[:25], r.get("product",""), r.get("version","")]
                    for r in results
                ]
                Console.table(headers, rows)
                Console.success(f"{len(results)} result(s) found")
        return True

    def _run_cve(self, args) -> bool:
        from modules.vulnscan.cve_lookup import CVELookup
        cve = CVELookup(self.config)

        results = cve.search(
            vendor=getattr(args, "vendor", None),
            product=getattr(args, "product", None),
            cve_id=getattr(args, "cve_id", None),
            severity=getattr(args, "severity", None),
            year=getattr(args, "year", None)
        )

        Console.section("CVE DATABASE RESULTS")
        if results:
            headers = ["CVE ID", "CVSS", "Severity", "Published", "Summary"]
            rows = [
                [
                    r.get("id", ""),
                    str(r.get("cvss_score", "N/A")),
                    r.get("severity", ""),
                    r.get("published", "")[:10],
                    r.get("summary", "")[:55]
                ]
                for r in results
            ]
            Console.table(headers, rows)
            Console.success(f"{len(results)} CVE(s) found")
        else:
            Console.warning("No CVEs found matching the specified criteria.")
        return bool(results)

    def _run_audit(self, args) -> bool:
        """Full automated audit pipeline."""
        Console.section("FULL AUDIT PIPELINE")
        profile = getattr(args, "profile", "standard")
        Console.info(f"Audit profile: {profile.upper()}")

        # Phase 1: Discovery
        Console.section("PHASE 1 - NETWORK DISCOVERY")
        from modules.discovery.discovery import DiscoveryModule
        disc = DiscoveryModule(self.config)
        self.devices = disc.run(
            network=args.network,
            method="all",
            exclude=self._parse_exclude(getattr(args, "exclude", None))
        )

        if not self.devices:
            Console.warning("No devices found. Audit terminated.")
            return False

        Console.success(f"Discovered {len(self.devices)} device(s)")

        # Phase 2: Port scan + fingerprint
        Console.section("PHASE 2 - PORT SCAN AND FINGERPRINTING")
        from modules.scanner.portscan import PortScanner
        from modules.fingerprint.fingerprint import FingerprintModule
        scanner = PortScanner(self.config)
        fp_mod = FingerprintModule(self.config)

        for device in self.devices:
            ip = device.get("ip", "")
            if not ip:
                continue
            Console.info(f"Scanning {ip}...")
            ports = self._parse_ports("iot-common")
            scan_results = scanner.scan(ip, ports, banner=True)
            device["scan_results"] = scan_results
            device["open_ports"] = [r["port"] for r in scan_results if r.get("state") == "open"]

            fp_result = fp_mod.run(ip)
            if fp_result:
                device.update(fp_result)

        # Phase 3: Vulnerability scan
        Console.section("PHASE 3 - VULNERABILITY ASSESSMENT")
        from modules.vulnscan.vulnscan import VulnScanner
        vuln_scanner = VulnScanner(self.config)
        checks = ["telnet", "ssh", "mqtt", "http", "upnp", "snmp", "ftp", "rtsp"]

        for device in self.devices:
            ip = device.get("ip", "")
            if not ip:
                continue
            Console.info(f"Vulnerability scan: {ip}...")
            findings = vuln_scanner.run(ip, checks=checks, cve_lookup=True)
            self.findings.extend(findings)
            device["findings"] = findings

        # Phase 4: Shodan (optional)
        if getattr(args, "shodan", False):
            Console.section("PHASE 4 - SHODAN INTELLIGENCE")
            from modules.discovery.shodan_intel import ShodanIntel
            api_key = self.config.get("shodan_api_key")
            if api_key:
                si = ShodanIntel(self.config)
                si.set_api_key(api_key)
                for device in self.devices:
                    ip = device.get("ip", "")
                    if ip:
                        shodan_data = si.lookup_ip(ip)
                        if shodan_data:
                            device["shodan"] = shodan_data

        # Summary
        Console.section("AUDIT COMPLETE")
        Console.result_summary(self.findings)
        return True

    # ------------------------------------------------------------------ #
    # Report generation                                                    #
    # ------------------------------------------------------------------ #

    def _generate_reports(self, args):
        """Generate all requested report formats."""
        from modules.reporting.report import ReportGenerator
        from core.compliance import enrich_finding_compliance
        # G10: Enrich all findings with compliance framework mappings
        for finding in self.findings:
            enrich_finding_compliance(finding)

        # G2: Persist session to SQLite database
        db_path = self.config.get("db_path", "")
        if db_path:
            try:
                from core.database import Database
                db = Database(db_path)
                db.save_session(self)
            except Exception as exc:
                logger.warning(f"Database persistence failed: {exc}")
        fmt = getattr(args, "format", "all")
        out_dir = Path(self.config.get("output_dir", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        rg = ReportGenerator(
            session_id=self.session_id,
            devices=self.devices,
            findings=self.findings,
            config=self.config
        )

        if fmt in ("json", "all"):
            path = rg.generate_json(out_dir)
            Console.success(f"JSON report: {path}")

        if fmt in ("html", "all"):
            path = rg.generate_html(out_dir)
            Console.success(f"HTML report: {path}")

        if fmt in ("pdf", "all"):
            path = rg.generate_pdf(out_dir)
            Console.success(f"PDF report: {path}")

        # G4: Delta report if --compare baseline provided
        compare_path = getattr(args, "compare", None)
        if compare_path:
            try:
                delta_path = rg.generate_delta(compare_path, out_dir)
                Console.success(f"Delta report: {delta_path}")
            except FileNotFoundError as e:
                Console.error(str(e))

        # 4.4: SIEM / SOAR exports (opt-in via --siem flags)
        if self.findings:
            siem_cfg = self.config.get("siem", {})
            if isinstance(siem_cfg, dict) and siem_cfg:
                try:
                    from modules.reporting.siem import SiemExporter
                    exporter = SiemExporter(self.config)

                    hec_url   = siem_cfg.get("splunk_hec_url", "")
                    hec_token = siem_cfg.get("splunk_hec_token", "")
                    if hec_url and hec_token:
                        exporter.export_splunk_hec(
                            self.findings, self.session_id, hec_url, hec_token,
                            index=siem_cfg.get("splunk_index", "iotbreaker"),
                        )
                        Console.success("Splunk HEC export complete.")

                    if siem_cfg.get("cef_host"):
                        exporter.export_cef(
                            self.findings, self.session_id,
                            syslog_host=siem_cfg.get("cef_host", "127.0.0.1"),
                            syslog_port=int(siem_cfg.get("cef_port", 514)),
                            use_tcp=siem_cfg.get("cef_tcp", False),
                        )
                        Console.success("CEF syslog export complete.")

                    if siem_cfg.get("ecs_enabled", False):
                        ecs_path = exporter.export_ecs(
                            self.findings, self.session_id,
                            output_dir=str(out_dir),
                        )
                        Console.success(f"ECS NDJSON export: {ecs_path}")

                except Exception as exc:
                    logger.warning(f"SIEM export failed: {exc}")

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_ports(port_spec: str) -> List[int]:
        """Parse a port specification string into a list of integers."""
        from core.config import IOT_COMMON_PORTS

        if port_spec == "iot-common":
            return IOT_COMMON_PORTS
        if port_spec == "all":
            return list(range(1, 65536))

        ports = set()
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    @staticmethod
    def _parse_exclude(exclude_str: Optional[str]) -> List[str]:
        """Parse a comma-separated list of IPs to exclude."""
        if not exclude_str:
            return []
        return [ip.strip() for ip in exclude_str.split(",") if ip.strip()]
