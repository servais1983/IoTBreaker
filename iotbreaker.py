#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Professional IoT Security Assessment Framework
Version 4.0.0

A comprehensive penetration testing framework for Internet of Things devices,
designed for authorized security assessments and research.

Usage:
    python3 iotbreaker.py [module] [options]

License: MIT
Author: IoTBreaker Project
"""

import argparse
import sys
import os
import json
import logging
import time
import signal
from datetime import datetime
from pathlib import Path

# Ensure the project root is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import Engine
from core.config import Config
from core.logger import setup_logger, get_logger
from core.output import Console

__version__ = "4.0.0"
__author__  = "IoTBreaker Project"
__license__ = "MIT"

BANNER = r"""
  ___    _____   ____                  _
 |_ _|  |_   _| | __ )  _ __  ___  __ _| | _____ _ __
  | |     | |   |  _ \ | '__|/ _ \/ _` | |/ / _ \ '__|
  | |     | |   | |_) || |  |  __/ (_| |   <  __/ |
 |___|    |_|   |____/ |_|   \___|\__,_|_|\_\___|_|

  IoT Security Assessment Framework  v{version}
  Professional Penetration Testing Toolkit for IoT Devices
  -------------------------------------------------------
  Use only on systems you own or have explicit permission to test.
""".format(version=__version__)


def signal_handler(sig, frame):
    """Handle graceful shutdown on SIGINT."""
    Console.warning("\nInterrupt received. Shutting down gracefully...")
    sys.exit(0)


def build_parser() -> argparse.ArgumentParser:
    """Build the main argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="iotbreaker",
        description="IoTBreaker - Professional IoT Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full network discovery
  python3 iotbreaker.py discover --network 192.168.1.0/24

  # Port scan a specific target
  python3 iotbreaker.py scan --target 192.168.1.100 --ports 1-65535

  # Device fingerprinting
  python3 iotbreaker.py fingerprint --target 192.168.1.100

  # Vulnerability assessment
  python3 iotbreaker.py vuln --target 192.168.1.100 --all

  # Credential brute-force
  python3 iotbreaker.py brute --target 192.168.1.100 --protocol telnet

  # Firmware analysis
  python3 iotbreaker.py firmware --file /path/to/firmware.bin

  # Shodan intelligence
  python3 iotbreaker.py shodan --query "product:Hikvision"

  # Full audit pipeline
  python3 iotbreaker.py audit --network 192.168.1.0/24 --output /tmp/report

  # CVE lookup
  python3 iotbreaker.py cve --vendor hikvision --product ipcam
        """
    )

    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"IoTBreaker {__version__}"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "html", "pdf", "all"],
        default="all",
        help="Report output format (default: all)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=5,
        metavar="SECONDS",
        help="Connection timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        metavar="N",
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the banner"
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to configuration file"
    )

    subparsers = parser.add_subparsers(
        dest="module",
        title="Modules",
        metavar="<module>"
    )

    # ------------------------------------------------------------------ #
    # MODULE: discover                                                     #
    # ------------------------------------------------------------------ #
    p_discover = subparsers.add_parser(
        "discover",
        help="Discover IoT devices on the network",
        description="Network discovery using ARP, mDNS, UPnP, SSDP, and TCP probing."
    )
    p_discover.add_argument("--network", "-n", required=True, metavar="CIDR",
        help="Target network in CIDR notation (e.g. 192.168.1.0/24)")
    p_discover.add_argument("--method",
        choices=["arp", "tcp", "upnp", "mdns", "all"],
        default="all",
        help="Discovery method (default: all)")
    p_discover.add_argument("--exclude", metavar="IP[,IP]",
        help="Comma-separated list of IPs to exclude")

    # ------------------------------------------------------------------ #
    # MODULE: scan                                                         #
    # ------------------------------------------------------------------ #
    p_scan = subparsers.add_parser(
        "scan",
        help="Port scan and service detection",
        description="High-performance TCP/UDP port scanner with service banner grabbing."
    )
    p_scan.add_argument("--target", "-T", required=True, metavar="IP/CIDR",
        help="Target IP address or CIDR range")
    p_scan.add_argument("--ports", "-p", default="iot-common",
        metavar="RANGE",
        help="Port range: 1-1024, 80,443,8080, 'iot-common', 'all' (default: iot-common)")
    p_scan.add_argument("--udp", action="store_true",
        help="Include UDP scan (requires root)")
    p_scan.add_argument("--banner", action="store_true", default=True,
        help="Grab service banners (default: enabled)")
    p_scan.add_argument("--rate", type=int, default=500, metavar="PPS",
        help="Packets per second rate limit (default: 500)")

    # ------------------------------------------------------------------ #
    # MODULE: fingerprint                                                  #
    # ------------------------------------------------------------------ #
    p_fp = subparsers.add_parser(
        "fingerprint",
        help="Device fingerprinting and OS detection",
        description="Identify device manufacturer, model, firmware version, and OS."
    )
    p_fp.add_argument("--target", "-T", required=True, metavar="IP",
        help="Target IP address")
    p_fp.add_argument("--deep", action="store_true",
        help="Enable deep fingerprinting (slower, more accurate)")
    p_fp.add_argument("--mac", metavar="MAC",
        help="MAC address for OUI lookup (optional)")

    # ------------------------------------------------------------------ #
    # MODULE: vuln                                                         #
    # ------------------------------------------------------------------ #
    p_vuln = subparsers.add_parser(
        "vuln",
        help="Vulnerability scanning and CVE correlation",
        description="Scan for known IoT vulnerabilities with CVSS scoring and CVE correlation."
    )
    p_vuln.add_argument("--target", "-T", required=True, metavar="IP",
        help="Target IP address")
    p_vuln.add_argument("--all", "-a", action="store_true",
        help="Run all vulnerability checks")
    p_vuln.add_argument("--telnet", action="store_true",
        help="Test Telnet default credentials")
    p_vuln.add_argument("--ssh", action="store_true",
        help="Test SSH weak configurations")
    p_vuln.add_argument("--mqtt", action="store_true",
        help="Test MQTT authentication bypass")
    p_vuln.add_argument("--http", action="store_true",
        help="Test HTTP/HTTPS web interfaces")
    p_vuln.add_argument("--rtsp", action="store_true",
        help="Test RTSP stream authentication")
    p_vuln.add_argument("--coap", action="store_true",
        help="Test CoAP protocol vulnerabilities")
    p_vuln.add_argument("--upnp", action="store_true",
        help="Test UPnP misconfigurations")
    p_vuln.add_argument("--snmp", action="store_true",
        help="Test SNMP community strings")
    p_vuln.add_argument("--ftp", action="store_true",
        help="Test FTP anonymous access")
    p_vuln.add_argument("--cve", action="store_true",
        help="Correlate findings with CVE database")

    # ------------------------------------------------------------------ #
    # MODULE: brute                                                        #
    # ------------------------------------------------------------------ #
    p_brute = subparsers.add_parser(
        "brute",
        help="Credential brute-force attacks",
        description="Multi-protocol credential brute-force with smart wordlist management."
    )
    p_brute.add_argument("--target", "-T", required=True, metavar="IP",
        help="Target IP address")
    p_brute.add_argument("--protocol", required=True,
        choices=["telnet", "ssh", "ftp", "http", "rtsp", "snmp", "mqtt", "all"],
        help="Protocol to attack")
    p_brute.add_argument("--port", "-p", type=int, metavar="PORT",
        help="Custom port (overrides default)")
    p_brute.add_argument("--users", "-u", metavar="FILE",
        help="Custom username wordlist file")
    p_brute.add_argument("--passwords", "-P", metavar="FILE",
        help="Custom password wordlist file")
    p_brute.add_argument("--combo", metavar="FILE",
        help="Combo list file (user:pass format)")
    p_brute.add_argument("--stop-on-success", action="store_true", default=True,
        help="Stop after first successful credential (default: enabled)")
    p_brute.add_argument("--delay", type=float, default=0.0, metavar="SECONDS",
        help="Delay between attempts in seconds")

    # ------------------------------------------------------------------ #
    # MODULE: exploit                                                      #
    # ------------------------------------------------------------------ #
    p_exploit = subparsers.add_parser(
        "exploit",
        help="Exploit known IoT vulnerabilities",
        description="Execute proof-of-concept exploits for known IoT CVEs."
    )
    p_exploit.add_argument("--target", "-T", required=True, metavar="IP",
        help="Target IP address")
    p_exploit.add_argument("--cve", metavar="CVE-ID",
        help="Specific CVE to exploit (e.g. CVE-2021-36260)")
    p_exploit.add_argument("--list", action="store_true",
        help="List all available exploits")
    p_exploit.add_argument("--check", action="store_true",
        help="Check if target is vulnerable without exploiting")
    p_exploit.add_argument("--payload", metavar="CMD",
        help="Command payload for RCE exploits")

    # ------------------------------------------------------------------ #
    # MODULE: firmware                                                     #
    # ------------------------------------------------------------------ #
    p_fw = subparsers.add_parser(
        "firmware",
        help="Firmware extraction and analysis",
        description="Analyze firmware images for hardcoded credentials, backdoors, and vulnerabilities."
    )
    p_fw.add_argument("--file", "-F", required=True, metavar="FILE",
        help="Path to firmware binary file")
    p_fw.add_argument("--extract", action="store_true", default=True,
        help="Extract filesystem from firmware (default: enabled)")
    p_fw.add_argument("--secrets", action="store_true", default=True,
        help="Search for hardcoded credentials and secrets")
    p_fw.add_argument("--crypto", action="store_true",
        help="Analyze cryptographic implementations")
    p_fw.add_argument("--strings", action="store_true",
        help="Extract and analyze interesting strings")
    p_fw.add_argument("--entropy", action="store_true",
        help="Compute entropy analysis (detect encryption/compression)")

    # ------------------------------------------------------------------ #
    # MODULE: shodan                                                       #
    # ------------------------------------------------------------------ #
    p_shodan = subparsers.add_parser(
        "shodan",
        help="Shodan intelligence gathering",
        description="Query Shodan for IoT device intelligence and exposure analysis."
    )
    p_shodan.add_argument("--query", "-q", metavar="QUERY",
        help="Shodan search query")
    p_shodan.add_argument("--ip", metavar="IP",
        help="Look up a specific IP address")
    p_shodan.add_argument("--limit", type=int, default=50, metavar="N",
        help="Maximum number of results (default: 50)")
    p_shodan.add_argument("--facets", metavar="FACETS",
        help="Comma-separated facets for aggregation (e.g. country,org)")
    p_shodan.add_argument("--api-key", metavar="KEY",
        help="Shodan API key (overrides env variable)")

    # ------------------------------------------------------------------ #
    # MODULE: cve                                                          #
    # ------------------------------------------------------------------ #
    p_cve = subparsers.add_parser(
        "cve",
        help="CVE database lookup and correlation",
        description="Search the NVD/CVE database for IoT-related vulnerabilities."
    )
    p_cve.add_argument("--vendor", metavar="VENDOR",
        help="Vendor name (e.g. hikvision, dahua, dlink)")
    p_cve.add_argument("--product", metavar="PRODUCT",
        help="Product name")
    p_cve.add_argument("--cve-id", metavar="CVE-ID",
        help="Specific CVE identifier")
    p_cve.add_argument("--severity",
        choices=["critical", "high", "medium", "low"],
        help="Filter by minimum severity")
    p_cve.add_argument("--year", type=int, metavar="YEAR",
        help="Filter by publication year")

    # ------------------------------------------------------------------ #
    # MODULE: audit                                                        #
    # ------------------------------------------------------------------ #
    p_audit = subparsers.add_parser(
        "audit",
        help="Full automated security audit pipeline",
        description="Run the complete IoT security assessment pipeline: discover, scan, fingerprint, vuln, report."
    )
    p_audit.add_argument("--network", "-n", required=True, metavar="CIDR",
        help="Target network in CIDR notation")
    p_audit.add_argument("--target", "-T", metavar="IP",
        help="Single target IP (skips discovery)")
    p_audit.add_argument("--profile",
        choices=["quick", "standard", "deep", "stealth"],
        default="standard",
        help="Audit profile (default: standard)")
    p_audit.add_argument("--exclude", metavar="IP[,IP]",
        help="Comma-separated IPs to exclude")
    p_audit.add_argument("--no-exploit", action="store_true",
        help="Skip exploitation phase")
    p_audit.add_argument("--shodan", action="store_true",
        help="Include Shodan intelligence gathering")

    return parser


def main():
    """Main entry point for IoTBreaker."""
    signal.signal(signal.SIGINT, signal_handler)

    parser = build_parser()
    args = parser.parse_args()

    # Display banner
    if not getattr(args, "no_banner", False):
        print(BANNER)

    # Setup logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG

    setup_logger(log_level)
    logger = get_logger(__name__)

    # Load configuration
    config = Config()
    if args.config:
        config.load_file(args.config)

    # Apply CLI overrides
    config.set("timeout", args.timeout)
    config.set("threads", args.threads)
    config.set("output_dir", args.output)
    config.set("report_format", args.format)
    config.set("verbose", args.verbose)

    # Ensure output directory exists
    Path(args.output).mkdir(parents=True, exist_ok=True)

    # No module selected
    if not args.module:
        parser.print_help()
        sys.exit(0)

    # Initialize the engine
    engine = Engine(config)

    # Dispatch to the appropriate module
    try:
        exit_code = engine.run(args)
    except KeyboardInterrupt:
        Console.warning("Operation interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception("Unhandled exception in engine")
        Console.error(f"Fatal error: {e}")
        sys.exit(1)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
