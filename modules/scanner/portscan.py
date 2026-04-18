#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - High-Performance Port Scanner

Features:
  - Concurrent TCP/UDP scanning with configurable thread pool
  - Service banner grabbing with protocol-aware probes
  - Service version detection via banner analysis
  - IoT-specific protocol probes (RTSP, MQTT, CoAP, Modbus, etc.)
"""

import socket
import struct
import time
import re
import threading
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import get_logger
from core.output import Console
from core.config import Config

logger = get_logger(__name__)


# Service identification by port number
PORT_SERVICE_MAP = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    69:    "tftp",
    80:    "http",
    81:    "http",
    102:   "s7comm",
    110:   "pop3",
    143:   "imap",
    161:   "snmp",
    162:   "snmp-trap",
    443:   "https",
    502:   "modbus",
    554:   "rtsp",
    1883:  "mqtt",
    1900:  "ssdp",
    2323:  "telnet-alt",
    4433:  "https-alt",
    4840:  "opc-ua",
    5000:  "upnp",
    5683:  "coap",
    7547:  "cwmp",
    8000:  "http-alt",
    8080:  "http-proxy",
    8081:  "http-alt",
    8443:  "https-alt",
    8883:  "mqtt-tls",
    9100:  "jetdirect",
    9090:  "http-alt",
    10000: "webmin",
    20000: "dnp3",
    37777: "dahua-dvr",
    44818: "ethernet-ip",
    47808: "bacnet",
    49152: "upnp-igd",
}

# Protocol-specific banner probes
BANNER_PROBES = {
    "http":     b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "ftp":      None,  # FTP sends banner on connect
    "ssh":      None,  # SSH sends banner on connect
    "telnet":   None,  # Telnet sends banner on connect
    "smtp":     None,  # SMTP sends banner on connect
    "rtsp":     b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    "mqtt":     b"\x10\x0e\x00\x04MQTT\x04\x00\x00\x3c\x00\x02id",
    "modbus":   b"\x00\x01\x00\x00\x00\x06\x01\x11\x00\x00\x00\x00",
    "s7comm":   b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x09",
    "bacnet":   b"\x81\x0a\x00\x11\x01\x20\xff\xff\x00\xff\x10\x08\x0e\x0c\x02\x3f\xff\xff\x19\x4b",
}


class PortScanner:
    """
    High-performance TCP/UDP port scanner with service detection.

    Implements concurrent scanning with configurable rate limiting
    and protocol-aware banner grabbing.
    """

    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("timeout", 3)
        self.threads = config.get("threads", 100)
        self.banner_timeout = config.get("banner_grab_timeout", 3)

    def scan(
        self,
        target: str,
        ports: List[int],
        udp: bool = False,
        banner: bool = True
    ) -> List[Dict]:
        """
        Scan a target for open ports.

        Parameters
        ----------
        target : str
            Target IP address.
        ports : list of int
            List of port numbers to scan.
        udp : bool
            Include UDP scanning.
        banner : bool
            Attempt banner grabbing on open ports.

        Returns
        -------
        list of dict
            List of port result dictionaries.
        """
        Console.info(f"Scanning {target} ({len(ports)} ports, {self.threads} threads)")
        results = []

        # TCP scan
        tcp_results = self._tcp_scan(target, ports, banner)
        results.extend(tcp_results)

        # UDP scan (optional, requires root)
        if udp:
            udp_results = self._udp_scan(target, ports)
            results.extend(udp_results)

        open_count = sum(1 for r in results if r.get("state") == "open")
        Console.success(f"Scan complete: {open_count}/{len(ports)} port(s) open")

        return sorted(results, key=lambda r: r.get("port", 0))

    # ------------------------------------------------------------------ #
    # TCP scanning                                                         #
    # ------------------------------------------------------------------ #

    def _tcp_scan(self, target: str, ports: List[int], grab_banner: bool) -> List[Dict]:
        """Concurrent TCP port scanner."""
        results = []
        lock = threading.Lock()

        def scan_port(port: int) -> Optional[Dict]:
            result = self._probe_tcp(target, port)
            if result and grab_banner and result["state"] == "open":
                banner_data = self._grab_banner(target, port, result.get("service", ""))
                result["banner"] = banner_data
                result["version"] = self._extract_version(banner_data)
            return result

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(scan_port, p): p for p in ports}
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 500 == 0:
                    Console.progress(completed, len(ports), f"ports scanned")
                result = future.result()
                if result:
                    with lock:
                        results.append(result)

        return results

    def _probe_tcp(self, target: str, port: int) -> Optional[Dict]:
        """Probe a single TCP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()

            state = "open" if result == 0 else "closed"
            service = PORT_SERVICE_MAP.get(port, "unknown")

            return {
                "port": port,
                "protocol": "tcp",
                "state": state,
                "service": service,
                "banner": "",
                "version": "",
            }
        except Exception as e:
            logger.debug(f"TCP probe error {target}:{port} - {e}")
            return None

    # ------------------------------------------------------------------ #
    # UDP scanning                                                         #
    # ------------------------------------------------------------------ #

    def _udp_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """UDP port scanner (best-effort, requires root for ICMP)."""
        results = []
        udp_ports = [p for p in ports if p in (53, 69, 123, 161, 162, 1900, 5353, 5683)]

        for port in udp_ports:
            result = self._probe_udp(target, port)
            if result:
                results.append(result)

        return results

    def _probe_udp(self, target: str, port: int) -> Optional[Dict]:
        """Probe a single UDP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            # Send a generic probe
            sock.sendto(b"\x00" * 4, (target, port))

            try:
                data, _ = sock.recvfrom(1024)
                state = "open"
                banner = data[:64].hex()
            except socket.timeout:
                state = "open|filtered"
                banner = ""
            finally:
                sock.close()

            return {
                "port": port,
                "protocol": "udp",
                "state": state,
                "service": PORT_SERVICE_MAP.get(port, "unknown"),
                "banner": banner,
                "version": "",
            }
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # Banner grabbing                                                      #
    # ------------------------------------------------------------------ #

    def _grab_banner(self, target: str, port: int, service: str) -> str:
        """
        Grab service banner from an open port.

        Uses protocol-specific probes for known services and
        falls back to passive listening for others.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.banner_timeout)
            sock.connect((target, port))

            # Send protocol-specific probe if available
            probe = BANNER_PROBES.get(service)
            if probe:
                if b"{host}" in probe:
                    probe = probe.replace(b"{host}", target.encode())
                sock.send(probe)

            # Read response
            banner_bytes = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    banner_bytes += chunk
                    if len(banner_bytes) > 2048:
                        break
            except socket.timeout:
                pass

            sock.close()

            # Decode and clean banner
            try:
                banner = banner_bytes.decode("utf-8", errors="replace").strip()
            except Exception:
                banner = banner_bytes[:128].hex()

            # Remove non-printable characters
            banner = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", banner)
            return banner[:256]

        except Exception as e:
            logger.debug(f"Banner grab failed {target}:{port} - {e}")
            return ""

    def _extract_version(self, banner: str) -> str:
        """Extract version string from a service banner."""
        if not banner:
            return ""

        # Common version patterns
        patterns = [
            r"OpenSSH[_\s]+([\d.]+\w*)",
            r"Apache[/\s]+([\d.]+)",
            r"nginx[/\s]+([\d.]+)",
            r"vsftpd\s+([\d.]+)",
            r"ProFTPD\s+([\d.]+)",
            r"Postfix\s+ESMTP\s+([\d.]+)",
            r"Microsoft-IIS[/\s]+([\d.]+)",
            r"lighttpd[/\s]+([\d.]+)",
            r"Server:\s+(.+?)[\r\n]",
            r"SSH-([\d.]+)-(.+?)[\r\n]",
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:64]

        return ""
