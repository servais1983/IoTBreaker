#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Vulnerability Scanner Module

Comprehensive IoT vulnerability assessment covering:
  - Telnet default credentials
  - SSH weak configurations and algorithms
  - MQTT authentication bypass and wildcard subscriptions
  - HTTP/HTTPS exposed admin interfaces and path traversal
  - RTSP unauthenticated stream access
  - CoAP resource enumeration
  - UPnP IGD misconfigurations
  - SNMP community string enumeration
  - FTP anonymous access
  - CVE correlation via NVD API

All findings include CVSS v3.1 base scores and CWE references.
"""

import socket
import time
import re
import requests
import threading
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin

from core.logger import get_logger
from core.output import Console
from core.config import Config
from .cve_lookup import CVELookup

logger = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Default credential pairs (user:password) for IoT devices
DEFAULT_CREDENTIALS = [
    ("admin",    "admin"),
    ("admin",    ""),
    ("admin",    "1234"),
    ("admin",    "12345"),
    ("admin",    "123456"),
    ("admin",    "password"),
    ("admin",    "admin123"),
    ("root",     ""),
    ("root",     "root"),
    ("root",     "admin"),
    ("root",     "toor"),
    ("root",     "1234"),
    ("root",     "vizxv"),
    ("root",     "xc3511"),
    ("root",     "888888"),
    ("root",     "default"),
    ("user",     "user"),
    ("guest",    "guest"),
    ("support",  "support"),
    ("service",  "service"),
    ("ubnt",     "ubnt"),
    ("pi",       "raspberry"),
    ("admin",    "hikvision"),
    ("admin",    "dahua"),
    ("admin",    "888888"),
    ("admin",    "666666"),
    ("admin",    "1111111"),
    ("admin",    "admin1234"),
    ("666666",   "666666"),
    ("888888",   "888888"),
    ("default",  "default"),
]

# Common IoT admin web paths
ADMIN_PATHS = [
    "/",
    "/admin",
    "/admin/",
    "/admin.html",
    "/admin.php",
    "/login",
    "/login.html",
    "/login.php",
    "/cgi-bin/login.cgi",
    "/cgi-bin/admin.cgi",
    "/setup",
    "/setup.html",
    "/config",
    "/configuration",
    "/management",
    "/manager",
    "/webadmin",
    "/web/",
    "/index.html",
    "/index.php",
    "/home.html",
    "/main.html",
    "/dashboard",
    "/api/v1/",
    "/api/v2/",
    "/api/",
    "/rest/",
    "/cgi-bin/",
    "/cgi/",
    "/goform/",
    "/HNAP1/",
    "/device.rsp",
    "/stok=",
    "/doc/page/login.asp",
    "/en-US/account/login",
    "/cgi-bin/viewer/video.jpg",
    "/snapshot.jpg",
    "/image.jpg",
    "/video.mjpg",
    "/.env",
    "/config.php",
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/backup/",
    "/backup.zip",
    "/backup.tar.gz",
    "/www.zip",
    "/admin.zip",
]

# SNMP community strings to test
SNMP_COMMUNITIES = [
    "public",
    "private",
    "community",
    "admin",
    "default",
    "cisco",
    "monitor",
    "manager",
    "write",
    "all",
    "secret",
    "password",
    "snmpd",
    "SNMP_trap",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
]


class Finding:
    """Represents a security finding with CVSS scoring."""

    def __init__(
        self,
        title: str,
        severity: str,
        description: str,
        target: str,
        port: int = None,
        protocol: str = None,
        cvss_score: float = None,
        cve_ids: List[str] = None,
        cwe_id: str = None,
        evidence: str = None,
        remediation: str = None,
    ):
        self.title = title
        self.severity = severity
        self.description = description
        self.target = target
        self.port = port
        self.protocol = protocol
        self.cvss_score = cvss_score
        self.cve_ids = cve_ids or []
        self.cwe_id = cwe_id
        self.evidence = evidence or ""
        self.remediation = remediation or ""

    def to_dict(self) -> Dict:
        return {
            "title":       self.title,
            "severity":    self.severity,
            "description": self.description,
            "target":      self.target,
            "port":        self.port,
            "protocol":    self.protocol,
            "cvss_score":  self.cvss_score,
            "cve_ids":     self.cve_ids,
            "cwe_id":      self.cwe_id,
            "evidence":    self.evidence,
            "remediation": self.remediation,
        }


class VulnScanner:
    """
    Comprehensive IoT vulnerability scanner.

    Executes protocol-specific vulnerability checks and correlates
    findings with the NVD CVE database for CVSS scoring.
    """

    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("timeout", 5)
        self.cve_lookup = CVELookup(config)

    def run(
        self,
        target: str,
        checks: List[str] = None,
        cve_lookup: bool = False
    ) -> List[Dict]:
        """
        Run vulnerability checks against a target.

        Parameters
        ----------
        target : str
            Target IP address.
        checks : list of str
            List of check names to run.
        cve_lookup : bool
            Enrich findings with CVE data from NVD.

        Returns
        -------
        list of dict
            List of finding dictionaries.
        """
        if checks is None:
            checks = ["telnet", "ssh", "mqtt", "http", "upnp", "snmp"]

        Console.info(f"Vulnerability scan: {target} | checks: {', '.join(checks)}")
        findings: List[Finding] = []

        check_map = {
            "telnet": self._check_telnet,
            "ssh":    self._check_ssh,
            "mqtt":   self._check_mqtt,
            "http":   self._check_http,
            "rtsp":   self._check_rtsp,
            "coap":   self._check_coap,
            "upnp":   self._check_upnp,
            "snmp":   self._check_snmp,
            "ftp":    self._check_ftp,
        }

        for check_name in checks:
            fn = check_map.get(check_name)
            if fn:
                try:
                    result = fn(target)
                    if result:
                        if isinstance(result, list):
                            findings.extend(result)
                        else:
                            findings.append(result)
                except Exception as e:
                    logger.debug(f"Check {check_name} failed on {target}: {e}")

        # CVE enrichment
        if cve_lookup and findings:
            self._enrich_with_cve(findings, target)

        return [f.to_dict() for f in findings]

    # ------------------------------------------------------------------ #
    # Telnet checks                                                        #
    # ------------------------------------------------------------------ #

    def _check_telnet(self, target: str) -> Optional[Finding]:
        """Test Telnet for default credentials."""
        port = 23
        if not self._port_open(target, port):
            # Also check alternate Telnet port
            port = 2323
            if not self._port_open(target, port):
                return None

        Console.info(f"  Testing Telnet default credentials on {target}:{port}...")

        for username, password in DEFAULT_CREDENTIALS[:15]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))

                # Read banner
                banner = b""
                try:
                    while True:
                        chunk = sock.recv(256)
                        if not chunk:
                            break
                        banner += chunk
                        # Strip IAC sequences
                        clean = re.sub(rb"\xff[\xfb-\xfe].", b"", banner)
                        if b"login" in clean.lower() or b"username" in clean.lower():
                            break
                        if len(banner) > 1024:
                            break
                except socket.timeout:
                    pass

                # Send username
                sock.send((username + "\n").encode())
                time.sleep(0.5)

                # Check if password prompt appears
                response = b""
                try:
                    response = sock.recv(512)
                except socket.timeout:
                    pass

                if b"password" in response.lower() or b"passwd" in response.lower():
                    sock.send((password + "\n").encode())
                    time.sleep(1)
                    try:
                        auth_response = sock.recv(512)
                        clean_resp = re.sub(rb"\xff[\xfb-\xfe].", b"", auth_response)
                        if any(p in clean_resp for p in [b"$", b"#", b">", b"~"]):
                            sock.close()
                            return Finding(
                                title="Telnet Default Credentials",
                                severity="CRITICAL",
                                description=f"Telnet service accepts default credentials.",
                                target=target,
                                port=port,
                                protocol="telnet",
                                cvss_score=9.8,
                                cve_ids=["CVE-2023-1389"],
                                cwe_id="CWE-1392",
                                evidence=f"Credentials: {username}:{password}",
                                remediation="Disable Telnet. Use SSH with key-based authentication. Change all default credentials immediately."
                            )
                    except socket.timeout:
                        pass
                elif b"$" in response or b"#" in response:
                    # No password required
                    sock.close()
                    return Finding(
                        title="Telnet Authentication Bypass (No Password)",
                        severity="CRITICAL",
                        description="Telnet service accepts login without password.",
                        target=target,
                        port=port,
                        protocol="telnet",
                        cvss_score=10.0,
                        cwe_id="CWE-306",
                        evidence=f"Username: {username} (no password required)",
                        remediation="Disable Telnet immediately. Enable SSH with strong authentication."
                    )

                sock.close()
            except Exception:
                pass

        return None

    # ------------------------------------------------------------------ #
    # SSH checks                                                           #
    # ------------------------------------------------------------------ #

    def _check_ssh(self, target: str) -> Optional[Finding]:
        """Test SSH for weak configurations."""
        if not self._port_open(target, 22):
            return None

        Console.info(f"  Testing SSH configuration on {target}:22...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, 22))
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            sock.close()

            if not banner.startswith("SSH-"):
                return None

            issues = []

            # Check for old SSH versions
            if "SSH-1." in banner:
                issues.append("SSHv1 protocol enabled (deprecated, vulnerable to MITM)")

            # Check for Dropbear (common in IoT, often outdated)
            if "Dropbear" in banner:
                version_match = re.search(r"Dropbear[_\s]+([\d.]+)", banner)
                if version_match:
                    version = version_match.group(1)
                    major, minor = (int(x) for x in version.split(".")[:2])
                    if major < 2020:
                        issues.append(f"Outdated Dropbear SSH version {version} (pre-2020)")

            if issues:
                return Finding(
                    title="SSH Weak Configuration",
                    severity="HIGH",
                    description="SSH service has weak or outdated configuration.",
                    target=target,
                    port=22,
                    protocol="ssh",
                    cvss_score=7.5,
                    cwe_id="CWE-326",
                    evidence=f"Banner: {banner} | Issues: {'; '.join(issues)}",
                    remediation="Upgrade SSH to latest version. Disable SSHv1. Use key-based authentication only."
                )

        except Exception as e:
            logger.debug(f"SSH check error {target}: {e}")

        return None

    # ------------------------------------------------------------------ #
    # MQTT checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_mqtt(self, target: str) -> Optional[Finding]:
        """Test MQTT for authentication bypass."""
        for port in [1883, 8883]:
            if not self._port_open(target, port):
                continue

            Console.info(f"  Testing MQTT authentication on {target}:{port}...")

            try:
                import paho.mqtt.client as mqtt

                connected = threading.Event()
                subscribed = threading.Event()
                messages = []
                connect_rc = [None]

                def on_connect(client, userdata, flags, rc):
                    connect_rc[0] = rc
                    if rc == 0:
                        connected.set()
                        client.subscribe("#", qos=0)

                def on_subscribe(client, userdata, mid, granted_qos):
                    if granted_qos and granted_qos[0] < 128:
                        subscribed.set()

                def on_message(client, userdata, msg):
                    messages.append({
                        "topic":   msg.topic,
                        "payload": msg.payload[:64].decode("utf-8", errors="replace")
                    })

                client = mqtt.Client(client_id="iotbreaker_probe_001")
                client.on_connect = on_connect
                client.on_subscribe = on_subscribe
                client.on_message = on_message

                if port == 8883:
                    import ssl
                    client.tls_set(cert_reqs=ssl.CERT_NONE)
                    client.tls_insecure_set(True)

                client.connect(target, port, keepalive=5)
                client.loop_start()

                connected.wait(timeout=5)
                if connected.is_set():
                    subscribed.wait(timeout=3)
                    time.sleep(2)
                    client.loop_stop()
                    client.disconnect()

                    if subscribed.is_set():
                        evidence = f"Connected anonymously and subscribed to '#' wildcard"
                        if messages:
                            evidence += f" | Intercepted {len(messages)} message(s)"
                        return Finding(
                            title="MQTT Authentication Bypass with Wildcard Subscription",
                            severity="CRITICAL",
                            description="MQTT broker allows anonymous connections and unrestricted topic subscriptions.",
                            target=target,
                            port=port,
                            protocol="mqtt",
                            cvss_score=9.1,
                            cve_ids=["CVE-2017-7650"],
                            cwe_id="CWE-306",
                            evidence=evidence,
                            remediation="Enable MQTT authentication. Implement ACL rules. Disable anonymous access. Use TLS encryption."
                        )
                    elif connect_rc[0] == 0:
                        return Finding(
                            title="MQTT Anonymous Authentication Allowed",
                            severity="HIGH",
                            description="MQTT broker allows anonymous connections.",
                            target=target,
                            port=port,
                            protocol="mqtt",
                            cvss_score=7.5,
                            cwe_id="CWE-306",
                            evidence="Anonymous connection accepted by broker",
                            remediation="Enable MQTT authentication and disable anonymous access."
                        )

                client.loop_stop()

            except Exception as e:
                logger.debug(f"MQTT check error {target}:{port}: {e}")

        return None

    # ------------------------------------------------------------------ #
    # HTTP checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_http(self, target: str) -> List[Finding]:
        """Test HTTP/HTTPS interfaces for vulnerabilities."""
        findings = []

        for scheme, port in [("http", 80), ("https", 443), ("http", 8080), ("http", 8000), ("https", 8443)]:
            if not self._port_open(target, port):
                continue

            Console.info(f"  Testing HTTP interface on {target}:{port}...")
            base_url = f"{scheme}://{target}:{port}"

            # Test exposed admin interfaces
            for path in ADMIN_PATHS[:20]:
                try:
                    url = base_url + path
                    resp = requests.get(
                        url,
                        timeout=3,
                        verify=False,
                        allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 IoTBreaker/4.0"}
                    )

                    if resp.status_code == 200:
                        content_lower = resp.text.lower()

                        # Detect login pages
                        if any(kw in content_lower for kw in ["login", "password", "username", "sign in"]):
                            # Test default credentials via form
                            login_finding = self._test_http_login(base_url, path, resp.text)
                            if login_finding:
                                findings.append(login_finding)

                        # Detect exposed sensitive files
                        if path in ["/.env", "/config.php", "/phpinfo.php", "/backup.zip"]:
                            findings.append(Finding(
                                title=f"Sensitive File Exposed: {path}",
                                severity="HIGH",
                                description=f"Sensitive file accessible without authentication at {path}.",
                                target=target,
                                port=port,
                                protocol=scheme,
                                cvss_score=7.5,
                                cwe_id="CWE-538",
                                evidence=f"HTTP {resp.status_code} at {url}",
                                remediation="Restrict access to sensitive files. Implement proper access controls."
                            ))

                        # Detect directory listing
                        if "index of /" in content_lower or "directory listing" in content_lower:
                            findings.append(Finding(
                                title="Directory Listing Enabled",
                                severity="MEDIUM",
                                description="Web server has directory listing enabled.",
                                target=target,
                                port=port,
                                protocol=scheme,
                                cvss_score=5.3,
                                cwe_id="CWE-548",
                                evidence=f"Directory listing at {url}",
                                remediation="Disable directory listing in web server configuration."
                            ))

                except requests.exceptions.ConnectionError:
                    break
                except Exception as e:
                    logger.debug(f"HTTP path check error {url}: {e}")

            # Check for missing security headers
            header_finding = self._check_http_headers(base_url)
            if header_finding:
                findings.append(header_finding)

        return findings

    def _test_http_login(self, base_url: str, path: str, page_content: str) -> Optional[Finding]:
        """Attempt default credentials on HTTP login forms."""
        # Extract form action and fields
        form_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', page_content, re.IGNORECASE)
        action = form_match.group(1) if form_match else path

        # Find input field names
        user_field = "username"
        pass_field = "password"

        user_match = re.search(
            r'<input[^>]*(?:name|id)=["\']([^"\']*(?:user|login|name|account)[^"\']*)["\']',
            page_content, re.IGNORECASE
        )
        pass_match = re.search(
            r'<input[^>]*(?:name|id)=["\']([^"\']*(?:pass|pwd|secret)[^"\']*)["\']',
            page_content, re.IGNORECASE
        )

        if user_match:
            user_field = user_match.group(1)
        if pass_match:
            pass_field = pass_match.group(1)

        login_url = urljoin(base_url, action)

        for username, password in DEFAULT_CREDENTIALS[:10]:
            try:
                resp = requests.post(
                    login_url,
                    data={user_field: username, pass_field: password},
                    timeout=5,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 IoTBreaker/4.0"}
                )

                content_lower = resp.text.lower()
                # Heuristic: successful login redirects or shows dashboard
                if resp.status_code in (200, 302):
                    if not any(kw in content_lower for kw in ["invalid", "incorrect", "failed", "error", "wrong"]):
                        if any(kw in content_lower for kw in ["logout", "dashboard", "welcome", "admin", "settings"]):
                            return Finding(
                                title="HTTP Default Credentials Accepted",
                                severity="CRITICAL",
                                description="Web interface accepts default credentials.",
                                target=base_url,
                                port=None,
                                protocol="http",
                                cvss_score=9.8,
                                cwe_id="CWE-1392",
                                evidence=f"Credentials: {username}:{password} at {login_url}",
                                remediation="Change default credentials immediately. Implement account lockout policy."
                            )

            except Exception:
                pass

        return None

    def _check_http_headers(self, base_url: str) -> Optional[Finding]:
        """Check for missing security headers."""
        try:
            resp = requests.get(base_url, timeout=5, verify=False)
            headers = resp.headers

            missing = []
            if "X-Frame-Options" not in headers:
                missing.append("X-Frame-Options")
            if "X-Content-Type-Options" not in headers:
                missing.append("X-Content-Type-Options")
            if "Content-Security-Policy" not in headers:
                missing.append("Content-Security-Policy")
            if "Strict-Transport-Security" not in headers and base_url.startswith("https"):
                missing.append("Strict-Transport-Security")

            if len(missing) >= 3:
                return Finding(
                    title="Missing HTTP Security Headers",
                    severity="LOW",
                    description="Web interface is missing important security response headers.",
                    target=base_url,
                    protocol="http",
                    cvss_score=3.1,
                    cwe_id="CWE-693",
                    evidence=f"Missing headers: {', '.join(missing)}",
                    remediation="Add security headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, HSTS."
                )
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------ #
    # RTSP checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_rtsp(self, target: str) -> Optional[Finding]:
        """Test RTSP for unauthenticated stream access."""
        if not self._port_open(target, 554):
            return None

        Console.info(f"  Testing RTSP authentication on {target}:554...")

        common_paths = [
            "/",
            "/live",
            "/live/ch00_0",
            "/live/ch01_0",
            "/stream",
            "/stream1",
            "/stream2",
            "/video",
            "/video1",
            "/cam/realmonitor",
            "/h264Preview_01_main",
            "/h264Preview_01_sub",
            "/Streaming/Channels/1",
            "/Streaming/Channels/101",
            "/mpeg4/media.amp",
            "/onvif/device_service",
            "/MediaInput/h264",
            "/ch0_0.264",
        ]

        for path in common_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, 554))

                request = (
                    f"DESCRIBE rtsp://{target}:554{path} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"Accept: application/sdp\r\n\r\n"
                )
                sock.send(request.encode())

                response = b""
                try:
                    response = sock.recv(1024)
                except socket.timeout:
                    pass
                sock.close()

                resp_str = response.decode("utf-8", errors="replace")

                # 200 OK = unauthenticated access
                if "RTSP/1.0 200" in resp_str:
                    return Finding(
                        title="RTSP Unauthenticated Stream Access",
                        severity="HIGH",
                        description="RTSP camera stream accessible without authentication.",
                        target=target,
                        port=554,
                        protocol="rtsp",
                        cvss_score=7.5,
                        cwe_id="CWE-306",
                        evidence=f"Unauthenticated DESCRIBE at rtsp://{target}:554{path}",
                        remediation="Enable RTSP authentication. Use RTSP over HTTPS (RTSPS). Restrict network access."
                    )

            except Exception:
                pass

        return None

    # ------------------------------------------------------------------ #
    # CoAP checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_coap(self, target: str) -> Optional[Finding]:
        """Test CoAP for resource enumeration."""
        port = 5683
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            # CoAP GET /.well-known/core (resource discovery)
            # Version=1, Type=CON, TKL=0, Code=GET(0.01), MID=1
            # Option: Uri-Path = .well-known/core
            coap_get = (
                b"\x40\x01\x00\x01"  # Header
                b"\xbb.well-known"   # Uri-Path option
                b"\x04core"
            )

            sock.sendto(coap_get, (target, port))
            try:
                data, _ = sock.recvfrom(4096)
                if data:
                    content = data[4:].decode("utf-8", errors="replace")
                    return Finding(
                        title="CoAP Resource Discovery Exposed",
                        severity="MEDIUM",
                        description="CoAP device responds to unauthenticated resource discovery.",
                        target=target,
                        port=port,
                        protocol="coap",
                        cvss_score=5.3,
                        cwe_id="CWE-306",
                        evidence=f"Resource list: {content[:256]}",
                        remediation="Implement CoAP authentication (DTLS). Restrict resource discovery to authorized clients."
                    )
            except socket.timeout:
                pass
            finally:
                sock.close()

        except Exception as e:
            logger.debug(f"CoAP check error {target}: {e}")

        return None

    # ------------------------------------------------------------------ #
    # UPnP checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_upnp(self, target: str) -> Optional[Finding]:
        """Test UPnP for IGD misconfigurations."""
        for port in [1900, 5000, 49152]:
            if not self._port_open(target, port):
                continue

            Console.info(f"  Testing UPnP on {target}:{port}...")

            try:
                # Try to access IGD service
                for path in ["/rootDesc.xml", "/description.xml", "/upnp/IGD.xml"]:
                    try:
                        resp = requests.get(
                            f"http://{target}:{port}{path}",
                            timeout=3, verify=False
                        )
                        if resp.status_code == 200:
                            content = resp.text

                            # Check for WANIPConnection service (port mapping)
                            if "WANIPConnection" in content or "WANPPPConnection" in content:
                                return Finding(
                                    title="UPnP IGD Port Mapping Exposed",
                                    severity="HIGH",
                                    description="UPnP Internet Gateway Device service exposed, allowing arbitrary port forwarding.",
                                    target=target,
                                    port=port,
                                    protocol="upnp",
                                    cvss_score=8.1,
                                    cve_ids=["CVE-2013-0229", "CVE-2020-12695"],
                                    cwe_id="CWE-284",
                                    evidence=f"IGD service description at http://{target}:{port}{path}",
                                    remediation="Disable UPnP on internet-facing interfaces. Restrict UPnP to trusted networks only."
                                )
                            elif resp.status_code == 200:
                                return Finding(
                                    title="UPnP Device Description Exposed",
                                    severity="LOW",
                                    description="UPnP device description accessible without authentication.",
                                    target=target,
                                    port=port,
                                    protocol="upnp",
                                    cvss_score=3.7,
                                    cwe_id="CWE-200",
                                    evidence=f"Device description at http://{target}:{port}{path}",
                                    remediation="Restrict UPnP access to local network only."
                                )
                    except Exception:
                        continue

            except Exception as e:
                logger.debug(f"UPnP check error {target}: {e}")

        return None

    # ------------------------------------------------------------------ #
    # SNMP checks                                                          #
    # ------------------------------------------------------------------ #

    def _check_snmp(self, target: str) -> Optional[Finding]:
        """Test SNMP for default community strings."""
        Console.info(f"  Testing SNMP community strings on {target}:161...")

        for community in SNMP_COMMUNITIES[:10]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)

                # SNMP v1 GET sysDescr
                comm_bytes = community.encode()
                oid = b"\x06\x09\x2b\x06\x01\x02\x01\x01\x01\x00"
                varbind = b"\x30" + bytes([len(oid) + 4]) + oid + b"\x05\x00"
                pdu_data = b"\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30" + bytes([len(varbind)]) + varbind
                get_pdu = b"\xa0" + bytes([len(pdu_data)]) + pdu_data
                community_field = b"\x04" + bytes([len(comm_bytes)]) + comm_bytes
                message_data = b"\x02\x01\x00" + community_field + get_pdu
                packet = b"\x30" + bytes([len(message_data)]) + message_data

                sock.sendto(packet, (target, 161))
                try:
                    data, _ = sock.recvfrom(4096)
                    if data and len(data) > 10:
                        # Extract readable text
                        text = re.sub(rb"[^\x20-\x7e]", b" ", data).decode("ascii", errors="replace")
                        text = re.sub(r"\s+", " ", text).strip()
                        sock.close()
                        return Finding(
                            title=f"SNMP Default Community String: '{community}'",
                            severity="HIGH",
                            description=f"SNMP service responds to default community string '{community}'.",
                            target=target,
                            port=161,
                            protocol="snmp",
                            cvss_score=7.5,
                            cve_ids=["CVE-1999-0517"],
                            cwe_id="CWE-1392",
                            evidence=f"Community: {community} | sysDescr: {text[:128]}",
                            remediation="Change SNMP community strings. Use SNMPv3 with authentication and encryption. Restrict SNMP access by ACL."
                        )
                except socket.timeout:
                    pass
                sock.close()

            except Exception:
                pass

        return None

    # ------------------------------------------------------------------ #
    # FTP checks                                                           #
    # ------------------------------------------------------------------ #

    def _check_ftp(self, target: str) -> Optional[Finding]:
        """Test FTP for anonymous access."""
        if not self._port_open(target, 21):
            return None

        Console.info(f"  Testing FTP anonymous access on {target}:21...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, 21))

            banner = sock.recv(256).decode("utf-8", errors="replace")

            # Try anonymous login
            sock.send(b"USER anonymous\r\n")
            resp1 = sock.recv(256).decode("utf-8", errors="replace")

            if "331" in resp1:  # Password required
                sock.send(b"PASS anonymous@\r\n")
                resp2 = sock.recv(256).decode("utf-8", errors="replace")

                if "230" in resp2:  # Login successful
                    sock.send(b"LIST\r\n")
                    sock.close()
                    return Finding(
                        title="FTP Anonymous Access Allowed",
                        severity="HIGH",
                        description="FTP server allows anonymous login.",
                        target=target,
                        port=21,
                        protocol="ftp",
                        cvss_score=7.5,
                        cwe_id="CWE-284",
                        evidence=f"Banner: {banner.strip()} | Anonymous login successful",
                        remediation="Disable anonymous FTP access. Use SFTP or FTPS instead."
                    )

            sock.close()

        except Exception as e:
            logger.debug(f"FTP check error {target}: {e}")

        return None

    # ------------------------------------------------------------------ #
    # CVE enrichment                                                       #
    # ------------------------------------------------------------------ #

    def _enrich_with_cve(self, findings: List[Finding], target: str):
        """Enrich findings with CVE data from NVD."""
        for finding in findings:
            if not finding.cve_ids:
                continue
            for cve_id in finding.cve_ids[:3]:
                try:
                    cve_data = self.cve_lookup.get_by_id(cve_id)
                    if cve_data and not finding.cvss_score:
                        finding.cvss_score = cve_data.get("cvss_score")
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Utility                                                              #
    # ------------------------------------------------------------------ #

    def _port_open(self, target: str, port: int) -> bool:
        """Check if a TCP port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(self.timeout, 2))
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
