#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Device Fingerprinting Module

Identifies IoT device manufacturer, model, firmware version, and OS
using multiple techniques:
  - HTTP Server header analysis
  - SSH version string parsing
  - Telnet banner analysis
  - RTSP server identification
  - MAC OUI vendor lookup
  - TTL-based OS fingerprinting
  - UPnP device description parsing
  - SNMP system description
"""

import socket
import re
import struct
import requests
import xml.etree.ElementTree as ET
from typing import Dict, Optional, List, Tuple

from core.logger import get_logger
from core.output import Console
from core.config import Config

logger = get_logger(__name__)

# Disable SSL warnings for IoT devices with self-signed certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# TTL-based OS fingerprinting
TTL_OS_MAP = {
    range(0, 65):    "Network Device (TTL < 64)",
    range(64, 65):   "Linux / Android",
    range(65, 129):  "Linux / Unix",
    range(128, 129): "Windows",
    range(129, 256): "Windows / Cisco IOS",
    range(255, 256): "Cisco IOS / Solaris",
}

# Known IoT device HTTP signatures
HTTP_DEVICE_SIGNATURES = [
    (r"Hikvision",              "Hikvision",    "IP Camera / DVR"),
    (r"Dahua",                  "Dahua",        "IP Camera / DVR"),
    (r"Axis",                   "Axis",         "IP Camera"),
    (r"Foscam",                 "Foscam",       "IP Camera"),
    (r"Amcrest",                "Amcrest",      "IP Camera"),
    (r"Reolink",                "Reolink",      "IP Camera"),
    (r"TP-Link",                "TP-Link",      "Router / Switch"),
    (r"D-Link",                 "D-Link",       "Router / Switch"),
    (r"NETGEAR",                "NETGEAR",      "Router / Switch"),
    (r"ASUS",                   "ASUS",         "Router"),
    (r"Ubiquiti|UniFi|EdgeOS",  "Ubiquiti",     "Network Device"),
    (r"MikroTik|RouterOS",      "MikroTik",     "Router"),
    (r"Cisco",                  "Cisco",        "Network Device"),
    (r"Juniper",                "Juniper",      "Network Device"),
    (r"Philips Hue",            "Philips",      "Smart Lighting"),
    (r"Sonos",                  "Sonos",        "Smart Speaker"),
    (r"Nest",                   "Google",       "Smart Home Device"),
    (r"Ring",                   "Amazon",       "Smart Doorbell"),
    (r"Wyze",                   "Wyze",         "Smart Camera"),
    (r"Shelly",                 "Shelly",       "Smart Relay"),
    (r"Tasmota",                "Tasmota",      "Smart Plug / Relay"),
    (r"ESPHome",                "ESPHome",      "DIY IoT Device"),
    (r"Home Assistant",         "Home Assistant","Smart Home Hub"),
    (r"OpenWrt",                "OpenWrt",      "Router (OpenWrt)"),
    (r"DD-WRT",                 "DD-WRT",       "Router (DD-WRT)"),
    (r"Tomato",                 "Tomato",       "Router (Tomato)"),
    (r"GoAhead",                "GoAhead",      "Embedded Web Server"),
    (r"lighttpd",               "lighttpd",     "Embedded Web Server"),
    (r"mini_httpd",             "mini_httpd",   "Embedded Web Server"),
    (r"Boa",                    "Boa",          "Embedded Web Server"),
    (r"thttpd",                 "thttpd",       "Embedded Web Server"),
    (r"Allegro",                "Allegro",      "Embedded Web Server"),
    (r"Siemens",                "Siemens",      "Industrial Device"),
    (r"Schneider",              "Schneider",    "Industrial Device"),
    (r"Rockwell|Allen-Bradley", "Rockwell",     "Industrial PLC"),
    (r"Moxa",                   "Moxa",         "Industrial Gateway"),
    (r"Advantech",              "Advantech",    "Industrial Device"),
]

# OUI prefix to vendor mapping (partial, most common IoT vendors)
OUI_VENDORS = {
    "00:00:5E": "IANA",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    "00:1A:22": "Cisco",
    "00:1B:54": "Cisco",
    "FC:FB:FB": "Cisco",
    "A4:CF:12": "Espressif (ESP8266/ESP32)",
    "30:AE:A4": "Espressif (ESP8266/ESP32)",
    "24:6F:28": "Espressif (ESP8266/ESP32)",
    "AC:67:B2": "Espressif (ESP8266/ESP32)",
    "18:FE:34": "Espressif (ESP8266/ESP32)",
    "5C:CF:7F": "Espressif (ESP8266/ESP32)",
    "00:0F:13": "Dahua",
    "4C:11:BF": "Hikvision",
    "C0:56:E3": "Hikvision",
    "BC:AD:28": "Hikvision",
    "00:1E:C0": "Axis Communications",
    "AC:CC:8E": "Axis Communications",
    "00:40:8C": "Axis Communications",
    "F0:9F:C2": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "00:15:6D": "Ubiquiti",
    "DC:9F:DB": "TP-Link",
    "50:C7:BF": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "00:1D:0F": "D-Link",
    "1C:7E:E5": "D-Link",
    "28:10:7B": "NETGEAR",
    "A0:04:60": "NETGEAR",
    "00:26:F2": "NETGEAR",
    "00:50:F2": "Microsoft",
    "00:0D:3A": "Microsoft",
    "00:1C:42": "Parallels",
    "08:00:27": "Oracle VirtualBox",
}


class FingerprintModule:
    """
    Multi-technique IoT device fingerprinting engine.

    Identifies device manufacturer, model, firmware version,
    and operating system using passive and active techniques.
    """

    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("timeout", 5)
        self.verify_ssl = config.get("verify_ssl", False)

    def run(
        self,
        target: str,
        deep: bool = False,
        mac: str = None
    ) -> Optional[Dict]:
        """
        Fingerprint a target device.

        Parameters
        ----------
        target : str
            Target IP address.
        deep : bool
            Enable deep fingerprinting (more probes, slower).
        mac : str, optional
            MAC address for OUI lookup.

        Returns
        -------
        dict or None
            Device fingerprint data.
        """
        result = {
            "ip": target,
            "mac": mac or "N/A",
            "oui_vendor": "N/A",
            "hostname": "N/A",
            "device_type": "Unknown",
            "manufacturer": "N/A",
            "model": "N/A",
            "firmware_version": "N/A",
            "os": "N/A",
            "open_ports": [],
            "services": [],
            "ttl": None,
            "http_server": "N/A",
            "upnp_info": {},
        }

        # Hostname resolution
        result["hostname"] = self._resolve_hostname(target)

        # MAC OUI lookup
        if mac:
            result["oui_vendor"] = self._oui_lookup(mac)

        # TTL-based OS detection
        ttl = self._get_ttl(target)
        if ttl:
            result["ttl"] = ttl
            result["os"] = self._ttl_to_os(ttl)

        # HTTP fingerprinting
        http_info = self._http_fingerprint(target)
        if http_info:
            result.update(http_info)

        # SSH banner analysis
        ssh_info = self._ssh_fingerprint(target)
        if ssh_info:
            result.update(ssh_info)

        # Telnet banner analysis
        telnet_info = self._telnet_fingerprint(target)
        if telnet_info:
            result.update(telnet_info)

        # UPnP device description
        upnp_info = self._upnp_fingerprint(target)
        if upnp_info:
            result["upnp_info"] = upnp_info
            if upnp_info.get("manufacturer") and result["manufacturer"] == "N/A":
                result["manufacturer"] = upnp_info["manufacturer"]
            if upnp_info.get("model") and result["model"] == "N/A":
                result["model"] = upnp_info["model"]
            if upnp_info.get("device_type") and result["device_type"] == "Unknown":
                result["device_type"] = upnp_info["device_type"]

        if deep:
            # RTSP fingerprinting
            rtsp_info = self._rtsp_fingerprint(target)
            if rtsp_info:
                result.update(rtsp_info)

            # SNMP fingerprinting
            snmp_info = self._snmp_fingerprint(target)
            if snmp_info:
                result.update(snmp_info)

        return result

    # ------------------------------------------------------------------ #
    # Fingerprinting techniques                                            #
    # ------------------------------------------------------------------ #

    def _http_fingerprint(self, target: str) -> Optional[Dict]:
        """Fingerprint via HTTP/HTTPS headers and page content."""
        for scheme, port in [("http", 80), ("https", 443), ("http", 8080), ("http", 8000)]:
            try:
                url = f"{scheme}://{target}:{port}/"
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                    headers={"User-Agent": self.config.get("user_agent", "IoTBreaker/4.0")}
                )

                server_header = resp.headers.get("Server", "")
                content = resp.text[:4096]
                combined = server_header + " " + content

                info = {
                    "http_server": server_header,
                    "http_port": port,
                    "http_scheme": scheme,
                }

                # Match against known signatures
                for pattern, manufacturer, device_type in HTTP_DEVICE_SIGNATURES:
                    if re.search(pattern, combined, re.IGNORECASE):
                        info["manufacturer"] = manufacturer
                        info["device_type"] = device_type
                        break

                # Extract firmware/version from page
                fw_match = re.search(
                    r"(?:firmware|version|fw)[:\s]+v?([\d.]+[\w.-]*)",
                    combined, re.IGNORECASE
                )
                if fw_match:
                    info["firmware_version"] = fw_match.group(1)

                # Extract model
                model_match = re.search(
                    r"(?:model|product)[:\s]+([A-Z0-9][\w\s-]{2,30})",
                    combined, re.IGNORECASE
                )
                if model_match:
                    info["model"] = model_match.group(1).strip()

                return info

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception as e:
                logger.debug(f"HTTP fingerprint error {target}: {e}")
                continue

        return None

    def _ssh_fingerprint(self, target: str) -> Optional[Dict]:
        """Fingerprint via SSH banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((target, 22)) != 0:
                return None

            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            sock.close()

            if not banner.startswith("SSH-"):
                return None

            info = {"ssh_banner": banner}

            # SSH-2.0-OpenSSH_7.4 Raspbian-1+deb9u7
            match = re.match(r"SSH-([\d.]+)-(\S+)\s*(.*)", banner)
            if match:
                info["ssh_version"] = match.group(1)
                info["ssh_software"] = match.group(2)
                comment = match.group(3)

                if "Dropbear" in banner:
                    info["os"] = "Embedded Linux (Dropbear SSH)"
                    info["device_type"] = "Embedded Linux Device"
                elif "OpenSSH" in banner:
                    if "Raspbian" in comment or "Ubuntu" in comment or "Debian" in comment:
                        info["os"] = comment.strip()
                    elif "RouterOS" in comment:
                        info["manufacturer"] = "MikroTik"
                        info["device_type"] = "Router"
                        info["os"] = "RouterOS"

            return info

        except Exception as e:
            logger.debug(f"SSH fingerprint error {target}: {e}")
            return None

    def _telnet_fingerprint(self, target: str) -> Optional[Dict]:
        """Fingerprint via Telnet banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((target, 23)) != 0:
                return None

            # Read initial banner (skip Telnet option negotiation)
            data = b""
            try:
                while True:
                    chunk = sock.recv(256)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 512:
                        break
            except socket.timeout:
                pass
            sock.close()

            # Strip Telnet IAC sequences
            banner = re.sub(rb"\xff[\xfb-\xfe].", b"", data)
            banner_str = banner.decode("utf-8", errors="replace").strip()

            if not banner_str:
                return None

            info = {"telnet_banner": banner_str[:256]}

            # Device identification from banner
            for pattern, manufacturer, device_type in HTTP_DEVICE_SIGNATURES:
                if re.search(pattern, banner_str, re.IGNORECASE):
                    info["manufacturer"] = manufacturer
                    info["device_type"] = device_type
                    break

            if "BusyBox" in banner_str:
                info["os"] = "BusyBox / Embedded Linux"
                info["device_type"] = "Embedded Linux Device"
            elif "Linux" in banner_str:
                info["os"] = "Linux"

            return info

        except Exception as e:
            logger.debug(f"Telnet fingerprint error {target}: {e}")
            return None

    def _upnp_fingerprint(self, target: str) -> Optional[Dict]:
        """Retrieve UPnP device description XML."""
        for port in [1900, 5000, 49152, 49153]:
            try:
                # Try to fetch device description
                for path in ["/rootDesc.xml", "/description.xml", "/device.xml", "/upnp/desc.xml"]:
                    try:
                        url = f"http://{target}:{port}{path}"
                        resp = requests.get(url, timeout=3, verify=False)
                        if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", "").lower():
                            return self._parse_upnp_xml(resp.text)
                    except Exception:
                        continue
            except Exception:
                continue
        return None

    def _parse_upnp_xml(self, xml_content: str) -> Dict:
        """Parse UPnP device description XML."""
        info = {}
        try:
            root = ET.fromstring(xml_content)
            ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}

            def find_text(tag):
                el = root.find(f".//{tag}")
                if el is None:
                    el = root.find(f".//upnp:{tag}", ns)
                return el.text.strip() if el is not None and el.text else None

            info["manufacturer"] = find_text("manufacturer") or "N/A"
            info["model"] = find_text("modelName") or find_text("modelNumber") or "N/A"
            info["device_type"] = find_text("deviceType") or "N/A"
            info["friendly_name"] = find_text("friendlyName") or "N/A"
            info["firmware_version"] = find_text("modelNumber") or find_text("softwareVersion") or "N/A"
            info["serial"] = find_text("serialNumber") or "N/A"
        except Exception as e:
            logger.debug(f"UPnP XML parse error: {e}")
        return info

    def _rtsp_fingerprint(self, target: str) -> Optional[Dict]:
        """Fingerprint via RTSP OPTIONS response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((target, 554)) != 0:
                return None

            request = f"OPTIONS rtsp://{target}:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            sock.send(request.encode())

            response = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
            except socket.timeout:
                pass
            sock.close()

            resp_str = response.decode("utf-8", errors="replace")
            info = {"rtsp_response": resp_str[:256]}

            server_match = re.search(r"Server:\s*(.+?)[\r\n]", resp_str, re.IGNORECASE)
            if server_match:
                server = server_match.group(1).strip()
                info["rtsp_server"] = server
                info["device_type"] = "IP Camera / Streaming Device"

                for pattern, manufacturer, _ in HTTP_DEVICE_SIGNATURES:
                    if re.search(pattern, server, re.IGNORECASE):
                        info["manufacturer"] = manufacturer
                        break

            return info

        except Exception as e:
            logger.debug(f"RTSP fingerprint error {target}: {e}")
            return None

    def _snmp_fingerprint(self, target: str) -> Optional[Dict]:
        """Fingerprint via SNMP sysDescr (community: public)."""
        try:
            # SNMP v1 GET request for sysDescr (OID 1.3.6.1.2.1.1.1.0)
            # Minimal SNMP v1 PDU
            oid = b"\x06\x09\x2b\x06\x01\x02\x01\x01\x01\x00"
            community = b"public"
            pdu = (
                b"\x30" + bytes([len(community) + len(oid) + 20]) +
                b"\x02\x01\x00" +  # version: 0 (SNMPv1)
                b"\x04" + bytes([len(community)]) + community +
                b"\xa0" + bytes([len(oid) + 10]) +
                b"\x02\x01\x01" +  # request-id
                b"\x02\x01\x00" +  # error-status
                b"\x02\x01\x00" +  # error-index
                b"\x30" + bytes([len(oid) + 4]) +
                b"\x30" + bytes([len(oid) + 2]) +
                oid + b"\x05\x00"  # NULL value
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(pdu, (target, 161))

            try:
                data, _ = sock.recvfrom(4096)
                # Extract printable string from response
                text = re.sub(rb"[^\x20-\x7e]", b" ", data).decode("ascii", errors="replace")
                text = re.sub(r"\s+", " ", text).strip()
                if len(text) > 10:
                    return {"snmp_sysdescr": text[:256], "snmp_community": "public"}
            except socket.timeout:
                pass
            finally:
                sock.close()

        except Exception as e:
            logger.debug(f"SNMP fingerprint error {target}: {e}")

        return None

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _get_ttl(self, target: str) -> Optional[int]:
        """Get TTL via ICMP ping (Linux only)."""
        try:
            import subprocess
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", target],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r"ttl=(\d+)", result.stdout, re.IGNORECASE)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def _ttl_to_os(self, ttl: int) -> str:
        """Estimate OS from TTL value."""
        if ttl <= 64:
            return "Linux / Android / Embedded"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco IOS / Solaris / HP-UX"
        return "Unknown"

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"

    def _oui_lookup(self, mac: str) -> str:
        """Look up vendor from MAC OUI prefix."""
        if not mac or mac == "N/A":
            return "N/A"
        prefix = mac.upper()[:8]
        return OUI_VENDORS.get(prefix, "Unknown Vendor")
