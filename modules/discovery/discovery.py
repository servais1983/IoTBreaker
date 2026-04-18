#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Network Discovery Module

Multi-method IoT device discovery:
  - ARP sweep (Layer 2, requires root on Linux)
  - TCP probing (Layer 4, works without root)
  - UPnP/SSDP multicast discovery
  - mDNS/DNS-SD service discovery
  - ICMP ping sweep
"""

import socket
import struct
import time
import threading
import queue
import subprocess
import ipaddress
import re
import json
from typing import List, Dict, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import get_logger
from core.output import Console
from core.config import Config, IOT_COMMON_PORTS

logger = get_logger(__name__)


# Known IoT device signatures based on open ports
DEVICE_SIGNATURES = {
    frozenset([554, 80]):           "IP Camera",
    frozenset([554, 443]):          "IP Camera (HTTPS)",
    frozenset([37777, 37778]):      "Dahua DVR/NVR",
    frozenset([8000, 8080]):        "Hikvision DVR/NVR",
    frozenset([1883]):              "MQTT Broker",
    frozenset([5683]):              "CoAP Device",
    frozenset([102]):               "Siemens PLC (S7)",
    frozenset([502]):               "Modbus Device",
    frozenset([4840]):              "OPC-UA Server",
    frozenset([47808]):             "BACnet Device",
    frozenset([20000]):             "DNP3 Device",
    frozenset([9100]):              "Network Printer",
    frozenset([5353]):              "mDNS Device",
    frozenset([7547]):              "TR-069 CPE",
    frozenset([23]):                "Telnet Device",
    frozenset([22]):                "SSH Device",
}

# Quick probe ports for host discovery
PROBE_PORTS = [80, 443, 22, 23, 8080, 554, 1883, 7547, 8443, 8000]


class DiscoveryModule:
    """
    Multi-method IoT network discovery engine.

    Combines ARP, TCP probing, UPnP, and mDNS to provide
    comprehensive device enumeration on local networks.
    """

    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("timeout", 3)
        self.threads = config.get("threads", 100)

    def run(
        self,
        network: str,
        method: str = "all",
        exclude: List[str] = None
    ) -> List[Dict]:
        """
        Discover IoT devices on the specified network.

        Parameters
        ----------
        network : str
            CIDR notation network (e.g. 192.168.1.0/24).
        method : str
            Discovery method: arp, tcp, upnp, mdns, or all.
        exclude : list of str
            IP addresses to skip.

        Returns
        -------
        list of dict
            List of discovered device dictionaries.
        """
        exclude = exclude or []
        Console.info(f"Starting network discovery on {network} (method: {method})")

        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            Console.error(f"Invalid network specification: {e}")
            return []

        all_ips: Set[str] = set()

        if method in ("tcp", "all"):
            Console.info("TCP probe sweep...")
            tcp_ips = self._tcp_sweep(net, exclude)
            all_ips.update(tcp_ips)
            Console.success(f"TCP sweep: {len(tcp_ips)} host(s) responding")

        if method in ("arp", "all"):
            Console.info("ARP sweep...")
            arp_ips = self._arp_sweep(str(network))
            all_ips.update(arp_ips)
            if arp_ips:
                Console.success(f"ARP sweep: {len(arp_ips)} host(s) found")

        if method in ("upnp", "all"):
            Console.info("UPnP/SSDP discovery...")
            upnp_ips = self._upnp_discovery()
            all_ips.update(upnp_ips)
            if upnp_ips:
                Console.success(f"UPnP: {len(upnp_ips)} device(s) found")

        if method in ("mdns", "all"):
            Console.info("mDNS/DNS-SD discovery...")
            mdns_ips = self._mdns_discovery()
            all_ips.update(mdns_ips)
            if mdns_ips:
                Console.success(f"mDNS: {len(mdns_ips)} device(s) found")

        # Filter excluded IPs
        all_ips -= set(exclude)

        if not all_ips:
            return []

        # Enrich each discovered IP
        Console.info(f"Enriching {len(all_ips)} discovered host(s)...")
        devices = []
        with ThreadPoolExecutor(max_workers=min(self.threads, len(all_ips))) as ex:
            futures = {ex.submit(self._enrich_host, ip): ip for ip in sorted(all_ips)}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    devices.append(result)

        devices.sort(key=lambda d: socket.inet_aton(d["ip"]))
        return devices

    # ------------------------------------------------------------------ #
    # Discovery methods                                                    #
    # ------------------------------------------------------------------ #

    def _tcp_sweep(self, network: ipaddress.IPv4Network, exclude: List[str]) -> Set[str]:
        """Fast TCP probe sweep using thread pool."""
        active = set()
        lock = threading.Lock()

        def probe(ip_str: str):
            if ip_str in exclude:
                return
            for port in PROBE_PORTS:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout / len(PROBE_PORTS))
                    if sock.connect_ex((ip_str, port)) == 0:
                        with lock:
                            active.add(ip_str)
                        sock.close()
                        return
                    sock.close()
                except Exception:
                    pass

        hosts = [str(h) for h in network.hosts()]
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(probe, hosts)

        return active

    def _arp_sweep(self, network: str) -> Set[str]:
        """ARP sweep using system arp-scan or arping."""
        active = set()
        try:
            result = subprocess.run(
                ["arp-scan", "--localnet", "--quiet"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if parts and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
                        active.add(parts[0])
                return active
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: parse /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "00:00:00:00:00:00":
                        active.add(parts[0])
        except Exception:
            pass

        return active

    def _upnp_discovery(self, timeout: float = 5.0) -> Set[str]:
        """UPnP/SSDP multicast discovery."""
        devices = set()
        SSDP_ADDR = "239.255.255.250"
        SSDP_PORT = 1900
        MSEARCH = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "ST: ssdp:all\r\n"
            "MX: 3\r\n\r\n"
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(timeout)
            sock.sendto(MSEARCH.encode(), (SSDP_ADDR, SSDP_PORT))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    devices.add(addr[0])
                except socket.timeout:
                    break
        except Exception as e:
            logger.debug(f"UPnP discovery error: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return devices

    def _mdns_discovery(self, timeout: float = 5.0) -> Set[str]:
        """mDNS/DNS-SD service discovery."""
        devices = set()
        MDNS_ADDR = "224.0.0.251"
        MDNS_PORT = 5353

        # DNS query for _services._dns-sd._udp.local (PTR record)
        query = (
            b"\x00\x00"  # Transaction ID
            b"\x00\x00"  # Flags: standard query
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answer RRs: 0
            b"\x00\x00"  # Authority RRs: 0
            b"\x00\x00"  # Additional RRs: 0
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
            b"\x00\x0c"  # Type: PTR
            b"\x00\x01"  # Class: IN
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.settimeout(timeout)
            sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    devices.add(addr[0])
                except socket.timeout:
                    break
        except Exception as e:
            logger.debug(f"mDNS discovery error: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return devices

    # ------------------------------------------------------------------ #
    # Host enrichment                                                      #
    # ------------------------------------------------------------------ #

    def _enrich_host(self, ip: str) -> Optional[Dict]:
        """Gather basic information about a discovered host."""
        device = {
            "ip": ip,
            "mac": self._get_mac(ip),
            "hostname": self._resolve_hostname(ip),
            "open_ports": [],
            "device_type": "Unknown",
            "ttl": None,
        }

        # Quick port scan for classification
        open_ports = set()
        for port in IOT_COMMON_PORTS[:20]:  # Quick scan of top IoT ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.add(port)
                sock.close()
            except Exception:
                pass

        device["open_ports"] = sorted(open_ports)
        device["device_type"] = self._classify_device(open_ports)

        return device

    def _get_mac(self, ip: str) -> str:
        """Retrieve MAC address from ARP cache."""
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac.upper()
        except Exception:
            pass
        return "N/A"

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "N/A"

    def _classify_device(self, open_ports: Set[int]) -> str:
        """Classify device type based on open port signature."""
        for sig_ports, device_type in DEVICE_SIGNATURES.items():
            if sig_ports.issubset(open_ports):
                return device_type

        # Single-port heuristics
        if 554 in open_ports:
            return "IP Camera / Streaming Device"
        if 1883 in open_ports or 8883 in open_ports:
            return "MQTT Broker / IoT Hub"
        if 502 in open_ports:
            return "Modbus Industrial Device"
        if 102 in open_ports:
            return "Siemens PLC"
        if 47808 in open_ports:
            return "BACnet Building Automation"
        if 9100 in open_ports:
            return "Network Printer"
        if 7547 in open_ports:
            return "CPE / Home Router (TR-069)"
        if 5683 in open_ports:
            return "CoAP IoT Device"
        if 23 in open_ports:
            return "Telnet-Enabled Device"
        if 80 in open_ports or 8080 in open_ports:
            return "Web-Enabled Device"

        return "Unknown IoT Device"
