#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Configuration Manager

Handles all runtime configuration, environment variables, and
persistent settings for the framework.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Any, Dict, Optional


# Default IoT-specific port list
IOT_COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    81,    # HTTP alternate
    443,   # HTTPS
    554,   # RTSP (IP cameras)
    1883,  # MQTT
    1900,  # UPnP/SSDP
    2323,  # Telnet alternate
    4433,  # HTTPS alternate
    5000,  # UPnP / various
    5683,  # CoAP
    7547,  # TR-069 (CWMP)
    8080,  # HTTP alternate
    8081,  # HTTP alternate
    8443,  # HTTPS alternate
    8883,  # MQTT over TLS
    9000,  # Various web interfaces
    9090,  # Various web interfaces
    9100,  # JetDirect (printers)
    10000, # Webmin
    37777, # Dahua DVR
    49152, # UPnP IGD
    49153, # UPnP IGD
    49154, # UPnP IGD
    50000, # Various
    51413, # BitTorrent (some IoT)
    55443, # Various
    161,   # SNMP
    162,   # SNMP Trap
    69,    # TFTP
    102,   # Siemens S7
    502,   # Modbus
    4840,  # OPC-UA
    20000, # DNP3
    44818, # EtherNet/IP
    47808, # BACnet
]

DEFAULTS: Dict[str, Any] = {
    "timeout": 5,
    "threads": 100,
    "output_dir": "./reports",
    "report_format": "all",
    "verbose": 0,
    "rate_limit": 500,
    "retry_count": 2,
    "user_agent": "IoTBreaker/4.0.0 Security Scanner",
    "shodan_api_key": "",
    "nvd_api_key": "",
    "iot_ports": IOT_COMMON_PORTS,
    "wordlist_users": "wordlists/users.txt",
    "wordlist_passwords": "wordlists/passwords.txt",
    "wordlist_web_paths": "wordlists/web_paths.txt",
    "safe_mode": True,
    "verify_ssl": False,
    "follow_redirects": True,
    "max_redirects": 5,
    "banner_grab_timeout": 3,
    "brute_delay": 0.0,
    "stop_on_success": True,
}


class Config:
    """
    Central configuration manager for IoTBreaker.

    Merges defaults, configuration file values, and environment
    variable overrides into a single unified configuration object.
    """

    def __init__(self):
        self._data: Dict[str, Any] = dict(DEFAULTS)
        self._load_env()

    def _load_env(self):
        """Load configuration from environment variables."""
        env_map = {
            "SHODAN_API_KEY":  "shodan_api_key",
            "NVD_API_KEY":     "nvd_api_key",
            "IOTBREAKER_TIMEOUT": "timeout",
            "IOTBREAKER_THREADS": "threads",
            "IOTBREAKER_OUTPUT":  "output_dir",
        }
        for env_var, config_key in env_map.items():
            value = os.getenv(env_var)
            if value:
                # Type coercion for numeric values
                if config_key in ("timeout", "threads"):
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                self._data[config_key] = value

    def load_file(self, path: str):
        """Load configuration from a YAML or JSON file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(p, "r", encoding="utf-8") as fh:
            if p.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(fh)
            elif p.suffix == ".json":
                data = json.load(fh)
            else:
                raise ValueError(f"Unsupported configuration format: {p.suffix}")

        if isinstance(data, dict):
            self._data.update(data)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a configuration value."""
        return self._data.get(key, default)

    def set(self, key: str, value: Any):
        """Set a configuration value at runtime."""
        if value is not None:
            self._data[key] = value

    def all(self) -> Dict[str, Any]:
        """Return all configuration values."""
        return dict(self._data)

    def __repr__(self) -> str:
        safe = {k: v for k, v in self._data.items()
                if "key" not in k.lower() and "password" not in k.lower()}
        return f"Config({safe})"
