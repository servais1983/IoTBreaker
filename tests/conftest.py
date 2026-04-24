"""
Shared pytest fixtures and configuration for the IoTBreaker test suite.
"""
import os
import sys
import tempfile
import pytest

# Ensure project root is on sys.path regardless of cwd
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.config import Config


@pytest.fixture
def config() -> Config:
    """Return a default Config instance (no disk I/O)."""
    return Config()


@pytest.fixture
def tmp_dir(tmp_path):
    """Return a temporary directory path (pathlib.Path)."""
    return tmp_path


@pytest.fixture
def sample_finding():
    """A realistic finding dict used across multiple tests."""
    return {
        "title":       "Telnet Enabled",
        "severity":    "HIGH",
        "cvss_score":  7.5,
        "target":      "192.168.1.1",
        "port":        23,
        "protocol":    "tcp",
        "cve_ids":     ["CVE-2023-9999"],
        "description": "Telnet service exposed without authentication.",
        "remediation": "Disable Telnet and use SSH.",
    }


@pytest.fixture
def sample_device():
    """A realistic device dict."""
    return {
        "ip":          "192.168.1.1",
        "mac":         "aa:bb:cc:dd:ee:ff",
        "hostname":    "camera-01",
        "vendor":      "Hikvision",
        "device_type": "IP Camera",
        "open_ports":  [23, 80, 554],
    }
