"""Offline tests for FingerprintModule.

Active probes are patched. No sockets or HTTP calls are made.
"""

from unittest.mock import patch

from modules.fingerprint.fingerprint import FingerprintModule


def _silence(fp):
    return (
        patch.object(fp, "_resolve_hostname", return_value="n/a"),
        patch.object(fp, "_get_ttl", return_value=None),
        patch.object(fp, "_http_fingerprint", return_value=None),
        patch.object(fp, "_ssh_fingerprint", return_value=None),
        patch.object(fp, "_telnet_fingerprint", return_value=None),
        patch.object(fp, "_upnp_fingerprint", return_value=None),
    )


class TestFingerprintRun:
    def test_shallow_run_skips_deep_probes(self, config):
        fp = FingerprintModule(config)
        patches = _silence(fp)
        for item in patches:
            item.start()
        try:
            with patch.object(fp, "_rtsp_fingerprint") as rtsp, \
                 patch.object(fp, "_snmp_fingerprint") as snmp:
                result = fp.run("203.0.113.10", deep=False, mac="08:00:27:aa:bb:cc")
        finally:
            for item in patches:
                item.stop()
        rtsp.assert_not_called()
        snmp.assert_not_called()
        assert result["ip"] == "203.0.113.10"
        assert result["oui_vendor"] == "Oracle VirtualBox"
        assert result["os"] == "N/A"

    def test_deep_run_calls_extra_probes(self, config):
        fp = FingerprintModule(config)
        patches = _silence(fp)
        for item in patches:
            item.start()
        try:
            with patch.object(fp, "_rtsp_fingerprint", return_value={"rtsp_server": "demo"}) as rtsp, \
                 patch.object(fp, "_snmp_fingerprint", return_value={"snmp_sysdescr": "demo"}) as snmp:
                result = fp.run("203.0.113.10", deep=True)
        finally:
            for item in patches:
                item.stop()
        rtsp.assert_called_once_with("203.0.113.10")
        snmp.assert_called_once_with("203.0.113.10")
        assert result["rtsp_server"] == "demo"
        assert result["snmp_sysdescr"] == "demo"

    def test_ttl_sets_os_hint(self, config):
        fp = FingerprintModule(config)
        with patch.object(fp, "_resolve_hostname", return_value="host.example"), \
             patch.object(fp, "_get_ttl", return_value=64), \
             patch.object(fp, "_http_fingerprint", return_value=None), \
             patch.object(fp, "_ssh_fingerprint", return_value=None), \
             patch.object(fp, "_telnet_fingerprint", return_value=None), \
             patch.object(fp, "_upnp_fingerprint", return_value=None):
            result = fp.run("203.0.113.10")
        assert result["ttl"] == 64
        assert result["os"] == "Linux / Android / Embedded"
        assert result["hostname"] == "host.example"


class TestFingerprintHelpers:
    def test_ttl_bands(self, config):
        fp = FingerprintModule(config)
        assert fp._ttl_to_os(64) == "Linux / Android / Embedded"
        assert fp._ttl_to_os(128) == "Windows"
        assert fp._ttl_to_os(255) == "Cisco IOS / Solaris / HP-UX"
        assert fp._ttl_to_os(256) == "Unknown"

    def test_oui_unknown_and_missing(self, config):
        fp = FingerprintModule(config)
        assert fp._oui_lookup("N/A") == "N/A"
        assert fp._oui_lookup("02:00:00:00:00:01") == "Unknown Vendor"

    def test_upnp_xml_fields(self, config):
        fp = FingerprintModule(config)
        xml = """<?xml version="1.0"?>
        <root>
          <device>
            <manufacturer>Example Co</manufacturer>
            <modelName>DemoCam</modelName>
            <deviceType>urn:example:camera</deviceType>
            <friendlyName>Lobby</friendlyName>
            <serialNumber>SN1</serialNumber>
          </device>
        </root>
        """
        info = fp._parse_upnp_xml(xml)
        assert info["manufacturer"] == "Example Co"
        assert info["model"] == "DemoCam"
        assert info["serial"] == "SN1"
