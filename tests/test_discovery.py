"""Offline tests for DiscoveryModule.

Network sweeps are patched. No sockets are opened.
"""

from unittest.mock import patch

from modules.discovery.discovery import DiscoveryModule


class TestDiscoveryRun:
    def test_invalid_cidr_returns_empty(self, config):
        mod = DiscoveryModule(config)
        assert mod.run("not-a-network", method="tcp") == []

    def test_tcp_method_does_not_call_other_sweeps(self, config):
        mod = DiscoveryModule(config)
        host = {"ip": "203.0.113.5", "open_ports": [80]}
        with patch.object(mod, "_tcp_sweep", return_value={"203.0.113.5"}) as tcp, \
             patch.object(mod, "_arp_sweep") as arp, \
             patch.object(mod, "_upnp_discovery") as upnp, \
             patch.object(mod, "_mdns_discovery") as mdns, \
             patch.object(mod, "_enrich_host", return_value=host):
            devices = mod.run("203.0.113.0/24", method="tcp")
        tcp.assert_called_once()
        arp.assert_not_called()
        upnp.assert_not_called()
        mdns.assert_not_called()
        assert devices == [host]

    def test_exclude_removes_addresses_before_enrichment(self, config):
        mod = DiscoveryModule(config)
        seen = []

        def enrich(ip):
            seen.append(ip)
            return {"ip": ip, "open_ports": []}

        with patch.object(mod, "_tcp_sweep", return_value={"203.0.113.5", "203.0.113.6"}), \
             patch.object(mod, "_enrich_host", side_effect=enrich):
            devices = mod.run("203.0.113.0/24", method="tcp", exclude=["203.0.113.5"])
        assert seen == ["203.0.113.6"]
        assert [d["ip"] for d in devices] == ["203.0.113.6"]

    def test_no_responders_skips_enrichment(self, config):
        mod = DiscoveryModule(config)
        with patch.object(mod, "_tcp_sweep", return_value=set()), \
             patch.object(mod, "_enrich_host") as enrich:
            assert mod.run("203.0.113.0/24", method="tcp") == []
        enrich.assert_not_called()


class TestClassifyDevice:
    def test_camera_signature(self, config):
        mod = DiscoveryModule(config)
        assert mod._classify_device({80, 554}) == "IP Camera"

    def test_unknown_when_no_ports(self, config):
        mod = DiscoveryModule(config)
        assert mod._classify_device(set()) == "Unknown IoT Device"

    def test_signature_beats_later_heuristic(self, config):
        mod = DiscoveryModule(config)
        assert mod._classify_device({502}) == "Modbus Device"

    def test_single_port_heuristic(self, config):
        mod = DiscoveryModule(config)
        assert mod._classify_device({554}) == "IP Camera / Streaming Device"
