"""
Tests for the OT/ICS active probing module (modules/ot/ot_probe.py).

Frame builders and response parsers are pure functions and are tested directly.
The OTScanner socket layer is exercised with monkeypatched sockets so no real
network traffic is generated.
"""
import struct
import pytest

from modules.ot import ot_probe as ot
from modules.ot.ot_probe import OTScanner, OT_PORTS, ALL_PROTOCOLS
from core.compliance import get_compliance_mapping, enrich_finding_compliance


# ===================================================================== #
# Modbus
# ===================================================================== #

class TestModbus:
    def test_devid_request_frame(self):
        req = ot.build_modbus_devid_request()
        assert req == bytes.fromhex("000100000005012b0e0100")
        # MBAP protocol id field (bytes 2-3) must be zero
        assert req[2:4] == b"\x00\x00"

    def test_read_holding_request_frame(self):
        req = ot.build_modbus_read_holding()
        assert req[7] == 0x03          # function code
        assert req[2:4] == b"\x00\x00"

    def test_parse_devid_response_extracts_objects(self):
        objs = bytes([0x00, 0x05]) + b"ACME " + bytes([0x01, 0x03]) + b"PLC"
        pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 2]) + objs
        mbap = struct.pack(">HHHB", 0, 0, len(pdu) + 1, 1)
        parsed = ot.parse_modbus_response(mbap + pdu)
        assert parsed["vendor"] == "ACME "
        assert parsed["product_code"] == "PLC"
        assert parsed["exception"] is False

    def test_parse_exception_response(self):
        frame = struct.pack(">HHHB", 1, 0, 3, 1) + bytes([0xAB, 0x02])
        parsed = ot.parse_modbus_response(frame)
        assert parsed["exception"] is True
        assert parsed["function_code"] == 0xAB

    def test_parse_rejects_non_modbus(self):
        # non-zero protocol id => not Modbus/TCP
        frame = struct.pack(">HHHB", 1, 5, 3, 1) + bytes([0x03, 0x02])
        assert ot.parse_modbus_response(frame) is None

    def test_parse_rejects_short(self):
        assert ot.parse_modbus_response(b"\x00\x01") is None


# ===================================================================== #
# Siemens S7 / COTP
# ===================================================================== #

class TestS7:
    def test_cotp_cr_is_valid_tpkt(self):
        cr = ot.build_cotp_connection_request()
        assert cr[0] == 0x03                      # TPKT version
        assert struct.unpack(">H", cr[2:4])[0] == len(cr)
        assert cr[5] == 0xE0                      # COTP Connection Request

    def test_parse_connection_confirm(self):
        cc = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xD0]) + bytes(16)
        parsed = ot.parse_cotp_response(cc)
        assert parsed["connection_confirm"] is True

    def test_parse_rejects_non_tpkt(self):
        assert ot.parse_cotp_response(b"\x99\x00\x00\x06\x05\xd0") is None


# ===================================================================== #
# BACnet
# ===================================================================== #

class TestBACnet:
    def test_whois_frame(self):
        assert ot.build_bacnet_whois() == bytes.fromhex("810a000801001008")

    def test_parse_i_am_device_instance(self):
        frame = bytes([0x81, 0x0B, 0x00, 0x0B, 0x01, 0x00,
                       0x10, 0x00, 0xC4, 0x02, 0x00, 0x00, 0x05])
        parsed = ot.parse_bacnet_response(frame)
        assert parsed["is_i_am"] is True
        assert parsed["device_instance"] == 5

    def test_parse_plain_bvlc(self):
        parsed = ot.parse_bacnet_response(bytes([0x81, 0x00, 0x00, 0x04]))
        assert parsed is not None
        assert "device_instance" not in parsed

    def test_parse_rejects_non_bacnet(self):
        assert ot.parse_bacnet_response(b"\x00\x00\x00\x00") is None


# ===================================================================== #
# DNP3
# ===================================================================== #

class TestDNP3:
    def test_crc_is_deterministic_and_16bit(self):
        crc = ot.dnp3_crc(b"\x05\x64\x05\xc9\x01\x00\x00\x04")
        assert 0 <= crc <= 0xFFFF
        # same input -> same output
        assert crc == ot.dnp3_crc(b"\x05\x64\x05\xc9\x01\x00\x00\x04")

    def test_link_status_frame_shape(self):
        frame = ot.build_dnp3_link_status()
        assert len(frame) == 10
        assert frame[:2] == b"\x05\x64"
        # CRC at the end must match a recomputation over the 8-octet header
        assert struct.unpack("<H", frame[8:10])[0] == ot.dnp3_crc(frame[:8])

    def test_parse_response(self):
        resp = bytes([0x05, 0x64, 0x05, 0x0B, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00])
        parsed = ot.parse_dnp3_response(resp)
        assert parsed["function_code"] == 0x0B
        assert parsed["from_outstation"] is True

    def test_parse_rejects_non_dnp3(self):
        assert ot.parse_dnp3_response(b"\x00\x64\x05") is None


# ===================================================================== #
# EtherNet/IP
# ===================================================================== #

class TestEtherNetIP:
    def test_list_identity_header(self):
        req = ot.build_enip_list_identity()
        assert len(req) == 24
        assert struct.unpack("<H", req[:2])[0] == 0x0063

    def test_parse_identity_extracts_product_name(self):
        resp = ot.build_enip_list_identity() + b"\x00" * 20 + b"1756-EN2T/D" + b"\x00\x00"
        parsed = ot.parse_enip_identity(resp)
        assert parsed["product_name"] == "1756-EN2T/D"

    def test_parse_rejects_wrong_command(self):
        bad = struct.pack("<HHII8sI", 0x0004, 0, 0, 0, b"\x00" * 8, 0)
        assert ot.parse_enip_identity(bad) is None


# ===================================================================== #
# OPC-UA
# ===================================================================== #

class TestOPCUA:
    def test_hello_frame_header(self):
        hel = ot.build_opcua_hello("opc.tcp://10.0.0.1:4840")
        assert hel[:3] == b"HEL"
        assert hel[3:4] == b"F"
        assert struct.unpack("<I", hel[4:8])[0] == len(hel)

    def test_parse_ack(self):
        assert ot.parse_opcua_response(b"ACKF\x00\x00")["accepted"] is True

    def test_parse_err(self):
        assert ot.parse_opcua_response(b"ERRF")["accepted"] is False

    def test_parse_unknown(self):
        assert ot.parse_opcua_response(b"XYZ") is None


# ===================================================================== #
# OTScanner (with monkeypatched network layer)
# ===================================================================== #

@pytest.fixture
def scanner(config):
    return OTScanner(config)


class TestOTScanner:
    def test_run_defaults_to_all_protocols(self, scanner, monkeypatch):
        called = []
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: called.append(a) or None)
        monkeypatch.setattr(scanner, "_udp_query", lambda *a, **k: called.append(a) or None)
        findings = scanner.run("10.0.0.1")
        assert findings == []
        # one query attempt per protocol (modbus tries twice on no-response)
        assert len(called) >= len(ALL_PROTOCOLS)

    def test_modbus_finding_generated(self, scanner, monkeypatch):
        pdu = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 1]) + bytes([0x00, 0x04]) + b"Acme"
        frame = struct.pack(">HHHB", 0, 0, len(pdu) + 1, 1) + pdu
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: frame)
        finding = scanner._probe_modbus("10.0.0.1", 502)
        assert finding["severity"] == "HIGH"
        assert finding["protocol"] == "modbus"
        assert "Acme" in finding["evidence"]
        assert finding["cwe_id"] == "CWE-306"

    def test_modbus_no_response_returns_none(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: None)
        assert scanner._probe_modbus("10.0.0.1", 502) is None

    def test_s7_finding_requires_connection_confirm(self, scanner, monkeypatch):
        cc = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xD0]) + bytes(16)
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: cc)
        finding = scanner._probe_s7("10.0.0.1", 102)
        assert finding is not None
        assert finding["protocol"] == "s7comm"

    def test_s7_no_confirm_returns_none(self, scanner, monkeypatch):
        # Data response (0xF0), not a connection confirm
        dt = bytes([0x03, 0x00, 0x00, 0x07, 0x02, 0xF0, 0x80])
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: dt)
        assert scanner._probe_s7("10.0.0.1", 102) is None

    def test_bacnet_finding(self, scanner, monkeypatch):
        frame = bytes([0x81, 0x0B, 0x00, 0x0B, 0x01, 0x00,
                       0x10, 0x00, 0xC4, 0x02, 0x00, 0x00, 0x2A])
        monkeypatch.setattr(scanner, "_udp_query", lambda *a, **k: frame)
        finding = scanner._probe_bacnet("10.0.0.1", 47808)
        assert finding["protocol"] == "bacnet"
        assert "42" in finding["evidence"]      # device instance 0x2A = 42

    def test_enip_finding(self, scanner, monkeypatch):
        resp = ot.build_enip_list_identity() + b"\x00" * 16 + b"ControlLogix"
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: resp)
        finding = scanner._probe_enip("10.0.0.1", 44818)
        assert finding["protocol"] == "ethernet/ip"
        assert "ControlLogix" in finding["evidence"]

    def test_opcua_finding(self, scanner, monkeypatch):
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: b"ACKF\x1c\x00\x00\x00")
        finding = scanner._probe_opcua("10.0.0.1", 4840)
        assert finding["protocol"] == "opc-ua"

    def test_port_override_single_protocol(self, scanner, monkeypatch):
        seen = {}
        def fake_tcp(target, port, payload, read=1024):
            seen["port"] = port
            return None
        monkeypatch.setattr(scanner, "_tcp_query", fake_tcp)
        scanner.run("10.0.0.1", protocols=["modbus"], port_override=1502)
        assert seen["port"] == 1502

    def test_all_findings_carry_standard_schema(self, scanner, monkeypatch):
        cc = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xD0]) + bytes(16)
        monkeypatch.setattr(scanner, "_tcp_query", lambda *a, **k: cc)
        finding = scanner._probe_s7("10.0.0.1", 102)
        for key in ("title", "severity", "description", "target", "port",
                    "protocol", "cvss_score", "cve_ids", "cwe_id",
                    "evidence", "remediation"):
            assert key in finding


# ===================================================================== #
# Compliance integration
# ===================================================================== #

class TestOTCompliance:
    @pytest.mark.parametrize("title,protocol", [
        ("Modbus/TCP Unauthenticated Access", "modbus"),
        ("Siemens S7comm (ISO-on-TCP) Exposed", "s7comm"),
        ("BACnet/IP Device Enumeration Exposed", "bacnet"),
        ("DNP3 Outstation Reachable (Unauthenticated)", "dnp3"),
        ("EtherNet/IP Identity Disclosure", "ethernet/ip"),
        ("OPC-UA Server Exposed", "opc-ua"),
    ])
    def test_ot_findings_map_to_iec_62443(self, title, protocol):
        mapping = get_compliance_mapping(title, protocol)
        assert mapping, f"no compliance mapping for {title}"
        assert "IEC_62443_3_3" in mapping
        assert any("SR 1.1" in c for c in mapping["IEC_62443_3_3"])

    def test_enrich_adds_mapping_to_ot_finding(self):
        finding = {"title": "Modbus/TCP Unauthenticated Access", "protocol": "modbus"}
        enrich_finding_compliance(finding)
        assert finding["compliance_mapping"]["NIST_SP_800_82"]

    def test_port_table_complete(self):
        assert set(OT_PORTS) == set(ALL_PROTOCOLS)
        assert OT_PORTS["modbus"] == 502
        assert OT_PORTS["dnp3"] == 20000
