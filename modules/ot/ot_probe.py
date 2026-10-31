#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - OT / ICS Active Probing Module

G5 (partial): Active, READ-ONLY testing of industrial control protocols.

This module implements safe, non-intrusive probes for the most common
OT/ICS protocols found on IP networks. Every probe is strictly read-only:
it sends a well-formed identification / status request and classifies the
response. No write, no command execution, no state change is ever issued.

Because these protocols were designed for isolated, trusted networks, most
of them have **no authentication**. A device that answers an unauthenticated
probe is therefore reporting an exposure, which is exactly what an assessment
needs to document (IEC 62443 SR 1.1 / SR 1.2, NIST SP 800-82).

Implemented protocols (pure-Python, stdlib only — no extra dependencies):

| Protocol      | Port        | Probe (read-only)                         |
|---------------|-------------|-------------------------------------------|
| Modbus/TCP    | 502  (TCP)  | Read Device Identification (FC 43/14)     |
| Siemens S7    | 102  (TCP)  | COTP connection request (ISO-on-TCP)      |
| BACnet/IP     | 47808 (UDP) | Who-Is (unconfirmed service)              |
| DNP3          | 20000 (TCP) | Request Link Status (data-link layer)     |
| EtherNet/IP   | 44818 (TCP) | ListIdentity (encapsulation command)      |
| OPC-UA        | 4840 (TCP)  | Hello / Acknowledge transport handshake   |

The frame builders and response parsers are implemented as pure functions so
they can be unit-tested without any network access.
"""

import socket
import struct
from typing import Dict, List, Optional, Callable

from core.logger import get_logger
from core.output import Console
from core.config import Config

logger = get_logger(__name__)

# Default ports per protocol
OT_PORTS: Dict[str, int] = {
    "modbus": 502,
    "s7":     102,
    "bacnet": 47808,
    "dnp3":   20000,
    "enip":   44818,
    "opcua":  4840,
}

# Protocols that speak UDP rather than TCP
_UDP_PROTOCOLS = {"bacnet"}

ALL_PROTOCOLS = list(OT_PORTS.keys())


# ===================================================================== #
# Pure frame builders / parsers (unit-testable, no I/O)                 #
# ===================================================================== #

# ---- Modbus/TCP ----------------------------------------------------- #

def build_modbus_devid_request(unit_id: int = 1, transaction_id: int = 1) -> bytes:
    """
    Build a Modbus/TCP 'Read Device Identification' request
    (function code 0x2B, MEI type 0x0E, basic device ID, object 0x00).

    MBAP header (7 bytes) + PDU (4 bytes).
    """
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])          # FC, MEI, ReadDevIDCode=basic, ObjectId=0
    length = len(pdu) + 1                           # PDU + unit id
    mbap = struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id)
    return mbap + pdu


def build_modbus_read_holding(unit_id: int = 1, transaction_id: int = 1) -> bytes:
    """Build a Modbus/TCP 'Read Holding Registers' request (FC 0x03) as a fallback."""
    pdu = struct.pack(">BHH", 0x03, 0x0000, 0x0001)  # FC, start addr 0, qty 1
    length = len(pdu) + 1
    mbap = struct.pack(">HHHB", transaction_id, 0x0000, length, unit_id)
    return mbap + pdu


def parse_modbus_response(data: bytes) -> Optional[Dict]:
    """
    Validate and parse a Modbus/TCP response.

    Returns a dict describing the response (including any device-identification
    objects) or None if the bytes are not a valid Modbus/TCP reply.
    """
    if len(data) < 8:
        return None
    _tid, proto_id, _length, _unit = struct.unpack(">HHHB", data[:7])
    if proto_id != 0x0000:          # Modbus/TCP protocol identifier is always 0
        return None
    fc = data[7]
    info: Dict = {"function_code": fc, "exception": bool(fc & 0x80)}

    # Read Device Identification response (FC 0x2B / MEI 0x0E)
    if fc == 0x2B and len(data) > 14 and data[8] == 0x0E:
        objects: Dict[int, str] = {}
        num_objects = data[13]
        idx = 14
        for _ in range(num_objects):
            if idx + 2 > len(data):
                break
            obj_id = data[idx]
            obj_len = data[idx + 1]
            val = data[idx + 2: idx + 2 + obj_len]
            objects[obj_id] = val.decode("latin-1", errors="replace")
            idx += 2 + obj_len
        info["objects"] = objects
        info["vendor"] = objects.get(0x00, "")
        info["product_code"] = objects.get(0x01, "")
        info["revision"] = objects.get(0x02, "")
    return info


# ---- Siemens S7 (ISO-on-TCP / COTP) --------------------------------- #

def build_cotp_connection_request() -> bytes:
    """
    Build a TPKT + COTP Connection Request (CR) for ISO-on-TCP (RFC 1006),
    the first handshake used by Siemens S7comm on port 102.
    """
    # COTP CR: length, PDU type 0xE0 (CR), dst-ref, src-ref, class,
    #          params: src-TSAP (0xC1), dst-TSAP (0xC2), tpdu-size (0xC0)
    cotp = bytes([
        0x11,                   # length of COTP header following this byte
        0xE0,                   # PDU type: Connection Request
        0x00, 0x00,             # destination reference
        0x00, 0x01,             # source reference
        0x00,                   # class / option
        0xC1, 0x02, 0x01, 0x00,  # src-TSAP
        0xC2, 0x02, 0x01, 0x02,  # dst-TSAP
        0xC0, 0x01, 0x09,        # tpdu-size (2^9 = 512)
    ])
    tpkt = struct.pack(">BBH", 0x03, 0x00, len(cotp) + 4)  # version, reserved, total len
    return tpkt + cotp


def parse_cotp_response(data: bytes) -> Optional[Dict]:
    """
    Parse a TPKT/COTP response. Returns dict with 'pdu_type' when the frame is a
    valid TPKT (version 0x03); recognises a Connection Confirm (0xD0).
    """
    if len(data) < 6 or data[0] != 0x03:   # TPKT version
        return None
    pdu_type = data[5]                      # COTP PDU type (after TPKT[4] + len byte)
    return {
        "pdu_type": pdu_type,
        "connection_confirm": pdu_type == 0xD0,
    }


# ---- BACnet/IP ------------------------------------------------------ #

def build_bacnet_whois() -> bytes:
    """
    Build a BACnet/IP 'Who-Is' request (unconfirmed service, unicast NPDU).

    BVLC (4) + NPDU (2) + APDU (2).
    """
    apdu = bytes([0x10, 0x08])          # unconfirmed-request PDU, service = Who-Is (8)
    npdu = bytes([0x01, 0x00])          # version 1, control 0
    body = npdu + apdu
    bvlc = bytes([0x81, 0x0A]) + struct.pack(">H", 4 + len(body))  # type, Original-Unicast-NPDU
    return bvlc + body


def parse_bacnet_response(data: bytes) -> Optional[Dict]:
    """
    Parse a BACnet/IP response. Any frame with a valid BVLC type byte (0x81)
    confirms a reachable BACnet device; attempts to extract the I-Am device
    instance when present.
    """
    if len(data) < 4 or data[0] != 0x81:
        return None
    info: Dict = {"bvlc_function": data[1]}
    # Look for an I-Am APDU (unconfirmed 0x10, service 0x00) and decode the
    # Device object identifier that follows (tag 0xC4 + 4-byte object id).
    body = data[4:]
    idx = body.find(b"\x10\x00")
    if idx != -1:
        rest = body[idx + 2:]
        tpos = rest.find(b"\xC4")
        if tpos != -1 and len(rest) >= tpos + 5:
            obj_id = struct.unpack(">I", rest[tpos + 1: tpos + 5])[0]
            info["is_i_am"] = True
            info["device_instance"] = obj_id & 0x3FFFFF   # low 22 bits
    return info


# ---- DNP3 ----------------------------------------------------------- #

def dnp3_crc(data: bytes) -> int:
    """Compute the DNP3 data-link CRC (polynomial 0x3D65, reflected)."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC   # reversed 0x3D65
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def build_dnp3_link_status(dest: int = 1, src: int = 1024) -> bytes:
    """
    Build a DNP3 data-link 'Request Link Status' frame (read-only).

    Control byte 0xC9 = DIR=1, PRM=1, FCB=0, FCV=0, function code 9.
    """
    start = bytes([0x05, 0x64])
    length = 0x05                 # covers control + dest + src (5 bytes)
    control = 0xC9
    header = struct.pack("<BHH", control, dest, src)   # control, dest(LE), src(LE)
    block = start + bytes([length]) + header   # 8-octet data-link header block
    crc = dnp3_crc(block)         # DNP3 CRC is computed over the full header block
    return block + struct.pack("<H", crc)


def parse_dnp3_response(data: bytes) -> Optional[Dict]:
    """Parse a DNP3 response. A frame starting with 0x05 0x64 is a valid DNP3 reply."""
    if len(data) < 5 or data[0] != 0x05 or data[1] != 0x64:
        return None
    control = data[3]
    return {
        "control": control,
        "function_code": control & 0x0F,
        "from_outstation": not bool(control & 0x80),   # DIR bit
    }


# ---- EtherNet/IP ---------------------------------------------------- #

def build_enip_list_identity() -> bytes:
    """
    Build an EtherNet/IP 'ListIdentity' request (encapsulation command 0x0063).
    24-byte encapsulation header, empty command body.
    """
    command = 0x0063
    return struct.pack("<HHII8sI", command, 0, 0, 0, b"\x00" * 8, 0)


def parse_enip_identity(data: bytes) -> Optional[Dict]:
    """
    Parse an EtherNet/IP ListIdentity response. Confirms the command echo (0x0063)
    and best-effort extracts the printable product-name string from the CIP payload.
    """
    if len(data) < 24:
        return None
    command, length = struct.unpack("<HH", data[:4])
    if command != 0x0063:
        return None
    info: Dict = {"command": command, "length": length}
    payload = data[24:]
    # Product name is a short ASCII string near the end of the Identity item.
    ascii_runs = []
    current = bytearray()
    for b in payload:
        if 0x20 <= b <= 0x7E:
            current.append(b)
        else:
            if len(current) >= 4:
                ascii_runs.append(current.decode("ascii"))
            current = bytearray()
    if len(current) >= 4:
        ascii_runs.append(current.decode("ascii"))
    if ascii_runs:
        info["product_name"] = max(ascii_runs, key=len)
    return info


# ---- OPC-UA --------------------------------------------------------- #

def build_opcua_hello(endpoint_url: str) -> bytes:
    """
    Build an OPC-UA binary 'Hello' (HEL) transport message.

    MessageType 'HEL' + ChunkType 'F' + MessageSize + protocol parameters +
    EndpointUrl (UA String: int32 length prefix + bytes).
    """
    url_bytes = endpoint_url.encode("utf-8")
    body = struct.pack(
        "<IIIII",
        0,              # ProtocolVersion
        65536,          # ReceiveBufferSize
        65536,          # SendBufferSize
        16777216,       # MaxMessageSize
        0,              # MaxChunkCount
    )
    body += struct.pack("<i", len(url_bytes)) + url_bytes
    message_size = 8 + len(body)   # 3 (type) + 1 (chunk) + 4 (size) = 8-byte header
    header = b"HEL" + b"F" + struct.pack("<I", message_size)
    return header + body


def parse_opcua_response(data: bytes) -> Optional[Dict]:
    """Parse an OPC-UA transport response. 'ACK' = handshake accepted; 'ERR' = rejected."""
    if len(data) < 3:
        return None
    msg_type = data[:3]
    if msg_type == b"ACK":
        return {"message_type": "ACK", "accepted": True}
    if msg_type == b"ERR":
        return {"message_type": "ERR", "accepted": False}
    return None


# ===================================================================== #
# Scanner                                                               #
# ===================================================================== #

class OTScanner:
    """
    Active, read-only OT/ICS protocol scanner.

    Produces finding dictionaries compatible with the IoTBreaker reporting,
    compliance-enrichment, and persistence pipeline.
    """

    def __init__(self, config: Config):
        self.config = config
        self.timeout = config.get("timeout", 5)

    # -- public API --------------------------------------------------- #

    def run(self, target: str, protocols: Optional[List[str]] = None,
            port_override: Optional[int] = None) -> List[Dict]:
        """
        Probe ``target`` for the requested OT/ICS protocols.

        Parameters
        ----------
        target        : target IP address
        protocols     : list of protocol keys (see OT_PORTS); defaults to all
        port_override : force a single custom port (only valid with one protocol)

        Returns
        -------
        list of finding dicts.
        """
        if not protocols or protocols == ["all"]:
            protocols = ALL_PROTOCOLS

        Console.info(f"OT/ICS active probe: {target} | protocols: {', '.join(protocols)}")

        probe_map: Dict[str, Callable[[str, int], Optional[Dict]]] = {
            "modbus": self._probe_modbus,
            "s7":     self._probe_s7,
            "bacnet": self._probe_bacnet,
            "dnp3":   self._probe_dnp3,
            "enip":   self._probe_enip,
            "opcua":  self._probe_opcua,
        }

        findings: List[Dict] = []
        for proto in protocols:
            fn = probe_map.get(proto)
            if not fn:
                logger.debug(f"Unknown OT protocol '{proto}' — skipping")
                continue
            port = port_override or OT_PORTS[proto]
            try:
                result = fn(target, port)
                if result:
                    findings.append(result)
            except Exception as e:
                logger.debug(f"OT probe {proto} failed on {target}:{port}: {e}")

        return findings

    # -- per-protocol probes ------------------------------------------ #

    def _probe_modbus(self, target: str, port: int) -> Optional[Dict]:
        resp = self._tcp_query(target, port, build_modbus_devid_request())
        parsed = parse_modbus_response(resp) if resp else None
        if parsed is None:
            resp = self._tcp_query(target, port, build_modbus_read_holding())
            parsed = parse_modbus_response(resp) if resp else None
        if parsed is None:
            return None

        ident_bits = []
        if parsed.get("vendor"):
            ident_bits.append(f"vendor='{parsed['vendor']}'")
        if parsed.get("product_code"):
            ident_bits.append(f"product='{parsed['product_code']}'")
        if parsed.get("revision"):
            ident_bits.append(f"rev='{parsed['revision']}'")
        ident = " ".join(ident_bits) if ident_bits else f"function code 0x{parsed['function_code']:02X}"

        return self._finding(
            title="Modbus/TCP Unauthenticated Access",
            severity="HIGH",
            description=(
                "A Modbus/TCP endpoint responded to an unauthenticated request. Modbus "
                "has no authentication or encryption; any network-reachable client can "
                "read and write coils, registers, and device state."
            ),
            target=target, port=port, protocol="modbus",
            cvss_score=8.6, cwe_id="CWE-306",
            evidence=f"Modbus response received ({ident}).",
            remediation=(
                "Isolate Modbus devices in a dedicated OT segment behind a firewall/data "
                "diode. Restrict port 502 to authorised engineering workstations. Deploy "
                "Modbus/TCP security (TLS) per the Modbus Security spec where supported."
            ),
        )

    def _probe_s7(self, target: str, port: int) -> Optional[Dict]:
        resp = self._tcp_query(target, port, build_cotp_connection_request())
        parsed = parse_cotp_response(resp) if resp else None
        if not parsed or not parsed.get("connection_confirm"):
            return None
        return self._finding(
            title="Siemens S7comm (ISO-on-TCP) Exposed",
            severity="HIGH",
            description=(
                "A Siemens S7 / ISO-on-TCP endpoint accepted an unauthenticated COTP "
                "connection on port 102. S7comm (pre-S7comm-plus) offers no authentication; "
                "an attacker can read/write data blocks and change CPU run/stop state."
            ),
            target=target, port=port, protocol="s7comm",
            cvss_score=8.6, cwe_id="CWE-306",
            evidence="COTP Connection Confirm (0xD0) received for ISO-on-TCP handshake.",
            remediation=(
                "Enable S7 'access protection' and connection mechanisms on the PLC, use "
                "S7comm-plus with authentication, and restrict port 102 to the engineering "
                "network via firewall rules."
            ),
        )

    def _probe_bacnet(self, target: str, port: int) -> Optional[Dict]:
        resp = self._udp_query(target, port, build_bacnet_whois())
        parsed = parse_bacnet_response(resp) if resp else None
        if parsed is None:
            return None
        inst = parsed.get("device_instance")
        evidence = "BACnet/IP device replied to Who-Is"
        if inst is not None:
            evidence += f" (I-Am, device instance {inst})"
        return self._finding(
            title="BACnet/IP Device Enumeration Exposed",
            severity="MEDIUM",
            description=(
                "A BACnet/IP building-automation device responded to an unauthenticated "
                "Who-Is request, disclosing its presence and device identity. BACnet "
                "property reads and writes are typically unauthenticated."
            ),
            target=target, port=port, protocol="bacnet",
            cvss_score=5.3, cwe_id="CWE-306",
            evidence=evidence + ".",
            remediation=(
                "Segment BACnet/IP on a dedicated BAS VLAN, filter UDP/47808 at the "
                "perimeter, and deploy BACnet/SC (Secure Connect) for authenticated, "
                "encrypted communication where the devices support it."
            ),
        )

    def _probe_dnp3(self, target: str, port: int) -> Optional[Dict]:
        resp = self._tcp_query(target, port, build_dnp3_link_status())
        parsed = parse_dnp3_response(resp) if resp else None
        if parsed is None:
            return None
        return self._finding(
            title="DNP3 Outstation Reachable (Unauthenticated)",
            severity="HIGH",
            description=(
                "A DNP3 outstation answered an unauthenticated data-link status request "
                "on port 20000. Without DNP3 Secure Authentication (SAv5), an attacker "
                "can issue control commands to the SCADA outstation."
            ),
            target=target, port=port, protocol="dnp3",
            cvss_score=8.1, cwe_id="CWE-306",
            evidence=f"DNP3 link-layer reply received (control 0x{parsed['control']:02X}).",
            remediation=(
                "Enable DNP3 Secure Authentication v5, restrict TCP/20000 to the SCADA "
                "master, and deploy an OT firewall with DNP3-aware deep packet inspection."
            ),
        )

    def _probe_enip(self, target: str, port: int) -> Optional[Dict]:
        resp = self._tcp_query(target, port, build_enip_list_identity())
        parsed = parse_enip_identity(resp) if resp else None
        if parsed is None:
            return None
        name = parsed.get("product_name", "")
        evidence = "EtherNet/IP ListIdentity response received"
        if name:
            evidence += f" (product '{name}')"
        return self._finding(
            title="EtherNet/IP Identity Disclosure",
            severity="MEDIUM",
            description=(
                "An EtherNet/IP (CIP) device responded to an unauthenticated ListIdentity "
                "request, disclosing vendor, product, and revision information useful for "
                "targeting known CIP/PLC vulnerabilities."
            ),
            target=target, port=port, protocol="ethernet/ip",
            cvss_score=5.3, cwe_id="CWE-200",
            evidence=evidence + ".",
            remediation=(
                "Restrict TCP/UDP 44818 to authorised controllers, disable unused CIP "
                "services, and place EtherNet/IP assets behind an OT-aware firewall."
            ),
        )

    def _probe_opcua(self, target: str, port: int) -> Optional[Dict]:
        endpoint = f"opc.tcp://{target}:{port}"
        resp = self._tcp_query(target, port, build_opcua_hello(endpoint))
        parsed = parse_opcua_response(resp) if resp else None
        if not parsed or not parsed.get("accepted"):
            return None
        return self._finding(
            title="OPC-UA Server Exposed",
            severity="MEDIUM",
            description=(
                "An OPC-UA server completed the binary transport handshake (Hello/Acknowledge) "
                "without network-level restrictions. If the server exposes anonymous or "
                "'None' security-policy endpoints, clients can browse the address space "
                "without authentication or encryption."
            ),
            target=target, port=port, protocol="opc-ua",
            cvss_score=5.3, cwe_id="CWE-306",
            evidence="OPC-UA Acknowledge (ACK) received for Hello handshake.",
            remediation=(
                "Disable the 'None' security policy and anonymous user token, require "
                "Sign&Encrypt with certificate trust lists, and restrict TCP/4840 to "
                "authorised OPC-UA clients."
            ),
        )

    # -- helpers ------------------------------------------------------ #

    def _finding(self, **kwargs) -> Dict:
        """Build a finding dict with the standard IoTBreaker schema."""
        base = {
            "title": "", "severity": "INFO", "description": "", "target": "",
            "port": None, "protocol": None, "cvss_score": None,
            "cve_ids": [], "cwe_id": None, "evidence": "", "remediation": "",
        }
        base.update(kwargs)
        return base

    def _tcp_query(self, target: str, port: int, payload: bytes,
                   read: int = 1024) -> Optional[bytes]:
        """Send a TCP payload and return the raw response, or None on failure."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if sock.connect_ex((target, port)) != 0:
                return None
            sock.sendall(payload)
            return sock.recv(read)
        except Exception:
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _udp_query(self, target: str, port: int, payload: bytes,
                   read: int = 1024) -> Optional[bytes]:
        """Send a UDP payload and return the raw response, or None on failure."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(min(self.timeout, 3))
            sock.sendto(payload, (target, port))
            data, _ = sock.recvfrom(read)
            return data
        except Exception:
            return None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
