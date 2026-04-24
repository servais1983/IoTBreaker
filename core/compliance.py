#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Compliance Framework Mapping

G10: Maps IoTBreaker check types to controls in common security frameworks,
enabling reports to reference specific standards for regulated-industry clients.

Frameworks covered:
  - OWASP IoT Top 10 (2018)
  - IEC 62443-3-3 (Industrial Automation)
  - NIST SP 800-82 Rev. 3 (Industrial Control Systems)
  - ETSI EN 303 645 (Consumer IoT, EU)
  - NIST CSF 2.0 (General Enterprise)
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Static mapping table
# Keys are IoTBreaker check / finding category identifiers.
# Each maps to a dict of framework → list of control references.
# ---------------------------------------------------------------------------

COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {
    # ---------- Authentication / Weak Credentials ----------
    "weak_credentials": {
        "OWASP_IoT_2018":  ["I1 - Weak, Guessable, or Hardcoded Passwords"],
        "IEC_62443_3_3":   ["SR 1.1 - Human User Identification and Authentication",
                            "SR 1.2 - Software Process and Device Identification"],
        "NIST_SP_800_82":  ["IA-5 (Authenticator Management)"],
        "ETSI_EN_303_645": ["5.1 - No universal default passwords"],
        "NIST_CSF_2":      ["PR.AA-01 (Identities and credentials are managed)"],
    },
    "default_credentials": {
        "OWASP_IoT_2018":  ["I1 - Weak, Guessable, or Hardcoded Passwords"],
        "IEC_62443_3_3":   ["SR 1.1 - Human User Identification and Authentication"],
        "NIST_SP_800_82":  ["IA-5 (Authenticator Management)"],
        "ETSI_EN_303_645": ["5.1 - No universal default passwords"],
        "NIST_CSF_2":      ["PR.AA-01 (Identities and credentials are managed)"],
    },
    "brute_force": {
        "OWASP_IoT_2018":  ["I1 - Weak, Guessable, or Hardcoded Passwords"],
        "IEC_62443_3_3":   ["SR 1.11 - Unsuccessful Login Attempts"],
        "NIST_SP_800_82":  ["AC-7 (Unsuccessful Logon Attempts)"],
        "ETSI_EN_303_645": ["5.1 - No universal default passwords"],
        "NIST_CSF_2":      ["PR.AA-05 (Access permissions managed)"],
    },

    # ---------- Unencrypted / Cleartext Protocols ----------
    "telnet": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces"],
        "IEC_62443_3_3":   ["SR 4.1 - Information Confidentiality"],
        "NIST_SP_800_82":  ["SC-8 (Transmission Confidentiality and Integrity)"],
        "ETSI_EN_303_645": ["5.8 - Ensure software integrity"],
        "NIST_CSF_2":      ["PR.DS-02 (Data-in-transit is protected)"],
    },
    "mqtt_anonymous": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces",
                            "I9 - Insecure Default Settings"],
        "IEC_62443_3_3":   ["SR 1.1 - Human User Identification and Authentication",
                            "SR 4.1 - Information Confidentiality"],
        "NIST_SP_800_82":  ["AC-3 (Access Enforcement)",
                            "SC-8 (Transmission Confidentiality and Integrity)"],
        "ETSI_EN_303_645": ["5.5 - Communicate securely"],
        "NIST_CSF_2":      ["PR.DS-02 (Data-in-transit is protected)"],
    },
    "mqtt_tls": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces"],
        "IEC_62443_3_3":   ["SR 4.1 - Information Confidentiality",
                            "SR 4.3 - Use of Cryptography"],
        "NIST_SP_800_82":  ["SC-8 (Transmission Confidentiality and Integrity)",
                            "SC-28 (Protection of Information at Rest)"],
        "ETSI_EN_303_645": ["5.5 - Communicate securely"],
        "NIST_CSF_2":      ["PR.DS-02 (Data-in-transit is protected)"],
    },

    # ---------- Network / Service Exposure ----------
    "upnp": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces",
                            "I9 - Insecure Default Settings"],
        "IEC_62443_3_3":   ["SR 2.1 - Authorization Enforcement"],
        "NIST_SP_800_82":  ["CM-7 (Least Functionality)"],
        "ETSI_EN_303_645": ["5.6 - Minimize exposed attack surfaces"],
        "NIST_CSF_2":      ["PR.PS-03 (Hardware is managed consistently)"],
    },
    "snmp": {
        "OWASP_IoT_2018":  ["I1 - Weak, Guessable, or Hardcoded Passwords",
                            "I3 - Insecure Ecosystem Interfaces"],
        "IEC_62443_3_3":   ["SR 1.1 - Human User Identification and Authentication"],
        "NIST_SP_800_82":  ["IA-5 (Authenticator Management)"],
        "ETSI_EN_303_645": ["5.6 - Minimize exposed attack surfaces"],
        "NIST_CSF_2":      ["PR.AA-01 (Identities and credentials are managed)"],
    },
    "ftp": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces"],
        "IEC_62443_3_3":   ["SR 4.1 - Information Confidentiality"],
        "NIST_SP_800_82":  ["CM-7 (Least Functionality)"],
        "ETSI_EN_303_645": ["5.6 - Minimize exposed attack surfaces"],
        "NIST_CSF_2":      ["PR.DS-02 (Data-in-transit is protected)"],
    },

    # ---------- Firmware / Software ----------
    "hardcoded_credentials": {
        "OWASP_IoT_2018":  ["I1 - Weak, Guessable, or Hardcoded Passwords"],
        "IEC_62443_3_3":   ["SR 1.1 - Human User Identification and Authentication"],
        "NIST_SP_800_82":  ["IA-5 (Authenticator Management)"],
        "ETSI_EN_303_645": ["5.1 - No universal default passwords"],
        "NIST_CSF_2":      ["PR.AA-01 (Identities and credentials are managed)"],
    },
    "firmware_secrets": {
        "OWASP_IoT_2018":  ["I1 - Weak, Guessable, or Hardcoded Passwords",
                            "I8 - Lack of Device Management"],
        "IEC_62443_3_3":   ["SR 1.5 - Authenticator Management"],
        "NIST_SP_800_82":  ["IA-5 (Authenticator Management)"],
        "ETSI_EN_303_645": ["5.1 - No universal default passwords",
                            "5.3 - Keep software updated"],
        "NIST_CSF_2":      ["PR.AA-01 (Identities and credentials are managed)"],
    },

    # ---------- HTTP / Web ----------
    "http_admin": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces",
                            "I9 - Insecure Default Settings"],
        "IEC_62443_3_3":   ["SR 2.1 - Authorization Enforcement"],
        "NIST_SP_800_82":  ["AC-3 (Access Enforcement)"],
        "ETSI_EN_303_645": ["5.6 - Minimize exposed attack surfaces"],
        "NIST_CSF_2":      ["PR.AA-05 (Access permissions managed)"],
    },
    "missing_security_headers": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces"],
        "IEC_62443_3_3":   ["SR 3.3 - Security Functionality Verification"],
        "NIST_SP_800_82":  ["SI-10 (Information Input Validation)"],
        "ETSI_EN_303_645": ["5.5 - Communicate securely"],
        "NIST_CSF_2":      ["PR.DS-02 (Data-in-transit is protected)"],
    },

    # ---------- CVE / Exploit ----------
    "cve_exploit": {
        "OWASP_IoT_2018":  ["I3 - Insecure Ecosystem Interfaces",
                            "I5 - Use of Insecure or Outdated Components"],
        "IEC_62443_3_3":   ["SR 2.4 - Mobile Code",
                            "SR 3.2 - Malicious Code Protection"],
        "NIST_SP_800_82":  ["SI-2 (Flaw Remediation)",
                            "RA-5 (Vulnerability Monitoring and Scanning)"],
        "ETSI_EN_303_645": ["5.3 - Keep software updated"],
        "NIST_CSF_2":      ["ID.RA-01 (Vulnerabilities in assets are identified)"],
    },
}

# ---------------------------------------------------------------------------
# Keyword → compliance category routing
# Maps tokens found in finding titles/protocols to COMPLIANCE_MAP keys
# ---------------------------------------------------------------------------

_TITLE_ROUTER = [
    ("Hardcoded",             "hardcoded_credentials"),
    ("Default Credential",    "default_credentials"),
    ("Valid credential",      "weak_credentials"),
    ("Brute",                 "brute_force"),
    ("Telnet",                "telnet"),
    ("MQTT TLS",              "mqtt_tls"),
    ("MQTT",                  "mqtt_anonymous"),
    ("UPnP",                  "upnp"),
    ("SNMP",                  "snmp"),
    ("FTP",                   "ftp"),
    ("Admin Interface",       "http_admin"),
    ("Security Header",       "missing_security_headers"),
    ("Firmware",              "firmware_secrets"),
    ("CVE-",                  "cve_exploit"),
    ("RCE",                   "cve_exploit"),
    ("Command Injection",     "cve_exploit"),
]


def get_compliance_mapping(title: str, protocol: str = "") -> Dict[str, List[str]]:
    """
    Return a compliance mapping dict for a finding based on its title and protocol.

    Parameters
    ----------
    title    : Finding title string
    protocol : Protocol string (optional, e.g. "mqtt", "telnet")

    Returns
    -------
    dict[framework_name, list[control_refs]] or empty dict if no match
    """
    combined = f"{title} {protocol}".upper()

    for keyword, category in _TITLE_ROUTER:
        if keyword.upper() in combined:
            return COMPLIANCE_MAP.get(category, {})

    return {}


def enrich_finding_compliance(finding: dict) -> dict:
    """
    Mutate a finding dict in-place by adding a 'compliance_mapping' key.

    Returns the same dict for chaining.
    """
    title    = finding.get("title", "")
    protocol = finding.get("protocol", "")
    finding["compliance_mapping"] = get_compliance_mapping(title, protocol)
    return finding
