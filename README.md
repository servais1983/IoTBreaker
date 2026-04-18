# IoTBreaker - Professional IoT Security Assessment Framework

**IoTBreaker** is a comprehensive, modular penetration testing framework specifically designed for Internet of Things (IoT) devices. It provides security professionals and researchers with an automated pipeline for discovery, fingerprinting, vulnerability scanning, and exploitation of IoT ecosystems.

## Disclaimer

This tool is intended for **authorized security testing only**. Unauthorized use of this tool against systems you do not own or have explicit written permission to test is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Architecture & Features

IoTBreaker is built on a high-performance, modular Python architecture, allowing for targeted execution or full automated audits.

- **Network Discovery (`discover`)**: High-speed device enumeration using ARP, ICMP, TCP, mDNS, and UPnP/SSDP probes.
- **Port Scanning (`scan`)**: Multi-threaded TCP/UDP port scanner optimized for common IoT and industrial control system (ICS) ports, including service banner grabbing.
- **Device Fingerprinting (`fingerprint`)**: Advanced OS and device identification leveraging MAC OUI lookups, HTTP headers, RTSP descriptors, UPnP XML parsing, and SNMP queries.
- **Vulnerability Assessment (`vuln`)**: Automated checks for default credentials, authentication bypasses, directory traversals, and exposed administrative interfaces across multiple protocols (Telnet, SSH, MQTT, HTTP, RTSP, CoAP, UPnP, SNMP, FTP).
- **Credential Brute-Forcing (`brute`)**: Multi-protocol credential testing engine with customizable wordlists and delay controls to evade basic rate limiting.
- **Exploitation (`exploit`)**: A curated repository of proof-of-concept (PoC) exploits for known, high-impact IoT vulnerabilities (e.g., Hikvision RCE, Dasan GPON, Huawei HG532, Zyxel OS Command Injection). Supports "check-only" verification mode.
- **Firmware Analysis (`firmware`)**: Static analysis module to extract filesystems, compute entropy, and identify hardcoded secrets or cryptographic keys within firmware binaries.
- **Threat Intelligence (`shodan`, `cve`)**: Native integration with the Shodan API for external exposure mapping, and the NIST NVD API for real-time CVE correlation and CVSS v3.1 scoring.
- **Professional Reporting**: Generates comprehensive, client-ready reports in HTML, PDF, JSON, and TXT formats, including executive summaries, risk scoring, and actionable remediation advice.

## Installation

IoTBreaker requires Python 3.8 or higher.

```bash
# Clone the repository
git clone https://github.com/servais1983/IoTBreaker.git
cd IoTBreaker

# Install required dependencies
pip3 install -r requirements.txt

# (Optional) Install WeasyPrint for PDF report generation
# Note: WeasyPrint requires system-level dependencies (Pango, Cairo, etc.)
# Ubuntu/Debian: sudo apt install libpango-1.0-0 libpangoft2-1.0-0
pip3 install weasyprint
```

## Configuration

Global settings and API keys can be configured via environment variables or a configuration file.

```bash
# Copy the example environment file
cp env.example .env

# Edit .env to add your API keys
nano .env
source .env
```

Key environment variables:
- `SHODAN_API_KEY`: Required for the `shodan` module.
- `NVD_API_KEY`: Recommended for the `cve` module to increase API rate limits.
- `IOTBREAKER_THREADS`: Default number of concurrent threads (default: 100).
- `IOTBREAKER_TIMEOUT`: Default connection timeout in seconds (default: 5).

## Usage Guide

The framework is operated via a central command-line interface.

```bash
python3 iotbreaker.py <module> [options]
```

### Full Automated Audit

Run the complete pipeline (discovery, scanning, fingerprinting, vulnerability assessment, and reporting) against a target network.

```bash
python3 iotbreaker.py audit --network 192.168.1.0/24 --format html
```

### Individual Modules

**1. Network Discovery**
```bash
python3 iotbreaker.py discover --network 192.168.1.0/24 --method all
```

**2. Port Scanning**
```bash
python3 iotbreaker.py scan --target 192.168.1.100 --ports iot-common
```

**3. Device Fingerprinting**
```bash
python3 iotbreaker.py fingerprint --target 192.168.1.100 --deep
```

**4. Vulnerability Assessment**
```bash
# Run all checks and correlate findings with the NVD database
python3 iotbreaker.py vuln --target 192.168.1.100 --all --cve
```

**5. Credential Brute-Forcing**
```bash
python3 iotbreaker.py brute --target 192.168.1.100 --protocol telnet --users wordlists/users.txt --passwords wordlists/passwords.txt
```

**6. Exploitation**
```bash
# List available exploits
python3 iotbreaker.py exploit --list

# Verify vulnerability without executing a payload
python3 iotbreaker.py exploit --target 192.168.1.100 --cve CVE-2021-36260 --check

# Execute exploit with custom payload
python3 iotbreaker.py exploit --target 192.168.1.100 --cve CVE-2021-36260 --payload "id"
```

**7. Firmware Analysis**
```bash
python3 iotbreaker.py firmware --file /path/to/firmware.bin --secrets --entropy
```

**8. Threat Intelligence**
```bash
# Query Shodan for specific IP
python3 iotbreaker.py shodan --ip 1.2.3.4

# Query NVD database for vendor vulnerabilities
python3 iotbreaker.py cve --vendor hikvision --severity critical
```

## Output & Reporting

By default, IoTBreaker generates reports in the `./reports` directory. The output format can be controlled using the `--format` flag (options: `json`, `html`, `pdf`, `all`).

The HTML and PDF reports include:
- An executive summary with an aggregated risk score.
- Statistical breakdowns of findings by severity.
- Detailed vulnerability descriptions with CVSS v3.1 scoring, CWE mappings, and remediation guidance.
- A complete inventory of discovered hosts and open ports.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
