#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Firmware Analysis Module

Static analysis of IoT firmware images:
  - File type and architecture detection
  - Filesystem extraction via binwalk
  - Hardcoded credential and secret detection
  - Cryptographic key identification
  - Entropy analysis for encrypted/compressed sections
  - Interesting string extraction
  - Binary analysis for known vulnerable patterns
"""

import os
import re
import hashlib
import subprocess
import struct
import math
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from core.logger import get_logger
from core.output import Console
from core.config import Config

logger = get_logger(__name__)


# Regex patterns for secret detection
SECRET_PATTERNS = [
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "RSA/EC Private Key", "CRITICAL"),
    # Hardcoded passwords
    (r'(?:password|passwd|pass|pwd)\s*[=:]\s*["\']?([^\s"\'<>{}\[\]]{4,64})["\']?',
     "Hardcoded Password", "HIGH"),
    # Hardcoded usernames
    (r'(?:username|user|login|account)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{3,32})["\']?',
     "Hardcoded Username", "MEDIUM"),
    # API keys and tokens
    (r'(?:api[_-]?key|api[_-]?token|access[_-]?token|secret[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9\-_]{16,64})["\']?',
     "API Key / Token", "HIGH"),
    # AWS credentials
    (r'AKIA[0-9A-Z]{16}',
     "AWS Access Key ID", "CRITICAL"),
    (r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
     "AWS Secret Key", "CRITICAL"),
    # Database connection strings
    (r'(?:mysql|postgresql|mongodb|redis)://[^\s"\'<>]{8,128}',
     "Database Connection String", "HIGH"),
    # SSH private key material
    (r'(?:ssh-rsa|ssh-dss|ecdsa-sha2|ssh-ed25519)\s+[A-Za-z0-9+/=]{64,}',
     "SSH Public Key", "LOW"),
    # Telnet/shell backdoor indicators
    (r'(?:busybox|/bin/sh|/bin/bash|/bin/ash)\s+[-\w]+',
     "Shell Invocation", "MEDIUM"),
    # Default credentials in config files
    (r'(?:default[_-]?pass|factory[_-]?pass|admin[_-]?pass)\s*[=:]\s*["\']?([^\s"\']{4,32})["\']?',
     "Default/Factory Password", "CRITICAL"),
    # Backdoor ports
    (r'(?:backdoor|debug[_-]?port|hidden[_-]?port)\s*[=:]\s*(\d{2,5})',
     "Backdoor Port Reference", "CRITICAL"),
    # Telnet enable flags
    (r'(?:telnet[_-]?enable|enable[_-]?telnet)\s*[=:]\s*(?:1|true|yes)',
     "Telnet Enabled Flag", "HIGH"),
]

# Magic bytes for file type detection
FILE_MAGIC = {
    b"\x7fELF":                 "ELF Binary",
    b"MZ":                      "Windows PE",
    b"\x1f\x8b":                "Gzip Archive",
    b"BZh":                     "Bzip2 Archive",
    b"PK\x03\x04":              "ZIP Archive",
    b"\xfd7zXZ\x00":            "XZ Archive",
    b"ustar":                   "TAR Archive",
    b"\x27\x05\x19\x56":        "U-Boot Image",
    b"\x68\x73\x71\x73":        "SquashFS (little-endian)",
    b"\x73\x71\x73\x68":        "SquashFS (big-endian)",
    b"\x19\x85\x20\x03":        "JFFS2 Filesystem",
    b"\x85\x19\x03\x20":        "JFFS2 Filesystem (BE)",
    b"\x06\x05\x04\x03":        "CramFS",
    b"\x45\x3d\xcd\x28":        "YAFFS",
    b"\x06\x06\x2f\x4a":        "UBIFS",
}

# ELF architecture map
ELF_ARCH = {
    0x02: "SPARC",
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x28: "ARM",
    0x3e: "x86-64",
    0xb7: "AArch64",
    0xf3: "RISC-V",
}


class FirmwareAnalyzer:
    """
    Static firmware analysis engine.

    Performs comprehensive analysis of IoT firmware images including
    filesystem extraction, secret detection, and binary analysis.
    """

    def __init__(self, config: Config):
        self.config = config

    def run(
        self,
        firmware_path: str,
        extract: bool = True,
        find_secrets: bool = True,
        crypto_analysis: bool = False,
        strings_analysis: bool = False,
        entropy_analysis: bool = False
    ) -> Optional[Dict]:
        """
        Analyze a firmware image file.

        Parameters
        ----------
        firmware_path : str
            Path to the firmware binary file.
        extract : bool
            Extract filesystem using binwalk.
        find_secrets : bool
            Search for hardcoded credentials and secrets.
        crypto_analysis : bool
            Analyze cryptographic implementations.
        strings_analysis : bool
            Extract and analyze interesting strings.
        entropy_analysis : bool
            Compute entropy analysis.

        Returns
        -------
        dict or None
            Analysis results dictionary.
        """
        p = Path(firmware_path)
        if not p.exists():
            Console.error(f"Firmware file not found: {firmware_path}")
            return None

        Console.info(f"Analyzing firmware: {p.name} ({p.stat().st_size:,} bytes)")

        result = {
            "file":         str(p.absolute()),
            "filename":     p.name,
            "size":         p.stat().st_size,
            "size_human":   self._human_size(p.stat().st_size),
            "md5":          self._hash_file(p, "md5"),
            "sha256":       self._hash_file(p, "sha256"),
            "file_type":    self._detect_file_type(p),
            "architecture": self._detect_architecture(p),
            "secrets":      [],
            "strings":      [],
            "entropy":      None,
            "extracted_path": None,
        }

        Console.success(f"File type: {result['file_type']}")
        Console.success(f"Architecture: {result['architecture']}")
        Console.success(f"MD5: {result['md5']}")
        Console.success(f"SHA256: {result['sha256']}")

        # Entropy analysis
        if entropy_analysis:
            result["entropy"] = self._compute_entropy(p)
            Console.info(f"Entropy: {result['entropy']:.4f} bits/byte")

        # Filesystem extraction
        if extract:
            extracted = self._extract_firmware(p)
            if extracted:
                result["extracted_path"] = str(extracted)
                Console.success(f"Extracted to: {extracted}")

                # Search for secrets in extracted filesystem
                if find_secrets:
                    Console.info("Searching for hardcoded secrets...")
                    secrets = self._find_secrets_in_directory(extracted)
                    result["secrets"] = secrets
                    if secrets:
                        Console.warning(f"Found {len(secrets)} potential secret(s)")
                    else:
                        Console.success("No hardcoded secrets detected")

                # String analysis
                if strings_analysis:
                    result["strings"] = self._extract_interesting_strings(extracted)

        elif find_secrets:
            # Search in raw firmware binary
            secrets = self._find_secrets_in_file(p)
            result["secrets"] = secrets

        return result

    # ------------------------------------------------------------------ #
    # File analysis                                                        #
    # ------------------------------------------------------------------ #

    def _detect_file_type(self, path: Path) -> str:
        """Detect firmware file type from magic bytes."""
        try:
            with open(path, "rb") as f:
                header = f.read(16)

            for magic, file_type in FILE_MAGIC.items():
                if header[:len(magic)] == magic:
                    return file_type

            # Check for text-based formats
            try:
                with open(path, "r", encoding="utf-8", errors="strict") as f:
                    first_line = f.readline()
                if first_line.startswith("#!/"):
                    return f"Shell Script ({first_line.strip()})"
            except Exception:
                pass

            return "Unknown Binary"

        except Exception as e:
            logger.debug(f"File type detection error: {e}")
            return "Unknown"

    def _detect_architecture(self, path: Path) -> str:
        """Detect CPU architecture from ELF header."""
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic != b"\x7fELF":
                    # Try binwalk for non-ELF
                    return self._binwalk_architecture(path)

                f.seek(18)  # e_machine field
                e_machine = struct.unpack("<H", f.read(2))[0]
                arch = ELF_ARCH.get(e_machine, f"Unknown (0x{e_machine:04x})")

                f.seek(4)   # EI_CLASS
                ei_class = struct.unpack("B", f.read(1))[0]
                bits = "64-bit" if ei_class == 2 else "32-bit"

                f.seek(5)   # EI_DATA
                ei_data = struct.unpack("B", f.read(1))[0]
                endian = "little-endian" if ei_data == 1 else "big-endian"

                return f"{arch} ({bits}, {endian})"

        except Exception:
            return "Unknown"

    def _binwalk_architecture(self, path: Path) -> str:
        """Use binwalk to detect architecture."""
        try:
            result = subprocess.run(
                ["binwalk", "--disasm", str(path)],
                capture_output=True, text=True, timeout=30
            )
            arch_match = re.search(r"(MIPS|ARM|x86|PowerPC|SPARC|AArch64)", result.stdout)
            if arch_match:
                return arch_match.group(1)
        except Exception:
            pass
        return "Unknown"

    def _hash_file(self, path: Path, algorithm: str) -> str:
        """Compute file hash."""
        h = hashlib.new(algorithm)
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "N/A"

    def _compute_entropy(self, path: Path) -> float:
        """Compute Shannon entropy of the file."""
        try:
            with open(path, "rb") as f:
                data = f.read()

            if not data:
                return 0.0

            freq = [0] * 256
            for byte in data:
                freq[byte] += 1

            entropy = 0.0
            length = len(data)
            for count in freq:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)

            return entropy
        except Exception:
            return 0.0

    def _human_size(self, size: int) -> str:
        """Convert bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    # ------------------------------------------------------------------ #
    # Extraction                                                           #
    # ------------------------------------------------------------------ #

    def _extract_firmware(self, path: Path) -> Optional[Path]:
        """Extract firmware filesystem using binwalk."""
        try:
            result = subprocess.run(
                ["binwalk", "--check"],
                capture_output=True, timeout=5
            )
        except FileNotFoundError:
            Console.warning("binwalk not installed. Skipping extraction.")
            Console.info("Install with: sudo apt-get install binwalk")
            return None

        extract_dir = path.parent / f"_{path.name}.extracted"

        try:
            Console.info("Extracting firmware with binwalk...")
            # S7: Run binwalk as the invoking user; --run-as=root removed to prevent
            # path-traversal escalation when processing untrusted firmware images.
            subprocess.run(
                ["binwalk", "-eM", "-C", str(extract_dir), str(path)],
                capture_output=True, timeout=300
            )

            if extract_dir.exists() and any(extract_dir.iterdir()):
                # S7: Post-extraction path traversal validation
                safe_root = extract_dir.resolve()
                for extracted_file in extract_dir.rglob("*"):
                    try:
                        resolved = extracted_file.resolve()
                        if not str(resolved).startswith(str(safe_root)):
                            Console.warning(
                                f"[S7] Path traversal in firmware: {extracted_file} — removing"
                            )
                            if extracted_file.is_file():
                                extracted_file.unlink(missing_ok=True)
                    except Exception:
                        pass
                return extract_dir

        except subprocess.TimeoutExpired:
            Console.warning("Firmware extraction timed out (5 min limit)")
        except Exception as e:
            logger.error(f"Extraction error: {e}")

        return None

    # ------------------------------------------------------------------ #
    # Secret detection                                                     #
    # ------------------------------------------------------------------ #

    def _find_secrets_in_directory(self, directory: Path) -> List[Dict]:
        """Recursively search for secrets in extracted filesystem."""
        secrets = []
        skip_extensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
                           ".mp3", ".mp4", ".avi", ".so", ".ko", ".o"}

        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() in skip_extensions:
                continue
            if file_path.stat().st_size > 10 * 1024 * 1024:  # Skip files > 10MB
                continue

            file_secrets = self._find_secrets_in_file(file_path)
            secrets.extend(file_secrets)

        return secrets

    def _find_secrets_in_file(self, file_path: Path) -> List[Dict]:
        """Search a single file for hardcoded secrets."""
        secrets = []

        try:
            # Try text mode first
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(512 * 1024)  # Read up to 512KB
            except Exception:
                with open(file_path, "rb") as f:
                    raw = f.read(512 * 1024)
                content = raw.decode("utf-8", errors="replace")

            for pattern, secret_type, severity in SECRET_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(0)
                    if len(value) > 4:
                        secrets.append({
                            "file":     str(file_path),
                            "type":     secret_type,
                            "severity": severity,
                            "value":    value[:128],
                            "line":     content[:match.start()].count("\n") + 1,
                        })

        except Exception as e:
            logger.debug(f"Secret scan error in {file_path}: {e}")

        return secrets

    def _extract_interesting_strings(self, directory: Path) -> List[Dict]:
        """Extract interesting strings from binaries."""
        strings = []
        interesting_patterns = [
            r"(?:http|https|ftp)://[^\s\"'<>]{8,}",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            r"(?:telnet|ssh|ftp|smtp)://[^\s]{4,}",
        ]

        for file_path in directory.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                result = subprocess.run(
                    ["strings", "-n", "8", str(file_path)],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    for pattern in interesting_patterns:
                        if re.search(pattern, line):
                            strings.append({
                                "file":  str(file_path),
                                "value": line.strip()[:256],
                            })
                            break
            except Exception:
                pass

        return strings[:200]  # Limit to 200 interesting strings
