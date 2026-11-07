"""Offline tests for FirmwareAnalyzer.

Extraction is disabled or patched. No binwalk process is started and no
network call is made.
"""

import hashlib
from unittest.mock import patch

from modules.firmware.firmware import FirmwareAnalyzer


class TestFirmwareRun:
    def test_missing_file_returns_none(self, config):
        analyzer = FirmwareAnalyzer(config)
        assert analyzer.run("/no/such/firmware.bin", extract=False, find_secrets=False) is None

    def test_local_file_metadata_without_extraction(self, config, tmp_path):
        blob = tmp_path / "sample.bin"
        payload = b"\x1f\x8b" + b"\x00" * 32
        blob.write_bytes(payload)
        analyzer = FirmwareAnalyzer(config)
        with patch.object(analyzer, "_extract_firmware") as extract:
            result = analyzer.run(
                str(blob),
                extract=False,
                find_secrets=False,
                entropy_analysis=True,
            )
        extract.assert_not_called()
        assert result["file_type"] == "Gzip Archive"
        assert result["md5"] == hashlib.md5(payload).hexdigest()
        assert result["sha256"] == hashlib.sha256(payload).hexdigest()
        assert result["entropy"] == analyzer._compute_entropy(blob)
        assert result["extracted_path"] is None

    def test_elf_architecture_from_header(self, config, tmp_path):
        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 1  # 32-bit
        header[5] = 1  # little-endian
        header[18:20] = (0x28).to_bytes(2, "little")  # ARM
        path = tmp_path / "tiny.elf"
        path.write_bytes(header)
        analyzer = FirmwareAnalyzer(config)
        with patch.object(analyzer, "_binwalk_architecture") as binwalk:
            arch = analyzer._detect_architecture(path)
        binwalk.assert_not_called()
        assert arch == "ARM (32-bit, little-endian)"

    def test_empty_file_entropy_is_zero(self, config, tmp_path):
        path = tmp_path / "empty.bin"
        path.write_bytes(b"")
        analyzer = FirmwareAnalyzer(config)
        assert analyzer._compute_entropy(path) == 0.0


class TestExtractionGuard:
    def test_sibling_prefix_is_outside(self, tmp_path):
        root = tmp_path / "out.extracted"
        root.mkdir()
        sibling = tmp_path / "out.extracted-evil"
        sibling.mkdir()
        escaped = sibling / "file.txt"
        escaped.write_text("nope")
        inside = root / "ok.txt"
        inside.write_text("ok")
        assert FirmwareAnalyzer._is_inside(inside, root) is True
        assert FirmwareAnalyzer._is_inside(escaped, root) is False

    def test_human_size(self, config):
        analyzer = FirmwareAnalyzer(config)
        assert analyzer._human_size(512) == "512.0 B"
        assert analyzer._human_size(2048) == "2.0 KB"
