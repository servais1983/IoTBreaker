#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Console Output Manager

Provides consistent, professional console output with severity-coded
prefixes and structured result display.
"""

import sys
from typing import List, Dict, Any, Optional


class Console:
    """
    Static helper class for formatted console output.

    All output is written to stdout. Error and warning messages
    are written to stderr to allow clean pipeline usage.
    """

    # ANSI color codes
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    MAGENTA = "\033[95m"
    GRAY    = "\033[90m"

    _use_color: bool = sys.stdout.isatty()

    @classmethod
    def _c(cls, color: str, text: str) -> str:
        if cls._use_color:
            return f"{color}{text}{cls.RESET}"
        return text

    @classmethod
    def info(cls, message: str):
        """Informational message."""
        print(f"{cls._c(cls.BLUE, '[*]')} {message}")

    @classmethod
    def success(cls, message: str):
        """Success or positive finding."""
        print(f"{cls._c(cls.GREEN, '[+]')} {message}")

    @classmethod
    def warning(cls, message: str):
        """Warning message."""
        print(f"{cls._c(cls.YELLOW, '[!]')} {message}", file=sys.stderr)

    @classmethod
    def error(cls, message: str):
        """Error message."""
        print(f"{cls._c(cls.RED, '[ERROR]')} {message}", file=sys.stderr)

    @classmethod
    def debug(cls, message: str):
        """Debug message (only shown in verbose mode)."""
        print(f"{cls._c(cls.GRAY, '[DEBUG]')} {message}")

    @classmethod
    def section(cls, title: str):
        """Print a section header."""
        width = 70
        line = "-" * width
        print(f"\n{cls._c(cls.CYAN + cls.BOLD, line)}")
        print(f"{cls._c(cls.CYAN + cls.BOLD, f'  {title}')}")
        print(f"{cls._c(cls.CYAN + cls.BOLD, line)}")

    @classmethod
    def finding(cls, severity: str, title: str, detail: str = ""):
        """
        Print a security finding with severity coloring.

        Parameters
        ----------
        severity : str
            One of: CRITICAL, HIGH, MEDIUM, LOW, INFO
        title : str
            Short description of the finding.
        detail : str, optional
            Additional detail or evidence.
        """
        color_map = {
            "CRITICAL": cls.RED,
            "HIGH":     cls.RED,
            "MEDIUM":   cls.YELLOW,
            "LOW":      cls.BLUE,
            "INFO":     cls.CYAN,
        }
        sev = severity.upper()
        color = color_map.get(sev, cls.WHITE)
        badge = cls._c(color + cls.BOLD, f"[{sev}]")
        print(f"  {badge} {title}")
        if detail:
            print(f"         {cls._c(cls.GRAY, detail)}")

    @classmethod
    def table(cls, headers: List[str], rows: List[List[Any]], title: str = ""):
        """
        Print a formatted table.

        Parameters
        ----------
        headers : list of str
            Column headers.
        rows : list of list
            Table data rows.
        title : str, optional
            Table title.
        """
        if not rows:
            return

        if title:
            print(f"\n  {cls._c(cls.BOLD, title)}")

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # Header
        header_row = "  | " + " | ".join(
            h.ljust(col_widths[i]) for i, h in enumerate(headers)
        ) + " |"
        separator = "  +" + "+".join("-" * (w + 2) for w in col_widths) + "+"

        print(separator)
        print(cls._c(cls.BOLD, header_row))
        print(separator)

        # Data rows
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    cells.append(str(cell).ljust(col_widths[i]))
            print("  | " + " | ".join(cells) + " |")

        print(separator)

    @classmethod
    def progress(cls, current: int, total: int, label: str = ""):
        """Print an inline progress indicator."""
        pct = int((current / total) * 100) if total > 0 else 0
        bar_len = 30
        filled = int(bar_len * current / total) if total > 0 else 0
        bar = "#" * filled + "-" * (bar_len - filled)
        print(f"\r  [{bar}] {pct:3d}% {label}", end="", flush=True)
        if current >= total:
            print()

    @classmethod
    def result_summary(cls, findings: List[Dict]):
        """Print a final summary of all findings."""
        if not findings:
            cls.info("No vulnerabilities found.")
            return

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1

        cls.section("ASSESSMENT SUMMARY")
        print(f"  Total findings: {len(findings)}")
        print()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts[sev] > 0:
                cls.finding(sev, f"{counts[sev]} finding(s)")
        print()
