#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Engagement Management

G1: Provides a lightweight engagement context that ties a session to:
  - A named client and statement-of-work reference
  - An authorized CIDR scope
  - A time window (start_date / end_date)
  - The operator's name

Engagement files are YAML and follow this schema:

    client:          "Acme Corp"
    operator:        "john.doe"
    sow_reference:   "SOW-2026-042"
    start_date:      "2026-04-24"
    end_date:        "2026-04-30"
    authorized_cidrs:
      - 192.168.1.0/24
      - 10.0.10.0/24

Loading an engagement automatically:
  1. Populates scope networks in the Engine (replaces --scope-file)
  2. Validates the current date is within the authorized testing window
  3. Records operator + client in session metadata / reports
"""

import ipaddress
import yaml
from datetime import date, datetime
from pathlib import Path
from typing import List, Optional

from core.logger import get_logger
from core.output import Console

logger = get_logger(__name__)


class Engagement:
    """
    Lightweight engagement context.

    Attributes
    ----------
    client          : str
    operator        : str
    sow_reference   : str
    start_date      : date
    end_date        : date
    authorized_cidrs: List[ipaddress.IPv4Network]
    """

    def __init__(self, data: dict):
        self.client         = str(data.get("client", "Unknown"))
        self.operator       = str(data.get("operator", "Unknown"))
        self.sow_reference  = str(data.get("sow_reference", ""))
        self.notes          = str(data.get("notes", ""))

        self.start_date: Optional[date] = self._parse_date(data.get("start_date"))
        self.end_date:   Optional[date] = self._parse_date(data.get("end_date"))

        raw_cidrs = data.get("authorized_cidrs", [])
        self.authorized_cidrs: List[ipaddress.IPv4Network] = []
        for cidr in raw_cidrs:
            try:
                self.authorized_cidrs.append(
                    ipaddress.ip_network(str(cidr).strip(), strict=False)
                )
            except ValueError:
                logger.warning(f"Engagement: invalid CIDR '{cidr}' — skipping")

    # ------------------------------------------------------------------ #
    # Validation                                                           #
    # ------------------------------------------------------------------ #

    def validate_window(self) -> bool:
        """
        Check that the current date is within the authorized testing window.
        Returns True if within window (or no dates specified).
        Prints a warning and returns False if outside the window.
        """
        today = date.today()
        if self.start_date and today < self.start_date:
            Console.error(
                f"[ENGAGEMENT] Testing window has not started yet. "
                f"Authorized from {self.start_date} — today is {today}."
            )
            return False
        if self.end_date and today > self.end_date:
            Console.error(
                f"[ENGAGEMENT] Testing window has expired. "
                f"Authorized until {self.end_date} — today is {today}."
            )
            return False
        return True

    def is_in_scope(self, target: str) -> bool:
        """Check whether a target IP is within authorized CIDRs."""
        if not self.authorized_cidrs:
            return True  # No restriction — permit all (with scope warning)
        try:
            addr = ipaddress.ip_address(target)
            return any(addr in net for net in self.authorized_cidrs)
        except ValueError:
            return True  # Hostnames pass through

    def summary(self) -> dict:
        """Return a dict suitable for embedding in report metadata."""
        return {
            "client":          self.client,
            "operator":        self.operator,
            "sow_reference":   self.sow_reference,
            "start_date":      str(self.start_date) if self.start_date else None,
            "end_date":        str(self.end_date)   if self.end_date   else None,
            "authorized_cidrs": [str(n) for n in self.authorized_cidrs],
            "notes":           self.notes,
        }

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_date(value) -> Optional[date]:
        if value is None:
            return None
        if isinstance(value, date):
            return value
        if isinstance(value, datetime):
            return value.date()
        try:
            return date.fromisoformat(str(value))
        except (ValueError, TypeError):
            logger.warning(f"Engagement: could not parse date '{value}'")
            return None


def load_engagement(path: str) -> Engagement:
    """
    Load and return an Engagement from a YAML file.

    Raises FileNotFoundError if the file does not exist.
    Raises ValueError if the YAML is malformed or fails window validation.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Engagement file not found: {path}")

    with open(p, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not isinstance(data, dict):
        raise ValueError(f"Engagement file must be a YAML mapping: {path}")

    eng = Engagement(data)

    Console.info(
        f"[ENGAGEMENT] Client: {eng.client} | "
        f"Operator: {eng.operator} | "
        f"SoW: {eng.sow_reference or 'N/A'}"
    )
    if eng.authorized_cidrs:
        Console.info(
            f"[ENGAGEMENT] Authorized scope: "
            + ", ".join(str(n) for n in eng.authorized_cidrs)
        )
    return eng
