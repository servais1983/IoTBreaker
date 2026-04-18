#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - CVE / NVD Lookup Module

Queries the NIST National Vulnerability Database (NVD) API v2.0
for CVE information, CVSS scores, and affected product enumeration.

API documentation: https://nvd.nist.gov/developers/vulnerabilities
"""

import time
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.logger import get_logger
from core.config import Config

logger = get_logger(__name__)


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_BASE = "https://services.nvd.nist.gov/rest/json/cve/2.0/{cve_id}"

# Rate limit: NVD allows 5 req/30s without API key, 50 req/30s with key
REQUEST_DELAY_NO_KEY = 6.0
REQUEST_DELAY_WITH_KEY = 0.6

# CVSS v3 severity thresholds
CVSS_SEVERITY = {
    (9.0, 10.0): "CRITICAL",
    (7.0, 8.9):  "HIGH",
    (4.0, 6.9):  "MEDIUM",
    (0.1, 3.9):  "LOW",
    (0.0, 0.0):  "NONE",
}


def cvss_to_severity(score: float) -> str:
    """Convert a CVSS v3 score to a severity label."""
    if score is None:
        return "UNKNOWN"
    for (low, high), label in CVSS_SEVERITY.items():
        if low <= score <= high:
            return label
    return "UNKNOWN"


class CVELookup:
    """
    NVD CVE database client.

    Provides CVE lookup by ID, vendor/product search,
    and severity-filtered queries for IoT-relevant vulnerabilities.
    """

    def __init__(self, config: Config):
        self.config = config
        self.api_key = config.get("nvd_api_key") or ""
        self._last_request = 0.0
        self._cache: Dict[str, Any] = {}

    def _rate_limit(self):
        """Enforce NVD API rate limiting."""
        delay = REQUEST_DELAY_WITH_KEY if self.api_key else REQUEST_DELAY_NO_KEY
        elapsed = time.time() - self._last_request
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request = time.time()

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def get_by_id(self, cve_id: str) -> Optional[Dict]:
        """
        Retrieve full CVE details by CVE identifier.

        Parameters
        ----------
        cve_id : str
            CVE identifier (e.g. CVE-2021-36260).

        Returns
        -------
        dict or None
            Normalized CVE data dictionary.
        """
        if cve_id in self._cache:
            return self._cache[cve_id]

        self._rate_limit()
        try:
            url = NVD_CVE_BASE.format(cve_id=cve_id)
            resp = requests.get(url, headers=self._get_headers(), timeout=15)
            resp.raise_for_status()
            data = resp.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            result = self._normalize_cve(vulns[0].get("cve", {}))
            self._cache[cve_id] = result
            return result

        except requests.exceptions.HTTPError as e:
            logger.warning(f"NVD API HTTP error for {cve_id}: {e}")
        except Exception as e:
            logger.debug(f"CVE lookup failed for {cve_id}: {e}")

        return None

    def search(
        self,
        vendor: str = None,
        product: str = None,
        cve_id: str = None,
        severity: str = None,
        year: int = None,
        limit: int = 20
    ) -> List[Dict]:
        """
        Search the NVD database for CVEs.

        Parameters
        ----------
        vendor : str, optional
            CPE vendor name.
        product : str, optional
            CPE product name.
        cve_id : str, optional
            Specific CVE ID to look up.
        severity : str, optional
            Minimum severity: critical, high, medium, low.
        year : int, optional
            Publication year filter.
        limit : int
            Maximum number of results.

        Returns
        -------
        list of dict
            List of normalized CVE records.
        """
        if cve_id:
            result = self.get_by_id(cve_id)
            return [result] if result else []

        self._rate_limit()
        params = {"resultsPerPage": min(limit, 2000), "startIndex": 0}

        # Keyword-based search (vendor/product)
        if vendor or product:
            keywords = []
            if vendor:
                keywords.append(vendor)
            if product:
                keywords.append(product)
            params["keywordSearch"] = " ".join(keywords)

        # Severity filter
        if severity:
            sev_map = {
                "critical": "CRITICAL",
                "high":     "HIGH",
                "medium":   "MEDIUM",
                "low":      "LOW",
            }
            params["cvssV3Severity"] = sev_map.get(severity.lower(), "HIGH")

        # Year filter
        if year:
            params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
            params["pubEndDate"] = f"{year}-12-31T23:59:59.999"

        try:
            resp = requests.get(
                NVD_API_BASE,
                params=params,
                headers=self._get_headers(),
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()

            results = []
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                normalized = self._normalize_cve(cve_data)
                if normalized:
                    results.append(normalized)

            return results

        except requests.exceptions.HTTPError as e:
            logger.warning(f"NVD API HTTP error: {e}")
        except Exception as e:
            logger.error(f"CVE search failed: {e}")

        return []

    def _normalize_cve(self, cve: Dict) -> Optional[Dict]:
        """Normalize a raw NVD CVE record into a clean dictionary."""
        if not cve:
            return None

        cve_id = cve.get("id", "")

        # Extract English description
        descriptions = cve.get("descriptions", [])
        summary = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )

        # Extract CVSS v3.1 score (prefer v3.1 over v3.0)
        metrics = cve.get("metrics", {})
        cvss_score = None
        cvss_vector = None

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(key, [])
            if metric_list:
                m = metric_list[0].get("cvssData", {})
                cvss_score = m.get("baseScore")
                cvss_vector = m.get("vectorString")
                break

        severity = cvss_to_severity(cvss_score) if cvss_score else "UNKNOWN"

        # Extract CWE
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        # Extract affected configurations
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        cpe = cpe_match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) >= 5:
                            affected.append(f"{parts[3]}:{parts[4]}")

        # Published date
        published = cve.get("published", "")[:10]

        return {
            "id":           cve_id,
            "summary":      summary[:512],
            "cvss_score":   cvss_score,
            "cvss_vector":  cvss_vector,
            "severity":     severity,
            "cwe_ids":      list(set(cwe_ids)),
            "affected":     list(set(affected))[:10],
            "published":    published,
            "url":          f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
