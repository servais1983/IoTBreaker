#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Shodan Intelligence Module

Provides IoT threat intelligence via the Shodan API:
  - IP address lookup with full host information
  - Device search with faceted analysis
  - CVE exposure analysis
  - Geographic and organizational intelligence
"""

import os
from typing import Dict, List, Optional, Any

from core.logger import get_logger
from core.output import Console
from core.config import Config

logger = get_logger(__name__)


class ShodanIntel:
    """
    Shodan API integration for IoT intelligence gathering.

    Requires a valid Shodan API key set via the SHODAN_API_KEY
    environment variable or provided directly.
    """

    def __init__(self, config: Config):
        self.config = config
        self._api_key: Optional[str] = config.get("shodan_api_key") or os.getenv("SHODAN_API_KEY")
        self._api = None

    def set_api_key(self, key: str):
        """Set the Shodan API key."""
        self._api_key = key
        self._api = None  # Reset cached API object

    def _get_api(self):
        """Initialize and return the Shodan API client."""
        if self._api is None:
            try:
                import shodan
                if not self._api_key:
                    raise ValueError("Shodan API key not configured.")
                self._api = shodan.Shodan(self._api_key)
            except ImportError:
                raise RuntimeError("shodan package not installed. Run: pip install shodan")
        return self._api

    def lookup_ip(self, ip: str) -> Optional[Dict]:
        """
        Retrieve full Shodan information for an IP address.

        Parameters
        ----------
        ip : str
            Target IP address.

        Returns
        -------
        dict or None
            Normalized host information dictionary.
        """
        try:
            api = self._get_api()
            host = api.host(ip)

            services = []
            for item in host.get("data", []):
                svc = {
                    "port":    item.get("port"),
                    "service": item.get("_shodan", {}).get("module", "unknown"),
                    "version": item.get("version", ""),
                    "banner":  item.get("data", "")[:256],
                    "cpe":     item.get("cpe", []),
                }
                services.append(svc)

            result = {
                "ip":          ip,
                "country":     host.get("country_name", "N/A"),
                "country_code":host.get("country_code", ""),
                "city":        host.get("city", "N/A"),
                "org":         host.get("org", "N/A"),
                "isp":         host.get("isp", "N/A"),
                "asn":         host.get("asn", "N/A"),
                "hostnames":   host.get("hostnames", []),
                "domains":     host.get("domains", []),
                "ports":       host.get("ports", []),
                "tags":        host.get("tags", []),
                "vulns":       list(host.get("vulns", {}).keys()),
                "services":    services,
                "os":          host.get("os", "N/A"),
                "last_update": host.get("last_update", "N/A"),
            }

            if result["vulns"]:
                Console.warning(f"Shodan reports {len(result['vulns'])} CVE(s) for {ip}")
                for cve in result["vulns"][:10]:
                    Console.finding("HIGH", cve, "Reported by Shodan")

            return result

        except Exception as e:
            logger.error(f"Shodan IP lookup failed for {ip}: {e}")
            Console.error(f"Shodan lookup failed: {e}")
            return None

    def search(
        self,
        query: str,
        limit: int = 50,
        facets: Optional[str] = None
    ) -> List[Dict]:
        """
        Search Shodan for IoT devices matching a query.

        Parameters
        ----------
        query : str
            Shodan search query (e.g. 'product:Hikvision country:FR').
        limit : int
            Maximum number of results to return.
        facets : str, optional
            Comma-separated facet fields for aggregation.

        Returns
        -------
        list of dict
            List of matching device records.
        """
        try:
            api = self._get_api()
            Console.info(f"Shodan search: {query} (limit: {limit})")

            kwargs = {"limit": limit}
            if facets:
                kwargs["facets"] = [(f, 10) for f in facets.split(",")]

            results = api.search(query, **kwargs)
            total = results.get("total", 0)
            Console.info(f"Total matches in Shodan: {total:,}")

            devices = []
            for match in results.get("matches", []):
                device = {
                    "ip":      match.get("ip_str", ""),
                    "port":    match.get("port", ""),
                    "country": match.get("location", {}).get("country_name", "N/A"),
                    "org":     match.get("org", "N/A"),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "banner":  match.get("data", "")[:128],
                    "vulns":   list(match.get("vulns", {}).keys()),
                    "tags":    match.get("tags", []),
                    "hostnames": match.get("hostnames", []),
                }
                devices.append(device)

            return devices

        except Exception as e:
            logger.error(f"Shodan search failed: {e}")
            Console.error(f"Shodan search failed: {e}")
            return []

    def get_exploits(self, query: str, limit: int = 20) -> List[Dict]:
        """
        Search Shodan Exploits database.

        Parameters
        ----------
        query : str
            Search term (e.g. CVE ID or product name).
        limit : int
            Maximum results.

        Returns
        -------
        list of dict
        """
        try:
            api = self._get_api()
            results = api.exploits.search(query, facets=None)
            exploits = []
            for match in results.get("matches", [])[:limit]:
                exploits.append({
                    "id":          match.get("id", ""),
                    "description": match.get("description", ""),
                    "type":        match.get("type", ""),
                    "platform":    match.get("platform", ""),
                    "author":      match.get("author", ""),
                    "date":        match.get("date", ""),
                    "cve":         match.get("cve", []),
                })
            return exploits
        except Exception as e:
            logger.error(f"Shodan exploit search failed: {e}")
            return []
