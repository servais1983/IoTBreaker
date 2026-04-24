#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoTBreaker - Shared HTTP Session Factory

G7: All HTTP modules use this factory to get a pre-configured
requests.Session with proxy and SSL settings applied globally.
Operators can route all traffic through Burp Suite or OWASP ZAP
by setting IOTBREAKER_PROXY=http://127.0.0.1:8080.
"""

import requests
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.config import Config


def make_session(config: "Config") -> requests.Session:
    """
    Return a requests.Session pre-configured with:
    - Proxy (IOTBREAKER_PROXY env var or http_proxy config key)
    - SSL verification setting
    - Default User-Agent

    Usage in modules
    ----------------
    from core.http import make_session

    class MyModule:
        def __init__(self, config):
            self.session = make_session(config)
            # All self.session.get/post/put calls are automatically proxied.
    """
    session = requests.Session()

    proxy = config.get("http_proxy", "")
    if proxy:
        session.proxies = {
            "http":  proxy,
            "https": proxy,
        }

    session.verify = config.get("verify_ssl", True)
    session.headers.update({
        "User-Agent": config.get("user_agent", "IoTBreaker/4.0.0 Security Scanner"),
    })

    return session
