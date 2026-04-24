"""
Tests for core/http.py

Covers:
- make_session returns requests.Session
- verify is set from config
- Proxy is applied when http_proxy is set
- User-Agent header is set
- No proxy when http_proxy is empty
"""
import pytest
import requests

from core.http import make_session
from core.config import Config


class TestMakeSession:
    def test_returns_requests_session(self, config):
        s = make_session(config)
        assert isinstance(s, requests.Session)

    def test_verify_ssl_true_by_default(self, config):
        s = make_session(config)
        assert s.verify is True

    def test_verify_ssl_false_when_disabled(self, config):
        config.set("verify_ssl", False)
        s = make_session(config)
        assert s.verify is False

    def test_proxy_set_when_configured(self, config):
        config.set("http_proxy", "http://127.0.0.1:8080")
        s = make_session(config)
        assert s.proxies.get("http") == "http://127.0.0.1:8080"
        assert s.proxies.get("https") == "http://127.0.0.1:8080"

    def test_no_proxy_when_empty(self, config):
        config.set("http_proxy", "")
        s = make_session(config)
        # proxies dict may be empty or not contain http/https
        assert not s.proxies.get("http")

    def test_user_agent_header_set(self, config):
        s = make_session(config)
        assert "IoTBreaker" in s.headers.get("User-Agent", "")

    def test_custom_user_agent(self, config):
        config.set("user_agent", "CustomAgent/1.0")
        s = make_session(config)
        assert s.headers["User-Agent"] == "CustomAgent/1.0"

    def test_separate_calls_return_independent_sessions(self, config):
        s1 = make_session(config)
        s2 = make_session(config)
        assert s1 is not s2
