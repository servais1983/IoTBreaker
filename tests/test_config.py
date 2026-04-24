"""
Tests for core/config.py

Covers:
- DEFAULTS schema completeness
- Config.get / Config.set
- Config.load_file (valid YAML, unknown key warning, JSON, missing file)
- Environment variable loading
- Config.__repr__ masks sensitive keys
"""
import os
import json
import warnings
import tempfile
import pytest
import yaml

from core.config import Config, DEFAULTS


# ------------------------------------------------------------------ #
# DEFAULTS                                                             #
# ------------------------------------------------------------------ #

class TestDefaults:
    REQUIRED_KEYS = [
        "timeout", "threads", "output_dir", "report_format", "verbose",
        "rate_limit", "retry_count", "user_agent", "shodan_api_key",
        "nvd_api_key", "iot_ports", "wordlist_users", "wordlist_passwords",
        "wordlist_web_paths", "safe_mode", "verify_ssl", "http_proxy",
        "follow_redirects", "max_redirects", "banner_grab_timeout",
        "brute_delay", "stop_on_success", "siem",
    ]

    def test_all_required_keys_present(self):
        for key in self.REQUIRED_KEYS:
            assert key in DEFAULTS, f"DEFAULTS missing key: {key}"

    def test_verify_ssl_default_true(self):
        assert DEFAULTS["verify_ssl"] is True

    def test_brute_delay_at_least_half_second(self):
        assert DEFAULTS["brute_delay"] >= 0.5

    def test_iot_ports_is_list(self):
        assert isinstance(DEFAULTS["iot_ports"], list)
        assert len(DEFAULTS["iot_ports"]) > 10

    def test_siem_is_empty_dict(self):
        assert DEFAULTS["siem"] == {}


# ------------------------------------------------------------------ #
# Config.get / Config.set                                              #
# ------------------------------------------------------------------ #

class TestGetSet:
    def test_get_returns_default_value(self, config):
        assert config.get("timeout") == DEFAULTS["timeout"]

    def test_get_missing_key_returns_none(self, config):
        assert config.get("__nonexistent__") is None

    def test_get_missing_key_returns_provided_default(self, config):
        assert config.get("__nonexistent__", 42) == 42

    def test_set_overrides_value(self, config):
        config.set("timeout", 99)
        assert config.get("timeout") == 99

    def test_set_none_is_noop(self, config):
        original = config.get("timeout")
        config.set("timeout", None)
        assert config.get("timeout") == original

    def test_set_new_key(self, config):
        config.set("custom_key", "hello")
        assert config.get("custom_key") == "hello"

    def test_all_returns_dict(self, config):
        data = config.all()
        assert isinstance(data, dict)
        assert "timeout" in data


# ------------------------------------------------------------------ #
# Config.load_file                                                      #
# ------------------------------------------------------------------ #

class TestLoadFile:
    def test_load_valid_yaml(self, config, tmp_dir):
        cfg_file = tmp_dir / "test.yml"
        cfg_file.write_text("timeout: 30\nverbose: 2\n")
        config.load_file(str(cfg_file))
        assert config.get("timeout") == 30
        assert config.get("verbose") == 2

    def test_load_valid_json(self, config, tmp_dir):
        cfg_file = tmp_dir / "test.json"
        cfg_file.write_text(json.dumps({"timeout": 15}))
        config.load_file(str(cfg_file))
        assert config.get("timeout") == 15

    def test_unknown_key_emits_warning(self, config, tmp_dir):
        cfg_file = tmp_dir / "test.yml"
        cfg_file.write_text("unknown_custom_key: 99\n")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            config.load_file(str(cfg_file))
        assert any("unknown_custom_key" in str(w.message) for w in caught)

    def test_unknown_key_not_merged(self, config, tmp_dir):
        cfg_file = tmp_dir / "test.yml"
        cfg_file.write_text("unknown_custom_key: 99\n")
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            config.load_file(str(cfg_file))
        assert config.get("unknown_custom_key") is None

    def test_missing_file_raises(self, config):
        with pytest.raises(FileNotFoundError):
            config.load_file("/nonexistent/path/config.yml")

    def test_unsupported_extension_raises(self, config, tmp_dir):
        f = tmp_dir / "test.toml"
        f.write_text("[section]\nkey = 1\n")
        with pytest.raises(ValueError):
            config.load_file(str(f))


# ------------------------------------------------------------------ #
# Environment variable loading                                         #
# ------------------------------------------------------------------ #

class TestEnvVars:
    def test_iotbreaker_proxy_loaded(self, monkeypatch):
        monkeypatch.setenv("IOTBREAKER_PROXY", "http://127.0.0.1:8080")
        c = Config()
        assert c.get("http_proxy") == "http://127.0.0.1:8080"

    def test_iotbreaker_verify_ssl_false(self, monkeypatch):
        monkeypatch.setenv("IOTBREAKER_VERIFY_SSL", "false")
        c = Config()
        assert c.get("verify_ssl") is False

    def test_iotbreaker_verify_ssl_true(self, monkeypatch):
        monkeypatch.setenv("IOTBREAKER_VERIFY_SSL", "1")
        c = Config()
        assert c.get("verify_ssl") is True

    def test_iotbreaker_timeout_int(self, monkeypatch):
        monkeypatch.setenv("IOTBREAKER_TIMEOUT", "20")
        c = Config()
        assert c.get("timeout") == 20


# ------------------------------------------------------------------ #
# __repr__                                                             #
# ------------------------------------------------------------------ #

class TestRepr:
    def test_repr_masks_api_key(self, config):
        config.set("shodan_api_key", "super_secret")
        r = repr(config)
        assert "super_secret" not in r
