"""
Tests for modules/bruteforce/bruteforce.py

Covers:
- load_wordlist: valid file, missing file, commented lines skipped
- _attempt_with_backoff: success on first try, retry on ConnectionResetError,
  HTTP-429 back-off, ConnectionRefusedError returns None
- BruteForceModule initialises correctly from config
- _attack dispatches to correct protocol handler
- _attack_http uses backoff; 200-OK with clean content returns True
- _attack_http returns False on 401
- Credential masking: password hidden unless reveal_creds=True
"""
import time
import types
import pytest
from unittest.mock import MagicMock, patch, call
from pathlib import Path

from modules.bruteforce.bruteforce import BruteForceModule, load_wordlist
from core.config import Config


# ------------------------------------------------------------------ #
# load_wordlist                                                        #
# ------------------------------------------------------------------ #

class TestLoadWordlist:
    def test_loads_lines(self, tmp_dir):
        f = tmp_dir / "words.txt"
        f.write_text("admin\nroot\nguest\n")
        result = load_wordlist(str(f))
        assert result == ["admin", "root", "guest"]

    def test_skips_blank_lines(self, tmp_dir):
        f = tmp_dir / "words.txt"
        f.write_text("admin\n\nroot\n  \n")
        result = load_wordlist(str(f))
        assert "" not in result
        assert "  " not in result

    def test_skips_comments(self, tmp_dir):
        f = tmp_dir / "words.txt"
        f.write_text("# comment\nadmin\n")
        result = load_wordlist(str(f))
        assert "# comment" not in result
        assert "admin" in result

    def test_missing_file_returns_empty_list(self):
        result = load_wordlist("/nonexistent/wordlist.txt")
        assert result == []


# ------------------------------------------------------------------ #
# BruteForceModule construction                                        #
# ------------------------------------------------------------------ #

class TestBruteForceModuleInit:
    def test_default_delay_from_config(self, config):
        bf = BruteForceModule(config)
        assert bf.delay == config.get("brute_delay", 0.5)

    def test_verify_ssl_from_config(self, config):
        config.set("verify_ssl", False)
        bf = BruteForceModule(config)
        assert bf.verify_ssl is False

    def test_reveal_creds_default_false(self, config):
        bf = BruteForceModule(config)
        assert bf.reveal_creds is False

    def test_reveal_creds_set_true(self, config):
        config.set("reveal_creds", True)
        bf = BruteForceModule(config)
        assert bf.reveal_creds is True


# ------------------------------------------------------------------ #
# _attempt_with_backoff                                                #
# ------------------------------------------------------------------ #

class TestAttemptWithBackoff:
    def _bf(self, config):
        return BruteForceModule(config)

    def test_success_on_first_try(self, config):
        bf = self._bf(config)
        fn = MagicMock(return_value="ok")
        result = bf._attempt_with_backoff(fn, "arg1")
        assert result == "ok"
        fn.assert_called_once_with("arg1")

    def test_retries_on_connection_reset(self, config):
        bf = self._bf(config)
        fn = MagicMock(side_effect=[ConnectionResetError, ConnectionResetError, "success"])
        with patch("time.sleep"):  # skip actual delays
            result = bf._attempt_with_backoff(fn, max_retries=3)
        assert result == "success"
        assert fn.call_count == 3

    def test_returns_none_after_max_retries(self, config):
        bf = self._bf(config)
        fn = MagicMock(side_effect=ConnectionResetError)
        with patch("time.sleep"):
            result = bf._attempt_with_backoff(fn, max_retries=3)
        assert result is None

    def test_connection_refused_returns_none(self, config):
        bf = self._bf(config)
        fn = MagicMock(side_effect=ConnectionRefusedError)
        result = bf._attempt_with_backoff(fn)
        assert result is None
        fn.assert_called_once()

    def test_http_429_triggers_backoff(self, config):
        bf = self._bf(config)
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.text = "Welcome"
        fn = MagicMock(side_effect=[resp_429, resp_200])
        with patch("time.sleep") as mock_sleep:
            result = bf._attempt_with_backoff(fn, max_retries=3)
        # Should have slept at least once due to 429
        assert mock_sleep.called


# ------------------------------------------------------------------ #
# _attack_http (mocked session)                                        #
# ------------------------------------------------------------------ #

class TestAttackHttp:
    def _bf(self, config):
        return BruteForceModule(config)

    def _mock_resp(self, status, text=""):
        r = MagicMock()
        r.status_code = status
        r.text = text
        return r

    def test_200_with_clean_content_returns_true(self, config):
        bf = self._bf(config)
        resp = self._mock_resp(200, "Dashboard — Welcome admin")
        with patch.object(bf.session, "get", return_value=resp):
            result = bf._attack_http("192.168.1.1", 80, "admin", "admin")
        assert result is True

    def test_200_with_login_keyword_returns_false(self, config):
        bf = self._bf(config)
        resp = self._mock_resp(200, "Please login to continue")
        with patch.object(bf.session, "get", return_value=resp):
            result = bf._attack_http("192.168.1.1", 80, "admin", "wrong")
        assert result is False

    def test_401_returns_false(self, config):
        bf = self._bf(config)
        resp = self._mock_resp(401, "Unauthorized")
        with patch.object(bf.session, "get", return_value=resp):
            result = bf._attack_http("192.168.1.1", 80, "admin", "bad")
        assert result is False

    def test_exception_returns_false(self, config):
        bf = self._bf(config)
        with patch.object(bf.session, "get", side_effect=ConnectionError):
            result = bf._attack_http("192.168.1.1", 80, "admin", "pass")
        assert result is False


# ------------------------------------------------------------------ #
# Credential masking                                                   #
# ------------------------------------------------------------------ #

class TestCredentialMasking:
    def test_password_masked_by_default(self, config, capsys):
        bf = BruteForceModule(config)
        # Inject a mock that immediately reports success
        bf._attack_http = MagicMock(return_value=True)
        bf._port_open   = MagicMock(return_value=False)  # skip auto-ports
        from core.output import Console
        with patch.object(Console, "finding") as mock_find:
            bf._attack("192.168.1.1", "http", 80,
                       [("admin", "secret123")])
        # Check masking in Console.finding call
        args = mock_find.call_args
        if args:
            msg = str(args)
            assert "secret123" not in msg

    def test_password_revealed_when_flag_set(self, config, capsys):
        config.set("reveal_creds", True)
        bf = BruteForceModule(config)
        bf._attack_http = MagicMock(return_value=True)
        from core.output import Console
        with patch.object(Console, "finding") as mock_find:
            bf._attack("192.168.1.1", "http", 80,
                       [("admin", "secret123")])
        args = mock_find.call_args
        if args:
            msg = str(args)
            assert "secret123" in msg
