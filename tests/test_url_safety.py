"""Tests for app.utils.url_safety — SSRF protection module.

Covers: is_safe_url(), resolve_and_validate(), _allow_local_targets()
"""

import os
import socket
import pytest
from unittest.mock import patch, MagicMock

from app.utils.url_safety import (
    is_safe_url,
    resolve_and_validate,
    _allow_local_targets,
    _BLOCKED_RANGES,
    _BLOCKED_HOSTNAMES,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _fake_getaddrinfo(ip_str):
    """Return a mock getaddrinfo result resolving to the given IP."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip_str, 0))]


# ── _allow_local_targets() ──────────────────────────────────────────────

class TestAllowLocalTargets:
    def test_default_is_false(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ALLOW_LOCAL_TARGETS", None)
            assert _allow_local_targets() is False

    def test_true_values(self):
        for val in ("true", "True", "TRUE", "1", "yes", "Yes"):
            with patch.dict(os.environ, {"ALLOW_LOCAL_TARGETS": val}):
                assert _allow_local_targets() is True, f"Failed for ALLOW_LOCAL_TARGETS={val}"

    def test_false_values(self):
        for val in ("false", "0", "no", "anything", ""):
            with patch.dict(os.environ, {"ALLOW_LOCAL_TARGETS": val}):
                assert _allow_local_targets() is False, f"Failed for ALLOW_LOCAL_TARGETS={val}"


# ── resolve_and_validate() ──────────────────────────────────────────────

class TestResolveAndValidate:
    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_public_ip_is_safe(self, mock_dns):
        mock_dns.return_value = _fake_getaddrinfo("93.184.216.34")
        ip, is_safe, reason = resolve_and_validate("example.com")
        assert ip == "93.184.216.34"
        assert is_safe is True
        assert reason is None

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_loopback_is_blocked(self, mock_dns):
        mock_dns.return_value = _fake_getaddrinfo("127.0.0.1")
        ip, is_safe, reason = resolve_and_validate("localhost")
        assert ip == "127.0.0.1"
        assert is_safe is False
        assert "blocked" in reason.lower()

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_private_10_is_blocked(self, mock_dns):
        mock_dns.return_value = _fake_getaddrinfo("10.0.0.1")
        ip, is_safe, reason = resolve_and_validate("internal.corp")
        assert is_safe is False

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_private_172_is_blocked(self, mock_dns):
        mock_dns.return_value = _fake_getaddrinfo("172.16.0.1")
        ip, is_safe, reason = resolve_and_validate("internal.corp")
        assert is_safe is False

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_private_192_is_blocked(self, mock_dns):
        mock_dns.return_value = _fake_getaddrinfo("192.168.1.1")
        ip, is_safe, reason = resolve_and_validate("router.local")
        assert is_safe is False

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_link_local_is_blocked(self, mock_dns):
        mock_dns.return_value = _fake_getaddrinfo("169.254.169.254")
        ip, is_safe, reason = resolve_and_validate("metadata")
        assert is_safe is False
        assert "blocked" in reason.lower()

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_dns_failure(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("Name or service not known")
        ip, is_safe, reason = resolve_and_validate("nonexistent.invalid")
        assert ip is None
        assert is_safe is False
        assert "DNS resolution failed" in reason

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_empty_dns_results(self, mock_dns):
        mock_dns.return_value = []
        ip, is_safe, reason = resolve_and_validate("empty.example")
        assert ip is None
        assert is_safe is False
        assert "no results" in reason.lower()

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_unexpected_exception(self, mock_dns):
        mock_dns.side_effect = RuntimeError("unexpected")
        ip, is_safe, reason = resolve_and_validate("error.example")
        assert ip is None
        assert is_safe is False
        assert "error" in reason.lower()


# ── is_safe_url() ───────────────────────────────────────────────────────

class TestIsSafeUrl:
    """Test the main SSRF validation function.

    After BUG-001 fix, is_safe_url() ALWAYS returns a 2-tuple (bool, str).
    """

    @patch("app.utils.url_safety.resolve_and_validate")
    @patch("app.utils.url_safety._allow_local_targets", return_value=False)
    def test_public_url_is_safe(self, mock_local, mock_resolve):
        mock_resolve.return_value = ("93.184.216.34", True, None)
        is_safe, reason = is_safe_url("https://example.com/path")
        assert is_safe is True
        assert reason == ""

    @patch("app.utils.url_safety.resolve_and_validate")
    @patch("app.utils.url_safety._allow_local_targets", return_value=False)
    def test_returns_exactly_two_elements(self, mock_local, mock_resolve):
        """Regression test for BUG-001: must return 2-tuple, not 3-tuple."""
        mock_resolve.return_value = ("93.184.216.34", True, None)
        result = is_safe_url("https://example.com")
        assert len(result) == 2, f"Expected 2-tuple, got {len(result)}-tuple: {result}"

    @patch("app.utils.url_safety.resolve_and_validate")
    @patch("app.utils.url_safety._allow_local_targets", return_value=False)
    def test_private_ip_is_blocked(self, mock_local, mock_resolve):
        mock_resolve.return_value = ("192.168.1.1", False, "Resolved to blocked IP: 192.168.1.1")
        is_safe, reason = is_safe_url("http://internal.corp:8080/admin")
        assert is_safe is False
        assert "blocked" in reason.lower()

    def test_no_hostname_fails(self):
        is_safe, reason = is_safe_url("not-a-url")
        assert is_safe is False
        assert "no hostname" in reason.lower()

    def test_empty_url_fails(self):
        is_safe, reason = is_safe_url("")
        assert is_safe is False

    @patch("app.utils.url_safety._allow_local_targets", return_value=False)
    def test_cloud_metadata_always_blocked(self, mock_local):
        """Cloud metadata hostnames must be blocked regardless of settings."""
        for hostname in _BLOCKED_HOSTNAMES:
            is_safe, reason = is_safe_url(f"http://{hostname}/latest/meta-data/")
            assert is_safe is False, f"{hostname} should be blocked"
            assert "metadata" in reason.lower() or "blocked" in reason.lower()

    @patch("app.utils.url_safety._allow_local_targets", return_value=True)
    def test_cloud_metadata_blocked_even_with_local_allowed(self, mock_local):
        """Metadata endpoints must be blocked even when ALLOW_LOCAL_TARGETS=true."""
        is_safe, reason = is_safe_url("http://metadata.google.internal/computeMetadata/v1/")
        assert is_safe is False
        assert "metadata" in reason.lower() or "blocked" in reason.lower()

    @patch("app.utils.url_safety._allow_local_targets", return_value=True)
    def test_localhost_allowed_when_local_enabled(self, mock_local):
        """ALLOW_LOCAL_TARGETS=true should allow localhost."""
        is_safe, reason = is_safe_url("http://localhost:8888/dvwa/")
        assert is_safe is True
        assert reason == ""

    @patch("app.utils.url_safety._allow_local_targets", return_value=True)
    def test_private_ip_allowed_when_local_enabled(self, mock_local):
        is_safe, reason = is_safe_url("http://192.168.1.1:8080/")
        assert is_safe is True
        assert reason == ""

    @patch("app.utils.url_safety.resolve_and_validate")
    @patch("app.utils.url_safety._allow_local_targets", return_value=False)
    def test_dns_failure_is_blocked(self, mock_local, mock_resolve):
        mock_resolve.return_value = (None, False, "DNS resolution failed for: bad.host")
        is_safe, reason = is_safe_url("http://bad.host/")
        assert is_safe is False
        assert "DNS" in reason or "failed" in reason.lower()

    def test_url_with_port_parses_correctly(self):
        """URL with port number should still parse the hostname."""
        # This exercises the urlparse path — hostname should be extracted
        with patch("app.utils.url_safety._allow_local_targets", return_value=True):
            is_safe, reason = is_safe_url("http://localhost:3000/api")
            assert is_safe is True

    @patch("app.utils.url_safety.resolve_and_validate")
    @patch("app.utils.url_safety._allow_local_targets", return_value=False)
    def test_loopback_127_blocked(self, mock_local, mock_resolve):
        mock_resolve.return_value = ("127.0.0.1", False, "Resolved to blocked IP: 127.0.0.1")
        is_safe, reason = is_safe_url("http://127.0.0.1/")
        assert is_safe is False

    @patch("app.utils.url_safety.resolve_and_validate")
    @patch("app.utils.url_safety._allow_local_targets", return_value=False)
    def test_validation_error_returns_false(self, mock_local, mock_resolve):
        mock_resolve.side_effect = RuntimeError("boom")
        is_safe, reason = is_safe_url("http://crash.example/")
        assert is_safe is False
        assert "error" in reason.lower()


# ── Blocked ranges coverage ─────────────────────────────────────────────

class TestBlockedRanges:
    """Verify our blocked IP ranges cover all expected private/internal ranges."""

    def test_blocked_ranges_exist(self):
        assert len(_BLOCKED_RANGES) >= 8, "Should have at least 8 blocked ranges"

    def test_blocked_hostnames_exist(self):
        assert "metadata.google.internal" in _BLOCKED_HOSTNAMES
        assert "metadata" in _BLOCKED_HOSTNAMES

    @patch("app.utils.url_safety.socket.getaddrinfo")
    def test_cloud_metadata_ip_169_254_blocked(self, mock_dns):
        """AWS/GCP metadata endpoint IP (169.254.169.254) should be blocked."""
        mock_dns.return_value = _fake_getaddrinfo("169.254.169.254")
        ip, is_safe, reason = resolve_and_validate("some-host")
        assert is_safe is False
