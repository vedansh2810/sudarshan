"""
URL safety validation — blocks SSRF to internal/cloud targets.

Used by:
  - Webhook delivery (app/models/webhook.py)
  - Scan target validation (app/routes/scan.py)

Uses only stdlib: socket, ipaddress, urllib.parse, os — no new dependencies.

Set ALLOW_LOCAL_TARGETS=true in .env to allow scanning localhost / private IPs
(e.g. DVWA on localhost:8888).
"""

import os
import socket
import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _allow_local_targets() -> bool:
    """Read at call time so .env changes are picked up after load_dotenv()."""
    return os.getenv("ALLOW_LOCAL_TARGETS", "false").lower() in ("true", "1", "yes")


# IP ranges that must never be reached via user-supplied URLs
_BLOCKED_RANGES = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # RFC-1918 private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    # Cloud metadata
    ipaddress.ip_network("fd00:ec2::/32"),
    # Unique-local (IPv6 private)
    ipaddress.ip_network("fc00::/7"),
]

# Hostnames that are always blocked regardless of resolution
_BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.google",
    "metadata",
}


def resolve_and_validate(hostname):
    """Resolve hostname and validate the resolved IP is safe.

    Returns (ip_string, is_safe, reason).
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not results:
            return None, False, f"DNS resolution returned no results for: {hostname}"
        ip_str = results[0][4][0]
        ip = ipaddress.ip_address(ip_str)
        for blocked in _BLOCKED_RANGES:
            if ip in blocked:
                return ip_str, False, f"Resolved to blocked IP: {ip_str}"
        return ip_str, True, None
    except socket.gaierror:
        return None, False, f"DNS resolution failed for: {hostname}"
    except Exception as e:
        return None, False, f"IP validation error: {e}"


def is_safe_url(url: str) -> tuple[bool, str]:
    """Validate that a URL does not resolve to a blocked IP range.

    Returns:
        (is_safe, reason) — True with empty reason if safe,
        False with human-readable reason if blocked.

    The resolved IP can be obtained separately via get_pinned_ip()
    to prevent DNS rebinding after validation.

    Algorithm:
        1. Parse the URL and extract the hostname.
        2. Reject known cloud metadata hostnames.
        3. Resolve the hostname via resolve_and_validate().
        4. Check the resolved IP against the blocked ranges.
        5. Reject if the resolved IP falls in a blocked range.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False, "URL has no hostname"

        # Always block cloud metadata hostnames even in local mode
        if hostname.lower() in _BLOCKED_HOSTNAMES:
            return False, f'Hostname "{hostname}" is a blocked cloud metadata endpoint'

        # Allow localhost / private IPs when explicitly enabled
        if _allow_local_targets():
            return True, ""

        # Resolve and validate hostname via single code path
        ip_str, is_safe, reason = resolve_and_validate(hostname)
        if not is_safe:
            return False, reason or f'Hostname "{hostname}" failed validation'

        return True, ""

    except Exception as e:
        logger.warning(f"URL safety check error: {e}")
        return False, f"URL validation error: {e}"

