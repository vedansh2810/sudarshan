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


# IP ranges that must ALWAYS be blocked, even when ALLOW_LOCAL_TARGETS=true
_ALWAYS_BLOCKED_RANGES = [
    # Cloud metadata endpoints (AWS, GCP, Azure)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fd00:ec2::/32"),
    # "This" network — used for SSRF tricks
    ipaddress.ip_network("0.0.0.0/8"),
]

# IP ranges blocked unless ALLOW_LOCAL_TARGETS is enabled
_BLOCKED_RANGES = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    # RFC-1918 private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # Link-local (covered by ALWAYS_BLOCKED but kept for completeness)
    ipaddress.ip_network("fe80::/10"),
    # Carrier-Grade NAT (shared address space)
    ipaddress.ip_network("100.64.0.0/10"),
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
        # Check ALL resolved IPs to prevent multi-A-record DNS rebinding
        all_ips = list({r[4][0] for r in results})
        for ip_str in all_ips:
            ip = ipaddress.ip_address(ip_str)
            # Always-blocked ranges (cloud metadata) — even with ALLOW_LOCAL_TARGETS
            for blocked in _ALWAYS_BLOCKED_RANGES:
                if ip in blocked:
                    return ip_str, False, f"Resolved to blocked IP: {ip_str}"
            for blocked in _BLOCKED_RANGES:
                if ip in blocked:
                    return ip_str, False, f"Resolved to blocked IP: {ip_str}"
        # Return the first IP as the primary resolved address
        return all_ips[0], True, None
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

        # When local targets are allowed, still validate against always-blocked
        # ranges (cloud metadata IPs) to prevent SSRF to cloud services
        if _allow_local_targets():
            try:
                results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if results:
                    for r in results:
                        ip = ipaddress.ip_address(r[4][0])
                        for blocked in _ALWAYS_BLOCKED_RANGES:
                            if ip in blocked:
                                return False, f"Blocked cloud metadata IP: {r[4][0]}"
            except Exception:
                pass  # DNS failure is not a block reason in local mode
            return True, ""

        # Resolve and validate hostname via single code path
        ip_str, is_safe, reason = resolve_and_validate(hostname)
        if not is_safe:
            return False, reason or f'Hostname "{hostname}" failed validation'

        return True, ""

    except Exception as e:
        logger.warning(f"URL safety check error: {e}")
        return False, f"URL validation error: {e}"

