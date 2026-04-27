"""
Prometheus metrics for Sudarshan.
Provides counters and histograms for monitoring scan activity.
"""
import logging

logger = logging.getLogger(__name__)

# ── Metric definitions ──────────────────────────────────────────────
# Using try/except so the app still works without prometheus-client
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

    scans_total = Counter(
        'sudarshan_scans_total',
        'Total number of scans started',
        ['status'],  # completed, failed, stopped
    )

    scan_duration = Histogram(
        'sudarshan_scan_duration_seconds',
        'Time taken to complete scans',
        buckets=[30, 60, 120, 300, 600, 1200, 3600],
    )

    vulnerabilities_found = Counter(
        'sudarshan_vulnerabilities_found',
        'Total vulnerabilities found',
        ['severity', 'type'],
    )


    active_scans = Gauge(
        'sudarshan_active_scans',
        'Currently running scans',
    )

    PROMETHEUS_AVAILABLE = True

except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.info('prometheus-client not installed. Metrics endpoint will return 503.')


# ── Helper functions ─────────────────────────────────────────────────

def track_scan_started():
    """Increment active scan gauge."""
    if PROMETHEUS_AVAILABLE:
        active_scans.inc()


def track_scan_completed(duration_seconds, status='completed'):
    """Record scan completion metrics."""
    if PROMETHEUS_AVAILABLE:
        scans_total.labels(status=status).inc()
        scan_duration.observe(duration_seconds)
        active_scans.dec()


def track_vulnerability(severity, vuln_type):
    """Record a found vulnerability."""
    if PROMETHEUS_AVAILABLE:
        vulnerabilities_found.labels(severity=severity, type=vuln_type).inc()




# ── Endpoint function ────────────────────────────────────────────────

def metrics_endpoint():
    """Generate Prometheus metrics output.

    Returns:
        Tuple of (body, status_code, headers).
    """
    if not PROMETHEUS_AVAILABLE:
        return 'prometheus-client not installed', 503, {'Content-Type': 'text/plain'}

    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
