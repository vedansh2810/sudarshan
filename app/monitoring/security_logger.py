"""Security event logging for authentication, API errors, and suspicious traffic.

Provides structured logging for security-relevant events that can be consumed
by SIEM systems, log aggregators, or reviewed manually. All events are logged
to both the application logger and a dedicated security log file.

Usage:
    from app.monitoring.security_logger import security_log
    security_log.auth_success(user_id=1, username='alice', ip='1.2.3.4')
    security_log.auth_failure(email='alice@example.com', ip='1.2.3.4', reason='invalid_token')
    security_log.suspicious_activity(ip='1.2.3.4', reason='rate_limit_exceeded', path='/auth/callback')
"""
import json
import logging
import os
from datetime import datetime, timezone

from app.config import PROJECT_ROOT

# Dedicated security logger — writes to logs/security.log
_security_logger = logging.getLogger('sudarshan.security')
_security_logger.setLevel(logging.INFO)

# Avoid duplicate handlers on reload
if not _security_logger.handlers:
    log_dir = os.path.join(PROJECT_ROOT, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # Rotating file handler for security events
    from logging.handlers import RotatingFileHandler
    handler = RotatingFileHandler(
        os.path.join(log_dir, 'security.log'),
        maxBytes=10 * 1024 * 1024,  # 10 MB per file
        backupCount=5,              # Keep 5 rotated files
    )
    handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    _security_logger.addHandler(handler)


def _emit(level: str, event_type: str, **fields):
    """Emit a structured security event as JSON."""
    entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event': event_type,
        **fields,
    }
    # Remove None values for cleaner output
    entry = {k: v for k, v in entry.items() if v is not None}
    msg = json.dumps(entry, default=str)

    if level == 'warning':
        _security_logger.warning(msg)
    elif level == 'error':
        _security_logger.error(msg)
    elif level == 'critical':
        _security_logger.critical(msg)
    else:
        _security_logger.info(msg)


class SecurityLog:
    """Structured security event logger."""

    # ── Authentication events ────────────────────────────────────────────

    @staticmethod
    def auth_success(user_id, username, ip, method='supabase'):
        """Log successful authentication."""
        _emit('info', 'auth_success',
              user_id=user_id, username=username, ip=ip, method=method)

    @staticmethod
    def auth_failure(ip, reason, email=None, **extra):
        """Log failed authentication attempt."""
        _emit('warning', 'auth_failure',
              ip=ip, reason=reason, email=email, **extra)

    @staticmethod
    def logout(user_id, username, ip):
        """Log user logout."""
        _emit('info', 'logout',
              user_id=user_id, username=username, ip=ip)

    @staticmethod
    def session_invalidated(user_id, ip, reason):
        """Log session invalidation (expired, deleted user, etc.)."""
        _emit('warning', 'session_invalidated',
              user_id=user_id, ip=ip, reason=reason)

    # ── API events ───────────────────────────────────────────────────────

    @staticmethod
    def api_error(ip, method, path, status_code, error=None, user_id=None):
        """Log API error responses (4xx/5xx)."""
        _emit('warning' if status_code < 500 else 'error', 'api_error',
              ip=ip, method=method, path=path,
              status_code=status_code, error=error, user_id=user_id)

    @staticmethod
    def api_unauthorized(ip, method, path, reason='missing_auth'):
        """Log unauthorized API access attempt."""
        _emit('warning', 'api_unauthorized',
              ip=ip, method=method, path=path, reason=reason)

    # ── Suspicious activity ──────────────────────────────────────────────

    @staticmethod
    def suspicious_activity(ip, reason, path=None, user_id=None, **extra):
        """Log suspicious traffic patterns.

        Examples: rate limit exceeded, origin mismatch, repeated 403s,
        scan of non-existent endpoints, etc.
        """
        _emit('warning', 'suspicious_activity',
              ip=ip, reason=reason, path=path, user_id=user_id, **extra)

    @staticmethod
    def rate_limited(ip, path, limit):
        """Log rate limit hit."""
        _emit('warning', 'rate_limited',
              ip=ip, path=path, limit=limit)

    @staticmethod
    def access_denied(ip, path, user_id=None, reason='forbidden'):
        """Log 403 access denial."""
        _emit('warning', 'access_denied',
              ip=ip, path=path, user_id=user_id, reason=reason)

    @staticmethod
    def invalid_input(ip, path, reason, user_id=None):
        """Log malformed or suspicious input."""
        _emit('warning', 'invalid_input',
              ip=ip, path=path, reason=reason, user_id=user_id)


# Singleton instance
security_log = SecurityLog()
