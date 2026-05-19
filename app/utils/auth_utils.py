"""Centralized authentication utilities for all route blueprints."""
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import session, redirect, url_for, jsonify, request

logger = logging.getLogger(__name__)

# Re-validate session user against the database every 5 minutes.
# This catches deleted/deactivated users without a DB query on every request.
_SESSION_REVALIDATION_INTERVAL = 300  # seconds


def login_required(f):
    """Require an authenticated user via session.
    Redirects to login for browser requests; returns 401 JSON for API calls.

    Security: periodically re-validates the session user against the database
    to ensure deleted or deactivated users are logged out within 5 minutes.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login'))

        # ── Periodic session integrity check ────────────────────────────
        last_check = session.get('_last_validated', '')
        now = datetime.now(timezone.utc)
        needs_check = True

        if last_check:
            try:
                elapsed = (now - datetime.fromisoformat(last_check)).total_seconds()
                needs_check = elapsed > _SESSION_REVALIDATION_INTERVAL
            except (ValueError, TypeError):
                needs_check = True

        if needs_check:
            from app.models.user import User
            user = User.get_by_id(session['user_id'])
            if not user:
                logger.warning(
                    f"Session invalidated: user_id={session.get('user_id')} "
                    f"no longer exists in database"
                )
                from app.monitoring.security_logger import security_log
                security_log.session_invalidated(
                    user_id=session.get('user_id'),
                    ip=request.remote_addr,
                    reason='user_deleted'
                )
                session.clear()
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': 'Session expired'}), 401
                return redirect(url_for('auth.login'))
            session['_last_validated'] = now.isoformat()

        return f(*args, **kwargs)
    return decorated
