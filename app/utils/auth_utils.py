"""Centralized authentication utilities for all route blueprints."""
from functools import wraps
from flask import session, redirect, url_for, jsonify, request


def login_required(f):
    """Require an authenticated user via session.
    Redirects to login for browser requests; returns 401 JSON for API calls."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated
