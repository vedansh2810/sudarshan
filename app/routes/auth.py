"""Authentication routes using Supabase Auth.
Supabase handles user registration and login; Flask manages the session.

Security hardening (v2.1):
- Session fixation protection: session is regenerated on every login
- Origin validation on CSRF-exempt callback endpoint
- Tightened rate limiting on auth callback (10/min)
- Login timestamp for session auditing
"""
import logging
from datetime import datetime, timezone
import requests as http_requests
from flask import (Blueprint, render_template, request, redirect,
                   url_for, session, flash, current_app, jsonify)
from app.models.user import User
from app import limiter, csrf

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


def _verify_supabase_token(access_token):
    """Verify a Supabase access token server-side using the Supabase REST API.
    Returns the Supabase user object or None."""
    supabase_url = current_app.config['SUPABASE_URL']
    service_key = current_app.config['SUPABASE_SERVICE_KEY']

    if not supabase_url or not service_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set")

    # Call Supabase Auth API to verify the token and get user info
    resp = http_requests.get(
        f"{supabase_url}/auth/v1/user",
        headers={
            'Authorization': f'Bearer {access_token}',
            'apikey': service_key
        },
        timeout=10
    )

    if resp.status_code == 200:
        return resp.json()
    return None


def _validate_request_origin():
    """Validate Origin/Referer header for CSRF-exempt endpoints.

    Since /auth/callback is @csrf.exempt (required because the client-side
    Supabase JS SDK posts the token), we validate the Origin header manually
    to prevent cross-origin CSRF attacks.

    Returns True if the request is safe (same-origin or no Origin header).
    """
    origin = request.headers.get('Origin') or ''
    if not origin:
        # Requests without Origin header (e.g. same-origin, non-browser clients)
        # are allowed; Referer can be checked as a fallback
        referer = request.headers.get('Referer') or ''
        if not referer:
            return True  # No origin info — likely server-to-server or same-origin
        origin = referer

    server_origin = request.host_url.rstrip('/')
    return origin.startswith(server_origin)


@auth_bp.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    return render_template('auth/login.html',
                           supabase_url=current_app.config['SUPABASE_URL'],
                           supabase_anon_key=current_app.config['SUPABASE_ANON_KEY'])


@auth_bp.route('/register')
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    return render_template('auth/register.html',
                           supabase_url=current_app.config['SUPABASE_URL'],
                           supabase_anon_key=current_app.config['SUPABASE_ANON_KEY'])


@auth_bp.route('/auth/callback', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute")
def auth_callback():
    """Receives Supabase access token from client-side auth, verifies it,
    and creates a Flask session.

    Security:
    - Rate limited to 10/min (brute-force defense)
    - Origin header validated (CSRF protection for exempt endpoint)
    - Session regenerated on login (session fixation protection)
    - Authentication timestamp recorded for auditing
    """
    # ── Origin validation (replaces CSRF for this exempt endpoint) ───────
    if not _validate_request_origin():
        logger.warning(
            f"Auth callback rejected: invalid origin "
            f"(Origin={request.headers.get('Origin')}, "
            f"IP={request.remote_addr})"
        )
        return jsonify({'error': 'Invalid request origin'}), 403

    data = request.get_json(silent=True)
    if not data or 'access_token' not in data:
        return jsonify({'error': 'Missing access_token'}), 400

    access_token = data['access_token']

    try:
        # Verify the token server-side
        supabase_user_data = _verify_supabase_token(access_token)
        if not supabase_user_data:
            # Generic error message to prevent account enumeration
            return jsonify({'error': 'Authentication failed'}), 401

        # Create a simple namespace object for get_or_create_from_supabase
        class SupabaseUser:
            def __init__(self, data):
                self.id = data.get('id', '')
                self.email = data.get('email', '')
                self.user_metadata = data.get('user_metadata', {})

        supabase_user = SupabaseUser(supabase_user_data)

        # Find or create local user record
        local_user = User.get_or_create_from_supabase(supabase_user)
        if not local_user:
            return jsonify({'error': 'Authentication failed'}), 500

        # ── Session fixation protection ──────────────────────────────────
        # Clear old session data before setting new credentials.
        # This prevents an attacker from pre-setting a session ID and
        # having the victim authenticate into it.
        session.clear()

        # Set Flask session
        session['user_id'] = local_user['id']
        session['username'] = local_user['username']
        session['email'] = local_user['email']
        session['_authenticated_at'] = datetime.now(timezone.utc).isoformat()
        session['_last_validated'] = datetime.now(timezone.utc).isoformat()

        logger.info(f"User {local_user['username']} authenticated via Supabase")
        return jsonify({
            'success': True,
            'redirect': url_for('dashboard.index')
        })

    except Exception as e:
        logger.error(f"Supabase auth callback failed: {e}")
        # Generic error message to prevent information leakage
        return jsonify({'error': 'Authentication failed'}), 401


@auth_bp.route('/auth/callback-handler')
def callback_handler():
    """Handle Supabase OAuth redirect.

    Supabase sends the access_token in the URL hash fragment (e.g.
    /auth/callback-handler#access_token=xxx&...).  Hash fragments are
    NOT sent to the server, so we serve a small page whose JS extracts
    the token and POSTs it to /auth/callback.
    """
    return render_template('auth/callback_handler.html',
                           supabase_url=current_app.config['SUPABASE_URL'],
                           supabase_anon_key=current_app.config['SUPABASE_ANON_KEY'])


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))
