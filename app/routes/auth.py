"""Authentication routes using Supabase Auth.
Supabase handles user registration and login; Flask manages the session."""
import logging
import httpx
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
    resp = httpx.get(
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
@limiter.limit("30 per minute")
def auth_callback():
    """Receives Supabase access token from client-side auth, verifies it,
    and creates a Flask session."""
    data = request.get_json(silent=True)
    if not data or 'access_token' not in data:
        return jsonify({'error': 'Missing access_token'}), 400

    access_token = data['access_token']

    try:
        # Verify the token server-side
        supabase_user_data = _verify_supabase_token(access_token)
        if not supabase_user_data:
            return jsonify({'error': 'Invalid token'}), 401

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
            return jsonify({'error': 'Failed to create user record'}), 500

        # Set Flask session (same format as before — all existing routes work unchanged)
        session['user_id'] = local_user['id']
        session['username'] = local_user['username']
        session['email'] = local_user['email']

        logger.info(f"User {local_user['username']} authenticated via Supabase")
        return jsonify({
            'success': True,
            'redirect': url_for('dashboard.index')
        })

    except Exception as e:
        logger.error(f"Supabase auth callback failed: {e}")
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
