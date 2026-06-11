"""Access control helpers for multi-tenant data isolation."""

import logging
from functools import wraps
from flask import session, redirect, url_for, jsonify, request, abort
from app.models.organization import Organization

logger = logging.getLogger(__name__)


def user_can_access_scan(scan, user_id, require_write=False):
    """Non-aborting version: returns True/False.

    Args:
        scan: scan dict (must include user_id and org_id keys)
        user_id: the user to check access for
        require_write: if True, requires 'member' or higher role (not 'viewer')
    """
    if not scan or not user_id:
        return False
    if scan["user_id"] == user_id:
        return True
    scan_org_id = scan.get("org_id")
    if scan_org_id:
        if require_write:
            return Organization.user_has_write_access(scan_org_id, user_id)
        return Organization.user_has_access(scan_org_id, user_id)
    return False


def admin_required(f):
    """Restrict endpoint to admin users only.

    Checks session['is_admin']. Returns 403 for non-admin users.
    For JSON/API requests returns JSON error; for browser requests aborts 403.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("auth.login"))
        if not session.get("is_admin", False):
            logger.warning(
                f"Admin access denied for user_id={session.get('user_id')} "
                f"on {request.method} {request.path}"
            )
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Admin access required"}), 403
            abort(403)
        return f(*args, **kwargs)

    return decorated
