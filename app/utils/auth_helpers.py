"""Access control helpers for multi-tenant data isolation."""
import logging
from functools import wraps
from flask import session, abort
from app.models.scan import Scan
from app.models.organization import Organization

logger = logging.getLogger(__name__)


def get_current_user_id():
    """Get the current user_id from session, or None."""
    return session.get('user_id')


def require_scan_access(scan_id):
    """Check if the current user can access a scan.

    Access is granted if:
    1. The user owns the scan directly, OR
    2. The scan belongs to an org the user is a member of

    Returns:
        scan dict if access granted.
    Raises:
        404 if scan not found.
        403 if user doesn't have access.
    """
    user_id = get_current_user_id()
    if not user_id:
        abort(401)

    scan = Scan.get_by_id(scan_id)
    if not scan:
        abort(404)

    # Direct ownership
    if scan['user_id'] == user_id:
        return scan

    # Org membership check
    scan_org_id = scan.get('org_id')
    if scan_org_id and Organization.user_has_access(scan_org_id, user_id):
        return scan

    abort(403)


def user_can_access_scan(scan, user_id):
    """Non-aborting version: returns True/False.

    Args:
        scan: scan dict (must include user_id and org_id keys)
        user_id: the user to check access for
    """
    if not scan or not user_id:
        return False
    if scan['user_id'] == user_id:
        return True
    scan_org_id = scan.get('org_id')
    if scan_org_id and Organization.user_has_access(scan_org_id, user_id):
        return True
    return False
