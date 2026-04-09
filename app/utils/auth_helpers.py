"""Access control helpers for multi-tenant data isolation."""
import logging
from app.models.organization import Organization

logger = logging.getLogger(__name__)


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
