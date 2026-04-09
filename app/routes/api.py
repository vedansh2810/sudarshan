from flask import Blueprint, jsonify, session
from app.models.scan import Scan
from app.models.database import db, ScanModel, VulnerabilityModel
from app.scanner.scan_manager import ScanManager
from app.utils.auth_utils import login_required
from app import csrf
from sqlalchemy import func

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/scan/<int:scan_id>/status')
@login_required
def scan_status(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan or scan['user_id'] != session['user_id']:
        return jsonify({'error': 'Not found'}), 404
    manager = ScanManager.get_instance()
    status = manager.get_status(scan_id)
    return jsonify(status or {'status': scan['status']})

@api_bp.route('/api/stats')
@login_required
def global_stats():
    """User-scoped statistics via SQLAlchemy ORM."""
    user_id = session['user_id']

    total_scans = ScanModel.query.filter_by(user_id=user_id).count()

    total_vulns = db.session.query(func.count(VulnerabilityModel.id)) \
        .join(ScanModel, VulnerabilityModel.scan_id == ScanModel.id) \
        .filter(ScanModel.user_id == user_id).scalar() or 0

    vuln_dist_rows = db.session.query(
        VulnerabilityModel.severity,
        func.count(VulnerabilityModel.id)
    ).join(ScanModel, VulnerabilityModel.scan_id == ScanModel.id) \
     .filter(ScanModel.user_id == user_id) \
     .group_by(VulnerabilityModel.severity).all()

    distribution = {sev: cnt for sev, cnt in vuln_dist_rows}

    return jsonify({
        'total_scans': total_scans,
        'total_vulns': total_vulns,
        'distribution': distribution
    })

@api_bp.route('/api/health')
def health():
    """Health check endpoint for load balancer / container probes."""
    return jsonify({'status': 'healthy', 'service': 'sudarshan'})


@api_bp.route('/api/metrics')
@csrf.exempt
def metrics():
    """Prometheus metrics endpoint."""
    from app.monitoring.metrics import metrics_endpoint
    body, status, headers = metrics_endpoint()
    return body, status, headers
