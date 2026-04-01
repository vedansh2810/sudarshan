"""REST API v2 — JSON endpoints for programmatic access and integrations.

All endpoints return JSON. Auth is via Flask session (set by /auth/callback).
Prefix: /api/v2
"""
import math
import logging
from flask import Blueprint, jsonify, session, request, Response
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.database import ScanModel
from app.scanner.scan_manager import ScanManager
from app.utils.auth_utils import login_required
from app.utils.auth_helpers import user_can_access_scan
from app.config import Config
from app import csrf
from sqlalchemy import func
import json

logger = logging.getLogger(__name__)

api_v2_bp = Blueprint('api_v2', __name__, url_prefix='/api/v2')


# ── Helper ────────────────────────────────────────────────────────────────

def _json_error(msg, status=400):
    return jsonify({'error': msg}), status


def _scan_to_dict(scan_orm):
    """Convert a ScanModel ORM object to a JSON-safe dict."""
    s = scan_orm
    started = s.started_at.isoformat() if s.started_at else None
    completed = s.completed_at.isoformat() if s.completed_at else None
    return {
        'id': s.id,
        'user_id': s.user_id,
        'target_url': s.target_url,
        'status': s.status,
        'scan_mode': s.scan_mode,
        'scan_speed': s.scan_speed,
        'crawl_depth': s.crawl_depth,
        'score': s.score,
        'total_urls': s.total_urls or 0,
        'tested_urls': s.tested_urls or 0,
        'vuln_count': s.vuln_count or 0,
        'critical_count': s.critical_count or 0,
        'high_count': s.high_count or 0,
        'medium_count': s.medium_count or 0,
        'low_count': s.low_count or 0,
        'duration': s.duration or 0,
        'started_at': started,
        'completed_at': completed,
    }


# ── Auth ──────────────────────────────────────────────────────────────────

@api_v2_bp.route('/auth/session')
def auth_session():
    """Return current session info or 401."""
    if 'user_id' not in session:
        return _json_error('Not authenticated', 401)
    return jsonify({
        'user_id': session['user_id'],
        'username': session.get('username', ''),
        'email': session.get('email', ''),
    })


# ── Dashboard ─────────────────────────────────────────────────────────────

@api_v2_bp.route('/dashboard')
@login_required
def dashboard():
    """All data needed for the dashboard page in one call."""
    user_id = session['user_id']

    # Stats
    total_obj, vulns_obj = Scan.get_stats(user_id)
    stats = {
        'total_scans': total_obj['cnt'] if total_obj else 0,
        'critical': (vulns_obj['crit'] or 0) if vulns_obj else 0,
        'high': (vulns_obj['high'] or 0) if vulns_obj else 0,
        'medium': (vulns_obj['med'] or 0) if vulns_obj else 0,
        'low': (vulns_obj['low'] or 0) if vulns_obj else 0,
    }

    # Recent scans (last 10)
    raw_scans = Scan.get_recent(user_id, limit=10)
    recent_scans = []
    for s in raw_scans:
        started = str(s['started_at'] or '')
        status = 'complete' if s['status'] == 'completed' else s['status']
        recent_scans.append({
            'id': s['id'],
            'target_url': s['target_url'],
            'status': status,
            'score': s['score'] or None,
            'critical_count': s['critical_count'] or 0,
            'high_count': s['high_count'] or 0,
            'medium_count': s['medium_count'] or 0,
            'started_at': started,
        })

    # Trend data (last 7 scans) — org-aware
    trend_scans = Scan.for_user_query(user_id) \
        .order_by(ScanModel.started_at.desc()).limit(7).all()
    trend_labels = []
    trend_critical = []
    trend_high = []
    trend_medium = []
    for t in reversed(trend_scans):
        label = t.started_at.isoformat()[:10] if t.started_at else ''
        trend_labels.append(label)
        trend_critical.append(t.critical_count or 0)
        trend_high.append(t.high_count or 0)
        trend_medium.append(t.medium_count or 0)

    # Severity percentages
    total_vulns = stats['critical'] + stats['high'] + stats['medium'] + stats['low']
    if total_vulns > 0:
        sev_pct = {k: round(stats[k] / total_vulns * 100) for k in ('critical', 'high', 'medium', 'low')}
    else:
        sev_pct = {k: 0 for k in ('critical', 'high', 'medium', 'low')}

    return jsonify({
        'stats': stats,
        'recent_scans': recent_scans,
        'trend': {
            'labels': trend_labels or ['No data'],
            'critical': trend_critical or [0],
            'high': trend_high or [0],
            'medium': trend_medium or [0],
        },
        'severity_pct': sev_pct,
    })


# ── Scans CRUD ────────────────────────────────────────────────────────────

@api_v2_bp.route('/scans')
@login_required
def list_scans():
    """Paginated scan history with search/date filters."""
    user_id = session['user_id']
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)

    query = Scan.for_user_query(user_id)
    if search:
        query = query.filter(ScanModel.target_url.ilike(f'%{search}%'))
    if date_from:
        query = query.filter(func.date(ScanModel.started_at) >= date_from)
    if date_to:
        query = query.filter(func.date(ScanModel.started_at) <= date_to)

    total = query.count()
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    scans_orm = query.order_by(ScanModel.started_at.desc()) \
        .limit(per_page).offset(offset).all()

    scans = [_scan_to_dict(s) for s in scans_orm]

    return jsonify({
        'scans': scans,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'total_pages': total_pages,
        }
    })


@api_v2_bp.route('/scans', methods=['POST'])
@csrf.exempt
@login_required
def create_scan():
    """Start a new vulnerability scan."""
    data = request.get_json(silent=True) or {}
    target_url = (data.get('target_url') or '').strip()
    scan_mode = data.get('scan_mode', 'active')
    scan_speed = data.get('scan_speed', 'balanced')
    crawl_depth = data.get('crawl_depth', 3)
    selected_checks = data.get('checks', [])
    dvwa_security = data.get('dvwa_security', 'low')
    authorized = data.get('authorized', False)

    if not authorized:
        return _json_error('You must confirm legal authorization before scanning.')
    if not target_url:
        return _json_error('target_url is required.')
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    # SSRF protection
    from app.utils.url_safety import is_safe_url
    is_safe, reason = is_safe_url(target_url)
    if not is_safe:
        return _json_error(f'Target blocked: {reason}')

    try:
        crawl_depth = max(1, min(10, int(crawl_depth)))
    except (ValueError, TypeError):
        crawl_depth = 3

    if not selected_checks:
        selected_checks = Config.VULNERABILITY_CHECKS

    # Org context and quota check
    org_id = data.get('org_id') or session.get('org_id')
    if org_id:
        from app.models.organization import Organization
        allowed, reason = Organization.check_scan_quota(org_id)
        if not allowed:
            return _json_error(reason, 403)

    scan_id = Scan.create(
        user_id=session['user_id'],
        target_url=target_url,
        scan_mode=scan_mode,
        scan_speed=scan_speed,
        crawl_depth=crawl_depth,
        org_id=org_id
    )

    manager = ScanManager.get_instance()
    manager.start_scan(
        scan_id=scan_id,
        target_url=target_url,
        scan_mode=scan_mode,
        scan_speed=scan_speed,
        crawl_depth=crawl_depth,
        selected_checks=selected_checks,
        dvwa_security=dvwa_security
    )

    return jsonify({'scan_id': scan_id}), 201


@api_v2_bp.route('/scans/<int:scan_id>')
@login_required
def get_scan(scan_id):
    """Get details of a single scan."""
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Not found', 404)
    return jsonify({'scan': dict(scan)})


@api_v2_bp.route('/scans/<int:scan_id>', methods=['DELETE'])
@csrf.exempt
@login_required
def delete_scan(scan_id):
    """Delete a scan."""
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Not found', 404)
    Scan.delete(scan_id)
    return jsonify({'success': True})


# ── Scan Results ──────────────────────────────────────────────────────────

@api_v2_bp.route('/scans/<int:scan_id>/results')
@login_required
def scan_results(scan_id):
    """Vulnerabilities for a scan, with optional severity/type filters."""
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Not found', 404)

    severity = request.args.get('severity', 'all')
    vuln_type = request.args.get('type', 'all')

    all_vulns = Vulnerability.get_by_scan(scan_id)
    all_types = list(set(v['vuln_type'] for v in all_vulns))

    vulns = all_vulns
    if severity != 'all':
        vulns = [v for v in vulns if v['severity'] == severity]
    if vuln_type != 'all':
        vulns = [v for v in vulns if v['vuln_type'] == vuln_type]

    counts = Vulnerability.get_count_by_severity(scan_id)

    # Convert to JSON-safe dicts
    vuln_list = []
    for v in vulns:
        vd = dict(v)
        vd['found_at'] = str(vd.get('found_at', ''))
        vuln_list.append(vd)

    return jsonify({
        'scan': dict(scan),
        'vulnerabilities': vuln_list,
        'counts': dict(counts) if counts else {},
        'all_types': all_types,
    })


# ── Scan Controls ─────────────────────────────────────────────────────────

@api_v2_bp.route('/scans/<int:scan_id>/status')
@login_required
def scan_status(scan_id):
    """Get live status of a scan."""
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Forbidden', 403)
    manager = ScanManager.get_instance()
    st = manager.get_status(scan_id)
    if st:
        return jsonify(st)
    return jsonify({
        'status': scan['status'],
        'total_urls': scan['total_urls'] or 0,
        'tested_urls': scan['tested_urls'] or 0,
        'findings': scan['vuln_count'] or 0,
        'elapsed': scan['duration'] or 0,
    })


@api_v2_bp.route('/scans/<int:scan_id>/pause', methods=['POST'])
@csrf.exempt
@login_required
def pause_scan(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Forbidden', 403)
    manager = ScanManager.get_instance()
    return jsonify({'success': manager.pause_scan(scan_id)})


@api_v2_bp.route('/scans/<int:scan_id>/resume', methods=['POST'])
@csrf.exempt
@login_required
def resume_scan(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Forbidden', 403)
    manager = ScanManager.get_instance()
    return jsonify({'success': manager.resume_scan(scan_id)})


@api_v2_bp.route('/scans/<int:scan_id>/stop', methods=['POST'])
@csrf.exempt
@login_required
def stop_scan(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Forbidden', 403)
    manager = ScanManager.get_instance()
    return jsonify({'success': manager.stop_scan(scan_id)})


# ── SSE Stream (reuses existing logic) ────────────────────────────────────

@api_v2_bp.route('/scans/<int:scan_id>/stream')
@login_required
def scan_stream(scan_id):
    """SSE event stream for real-time scan updates."""
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Forbidden', 403)

    manager = ScanManager.get_instance()

    # Reuse existing stream logic from scan routes
    from app.routes.scan import _stream_redis, _stream_threading
    if manager.is_redis_mode():
        return _stream_redis(scan_id, manager)
    else:
        return _stream_threading(scan_id, manager)


# ── Reports ───────────────────────────────────────────────────────────────

@api_v2_bp.route('/scans/<int:scan_id>/report/<fmt>')
@login_required
def download_report(scan_id, fmt):
    """Download PDF or HTML report."""
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return _json_error('Not found', 404)

    if fmt not in ('pdf', 'html'):
        return _json_error('Invalid format. Use "pdf" or "html".')

    # Reuse existing report generators
    from app.routes.results import _generate_pdf_report, _generate_html_report, _get_ai_executive_summary
    vulns = Vulnerability.get_by_scan(scan_id)
    ai_summary = _get_ai_executive_summary(scan, vulns)

    if fmt == 'pdf':
        pdf_bytes = _generate_pdf_report(scan, vulns, ai_summary=ai_summary)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename=sudarshan-report-{scan_id}.pdf'}
        )
    else:
        html = _generate_html_report(scan, vulns, ai_summary=ai_summary)
        return Response(
            html,
            mimetype='text/html',
            headers={'Content-Disposition': f'attachment; filename=sudarshan-report-{scan_id}.html'}
        )


# ── Vulnerability checks list ────────────────────────────────────────────

@api_v2_bp.route('/checks')
@login_required
def list_checks():
    """Return available vulnerability checks for scan config UI."""
    return jsonify({'checks': Config.VULNERABILITY_CHECKS})
