from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify
from app.models.scan import Scan
from app.models.database import ScanModel
from app.utils.auth_utils import login_required
from app.utils.auth_helpers import user_can_access_scan
from app import csrf
from sqlalchemy import func
import math

history_bp = Blueprint('history', __name__)


@history_bp.route('/history')
@login_required
def index():
    user_id = session['user_id']
    search = request.args.get('search', '').strip()
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    # Build query dynamically — org-aware via Scan.for_user_query
    query = Scan.for_user_query(user_id)

    if search:
        query = query.filter(ScanModel.target_url.ilike(f'%{search}%'))
    if date_from:
        query = query.filter(func.date(ScanModel.started_at) >= date_from)
    if date_to:
        query = query.filter(func.date(ScanModel.started_at) <= date_to)

    # Count total
    total = query.count()
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))

    # Fetch page of scans
    offset = (page - 1) * per_page
    raw_scans = query.order_by(ScanModel.started_at.desc()) \
        .limit(per_page).offset(offset).all()

    # Transform scans to match template's expected property names
    scans = []
    for s in raw_scans:
        started = s.started_at.isoformat() if s.started_at else ''
        date_display = started[:16].replace('T', ' ') if started else '—'
        dur = s.duration or 0
        if s.status in ('running', 'paused'):
            dur_display = s.status.title()
        elif dur >= 60:
            dur_display = f"{dur // 60}m {dur % 60}s"
        else:
            dur_display = f"{dur}s"
        status = s.status
        if status == 'completed':
            status = 'complete'

        scans.append({
            'id': s.id,
            'target': s.target_url,
            'status': status,
            'grade': s.score or '—',
            'crit': s.critical_count or 0,
            'high': s.high_count or 0,
            'med': s.medium_count or 0,
            'date': date_display,
            'duration': dur_display,
            'mode': (s.scan_mode or 'active').title(),
            'depth': s.crawl_depth or 3,
        })

    pagination = {
        'page': page,
        'pages': total_pages,
        'total': total,
    }

    return render_template('history/index.html',
                         scans=scans, search=search,
                         date_from=date_from, date_to=date_to,
                         pagination=pagination)

@history_bp.route('/history/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete(scan_id):
    scan = Scan.get_by_id(scan_id)
    if user_can_access_scan(scan, session.get('user_id')):
        Scan.delete(scan_id)
    return redirect(url_for('history.index'))

@history_bp.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@csrf.exempt
@login_required
def api_delete(scan_id):
    """API endpoint for JS-based deletion"""
    scan = Scan.get_by_id(scan_id)
    if user_can_access_scan(scan, session.get('user_id')):
        Scan.delete(scan_id)
        return jsonify({'success': True})
    return jsonify({'success': False}), 404
