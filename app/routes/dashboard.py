from flask import Blueprint, render_template, session, redirect, url_for, jsonify
from app.models.scan import Scan
from app.models.database import ScanModel
from app.utils.auth_utils import login_required

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/dashboard')
@login_required
def index():
    user_id = session['user_id']

    # Single query for both recent scans and trend data (previously 2 separate queries)
    recent_scans_orm = Scan.for_user_query(user_id) \
        .order_by(ScanModel.started_at.desc()).limit(10).all()

    total, vulns = Scan.get_stats(user_id)

    # Build trend data from the same query results (first 7)
    trend_scans = []
    for s in recent_scans_orm[:7]:
        trend_scans.append({
            'started_at': s.started_at.isoformat() if s.started_at else '',
            'critical_count': s.critical_count or 0,
            'high_count': s.high_count or 0,
            'medium_count': s.medium_count or 0,
            'low_count': s.low_count or 0,
            'score': s.score,
        })

    stats = {
        'total_scans': total['cnt'] if total else 0,
        'critical': (vulns['crit'] or 0) if vulns else 0,
        'high': (vulns['high'] or 0) if vulns else 0,
        'medium': (vulns['med'] or 0) if vulns else 0,
        'low': (vulns['low'] or 0) if vulns else 0,
    }

    # Calculate severity percentages for the bar chart
    total_vulns = stats['critical'] + stats['high'] + stats['medium'] + stats['low']
    if total_vulns > 0:
        sev_pct = {
            'critical': round(stats['critical'] / total_vulns * 100),
            'high': round(stats['high'] / total_vulns * 100),
            'medium': round(stats['medium'] / total_vulns * 100),
            'low': round(stats['low'] / total_vulns * 100),
        }
    else:
        sev_pct = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

    # Transform recent scans to match template's expected property names
    recent_scans = []
    raw_scans = []
    for s in recent_scans_orm:
        started = s.started_at.isoformat() if s.started_at else ''
        date_display = started[:16].replace('T', ' ') if started else '—'
        status = s.status
        if status == 'completed':
            status = 'complete'
        recent_scans.append({
            'id': s.id,
            'target': s.target_url,
            'status': status,
            'score': s.score or '—',
            'critical': s.critical_count or 0,
            'high': s.high_count or 0,
            'med': s.medium_count or 0,
            'date': date_display,
        })
        # Also build raw_scans dict for backward compat
        raw_scans.append({c.name: getattr(s, c.name) for c in ScanModel.__table__.columns})

    # Build trend data for chart
    trend_labels = []
    trend_critical = []
    trend_high = []
    trend_medium = []
    for t in reversed(trend_scans or []):
        label = str(t['started_at'] or '')[:10]
        trend_labels.append(label)
        trend_critical.append(t['critical_count'] or 0)
        trend_high.append(t['high_count'] or 0)
        trend_medium.append(t['medium_count'] or 0)

    trend_data = {
        'labels': trend_labels or ['No data'],
        'critical': trend_critical or [0],
        'high': trend_high or [0],
        'medium': trend_medium or [0],
    }

    return render_template(
        'dashboard/index.html',
        scans=raw_scans,
        recent_scans=recent_scans,
        stats=stats,
        trend_scans=trend_scans,
        trend_data=trend_data,
        sev_pct=sev_pct
    )
