from flask import Blueprint, render_template, redirect, url_for, session
from app.models.database import db, ScanModel, VulnerabilityModel
from sqlalchemy import func

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    # Redirect authenticated users to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    
    # Platform-wide stats shown on public landing page (intentionally unfiltered)
    total_scans = ScanModel.query.count()
    total_vulns = VulnerabilityModel.query.count()

    vuln_dist_rows = db.session.query(
        VulnerabilityModel.severity,
        func.count(VulnerabilityModel.id)
    ).group_by(VulnerabilityModel.severity).all()

    stats = {
        'total_scans': total_scans,
        'total_vulns': total_vulns,
        'vuln_dist': {sev: cnt for sev, cnt in vuln_dist_rows},
        'scope': 'platform'  # Indicates these are aggregate, not per-user
    }

    return render_template('main/index.html', stats=stats)
