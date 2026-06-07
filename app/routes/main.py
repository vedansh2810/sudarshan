from flask import Blueprint, render_template, redirect, url_for, session, jsonify
from app.models.database import db, ScanModel, VulnerabilityModel
from sqlalchemy import func, text

main_bp = Blueprint("main", __name__)


@main_bp.route("/health")
def health():
    """Liveness check — returns 200 if the app process is running.
    Used by load balancers and container orchestrators (e.g. Docker, K8s)."""
    return jsonify({"status": "ok"}), 200


@main_bp.route("/readiness")
def readiness():
    """Readiness check — returns 200 only if the database is reachable.
    Returns 503 if the database connection fails."""
    try:
        db.session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    status_code = 200 if db_ok else 503
    return jsonify({
        "status": "ready" if db_ok else "unavailable",
        "database": "connected" if db_ok else "disconnected",
    }), status_code


@main_bp.route("/")
def index():
    # Redirect authenticated users to dashboard
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    # Platform-wide stats shown on public landing page (intentionally unfiltered)
    total_scans = ScanModel.query.count()
    total_vulns = VulnerabilityModel.query.count()

    vuln_dist_rows = (
        db.session.query(VulnerabilityModel.severity, func.count(VulnerabilityModel.id))
        .group_by(VulnerabilityModel.severity)
        .all()
    )

    stats = {
        "total_scans": total_scans,
        "total_vulns": total_vulns,
        "vuln_dist": {sev: cnt for sev, cnt in vuln_dist_rows},
        "scope": "platform",  # Indicates these are aggregate, not per-user
    }

    return render_template("main/index.html", stats=stats)
