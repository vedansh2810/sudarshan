from flask import Blueprint, render_template, redirect, url_for, session, jsonify
from app.models.database import db
from sqlalchemy import text

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

    # Landing page uses static marketing-style content;
    # no DB queries needed.
    return render_template("main/index.html")
