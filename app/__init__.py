"""Sudarshan Web Vulnerability Scanner - Application Factory"""

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from app.config import DevelopmentConfig
from app.models.database import db, init_db
import os
import logging

# Extensions (initialized here, bound to app in create_app)
csrf = CSRFProtect()
migrate = Migrate()

# Rate limiter: storage_uri is set dynamically in create_app()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def create_app(config=None):
    # Note: .env is loaded at module level in app/config.py (via load_dotenv)
    # so env vars are available before Config class attributes are evaluated.
    app = Flask(__name__)
    app.config.from_object(config or DevelopmentConfig)

    # ── Startup environment validation & helpful messages ──────────────
    try:
        missing = []
        # Critical vars for production
        prod_required = [
            "SECRET_KEY",
            "SQLALCHEMY_DATABASE_URI",
        ]
        for key in prod_required:
            if not os.getenv(key) and not app.config.get(key):
                missing.append(key)

        # Supabase is optional for local dev but commonly missing on fresh clones
        supabase_missing = [
            k for k in ("SUPABASE_URL", "SUPABASE_SERVICE_KEY") if not os.getenv(k)
        ]

        if not app.debug:
            if missing:
                raise RuntimeError(
                    "Missing required environment variables for production: "
                    + ", ".join(missing)
                )
        else:
            if missing:
                app.logger.warning(
                    "Missing env vars (development): %s. App will continue, "
                    "but provide these in production. See docs/RUNNING.md",
                    ", ".join(missing),
                )
            if supabase_missing:
                app.logger.info(
                    "Supabase env vars not set: %s. Authentication will use the debug fallback. "
                    "Set SUPABASE_URL and SUPABASE_SERVICE_KEY to enable real auth.",
                    ", ".join(supabase_missing),
                )
    except Exception as e:
        # Fail early in case of configuration errors in production
        if not app.debug:
            raise
        app.logger.warning("Startup validation raised: %s", e)

    # Fix common Supabase/Heroku PostgreSQL URI issue:
    # They may provide 'postgres://' but SQLAlchemy requires 'postgresql://'
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if db_uri.startswith("postgres://"):
        app.config["SQLALCHEMY_DATABASE_URI"] = db_uri.replace(
            "postgres://", "postgresql+psycopg://", 1
        )
    elif db_uri.startswith("postgresql://") and "+" not in db_uri.split("://")[0]:
        # Ensure psycopg3 driver is used (not psycopg2)
        app.config["SQLALCHEMY_DATABASE_URI"] = db_uri.replace(
            "postgresql://", "postgresql+psycopg://", 1
        )

    # ── Probe database connectivity BEFORE init ─────────────────────────
    # If DATABASE_URL points to a dead/paused PostgreSQL (e.g. Supabase),
    # fall back to local SQLite so the app still starts for development.
    # This MUST happen before db.init_app() so SQLite gets correct engine
    # options (PostgreSQL pool_size/max_overflow are incompatible with SQLite).
    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if "sqlite" not in db_uri:
        from sqlalchemy import create_engine

        probe_engine = create_engine(db_uri, pool_pre_ping=True)
        try:
            with probe_engine.connect() as conn:
                pass  # Connection works
        except Exception as db_err:
            from app.config import PROJECT_ROOT

            sqlite_uri = "sqlite:///" + os.path.join(
                PROJECT_ROOT, "data", "database.db"
            )
            logging.warning(
                f"PostgreSQL unreachable ({type(db_err).__name__}). "
                f"Falling back to SQLite: {sqlite_uri}"
            )
            app.config["SQLALCHEMY_DATABASE_URI"] = sqlite_uri
            app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}
        finally:
            probe_engine.dispose()

    # Initialize extensions (after DB probe so SQLite fallback gets correct options)
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    # Set rate limiter storage: Redis in production, memory in development
    limiter_storage = app.config.get("RATELIMIT_STORAGE_URI", "memory://")
    limiter.storage_uri = limiter_storage
    limiter.init_app(app)

    # Initialize Celery with Flask app context
    from app.celery_app import init_celery

    init_celery(app)

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if app.debug else logging.INFO,
        format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
    )

    # ── Session security: make all sessions permanent ────────────────────
    # This activates PERMANENT_SESSION_LIFETIME (8h default).
    # Without this, Flask sessions never expire server-side.
    from flask import session as flask_session

    @app.before_request
    def _enforce_session_lifetime():
        flask_session.permanent = True

    # Ensure data directories exist (use absolute paths based on project root)
    from app.config import PROJECT_ROOT

    os.makedirs(os.path.join(PROJECT_ROOT, "data", "reports"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "data", "ml_models"), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, "logs"), exist_ok=True)

    # Initialize database (create tables)
    with app.app_context():
        # Import models so their tables are created by db.create_all()
        from app.models.ml_training import ScanAttempt, MLModel  # noqa: F401
        from app.models.api_key import APIKey  # noqa: F401
        from app.models.webhook import Webhook  # noqa: F401
        from app.models.organization import (
            OrganizationModel,
            OrgMembershipModel,
        )  # noqa: F401

        init_db()

        # Recover scans orphaned by previous server crash
        try:
            from app.models.scan import Scan

            recovered = Scan.recover_orphaned(max_age_minutes=10)
            if recovered:
                app.logger.warning(
                    f"Recovered {recovered} orphaned scan(s) from previous run"
                )
        except Exception as e:
            app.logger.warning(f"Orphan recovery skipped: {e}")

    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.scan import scan_bp
    from app.routes.results import results_bp
    from app.routes.history import history_bp
    from app.routes.api import api_bp
    from app.routes.ml_admin import ml_admin_bp
    from app.routes.api_v2 import api_v2_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(results_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(ml_admin_bp)
    app.register_blueprint(api_v2_bp)

    # ── Security response headers ────────────────────────────────────────
    # Applied to every response (X-Content-Type-Options, X-Frame-Options,
    # HSTS in production, CSP in production, etc.)
    @app.after_request
    def _set_security_headers(response):
        headers = app.config.get("SECURITY_HEADERS", {})
        for header, value in headers.items():
            response.headers.setdefault(header, value)
        return response

    # ── HTTPS redirect in production ─────────────────────────────────────
    if not app.debug:

        @app.before_request
        def _enforce_https():
            from flask import request as req, redirect as redir

            # Behind a reverse proxy, X-Forwarded-Proto tells us the
            # original protocol. If it's HTTP, redirect to HTTPS.
            if req.headers.get("X-Forwarded-Proto", "https") == "http":
                url = req.url.replace("http://", "https://", 1)
                return redir(url, code=301)

    # ── Security-aware error handlers ────────────────────────────────────
    from app.monitoring.security_logger import security_log

    @app.errorhandler(403)
    def _forbidden(e):
        from flask import request as req, jsonify as jf, session as sess

        security_log.access_denied(
            ip=req.remote_addr,
            path=req.path,
            user_id=sess.get("user_id"),
            reason="forbidden",
        )
        if req.is_json or req.path.startswith("/api/"):
            return jf({"error": "Forbidden"}), 403
        return "Forbidden", 403

    @app.errorhandler(404)
    def _not_found(e):
        from flask import request as req, jsonify as jf

        # Log 404s on sensitive paths (potential enumeration)
        sensitive_prefixes = ("/admin", "/api/", "/auth/", "/ml/")
        if any(req.path.startswith(p) for p in sensitive_prefixes):
            security_log.suspicious_activity(
                ip=req.remote_addr, reason="404_on_sensitive_path", path=req.path
            )
        if req.is_json or req.path.startswith("/api/"):
            return jf({"error": "Not found"}), 404
        return "Not found", 404

    @app.errorhandler(429)
    def _rate_limited(e):
        from flask import request as req, jsonify as jf

        security_log.rate_limited(
            ip=req.remote_addr,
            path=req.path,
            limit=str(e.description) if hasattr(e, "description") else "unknown",
        )
        if req.is_json or req.path.startswith("/api/"):
            return jf({"error": "Too many requests"}), 429
        return "Too many requests. Please try again later.", 429

    @app.errorhandler(500)
    def _internal_error(e):
        from flask import request as req, jsonify as jf, session as sess

        security_log.api_error(
            ip=req.remote_addr,
            method=req.method,
            path=req.path,
            status_code=500,
            error=str(e),
            user_id=sess.get("user_id"),
        )
        if req.is_json or req.path.startswith("/api/"):
            return jf({"error": "Internal server error"}), 500
        return "Internal server error", 500

    # Call init_app if the config class defines it (production validation)
    if hasattr(app.config.get("__class__", type(None)), "init_app"):
        pass  # init_app is a @staticmethod on the config class, called via from_object

    return app
