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
)


def create_app(config=None):
    # Load .env file early (python-dotenv is already in requirements)
    from dotenv import load_dotenv
    load_dotenv()

    app = Flask(__name__)
    app.config.from_object(config or DevelopmentConfig)

    # Fix common Supabase/Heroku PostgreSQL URI issue:
    # They may provide 'postgres://' but SQLAlchemy requires 'postgresql://'
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if db_uri.startswith('postgres://'):
        app.config['SQLALCHEMY_DATABASE_URI'] = db_uri.replace(
            'postgres://', 'postgresql+psycopg://', 1
        )
    elif db_uri.startswith('postgresql://') and '+' not in db_uri.split('://')[0]:
        # Ensure psycopg3 driver is used (not psycopg2)
        app.config['SQLALCHEMY_DATABASE_URI'] = db_uri.replace(
            'postgresql://', 'postgresql+psycopg://', 1
        )

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    # Set rate limiter storage: Redis in production, memory in development
    limiter_storage = app.config.get('RATELIMIT_STORAGE_URI', 'memory://')
    limiter._storage_uri = limiter_storage
    limiter.init_app(app)

    # Initialize Celery with Flask app context
    from app.celery_app import init_celery
    init_celery(app)

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if app.debug else logging.INFO,
        format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )

    # Ensure data directories exist (use absolute paths based on project root)
    from app.config import PROJECT_ROOT
    os.makedirs(os.path.join(PROJECT_ROOT, 'data', 'reports'), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, 'data', 'ml_models'), exist_ok=True)
    os.makedirs(os.path.join(PROJECT_ROOT, 'logs'), exist_ok=True)

    # Initialize database (create tables)
    with app.app_context():
        # Import ML and advanced models so their tables are created
        from app.models.ml_training import ScanAttempt, MLModel  # noqa: F401
        from app.models.api_key import APIKey  # noqa: F401
        from app.models.webhook import Webhook  # noqa: F401
        from app.models.organization import OrganizationModel, OrgMembershipModel  # noqa: F401
        init_db()

        # Fix 3: Recover scans orphaned by previous server crash
        from app.models.scan import Scan
        recovered = Scan.recover_orphaned(max_age_minutes=10)
        if recovered:
            app.logger.warning(f"Recovered {recovered} orphaned scan(s) from previous run")

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

    return app
