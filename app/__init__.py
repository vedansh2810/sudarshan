"""Sudarshan Web Vulnerability Scanner - Application Factory"""
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.config import DevelopmentConfig
from app.models.database import db, init_db
import os
import logging

# Extensions (initialized here, bound to app in create_app)
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def create_app(config=None):
    # Load .env file early (python-dotenv is already in requirements)
    from dotenv import load_dotenv
    load_dotenv()

    app = Flask(__name__)
    app.config.from_object(config or DevelopmentConfig)

    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
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
    os.makedirs(os.path.join(PROJECT_ROOT, 'logs'), exist_ok=True)

    # Initialize database (create tables)
    with app.app_context():
        init_db()

    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.scan import scan_bp
    from app.routes.results import results_bp
    from app.routes.history import history_bp
    from app.routes.api import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(results_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(api_bp)

    return app

