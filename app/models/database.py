"""SQLAlchemy ORM models and database initialization."""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import re

db = SQLAlchemy()


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scans = db.relationship('ScanModel', backref='user', lazy='dynamic',
                            cascade='all, delete-orphan')


class ScanModel(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target_url = db.Column(db.Text, nullable=False)
    scan_mode = db.Column(db.String(20), default='active')
    scan_speed = db.Column(db.String(20), default='balanced')
    crawl_depth = db.Column(db.Integer, default=3)
    status = db.Column(db.String(20), default='pending')
    score = db.Column(db.String(2), default=None)
    total_urls = db.Column(db.Integer, default=0)
    tested_urls = db.Column(db.Integer, default=0)
    vuln_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    duration = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, default=None)

    vulnerabilities = db.relationship('VulnerabilityModel', backref='scan',
                                      lazy='dynamic', cascade='all, delete-orphan')
    crawled_urls = db.relationship('CrawledUrlModel', backref='scan',
                                   lazy='dynamic', cascade='all, delete-orphan')
    logs = db.relationship('ScanLogModel', backref='scan',
                           lazy='dynamic', cascade='all, delete-orphan')


class VulnerabilityModel(db.Model):
    __tablename__ = 'vulnerabilities'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vuln_type = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    impact = db.Column(db.Text)
    severity = db.Column(db.String(20), default='medium')
    cvss_score = db.Column(db.Float, default=0.0)
    owasp_category = db.Column(db.String(50))
    affected_url = db.Column(db.Text)
    parameter = db.Column(db.String(200))
    payload = db.Column(db.Text)
    request_data = db.Column(db.Text)
    response_data = db.Column(db.Text)
    remediation = db.Column(db.Text)
    found_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class CrawledUrlModel(db.Model):
    __tablename__ = 'crawled_urls'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    url = db.Column(db.Text, nullable=False)
    status_code = db.Column(db.Integer)
    forms_found = db.Column(db.Integer, default=0)
    params_found = db.Column(db.Integer, default=0)
    crawled_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ScanLogModel(db.Model):
    __tablename__ = 'scan_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    log_type = db.Column(db.String(20), default='info')
    message = db.Column(db.Text, nullable=False)
    logged_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


def init_db():
    """Create all tables. Called from app factory after db.init_app()."""
    db.create_all()


# ── Backward-compatible helpers for scan_manager.py ──────────────────────
# scan_manager.py calls execute_db directly (line 213) and route files
# that haven't been migrated yet may still use query_db.

def _convert_placeholders(query, args):
    """Convert '?' positional placeholders to ':pN' named params for SQLAlchemy."""
    if not args:
        return query, {}
    params = {}
    idx = [0]

    def replacer(match):
        key = f'p{idx[0]}'
        params[key] = args[idx[0]]
        idx[0] += 1
        return f':{key}'

    converted_query = re.sub(r'\?', replacer, query)
    return converted_query, params


def query_db(query, args=(), one=False):
    """Legacy compatibility: run raw SQL SELECT via SQLAlchemy."""
    converted, params = _convert_placeholders(query, args)
    result = db.session.execute(db.text(converted), params)
    rows = [dict(row._mapping) for row in result]
    if one:
        return rows[0] if rows else None
    return rows


def execute_db(query, args=()):
    """Legacy compatibility: run raw SQL INSERT/UPDATE/DELETE via SQLAlchemy."""
    converted, params = _convert_placeholders(query, args)
    result = db.session.execute(db.text(converted), params)
    db.session.commit()
    # For INSERT, try to get the last inserted row id
    try:
        return result.lastrowid
    except Exception:
        return None
