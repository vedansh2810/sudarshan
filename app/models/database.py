"""SQLAlchemy ORM models and database initialization."""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import re

db = SQLAlchemy()


class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    supabase_uid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scans = db.relationship('ScanModel', backref='user', lazy='dynamic',
                            cascade='all, delete-orphan')


class ScanModel(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)
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
    ai_analysis = db.Column(db.Text)  # JSON string from LLM analysis
    ai_narrative = db.Column(db.Text)  # JSON string from attack narrative
    likely_false_positive = db.Column(db.Boolean, default=False)
    fp_confidence = db.Column(db.Float, nullable=True)
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
    """Create all tables and apply column migrations for existing tables."""
    import logging
    logger = logging.getLogger(__name__)

    try:
        db.create_all()
        logger.info("Database tables created/verified successfully")
    except Exception as e:
        # Tables likely already exist with slightly different schema (e.g. TIMESTAMPTZ vs TIMESTAMP)
        # This is normal when connecting to an existing Supabase database
        logger.warning(f"create_all() encountered an issue (tables may already exist): {e}")
        # Try to create only missing tables individually
        try:
            from sqlalchemy import inspect as sa_inspect
            existing = sa_inspect(db.engine).get_table_names()
            for table in db.metadata.sorted_tables:
                if table.name not in existing:
                    table.create(db.engine, checkfirst=True)
                    logger.info(f"Created missing table: {table.name}")
        except Exception as e2:
            logger.warning(f"Individual table creation also failed: {e2}")

    # Apply column migrations for existing tables that need new columns
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)

    # Migration: add org_id to scans table (Phase 1.4)
    if 'scans' in inspector.get_table_names():
        existing_cols = {c['name'] for c in inspector.get_columns('scans')}
        if 'org_id' not in existing_cols:
            with db.engine.begin() as conn:
                conn.execute(text(
                    'ALTER TABLE scans ADD COLUMN org_id INTEGER REFERENCES organizations(id)'
                ))

    # Migration: add AI columns to vulnerabilities table
    if 'vulnerabilities' in inspector.get_table_names():
        existing_cols = {c['name'] for c in inspector.get_columns('vulnerabilities')}
        new_cols = {
            'ai_analysis': 'TEXT',
            'ai_narrative': 'TEXT',
            'likely_false_positive': 'BOOLEAN DEFAULT FALSE',
            'fp_confidence': 'FLOAT',
        }
        for col_name, col_type in new_cols.items():
            if col_name not in existing_cols:
                with db.engine.begin() as conn:
                    conn.execute(text(
                        f'ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}'
                    ))

    # Migration: add org_id to api_keys table
    if 'api_keys' in inspector.get_table_names():
        existing_cols = {c['name'] for c in inspector.get_columns('api_keys')}
        if 'org_id' not in existing_cols:
            with db.engine.begin() as conn:
                conn.execute(text(
                    'ALTER TABLE api_keys ADD COLUMN org_id INTEGER REFERENCES organizations(id)'
                ))


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


def execute_db(query, args=()):
    """Legacy compatibility: run raw SQL INSERT/UPDATE/DELETE via SQLAlchemy.

    Works with both SQLite and PostgreSQL by using RETURNING for INSERTs.
    """
    converted, params = _convert_placeholders(query, args)

    # For INSERT statements on PostgreSQL, add RETURNING id to get the new row's PK
    is_insert = converted.strip().upper().startswith('INSERT')
    if is_insert and 'RETURNING' not in converted.upper():
        converted = converted.rstrip().rstrip(';') + ' RETURNING id'

    result = db.session.execute(db.text(converted), params)
    db.session.commit()

    if is_insert:
        try:
            row = result.fetchone()
            return row[0] if row else None
        except Exception:
            return None
    return None

