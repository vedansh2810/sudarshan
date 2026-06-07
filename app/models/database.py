"""SQLAlchemy ORM models and database initialization."""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone


db = SQLAlchemy()


class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    supabase_uid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    scans = db.relationship(
        "ScanModel", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )


class ScanModel(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    org_id = db.Column(
        db.Integer, db.ForeignKey("organizations.id"), nullable=True, index=True
    )
    target_url = db.Column(db.Text, nullable=False)
    scan_mode = db.Column(db.String(20), default="active")
    scan_speed = db.Column(db.String(20), default="balanced")
    crawl_depth = db.Column(db.Integer, default=3)
    status = db.Column(db.String(20), default="pending", index=True)
    score = db.Column(db.String(2), default=None)
    total_urls = db.Column(db.Integer, default=0)
    tested_urls = db.Column(db.Integer, default=0)
    vuln_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    duration = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    completed_at = db.Column(db.DateTime, default=None)

    __table_args__ = (
        db.Index("ix_scans_user_started", "user_id", "started_at"),
        db.Index("ix_scans_status_started", "status", "started_at"),
    )

    vulnerabilities = db.relationship(
        "VulnerabilityModel",
        backref="scan",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    crawled_urls = db.relationship(
        "CrawledUrlModel", backref="scan", lazy="dynamic", cascade="all, delete-orphan"
    )
    logs = db.relationship(
        "ScanLogModel", backref="scan", lazy="dynamic", cascade="all, delete-orphan"
    )


class VulnerabilityModel(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    vuln_type = db.Column(db.String(50), nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    impact = db.Column(db.Text)
    severity = db.Column(db.String(20), default="medium", index=True)
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

    __table_args__ = (
        db.Index("ix_vulns_scan_severity", "scan_id", "severity"),
    )


class CrawledUrlModel(db.Model):
    __tablename__ = "crawled_urls"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    status_code = db.Column(db.Integer)
    forms_found = db.Column(db.Integer, default=0)
    params_found = db.Column(db.Integer, default=0)
    crawled_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ScanLogModel(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    log_type = db.Column(db.String(20), default="info")
    message = db.Column(db.Text, nullable=False)
    logged_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.Index("ix_logs_scan_logged", "scan_id", "logged_at"),
    )


def init_db():
    """Create all tables.

    All columns (including org_id, AI columns, etc.) are now declared in the
    ORM models above, so db.create_all() creates them correctly on fresh
    databases.  For existing databases that need schema updates, use
    Flask-Migrate:

        flask db migrate -m "description"
        flask db upgrade

    The manual ALTER TABLE statements that used to live here have been
    removed — they were fragile (no idempotency guarantees across DB engines)
    and duplicated what Flask-Migrate already handles.
    """
    db.create_all()

