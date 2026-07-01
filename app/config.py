import os
from datetime import timedelta
from dotenv import load_dotenv

# Load .env file FIRST, before Config class attributes read os.environ.
# This MUST happen at module level (not inside create_app) because Config
# class attributes like SUPABASE_URL = os.environ.get(...) are evaluated
# at import time when Python first loads this module.
load_dotenv()

# Project root is two levels up from this file (app/config.py -> app/ -> project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

import secrets


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # ── Database (PostgreSQL via Supabase) ────────────────────────────────
    _sqlite_default = "sqlite:///" + os.path.join(PROJECT_ROOT, "data", "database.db")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "") or _sqlite_default
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": 10,
        "max_overflow": 20,
        "pool_timeout": 30,
        "pool_recycle": 1800,  # Recycle connections every 30 min
        "pool_pre_ping": True,  # Verify connections before use
    }

    # ── Session security ──────────────────────────────────────────────────
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)  # Sessions expire after 8h
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = (
        False  # HTTP allowed in development; overridden in ProductionConfig
    )
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF tokens valid for 1 hour

    # ── Security response headers ─────────────────────────────────────────
    # Applied via after_request middleware in __init__.py
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        # X-XSS-Protection deliberately omitted — deprecated by modern browsers
        # and can introduce vulnerabilities in older ones. Rely on CSP instead.
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }

    # Redis + Celery (optional — falls back to in-process threading if unavailable)
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL = os.environ.get(
        "CELERY_BROKER_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    )
    CELERY_RESULT_BACKEND = os.environ.get(
        "CELERY_RESULT_BACKEND", os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    )

    # Supabase Auth
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
    SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

    # Rate limiter storage (default: in-memory; overridden to Redis in production)
    RATELIMIT_STORAGE_URI = "memory://"

    # AI / LLM Configuration (Groq — Qwen3 32B)
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    GROQ_API_KEYS = os.environ.get("GROQ_API_KEYS", "")  # Comma-separated, for key rotation
    GROQ_MODEL = os.environ.get("GROQ_MODEL", "qwen/qwen3-32b")

    # ── Scanner Identity ──────────────────────────────────────────────────
    # These headers are sent with EVERY outgoing HTTP request during a scan.
    # They allow the target's security team to identify Sudarshan in their
    # server logs (access logs, WAF, IDS/IPS) and confirm the scan is authorized.
    SCANNER_NAME = "Sudarshan"
    SCANNER_VERSION = "1.0"
    SCANNER_USER_AGENT = f"Sudarshan-Scanner/{SCANNER_VERSION} (Authorized Security Scan)"
    SCANNER_HEADERS = {
        "User-Agent": SCANNER_USER_AGENT,
        "X-Scanner": SCANNER_NAME,
        "X-Scanner-Version": SCANNER_VERSION,
    }

    SCAN_SPEEDS = {
        "safe": {"delay": 1.0, "threads": 3, "timeout": 10, "max_urls": 75},
        "balanced": {"delay": 0.15, "threads": 6, "timeout": 8, "max_urls": 200},
        "aggressive": {"delay": 0.05, "threads": 10, "timeout": 5, "max_urls": 500},
    }

    SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

    OWASP_CATEGORIES = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable Components",
        "A07": "Identification and Auth Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging Failures",
        "A10": "Server-Side Request Forgery",
    }

    VULNERABILITY_CHECKS = [
        "sql_injection",
        "xss",
        "csrf",
        "security_headers",
        "directory_traversal",
        "command_injection",
        "idor",
        "directory_listing",
        "xxe",
        "ssrf",
        "open_redirect",
        "cors",
        "clickjacking",
        "ssti",
        "jwt_attacks",
        "broken_auth",
        "nosql_injection",
        "file_upload",
        "host_header",
        "info_disclosure",
        "prototype_pollution",
        "insecure_deserialization",
    ]

    # Allow skipping TLS verification for testing local/unsafe targets.
    # Default: False. Set environment variable ALLOW_INSECURE_TARGETS=1 to allow.
    ALLOW_INSECURE_TARGETS = os.environ.get("ALLOW_INSECURE_TARGETS", "0") in (
        "1",
        "true",
        "True",
        "yes",
        "YES",
    )

    # Allow destructive SQL payloads (DROP TABLE, INSERT INTO, etc.) in scans.
    # Default: False. Only enable for controlled lab environments.
    ALLOW_DESTRUCTIVE_PAYLOADS = os.environ.get("ALLOW_DESTRUCTIVE_PAYLOADS", "0") in (
        "1",
        "true",
        "True",
        "yes",
    )

    # ── Plan-based resource limits ─────────────────────────────────────
    PLAN_LIMITS = {
        "free": {
            "max_scans_per_month": 5,
            "max_concurrent_scans": 1,
            "max_team_members": 3,
            "max_urls_per_scan": 100,
            "ai_analysis": False,
        },
        "pro": {
            "max_scans_per_month": 50,
            "max_concurrent_scans": 3,
            "max_team_members": 15,
            "max_urls_per_scan": 500,
            "ai_analysis": True,
        },
        "enterprise": {
            "max_scans_per_month": -1,  # unlimited
            "max_concurrent_scans": 10,
            "max_team_members": -1,  # unlimited
            "max_urls_per_scan": -1,  # unlimited
            "ai_analysis": True,
        },
    }


class DevelopmentConfig(Config):
    DEBUG = True
    RATELIMIT_STORAGE_URI = "memory://"


class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # ── HTTPS enforcement ─────────────────────────────────────────────────
    SESSION_COOKIE_SECURE = True  # Cookie only sent over HTTPS
    PREFERRED_URL_SCHEME = "https"  # url_for() generates https:// links

    # ── Database ──────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", Config.SQLALCHEMY_DATABASE_URI
    )
    # Force SSL for PostgreSQL connections (prevents MitM on DB traffic)
    # For psycopg3, sslmode is passed via the URI, not connect_args
    _prod_db_url = os.environ.get("DATABASE_URL", Config.SQLALCHEMY_DATABASE_URI)
    if _prod_db_url and "postgresql" in _prod_db_url and "sslmode" not in _prod_db_url:
        _separator = "&" if "?" in _prod_db_url else "?"
        SQLALCHEMY_DATABASE_URI = _prod_db_url + _separator + "sslmode=require"
    else:
        SQLALCHEMY_DATABASE_URI = _prod_db_url

    SQLALCHEMY_ENGINE_OPTIONS = {
        **Config.SQLALCHEMY_ENGINE_OPTIONS,
    }

    # Use Redis for rate limiting in production (shared across workers)
    RATELIMIT_STORAGE_URI = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # Stricter HSTS header in production (added to base SECURITY_HEADERS)
    SECURITY_HEADERS = {
        **Config.SECURITY_HEADERS,
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://*.supabase.co wss://*.supabase.co"
        ),
    }

    @staticmethod
    def init_app(app):
        if not app.config.get("SECRET_KEY"):
            raise RuntimeError(
                "SECRET_KEY environment variable is REQUIRED in production. "
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )

        # ── Trust proxy headers (Render, Railway, etc.) ───────────────────
        # Required so request.remote_addr reflects the real client IP
        # rather than the load balancer's IP.
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
