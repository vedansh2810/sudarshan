import os

# Project root is two levels up from this file (app/config.py -> app/ -> project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-insecure-key-change-me')

    # ── Database (PostgreSQL via Supabase) ────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(PROJECT_ROOT, 'data', 'database.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 5,
        'max_overflow': 10,
        'pool_timeout': 30,
        'pool_recycle': 300,     # Recycle connections every 5 min (Supabase pooler compat)
        'pool_pre_ping': True,   # Verify connections before use
    }

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF tokens valid for 1 hour

    # Redis + Celery (optional — falls back to in-process threading if unavailable)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))

    # Supabase Auth
    SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
    SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', '')
    SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY', '')

    # Rate limiter storage (default: in-memory; overridden to Redis in production)
    RATELIMIT_STORAGE_URI = 'memory://'

    # AI / LLM Configuration (Groq — Llama 3.3 70B)
    GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
    GROQ_MODEL = os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile')

    SCAN_SPEEDS = {
        'safe': {
            'delay': 1.0,
            'threads': 3,
            'timeout': 10,
            'max_urls': 75
        },
        'balanced': {
            'delay': 0.15,
            'threads': 6,
            'timeout': 8,
            'max_urls': 200
        },
        'aggressive': {
            'delay': 0.05,
            'threads': 10,
            'timeout': 5,
            'max_urls': 500
        }
    }

    SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']

    OWASP_CATEGORIES = {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable Components',
        'A07': 'Identification and Auth Failures',
        'A08': 'Software and Data Integrity Failures',
        'A09': 'Security Logging Failures',
        'A10': 'Server-Side Request Forgery'
    }

    VULNERABILITY_CHECKS = [
        'sql_injection',
        'xss',
        'csrf',
        'security_headers',
        'directory_traversal',
        'command_injection',
        'idor',
        'directory_listing',
        'xxe',
        'ssrf',
        'open_redirect',
        'cors',
        'clickjacking',
        'ssti',
        'jwt_attacks',
        'broken_auth',
    ]

    # ── Plan-based resource limits ─────────────────────────────────────
    PLAN_LIMITS = {
        'free': {
            'max_scans_per_month': 5,
            'max_concurrent_scans': 1,
            'max_team_members': 3,
            'max_urls_per_scan': 100,
            'ai_analysis': False,
        },
        'pro': {
            'max_scans_per_month': 50,
            'max_concurrent_scans': 3,
            'max_team_members': 15,
            'max_urls_per_scan': 500,
            'ai_analysis': True,
        },
        'enterprise': {
            'max_scans_per_month': -1,  # unlimited
            'max_concurrent_scans': 10,
            'max_team_members': -1,  # unlimited
            'max_urls_per_scan': -1,  # unlimited
            'ai_analysis': True,
        },
    }

class DevelopmentConfig(Config):
    DEBUG = True
    RATELIMIT_STORAGE_URI = 'memory://'

class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        Config.SQLALCHEMY_DATABASE_URI
    )
    # Use Redis for rate limiting in production (shared across workers)
    RATELIMIT_STORAGE_URI = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    @staticmethod
    def init_app(app):
        if not app.config.get('SECRET_KEY'):
            raise RuntimeError(
                "SECRET_KEY environment variable is REQUIRED in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
