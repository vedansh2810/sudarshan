import os

# Project root is two levels up from this file (app/config.py -> app/ -> project root)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-insecure-key-change-me')
    DATABASE_PATH = os.path.join(PROJECT_ROOT, 'data', 'database.db')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(PROJECT_ROOT, 'data', 'database.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    WTF_CSRF_TIME_LIMIT = 3600  # CSRF tokens valid for 1 hour

    # Redis + Celery (optional — falls back to in-process threading if unavailable)
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    # Celery 5.x uses lowercase config keys
    broker_url = os.environ.get('CELERY_BROKER_URL', os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
    result_backend = os.environ.get('CELERY_RESULT_BACKEND', os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))

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
        'directory_listing'
    ]

class DevelopmentConfig(Config):
    DEBUG = True
    # Dev convenience: fallback key is fine for local development
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-insecure-key-change-me')

class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        Config.SQLALCHEMY_DATABASE_URI
    )

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
