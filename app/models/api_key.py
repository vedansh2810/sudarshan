"""
API Key model for JWT-less API authentication.
Uses HMAC-SHA256 with the app's SECRET_KEY for key hashing.

Upgrade from raw SHA-256: HMAC binds the hash to the app's secret,
preventing offline rainbow-table attacks even if the DB is leaked.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from flask import current_app
from app.models.database import db


class APIKey(db.Model):
    """API Key for programmatic access."""
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    key_prefix = db.Column(db.String(8))  # First 8 chars for identification

    is_active = db.Column(db.Boolean, default=True, index=True)
    expires_at = db.Column(db.DateTime)
    last_used = db.Column(db.DateTime)
    usage_count = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    user = db.relationship('UserModel', backref=db.backref('api_keys', lazy='dynamic'))

    def __repr__(self):
        return f'<APIKey {self.key_prefix}... ({self.name})>'

    @staticmethod
    def _hash_key(key):
        """Hash an API key using HMAC-SHA256 with the app's SECRET_KEY.

        HMAC prevents rainbow-table attacks if the database is compromised:
        the attacker also needs SECRET_KEY to compute valid hashes.
        """
        secret = current_app.config['SECRET_KEY']
        return hmac.new(
            secret.encode('utf-8'),
            key.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _hash_key_legacy(key):
        """Legacy SHA-256 hash (for backward-compatible lookups)."""
        return hashlib.sha256(key.encode()).hexdigest()

    @classmethod
    def create(cls, user_id, name, expires_at=None):
        """Create a new API key.

        Returns:
            Tuple (APIKey instance, plaintext_key).
            The plaintext key is only returned once and cannot be recovered.
        """
        plaintext_key = f'sdk_{secrets.token_hex(32)}'
        key_hash = cls._hash_key(plaintext_key)

        api_key = cls(
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=plaintext_key[:8],
            expires_at=expires_at,
        )
        db.session.add(api_key)
        db.session.commit()
        return api_key, plaintext_key

    @classmethod
    def verify(cls, key):
        """Verify an API key and return the user_id if valid.

        Tries HMAC-SHA256 first, then falls back to legacy SHA-256 for
        backward compatibility. If a legacy key matches, it is re-hashed
        with HMAC-SHA256 (transparent migration).

        Returns:
            user_id (int) or None.
        """
        # Try HMAC-SHA256 (new keys)
        key_hash = cls._hash_key(key)
        api_key = cls.query.filter_by(key_hash=key_hash, is_active=True).first()

        if not api_key:
            # Fallback: try legacy SHA-256 (old keys created before the upgrade)
            legacy_hash = cls._hash_key_legacy(key)
            api_key = cls.query.filter_by(key_hash=legacy_hash, is_active=True).first()

            if api_key:
                # Transparent migration: re-hash with HMAC-SHA256
                api_key.key_hash = key_hash
                db.session.commit()

        if not api_key:
            return None

        # Check expiry
        if api_key.expires_at and datetime.now(timezone.utc) > api_key.expires_at:
            return None

        # Update last used
        api_key.last_used = datetime.now(timezone.utc)
        api_key.usage_count = (api_key.usage_count or 0) + 1
        db.session.commit()

        return api_key.user_id

    @classmethod
    def deactivate(cls, key_id, user_id):
        """Deactivate an API key (soft delete)."""
        key = cls.query.filter_by(id=key_id, user_id=user_id).first()
        if key:
            key.is_active = False
            db.session.commit()
            return True
        return False
