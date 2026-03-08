import bcrypt
import logging
from app.models.database import db, UserModel

logger = logging.getLogger(__name__)


class User:
    """User operations backed by SQLAlchemy ORM.
    Keeps the same static method API used by routes and scan_manager."""

    @staticmethod
    def hash_password(password):
        """Hash a password using bcrypt with work factor 12."""
        return bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt(rounds=12)
        ).decode('utf-8')

    @staticmethod
    def verify_password(password, stored_hash):
        """Verify a password against the stored hash.
        Supports both bcrypt (new) and legacy SHA-256 hashes."""
        try:
            if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'):
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    stored_hash.encode('utf-8')
                )
            import hashlib
            if ':' in stored_hash:
                salt, hashed = stored_hash.split(':', 1)
                return hashlib.sha256(
                    (password + salt).encode()
                ).hexdigest() == hashed
            return False
        except (ValueError, AttributeError) as e:
            logger.warning(f"Password verification error: {e}")
            return False

    @staticmethod
    def _migrate_hash(user_id, password):
        """Re-hash a legacy SHA-256 password with bcrypt and update the DB."""
        new_hash = User.hash_password(password)
        try:
            user = db.session.get(UserModel, user_id)
            if user:
                user.password_hash = new_hash
                db.session.commit()
                logger.info(f"Migrated password hash to bcrypt for user {user_id}")
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Failed to migrate hash for user {user_id}: {e}")

    @staticmethod
    def create(username, email, password):
        password_hash = User.hash_password(password)
        try:
            user = UserModel(username=username, email=email, password_hash=password_hash)
            db.session.add(user)
            db.session.commit()
            return user.id
        except Exception as e:
            db.session.rollback()
            logger.warning(f"User creation failed: {e}")
            return None

    @staticmethod
    def _row_to_dict(user):
        """Convert a UserModel to dict matching old sqlite3.Row interface."""
        if user is None:
            return None
        return {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'password_hash': user.password_hash,
            'created_at': user.created_at.isoformat() if user.created_at else None,
        }

    @staticmethod
    def get_by_id(user_id):
        return User._row_to_dict(db.session.get(UserModel, user_id))

    @staticmethod
    def get_by_username(username):
        user = UserModel.query.filter_by(username=username).first()
        return User._row_to_dict(user)

    @staticmethod
    def get_by_email(email):
        user = UserModel.query.filter_by(email=email).first()
        return User._row_to_dict(user)

    @staticmethod
    def authenticate(username, password):
        user = User.get_by_username(username)
        if user and User.verify_password(password, user['password_hash']):
            stored = user['password_hash']
            if not (stored.startswith('$2b$') or stored.startswith('$2a$')):
                User._migrate_hash(user['id'], password)
            return user
        return None
