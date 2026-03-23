"""User operations backed by SQLAlchemy ORM.
Authentication is handled by Supabase — this module manages local user records."""
import logging
from app.models.database import db, UserModel

logger = logging.getLogger(__name__)


class User:
    """User CRUD operations.
    Supabase handles authentication; this class manages the local user record
    that maps supabase_uid to a local integer ID for FK relationships."""

    @staticmethod
    def _row_to_dict(user):
        """Convert a UserModel to dict matching old sqlite3.Row interface."""
        if user is None:
            return None
        return {
            'id': user.id,
            'supabase_uid': user.supabase_uid,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'created_at': user.created_at.isoformat() if user.created_at else None,
        }

    @staticmethod
    def get_or_create_from_supabase(supabase_user):
        """Find or create a local user from Supabase user data.
        
        Args:
            supabase_user: Supabase user object with .id, .email, .user_metadata
        
        Returns:
            dict with local user data, or None on failure
        """
        uid = supabase_user.id
        email = supabase_user.email or ''
        metadata = supabase_user.user_metadata or {}
        
        # Derive username from metadata or email
        username = (
            metadata.get('preferred_username')
            or metadata.get('user_name')
            or metadata.get('name')
            or metadata.get('full_name')
            or email.split('@')[0] if email else f'user_{uid[:8]}'
        )

        try:
            # Check if user already exists by supabase_uid
            existing = UserModel.query.filter_by(supabase_uid=uid).first()
            if existing:
                # Update email if it changed in Supabase
                if existing.email != email and email:
                    existing.email = email
                    db.session.commit()
                return User._row_to_dict(existing)

            # Ensure username is unique (append suffix if taken)
            base_username = username
            counter = 1
            while UserModel.query.filter_by(username=username).first():
                username = f"{base_username}_{counter}"
                counter += 1

            # Create new local user
            user = UserModel(
                supabase_uid=uid,
                username=username,
                email=email
            )
            db.session.add(user)
            db.session.commit()
            logger.info(f"Created local user {username} (supabase_uid={uid[:8]}...)")
            return User._row_to_dict(user)

        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to get/create user from Supabase: {e}")
            return None

    @staticmethod
    def get_by_id(user_id):
        return User._row_to_dict(db.session.get(UserModel, user_id))

    @staticmethod
    def get_by_supabase_uid(uid):
        user = UserModel.query.filter_by(supabase_uid=uid).first()
        return User._row_to_dict(user)

    @staticmethod
    def get_by_username(username):
        user = UserModel.query.filter_by(username=username).first()
        return User._row_to_dict(user)

    @staticmethod
    def get_by_email(email):
        user = UserModel.query.filter_by(email=email).first()
        return User._row_to_dict(user)
