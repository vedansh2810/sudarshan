"""Organization and team membership models for multi-tenant data isolation."""
import re
import logging
from datetime import datetime, timezone
from app.models.database import db

logger = logging.getLogger(__name__)


class OrganizationModel(db.Model):
    """Team/organization container."""
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    plan = db.Column(db.String(20), default='free')  # free / pro / enterprise
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    memberships = db.relationship('OrgMembershipModel', backref='organization',
                                  lazy='dynamic', cascade='all, delete-orphan')


class OrgMembershipModel(db.Model):
    """User ↔ Organization mapping with role."""
    __tablename__ = 'org_memberships'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    role = db.Column(db.String(20), default='member')  # owner / admin / member / viewer
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'org_id', name='uq_user_org'),
    )

    user = db.relationship('UserModel', backref=db.backref('memberships', lazy='dynamic'))


# ── Helper class ─────────────────────────────────────────────────────

class Organization:
    """Organization CRUD and membership operations."""

    @staticmethod
    def _slugify(name):
        """Generate a URL-safe slug from a name."""
        slug = re.sub(r'[^\w\s-]', '', name.lower().strip())
        slug = re.sub(r'[\s_]+', '-', slug)
        return slug[:100]

    @staticmethod
    def create(name, owner_user_id):
        """Create an organization and add the creator as owner.

        Returns:
            dict with org data, or None on failure.
        """
        slug = Organization._slugify(name)
        # Ensure unique slug
        base_slug = slug
        counter = 1
        while OrganizationModel.query.filter_by(slug=slug).first():
            slug = f"{base_slug}-{counter}"
            counter += 1

        try:
            org = OrganizationModel(name=name, slug=slug)
            db.session.add(org)
            db.session.flush()  # Get org.id

            membership = OrgMembershipModel(
                user_id=owner_user_id,
                org_id=org.id,
                role='owner'
            )
            db.session.add(membership)
            db.session.commit()
            logger.info(f"Created org '{name}' (slug={slug}) with owner user_id={owner_user_id}")
            return Organization._to_dict(org)
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create org: {e}")
            return None

    @staticmethod
    def get_by_id(org_id):
        org = db.session.get(OrganizationModel, org_id)
        return Organization._to_dict(org)

    @staticmethod
    def get_by_slug(slug):
        org = OrganizationModel.query.filter_by(slug=slug).first()
        return Organization._to_dict(org)

    @staticmethod
    def get_user_orgs(user_id):
        """Get all organizations a user belongs to."""
        memberships = OrgMembershipModel.query.filter_by(user_id=user_id).all()
        result = []
        for m in memberships:
            org = Organization._to_dict(m.organization)
            if org:
                org['role'] = m.role
                result.append(org)
        return result

    @staticmethod
    def get_user_org_ids(user_id):
        """Get list of org IDs a user belongs to (for query scoping)."""
        rows = db.session.query(OrgMembershipModel.org_id).filter_by(
            user_id=user_id
        ).all()
        return [r[0] for r in rows]

    @staticmethod
    def add_member(org_id, user_id, role='member'):
        """Add a user to an organization."""
        existing = OrgMembershipModel.query.filter_by(
            user_id=user_id, org_id=org_id
        ).first()
        if existing:
            existing.role = role
            db.session.commit()
            return True
        try:
            m = OrgMembershipModel(user_id=user_id, org_id=org_id, role=role)
            db.session.add(m)
            db.session.commit()
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to add member: {e}")
            return False

    @staticmethod
    def remove_member(org_id, user_id):
        """Remove a user from an organization."""
        m = OrgMembershipModel.query.filter_by(
            user_id=user_id, org_id=org_id
        ).first()
        if m:
            db.session.delete(m)
            db.session.commit()
            return True
        return False

    @staticmethod
    def get_members(org_id):
        """Get all members of an organization with roles."""
        memberships = OrgMembershipModel.query.filter_by(org_id=org_id).all()
        return [{
            'user_id': m.user_id,
            'role': m.role,
            'joined_at': m.joined_at.isoformat() if m.joined_at else None,
        } for m in memberships]

    @staticmethod
    def user_has_access(org_id, user_id):
        """Check if a user is a member of an organization."""
        return OrgMembershipModel.query.filter_by(
            user_id=user_id, org_id=org_id
        ).first() is not None

    @staticmethod
    def _to_dict(org):
        if org is None:
            return None
        return {
            'id': org.id,
            'name': org.name,
            'slug': org.slug,
            'plan': org.plan,
            'created_at': org.created_at.isoformat() if org.created_at else None,
        }
