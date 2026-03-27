"""Organization and team membership models for multi-tenant data isolation."""
import re
import logging
from datetime import datetime, timezone
from app.models.database import db
from app.config import Config

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


class OrgSettingsModel(db.Model):
    """Per-organization configuration and policies."""
    __tablename__ = 'org_settings'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), unique=True, nullable=False)
    max_scans_per_month = db.Column(db.Integer, nullable=True)  # None = use plan default
    allowed_domains = db.Column(db.Text, nullable=True)  # JSON list of allowed target domains
    notification_email = db.Column(db.String(200), nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    organization = db.relationship('OrganizationModel',
                                   backref=db.backref('settings', uselist=False, cascade='all, delete-orphan'))


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

    @staticmethod
    def delete_all_data(org_id):
        """Delete ALL data for an organization (GDPR 'right to erasure').

        Deletes: scans (cascading to vulns, logs, crawled_urls),
        API keys, webhooks, memberships, settings, and the org itself.
        """
        import json
        try:
            # Delete scans (cascade handles vulnerabilities, logs, crawled_urls)
            from app.models.scan import Scan
            scan_count = Scan.delete_by_org(org_id)

            # Delete org-scoped API keys
            from app.models.api_key import APIKey
            APIKey.query.filter_by(org_id=org_id).delete()

            # Delete webhooks owned by org members
            member_ids = [m.user_id for m in
                          OrgMembershipModel.query.filter_by(org_id=org_id).all()]
            if member_ids:
                from app.models.webhook import Webhook
                Webhook.query.filter(
                    Webhook.user_id.in_(member_ids)
                ).delete(synchronize_session='fetch')

            # Delete settings
            OrgSettingsModel.query.filter_by(org_id=org_id).delete()

            # Delete memberships
            OrgMembershipModel.query.filter_by(org_id=org_id).delete()

            # Delete the organization itself
            org = db.session.get(OrganizationModel, org_id)
            if org:
                db.session.delete(org)

            db.session.commit()
            logger.info(f"GDPR purge: deleted org {org_id} ({scan_count} scans)")
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"GDPR purge failed for org {org_id}: {e}")
            return False

    @staticmethod
    def get_plan_limits(org_id):
        """Get resource limits for an organization based on its plan."""
        org = db.session.get(OrganizationModel, org_id)
        if not org:
            return Config.PLAN_LIMITS.get('free', {})
        plan = org.plan or 'free'
        return Config.PLAN_LIMITS.get(plan, Config.PLAN_LIMITS.get('free', {}))

    @staticmethod
    def check_scan_quota(org_id):
        """Check if the organization has remaining scan quota.

        Returns:
            (allowed: bool, reason: str)
        """
        if not org_id:
            return True, ''

        limits = Organization.get_plan_limits(org_id)
        max_scans = limits.get('max_scans_per_month', -1)
        if max_scans == -1:
            return True, ''

        # Check custom override from org settings
        settings = OrgSettingsModel.query.filter_by(org_id=org_id).first()
        if settings and settings.max_scans_per_month is not None:
            max_scans = settings.max_scans_per_month

        from app.models.database import ScanModel
        from datetime import timedelta
        month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        current_count = ScanModel.query.filter(
            ScanModel.org_id == org_id,
            ScanModel.started_at >= month_start
        ).count()

        if current_count >= max_scans:
            return False, f'Monthly scan quota reached ({current_count}/{max_scans}). Upgrade your plan.'
        return True, ''

    @staticmethod
    def get_settings(org_id):
        """Get org settings as a dict."""
        import json
        settings = OrgSettingsModel.query.filter_by(org_id=org_id).first()
        if not settings:
            return {'org_id': org_id, 'max_scans_per_month': None, 'allowed_domains': [], 'notification_email': None}
        domains = []
        if settings.allowed_domains:
            try:
                domains = json.loads(settings.allowed_domains)
            except Exception:
                pass
        return {
            'org_id': org_id,
            'max_scans_per_month': settings.max_scans_per_month,
            'allowed_domains': domains,
            'notification_email': settings.notification_email,
        }

    @staticmethod
    def update_settings(org_id, **kwargs):
        """Update org settings. Creates if not exists."""
        import json
        settings = OrgSettingsModel.query.filter_by(org_id=org_id).first()
        if not settings:
            settings = OrgSettingsModel(org_id=org_id)
            db.session.add(settings)
        if 'max_scans_per_month' in kwargs:
            settings.max_scans_per_month = kwargs['max_scans_per_month']
        if 'allowed_domains' in kwargs:
            settings.allowed_domains = json.dumps(kwargs['allowed_domains'])
        if 'notification_email' in kwargs:
            settings.notification_email = kwargs['notification_email']
        db.session.commit()
        return Organization.get_settings(org_id)
