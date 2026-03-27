"""
Tests for multi-tenancy hardening changes.
Tests org-aware queries, org settings, plan limits, and GDPR purge.
"""

import pytest
from unittest.mock import patch, MagicMock


class TestOrgAwareQueries:
    """Test that Scan queries are org-aware via for_user_query."""

    def test_for_user_query_method_exists(self):
        """for_user_query should exist and be callable for org-aware queries."""
        from app.models.scan import Scan

        assert hasattr(Scan, 'for_user_query')
        assert callable(Scan.for_user_query)

    def test_delete_by_org_method_exists(self):
        """Scan.delete_by_org should be available for GDPR compliance."""
        from app.models.scan import Scan
        assert hasattr(Scan, 'delete_by_org')
        assert callable(Scan.delete_by_org)


class TestOrgSettings:
    """Test organization settings model and helpers."""

    def test_org_settings_model_exists(self):
        """OrgSettingsModel should be importable."""
        from app.models.organization import OrgSettingsModel
        assert OrgSettingsModel.__tablename__ == 'org_settings'

    def test_organization_has_get_settings(self):
        """Organization helper class should have get_settings."""
        from app.models.organization import Organization
        assert hasattr(Organization, 'get_settings')
        assert callable(Organization.get_settings)

    def test_organization_has_update_settings(self):
        """Organization helper class should have update_settings."""
        from app.models.organization import Organization
        assert hasattr(Organization, 'update_settings')
        assert callable(Organization.update_settings)


class TestPlanLimits:
    """Test plan-based resource limits."""

    def test_plan_limits_defined(self):
        """Config should define PLAN_LIMITS for free, pro, enterprise."""
        from app.config import Config
        assert hasattr(Config, 'PLAN_LIMITS')
        assert 'free' in Config.PLAN_LIMITS
        assert 'pro' in Config.PLAN_LIMITS
        assert 'enterprise' in Config.PLAN_LIMITS

    def test_free_plan_has_limits(self):
        from app.config import Config
        free = Config.PLAN_LIMITS['free']
        assert free['max_scans_per_month'] == 5
        assert free['max_concurrent_scans'] == 1
        assert free['ai_analysis'] is False

    def test_enterprise_plan_unlimited(self):
        from app.config import Config
        ent = Config.PLAN_LIMITS['enterprise']
        assert ent['max_scans_per_month'] == -1  # unlimited
        assert ent['ai_analysis'] is True

    def test_check_scan_quota_exists(self):
        """Organization should have check_scan_quota method."""
        from app.models.organization import Organization
        assert hasattr(Organization, 'check_scan_quota')

    def test_quota_allows_when_no_org(self):
        """No org_id should always allow scans."""
        from app.models.organization import Organization
        allowed, reason = Organization.check_scan_quota(None)
        assert allowed is True
        assert reason == ''


class TestGDPRPurge:
    """Test GDPR-compliant tenant data deletion."""

    def test_delete_all_data_exists(self):
        """Organization should have delete_all_data for GDPR compliance."""
        from app.models.organization import Organization
        assert hasattr(Organization, 'delete_all_data')
        assert callable(Organization.delete_all_data)


class TestOrgScopedAPIKeys:
    """Test org-scoped API key support."""

    def test_api_key_has_org_id(self):
        """APIKey model should have org_id column."""
        from app.models.api_key import APIKey
        assert hasattr(APIKey, 'org_id')

    def test_api_key_create_accepts_org_id(self):
        """APIKey.create should accept org_id parameter."""
        import inspect
        from app.models.api_key import APIKey
        sig = inspect.signature(APIKey.create)
        assert 'org_id' in sig.parameters
