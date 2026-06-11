"""Route-level integration tests for all major endpoints.

Tests authentication flows, scan management, API v2, and access control
using Flask's test client with an in-memory SQLite database.

Run with:
    pytest tests/test_routes.py -v
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from app import create_app
from app.config import Config
from app.models.database import db as _db, UserModel, ScanModel, VulnerabilityModel


# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret-routes"
    SERVER_NAME = "localhost"
    SUPABASE_URL = "https://fake.supabase.co"
    SUPABASE_SERVICE_KEY = "fake-service-key"
    SUPABASE_ANON_KEY = "fake-anon-key"
    RATELIMIT_ENABLED = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(app, client):
    """Authenticated client with a real user in the DB."""
    with app.app_context():
        user = UserModel(
            id=1,
            supabase_uid="route-test-uid",
            username="routeuser",
            email="route@example.com",
        )
        _db.session.add(user)
        _db.session.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "routeuser"
        sess["email"] = "route@example.com"
        sess["is_admin"] = False

    return client


def _create_scan(user_id, status="completed", target_url="https://example.com"):
    """Helper: create a scan in the DB."""
    scan = ScanModel(
        user_id=user_id,
        target_url=target_url,
        scan_mode="active",
        scan_speed="balanced",
        status=status,
        score="A",
        total_urls=5,
        tested_urls=5,
        vuln_count=0,
        duration=10,
    )
    _db.session.add(scan)
    _db.session.commit()
    return scan


# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------

class TestAuthRoutes:
    def test_login_page_loads(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_register_page_loads(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200

    def test_login_redirects_when_authenticated(self, auth_client):
        resp = auth_client.get("/login", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)

    def test_callback_missing_token(self, client):
        resp = client.post(
            "/auth/callback",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "access_token" in data.get("error", "").lower() or "missing" in data.get("error", "").lower()

    @patch("app.routes.auth._verify_supabase_token")
    def test_callback_invalid_token(self, mock_verify, client):
        mock_verify.return_value = None
        resp = client.post(
            "/auth/callback",
            data=json.dumps({"access_token": "bad-token"}),
            content_type="application/json",
        )
        assert resp.status_code == 401

    @patch("app.routes.auth._verify_supabase_token")
    def test_callback_successful_login(self, mock_verify, app, client):
        mock_verify.return_value = {
            "id": "supabase-uid-123",
            "email": "new@example.com",
            "user_metadata": {"preferred_username": "newuser"},
        }
        resp = client.post(
            "/auth/callback",
            data=json.dumps({"access_token": "valid-token"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get("success") is True
        assert "redirect" in data

    def test_logout(self, auth_client):
        resp = auth_client.get("/logout", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)

    def test_callback_handler_page_loads(self, client):
        resp = client.get("/auth/callback-handler")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Dashboard & History Routes
# ---------------------------------------------------------------------------

class TestDashboardRoutes:
    def test_dashboard_unauthenticated_redirects(self, client):
        resp = client.get("/dashboard", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)

    def test_dashboard_authenticated(self, auth_client):
        resp = auth_client.get("/dashboard")
        assert resp.status_code == 200

    def test_history_unauthenticated_redirects(self, client):
        resp = client.get("/history", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)

    def test_history_authenticated(self, auth_client):
        resp = auth_client.get("/history")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Scan Routes
# ---------------------------------------------------------------------------

class TestScanRoutes:
    def test_new_scan_page_loads(self, auth_client):
        resp = auth_client.get("/scan/new")
        assert resp.status_code == 200

    def test_new_scan_unauthenticated_redirects(self, client):
        resp = client.get("/scan/new", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)

    def test_new_scan_missing_url(self, auth_client):
        resp = auth_client.post("/scan/new", data={
            "target_url": "",
            "authorized": "on",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"enter a target URL" in resp.data or b"Please enter" in resp.data

    def test_new_scan_missing_authorization(self, auth_client):
        resp = auth_client.post("/scan/new", data={
            "target_url": "http://example.com",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"authorization" in resp.data.lower()

    def test_scan_progress_nonexistent(self, auth_client):
        """Non-existent scan should redirect to dashboard."""
        resp = auth_client.get("/scan/999/progress", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)

    def test_scan_results_nonexistent(self, auth_client):
        resp = auth_client.get("/scan/999/results", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)

    def test_scan_results_with_data(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            vuln = VulnerabilityModel(
                scan_id=scan.id,
                vuln_type="xss",
                name="Test XSS",
                severity="high",
                cvss_score=7.5,
                affected_url="http://example.com/search",
                parameter="q",
            )
            _db.session.add(vuln)
            _db.session.commit()
            scan_id = scan.id

        resp = auth_client.get(f"/scan/{scan_id}/results")
        assert resp.status_code == 200
        assert b"Test XSS" in resp.data

    def test_scan_status_nonexistent(self, auth_client):
        resp = auth_client.get("/scan/999/status")
        assert resp.status_code == 403

    def test_scan_status_with_data(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            scan_id = scan.id
        resp = auth_client.get(f"/scan/{scan_id}/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "status" in data

    def test_scan_access_denied_other_user(self, app, auth_client):
        """User should not see another user's scan."""
        with app.app_context():
            other_user = UserModel(
                supabase_uid="other-uid", username="other", email="other@ex.com"
            )
            _db.session.add(other_user)
            _db.session.commit()
            scan = _create_scan(user_id=other_user.id)
            scan_id = scan.id
        resp = auth_client.get(f"/scan/{scan_id}/results", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

class TestReportRoutes:
    def test_html_report(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            scan_id = scan.id
        resp = auth_client.get(f"/scan/{scan_id}/report/html")
        assert resp.status_code == 200
        assert resp.content_type.startswith("text/html")
        assert b"SUDARSHAN" in resp.data

    def test_pdf_report(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            scan_id = scan.id
        resp = auth_client.get(f"/scan/{scan_id}/report/pdf")
        assert resp.status_code == 200
        assert resp.content_type == "application/pdf"
        assert resp.data[:4] == b"%PDF"

    def test_report_access_denied(self, app, auth_client):
        with app.app_context():
            other = UserModel(supabase_uid="rpt-uid", username="rptuser", email="rpt@ex.com")
            _db.session.add(other)
            _db.session.commit()
            scan = _create_scan(user_id=other.id)
            scan_id = scan.id
        resp = auth_client.get(f"/scan/{scan_id}/report/html", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)


# ---------------------------------------------------------------------------
# API v2 Routes
# ---------------------------------------------------------------------------

class TestAPIv2Routes:
    def test_session_endpoint(self, auth_client):
        resp = auth_client.get("/api/v2/auth/session")
        assert resp.status_code == 200
        data = resp.get_json()
        # API returns user info directly (user_id, username, email)
        assert data.get("username") == "routeuser" or data.get("user", {}).get("username") == "routeuser"

    def test_session_unauthenticated(self, client):
        resp = client.get("/api/v2/auth/session", follow_redirects=False)
        # Should redirect or return auth error
        assert resp.status_code in (301, 302, 303, 401)

    def test_dashboard_api(self, auth_client):
        resp = auth_client.get("/api/v2/dashboard")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "stats" in data or "scans" in data or "total_scans" in data

    def test_list_scans_empty(self, auth_client):
        resp = auth_client.get("/api/v2/scans")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data.get("scans", []), list)

    def test_list_scans_with_data(self, app, auth_client):
        with app.app_context():
            _create_scan(user_id=1)
            _create_scan(user_id=1, target_url="https://test2.com")
        resp = auth_client.get("/api/v2/scans")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["scans"]) == 2

    def test_get_single_scan(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            scan_id = scan.id
        resp = auth_client.get(f"/api/v2/scans/{scan_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scan"]["target_url"] == "https://example.com"

    def test_get_scan_not_found(self, auth_client):
        resp = auth_client.get("/api/v2/scans/999")
        assert resp.status_code == 404

    def test_delete_scan(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            scan_id = scan.id
        resp = auth_client.delete(f"/api/v2/scans/{scan_id}")
        assert resp.status_code == 200

    def test_get_scan_results(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            _db.session.add(VulnerabilityModel(
                scan_id=scan.id, vuln_type="sqli", name="SQL Injection",
                severity="critical", cvss_score=9.8,
                affected_url="http://example.com/login",
            ))
            _db.session.commit()
            scan_id = scan.id
        resp = auth_client.get(f"/api/v2/scans/{scan_id}/results")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["vulnerabilities"]) == 1
        assert data["vulnerabilities"][0]["vuln_type"] == "sqli"

    def test_checks_endpoint(self, auth_client):
        resp = auth_client.get("/api/v2/checks")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data.get("checks", []), list)
        assert len(data["checks"]) > 0

    def test_scan_status_api(self, app, auth_client):
        with app.app_context():
            scan = _create_scan(user_id=1)
            scan_id = scan.id
        resp = auth_client.get(f"/api/v2/scans/{scan_id}/status")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Origin Validation (BUG-008 regression)
# ---------------------------------------------------------------------------

class TestOriginValidation:
    """Test strengthened origin validation on /auth/callback."""

    @patch("app.routes.auth._verify_supabase_token")
    def test_valid_origin_accepted(self, mock_verify, app, client):
        mock_verify.return_value = {
            "id": "uid-1", "email": "a@b.com", "user_metadata": {}
        }
        resp = client.post(
            "/auth/callback",
            data=json.dumps({"access_token": "tok"}),
            content_type="application/json",
            headers={"Origin": "http://localhost"},
        )
        assert resp.status_code == 200

    def test_cross_origin_blocked(self, client):
        resp = client.post(
            "/auth/callback",
            data=json.dumps({"access_token": "tok"}),
            content_type="application/json",
            headers={"Origin": "https://evil.com"},
        )
        assert resp.status_code == 403

    def test_browser_ua_without_origin_blocked(self, client):
        """BUG-008 regression: browser UA with no Origin/Referer should be blocked."""
        resp = client.post(
            "/auth/callback",
            data=json.dumps({"access_token": "tok"}),
            content_type="application/json",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            },
        )
        assert resp.status_code == 403

    @patch("app.routes.auth._verify_supabase_token")
    def test_non_browser_ua_without_origin_allowed(self, mock_verify, app, client):
        """Non-browser clients (curl, httpx) without Origin should be allowed."""
        mock_verify.return_value = {
            "id": "uid-2", "email": "c@d.com", "user_metadata": {}
        }
        resp = client.post(
            "/auth/callback",
            data=json.dumps({"access_token": "tok"}),
            content_type="application/json",
            headers={"User-Agent": "curl/7.88.0"},
        )
        # Should not be blocked by origin validation (may fail on token if mock doesn't match)
        assert resp.status_code in (200, 401)  # Not 403
