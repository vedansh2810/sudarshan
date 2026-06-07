"""Integration tests for the Sudarshan web vulnerability scanner.

Tests Flask routes, database ORM operations, and the scanner registry
using Flask's test client with an in-memory SQLite database.

Run with:
    pytest tests/test_integration.py -v
"""

import pytest
from app import create_app
from app.config import Config
from app.models.database import db as _db, UserModel, ScanModel, VulnerabilityModel


# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

class TestConfig(Config):
    """Minimal configuration for integration tests.

    Uses in-memory SQLite so tests are fast and fully isolated.
    Disables CSRF, rate limiting, and Supabase auth to keep tests
    self-contained.
    """

    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ENGINE_OPTIONS = {}          # No PostgreSQL pool options
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "test-secret"
    SERVER_NAME = "localhost"
    SUPABASE_URL = ""
    SUPABASE_SERVICE_KEY = ""
    SUPABASE_ANON_KEY = ""
    RATELIMIT_ENABLED = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app():
    """Create the Flask application with test configuration."""
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    """Unauthenticated Flask test client."""
    return app.test_client()


@pytest.fixture
def auth_client(app, client):
    """Authenticated Flask test client with a real user in the database.

    Creates a ``UserModel`` row so that the ``login_required`` decorator's
    periodic DB re-validation (``User.get_by_id``) succeeds.
    """
    with app.app_context():
        user = UserModel(
            id=1,
            supabase_uid="test-uid",
            username="testuser",
            email="test@example.com",
        )
        _db.session.add(user)
        _db.session.commit()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["username"] = "testuser"
        sess["email"] = "test@example.com"
        sess["is_admin"] = False

    return client


# ---------------------------------------------------------------------------
# Health & readiness endpoints
# ---------------------------------------------------------------------------

class TestHealthEndpoints:
    """Verify liveness and readiness probes."""

    def test_health_returns_ok(self, client):
        """GET /health should return 200 with {"status": "ok"}."""
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_readiness_returns_ready(self, client):
        """GET /readiness should return 200 with database=connected."""
        resp = client.get("/readiness")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["database"] == "connected"
        assert data["status"] == "ready"


# ---------------------------------------------------------------------------
# Public (unauthenticated) routes
# ---------------------------------------------------------------------------

class TestPublicRoutes:
    """Routes that should be accessible without authentication."""

    def test_index_page_loads(self, client):
        """GET / should render the landing page (200)."""
        resp = client.get("/")
        assert resp.status_code == 200

    def test_login_page_loads(self, client):
        """GET /login should render the login page (200)."""
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_unauthenticated_dashboard_redirects(self, client):
        """GET /dashboard should redirect to login when not authenticated."""
        resp = client.get("/dashboard", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)
        assert "/login" in resp.headers["Location"]

    def test_unauthenticated_scan_redirects(self, client):
        """GET /scan/new should redirect to login when not authenticated."""
        resp = client.get("/scan/new", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)
        assert "/login" in resp.headers["Location"]

    def test_unauthenticated_history_redirects(self, client):
        """GET /history should redirect to login when not authenticated."""
        resp = client.get("/history", follow_redirects=False)
        assert resp.status_code in (301, 302, 303)
        assert "/login" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Authenticated routes
# ---------------------------------------------------------------------------

class TestAuthenticatedRoutes:
    """Routes that require an active session with a valid user."""

    def test_dashboard_loads(self, auth_client):
        """GET /dashboard should return 200 for an authenticated user."""
        resp = auth_client.get("/dashboard")
        assert resp.status_code == 200

    def test_new_scan_page_loads(self, auth_client):
        """GET /scan/new should return 200 for an authenticated user."""
        resp = auth_client.get("/scan/new")
        assert resp.status_code == 200

    def test_history_page_loads(self, auth_client):
        """GET /history should return 200 for an authenticated user."""
        resp = auth_client.get("/history")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Database / ORM operations
# ---------------------------------------------------------------------------

class TestDatabaseOperations:
    """Direct ORM model tests against the in-memory SQLite database."""

    def _create_user(self):
        """Helper: insert a minimal user and return it."""
        user = UserModel(
            supabase_uid="db-test-uid",
            username="dbuser",
            email="dbuser@example.com",
        )
        _db.session.add(user)
        _db.session.commit()
        return user

    def _create_scan(self, user_id: int) -> ScanModel:
        """Helper: insert a minimal scan and return it."""
        scan = ScanModel(
            user_id=user_id,
            target_url="https://example.com",
            scan_mode="active",
            status="pending",
        )
        _db.session.add(scan)
        _db.session.commit()
        return scan

    # -- Tests ---------------------------------------------------------------

    def test_create_scan(self, app):
        """Creating a ScanModel should persist it in the database."""
        with app.app_context():
            user = self._create_user()
            scan = self._create_scan(user.id)

            fetched = _db.session.get(ScanModel, scan.id)
            assert fetched is not None
            assert fetched.target_url == "https://example.com"
            assert fetched.status == "pending"

    def test_scan_status_update(self, app):
        """Updating a scan's status should persist correctly."""
        with app.app_context():
            user = self._create_user()
            scan = self._create_scan(user.id)

            scan.status = "running"
            _db.session.commit()

            fetched = _db.session.get(ScanModel, scan.id)
            assert fetched.status == "running"

    def test_create_vulnerability(self, app):
        """A VulnerabilityModel linked to a scan should persist."""
        with app.app_context():
            user = self._create_user()
            scan = self._create_scan(user.id)

            vuln = VulnerabilityModel(
                scan_id=scan.id,
                vuln_type="xss",
                name="Reflected XSS in search param",
                severity="high",
                cvss_score=7.5,
                affected_url="https://example.com/search?q=<script>",
                description="User input is reflected without sanitisation.",
                remediation="Encode output and use CSP.",
            )
            _db.session.add(vuln)
            _db.session.commit()

            fetched = _db.session.get(VulnerabilityModel, vuln.id)
            assert fetched is not None
            assert fetched.vuln_type == "xss"
            assert fetched.severity == "high"
            assert fetched.scan_id == scan.id

    def test_scan_cascade_delete(self, app):
        """Deleting a scan should cascade-delete its vulnerabilities."""
        with app.app_context():
            user = self._create_user()
            scan = self._create_scan(user.id)
            scan_id = scan.id

            # Attach two vulnerabilities
            for i in range(2):
                _db.session.add(
                    VulnerabilityModel(
                        scan_id=scan_id,
                        vuln_type="sqli",
                        name=f"SQL Injection #{i}",
                        severity="critical",
                    )
                )
            _db.session.commit()

            # Sanity check
            assert VulnerabilityModel.query.filter_by(scan_id=scan_id).count() == 2

            # Delete the scan
            _db.session.delete(scan)
            _db.session.commit()

            # Vulnerabilities should be gone
            assert VulnerabilityModel.query.filter_by(scan_id=scan_id).count() == 0


# ---------------------------------------------------------------------------
# Scanner registry
# ---------------------------------------------------------------------------

class TestScannerRegistry:
    """Validate the scanner registry (SCANNER_MAP)."""

    def test_registry_has_all_scanners(self):
        """SCANNER_MAP should contain exactly 22 scanner entries."""
        from app.scanner.registry import SCANNER_MAP

        assert len(SCANNER_MAP) == 22, (
            f"Expected 22 scanners in SCANNER_MAP, got {len(SCANNER_MAP)}. "
            f"Keys: {list(SCANNER_MAP.keys())}"
        )

    def test_registry_entries_are_valid(self):
        """Each registry entry should be a (class, str) tuple."""
        from app.scanner.registry import SCANNER_MAP

        for key, value in SCANNER_MAP.items():
            assert isinstance(value, tuple), f"{key}: expected tuple, got {type(value)}"
            assert len(value) == 2, f"{key}: expected 2-tuple, got length {len(value)}"
            scanner_cls, display_name = value
            assert isinstance(display_name, str), (
                f"{key}: display_name should be str, got {type(display_name)}"
            )
            assert callable(scanner_cls), (
                f"{key}: scanner class should be callable, got {type(scanner_cls)}"
            )

    def test_all_scanner_classes_instantiate(self):
        """Every scanner class should instantiate with default arguments."""
        from app.scanner.registry import SCANNER_MAP

        for key, (ScannerClass, display_name) in SCANNER_MAP.items():
            try:
                instance = ScannerClass()
            except TypeError:
                import httpx

                instance = ScannerClass(session=httpx.Client(verify=False))

            assert instance is not None, f"{key}: failed to instantiate {ScannerClass}"
