"""
Tests for new vulnerability scanners: XXE, SSRF, Open Redirect, CORS, Clickjacking.

Uses unittest.mock to simulate HTTP responses without making real network requests.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock


# ══════════════════════════════════════════════════════════════════
#  XXE Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestXXEScanner:
    """Tests for XML External Entity (XXE) Injection scanner."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.xxe import XXEScanner
        scanner = XXEScanner()
        return scanner

    def test_xxe_linux_file_detection(self):
        """Test XXE detection with /etc/passwd content in response."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            '<result>root:x:0:0:root:/root:/bin/bash\n'
            'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
            'bin:x:2:2:bin:/bin:/usr/sbin/nologin</result>'
        )
        mock_resp.headers = {'Content-Type': 'application/xml'}

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/api/parse', [])

        assert len(findings) >= 1
        assert findings[0]['severity'] == 'critical'
        assert findings[0]['cwe'] == 'CWE-611'
        assert 'xxe' in findings[0]['vuln_type']

    def test_xxe_windows_file_detection(self):
        """Test XXE with Windows win.ini content in response."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<result>[extensions]\r\n[fonts]\r\n[files]</result>'
        mock_resp.headers = {'Content-Type': 'application/xml'}

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/api/parse', [])

        assert len(findings) >= 1
        assert findings[0]['severity'] == 'critical'

    def test_xxe_aws_metadata_detection(self):
        """Test XXE via AWS metadata SSRF response."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'ami-id\ninstance-id\ninstance-type\nlocal-ipv4'
        mock_resp.headers = {'Content-Type': 'text/plain'}

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/api/xml', [])

        assert len(findings) >= 1
        assert findings[0]['cvss_score'] >= 9.0

    def test_xxe_no_false_positive_on_safe_xml(self):
        """Test that safe XML response doesn't trigger a finding."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<response><status>ok</status><data>Hello World</data></response>'
        mock_resp.headers = {'Content-Type': 'application/xml'}

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/api/safe', [])

        assert len(findings) == 0

    def test_xxe_endpoint_detection(self):
        """Test _is_xml_endpoint correctly identifies XML endpoints."""
        scanner = self._make_scanner()

        assert scanner._is_xml_endpoint({'name': 'xml_data'}, 'http://target.com/page')
        assert scanner._is_xml_endpoint({'name': 'payload'}, 'http://target.com/api/parse')
        assert not scanner._is_xml_endpoint({'name': 'username'}, 'http://target.com/login')


# ══════════════════════════════════════════════════════════════════
#  SSRF Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestSSRFScanner:
    """Tests for Server-Side Request Forgery scanner."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.ssrf import SSRFScanner
        scanner = SSRFScanner()
        return scanner

    def test_ssrf_aws_metadata_detection(self):
        """Test SSRF detection with AWS metadata response."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'ami-id\ninstance-id\ninstance-type\nlocal-ipv4\nsecurity-groups'
        mock_resp.headers = {}

        injectable = [{'name': 'url', 'url': 'http://target.com/fetch?url=http://example.com'}]

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/fetch', injectable)

        assert len(findings) >= 1
        assert findings[0]['severity'] == 'critical'
        assert findings[0]['owasp_category'] == 'A10'
        assert findings[0]['cwe'] == 'CWE-918'

    def test_ssrf_localhost_detection(self):
        """Test SSRF to localhost detection."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><head><title>Apache2 Ubuntu Default Page: It works</title></head></html>'
        mock_resp.headers = {}

        injectable = [{'name': 'target', 'url': 'http://target.com/proxy?target=http://example.com'}]

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/proxy', injectable)

        assert len(findings) >= 1
        assert findings[0]['severity'] in ('critical', 'high')

    def test_ssrf_no_false_positive(self):
        """Test that normal response doesn't trigger SSRF finding."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body><h1>Hello World</h1><p>Regular content here</p></body></html>'
        mock_resp.headers = {}

        injectable = [{'name': 'url', 'url': 'http://target.com/fetch?url=http://example.com'}]

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/fetch', injectable)

        assert len(findings) == 0

    def test_ssrf_url_parameter_detection(self):
        """Test _is_url_parameter identifies URL-like parameter names."""
        scanner = self._make_scanner()

        assert scanner._is_url_parameter({'name': 'url'})
        assert scanner._is_url_parameter({'name': 'redirect_url'})
        assert scanner._is_url_parameter({'name': 'callback'})
        assert scanner._is_url_parameter({'name': 'image_src'})
        assert not scanner._is_url_parameter({'name': 'username'})
        assert not scanner._is_url_parameter({'name': 'password'})


# ══════════════════════════════════════════════════════════════════
#  Open Redirect Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestOpenRedirectScanner:
    """Tests for Open Redirect scanner."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.open_redirect import OpenRedirectScanner
        scanner = OpenRedirectScanner()
        return scanner

    def test_open_redirect_detection(self):
        """Test open redirect via Location header pointing to evil.com."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {'Location': 'http://evil.com'}
        mock_resp.text = ''

        injectable = [{'name': 'redirect', 'url': 'http://target.com/login?redirect=/dashboard'}]

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/login', injectable)

        assert len(findings) >= 1
        assert findings[0]['severity'] == 'medium'
        assert findings[0]['cwe'] == 'CWE-601'

    def test_open_redirect_no_false_positive(self):
        """Test that internal redirect doesn't trigger."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.headers = {'Location': '/dashboard'}
        mock_resp.text = ''

        injectable = [{'name': 'redirect', 'url': 'http://target.com/login?redirect=/dashboard'}]

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/login', injectable)

        assert len(findings) == 0

    def test_redirect_parameter_detection(self):
        """Test _is_redirect_parameter identifies redirect-like names."""
        scanner = self._make_scanner()

        assert scanner._is_redirect_parameter({'name': 'redirect'})
        assert scanner._is_redirect_parameter({'name': 'return_to'})
        assert scanner._is_redirect_parameter({'name': 'next'})
        assert not scanner._is_redirect_parameter({'name': 'username'})


# ══════════════════════════════════════════════════════════════════
#  CORS Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestCORSScanner:
    """Tests for CORS Misconfiguration scanner."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.cors import CORSScanner
        scanner = CORSScanner()
        return scanner

    def test_cors_wildcard_detection(self):
        """Test detection of Access-Control-Allow-Origin: *."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"data": "test"}'
        mock_resp.headers = {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
        }

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/api/data', [])

        assert len(findings) >= 1
        assert 'Wildcard' in findings[0]['name']

    def test_cors_reflected_origin(self):
        """Test detection of reflected Origin in ACAO header."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            origin = kwargs.get('headers', {}).get('Origin', '')
            resp = MagicMock()
            resp.status_code = 200
            resp.text = '{"data": "test"}'
            resp.headers = {
                'Access-Control-Allow-Origin': origin,
                'Access-Control-Allow-Credentials': 'true',
            }
            return resp

        with patch.object(scanner, '_request', side_effect=mock_request):
            findings = scanner.scan('http://target.com/api/data', [])

        assert len(findings) >= 1
        assert 'Reflection' in findings[0]['name']
        assert findings[0]['severity'] == 'high'

    def test_cors_no_false_positive(self):
        """Test no finding when CORS is properly configured."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"data": "test"}'
        mock_resp.headers = {
            'Content-Type': 'application/json',
        }

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/api/data', [])

        assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════
#  Clickjacking Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestClickjackingScanner:
    """Tests for Clickjacking scanner."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.clickjacking import ClickjackingScanner
        scanner = ClickjackingScanner()
        return scanner

    def test_clickjacking_missing_headers(self):
        """Test detection of missing X-Frame-Options and CSP."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>Hello</body></html>'
        mock_resp.headers = {
            'Content-Type': 'text/html',
        }

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/', [])

        assert len(findings) == 1
        assert findings[0]['severity'] == 'medium'
        assert findings[0]['cwe'] == 'CWE-1021'

    def test_clickjacking_xfo_deny_protected(self):
        """Test no finding when X-Frame-Options: DENY is set."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>Hello</body></html>'
        mock_resp.headers = {
            'Content-Type': 'text/html',
            'X-Frame-Options': 'DENY',
        }

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/', [])

        assert len(findings) == 0

    def test_clickjacking_csp_frame_ancestors_protected(self):
        """Test no finding when CSP frame-ancestors is set."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<html><body>Hello</body></html>'
        mock_resp.headers = {
            'Content-Type': 'text/html',
            'Content-Security-Policy': "frame-ancestors 'self'",
        }

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/', [])

        assert len(findings) == 0

    def test_clickjacking_non_html_ignored(self):
        """Test no finding for non-HTML content types."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"data": "json"}'
        mock_resp.headers = {
            'Content-Type': 'application/json',
        }

        with patch.object(scanner, '_request', return_value=mock_resp):
            findings = scanner.scan('http://target.com/api/data', [])

        assert len(findings) == 0
