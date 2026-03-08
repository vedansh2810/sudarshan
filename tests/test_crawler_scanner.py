"""
Tests for the Sudarshan crawler and scanner modules.
Tests URL normalization, link extraction, form extraction, finding creation,
and false-positive reduction logic.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from urllib.parse import urlparse, parse_qs


# ══════════════════════════════════════════════════════════════════
#  Crawler Tests
# ══════════════════════════════════════════════════════════════════

class TestCrawlerURLNormalization:
    """Test Crawler._normalize_url for proper deduplication."""

    def test_strip_fragment(self):
        from app.scanner.crawler import Crawler
        assert Crawler._normalize_url('http://example.com/page#section') == 'http://example.com/page'

    def test_strip_trailing_slash(self):
        from app.scanner.crawler import Crawler
        assert Crawler._normalize_url('http://example.com/page/') == 'http://example.com/page'

    def test_root_path_preserved(self):
        from app.scanner.crawler import Crawler
        result = Crawler._normalize_url('http://example.com/')
        assert result == 'http://example.com/'

    def test_empty_query_stripped(self):
        from app.scanner.crawler import Crawler
        assert Crawler._normalize_url('http://example.com/page?') == 'http://example.com/page'

    def test_query_params_sorted(self):
        from app.scanner.crawler import Crawler
        url1 = Crawler._normalize_url('http://example.com/page?b=2&a=1')
        url2 = Crawler._normalize_url('http://example.com/page?a=1&b=2')
        assert url1 == url2

    def test_same_url_different_formats(self):
        from app.scanner.crawler import Crawler
        urls = [
            'http://example.com/page',
            'http://example.com/page/',
            'http://example.com/page#anchor',
            'http://example.com/page/#anchor',
        ]
        normalized = set(Crawler._normalize_url(u) for u in urls)
        assert len(normalized) == 1

    def test_preserves_query_params(self):
        from app.scanner.crawler import Crawler
        result = Crawler._normalize_url('http://example.com/search?q=test&page=1')
        assert 'q=test' in result
        assert 'page=1' in result


class TestCrawlerLinkExtraction:
    """Test Crawler._extract_links for finding links in HTML."""

    def _make_crawler(self):
        from app.scanner.crawler import Crawler
        with patch.object(Crawler, '_parse_robots'):
            crawler = Crawler('http://example.com', respect_robots=False)
        return crawler

    def test_extract_anchor_links(self):
        crawler = self._make_crawler()
        html = '<html><body><a href="/page1">Link</a><a href="/page2">Link2</a></body></html>'
        links = crawler._extract_links(html, 'http://example.com')
        assert any('/page1' in l for l in links)
        assert any('/page2' in l for l in links)

    def test_ignores_external_links(self):
        crawler = self._make_crawler()
        html = '<html><body><a href="http://other-site.com/page">External</a></body></html>'
        links = crawler._extract_links(html, 'http://example.com')
        assert len(links) == 0

    def test_relative_links_resolved(self):
        crawler = self._make_crawler()
        html = '<html><body><a href="subpage">Link</a></body></html>'
        links = crawler._extract_links(html, 'http://example.com/dir/')
        assert any('example.com' in l and 'subpage' in l for l in links)

    def test_extract_script_src(self):
        crawler = self._make_crawler()
        html = '<html><body><script src="/js/app.js"></script></body></html>'
        links = crawler._extract_links(html, 'http://example.com')
        assert any('app.js' in l for l in links)


class TestCrawlerFormExtraction:
    """Test Crawler._extract_forms for parsing form inputs."""

    def _make_crawler(self):
        from app.scanner.crawler import Crawler
        with patch.object(Crawler, '_parse_robots'):
            crawler = Crawler('http://example.com', respect_robots=False)
        return crawler

    def test_basic_form_extraction(self):
        crawler = self._make_crawler()
        html = '''
        <form action="/login" method="POST">
            <input type="text" name="username" value="">
            <input type="password" name="password" value="">
            <input type="submit" value="Login">
        </form>
        '''
        forms = crawler._extract_forms(html, 'http://example.com')
        assert len(forms) == 1
        assert forms[0]['method'] == 'post'
        assert len(forms[0]['inputs']) == 2  # submit has no name, so skipped

    def test_form_action_resolved(self):
        crawler = self._make_crawler()
        html = '<form action="submit.php"><input name="q"></form>'
        forms = crawler._extract_forms(html, 'http://example.com/dir/')
        assert 'example.com' in forms[0]['action']

    def test_form_without_action(self):
        crawler = self._make_crawler()
        html = '<form><input name="q"></form>'
        forms = crawler._extract_forms(html, 'http://example.com/page')
        assert forms[0]['action'] == 'http://example.com/page'

    def test_textarea_and_select_extracted(self):
        crawler = self._make_crawler()
        html = '''
        <form action="/feedback" method="POST">
            <textarea name="comment"></textarea>
            <select name="rating"><option value="5">5</option></select>
            <input type="submit">
        </form>
        '''
        forms = crawler._extract_forms(html, 'http://example.com')
        input_names = [i['name'] for i in forms[0]['inputs']]
        assert 'comment' in input_names
        assert 'rating' in input_names


class TestCrawlerParamExtraction:
    """Test Crawler._extract_params for URL query parameter detection."""

    def _make_crawler(self):
        from app.scanner.crawler import Crawler
        with patch.object(Crawler, '_parse_robots'):
            crawler = Crawler('http://example.com', respect_robots=False)
        return crawler

    def test_single_param(self):
        crawler = self._make_crawler()
        params = crawler._extract_params('http://example.com/page?id=5')
        assert len(params) == 1
        assert params[0]['name'] == 'id'
        assert params[0]['value'] == '5'

    def test_multiple_params(self):
        crawler = self._make_crawler()
        params = crawler._extract_params('http://example.com/page?id=5&name=test')
        assert len(params) == 2

    def test_no_params(self):
        crawler = self._make_crawler()
        params = crawler._extract_params('http://example.com/page')
        assert len(params) == 0


# ══════════════════════════════════════════════════════════════════
#  SQLi Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestSQLiScanner:
    """Test SQL Injection scanner logic."""

    def test_error_pattern_detection(self):
        from app.scanner.vulnerabilities.sql_injection import SQLInjectionScanner
        scanner = SQLInjectionScanner()
        
        # Should detect MySQL error
        found, evidence = scanner._check_error_based(
            "Error: You have an error in your SQL syntax near 'x'"
        )
        assert found is True
        assert evidence is not None

    def test_no_false_positive_on_clean_page(self):
        from app.scanner.vulnerabilities.sql_injection import SQLInjectionScanner
        scanner = SQLInjectionScanner()
        
        found, evidence = scanner._check_error_based(
            "<html><body>Welcome to our website</body></html>"
        )
        assert found is False

    def test_finding_format(self):
        from app.scanner.vulnerabilities.sql_injection import SQLInjectionScanner
        scanner = SQLInjectionScanner()
        
        result = {
            'technique': 'error-based',
            'payload': "' OR '1'='1",
            'url': 'http://example.com/page?id=1',
            'param': 'id',
            'method': 'GET',
            'evidence': 'SQL error detected'
        }
        finding = scanner._make_finding(result)
        assert finding['vuln_type'] == 'sql_injection'
        assert finding['severity'] == 'critical'
        assert finding['cvss_score'] == 9.8
        assert finding['affected_url'] == result['url']
        assert finding['parameter'] == 'id'

    def test_detects_various_db_errors(self):
        from app.scanner.vulnerabilities.sql_injection import SQLInjectionScanner
        scanner = SQLInjectionScanner()
        
        error_messages = [
            "Warning: mysql_fetch_array()",
            "PostgreSQL query failed: ERROR",
            "sqlite3.OperationalError: near",
            "Microsoft OLE DB Provider for SQL Server",
            "ORA-01756: quoted string not properly terminated",
            "Unclosed quotation mark after the character string",
        ]
        
        for msg in error_messages:
            found, _ = scanner._check_error_based(msg)
            assert found is True, f"Should detect: {msg}"


# ══════════════════════════════════════════════════════════════════
#  XSS Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestXSSScanner:
    """Test XSS scanner reflection detection."""

    def test_unencoded_reflection_detected(self):
        from app.scanner.vulnerabilities.xss import XSSScanner
        scanner = XSSScanner()
        marker = scanner.MARKER
        
        payload = f'<script>alert("{marker}")</script>'
        response = f'<html><body>{payload}</body></html>'
        
        assert scanner._check_reflected(response, payload) is True

    def test_encoded_reflection_rejected(self):
        from app.scanner.vulnerabilities.xss import XSSScanner
        scanner = XSSScanner()
        marker = scanner.MARKER
        
        payload = f'<script>alert("{marker}")</script>'
        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        response = f'<html><body>{encoded}</body></html>'
        
        assert scanner._check_reflected(response, payload) is False

    def test_marker_without_html_chars(self):
        from app.scanner.vulnerabilities.xss import XSSScanner
        scanner = XSSScanner()
        marker = scanner.MARKER
        
        # Payload without HTML special chars, marker present
        payload = f'" onfocus="alert(\'{marker}\')" autofocus="'
        response = f'<html><body><input value="{payload}"></body></html>'
        
        assert scanner._check_reflected(response, payload) is True

    def test_reflection_context_detection(self):
        from app.scanner.vulnerabilities.xss import XSSScanner
        scanner = XSSScanner()
        marker = scanner.MARKER
        
        # HTML context
        html_response = f'<html><body><p>{marker}</p></body></html>'
        assert scanner._check_reflection_context(html_response, marker) == 'html'


# ══════════════════════════════════════════════════════════════════
#  IDOR Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestIDORScanner:
    """Test IDOR scanner with similarity-based detection."""

    def test_error_page_detection(self):
        from app.scanner.vulnerabilities.idor import IDORScanner
        scanner = IDORScanner()
        
        error_text = '<html><body><h1>404 Not Found</h1><p>The page does not exist. Error.</p></body></html>'
        assert scanner._is_error_page(error_text) is True
        
        normal_text = '<html><body><h1>User Profile</h1><p>Welcome, John!</p></body></html>'
        assert scanner._is_error_page(normal_text) is False

    def test_find_id_params(self):
        from app.scanner.vulnerabilities.idor import IDORScanner
        scanner = IDORScanner()
        
        params = scanner._find_id_params('http://example.com/profile?user_id=42')
        # user_id matches both 'id' and 'uid' keywords, yielding 2 matches
        assert len(params) == 2
        assert params[0]['param'] == 'user_id'
        assert params[0]['value'] == 42

    def test_non_numeric_id_ignored(self):
        from app.scanner.vulnerabilities.idor import IDORScanner
        scanner = IDORScanner()
        
        params = scanner._find_id_params('http://example.com/profile?user_id=abc')
        assert len(params) == 0


# ══════════════════════════════════════════════════════════════════
#  Command Injection Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestCommandInjectionScanner:
    """Test command injection scanner logic."""

    def test_detects_passwd_output(self):
        from app.scanner.vulnerabilities.command_injection import CommandInjectionScanner
        scanner = CommandInjectionScanner()
        
        found, evidence = scanner._check_cmd_output(
            'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin'
        )
        assert found is True

    def test_detects_windows_dir_output(self):
        from app.scanner.vulnerabilities.command_injection import CommandInjectionScanner
        scanner = CommandInjectionScanner()
        
        found, evidence = scanner._check_cmd_output(
            'Volume in drive C has no label\n Directory of C:\\Users\n3 File(s)'
        )
        assert found is True

    def test_no_false_positive_on_clean_page(self):
        from app.scanner.vulnerabilities.command_injection import CommandInjectionScanner
        scanner = CommandInjectionScanner()
        
        found, _ = scanner._check_cmd_output(
            '<html><body>Welcome to our website. Contact us at info@example.com</body></html>'
        )
        assert found is False


# ══════════════════════════════════════════════════════════════════
#  CSRF Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestCSRFScanner:
    """Test CSRF scanner token detection."""

    def test_detects_csrf_token(self):
        from app.scanner.vulnerabilities.csrf import CSRFScanner
        scanner = CSRFScanner()
        
        form = {
            'inputs': [
                {'name': 'csrf_token', 'type': 'hidden', 'value': 'abc123'},
                {'name': 'username', 'type': 'text', 'value': ''},
            ]
        }
        has_token, name, value = scanner._has_csrf_token(form)
        assert has_token is True
        assert name == 'csrf_token'
        assert value == 'abc123'

    def test_no_token_detected(self):
        from app.scanner.vulnerabilities.csrf import CSRFScanner
        scanner = CSRFScanner()
        
        form = {
            'inputs': [
                {'name': 'username', 'type': 'text', 'value': ''},
                {'name': 'password', 'type': 'password', 'value': ''},
            ]
        }
        has_token, name, value = scanner._has_csrf_token(form)
        assert has_token is False

    def test_detects_django_csrfmiddlewaretoken(self):
        from app.scanner.vulnerabilities.csrf import CSRFScanner
        scanner = CSRFScanner()
        
        form = {
            'inputs': [
                {'name': 'csrfmiddlewaretoken', 'type': 'hidden', 'value': 'xxx'},
            ]
        }
        has_token, name, _ = scanner._has_csrf_token(form)
        assert has_token is True
        assert name == 'csrfmiddlewaretoken'


# ══════════════════════════════════════════════════════════════════
#  Directory Traversal Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestDirectoryTraversalScanner:
    """Test directory traversal detection."""

    def test_detects_passwd_content(self):
        from app.scanner.vulnerabilities.directory_traversal import DirectoryTraversalScanner
        scanner = DirectoryTraversalScanner()
        
        found, evidence = scanner._check_traversal(
            'root:x:0:0:root:/root:/bin/bash'
        )
        assert found is True

    def test_detects_windows_ini(self):
        from app.scanner.vulnerabilities.directory_traversal import DirectoryTraversalScanner
        scanner = DirectoryTraversalScanner()
        
        found, evidence = scanner._check_traversal(
            '[fonts]\n[extensions]\nfoo=bar'
        )
        assert found is True

    def test_no_false_positive(self):
        from app.scanner.vulnerabilities.directory_traversal import DirectoryTraversalScanner
        scanner = DirectoryTraversalScanner()
        
        found, _ = scanner._check_traversal(
            '<html><body>Normal content here</body></html>'
        )
        assert found is False


# ══════════════════════════════════════════════════════════════════
#  Base Scanner Tests
# ══════════════════════════════════════════════════════════════════

class TestBaseScanner:
    """Test base scanner utilities."""

    def test_baseline_drops_outlier(self):
        """Verify that the baseline timing drops the highest sample."""
        from app.scanner.vulnerabilities.base import BaseScanner
        scanner = BaseScanner(timeout=5, delay=0)
        
        # Mock _timed_request to return controlled times
        call_count = [0]
        def mock_timed(method, url, **kwargs):
            call_count[0] += 1
            times = [0.1, 0.1, 5.0]  # Third is outlier
            elapsed = times[min(call_count[0] - 1, 2)]
            return MagicMock(), elapsed
        
        scanner._timed_request = mock_timed
        baseline = scanner._get_baseline_time('http://example.com')
        # Should drop 5.0 and average 0.1 and 0.1
        assert baseline == pytest.approx(0.1, abs=0.01)
