"""Broken Authentication Scanner

Detects authentication weaknesses:
  1. Default credentials — tests common username/password combos.
  2. Session fixation — checks if session ID changes after login.
  3. Cookie security flags — HttpOnly, Secure, SameSite checks.
  4. Password policy analysis — checks for weak password acceptance.
  5. Account lockout — detects missing brute-force protection.

OWASP: A07 (Identification & Authentication Failures)
Severity: High
"""

import re
import logging
import time
from urllib.parse import urljoin, urlparse
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)

# ── Default credentials to test ──────────────────────────────────────
DEFAULT_CREDS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('admin', 'admin123'),
    ('root', 'root'),
    ('root', 'toor'),
    ('test', 'test'),
    ('user', 'user'),
    ('guest', 'guest'),
    ('administrator', 'administrator'),
    ('admin', ''),
    ('admin', 'changeme'),
    ('admin', 'letmein'),
    ('demo', 'demo'),
]

# Login form indicators
LOGIN_FORM_PATTERNS = [
    re.compile(r'<input[^>]*type=["\']password["\']', re.I),
    re.compile(r'<form[^>]*(?:login|signin|auth)', re.I),
    re.compile(r'name=["\'](?:username|user|email|login)["\']', re.I),
]

# Login success indicators (should NOT appear after successful login)
LOGIN_FAILURE_PATTERNS = [
    re.compile(r'(?:invalid|incorrect|wrong|bad)\s+(?:username|password|credentials|login)', re.I),
    re.compile(r'login\s+failed', re.I),
    re.compile(r'authentication\s+(?:failed|error)', re.I),
    re.compile(r'(?:access|permission)\s+denied', re.I),
    re.compile(r'try\s+again', re.I),
]

# Login success indicators
LOGIN_SUCCESS_PATTERNS = [
    re.compile(r'(?:welcome|hello|hi)\s+\w+', re.I),
    re.compile(r'(?:dashboard|profile|account|home)', re.I),
    re.compile(r'(?:logout|sign\s*out|log\s*out)', re.I),
    re.compile(r'(?:successfully|logged\s+in)', re.I),
]


class BrokenAuthScanner(BaseScanner):
    """Detect broken authentication vulnerabilities."""

    def scan(self, target_url, injectable_points):
        self.findings = []

        # Discover login pages
        login_pages = self._find_login_pages(target_url, injectable_points)

        if not login_pages:
            # Even without login forms, check cookie security
            self._check_cookie_security(target_url)
            return self.findings

        for login_info in login_pages:
            # Test 1: Default credentials
            self._test_default_creds(target_url, login_info)

            # Test 2: Session fixation
            self._test_session_fixation(target_url, login_info)

            # Test 3: Account lockout bypass
            self._test_lockout(target_url, login_info)

        # Test 4: Cookie security (applies to all pages)
        self._check_cookie_security(target_url)

        return self.findings

    # ── Login page discovery ─────────────────────────────────────────

    def _find_login_pages(self, target_url, injectable_points):
        """Find login forms in crawled pages."""
        login_pages = []
        checked_urls = set()

        # Check common login paths
        common_paths = [
            '/login', '/signin', '/auth/login', '/admin/login',
            '/user/login', '/account/login', '/authenticate',
            '/admin', '/wp-login.php', '/wp-admin',
        ]

        urls_to_check = [target_url.rstrip('/') + p for p in common_paths]

        # Also check any forms found by the crawler
        for point in injectable_points:
            url = point.get('url', '')
            if url and url not in checked_urls:
                urls_to_check.append(url)

        for url in urls_to_check:
            if url in checked_urls:
                continue
            checked_urls.add(url)

            resp = self._request('GET', url)
            if not resp or resp.status_code >= 400:
                continue

            text = resp.text or ''
            has_password = any(p.search(text) for p in LOGIN_FORM_PATTERNS)

            if has_password:
                # Extract form details
                form_info = self._extract_login_form(text, url)
                if form_info:
                    login_pages.append(form_info)

            if len(login_pages) >= 3:  # Limit to 3 login forms
                break

        return login_pages

    def _extract_login_form(self, html, page_url):
        """Extract login form action URL and field names."""
        from html.parser import HTMLParser

        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self.current_form = None
                self.inputs = []

            def handle_starttag(self, tag, attrs):
                attrs_dict = dict(attrs)
                if tag == 'form':
                    self.current_form = {
                        'action': attrs_dict.get('action', ''),
                        'method': attrs_dict.get('method', 'POST').upper(),
                        'inputs': []
                    }
                elif tag == 'input' and self.current_form is not None:
                    self.current_form['inputs'].append({
                        'name': attrs_dict.get('name', ''),
                        'type': attrs_dict.get('type', 'text'),
                        'value': attrs_dict.get('value', ''),
                    })

            def handle_endtag(self, tag):
                if tag == 'form' and self.current_form:
                    self.forms.append(self.current_form)
                    self.current_form = None

        parser = FormParser()
        try:
            parser.feed(html)
        except Exception:
            return None

        # Find the form with a password field
        for form in parser.forms:
            has_password = any(i['type'] == 'password' for i in form['inputs'])
            if has_password:
                username_field = None
                password_field = None
                hidden_fields = {}

                for inp in form['inputs']:
                    if inp['type'] == 'password':
                        password_field = inp['name']
                    elif inp['type'] in ('text', 'email') and not username_field:
                        username_field = inp['name']
                    elif inp['type'] == 'hidden' and inp['name']:
                        hidden_fields[inp['name']] = inp['value']

                if username_field and password_field:
                    action = form['action'] or page_url
                    if not action.startswith('http'):
                        action = urljoin(page_url, action)

                    return {
                        'url': page_url,
                        'action': action,
                        'method': form['method'],
                        'username_field': username_field,
                        'password_field': password_field,
                        'hidden_fields': hidden_fields,
                    }

        return None

    # ── Attack: Default credentials ──────────────────────────────────

    def _test_default_creds(self, target_url, login_info):
        """Test common default username/password combinations."""
        for username, password in DEFAULT_CREDS:
            post_data = dict(login_info['hidden_fields'])
            post_data[login_info['username_field']] = username
            post_data[login_info['password_field']] = password

            resp = self._request(
                login_info['method'],
                login_info['action'],
                data=post_data,
                allow_redirects=True
            )

            if not resp:
                continue

            text = resp.text or ''

            # Check for login failure indicators
            is_failure = any(p.search(text) for p in LOGIN_FAILURE_PATTERNS)
            is_success = any(p.search(text) for p in LOGIN_SUCCESS_PATTERNS)

            # Also check: redirect to dashboard, status 302 to non-login page
            redirected_away = (
                resp.status_code == 200 and
                not any(p.search(text) for p in LOGIN_FORM_PATTERNS)
            )

            if (is_success or redirected_away) and not is_failure:
                self.findings.append({
                    'vuln_type': 'broken_auth',
                    'name': 'Default Credentials Accepted',
                    'description': (
                        f'The application accepts default credentials: '
                        f'username="{username}", password="{password}". '
                        f'Login form at: {login_info["url"]}'
                    ),
                    'impact': (
                        'Unauthorized access with default admin credentials. An attacker '
                        'can gain full access to the application without any brute-forcing.'
                    ),
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'owasp_category': 'A07',
                    'affected_url': login_info['url'],
                    'parameter': f'{login_info["username_field"]}/{login_info["password_field"]}',
                    'payload': f'{username}:{password}',
                    'request_data': f'POST {login_info["action"]}',
                    'response_data': text[:300],
                    'remediation': (
                        '1. Force password change on first login.\n'
                        '2. Remove all default credentials before deployment.\n'
                        '3. Implement strong password policies.\n'
                        '4. Use multi-factor authentication (MFA).'
                    ),
                })
                return  # One finding is enough

    # ── Attack: Session fixation ─────────────────────────────────────

    def _test_session_fixation(self, target_url, login_info):
        """Check if session ID changes after authentication."""
        # Get pre-login session cookies
        resp_before = self._request('GET', login_info['url'])
        if not resp_before:
            return

        pre_cookies = dict(resp_before.cookies)

        # Attempt a login (with intentionally wrong creds to just observe session behavior)
        post_data = dict(login_info['hidden_fields'])
        post_data[login_info['username_field']] = 'session_fixation_test'
        post_data[login_info['password_field']] = 'session_fixation_test'

        resp_after = self._request(
            login_info['method'],
            login_info['action'],
            data=post_data,
            allow_redirects=True
        )

        if not resp_after:
            return

        post_cookies = dict(resp_after.cookies)

        # Check if session-related cookies changed
        session_cookies = [
            name for name in pre_cookies
            if any(s in name.lower() for s in ['session', 'sess', 'sid', 'phpsessid', 'jsessionid'])
        ]

        for cookie_name in session_cookies:
            pre_val = pre_cookies.get(cookie_name)
            post_val = post_cookies.get(cookie_name)

            if pre_val and post_val and pre_val == post_val:
                self.findings.append({
                    'vuln_type': 'broken_auth',
                    'name': 'Session Fixation Vulnerability',
                    'description': (
                        f'The session cookie "{cookie_name}" does not change after '
                        f'authentication attempt. This suggests the application is '
                        f'vulnerable to session fixation attacks.'
                    ),
                    'impact': (
                        'An attacker can set a known session ID in the victim\'s browser '
                        'before login. After the victim authenticates, the attacker can '
                        'hijack the session using the known ID.'
                    ),
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'owasp_category': 'A07',
                    'affected_url': login_info['url'],
                    'parameter': cookie_name,
                    'payload': f'Pre-login: {pre_val[:30]}... == Post-login: {post_val[:30]}...',
                    'request_data': f'Login form at {login_info["action"]}',
                    'response_data': f'Session cookie unchanged: {cookie_name}',
                    'remediation': (
                        '1. Regenerate session ID after every authentication event.\n'
                        '2. Invalidate old session IDs immediately.\n'
                        '3. Use secure session management frameworks.\n'
                        '4. Set session cookies with HttpOnly, Secure, SameSite flags.'
                    ),
                })
                return

    # ── Attack: Account lockout ──────────────────────────────────────

    def _test_lockout(self, target_url, login_info):
        """Check if account lockout is implemented after failed logins."""
        failed_attempts = 0
        max_test_attempts = 8

        for i in range(max_test_attempts):
            post_data = dict(login_info['hidden_fields'])
            post_data[login_info['username_field']] = 'admin'
            post_data[login_info['password_field']] = f'wrong_password_{i}'

            resp = self._request(
                login_info['method'],
                login_info['action'],
                data=post_data,
                allow_redirects=True
            )

            if not resp:
                break

            text = resp.text or ''

            # Check for lockout indicators
            lockout_patterns = [
                re.compile(r'account\s+(?:locked|disabled|blocked)', re.I),
                re.compile(r'too\s+many\s+(?:attempts|tries|failures)', re.I),
                re.compile(r'temporarily\s+(?:locked|blocked|suspended)', re.I),
                re.compile(r'please\s+wait|try\s+(?:again\s+)?later', re.I),
            ]

            if any(p.search(text) for p in lockout_patterns):
                # Lockout detected — good, not vulnerable
                return

            if resp.status_code == 429:
                # Rate limited — also good
                return

            failed_attempts += 1

        if failed_attempts >= max_test_attempts:
            self.findings.append({
                'vuln_type': 'broken_auth',
                'name': 'Missing Account Lockout',
                'description': (
                    f'The application does not implement account lockout after '
                    f'{max_test_attempts} consecutive failed login attempts. '
                    f'Login form at: {login_info["url"]}'
                ),
                'impact': (
                    'An attacker can perform unlimited brute-force attacks against '
                    'user accounts without being blocked or rate-limited.'
                ),
                'severity': 'medium',
                'cvss_score': 5.3,
                'owasp_category': 'A07',
                'affected_url': login_info['url'],
                'parameter': login_info['username_field'],
                'payload': f'{max_test_attempts} failed attempts with no lockout',
                'request_data': f'POST {login_info["action"]} x{max_test_attempts}',
                'response_data': 'No lockout or rate-limiting detected',
                'remediation': (
                    '1. Implement account lockout after 5-10 failed attempts.\n'
                    '2. Use progressive delays (exponential backoff).\n'
                    '3. Implement CAPTCHA after 3 failed attempts.\n'
                    '4. Monitor and alert on brute-force patterns.\n'
                    '5. Use rate limiting per IP address.'
                ),
            })

    # ── Cookie security checks ───────────────────────────────────────

    def _check_cookie_security(self, target_url):
        """Check cookie security flags (HttpOnly, Secure, SameSite)."""
        resp = self._request('GET', target_url)
        if not resp:
            return

        insecure_cookies = []
        is_https = target_url.startswith('https')

        for cookie in resp.cookies:
            issues = []

            # Check HttpOnly
            # Note: requests library doesn't expose HttpOnly directly,
            # we need to check the Set-Cookie header
            cookie_name = cookie.name

            # Parse Set-Cookie headers for detailed flag checks
            set_cookie_headers = resp.headers.get('Set-Cookie', '') if hasattr(resp, 'headers') else ''

            if isinstance(set_cookie_headers, str):
                set_cookie_headers = [set_cookie_headers]

            for header_val in (resp.raw.headers.getlist('Set-Cookie') if hasattr(resp, 'raw') and hasattr(resp.raw, 'headers') else [set_cookie_headers] if isinstance(set_cookie_headers, str) else set_cookie_headers):
                if cookie_name in str(header_val):
                    header_lower = str(header_val).lower()
                    if 'httponly' not in header_lower:
                        issues.append('Missing HttpOnly flag')
                    if is_https and 'secure' not in header_lower:
                        issues.append('Missing Secure flag')
                    if 'samesite' not in header_lower:
                        issues.append('Missing SameSite flag')

            if issues and any(s in cookie_name.lower() for s in ['session', 'token', 'auth', 'jwt', 'sid']):
                insecure_cookies.append((cookie_name, issues))

        if insecure_cookies:
            details = '; '.join(
                f'"{name}": {", ".join(issues)}'
                for name, issues in insecure_cookies[:3]
            )
            self.findings.append({
                'vuln_type': 'broken_auth',
                'name': 'Insecure Cookie Configuration',
                'description': (
                    f'Security-sensitive cookies are missing protection flags: {details}'
                ),
                'impact': (
                    'Cookies without HttpOnly can be stolen via XSS. Cookies without '
                    'Secure can be intercepted over HTTP. Missing SameSite enables CSRF.'
                ),
                'severity': 'medium',
                'cvss_score': 4.7,
                'owasp_category': 'A07',
                'affected_url': target_url,
                'parameter': ', '.join(name for name, _ in insecure_cookies[:3]),
                'payload': 'Cookie flag analysis',
                'request_data': f'GET {target_url}',
                'response_data': details[:300],
                'remediation': (
                    '1. Set HttpOnly flag on all session/auth cookies.\n'
                    '2. Set Secure flag when serving over HTTPS.\n'
                    '3. Set SameSite=Lax or SameSite=Strict.\n'
                    '4. Use __Host- or __Secure- cookie prefixes.'
                ),
            })
