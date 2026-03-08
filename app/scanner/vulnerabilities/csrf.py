from app.scanner.vulnerabilities.base import BaseScanner
from bs4 import BeautifulSoup


class CSRFScanner(BaseScanner):
    """CSRF scanner that checks token presence, token validation,
    Referer/Origin header enforcement, and SameSite cookie attribute."""

    CSRF_TOKEN_NAMES = [
        'csrf', 'csrf_token', '_csrf', 'csrftoken', 'csrf_nonce',
        'token', '_token', 'authenticity_token', 'xsrf', '_xsrf',
        'csrfmiddlewaretoken', '__requestverificationtoken',
        'anti-csrf-token', 'anticsrf', 'user_token',
    ]

    def _has_csrf_token(self, form):
        """Check if form has a hidden CSRF token field."""
        for inp in form.get('inputs', []):
            name = inp.get('name', '').lower()
            inp_type = inp.get('type', '').lower()
            for token_name in self.CSRF_TOKEN_NAMES:
                if token_name in name and inp_type in ('hidden', ''):
                    return True, inp.get('name', ''), inp.get('value', '')
        return False, None, None

    def _check_samesite_cookies(self, url):
        """Check if session cookies have SameSite attribute."""
        response = self._request('GET', url)
        if not response:
            return True  # Can't check, assume safe

        set_cookies = response.headers.get('Set-Cookie', '')
        if not set_cookies:
            return True

        # Check all Set-Cookie headers
        all_cookies = response.headers.get_all('Set-Cookie') if hasattr(response.headers, 'get_all') else [set_cookies]

        for cookie in all_cookies:
            cookie_lower = cookie.lower()
            # Look for session-like cookies
            if any(name in cookie_lower for name in ['session', 'sess', 'sid', 'phpsessid', 'jsessionid']):
                if 'samesite=strict' in cookie_lower or 'samesite=lax' in cookie_lower:
                    continue
                else:
                    return False  # Session cookie missing SameSite
        return True

    def _test_token_validation(self, form):
        """Test if the CSRF token is actually validated by submitting with a bad token."""
        has_token, token_name, token_value = self._has_csrf_token(form)
        if not has_token or not token_name:
            return None

        url = form.get('action', '')
        method = form.get('method', 'get').upper()
        if method != 'POST':
            return None

        # First, get a valid baseline response by submitting with the real token
        baseline_data = {}
        for inp in form.get('inputs', []):
            name = inp.get('name', '')
            if inp.get('type', '') in ('submit', 'button'):
                baseline_data[name] = inp.get('value', 'Submit')
            else:
                baseline_data[name] = inp.get('value', '') or 'test'
        baseline_resp = self._request('POST', url, data=baseline_data)

        # Build form data with tampered token
        data = {}
        for inp in form.get('inputs', []):
            name = inp.get('name', '')
            if name == token_name:
                data[name] = 'INVALID_TOKEN_12345'  # Bad token
            elif inp.get('type', '') in ('submit', 'button'):
                data[name] = inp.get('value', 'Submit')
            else:
                data[name] = inp.get('value', '') or 'test'

        response = self._request('POST', url, data=data)
        if not response:
            return None

        # Check if the invalid-token request was truly accepted
        # False positive guards:
        # 1. If redirected to a login/error page, the token WAS validated
        final_url = response.url if hasattr(response, 'url') else ''
        login_indicators = ['login', 'signin', 'auth', 'error', 'denied', 'forbidden', 'expired']
        if any(ind in final_url.lower() for ind in login_indicators):
            return None  # Redirected to login = token was validated

        # 2. If we got 403/401, it was rejected
        if response.status_code in (401, 403):
            return None

        # 3. If page content looks like an error page
        if response.text:
            error_phrases = ['invalid token', 'csrf', 'forbidden', 'token expired',
                           'security error', 'access denied', 'token mismatch']
            resp_lower = response.text.lower()
            if any(phrase in resp_lower for phrase in error_phrases):
                return None

        # 4. Compare against baseline - if response is very different, might be error page
        if baseline_resp and response.status_code in (200, 302, 301):
            if baseline_resp.status_code == response.status_code:
                # Token was accepted even though invalid
                return {
                    'token_not_validated': True,
                    'url': url,
                    'token_field': token_name,
                    'status_code': response.status_code
                }
        
        return None

    def _test_referer_required(self, form):
        """Test if Referer/Origin header is required for form submission."""
        url = form.get('action', '')
        method = form.get('method', 'get').upper()
        if method != 'POST':
            return False

        data = {}
        for inp in form.get('inputs', []):
            name = inp.get('name', '')
            if inp.get('type', '') in ('submit', 'button'):
                data[name] = inp.get('value', 'Submit')
            else:
                data[name] = inp.get('value', '') or 'test'

        # Submit without Referer header
        headers = {'Referer': '', 'Origin': ''}
        response = self._request('POST', url, data=data, headers=headers)

        if response and response.status_code in (200, 302):
            return True  # Request accepted without Referer — vulnerable
        return False

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        # Check SameSite cookie once
        has_samesite = self._check_samesite_cookies(target_url)

        for point in injectable_points:
            if not isinstance(point, dict) or point.get('type') != 'form':
                continue

            method = point.get('method', 'get').upper()
            form_url = point.get('action', target_url)

            if method != 'POST':
                continue

            key = form_url
            if key in seen:
                continue

            has_token, token_name, _ = self._has_csrf_token(point)

            # ── No CSRF token at all ──
            if not has_token:
                if not has_samesite:
                    severity = 'high'
                    cvss = 8.0
                    description = (
                        'POST form has NO CSRF token and session cookies lack SameSite attribute. '
                        'This is a high-risk CSRF vulnerability — attackers can forge requests '
                        'that execute with the victim\'s authenticated session.'
                    )
                else:
                    severity = 'medium'
                    cvss = 6.5
                    description = (
                        'POST form has no CSRF token. While SameSite cookies provide '
                        'partial protection, this is still vulnerable to same-site attacks '
                        'and older browsers that don\'t support SameSite.'
                    )

                seen.add(key)
                self.findings.append({
                    'vuln_type': 'csrf',
                    'name': 'Cross-Site Request Forgery (CSRF)',
                    'description': description,
                    'impact': 'Attackers can perform state-changing actions on behalf of authenticated users — changing passwords, transferring funds, modifying data.',
                    'severity': severity,
                    'cvss_score': cvss,
                    'owasp_category': 'A01',
                    'affected_url': form_url,
                    'parameter': 'form submission',
                    'payload': 'No CSRF token present in form',
                    'request_data': f"POST {form_url}\nInputs: {[i['name'] for i in point.get('inputs', [])]}",
                    'response_data': f'No CSRF token. SameSite: {"present" if has_samesite else "missing"}',
                    'remediation': (
                        'Implement synchronizer token pattern (per-session or per-request CSRF tokens). '
                        'Add SameSite=Lax cookie attribute. Verify Origin/Referer headers. '
                        'Use double-submit cookie pattern as defense-in-depth.'
                    )
                })
                continue

            # ── Has token — check if it's actually validated ──
            invalid_result = self._test_token_validation(point)
            if invalid_result:
                seen.add(key)
                self.findings.append({
                    'vuln_type': 'csrf',
                    'name': 'CSRF Token Not Validated',
                    'description': (
                        f'The form at {form_url} has a CSRF token field ("{token_name}") '
                        'but the server accepts requests with invalid tokens. '
                        'The protection is decorative — it does not actually prevent CSRF.'
                    ),
                    'impact': 'Full CSRF vulnerability. Attackers can forge requests despite token presence.',
                    'severity': 'high',
                    'cvss_score': 8.0,
                    'owasp_category': 'A01',
                    'affected_url': form_url,
                    'parameter': token_name,
                    'payload': f'{token_name}=INVALID_TOKEN_12345 (accepted)',
                    'request_data': f'POST {form_url}\nToken field: {token_name}\nSubmitted: INVALID_TOKEN_12345',
                    'response_data': f'Server returned {invalid_result["status_code"]} with invalid token',
                    'remediation': (
                        'Ensure the server validates the CSRF token on every state-changing request. '
                        'Reject requests with missing, empty, or incorrect tokens with 403 status.'
                    )
                })

        return self.findings
