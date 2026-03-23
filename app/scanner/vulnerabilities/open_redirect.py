"""
Open Redirect Scanner
OWASP: A01 - Broken Access Control | CWE-601

Detects open redirect vulnerabilities where user input controls
redirect destinations, enabling phishing attacks.
"""

import logging
from urllib.parse import urlparse, parse_qs
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class OpenRedirectScanner(BaseScanner):
    """Detects Open Redirect vulnerabilities.

    Tests redirect-related parameters with external domain payloads
    and checks if the server issues a 3xx redirect to the attacker's domain.
    """

    # Parameter names commonly used for redirects
    REDIRECT_PARAM_KEYWORDS = [
        'redirect', 'return', 'next', 'url', 'continue', 'dest',
        'destination', 'redir', 'target', 'rurl', 'returnto',
        'return_to', 'goto', 'forward', 'to', 'out', 'view',
        'login_url', 'redirect_uri', 'redirect_url', 'callback',
        'returnurl', 'go', 'jump', 'checkout_url', 'ref',
    ]

    # Test payloads — external domains plus bypass techniques
    REDIRECT_PAYLOADS = [
        # Standard external URLs
        ('http://evil.com', 'evil.com'),
        ('https://attacker.com', 'attacker.com'),
        # Protocol-relative URL
        ('//evil.com', 'evil.com'),
        # Backslash bypass
        ('/\\evil.com', 'evil.com'),
        # URL-encoded bypass
        ('https://evil.com%00.example.com', 'evil.com'),
        # Double-URL-encoded
        ('https:%2F%2Fevil.com', 'evil.com'),
        # At-sign bypass (user:pass@host)
        ('https://example.com@evil.com', 'evil.com'),
        # Tab/newline injection bypass
        ('http://evil%09.com', 'evil'),
    ]

    # ── Parameter detection ──────────────────────────────────────────

    def _is_redirect_parameter(self, point):
        """Check if a parameter name suggests redirect functionality."""
        if isinstance(point, dict):
            param_name = point.get('name', '').lower()
            return any(kw in param_name for kw in self.REDIRECT_PARAM_KEYWORDS)
        return False

    # ── Core testing ─────────────────────────────────────────────────

    def _test_redirect(self, url, param_name, payload, expected_domain):
        """Test a single redirect payload.

        Sends the request without following redirects and checks
        if the Location header points to the attacker domain.
        Returns a vulnerability finding dict or None.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            # Inject payload
            test_params = dict(params)
            test_params[param_name] = [payload]
            query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            response = self._request(
                'GET', test_url,
                allow_redirects=False,
            )

            if not response:
                return None

            # Check for redirect status codes
            if response.status_code not in (301, 302, 303, 307, 308):
                return None

            location = response.headers.get('Location', '')
            if not location:
                return None

            # Check if Location points to attacker domain
            loc_lower = location.lower()
            if expected_domain.lower() not in loc_lower:
                return None

            # Record ML data
            self._record_attempt(
                url=url,
                param=param_name,
                payload=payload,
                baseline_response=None,
                test_response=response,
                vuln_found=True,
                technique='open-redirect',
                vuln_type='open_redirect',
                confidence=90,
                severity='medium',
                method='GET',
                context='query_parameter',
            )

            return {
                'vuln_type': 'open_redirect',
                'name': f'Open Redirect via "{param_name}" parameter',
                'description': (
                    f'The parameter "{param_name}" is used to redirect users '
                    f'without validating the destination URL. The server redirected '
                    f'to the attacker-controlled domain "{expected_domain}" with '
                    f'HTTP {response.status_code}.'
                ),
                'impact': (
                    'Open redirects enable:\n'
                    '• Phishing attacks (users trust the original domain)\n'
                    '• OAuth token theft via redirect_uri manipulation\n'
                    '• Bypassing domain-based security filters\n'
                    '• Social engineering campaigns'
                ),
                'severity': 'medium',
                'cvss_score': 6.1,
                'confidence': 90,
                'owasp_category': 'A01',
                'cwe': 'CWE-601',
                'affected_url': test_url,
                'parameter': param_name,
                'payload': payload,
                'request_data': f'GET {test_url}',
                'response_data': (
                    f'Status: {response.status_code}\n'
                    f'Location: {location}'
                ),
                'remediation': (
                    '1. Validate redirect URLs against an allowlist of trusted domains\n'
                    '2. Use relative URLs for redirects instead of absolute URLs\n'
                    '3. Map redirect targets to safe predefined paths (e.g., redirect=dashboard)\n'
                    '4. Warn users before redirecting to external sites\n'
                    '5. Avoid using user input to construct redirect destinations'
                ),
            }

        except Exception as e:
            logger.debug(f'Open redirect test error: {e}')
            return None

    # ── Form testing ─────────────────────────────────────────────────

    def _test_form_redirect(self, form):
        """Test form inputs for open redirect vulnerabilities."""
        url = form.get('action', '')
        method = form.get('method', 'get').upper()
        inputs = form.get('inputs', [])

        for target_input in inputs:
            inp_name = target_input.get('name', '').lower()
            if not any(kw in inp_name for kw in self.REDIRECT_PARAM_KEYWORDS):
                continue

            for payload, expected_domain in self.REDIRECT_PAYLOADS:
                try:
                    data = {}
                    for inp in inputs:
                        if inp['name'] == target_input['name']:
                            data[inp['name']] = payload
                        elif inp['type'] in ('submit', 'button'):
                            data[inp['name']] = inp.get('value', 'Submit')
                        else:
                            data[inp['name']] = inp.get('value', '') or 'test'

                    if method == 'POST':
                        response = self._request(
                            'POST', url, data=data, allow_redirects=False
                        )
                    else:
                        response = self._request(
                            'GET', url, params=data, allow_redirects=False
                        )

                    if not response:
                        continue

                    if response.status_code not in (301, 302, 303, 307, 308):
                        continue

                    location = response.headers.get('Location', '')
                    if expected_domain.lower() in location.lower():
                        return {
                            'vuln_type': 'open_redirect',
                            'name': f'Open Redirect via form field "{target_input["name"]}"',
                            'description': (
                                f'Form field "{target_input["name"]}" allows redirect '
                                f'to attacker-controlled domain "{expected_domain}".'
                            ),
                            'impact': 'Phishing, OAuth token theft, security filter bypass.',
                            'severity': 'medium',
                            'cvss_score': 6.1,
                            'confidence': 90,
                            'owasp_category': 'A01',
                            'cwe': 'CWE-601',
                            'affected_url': url,
                            'parameter': target_input['name'],
                            'payload': payload,
                            'request_data': f'{method} {url}\nField: {target_input["name"]}={payload}',
                            'response_data': f'Status: {response.status_code}\nLocation: {location}',
                            'remediation': (
                                '1. Validate redirect URLs against an allowlist\n'
                                '2. Use relative URLs for redirects\n'
                                '3. Map targets to predefined safe paths'
                            ),
                        }
                except Exception:
                    continue
        return None

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        """Scan for open redirect vulnerabilities."""
        self.findings = []
        seen = set()

        for point in injectable_points:
            # Test forms
            if isinstance(point, dict) and point.get('type') == 'form':
                form_key = point.get('action', target_url)
                if form_key not in seen:
                    seen.add(form_key)
                    result = self._test_form_redirect(point)
                    if result:
                        self.findings.append(result)

            # Test URL parameters
            elif isinstance(point, dict) and 'name' in point:
                if not self._is_redirect_parameter(point):
                    continue

                url = point.get('url', target_url)
                key = f"{url}:{point['name']}"
                if key in seen:
                    continue
                seen.add(key)

                for payload, expected_domain in self.REDIRECT_PAYLOADS:
                    result = self._test_redirect(
                        url, point['name'], payload, expected_domain
                    )
                    if result:
                        self.findings.append(result)
                        break

        return self.findings
