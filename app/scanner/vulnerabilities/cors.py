"""
CORS Misconfiguration Scanner
OWASP: A05 - Security Misconfiguration | CWE-942

Detects insecure Cross-Origin Resource Sharing configurations
that could allow unauthorized cross-origin data access.
"""

import logging
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class CORSScanner(BaseScanner):
    """Detects CORS misconfigurations.

    Checks:
    1. Wildcard origin (Access-Control-Allow-Origin: *)
    2. Reflected arbitrary origin without validation
    3. Null origin acceptance
    4. Credentials allowed with permissive origin
    """

    # Origins to test
    TEST_ORIGINS = [
        ('https://evil-attacker.com', 'arbitrary external domain'),
        ('https://subdomain.evil.com', 'subdomain of attacker'),
        ('null', 'null origin (sandboxed iframes)'),
        ('https://localhost', 'localhost origin'),
    ]

    def _test_cors(self, url, test_origin, origin_desc):
        """Send a request with a specific Origin header and analyze ACAO/ACAC.

        Returns a vulnerability finding dict or None.
        """
        try:
            headers = {'Origin': test_origin}
            response = self._request('GET', url, headers=headers)

            if not response:
                return None

            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
            credentials = acac == 'true'

            # No ACAO header — not a CORS issue
            if not acao:
                return None

            finding = None

            # Case 1: Wildcard origin
            if acao == '*':
                severity = 'high' if credentials else 'medium'
                cvss = 7.5 if credentials else 5.3
                finding = self._build_finding(
                    url, test_origin, acao, acac,
                    title='CORS Wildcard Origin (*)',
                    description=(
                        'Access-Control-Allow-Origin is set to "*", allowing '
                        'any website to read cross-origin responses.'
                        + (' Combined with Access-Control-Allow-Credentials: true, '
                           'this enables authenticated cross-origin data theft.'
                           if credentials else '')
                    ),
                    severity=severity,
                    cvss=cvss,
                )

            # Case 2: Origin reflected back (most dangerous)
            elif acao.lower() == test_origin.lower() and test_origin != 'null':
                severity = 'high' if credentials else 'medium'
                cvss = 8.0 if credentials else 5.3
                finding = self._build_finding(
                    url, test_origin, acao, acac,
                    title='CORS Origin Reflection',
                    description=(
                        f'The server reflects the Origin header ({test_origin}) '
                        'directly in Access-Control-Allow-Origin without validation. '
                        'Any website can bypass the same-origin policy.'
                        + (' With credentials allowed, authenticated data can be stolen.'
                           if credentials else '')
                    ),
                    severity=severity,
                    cvss=cvss,
                )

            # Case 3: Null origin accepted
            elif acao.lower() == 'null' and test_origin == 'null':
                severity = 'medium'
                cvss = 5.3
                finding = self._build_finding(
                    url, test_origin, acao, acac,
                    title='CORS Null Origin Accepted',
                    description=(
                        'The server accepts "null" as a valid origin. '
                        'Sandboxed iframes and data: URLs send null origin, '
                        'allowing attackers to bypass CORS restrictions.'
                    ),
                    severity=severity,
                    cvss=cvss,
                )

            return finding

        except Exception as e:
            logger.debug(f'CORS test error: {e}')
            return None

    def _build_finding(self, url, test_origin, acao, acac,
                        title, description, severity, cvss):
        """Build a standard vulnerability finding dict."""
        return {
            'vuln_type': 'cors',
            'name': title,
            'description': description,
            'impact': (
                'CORS misconfiguration can lead to:\n'
                '• Cross-origin data theft from authenticated sessions\n'
                '• Unauthorized API access\n'
                '• Bypassing same-origin policy protections\n'
                '• Account takeover via stolen tokens'
            ),
            'severity': severity,
            'cvss_score': cvss,
            'confidence': 95,
            'owasp_category': 'A05',
            'cwe': 'CWE-942',
            'affected_url': url,
            'parameter': 'Access-Control-Allow-Origin',
            'payload': f'Origin: {test_origin}',
            'request_data': f'GET {url}\nOrigin: {test_origin}',
            'response_data': (
                f'Access-Control-Allow-Origin: {acao}\n'
                f'Access-Control-Allow-Credentials: {acac or "not set"}'
            ),
            'remediation': (
                '1. Validate Origin against a strict allowlist of trusted domains\n'
                '2. Never reflect the Origin header blindly\n'
                '3. Avoid using Access-Control-Allow-Origin: *\n'
                '4. Do not allow credentials with wildcard origins\n'
                '5. Reject null origins unless explicitly required\n'
                '6. Restrict Access-Control-Allow-Methods to required HTTP methods'
            ),
        }

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        """Scan for CORS misconfiguration on the target URL.

        CORS is a server-level configuration, not parameter-specific,
        so we test the base URL with multiple Origin headers.
        """
        self.findings = []

        for test_origin, origin_desc in self.TEST_ORIGINS:
            result = self._test_cors(target_url, test_origin, origin_desc)
            if result:
                self.findings.append(result)
                # If we found origin reflection, it's the worst case — stop
                if 'Reflection' in result['name']:
                    break

        return self.findings
