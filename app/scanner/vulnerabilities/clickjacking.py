"""
Clickjacking Scanner
OWASP: A05 - Security Misconfiguration | CWE-1021

Detects missing clickjacking protections by checking for
X-Frame-Options and Content-Security-Policy frame-ancestors.
"""

import logging
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class ClickjackingScanner(BaseScanner):
    """Detects clickjacking vulnerabilities via missing frame protection.

    Checks for:
    - X-Frame-Options header (DENY or SAMEORIGIN)
    - Content-Security-Policy: frame-ancestors directive
    """

    def scan(self, target_url, injectable_points):
        """Check the target URL for clickjacking protections.

        This is a header-only check requiring a single request.
        """
        self.findings = []

        try:
            response = self._request('GET', target_url)
            if not response:
                return self.findings

            # Normalize headers to lowercase
            xfo = response.headers.get('X-Frame-Options', '').lower().strip()
            csp = response.headers.get('Content-Security-Policy', '').lower()

            # Check for valid X-Frame-Options
            has_xfo = xfo in ('deny', 'sameorigin')
            # Also accept ALLOW-FROM (deprecated but still used)
            if not has_xfo and xfo.startswith('allow-from'):
                has_xfo = True

            # Check for CSP frame-ancestors
            has_frame_ancestors = 'frame-ancestors' in csp

            if has_xfo or has_frame_ancestors:
                # Protected — no vulnerability
                return self.findings

            # Determine if the page is likely frameable (HTML content)
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type and 'application/xhtml' not in content_type:
                # Non-HTML responses aren't meaningfully frameable
                return self.findings

            # Build detailed description
            missing_headers = []
            if not has_xfo:
                missing_headers.append('X-Frame-Options')
            if not has_frame_ancestors:
                missing_headers.append('CSP frame-ancestors')

            self.findings.append({
                'vuln_type': 'clickjacking',
                'name': 'Clickjacking - Missing Frame Protection',
                'description': (
                    f'The page lacks clickjacking protection. '
                    f'Missing: {", ".join(missing_headers)}. '
                    'An attacker can embed this page in a transparent iframe '
                    'and trick users into clicking hidden elements.'
                ),
                'impact': (
                    'Clickjacking can lead to:\n'
                    '• Unauthorized actions performed on behalf of the user\n'
                    '• One-click account changes (password, email)\n'
                    '• Unintended purchases or transfers\n'
                    '• Likejacking on social platforms'
                ),
                'severity': 'medium',
                'cvss_score': 4.3,
                'confidence': 95,
                'owasp_category': 'A05',
                'cwe': 'CWE-1021',
                'affected_url': target_url,
                'parameter': 'X-Frame-Options / CSP',
                'payload': 'N/A — Header check',
                'request_data': f'GET {target_url}',
                'response_data': (
                    f'X-Frame-Options: {xfo or "(not set)"}\n'
                    f'Content-Security-Policy frame-ancestors: '
                    f'{"present" if has_frame_ancestors else "(not set)"}'
                ),
                'remediation': (
                    '1. Add X-Frame-Options header:\n'
                    '   X-Frame-Options: DENY (blocks all framing)\n'
                    '   X-Frame-Options: SAMEORIGIN (allows same-origin only)\n'
                    '2. Add CSP frame-ancestors directive (preferred, more flexible):\n'
                    "   Content-Security-Policy: frame-ancestors 'self'\n"
                    '3. For pages that must be framed, use ALLOW-FROM or\n'
                    "   frame-ancestors with specific trusted origins"
                ),
            })

        except Exception as e:
            logger.debug(f'Clickjacking check error: {e}')

        return self.findings
