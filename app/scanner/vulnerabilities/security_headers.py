import re
from app.scanner.vulnerabilities.base import BaseScanner


class SecurityHeadersScanner(BaseScanner):
    """Security headers scanner with header presence checks, cookie flag
    analysis, CORS misconfiguration detection, and CSP strength validation."""

    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HSTS header missing — site may be vulnerable to protocol downgrade and MitM attacks.',
            'severity': 'medium',
            'cvss': 5.4,
            'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        },
        'X-Frame-Options': {
            'description': 'X-Frame-Options missing — site may be vulnerable to clickjacking attacks.',
            'severity': 'medium',
            'cvss': 6.1,
            'remediation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'X-Content-Type-Options missing — browser MIME type sniffing may lead to XSS.',
            'severity': 'low',
            'cvss': 3.7,
            'remediation': 'Add: X-Content-Type-Options: nosniff'
        },
        'Content-Security-Policy': {
            'description': 'Content-Security-Policy (CSP) header missing — XSS and data injection attacks possible.',
            'severity': 'high',
            'cvss': 7.5,
            'remediation': "Implement a strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self'"
        },
        'X-XSS-Protection': {
            'description': 'X-XSS-Protection header missing or disabled.',
            'severity': 'low',
            'cvss': 3.1,
            'remediation': 'Add: X-XSS-Protection: 1; mode=block'
        },
        'Referrer-Policy': {
            'description': 'Referrer-Policy missing — sensitive URLs may be leaked via Referer header.',
            'severity': 'low',
            'cvss': 3.1,
            'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': 'Permissions-Policy missing — browser features (camera, mic, geolocation) not restricted.',
            'severity': 'low',
            'cvss': 2.6,
            'remediation': 'Add Permissions-Policy to restrict camera, microphone, geolocation, etc.'
        },
        'Cross-Origin-Opener-Policy': {
            'description': 'Cross-Origin-Opener-Policy (COOP) missing — may allow Spectre-like cross-origin attacks.',
            'severity': 'low',
            'cvss': 2.0,
            'remediation': 'Add: Cross-Origin-Opener-Policy: same-origin'
        },
        'Cross-Origin-Resource-Policy': {
            'description': 'Cross-Origin-Resource-Policy (CORP) missing — resources may be loaded by untrusted origins.',
            'severity': 'low',
            'cvss': 2.0,
            'remediation': 'Add: Cross-Origin-Resource-Policy: same-origin'
        },
    }

    CSP_UNSAFE = [
        ("unsafe-inline", "script-src", "Allows inline scripts, defeating most XSS protections"),
        ("unsafe-eval", "script-src", "Allows eval(), enabling code injection"),
        ("*", "default-src", "Wildcard allows loading from any origin"),
        ("*", "script-src", "Wildcard allows loading scripts from any origin"),
        ("data:", "script-src", "data: URI in script-src can be exploited for XSS"),
        ("http:", "script-src", "Allows scripts over insecure HTTP"),
    ]

    def _check_missing_headers(self, response, target_url):
        """Check for missing security headers."""
        headers = {k.lower(): v for k, v in response.headers.items()}
        findings = []

        for header_name, info in self.REQUIRED_HEADERS.items():
            if header_name.lower() not in headers:
                findings.append({
                    'vuln_type': 'security_headers',
                    'name': f'Missing Security Header: {header_name}',
                    'description': info['description'],
                    'impact': f'Increases attack surface. Missing {header_name} can enable client-side attacks.',
                    'severity': info['severity'],
                    'cvss_score': info['cvss'],
                    'owasp_category': 'A05',
                    'affected_url': target_url,
                    'parameter': header_name,
                    'payload': 'N/A — Header check',
                    'request_data': f'GET {target_url}\nHTTP/1.1',
                    'response_data': f'Response headers missing: {header_name}',
                    'remediation': info['remediation']
                })

        return findings

    def _check_csp_strength(self, response, target_url):
        """Validate CSP policy strength if present."""
        csp = response.headers.get('Content-Security-Policy', '')
        if not csp:
            return []

        findings = []
        csp_lower = csp.lower()

        for unsafe_value, directive, description in self.CSP_UNSAFE:
            # Check if directive contains the unsafe value
            pattern = rf"{directive}\s+[^;]*{re.escape(unsafe_value)}"
            if re.search(pattern, csp_lower):
                findings.append({
                    'vuln_type': 'security_headers',
                    'name': f'Weak CSP: {unsafe_value} in {directive}',
                    'description': f'The Content Security Policy contains "{unsafe_value}" in {directive}. {description}.',
                    'impact': 'Weakens XSS protections provided by CSP, potentially allowing script injection.',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'owasp_category': 'A05',
                    'affected_url': target_url,
                    'parameter': 'Content-Security-Policy',
                    'payload': f'{directive}: ... {unsafe_value} ...',
                    'request_data': f'GET {target_url}',
                    'response_data': f'CSP: {csp[:200]}',
                    'remediation': f'Remove "{unsafe_value}" from {directive}. Use nonce or hash-based CSP instead.'
                })

        return findings

    def _check_cookie_flags(self, response, target_url):
        """Check security flags on session cookies."""
        findings = []
        cookie_header = response.headers.get('Set-Cookie', '')
        if not cookie_header:
            return findings

        # Parse Set-Cookie headers
        cookies_raw = [cookie_header]
        if hasattr(response.headers, 'get_all'):
            cookies_raw = response.headers.get_all('Set-Cookie')

        for cookie in cookies_raw:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split('=')[0].strip() if '=' in cookie else 'unknown'

            # Focus on session-like cookies
            is_session = any(kw in cookie_name.lower()
                          for kw in ['session', 'sess', 'sid', 'phpsessid',
                                     'jsessionid', 'connect.sid', 'asp.net_sessionid'])

            if not is_session and len(cookies_raw) <= 2:
                is_session = True  # If few cookies, check all

            if not is_session:
                continue

            issues = []

            if 'httponly' not in cookie_lower:
                issues.append('HttpOnly')

            if 'secure' not in cookie_lower:
                issues.append('Secure')

            if 'samesite' not in cookie_lower:
                issues.append('SameSite')

            if issues:
                missing = ', '.join(issues)
                severity = 'medium' if 'HttpOnly' in issues else 'low'
                cvss = 5.5 if 'HttpOnly' in issues else 3.5

                findings.append({
                    'vuln_type': 'security_headers',
                    'name': f'Insecure Cookie: {cookie_name}',
                    'description': (
                        f'Cookie "{cookie_name}" is missing security flags: {missing}. '
                        f'{"Without HttpOnly, JavaScript can steal session tokens via XSS. " if "HttpOnly" in issues else ""}'
                        f'{"Without Secure, cookie transmits over unencrypted HTTP. " if "Secure" in issues else ""}'
                        f'{"Without SameSite, cookie is sent with cross-site requests (CSRF risk). " if "SameSite" in issues else ""}'
                    ),
                    'impact': 'Session hijacking, credential theft, cross-site request forgery.',
                    'severity': severity,
                    'cvss_score': cvss,
                    'owasp_category': 'A05',
                    'affected_url': target_url,
                    'parameter': f'Set-Cookie: {cookie_name}',
                    'payload': 'N/A — Cookie analysis',
                    'request_data': f'GET {target_url}',
                    'response_data': f'Cookie "{cookie_name}" missing: {missing}',
                    'remediation': (
                        f'Set cookie with: {cookie_name}=value; '
                        f'{"HttpOnly; " if "HttpOnly" in issues else ""}'
                        f'{"Secure; " if "Secure" in issues else ""}'
                        f'{"SameSite=Lax; " if "SameSite" in issues else ""}'
                        'Path=/'
                    )
                })

        return findings

    def _check_cors(self, target_url):
        """Check for CORS misconfiguration."""
        findings = []

        # Test with arbitrary Origin
        response = self._request('GET', target_url,
                                headers={'Origin': 'https://evil-attacker.com'})
        if not response:
            return findings

        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')

        if acao == '*':
            findings.append({
                'vuln_type': 'security_headers',
                'name': 'CORS Wildcard Origin',
                'description': 'Access-Control-Allow-Origin is set to "*", allowing any website to read responses from this API.',
                'impact': 'Any website can make authenticated cross-origin requests and read the response data.',
                'severity': 'medium' if acac.lower() == 'true' else 'low',
                'cvss_score': 6.5 if acac.lower() == 'true' else 3.5,
                'owasp_category': 'A05',
                'affected_url': target_url,
                'parameter': 'Access-Control-Allow-Origin',
                'payload': 'Origin: https://evil-attacker.com',
                'request_data': f'GET {target_url}\nOrigin: https://evil-attacker.com',
                'response_data': f'ACAO: {acao}' + (f', ACAC: {acac}' if acac else ''),
                'remediation': 'Restrict ACAO to specific trusted origins. Never use * with credentials. Validate Origin against an allowlist.'
            })
        elif acao == 'https://evil-attacker.com':
            findings.append({
                'vuln_type': 'security_headers',
                'name': 'CORS Origin Reflection',
                'description': 'The server reflects the Origin header directly in Access-Control-Allow-Origin without validation. This allows any website to bypass the same-origin policy.',
                'impact': 'Complete bypass of same-origin policy. Attackers can steal user data from authenticated sessions.',
                'severity': 'high',
                'cvss_score': 8.0,
                'owasp_category': 'A05',
                'affected_url': target_url,
                'parameter': 'Access-Control-Allow-Origin',
                'payload': 'Origin: https://evil-attacker.com',
                'request_data': f'GET {target_url}\nOrigin: https://evil-attacker.com',
                'response_data': f'ACAO: {acao}' + (f', ACAC: {acac}' if acac else ''),
                'remediation': 'Validate Origin against a strict allowlist of trusted domains. Never reflect Origin blindly.'
            })

        return findings

    def _check_server_disclosure(self, response, target_url):
        """Check for server/technology information disclosure."""
        findings = []
        headers = {k.lower(): v for k, v in response.headers.items()}

        server = headers.get('server', '')
        x_powered = headers.get('x-powered-by', '')
        x_aspnet = headers.get('x-aspnet-version', '')
        x_aspnetmvc = headers.get('x-aspnetmvc-version', '')

        if server and any(v in server.lower() for v in ['apache/', 'nginx/', 'iis/', 'lighttpd/', 'litespeed']):
            findings.append({
                'vuln_type': 'security_headers',
                'name': 'Server Version Disclosure',
                'description': f'Server header reveals version: {server}. This aids targeted attacks.',
                'impact': 'Enables targeted exploits based on known CVEs for the identified version.',
                'severity': 'low',
                'cvss_score': 2.5,
                'owasp_category': 'A05',
                'affected_url': target_url,
                'parameter': 'Server',
                'payload': 'N/A',
                'request_data': f'GET {target_url}',
                'response_data': f'Server: {server}',
                'remediation': 'Remove or obscure version information from the Server header.'
            })

        for header_name, header_value in [('X-Powered-By', x_powered),
                                           ('X-AspNet-Version', x_aspnet),
                                           ('X-AspNetMvc-Version', x_aspnetmvc)]:
            if header_value:
                findings.append({
                    'vuln_type': 'security_headers',
                    'name': f'Technology Disclosure: {header_name}',
                    'description': f'{header_name} reveals technology: {header_value}. Aids reconnaissance.',
                    'impact': 'Framework information helps attackers select targeted exploits.',
                    'severity': 'info',
                    'cvss_score': 1.0,
                    'owasp_category': 'A05',
                    'affected_url': target_url,
                    'parameter': header_name,
                    'payload': 'N/A',
                    'request_data': f'GET {target_url}',
                    'response_data': f'{header_name}: {header_value}',
                    'remediation': f'Remove the {header_name} header from server configuration.'
                })

        return findings

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []
        response = self._request('GET', target_url)

        if not response:
            return self.findings

        # 1. Missing headers
        self.findings.extend(self._check_missing_headers(response, target_url))

        # 2. CSP strength
        self.findings.extend(self._check_csp_strength(response, target_url))

        # 3. Cookie security flags
        self.findings.extend(self._check_cookie_flags(response, target_url))

        # 4. CORS misconfiguration
        self.findings.extend(self._check_cors(target_url))

        # 5. Server/technology disclosure
        self.findings.extend(self._check_server_disclosure(response, target_url))

        return self.findings
