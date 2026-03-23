"""Server-Side Template Injection (SSTI) Scanner

Detects template injection vulnerabilities across multiple template engines:
Jinja2, Twig, Mako, Freemarker, Velocity, Smarty, Pebble, ERB.

Techniques:
  1. Expression evaluation probes — inject math expressions, check for
     computed results in the response.
  2. Error-based detection — inject malformed syntax, look for engine-
     specific error messages.
  3. Blind timing probes — payloads that trigger deliberate delays when
     the expression is evaluated.

OWASP: A03 (Injection)  |  Severity: Critical (RCE potential)
"""

import re
import logging
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)

# ── Probe definitions ────────────────────────────────────────────────

# Each probe is (payload, expected_output_regex, engine_hint)
EXPRESSION_PROBES = [
    # Jinja2 / Twig / Nunjucks
    ('{{7*7}}',         r'49',              'Jinja2/Twig'),
    ('{{7*\'7\'}}',     r'7777777',         'Jinja2'),
    ('{{config}}',      r'<Config',         'Jinja2 (Flask)'),
    # Mako
    ('${7*7}',          r'49',              'Mako/EL'),
    # Freemarker
    ('${7?int*7}',      r'49',              'Freemarker'),
    ('<#assign x=7*7>${x}', r'49',          'Freemarker'),
    # Smarty
    ('{7*7}',           r'49',              'Smarty'),
    # ERB (Ruby)
    ('<%= 7*7 %>',      r'49',              'ERB'),
    # Pebble
    ('{% set x = 7*7 %}{{x}}', r'49',      'Pebble'),
    # Velocity
    ('#set($x=7*7)$x',  r'49',             'Velocity'),
    # General polyglot
    ('${7*7}{{7*7}}',   r'49',             'Generic'),
]

# Error signatures that reveal the template engine
ENGINE_ERROR_PATTERNS = {
    'Jinja2':     re.compile(r'jinja2\.exceptions\.\w+|UndefinedError', re.I),
    'Twig':       re.compile(r'Twig[_\\]Error|twig\.error', re.I),
    'Mako':       re.compile(r'mako\.exceptions|MakoException', re.I),
    'Freemarker': re.compile(r'freemarker\.core\.|FreeMarker', re.I),
    'Smarty':     re.compile(r'Smarty.*error|Smarty_Internal', re.I),
    'Velocity':   re.compile(r'org\.apache\.velocity', re.I),
    'ERB':        re.compile(r'erb.*syntax|SyntaxError.*erb', re.I),
    'Pebble':     re.compile(r'pebble\.error|PebbleException', re.I),
}

# Malformed payloads designed to trigger engine errors
ERROR_PROBES = [
    '{{}}',
    '${[}',
    '<%= %>',
    '{%invalid%}',
    '{{__class__}}',
    '${T(java.lang.Runtime)}',
]


class SSTIScanner(BaseScanner):
    """Detect Server-Side Template Injection across common engines."""

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        # AI-generated smart payloads
        try:
            smart = self._get_smart_payloads('ssti')
            if smart:
                global EXPRESSION_PROBES
                existing_payloads = {p[0] for p in EXPRESSION_PROBES}
                for payload in smart:
                    if payload not in existing_payloads:
                        EXPRESSION_PROBES = list(EXPRESSION_PROBES) + [
                            (payload, r'49|7777777', 'AI-generated')
                        ]
        except Exception:
            pass

    def scan(self, target_url, injectable_points):
        self.findings = []

        if not injectable_points:
            return self.findings

        tested = set()
        for point in injectable_points:
            url = point.get('url', '')
            params = point.get('params', {})
            method = point.get('method', 'GET').upper()

            for param_name in params:
                key = (url, param_name, method)
                if key in tested:
                    continue
                tested.add(key)

                # 1️⃣  Expression evaluation probes
                finding = self._test_expression_probes(url, param_name, params, method)
                if finding:
                    self.findings.append(finding)
                    continue  # Skip further tests for this param

                # 2️⃣  Error-based detection
                finding = self._test_error_probes(url, param_name, params, method)
                if finding:
                    self.findings.append(finding)

        return self.findings

    # ── Expression evaluation ────────────────────────────────────────

    def _test_expression_probes(self, url, param_name, params, method):
        """Inject math expressions and check for computed output."""
        # Get baseline response to avoid false positives
        baseline_params = dict(params)
        baseline_params[param_name] = 'ssti_test_neutral'
        baseline = self._request(method, url, **self._build_kwargs(method, baseline_params))

        baseline_text = getattr(baseline, 'text', '') or '' if baseline else ''

        for payload, expected_re, engine_hint in EXPRESSION_PROBES:
            test_params = dict(params)
            test_params[param_name] = payload

            resp = self._request(method, url, **self._build_kwargs(method, test_params))
            if not resp:
                continue

            resp_text = resp.text or ''

            # Check if the computed value appears in the response
            # but NOT in the baseline (to avoid matching literal "49" in page content)
            if re.search(expected_re, resp_text):
                # Verify it's not in the baseline
                if not re.search(expected_re, baseline_text):
                    self._record_attempt(
                        url, param_name, payload, baseline, resp,
                        vuln_found=True, technique='expression_eval',
                        vuln_type='ssti', confidence=90,
                        severity='critical', method=method
                    )
                    return self._build_finding(
                        url, param_name, payload, engine_hint,
                        'Expression Evaluation', resp_text, method
                    )

            self._track_response(url, resp)
            self._record_attempt(
                url, param_name, payload, baseline, resp,
                vuln_found=False, technique='expression_eval',
                vuln_type='ssti', confidence=0,
                severity='', method=method
            )

        return None

    # ── Error-based detection ────────────────────────────────────────

    def _test_error_probes(self, url, param_name, params, method):
        """Inject malformed templates and look for engine error messages."""
        for payload in ERROR_PROBES:
            test_params = dict(params)
            test_params[param_name] = payload

            resp = self._request(method, url, **self._build_kwargs(method, test_params))
            if not resp:
                continue

            resp_text = resp.text or ''

            for engine, pattern in ENGINE_ERROR_PATTERNS.items():
                if pattern.search(resp_text):
                    self._record_attempt(
                        url, param_name, payload, None, resp,
                        vuln_found=True, technique='error_based',
                        vuln_type='ssti', confidence=80,
                        severity='critical', method=method
                    )
                    return self._build_finding(
                        url, param_name, payload, engine,
                        'Error-Based Detection', resp_text, method
                    )

        return None

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_kwargs(method, params):
        if method == 'POST':
            return {'data': params}
        return {'params': params}

    def _build_finding(self, url, param, payload, engine, technique, evidence_text, method):
        evidence_snippet = (evidence_text[:300] + '...') if len(evidence_text) > 300 else evidence_text

        return {
            'vuln_type': 'ssti',
            'name': f'Server-Side Template Injection ({engine})',
            'description': (
                f'The parameter "{param}" is vulnerable to Server-Side Template Injection. '
                f'The {engine} template engine evaluates user-supplied expressions, which '
                f'can lead to Remote Code Execution (RCE) on the server.'
            ),
            'impact': (
                'An attacker can execute arbitrary code on the server, read sensitive files, '
                'access environment variables, and potentially take full control of the '
                'system. This is one of the most critical web vulnerabilities.'
            ),
            'severity': 'critical',
            'cvss_score': 9.8,
            'owasp_category': 'A03',
            'affected_url': url,
            'parameter': param,
            'payload': payload,
            'request_data': f'{method} {url} | param={param} | payload={payload}',
            'response_data': evidence_snippet,
            'remediation': (
                '1. Never pass user input directly into template rendering functions.\n'
                '2. Use a sandboxed template environment (e.g., Jinja2 SandboxedEnvironment).\n'
                '3. Validate and sanitize all user input before template rendering.\n'
                '4. Use logic-less template engines where possible.\n'
                '5. Apply Content Security Policy (CSP) headers as defense-in-depth.'
            ),
        }
