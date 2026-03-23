import re
import json
import logging
import requests
import time
import urllib3

# Suppress InsecureRequestWarning for self-signed cert scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class BaseScanner:
    def __init__(self, session=None, timeout=8, delay=0.5):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': 'Sudarshan-Scanner/1.0'})
        self.session.verify = False  # Allow scanning HTTPS with self-signed certs
        self.timeout = timeout
        self.delay = delay
        self.findings = []
        self._last_request_time = 0  # Track when last request was sent
        self._baseline_cache = {}     # Cache baselines per URL

        # Response similarity tracking for anti-false-positive detection
        self._response_hashes = {}  # url -> list of response hashes

        # ML data collection (set externally by ScanManager)
        self.collect_ml_data = False
        self.current_scan_id = None

    # ── Response Hashing (anti-false-positive) ───────────────────────

    @staticmethod
    def _get_response_hash(response):
        """Hash response body after stripping dynamic tokens.

        Removes timestamps, CSRF tokens, session IDs and nonces
        so that structurally identical pages produce the same hash.
        """
        import hashlib
        if not response or not hasattr(response, 'text'):
            return None
        text = response.text or ''
        # Strip common dynamic content
        text = re.sub(r'csrf[_-]?token["\']?\s*[:=]\s*["\'][^"\']+["\']', 'CSRF_TOKEN', text, flags=re.I)
        text = re.sub(r'nonce\s*=\s*["\'][^"\']+["\']', 'NONCE', text, flags=re.I)
        text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', 'TIMESTAMP', text)
        text = re.sub(r'session[_-]?id["\']?\s*[:=]\s*["\'][^"\']+["\']', 'SESSION', text, flags=re.I)
        return hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()

    def _track_response(self, url, response):
        """Track response hash for a URL. Call this for each test request."""
        h = self._get_response_hash(response)
        if h:
            self._response_hashes.setdefault(url, []).append(h)

    def _is_generic_response(self, url, min_samples=5, threshold=0.8):
        """Check if a URL returns the same content regardless of payload.

        Returns True if ≥threshold of responses share the same hash,
        indicating a catch-all/WAF page that likely causes false positives.
        """
        hashes = self._response_hashes.get(url, [])
        if len(hashes) < min_samples:
            return False
        from collections import Counter
        most_common_count = Counter(hashes).most_common(1)[0][1]
        return (most_common_count / len(hashes)) >= threshold

    def scan(self, target_url, injectable_points):
        raise NotImplementedError

    def _request(self, method, url, **kwargs):
        """Send HTTP request with rate-limiting between consecutive requests."""
        try:
            # Rate-limit: only sleep if we're sending requests too fast
            elapsed_since_last = time.time() - self._last_request_time
            if elapsed_since_last < self.delay:
                time.sleep(self.delay - elapsed_since_last)

            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('allow_redirects', True)
            kwargs.setdefault('verify', False)
            start = time.time()
            response = self.session.request(method, url, **kwargs)
            self._last_request_time = time.time()
            response.elapsed_time = time.time() - start
            return response
        except Exception:
            return None

    def _timed_request(self, method, url, **kwargs):
        """Send request and return (response, elapsed_seconds).
        Useful for time-based blind detection."""
        start = time.time()
        try:
            # Rate-limit
            elapsed_since_last = time.time() - self._last_request_time
            if elapsed_since_last < self.delay:
                time.sleep(self.delay - elapsed_since_last)

            kwargs.setdefault('timeout', max(self.timeout, 15))
            kwargs.setdefault('allow_redirects', True)
            kwargs.setdefault('verify', False)
            start = time.time()
            response = self.session.request(method, url, **kwargs)
            elapsed = time.time() - start
            self._last_request_time = time.time()
            return response, elapsed
        except requests.exceptions.Timeout:
            return None, time.time() - start
        except Exception:
            return None, 0

    def _get_baseline_time(self, url, method='GET', **kwargs):
        """Get average response time for baseline comparison.
        Results are cached per URL+method to avoid redundant measurements."""
        cache_key = f"{method}:{url}"
        if cache_key in self._baseline_cache:
            return self._baseline_cache[cache_key]

        times = []
        for _ in range(2):  # Reduced from 3 to 2 samples
            resp, elapsed = self._timed_request(method, url, **kwargs)
            if resp:
                times.append(elapsed)
        if not times:
            baseline = 1.0
        else:
            baseline = sum(times) / len(times)

        self._baseline_cache[cache_key] = baseline
        return baseline

    def scan(self, target_url, injectable_points):
        raise NotImplementedError

    # ── ML Data Collection ───────────────────────────────────────────

    def _extract_features(self, baseline_response, test_response, payload):
        """Extract numerical features from request/response pair for ML.

        Returns dict of ~18 features suitable for training.
        """
        features = {}

        # Payload features
        features['payload_length'] = len(payload) if payload else 0
        features['payload_special_chars'] = sum(
            1 for c in (payload or '') if c in "'\"<>;&|`$(){}[]\\"
        )
        features['payload_has_script_tag'] = 1 if '<script' in (payload or '').lower() else 0
        features['payload_has_sql_keyword'] = 1 if any(
            kw in (payload or '').upper()
            for kw in ('SELECT', 'UNION', 'DROP', 'INSERT', 'DELETE', 'UPDATE', 'SLEEP', 'WAITFOR')
        ) else 0
        features['payload_has_encoding'] = 1 if '%' in (payload or '') else 0

        # Baseline response features
        if baseline_response:
            features['baseline_status'] = getattr(baseline_response, 'status_code', 0) or 0
            features['baseline_length'] = len(getattr(baseline_response, 'text', '') or '')
        else:
            features['baseline_status'] = 0
            features['baseline_length'] = 0

        # Test response features
        if test_response:
            features['test_status'] = getattr(test_response, 'status_code', 0) or 0
            features['test_length'] = len(getattr(test_response, 'text', '') or '')
            features['response_time'] = getattr(test_response, 'elapsed_time', 0) or 0
        else:
            features['test_status'] = 0
            features['test_length'] = 0
            features['response_time'] = 0

        # Comparison features
        features['status_changed'] = 1 if features['baseline_status'] != features['test_status'] else 0
        features['length_diff'] = abs(features['test_length'] - features['baseline_length'])
        features['length_ratio'] = (
            features['test_length'] / features['baseline_length']
            if features['baseline_length'] > 0 else 0
        )

        # Error detection
        test_text = getattr(test_response, 'text', '') or '' if test_response else ''
        error_patterns = self._detect_error_patterns(test_text)
        features['error_count'] = len(error_patterns)
        features['has_db_error'] = 1 if any('sql' in e.lower() or 'database' in e.lower() for e in error_patterns) else 0

        # Reflection
        features['payload_reflected'] = 1 if payload and payload in test_text else 0

        return features

    def _detect_error_patterns(self, response_text):
        """Detect error patterns in response text.

        Returns list of matched error types.
        """
        if not response_text:
            return []

        patterns = {
            'sql_error': r'(?i)(sql\s*error|sql\s*syntax|mysql|sqlite|postgresql|ORA-\d{5})',
            'php_error': r'(?i)(fatal\s+error|warning.*php|parse\s+error|notice:.*undefined)',
            'python_error': r'(?i)(traceback\s*\(most\s+recent|internal\s+server\s+error)',
            'path_disclosure': r'(?i)([A-Z]:\\\\|/home/|/var/www/|/usr/)',
            'debug_info': r'(?i)(stack\s*trace|debug|exception\s+in)',
        }

        found = []
        text_lower = response_text.lower()
        for error_type, pattern in patterns.items():
            if re.search(pattern, response_text):
                found.append(error_type)

        return found

    # ── Smart AI Verification ────────────────────────────────────────

    def _ml_verify_finding(self, baseline_response, test_response, payload):
        """Use ML classifier to verify if a finding is a true positive.

        Extracts features from the request/response pair and runs the trained
        ML ensemble classifier. Non-fatal: returns (True, 50.0) on any error.

        Args:
            baseline_response: Clean response (no payload)
            test_response: Response with payload injected
            payload: The payload string

        Returns:
            (is_true_positive: bool, confidence: float 0-100)
        """
        try:
            from app.ai.smart_engine import get_smart_engine
            features = self._extract_features(baseline_response, test_response, payload)
            engine = get_smart_engine()
            return engine.ml_predict(features)
        except Exception as e:
            logger.debug(f'ML verification skipped: {e}')
            return True, 50.0

    def _ai_verify_finding(self, vuln_data, baseline_response, test_response, payload):
        """Three-layer finding verification: ML + LLM + combined.

        Uses SmartEngine to run ML prediction, then optionally LLM reasoning,
        and combines them for a final verdict. Non-fatal: returns
        ('true_positive', 0.5, 'Verification unavailable') on any error.

        Args:
            vuln_data: Dict with vuln_type, url, parameter, evidence
            baseline_response: Clean response
            test_response: Response with payload
            payload: The payload string

        Returns:
            (verdict, confidence, reasoning) tuple
        """
        try:
            from app.ai.smart_engine import get_smart_engine
            engine = get_smart_engine()

            features = self._extract_features(baseline_response, test_response, payload)

            test_text = getattr(test_response, 'text', '') or '' if test_response else ''
            response_data = {
                'status_code': getattr(test_response, 'status_code', None) if test_response else None,
                'content_length': len(test_text),
                'response_time': getattr(test_response, 'elapsed_time', None) if test_response else None,
                'reflection_detected': bool(payload and payload in test_text),
                'body_preview': self._sanitize_response_data(test_text[:500]),
            }

            return engine.verify_finding(vuln_data, features, response_data)
        except Exception as e:
            logger.debug(f'AI verification skipped: {e}')
            return 'true_positive', 0.5, 'Verification unavailable'

    # ── Smart Payload Generation ─────────────────────────────────────

    def _get_smart_payloads(self, vuln_type, target_context=None, num_payloads=8):
        """Generate LLM-powered payloads using SmartEngine.

        Calls SmartEngine.generate_smart_payloads() which uses the LLM with
        PortSwigger knowledge base context to generate targeted payloads.

        Args:
            vuln_type: Vulnerability type slug (e.g., 'sql_injection', 'xss')
            target_context: Optional dict from AI reconnaissance with tech stack info
            num_payloads: Number of payloads to request

        Returns:
            List of payload strings. Empty list if LLM unavailable.
        """
        try:
            from app.ai.smart_engine import get_smart_engine
            engine = get_smart_engine()
            smart_results = engine.generate_smart_payloads(
                vuln_type, target_context, num_payloads
            )
            # Extract just the payload strings from the dicts
            payloads = []
            for item in smart_results:
                if isinstance(item, dict):
                    p = item.get('payload', '')
                    if p:
                        payloads.append(p)
                elif isinstance(item, str) and item:
                    payloads.append(item)
            if payloads:
                logger.info(f'{vuln_type}: {len(payloads)} AI-generated payloads added')
            return payloads
        except Exception as e:
            logger.debug(f'Smart payload generation skipped: {e}')
            return []

    # ── Response Data Sanitization ────────────────────────────────────

    _SENSITIVE_PATTERNS = [
        (re.compile(r'Authorization:\s*\S+', re.IGNORECASE), 'Authorization: [REDACTED]'),
        (re.compile(r'Set-Cookie:\s*[^\r\n]+', re.IGNORECASE), 'Set-Cookie: [REDACTED]'),
        (re.compile(r'[a-zA-Z0-9+/=]{40,}'), '[LONG_TOKEN_REDACTED]'),
    ]

    _MAX_RESPONSE_DATA_LENGTH = 2048

    @classmethod
    def _sanitize_response_data(cls, text):
        """Strip sensitive patterns and truncate response data for ML storage."""
        if not text:
            return text
        if not isinstance(text, str):
            text = str(text)
        for pattern, replacement in cls._SENSITIVE_PATTERNS:
            text = pattern.sub(replacement, text)
        if len(text) > cls._MAX_RESPONSE_DATA_LENGTH:
            text = text[:cls._MAX_RESPONSE_DATA_LENGTH] + '... [TRUNCATED]'
        return text

    def _record_attempt(self, url, param, payload, baseline_response,
                        test_response, vuln_found, technique='',
                        vuln_type='', confidence=0, severity='',
                        method='GET', context='query_parameter'):
        """Record a scan attempt for ML training.

        Only records if collect_ml_data=True and current_scan_id is set.
        Failures are silently caught to never break core scanning.
        Response data is sanitized: truncated to 2048 chars with sensitive
        patterns (auth headers, cookies, long tokens) stripped.
        """
        if not self.collect_ml_data or not self.current_scan_id:
            return

        try:
            from app.models.ml_training import ScanAttempt

            features = self._extract_features(baseline_response, test_response, payload)
            error_patterns = self._detect_error_patterns(
                getattr(test_response, 'text', '') or '' if test_response else ''
            )

            # Sanitize response text before storage
            raw_response_text = getattr(test_response, 'text', '') or '' if test_response else ''
            sanitized_text = self._sanitize_response_data(raw_response_text)

            ScanAttempt.create(
                scan_id=self.current_scan_id,
                request_data={
                    'url': url,
                    'parameter': param,
                    'original_value': '',
                    'payload': payload or '',
                    'method': method,
                    'context': context,
                },
                response_data={
                    'status_code': getattr(test_response, 'status_code', None) if test_response else None,
                    'content_length': len(getattr(test_response, 'text', '') or '') if test_response else None,
                    'response_time': getattr(test_response, 'elapsed_time', None) if test_response else None,
                    'error_patterns': error_patterns,
                    'reflection_detected': bool(
                        payload and test_response and payload in (getattr(test_response, 'text', '') or '')
                    ),
                    'body_preview': sanitized_text,
                },
                detection_result={
                    'vulnerability_found': vuln_found,
                    'vulnerability_type': vuln_type,
                    'confidence': confidence,
                    'technique': technique,
                    'severity': severity,
                },
                features=features,
            )
        except Exception as e:
            logger.debug(f'ML data recording failed (non-fatal): {e}')

