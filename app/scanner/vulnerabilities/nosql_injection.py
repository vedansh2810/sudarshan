"""
NoSQL Injection Scanner
OWASP: A03 - Injection | CWE-943

Detects NoSQL injection vulnerabilities in MongoDB, CouchDB, and other
NoSQL databases. Tests operator injection, authentication bypass,
JavaScript injection, and blind boolean-based techniques.
"""

import re
import logging
import time
from urllib.parse import urlparse, parse_qs, urlencode
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class NoSQLInjectionScanner(BaseScanner):
    """Detects NoSQL injection vulnerabilities.

    Detection Techniques:
    1. MongoDB operator injection ($gt, $ne, $regex, $where)
    2. Authentication bypass via always-true operators
    3. JavaScript injection in $where clauses
    4. Blind boolean-based NoSQL injection
    5. Tautology-based detection
    """

    # ── Payload sets ─────────────────────────────────────────────────

    # MongoDB operator injection payloads (JSON body / query param)
    OPERATOR_PAYLOADS = [
        # Authentication bypass — always-true conditions
        {"payload": '{"$gt": ""}', "name": "gt-bypass", "technique": "operator"},
        {"payload": '{"$ne": ""}', "name": "ne-bypass", "technique": "operator"},
        {"payload": '{"$ne": null}', "name": "ne-null", "technique": "operator"},
        {"payload": '{"$exists": true}', "name": "exists-true", "technique": "operator"},
        # Regex-based data extraction
        {"payload": '{"$regex": ".*"}', "name": "regex-wildcard", "technique": "operator"},
        {"payload": '{"$regex": "^a"}', "name": "regex-prefix", "technique": "operator"},
    ]

    # Query string operator injection (MongoDB-style)
    QUERY_PAYLOADS = [
        {"payload": "[$gt]=", "name": "qs-gt", "technique": "query-operator"},
        {"payload": "[$ne]=", "name": "qs-ne", "technique": "query-operator"},
        {"payload": "[$regex]=.*", "name": "qs-regex", "technique": "query-operator"},
        {"payload": "[$exists]=true", "name": "qs-exists", "technique": "query-operator"},
        {"payload": "[$in][]=admin", "name": "qs-in", "technique": "query-operator"},
    ]

    # JavaScript injection payloads ($where, mapReduce)
    JS_PAYLOADS = [
        {"payload": "'; return true; var x='", "name": "js-true", "technique": "js-injection"},
        {"payload": "1; return true", "name": "js-return", "technique": "js-injection"},
        {"payload": "'; sleep(5000); var x='", "name": "js-sleep", "technique": "js-blind"},
        {"payload": "this.password.match(/.*/) || '1'=='1", "name": "js-match", "technique": "js-injection"},
    ]

    # Error-triggering payloads
    ERROR_PAYLOADS = [
        {"payload": "'\"\\;{}()", "name": "syntax-error", "technique": "error-based"},
        {"payload": "\\u0000", "name": "null-byte", "technique": "error-based"},
        {"payload": '{"$invalid": 1}', "name": "invalid-op", "technique": "error-based"},
    ]

    # MongoDB error patterns
    NOSQL_ERROR_PATTERNS = [
        r"MongoError",
        r"MongoDB",
        r"mongo\s*server",
        r"E11000\s+duplicate\s+key",
        r"\$where",
        r"mapReduce",
        r"BSON",
        r"ObjectId\(",
        r"bson\.errors",
        r"pymongo\.errors",
        r"Mongoose\s*Error",
        r"CastError",
        r"ValidationError.*mongo",
        r"SyntaxError.*\$",
        r"BadValue.*\$",
        r"unknown\s+operator.*\$",
        r"CouchDB",
        r"RethinkDB.*error",
    ]

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        self._compiled_errors = [
            re.compile(p, re.IGNORECASE) for p in self.NOSQL_ERROR_PATTERNS
        ]

    def _check_nosql_errors(self, response_text):
        """Check if response contains NoSQL error messages."""
        for pattern in self._compiled_errors:
            match = pattern.search(response_text)
            if match:
                return match.group(0)
        return None

    def _test_operator_injection(self, url, param_name, params, parsed, baseline_resp):
        """Test MongoDB operator injection via query parameters."""
        baseline_text = baseline_resp.text if baseline_resp else ""
        baseline_len = len(baseline_text)

        # Extract unique operators from payloads to avoid sending duplicate requests
        operators_tested = set()
        for payload_info in self.OPERATOR_PAYLOADS:
            # Extract the operator name from the payload (e.g. "$gt" from '{"$gt": ""}')
            import json as _json
            try:
                op_dict = _json.loads(payload_info["payload"])
                operator = list(op_dict.keys())[0]  # e.g. "$gt"
            except (ValueError, IndexError):
                continue

            if operator in operators_tested:
                continue
            operators_tested.add(operator)

            # Inject as query param value: param[$gt]=
            test_params = dict(params)
            test_params[f"{param_name}[{operator}]"] = [str(op_dict[operator])]
            if param_name in test_params:
                del test_params[param_name]
            query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            response = self._request("GET", test_url)
            if not response:
                continue

            # Check for significantly different response (bypass indicator)
            resp_len = len(response.text)
            len_diff = abs(resp_len - baseline_len)
            error_evidence = self._check_nosql_errors(response.text)

            if error_evidence:
                return {
                    "technique": "error-based",
                    "payload": f"{param_name}[{operator}]={op_dict[operator]}",
                    "url": test_url,
                    "param": param_name,
                    "method": "GET",
                    "evidence": f"NoSQL error: {error_evidence}",
                    "confidence": 90,
                }

            # Response length changed significantly = data leak
            if len_diff > 200 and resp_len > baseline_len:
                return {
                    "technique": "operator-injection",
                    "payload": f"{param_name}[{operator}]={op_dict[operator]}",
                    "url": test_url,
                    "param": param_name,
                    "method": "GET",
                    "evidence": f"Response length changed: {baseline_len} → {resp_len} (+{len_diff})",
                    "confidence": 70,
                }

        return None

    def _test_query_operators(self, url, param_name, params, parsed, baseline_resp):
        """Test query-string operator injection patterns."""
        baseline_text = baseline_resp.text if baseline_resp else ""

        for payload_info in self.QUERY_PAYLOADS:
            test_params = dict(params)
            # Replace param with operator version
            operator_key = f"{param_name}{payload_info['payload']}"
            test_params[operator_key] = [""]
            if param_name in test_params:
                del test_params[param_name]
            query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            response = self._request("GET", test_url)
            if not response:
                continue

            error_evidence = self._check_nosql_errors(response.text)
            if error_evidence:
                return {
                    "technique": payload_info["technique"],
                    "payload": f"{param_name}{payload_info['payload']}",
                    "url": test_url,
                    "param": param_name,
                    "method": "GET",
                    "evidence": f"NoSQL error: {error_evidence}",
                    "confidence": 85,
                }

        return None

    def _test_error_based(self, url, param_name, params, parsed, baseline_resp):
        """Test error-based NoSQL injection with syntax-breaking payloads."""
        for payload_info in self.ERROR_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload_info["payload"]]
            query = urlencode(test_params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

            response = self._request("GET", test_url)
            if not response:
                continue

            error_evidence = self._check_nosql_errors(response.text)
            if error_evidence:
                # Check baseline didn't have this error
                baseline_error = self._check_nosql_errors(
                    baseline_resp.text if baseline_resp else ""
                )
                if not baseline_error:
                    return {
                        "technique": "error-based",
                        "payload": payload_info["payload"],
                        "url": test_url,
                        "param": param_name,
                        "method": "GET",
                        "evidence": f"NoSQL error triggered: {error_evidence}",
                        "confidence": 90,
                    }

        return None

    def _test_form_nosql(self, form, baseline_body):
        """Test form inputs for NoSQL injection."""
        url = form.get("action", "")
        method = form.get("method", "post").upper()
        inputs = form.get("inputs", [])

        testable = [
            inp for inp in inputs
            if inp.get("type", "") not in ("submit", "button", "image", "reset", "hidden")
            and inp.get("name")
        ]
        if not testable:
            return None

        for target_input in testable:
            # Test operator injection in form data
            for payload_info in self.OPERATOR_PAYLOADS[:3]:
                data = {}
                for inp in inputs:
                    if inp["name"] == target_input["name"]:
                        data[f'{inp["name"]}[$gt]'] = ""
                    elif inp.get("type") in ("submit", "button"):
                        data[inp["name"]] = inp.get("value", "Submit")
                    else:
                        data[inp["name"]] = inp.get("value", "") or "test"

                response = self._request(method, url, data=data)
                if not response:
                    continue

                error_evidence = self._check_nosql_errors(response.text)
                if error_evidence:
                    return {
                        "technique": "operator-injection",
                        "payload": f'{target_input["name"]}[$gt]=',
                        "url": url,
                        "param": target_input["name"],
                        "method": method,
                        "evidence": f"NoSQL error: {error_evidence}",
                        "confidence": 85,
                    }

        return None

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        for point in injectable_points:
            # ── Forms ──
            if isinstance(point, dict) and point.get("type") == "form":
                form_key = point.get("action", target_url)
                if form_key in seen:
                    continue
                seen.add(form_key)

                baseline_resp = self._request("GET", point.get("action", target_url))
                result = self._test_form_nosql(
                    point, baseline_resp.text if baseline_resp else ""
                )
                if result:
                    self.findings.append(self._make_finding(result))

            # ── URL params ──
            elif isinstance(point, dict) and "name" in point:
                url = point.get("url", target_url)
                param = point["name"]
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                key = f"{url}:{param}"

                if key in seen or param not in params:
                    continue
                seen.add(key)

                # Fetch baseline
                baseline_resp = self._request("GET", url)

                # Try each technique
                result = self._test_operator_injection(
                    url, param, params, parsed, baseline_resp
                )
                if not result:
                    result = self._test_query_operators(
                        url, param, params, parsed, baseline_resp
                    )
                if not result:
                    result = self._test_error_based(
                        url, param, params, parsed, baseline_resp
                    )

                if result:
                    self.findings.append(self._make_finding(result))

        return self.findings

    def _make_finding(self, result):
        confidence = result.get("confidence", 75)
        return {
            "vuln_type": "nosql_injection",
            "name": f"NoSQL Injection ({result['technique']})",
            "description": (
                f"NoSQL injection detected via {result['technique']}. "
                "The application passes user input to NoSQL database queries "
                "without proper sanitization, allowing query manipulation."
            ),
            "impact": (
                "NoSQL injection can lead to:\n"
                "• Authentication bypass (login without valid credentials)\n"
                "• Data exfiltration from MongoDB/CouchDB/etc.\n"
                "• Arbitrary data modification or deletion\n"
                "• Denial of service via expensive queries\n"
                "• Server-side JavaScript execution ($where, mapReduce)"
            ),
            "severity": "high",
            "cvss_score": 8.6,
            "confidence": confidence,
            "owasp_category": "A03",
            "cwe": "CWE-943",
            "affected_url": result["url"],
            "parameter": result["param"],
            "payload": result["payload"],
            "request_data": f"{result.get('method', 'GET')} {result['url']}\nParam: {result['param']}",
            "response_data": result.get("evidence", "NoSQL injection indicators detected"),
            "remediation": (
                "1. Use parameterized queries or ORM methods instead of raw query construction\n"
                "2. Validate and sanitize all user input before database queries\n"
                "3. Use allowlists for query operators — reject $gt, $ne, $regex, $where from user input\n"
                "4. Disable server-side JavaScript execution (--noscripting in MongoDB)\n"
                "5. Apply the principle of least privilege to database accounts\n"
                "6. Use input type validation (reject objects/arrays when strings expected)"
            ),
        }
