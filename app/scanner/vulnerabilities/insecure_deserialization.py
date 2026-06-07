import re
import base64
import logging
from urllib.parse import urlparse, parse_qs, urlencode

from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class InsecureDeserializationScanner(BaseScanner):
    """Detects insecure deserialization by inspecting cookies, responses,
    and injectable parameters for Java, PHP, Python, and .NET serialized
    object markers.  Focus on DETECTION, not exploitation."""

    # ── Serialization markers ─────────────────────────────────────────

    # Java serialized stream magic bytes (0xACED0005)
    JAVA_MAGIC = b"\xac\xed\x00\x05"

    # Python pickle opcodes
    PICKLE_MAGIC_V4 = b"\x80\x04\x95"
    PICKLE_MARKER = b"ccopy_reg"

    # PHP serialized patterns
    PHP_OBJECT_RE = re.compile(r"O:\d+:")   # O:4:"User":...
    PHP_ARRAY_RE = re.compile(r"a:\d+:\{")  # a:2:{...

    # .NET ViewState
    VIEWSTATE_FIELD = "__VIEWSTATE"

    # ── Response-body framework hints ─────────────────────────────────

    FRAMEWORK_HINTS = [
        (r"java\.io\.(?:Serializable|ObjectInputStream|InvalidClassException)", "java"),
        (r"java\.lang\.ClassNotFoundException", "java"),
        (r"java\.io\.StreamCorruptedException", "java"),
        (r"ClassCastException", "java"),
        (r"ObjectInputStream", "java"),
        (r"pickle\.loads?", "python"),
        (r"_pickle\.UnpicklingError", "python"),
        (r"unpickling", "python"),
        (r"unserialize\(\)", "php"),
        (r"__wakeup|__destruct|__toString", "php"),
        (r"allowed_classes", "php"),
        (r"ViewState|__VIEWSTATE", "dotnet"),
        (r"System\.Web\.UI", "dotnet"),
    ]

    # ── Error indicators after payload injection ──────────────────────

    JAVA_ERRORS = [
        r"ClassNotFoundException",
        r"InvalidClassException",
        r"StreamCorruptedException",
        r"java\.io\.",
        r"java\.lang\.Exception",
        r"ObjectInputStream",
        r"NotSerializableException",
    ]

    PHP_ERRORS = [
        r"unserialize\(\)",
        r"__wakeup",
        r"__destruct",
        r"Error at offset",
        r"unserialize\(\):\s*Error",
        r"allowed_classes",
    ]

    PYTHON_ERRORS = [
        r"pickle\.loads?",
        r"UnpicklingError",
        r"_pickle\.",
        r"cPickle",
        r"Could not deserialize",
    ]

    # ── Test payloads (benign, designed to trigger errors) ─────────────

    # Corrupt Java serialized object (magic + garbage)
    JAVA_TEST_PAYLOAD = base64.b64encode(b"\xac\xed\x00\x05sr\x00\x10SUDARSHAN_TEST").decode()

    # Corrupt PHP serialized string
    PHP_TEST_PAYLOADS = [
        'O:15:"SUDARSHAN_TEST":0:{}',
        'a:1:{s:4:"test";O:15:"SUDARSHAN_TEST":0:{}}',
    ]

    # Corrupt Python pickle
    PYTHON_TEST_PAYLOAD = base64.b64encode(
        b"\x80\x04\x95\x0f\x00\x00\x00\x00\x00\x00\x00\x8c\x0bSUDARSHAN_T\x94."
    ).decode()

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)

    # ── Cookie inspection ─────────────────────────────────────────────

    def _check_cookies(self, url):
        """Fetch the URL and inspect cookies for serialized object markers."""
        findings = []
        resp = self._request("GET", url)
        if resp is None:
            return findings

        cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        # Fallback for httpx: iterate all set-cookie headers
        if not cookies:
            cookies = [
                v for k, v in resp.headers.multi_items()
                if k.lower() == "set-cookie"
            ]

        for cookie_header in cookies:
            # Extract cookie name=value
            parts = cookie_header.split(";")[0]
            if "=" not in parts:
                continue
            name, value = parts.split("=", 1)
            name = name.strip()
            value = value.strip()

            # Try base64-decode
            raw = None
            try:
                raw = base64.b64decode(value)
            except Exception:
                pass

            # Java check
            if raw and raw[:4] == self.JAVA_MAGIC:
                findings.append(self._make_cookie_finding(
                    url, name, value, "java",
                    "Cookie contains Java serialized object (magic bytes \\xACED0005).",
                ))
                continue

            # Python pickle check
            if raw and (raw[:3] == self.PICKLE_MAGIC_V4 or self.PICKLE_MARKER in raw):
                findings.append(self._make_cookie_finding(
                    url, name, value, "python",
                    "Cookie contains Python pickle data.",
                ))
                continue

            # PHP check (works on raw string too)
            check_str = value
            if raw:
                try:
                    check_str = raw.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            if self.PHP_OBJECT_RE.search(check_str) or self.PHP_ARRAY_RE.search(check_str):
                findings.append(self._make_cookie_finding(
                    url, name, value, "php",
                    "Cookie contains PHP serialized data.",
                ))
                continue

        return findings

    def _make_cookie_finding(self, url, cookie_name, cookie_value, framework, detail):
        severity_map = {
            "java": "critical",
            "python": "critical",
            "php": "high",
            "dotnet": "medium",
        }
        return {
            "vuln_type": "insecure_deserialization",
            "name": f"Insecure Deserialization — {framework.title()} Cookie",
            "description": (
                f"{detail} The cookie '{cookie_name}' contains a serialized "
                f"{framework} object. If the application deserializes this "
                f"without validation, an attacker can craft a malicious "
                f"serialized payload leading to remote code execution."
            ),
            "impact": (
                "Remote code execution, authentication bypass, "
                "denial of service, data tampering."
            ),
            "severity": severity_map.get(framework, "high"),
            "cvss_score": 9.8 if severity_map.get(framework) == "critical" else 8.1,
            "owasp_category": "A08",
            "cwe": "CWE-502",
            "affected_url": url,
            "parameter": f"Cookie: {cookie_name}",
            "payload": cookie_value[:200],
            "request_data": f"GET {url}\nCookie inspected: {cookie_name}",
            "response_data": detail,
            "remediation": (
                "Never deserialize untrusted data. Use safe serialization "
                "formats (JSON) instead of native serialization. Implement "
                "integrity checks (HMAC) on serialized cookies. Use "
                "allowlists for deserialized classes."
            ),
        }

    # ── Response-body inspection ──────────────────────────────────────

    def _check_response_hints(self, url):
        """Check if the response body mentions serialization frameworks."""
        findings = []
        resp = self._request("GET", url)
        if resp is None or not resp.text:
            return findings

        text = resp.text
        detected_frameworks = set()

        for pattern, framework in self.FRAMEWORK_HINTS:
            if re.search(pattern, text, re.IGNORECASE):
                detected_frameworks.add(framework)

        for fw in detected_frameworks:
            findings.append({
                "vuln_type": "insecure_deserialization",
                "name": f"Serialization Framework Exposed — {fw.title()}",
                "description": (
                    f"The response body contains references to {fw} "
                    f"serialization classes or functions. This suggests the "
                    f"application uses native deserialization which may be "
                    f"exploitable."
                ),
                "impact": "Information disclosure, potential remote code execution.",
                "severity": "medium",
                "cvss_score": 5.3,
                "owasp_category": "A08",
                "cwe": "CWE-502",
                "affected_url": url,
                "parameter": "N/A",
                "payload": "N/A",
                "request_data": f"GET {url}",
                "response_data": f"Framework references detected: {fw}",
                "remediation": (
                    "Suppress serialization error details in production. "
                    "Replace native deserialization with safe alternatives."
                ),
            })

        return findings

    # ── ViewState inspection ──────────────────────────────────────────

    def _check_viewstate(self, url, response_text=None):
        """Check for unprotected .NET ViewState (MAC disabled)."""
        findings = []
        if response_text is None:
            resp = self._request("GET", url)
            if resp is None:
                return findings
            response_text = resp.text or ""

        # Look for __VIEWSTATE hidden field
        vs_match = re.search(
            r'name\s*=\s*["\']__VIEWSTATE["\']\s+[^>]*value\s*=\s*["\']([^"\']+)["\']',
            response_text, re.IGNORECASE,
        )
        if not vs_match:
            vs_match = re.search(
                r'value\s*=\s*["\']([^"\']+)["\']\s+[^>]*name\s*=\s*["\']__VIEWSTATE["\']',
                response_text, re.IGNORECASE,
            )
        if not vs_match:
            return findings

        viewstate_b64 = vs_match.group(1)

        # Try to decode and check for MAC
        try:
            raw = base64.b64decode(viewstate_b64)
        except Exception:
            return findings

        # Heuristic: ViewState without MAC is typically shorter and doesn't
        # end with a 20-byte (SHA1) or 32-byte (SHA256) HMAC signature.
        # Also check for __VIEWSTATEGENERATOR without __VIEWSTATEMAC.
        has_mac_field = "__VIEWSTATEMAC" in response_text or "__EVENTVALIDATION" in response_text

        # Very short ViewState or no MAC field suggests MAC is disabled
        if not has_mac_field:
            findings.append({
                "vuln_type": "insecure_deserialization",
                "name": "Unprotected .NET ViewState (MAC Disabled)",
                "description": (
                    "The application uses ASP.NET ViewState without a "
                    "Message Authentication Code (MAC). An attacker can "
                    "tamper with the ViewState to inject serialized objects "
                    "or modify application state."
                ),
                "impact": (
                    "Remote code execution via crafted ViewState, "
                    "application state tampering, authentication bypass."
                ),
                "severity": "medium",
                "cvss_score": 6.5,
                "owasp_category": "A08",
                "cwe": "CWE-502",
                "affected_url": url,
                "parameter": "__VIEWSTATE",
                "payload": viewstate_b64[:120] + "..." if len(viewstate_b64) > 120 else viewstate_b64,
                "request_data": f"GET {url}\nViewState field found",
                "response_data": "ViewState present without MAC validation field",
                "remediation": (
                    "Enable ViewState MAC validation: set "
                    "enableViewStateMac=\"true\" in web.config. "
                    "Use ViewState encryption. Upgrade to ASP.NET 4.5+ "
                    "which enforces MAC by default."
                ),
            })

        return findings

    # ── Parameter injection tests ─────────────────────────────────────

    def _test_param_injection(self, url, param_name, params, parsed):
        """Inject modified serialized payloads into a URL parameter and
        check for deserialization error responses."""
        findings = []
        orig_val = params.get(param_name, [""])[0]

        # Determine which frameworks to test based on the original value
        test_sets = []

        # Check if original value looks like base64
        raw = None
        try:
            raw = base64.b64decode(orig_val)
        except Exception:
            pass

        if raw and raw[:4] == self.JAVA_MAGIC:
            test_sets.append(("java", [self.JAVA_TEST_PAYLOAD], self.JAVA_ERRORS))
        elif raw and (raw[:3] == self.PICKLE_MAGIC_V4 or self.PICKLE_MARKER in raw):
            test_sets.append(("python", [self.PYTHON_TEST_PAYLOAD], self.PYTHON_ERRORS))

        # Check for PHP serialized
        if self.PHP_OBJECT_RE.search(orig_val) or self.PHP_ARRAY_RE.search(orig_val):
            test_sets.append(("php", self.PHP_TEST_PAYLOADS, self.PHP_ERRORS))

        # If nothing detected, try all formats
        if not test_sets:
            test_sets = [
                ("java", [self.JAVA_TEST_PAYLOAD], self.JAVA_ERRORS),
                ("php", self.PHP_TEST_PAYLOADS, self.PHP_ERRORS),
                ("python", [self.PYTHON_TEST_PAYLOAD], self.PYTHON_ERRORS),
            ]

        for framework, payloads, error_patterns in test_sets:
            for payload in payloads:
                test_params = dict(params)
                test_params[param_name] = [payload]
                query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"

                resp = self._request("GET", test_url)
                if resp is None:
                    continue

                text = resp.text or ""
                for err_pattern in error_patterns:
                    if re.search(err_pattern, text, re.IGNORECASE):
                        severity_map = {
                            "java": "critical",
                            "python": "critical",
                            "php": "high",
                        }
                        findings.append({
                            "vuln_type": "insecure_deserialization",
                            "name": f"Insecure Deserialization — {framework.title()} (Parameter)",
                            "description": (
                                f"Injecting a corrupt {framework} serialized object into "
                                f"parameter '{param_name}' triggered a deserialization "
                                f"error. This confirms the application deserializes "
                                f"user-controlled input."
                            ),
                            "impact": (
                                "Remote code execution, denial of service, "
                                "data tampering, authentication bypass."
                            ),
                            "severity": severity_map.get(framework, "high"),
                            "cvss_score": 9.8 if severity_map.get(framework) == "critical" else 8.1,
                            "owasp_category": "A08",
                            "cwe": "CWE-502",
                            "affected_url": test_url,
                            "parameter": param_name,
                            "payload": payload[:200],
                            "request_data": (
                                f"GET {test_url}\n"
                                f"Injected {framework} test payload into '{param_name}'"
                            ),
                            "response_data": (
                                f"Deserialization error detected: matched pattern '{err_pattern}'"
                            ),
                            "remediation": (
                                "Never deserialize untrusted input. Use safe data "
                                "formats (JSON). Implement integrity checks. Use "
                                "class allowlists. Isolate deserialization in "
                                "low-privilege environments."
                            ),
                        })
                        return findings  # One hit per param is enough

        return findings

    def _test_form_injection(self, form, target_url):
        """Test form inputs for deserialization vulnerabilities."""
        findings = []
        url = form.get("action", target_url)
        method = form.get("method", "post").upper()
        inputs = form.get("inputs", [])

        testable = [
            inp for inp in inputs
            if inp.get("type", "").lower() not in ("submit", "button", "image", "reset", "file")
        ]

        for target_input in testable:
            orig_val = target_input.get("value", "")

            # Build test sets based on original value analysis
            test_sets = []
            raw = None
            try:
                raw = base64.b64decode(orig_val)
            except Exception:
                pass

            if raw and raw[:4] == self.JAVA_MAGIC:
                test_sets.append(("java", [self.JAVA_TEST_PAYLOAD], self.JAVA_ERRORS))
            if self.PHP_OBJECT_RE.search(orig_val) or self.PHP_ARRAY_RE.search(orig_val):
                test_sets.append(("php", self.PHP_TEST_PAYLOADS, self.PHP_ERRORS))
            if raw and (raw[:3] == self.PICKLE_MAGIC_V4 or self.PICKLE_MARKER in raw):
                test_sets.append(("python", [self.PYTHON_TEST_PAYLOAD], self.PYTHON_ERRORS))

            # For hidden fields (common for serialized state), try all
            if not test_sets and target_input.get("type", "").lower() == "hidden":
                test_sets = [
                    ("java", [self.JAVA_TEST_PAYLOAD], self.JAVA_ERRORS),
                    ("php", self.PHP_TEST_PAYLOADS, self.PHP_ERRORS),
                    ("python", [self.PYTHON_TEST_PAYLOAD], self.PYTHON_ERRORS),
                ]

            if not test_sets:
                continue

            for framework, payloads, error_patterns in test_sets:
                for payload in payloads:
                    data = {}
                    for inp in inputs:
                        name = inp.get("name", "")
                        if not name:
                            continue
                        if name == target_input.get("name"):
                            data[name] = payload
                        elif inp.get("type", "").lower() in ("submit", "button"):
                            data[name] = inp.get("value", "Submit")
                        else:
                            data[name] = inp.get("value", "") or "test"

                    if method == "POST":
                        resp = self._request("POST", url, data=data)
                    else:
                        resp = self._request("GET", url, params=data)

                    if resp is None:
                        continue

                    text = resp.text or ""
                    for err_pattern in error_patterns:
                        if re.search(err_pattern, text, re.IGNORECASE):
                            severity_map = {
                                "java": "critical",
                                "python": "critical",
                                "php": "high",
                            }
                            findings.append({
                                "vuln_type": "insecure_deserialization",
                                "name": f"Insecure Deserialization — {framework.title()} (Form)",
                                "description": (
                                    f"Injecting a corrupt {framework} serialized object "
                                    f"into form field '{target_input.get('name')}' triggered "
                                    f"a deserialization error."
                                ),
                                "impact": (
                                    "Remote code execution, denial of service, "
                                    "authentication bypass, data tampering."
                                ),
                                "severity": severity_map.get(framework, "high"),
                                "cvss_score": 9.8 if severity_map.get(framework) == "critical" else 8.1,
                                "owasp_category": "A08",
                                "cwe": "CWE-502",
                                "affected_url": url,
                                "parameter": target_input.get("name", ""),
                                "payload": payload[:200],
                                "request_data": (
                                    f"{method} {url}\n"
                                    f"Field: {target_input.get('name')}\n"
                                    f"Framework: {framework}"
                                ),
                                "response_data": (
                                    f"Deserialization error: matched '{err_pattern}'"
                                ),
                                "remediation": (
                                    "Do not deserialize untrusted input. Use signed "
                                    "and encrypted serialized data. Migrate to safe "
                                    "data formats."
                                ),
                            })
                            return findings  # One hit per form is enough

        return findings

    # ── Main scan ─────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        # 1. Cookie inspection
        cookie_key = f"cookie:{target_url}"
        if cookie_key not in seen:
            seen.add(cookie_key)
            cookie_findings = self._check_cookies(target_url)
            self.findings.extend(cookie_findings)

        # 2. Response-body framework hints
        urls_checked = {target_url}
        hint_findings = self._check_response_hints(target_url)
        self.findings.extend(hint_findings)

        # 3. ViewState check (fetches the page once)
        vs_findings = self._check_viewstate(target_url)
        self.findings.extend(vs_findings)

        # 4. Injectable parameter tests
        for point in injectable_points:
            if not isinstance(point, dict):
                continue

            # Forms
            if point.get("type") == "form":
                form_url = point.get("action", target_url)
                form_key = f"form:{form_url}"
                if form_key in seen:
                    continue
                seen.add(form_key)

                # Check ViewState inside the form too
                form_vs = self._check_viewstate(form_url)
                self.findings.extend(form_vs)

                # Check response hints for form action URL
                if form_url not in urls_checked:
                    urls_checked.add(form_url)
                    self.findings.extend(self._check_response_hints(form_url))

                # Injection tests
                form_findings = self._test_form_injection(point, target_url)
                self.findings.extend(form_findings)

            # URL parameters
            elif "name" in point:
                url = point.get("url", target_url)
                param = point["name"]
                param_key = f"param:{url}:{param}"
                if param_key in seen:
                    continue
                seen.add(param_key)

                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if param not in params:
                    continue

                param_findings = self._test_param_injection(url, param, params, parsed)
                self.findings.extend(param_findings)

        return self.findings
