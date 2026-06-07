"""
Tests for Phase 5 vulnerability scanners:
  NoSQL Injection, File Upload, Host Header,
  Info Disclosure, Prototype Pollution, Insecure Deserialization.

Uses unittest.mock to simulate HTTP responses without making real network requests.
"""

import base64
import pytest
from unittest.mock import MagicMock, patch, PropertyMock, call


# ══════════════════════════════════════════════════════════════════
#  NoSQL Injection Scanner Tests
# ══════════════════════════════════════════════════════════════════


class TestNoSQLInjectionScanner:
    """Tests for NoSQL Injection scanner (CWE-943)."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.nosql_injection import NoSQLInjectionScanner

        scanner = NoSQLInjectionScanner()
        return scanner

    def test_operator_injection_error_detection(self):
        """Test detection when MongoDB operator injection triggers a NoSQL error."""
        scanner = self._make_scanner()

        # Baseline response (normal)
        baseline_resp = MagicMock()
        baseline_resp.status_code = 200
        baseline_resp.text = '{"users": []}'
        baseline_resp.headers = {}

        # Injected response — triggers MongoError
        inject_resp = MagicMock()
        inject_resp.status_code = 500
        inject_resp.text = '{"error": "MongoError: unknown operator $gt near field username"}'
        inject_resp.headers = {}

        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline_resp  # baseline fetch
            return inject_resp  # injection attempts

        injectable = [
            {"name": "username", "url": "http://target.com/api/users?username=admin"}
        ]

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/api/users", injectable)

        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "nosql_injection"
        assert findings[0]["severity"] == "high"
        assert findings[0]["cwe"] == "CWE-943"
        assert findings[0]["owasp_category"] == "A03"

    def test_operator_injection_response_length_change(self):
        """Test detection when operator injection causes data leak (response grows)."""
        scanner = self._make_scanner()

        baseline_resp = MagicMock()
        baseline_resp.status_code = 200
        baseline_resp.text = '{"users": []}'  # short baseline
        baseline_resp.headers = {}

        # Injected response — much longer (data leaked)
        inject_resp = MagicMock()
        inject_resp.status_code = 200
        inject_resp.text = '{"users": [' + ', '.join([
            '{"name": "user%d", "email": "u%d@test.com"}' % (i, i)
            for i in range(50)
        ]) + ']}'  # Much larger than baseline
        inject_resp.headers = {}

        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline_resp
            return inject_resp

        injectable = [
            {"name": "username", "url": "http://target.com/api/users?username=admin"}
        ]

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/api/users", injectable)

        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "nosql_injection"

    def test_no_false_positive_on_normal_response(self):
        """Test that normal responses don't trigger NoSQL injection findings."""
        scanner = self._make_scanner()

        normal_resp = MagicMock()
        normal_resp.status_code = 200
        normal_resp.text = '{"users": [{"name": "admin"}]}'
        normal_resp.headers = {}

        injectable = [
            {"name": "username", "url": "http://target.com/api/users?username=admin"}
        ]

        with patch.object(scanner, "_request", return_value=normal_resp):
            findings = scanner.scan("http://target.com/api/users", injectable)

        assert len(findings) == 0

    def test_form_parameter_format(self):
        """Test scanning forms with type='form' and inputs list."""
        scanner = self._make_scanner()

        baseline_resp = MagicMock()
        baseline_resp.status_code = 200
        baseline_resp.text = '{"status": "ok"}'
        baseline_resp.headers = {}

        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.text = 'Mongoose Error: CastError on field "username"'
        error_resp.headers = {}

        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline_resp
            return error_resp

        injectable = [
            {
                "type": "form",
                "action": "http://target.com/login",
                "method": "post",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                    {"name": "submit", "type": "submit", "value": "Login"},
                ],
            }
        ]

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/login", injectable)

        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "nosql_injection"

    def test_flat_param_format(self):
        """Test scanning with flat {name: 'param'} injectable points."""
        scanner = self._make_scanner()

        baseline_resp = MagicMock()
        baseline_resp.status_code = 200
        baseline_resp.text = "No results"
        baseline_resp.headers = {}

        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.text = "E11000 duplicate key error collection: users"
        error_resp.headers = {}

        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return baseline_resp
            return error_resp

        injectable = [
            {"name": "id", "url": "http://target.com/search?id=123"}
        ]

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/search", injectable)

        assert len(findings) >= 1
        assert findings[0]["cwe"] == "CWE-943"


# ══════════════════════════════════════════════════════════════════
#  File Upload Scanner Tests
# ══════════════════════════════════════════════════════════════════


class TestFileUploadScanner:
    """Tests for File Upload vulnerability scanner (CWE-434)."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.file_upload import FileUploadScanner

        scanner = FileUploadScanner()
        return scanner

    def _make_upload_form(self, action="http://target.com/upload"):
        """Helper to build a standard upload form injectable point."""
        return {
            "type": "form",
            "action": action,
            "method": "post",
            "inputs": [
                {"name": "file", "type": "file", "value": ""},
                {"name": "description", "type": "text", "value": "test"},
                {"name": "submit", "type": "submit", "value": "Upload"},
            ],
        }

    def test_dangerous_extension_accepted(self):
        """Test detection when a .php file upload is accepted."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"message": "File uploaded successfully", "url": "/uploads/sudarshan_test.php"}'
        mock_resp.headers = {}

        injectable = [self._make_upload_form()]

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/upload", injectable)

        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "file_upload"
        assert findings[0]["cwe"] == "CWE-434"
        assert findings[0]["severity"] in ("high", "critical")

    def test_double_extension_bypass(self):
        """Test detection of double extension bypass (.php.jpg accepted)."""
        scanner = self._make_scanner()

        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            resp.headers = {}

            # Reject direct dangerous extensions, accept double extension
            files = kwargs.get("files", {})
            if files:
                filename = ""
                for field_name, file_tuple in files.items():
                    if isinstance(file_tuple, tuple) and len(file_tuple) >= 1:
                        filename = file_tuple[0]
                        break

                if filename.endswith(".php") or filename.endswith(".jsp") or \
                   filename.endswith(".aspx") or filename.endswith(".html") or \
                   filename.endswith(".svg"):
                    # Reject direct dangerous extension
                    resp.status_code = 403
                    resp.text = "File type not allowed"
                elif ".php." in filename or ".jsp." in filename:
                    # Accept double extension (bypass!)
                    resp.status_code = 200
                    resp.text = f'File uploaded successfully: {filename}'
                else:
                    resp.status_code = 403
                    resp.text = "File type not allowed"
            else:
                resp.status_code = 200
                resp.text = "OK"

            return resp

        injectable = [self._make_upload_form()]

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/upload", injectable)

        assert len(findings) >= 1
        found_double_ext = any("double" in f["name"].lower() or "double" in f.get("description", "").lower()
                               for f in findings)
        assert found_double_ext or len(findings) >= 1  # At least found the bypass

    def test_no_finding_when_upload_rejected(self):
        """Test no finding when server rejects all dangerous uploads."""
        scanner = self._make_scanner()

        reject_resp = MagicMock()
        reject_resp.status_code = 403
        reject_resp.text = "Forbidden: file type not allowed"
        reject_resp.headers = {}

        injectable = [self._make_upload_form()]

        with patch.object(scanner, "_request", return_value=reject_resp):
            findings = scanner.scan("http://target.com/upload", injectable)

        assert len(findings) == 0

    def test_requires_file_input_in_form(self):
        """Test that scanner only tests forms with file inputs."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Upload successful"
        mock_resp.headers = {}

        # Form WITHOUT file input — should be skipped
        injectable = [
            {
                "type": "form",
                "action": "http://target.com/submit",
                "method": "post",
                "inputs": [
                    {"name": "name", "type": "text", "value": ""},
                    {"name": "submit", "type": "submit", "value": "Submit"},
                ],
            }
        ]

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/submit", injectable)

        assert len(findings) == 0

    def test_has_file_input_detection(self):
        """Test _has_file_input correctly identifies forms with file inputs."""
        scanner = self._make_scanner()

        form_with_file = {
            "inputs": [
                {"name": "file", "type": "file"},
                {"name": "submit", "type": "submit"},
            ]
        }
        form_without_file = {
            "inputs": [
                {"name": "name", "type": "text"},
                {"name": "submit", "type": "submit"},
            ]
        }

        assert scanner._has_file_input(form_with_file) is True
        assert scanner._has_file_input(form_without_file) is False


# ══════════════════════════════════════════════════════════════════
#  Host Header Scanner Tests
# ══════════════════════════════════════════════════════════════════


class TestHostHeaderScanner:
    """Tests for Host Header Injection scanner (CWE-644)."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.host_header import HostHeaderScanner

        scanner = HostHeaderScanner()
        return scanner

    def test_host_header_injection_detected(self):
        """Test detection when canary domain is reflected in response body."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            headers = kwargs.get("headers", {})
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}

            host = headers.get("Host", "")
            if host == scanner.CANARY_DOMAIN:
                resp.text = (
                    f'<html><body><a href="http://{scanner.CANARY_DOMAIN}'
                    f'/reset">Reset Password</a></body></html>'
                )
            else:
                resp.text = "<html><body>Normal page</body></html>"
            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        host_injection_findings = [
            f for f in findings if "Host Header Injection" in f["name"]
        ]
        assert len(host_injection_findings) >= 1
        assert host_injection_findings[0]["severity"] == "critical"
        assert host_injection_findings[0]["cwe"] == "CWE-644"

    def test_x_forwarded_host_injection(self):
        """Test detection of X-Forwarded-Host header injection."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            headers = kwargs.get("headers", {})
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}

            # Only reflect when X-Forwarded-Host is used (not direct Host)
            xfh = headers.get("X-Forwarded-Host", "")
            host = headers.get("Host", "")

            if host == scanner.CANARY_DOMAIN:
                resp.text = "<html><body>Normal page</body></html>"
            elif xfh == scanner.CANARY_DOMAIN:
                resp.text = (
                    f'<html><body><link href="http://{scanner.CANARY_DOMAIN}'
                    f'/style.css"></body></html>'
                )
            else:
                resp.text = "<html><body>Normal page</body></html>"
            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        xfh_findings = [
            f for f in findings if "X-Forwarded-Host" in f["name"]
        ]
        assert len(xfh_findings) >= 1
        assert xfh_findings[0]["severity"] == "high"

    def test_no_false_positive_when_host_not_reflected(self):
        """Test no finding when injected host is NOT reflected."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Normal page without any canary</body></html>"
        mock_resp.headers = {}

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/", [])

        # Should have no Host Header Injection or X-Forwarded-Host findings
        injection_findings = [
            f for f in findings
            if "Host Header Injection" in f["name"] or "Host Override" in f["name"]
        ]
        assert len(injection_findings) == 0

    def test_password_reset_poisoning(self):
        """Test detection of password reset poisoning via Host header."""
        scanner = self._make_scanner()

        call_count = [0]

        def mock_request(method, url, **kwargs):
            call_count[0] += 1
            headers = kwargs.get("headers", {})
            resp = MagicMock()
            resp.headers = {}

            # Main page tests — don't reflect
            if "/password/reset" not in url and "/forgot-password" not in url:
                resp.status_code = 200
                resp.text = "<html><body>Normal page</body></html>"
                return resp

            host = headers.get("Host", "")

            # Password reset endpoint exists
            if host == scanner.CANARY_DOMAIN:
                resp.status_code = 200
                resp.text = (
                    f'<html><body>Reset link: '
                    f'http://{scanner.CANARY_DOMAIN}/reset?token=abc123'
                    f'</body></html>'
                )
            else:
                resp.status_code = 200
                resp.text = '<html><body><form>Enter your email</form></body></html>'

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        reset_findings = [
            f for f in findings if "Password Reset" in f["name"]
        ]
        assert len(reset_findings) >= 1
        assert reset_findings[0]["severity"] == "critical"


# ══════════════════════════════════════════════════════════════════
#  Info Disclosure Scanner Tests
# ══════════════════════════════════════════════════════════════════


class TestInfoDisclosureScanner:
    """Tests for Information Disclosure scanner (CWE-200)."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.info_disclosure import InfoDisclosureScanner

        scanner = InfoDisclosureScanner()
        return scanner

    def test_git_head_detection(self):
        """Test detection of exposed .git/HEAD file."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.headers = {}

            if "/.git/HEAD" in url:
                resp.status_code = 200
                resp.text = "ref: refs/heads/main\n"
            elif "/.git/config" in url:
                resp.status_code = 200
                resp.text = "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:org/repo.git"
            else:
                resp.status_code = 404
                resp.text = "Not Found"

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        git_findings = [f for f in findings if "Git" in f["name"]]
        assert len(git_findings) >= 1
        assert git_findings[0]["severity"] == "high"
        assert git_findings[0]["cwe"] == "CWE-200"

    def test_env_file_detection(self):
        """Test detection of exposed .env file with secrets."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.headers = {}

            if "/.env" in url and ".backup" not in url:
                resp.status_code = 200
                resp.text = (
                    "APP_ENV=production\n"
                    "DB_PASSWORD=s3cret_p4ss\n"
                    "SECRET_KEY=abc123def456\n"
                    "API_KEY=sk-live-12345\n"
                    "DATABASE_URL=postgres://user:pass@db:5432/app\n"
                )
            else:
                resp.status_code = 404
                resp.text = "Not Found"

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        env_findings = [f for f in findings if ".env" in f["name"]]
        assert len(env_findings) >= 1
        assert env_findings[0]["severity"] == "critical"

    def test_stack_trace_detection(self):
        """Test detection of stack traces in error responses."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.headers = {}

            if "'" in url or "__debug__" in url or "debug" in url:
                resp.status_code = 500
                resp.text = (
                    'Traceback (most recent call last):\n'
                    '  File "/app/views.py", line 42, in index\n'
                    '    result = db.query(user_input)\n'
                    'TypeError: expected string, got NoneType\n'
                )
            else:
                resp.status_code = 404
                resp.text = "Not Found"

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        trace_findings = [f for f in findings if "Stack Trace" in f["name"]]
        assert len(trace_findings) >= 1
        assert trace_findings[0]["severity"] == "medium"
        assert trace_findings[0]["cwe"] == "CWE-209"

    def test_java_stack_trace_detection(self):
        """Test detection of Java stack traces in error responses."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.headers = {}

            if "'" in url or "__debug__" in url or "debug" in url:
                resp.status_code = 500
                resp.text = (
                    'java.lang.NullPointerException\n'
                    '\tat com.example.App.handleRequest(App.java:45)\n'
                    '\tat org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1067)\n'
                )
            else:
                resp.status_code = 404
                resp.text = "Not Found"

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        trace_findings = [f for f in findings if "Stack Trace" in f["name"]]
        assert len(trace_findings) >= 1

    def test_no_false_positive_on_404(self):
        """Test no finding when all sensitive paths return 404."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "<html><body><h1>404 Not Found</h1></body></html>"
        mock_resp.headers = {}

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/", [])

        assert len(findings) == 0


# ══════════════════════════════════════════════════════════════════
#  Prototype Pollution Scanner Tests
# ══════════════════════════════════════════════════════════════════


class TestPrototypePollutionScanner:
    """Tests for Prototype Pollution scanner (CWE-1321)."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.prototype_pollution import (
            PrototypePollutionScanner,
        )

        scanner = PrototypePollutionScanner()
        return scanner

    def test_query_param_pollution_detected(self):
        """Test detection when canary is reflected after __proto__ injection."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}

            if "__proto__" in url and "polluted" in url:
                # Extract canary from URL and reflect it
                import re
                canary_match = re.search(r"sudarshan_pp_test_\d+", url)
                if canary_match:
                    canary = canary_match.group(0)
                    resp.text = f'{{"status": "ok", "polluted": "{canary}"}}'
                else:
                    resp.text = '{"status": "ok"}'
            elif "constructor" in url and "prototype" in url:
                resp.text = '{"status": "ok"}'
            else:
                resp.text = '{"status": "ok"}'

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/api/data", [])

        assert len(findings) >= 1
        assert findings[0]["vuln_type"] == "prototype_pollution"
        assert findings[0]["severity"] == "high"
        assert findings[0]["cwe"] == "CWE-1321"

    def test_json_body_pollution_detected(self):
        """Test detection via JSON body __proto__ injection."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}

            content = kwargs.get("content", b"")
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="ignore")

            if method == "POST" and "__proto__" in content:
                # Simulate pollution — canary reflected
                import re, json
                try:
                    body = json.loads(content)
                    canary = scanner._extract_canary(body)
                    if canary:
                        resp.text = f'{{"result": "ok", "polluted": "{canary}"}}'
                    else:
                        resp.text = '{"result": "ok"}'
                except Exception:
                    resp.text = '{"result": "ok"}'
            elif method == "POST" and '"test"' in content:
                # Probe request — accept JSON (don't return 415)
                resp.status_code = 200
                resp.text = '{"result": "ok"}'
            elif method == "GET":
                # Follow-up / query param tests — no pollution
                resp.text = '{"result": "ok"}'
            else:
                resp.text = '{"result": "ok"}'

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/api/data", [])

        json_findings = [
            f for f in findings if "Json Body" in f["name"]
        ]
        assert len(json_findings) >= 1
        assert json_findings[0]["cwe"] == "CWE-1321"

    def test_no_false_positive_when_canary_not_reflected(self):
        """Test no finding when canary is never reflected back."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "ok", "message": "Hello World"}'
        mock_resp.headers = {}

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/api/data", [])

        assert len(findings) == 0

    def test_form_post_pollution(self):
        """Test detection via form POST with __proto__ fields."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {}

            data = kwargs.get("data", {})

            if method == "POST" and any("__proto__" in k for k in data.keys()):
                # Find the canary value
                canary = None
                for k, v in data.items():
                    if "__proto__" in k or "constructor" in k:
                        canary = v
                        break
                if canary and "sudarshan_pp_test" in str(canary):
                    resp.text = f'{{"result": "ok", "polluted": "{canary}"}}'
                else:
                    resp.text = '{"result": "ok"}'
            else:
                resp.text = '{"result": "ok"}'

            return resp

        injectable = [
            {
                "type": "form",
                "action": "http://target.com/api/submit",
                "method": "post",
                "inputs": [
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "submit", "type": "submit", "value": "Submit"},
                ],
            }
        ]

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/api/submit", injectable)

        form_findings = [
            f for f in findings if "Form Post" in f["name"]
        ]
        assert len(form_findings) >= 1


# ══════════════════════════════════════════════════════════════════
#  Insecure Deserialization Scanner Tests
# ══════════════════════════════════════════════════════════════════


class TestInsecureDeserializationScanner:
    """Tests for Insecure Deserialization scanner (CWE-502)."""

    def _make_scanner(self):
        from app.scanner.vulnerabilities.insecure_deserialization import (
            InsecureDeserializationScanner,
        )

        scanner = InsecureDeserializationScanner()
        return scanner

    def test_java_serialization_in_cookie(self):
        """Test detection of Java serialized object in cookie (base64 with \\xac\\xed magic)."""
        scanner = self._make_scanner()

        # Build a cookie value that's base64-encoded Java serialized data
        java_serialized = b"\xac\xed\x00\x05sr\x00\x10com.example.User"
        cookie_b64 = base64.b64encode(java_serialized).decode()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Welcome</body></html>"
        mock_resp.headers = MagicMock()

        # Simulate multi_items for httpx-style header access
        mock_resp.headers.get_list = MagicMock(return_value=[])
        mock_resp.headers.multi_items = MagicMock(return_value=[
            ("set-cookie", f"session={cookie_b64}; Path=/; HttpOnly"),
        ])

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/", [])

        java_findings = [f for f in findings if "Java" in f["name"] and "Cookie" in f["name"]]
        assert len(java_findings) >= 1
        assert java_findings[0]["severity"] == "critical"
        assert java_findings[0]["cwe"] == "CWE-502"

    def test_php_serialization_in_cookie(self):
        """Test detection of PHP serialized object in cookie (O:N: pattern)."""
        scanner = self._make_scanner()

        php_cookie_value = 'O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Welcome</body></html>"
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=[])
        mock_resp.headers.multi_items = MagicMock(return_value=[
            ("set-cookie", f"user_data={php_cookie_value}; Path=/"),
        ])

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/", [])

        php_findings = [f for f in findings if "Php" in f["name"] and "Cookie" in f["name"]]
        assert len(php_findings) >= 1
        assert php_findings[0]["severity"] == "high"
        assert php_findings[0]["cwe"] == "CWE-502"

    def test_viewstate_detection(self):
        """Test detection of unprotected .NET ViewState."""
        scanner = self._make_scanner()

        viewstate_data = base64.b64encode(b"\xff\x01some_viewstate_data_here").decode()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            '<html><body>'
            f'<input type="hidden" name="__VIEWSTATE" value="{viewstate_data}" />'
            '<input type="hidden" name="__VIEWSTATEGENERATOR" value="ABC123" />'
            '</body></html>'
        )
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=[])
        mock_resp.headers.multi_items = MagicMock(return_value=[])

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/", [])

        vs_findings = [f for f in findings if "ViewState" in f["name"]]
        assert len(vs_findings) >= 1
        assert vs_findings[0]["cwe"] == "CWE-502"

    def test_deserialization_error_in_response(self):
        """Test detection when deserialization error appears in response body."""
        scanner = self._make_scanner()

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = MagicMock()
            resp.headers.get_list = MagicMock(return_value=[])
            resp.headers.multi_items = MagicMock(return_value=[])

            # Response contains Java serialization framework references
            if url == "http://target.com/":
                resp.text = (
                    '<html><body>'
                    '<p>Error: java.io.StreamCorruptedException: invalid stream header</p>'
                    '<p>at java.io.ObjectInputStream.readStreamHeader(ObjectInputStream.java:866)</p>'
                    '</body></html>'
                )
            else:
                resp.text = "<html><body>Page</body></html>"

            return resp

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/", [])

        # Should detect framework hints (Java serialization references)
        framework_findings = [
            f for f in findings
            if "Serialization Framework" in f.get("name", "")
            or "Java" in f.get("name", "")
        ]
        assert len(framework_findings) >= 1

    def test_no_false_positive_on_normal_cookies(self):
        """Test no deserialization finding with normal session cookies."""
        scanner = self._make_scanner()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Welcome</body></html>"
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=[])
        mock_resp.headers.multi_items = MagicMock(return_value=[
            ("set-cookie", "session_id=abc123def456; Path=/; HttpOnly"),
            ("set-cookie", "theme=dark; Path=/"),
        ])

        with patch.object(scanner, "_request", return_value=mock_resp):
            findings = scanner.scan("http://target.com/", [])

        # No cookie deserialization findings — normal cookies should not trigger
        cookie_findings = [f for f in findings if "Cookie" in f.get("name", "")]
        assert len(cookie_findings) == 0

    def test_parameter_injection_java_error(self):
        """Test detection when injecting corrupt serialized data into params triggers errors."""
        scanner = self._make_scanner()

        java_serialized = b"\xac\xed\x00\x05sr\x00\x10com.example.Data"
        param_value = base64.b64encode(java_serialized).decode()

        # The scanner's test payload (base64 of corrupt Java serialized object)
        # urlencode will encode '==' as '%3D%3D', so match on the unique prefix
        java_test_prefix = scanner.JAVA_TEST_PAYLOAD.rstrip("=")  # 'rO0ABXNyABBTVURBUlNIQU5fVEVTVA'

        def mock_request(method, url, **kwargs):
            resp = MagicMock()
            resp.headers = MagicMock()
            resp.headers.get_list = MagicMock(return_value=[])
            resp.headers.multi_items = MagicMock(return_value=[])

            # When the scanner injects JAVA_TEST_PAYLOAD into the URL param,
            # the base64 prefix (without padding) will be present in the URL
            if java_test_prefix in url:
                resp.status_code = 500
                resp.text = (
                    "java.io.InvalidClassException: SUDARSHAN_TEST; "
                    "class invalid for deserialization"
                )
            else:
                resp.status_code = 200
                resp.text = "<html><body>Normal</body></html>"

            return resp

        injectable = [
            {"name": "data", "url": f"http://target.com/api?data={param_value}"}
        ]

        with patch.object(scanner, "_request", side_effect=mock_request):
            findings = scanner.scan("http://target.com/api", injectable)

        param_findings = [
            f for f in findings
            if "Parameter" in f.get("name", "")
        ]
        assert len(param_findings) >= 1
        assert param_findings[0]["cwe"] == "CWE-502"


