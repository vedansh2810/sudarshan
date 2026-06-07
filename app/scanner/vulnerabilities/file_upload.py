import re
import logging
import time
from urllib.parse import urlparse, urljoin

from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class FileUploadScanner(BaseScanner):
    """Detects insecure file upload handling: dangerous extensions,
    MIME-type bypass, double-extension bypass, and null-byte bypass."""

    # ── Dangerous extensions & test content ───────────────────────────

    DANGEROUS_EXTENSIONS = [
        ".php", ".php5", ".phtml", ".jsp", ".aspx",
        ".py", ".rb", ".sh", ".html", ".svg",
    ]

    # Minimal file content per extension (benign but identifiable)
    TEST_CONTENT = {
        ".php":   b"<?php echo 'sudarshan_upload_test'; ?>",
        ".php5":  b"<?php echo 'sudarshan_upload_test'; ?>",
        ".phtml": b"<?php echo 'sudarshan_upload_test'; ?>",
        ".jsp":   b"<%= \"sudarshan_upload_test\" %>",
        ".aspx":  b"<%@ Page Language=\"C#\" %><%= \"sudarshan_upload_test\" %>",
        ".py":    b"print('sudarshan_upload_test')",
        ".rb":    b"puts 'sudarshan_upload_test'",
        ".sh":    b"#!/bin/sh\necho 'sudarshan_upload_test'",
        ".html":  b"<script>alert('sudarshan_upload_test')</script>",
        ".svg":   b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert("sudarshan_upload_test")</script></svg>',
    }

    # MIME types for bypass tests
    MIME_BY_EXT = {
        ".php": "application/x-php",
        ".jsp": "application/x-jsp",
        ".aspx": "application/x-aspx",
        ".py": "text/x-python",
        ".html": "text/html",
        ".svg": "image/svg+xml",
    }

    # Safe MIME types used during MIME-bypass testing
    SAFE_MIMES = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/pdf",
    ]

    # Success indicators in response body
    SUCCESS_INDICATORS = [
        r"upload(?:ed)?\s+success",
        r"file\s+(?:has\s+been\s+)?(?:uploaded|saved|stored|received)",
        r"successfully\s+uploaded",
        r"upload\s+complete",
        r"file\s+accepted",
        r'"(?:url|path|file_?name|location)"\s*:\s*"[^"]+\.\w{2,5}"',
        r"href\s*=\s*[\"'][^\"']*uploaded[^\"']*[\"']",
        r"src\s*=\s*[\"'][^\"']*uploads?[/\\]",
    ]

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _has_file_input(form):
        """Return True if the form has at least one <input type='file'>."""
        for inp in form.get("inputs", []):
            if inp.get("type", "").lower() == "file":
                return True
        return False

    @staticmethod
    def _file_input_names(form):
        """Return list of field names that accept files."""
        return [
            inp.get("name", "file")
            for inp in form.get("inputs", [])
            if inp.get("type", "").lower() == "file"
        ]

    def _build_multipart(self, form, file_field, filename, content, mime):
        """Build files dict and data dict for a multipart upload request."""
        files = {file_field: (filename, content, mime)}
        data = {}
        for inp in form.get("inputs", []):
            name = inp.get("name", "")
            if not name or inp.get("type", "").lower() == "file":
                continue
            if inp.get("type", "").lower() in ("submit", "button"):
                data[name] = inp.get("value", "Submit")
            else:
                data[name] = inp.get("value", "") or "test"
        return files, data

    def _upload(self, url, files, data):
        """Perform a multipart upload POST and return response."""
        try:
            return self._request("POST", url, files=files, data=data)
        except Exception as e:
            logger.debug(f"Upload request failed: {e}")
            return None

    def _is_upload_accepted(self, response):
        """Check if the server accepted the upload."""
        if response is None:
            return False
        if response.status_code >= 400:
            return False
        text = response.text or ""
        for pattern in self.SUCCESS_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        # 200/201 with a reasonable-length body that doesn't look like
        # a plain error page is also treated as possible acceptance.
        if response.status_code in (200, 201) and len(text) > 0:
            # Avoid counting generic "not found" or "forbidden" pages
            if not re.search(r"(?:not\s+found|forbidden|error|denied)", text, re.IGNORECASE):
                return True
        return False

    def _extract_upload_url(self, response):
        """Try to extract the URL of the uploaded file from the response."""
        if response is None:
            return None
        text = response.text or ""
        # JSON path / url field
        m = re.search(r'"(?:url|path|file_?name|location)"\s*:\s*"([^"]+)"', text, re.IGNORECASE)
        if m:
            return m.group(1)
        # href to uploads dir
        m = re.search(r'(?:href|src)\s*=\s*["\']([^"\']*uploads?[/\\][^"\']+)["\']', text, re.IGNORECASE)
        if m:
            return m.group(1)
        return None

    # ── Test strategies ───────────────────────────────────────────────

    def _test_dangerous_extension(self, form, url, file_field, ext):
        """Test uploading a file with a dangerous extension directly."""
        filename = f"sudarshan_test{ext}"
        content = self.TEST_CONTENT.get(ext, b"sudarshan_upload_test")
        mime = self.MIME_BY_EXT.get(ext, "application/octet-stream")
        files, data = self._build_multipart(form, file_field, filename, content, mime)
        resp = self._upload(url, files, data)
        if self._is_upload_accepted(resp):
            return {
                "technique": "dangerous_extension",
                "extension": ext,
                "filename": filename,
                "upload_url": self._extract_upload_url(resp),
                "status_code": resp.status_code,
            }
        return None

    def _test_mime_bypass(self, form, url, file_field, ext):
        """Send a dangerous extension with a safe (image) MIME type."""
        filename = f"sudarshan_test{ext}"
        content = self.TEST_CONTENT.get(ext, b"sudarshan_upload_test")
        for safe_mime in self.SAFE_MIMES[:2]:
            files, data = self._build_multipart(form, file_field, filename, content, safe_mime)
            resp = self._upload(url, files, data)
            if self._is_upload_accepted(resp):
                return {
                    "technique": "mime_type_bypass",
                    "extension": ext,
                    "filename": filename,
                    "spoofed_mime": safe_mime,
                    "upload_url": self._extract_upload_url(resp),
                    "status_code": resp.status_code,
                }
        return None

    def _test_double_extension(self, form, url, file_field, ext):
        """Test double-extension tricks: file.php.jpg and file.jpg.php."""
        content = self.TEST_CONTENT.get(ext, b"sudarshan_upload_test")
        variants = [
            (f"sudarshan_test{ext}.jpg", "image/jpeg"),      # file.php.jpg
            (f"sudarshan_test.jpg{ext}", "application/octet-stream"),  # file.jpg.php
        ]
        for filename, mime in variants:
            files, data = self._build_multipart(form, file_field, filename, content, mime)
            resp = self._upload(url, files, data)
            if self._is_upload_accepted(resp):
                return {
                    "technique": "double_extension",
                    "extension": ext,
                    "filename": filename,
                    "upload_url": self._extract_upload_url(resp),
                    "status_code": resp.status_code,
                }
        return None

    def _test_null_byte(self, form, url, file_field, ext):
        """Test null-byte bypass: file.php%00.jpg."""
        filename = f"sudarshan_test{ext}%00.jpg"
        content = self.TEST_CONTENT.get(ext, b"sudarshan_upload_test")
        files, data = self._build_multipart(
            form, file_field, filename, content, "image/jpeg",
        )
        resp = self._upload(url, files, data)
        if self._is_upload_accepted(resp):
            return {
                "technique": "null_byte_bypass",
                "extension": ext,
                "filename": filename,
                "upload_url": self._extract_upload_url(resp),
                "status_code": resp.status_code,
            }
        return None

    # ── Finding builder ───────────────────────────────────────────────

    def _make_finding(self, result, form_url, file_field):
        technique = result["technique"]
        ext = result["extension"]

        # Null-byte and double-extension with executable first are critical
        severity = "critical" if technique in ("null_byte_bypass",) else "high"
        if technique == "double_extension" and result["filename"].endswith(ext):
            severity = "critical"

        description = (
            f"The file upload endpoint accepts files with the dangerous "
            f"extension '{ext}' via {technique.replace('_', ' ')}. "
            f"Test filename: {result['filename']}."
        )
        if result.get("upload_url"):
            description += f" Uploaded file path: {result['upload_url']}."

        return {
            "vuln_type": "file_upload",
            "name": f"Insecure File Upload — {technique.replace('_', ' ').title()}",
            "description": description,
            "impact": (
                "Remote code execution via uploaded web shell, "
                "stored XSS via HTML/SVG files, server compromise."
            ),
            "severity": severity,
            "cvss_score": 9.8 if severity == "critical" else 8.8,
            "owasp_category": "A04",
            "cwe": "CWE-434",
            "affected_url": form_url,
            "parameter": file_field,
            "payload": result["filename"],
            "request_data": (
                f"POST {form_url}\n"
                f"Content-Type: multipart/form-data\n"
                f"File field: {file_field}\n"
                f"Filename: {result['filename']}"
            ),
            "response_data": (
                f"Upload accepted (HTTP {result.get('status_code', '?')}). "
                f"Technique: {technique}."
            ),
            "remediation": (
                "Validate file extensions against an allowlist of safe types. "
                "Verify MIME type AND file content (magic bytes). "
                "Rename uploaded files with random names. "
                "Store uploads outside the web root. "
                "Disable script execution in upload directories."
            ),
        }

    # ── Main scan ─────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        for point in injectable_points:
            if not isinstance(point, dict):
                continue
            if point.get("type") != "form":
                continue
            if not self._has_file_input(point):
                continue

            form_url = point.get("action", target_url)
            if not form_url.startswith("http"):
                form_url = urljoin(target_url, form_url)

            file_fields = self._file_input_names(point)

            for file_field in file_fields:
                # Test a focused subset of extensions to avoid excessive requests
                priority_exts = [".php", ".jsp", ".aspx", ".html", ".svg"]
                secondary_exts = [e for e in self.DANGEROUS_EXTENSIONS if e not in priority_exts]

                for ext in priority_exts + secondary_exts:
                    dedup_key = f"{form_url}:{file_field}:{ext}"
                    if dedup_key in seen:
                        continue

                    # 1. Direct dangerous extension
                    result = self._test_dangerous_extension(point, form_url, file_field, ext)
                    if result:
                        seen.add(dedup_key)
                        self.findings.append(self._make_finding(result, form_url, file_field))
                        continue  # Skip bypass tests — direct upload works

                    # 2. MIME-type bypass
                    result = self._test_mime_bypass(point, form_url, file_field, ext)
                    if result:
                        seen.add(dedup_key)
                        self.findings.append(self._make_finding(result, form_url, file_field))
                        continue

                    # 3. Double extension
                    result = self._test_double_extension(point, form_url, file_field, ext)
                    if result:
                        seen.add(dedup_key)
                        self.findings.append(self._make_finding(result, form_url, file_field))
                        continue

                    # 4. Null byte bypass
                    result = self._test_null_byte(point, form_url, file_field, ext)
                    if result:
                        seen.add(dedup_key)
                        self.findings.append(self._make_finding(result, form_url, file_field))

        return self.findings
