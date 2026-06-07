"""
Information Disclosure Scanner
OWASP: A01 - Broken Access Control | CWE-200

Detects sensitive information exposure via debug pages, exposed config files,
source code leaks, backup files, stack traces, and common sensitive endpoints.
"""

import re
import logging
from urllib.parse import urljoin
from app.scanner.vulnerabilities.base import BaseScanner

logger = logging.getLogger(__name__)


class InfoDisclosureScanner(BaseScanner):
    """Detects information disclosure vulnerabilities.

    Detection Techniques:
    1. Sensitive file/path exposure (.git, .env, phpinfo, etc.)
    2. Stack trace / debug page detection
    3. Backup file detection (.bak, .old, .swp)
    4. API documentation exposure (swagger, api-docs)
    5. Source code leak via debug mode
    6. Server status / monitoring endpoint exposure
    """

    # ── Sensitive paths to check ─────────────────────────────────────

    SENSITIVE_PATHS = [
        # Version control
        {"path": "/.git/HEAD", "indicators": [r"ref:\s*refs/"], "name": "Git Repository Exposed", "severity": "high", "cvss": 7.5},
        {"path": "/.git/config", "indicators": [r"\[core\]", r"\[remote"], "name": "Git Config Exposed", "severity": "high", "cvss": 7.5},
        {"path": "/.svn/entries", "indicators": [r"^\d+$", r"dir\n"], "name": "SVN Repository Exposed", "severity": "high", "cvss": 7.5},
        {"path": "/.hg/requires", "indicators": [r"revlogv\d", r"store"], "name": "Mercurial Repository Exposed", "severity": "high", "cvss": 7.5},

        # Environment / config files
        {"path": "/.env", "indicators": [r"(?:DB_|API_|SECRET|PASSWORD|KEY).*=", r"DATABASE_URL="], "name": ".env File Exposed", "severity": "critical", "cvss": 9.1},
        {"path": "/.env.backup", "indicators": [r"(?:DB_|API_|SECRET|PASSWORD|KEY).*="], "name": ".env Backup Exposed", "severity": "critical", "cvss": 9.1},
        {"path": "/config.yml", "indicators": [r"database:", r"secret_key:"], "name": "Config File Exposed", "severity": "high", "cvss": 7.5},
        {"path": "/config.json", "indicators": [r'"database"', r'"secret"', r'"password"'], "name": "Config JSON Exposed", "severity": "high", "cvss": 7.5},
        {"path": "/wp-config.php.bak", "indicators": [r"DB_NAME", r"DB_PASSWORD"], "name": "WordPress Config Backup", "severity": "critical", "cvss": 9.1},

        # Debug / info endpoints
        {"path": "/phpinfo.php", "indicators": [r"phpinfo\(\)", r"PHP Version", r"PHP Credits"], "name": "PHP Info Exposed", "severity": "medium", "cvss": 5.3},
        {"path": "/info.php", "indicators": [r"phpinfo\(\)", r"PHP Version"], "name": "PHP Info Page", "severity": "medium", "cvss": 5.3},
        {"path": "/server-status", "indicators": [r"Apache Server Status", r"Total Accesses"], "name": "Apache Server Status", "severity": "medium", "cvss": 5.3},
        {"path": "/server-info", "indicators": [r"Apache Server Information", r"Module Name"], "name": "Apache Server Info", "severity": "medium", "cvss": 5.3},
        {"path": "/nginx_status", "indicators": [r"Active connections:", r"server accepts"], "name": "Nginx Status Page", "severity": "medium", "cvss": 5.3},
        {"path": "/debug", "indicators": [r"Traceback", r"DEBUG", r"stack trace"], "name": "Debug Page Exposed", "severity": "high", "cvss": 7.5},
        {"path": "/trace", "indicators": [r"TRACE.*HTTP", r"Max-Forwards"], "name": "TRACE Method Enabled", "severity": "low", "cvss": 3.1},
        {"path": "/actuator", "indicators": [r'"_links"', r"actuator"], "name": "Spring Boot Actuator", "severity": "high", "cvss": 7.5},
        {"path": "/actuator/env", "indicators": [r'"propertySources"', r'"activeProfiles"'], "name": "Spring Actuator Env", "severity": "critical", "cvss": 9.1},
        {"path": "/actuator/health", "indicators": [r'"status"\s*:\s*"UP"'], "name": "Spring Actuator Health", "severity": "low", "cvss": 2.0},

        # API documentation
        {"path": "/swagger.json", "indicators": [r'"swagger"', r'"openapi"'], "name": "Swagger API Docs Exposed", "severity": "medium", "cvss": 5.3},
        {"path": "/swagger-ui.html", "indicators": [r"swagger-ui", r"Swagger UI"], "name": "Swagger UI Exposed", "severity": "medium", "cvss": 5.3},
        {"path": "/api-docs", "indicators": [r'"paths"', r'"info"'], "name": "API Documentation Exposed", "severity": "medium", "cvss": 5.3},
        {"path": "/openapi.json", "indicators": [r'"openapi"', r'"paths"'], "name": "OpenAPI Spec Exposed", "severity": "medium", "cvss": 5.3},
        {"path": "/graphql", "indicators": [r'"data"', r"__schema"], "name": "GraphQL Endpoint Found", "severity": "medium", "cvss": 5.3},

        # Backup files
        {"path": "/backup.sql", "indicators": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE"], "name": "SQL Backup Exposed", "severity": "critical", "cvss": 9.8},
        {"path": "/database.sql", "indicators": [r"CREATE TABLE", r"INSERT INTO"], "name": "Database Dump Exposed", "severity": "critical", "cvss": 9.8},
        {"path": "/dump.sql", "indicators": [r"CREATE TABLE", r"INSERT INTO"], "name": "SQL Dump Exposed", "severity": "critical", "cvss": 9.8},

        # Error / log files
        {"path": "/error.log", "indicators": [r"\[error\]", r"PHP (?:Fatal|Warning|Notice)", r"Traceback"], "name": "Error Log Exposed", "severity": "medium", "cvss": 5.3},
        {"path": "/debug.log", "indicators": [r"DEBUG", r"\[error\]", r"Exception"], "name": "Debug Log Exposed", "severity": "medium", "cvss": 5.3},

        # Admin panels
        {"path": "/elmah.axd", "indicators": [r"Error Log", r"ELMAH"], "name": "ELMAH Error Log", "severity": "high", "cvss": 7.5},
    ]

    # Stack trace patterns
    STACK_TRACE_PATTERNS = [
        r"Traceback \(most recent call last\)",
        r"at [\w.$]+\([\w.]+:\d+\)",  # Java stack trace
        r"File \"[^\"]+\", line \d+",  # Python stack trace
        r"Stack trace:.*\n.*at ",  # PHP stack trace
        r"Microsoft\.AspNetCore.*Exception",  # .NET
        r"<b>Fatal error</b>:.*on line <b>\d+</b>",  # PHP fatal
        r"Unhandled exception.*\n.*at [\w.]+",  # .NET unhandled
        r"Error:.*\n\s+at .*\(.*:\d+:\d+\)",  # Node.js
        r"panic:.*goroutine \d+",  # Go panic
    ]

    def __init__(self, session=None, timeout=8, delay=0.5):
        super().__init__(session, timeout, delay)
        self._compiled_traces = [
            re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.STACK_TRACE_PATTERNS
        ]

    def _check_stack_traces(self, response_text):
        """Check if response contains stack traces or debug information."""
        for pattern in self._compiled_traces:
            match = pattern.search(response_text)
            if match:
                return match.group(0)[:200]
        return None

    def _test_sensitive_paths(self, target_url):
        """Check for sensitive files and endpoints."""
        findings = []

        for path_info in self.SENSITIVE_PATHS:
            test_url = urljoin(target_url, path_info["path"])
            response = self._request("GET", test_url)

            if not response or response.status_code >= 400:
                continue

            # Check if ANY indicator pattern matches
            body = response.text
            matched_indicators = []
            for pattern in path_info["indicators"]:
                if re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                    matched_indicators.append(pattern)

            if not matched_indicators:
                continue

            # Build evidence snippet
            snippet = body[:300].strip()

            findings.append({
                "vuln_type": "info_disclosure",
                "name": path_info["name"],
                "description": (
                    f"Sensitive file or endpoint found at {path_info['path']}. "
                    "This exposes internal configuration, source code, or debug information "
                    "that can be used for further attacks."
                ),
                "impact": (
                    "Information disclosure can lead to:\n"
                    "• Credential theft from exposed config files\n"
                    "• Source code theft from exposed repositories\n"
                    "• Internal architecture mapping from debug pages\n"
                    "• Attack surface expansion via API documentation"
                ),
                "severity": path_info["severity"],
                "cvss_score": path_info["cvss"],
                "confidence": 90,
                "owasp_category": "A01",
                "cwe": "CWE-200",
                "affected_url": test_url,
                "parameter": path_info["path"],
                "payload": f"GET {path_info['path']}",
                "request_data": f"GET {test_url}",
                "response_data": f"Status: {response.status_code}\nSnippet: {snippet}",
                "remediation": (
                    "1. Remove or restrict access to sensitive files and endpoints\n"
                    "2. Add these paths to .gitignore and web server deny rules\n"
                    "3. Disable debug mode in production\n"
                    "4. Use proper access controls for admin/monitoring endpoints\n"
                    "5. Remove backup files from production servers"
                ),
            })

        return findings

    def _test_error_disclosure(self, target_url, injectable_points):
        """Test if the application leaks stack traces on errors."""
        findings = []

        # Test with deliberately malformed input to trigger errors
        error_triggers = [
            "/'\"\\;{}()<>[]",
            "/nonexistent_path_" + "x" * 50,
            "/%00%0a%0d",
            "/?__debug__=1",
            "/?debug=true",
        ]

        for trigger in error_triggers:
            test_url = target_url.rstrip("/") + trigger
            response = self._request("GET", test_url)

            if not response:
                continue

            trace = self._check_stack_traces(response.text)
            if trace:
                findings.append({
                    "vuln_type": "info_disclosure",
                    "name": "Stack Trace / Debug Information Leak",
                    "description": (
                        "The application exposes stack traces or debug information in error responses. "
                        "This reveals internal file paths, framework versions, and code structure."
                    ),
                    "impact": (
                        "Stack traces reveal:\n"
                        "• Internal file paths and directory structure\n"
                        "• Framework and library versions (enables targeted CVE exploitation)\n"
                        "• Database connection strings and configuration\n"
                        "• Code logic and variable names"
                    ),
                    "severity": "medium",
                    "cvss_score": 5.3,
                    "confidence": 85,
                    "owasp_category": "A01",
                    "cwe": "CWE-209",
                    "affected_url": test_url,
                    "parameter": "N/A",
                    "payload": trigger,
                    "request_data": f"GET {test_url}",
                    "response_data": f"Stack trace detected: {trace}",
                    "remediation": (
                        "1. Disable debug mode in production (DEBUG=False)\n"
                        "2. Implement custom error pages that don't expose internals\n"
                        "3. Log errors server-side, show generic messages to users\n"
                        "4. Use error monitoring services instead of verbose error display"
                    ),
                })
                break  # One finding is enough

        return findings

    # ── Main scan ────────────────────────────────────────────────────

    def scan(self, target_url, injectable_points):
        self.findings = []

        # 1. Check sensitive paths
        self.findings.extend(self._test_sensitive_paths(target_url))

        # 2. Check error/debug information disclosure
        self.findings.extend(self._test_error_disclosure(target_url, injectable_points))

        return self.findings
