"""Scanner Registry — single source of truth for all vulnerability scanner classes.

This module eliminates the need to duplicate the scanner_map in both
scan_manager.py and tasks.py. Import SCANNER_MAP from here whenever you
need to instantiate scanners by their config key.

Usage:
    from app.scanner.registry import SCANNER_MAP

    for name, (ScannerClass, display_name) in SCANNER_MAP.items():
        scanner = ScannerClass(session=session)
        findings = scanner.scan(url, injectable_points)
"""

from app.scanner.vulnerabilities.sql_injection import SQLInjectionScanner
from app.scanner.vulnerabilities.xss import XSSScanner
from app.scanner.vulnerabilities.csrf import CSRFScanner
from app.scanner.vulnerabilities.security_headers import SecurityHeadersScanner
from app.scanner.vulnerabilities.directory_traversal import DirectoryTraversalScanner
from app.scanner.vulnerabilities.command_injection import CommandInjectionScanner
from app.scanner.vulnerabilities.idor import IDORScanner, DirectoryListingScanner
from app.scanner.vulnerabilities.xxe import XXEScanner
from app.scanner.vulnerabilities.ssrf import SSRFScanner
from app.scanner.vulnerabilities.open_redirect import OpenRedirectScanner
from app.scanner.vulnerabilities.cors import CORSScanner
from app.scanner.vulnerabilities.clickjacking import ClickjackingScanner
from app.scanner.vulnerabilities.ssti import SSTIScanner
from app.scanner.vulnerabilities.jwt_attacks import JWTAttackScanner
from app.scanner.vulnerabilities.broken_auth import BrokenAuthScanner
from app.scanner.vulnerabilities.nosql_injection import NoSQLInjectionScanner
from app.scanner.vulnerabilities.file_upload import FileUploadScanner
from app.scanner.vulnerabilities.host_header import HostHeaderScanner
from app.scanner.vulnerabilities.info_disclosure import InfoDisclosureScanner
from app.scanner.vulnerabilities.prototype_pollution import PrototypePollutionScanner
from app.scanner.vulnerabilities.insecure_deserialization import (
    InsecureDeserializationScanner,
)

# Maps config key → (ScannerClass, display_name)
# Order follows Config.VULNERABILITY_CHECKS for consistency.
SCANNER_MAP = {
    "sql_injection": (SQLInjectionScanner, "SQL Injection"),
    "xss": (XSSScanner, "Cross-Site Scripting"),
    "csrf": (CSRFScanner, "CSRF"),
    "security_headers": (SecurityHeadersScanner, "Security Headers"),
    "directory_traversal": (DirectoryTraversalScanner, "Directory Traversal"),
    "command_injection": (CommandInjectionScanner, "Command Injection"),
    "idor": (IDORScanner, "IDOR"),
    "directory_listing": (DirectoryListingScanner, "Directory Listing"),
    "xxe": (XXEScanner, "XXE Injection"),
    "ssrf": (SSRFScanner, "SSRF"),
    "open_redirect": (OpenRedirectScanner, "Open Redirect"),
    "cors": (CORSScanner, "CORS Misconfiguration"),
    "clickjacking": (ClickjackingScanner, "Clickjacking"),
    "ssti": (SSTIScanner, "Server-Side Template Injection"),
    "jwt_attacks": (JWTAttackScanner, "JWT Vulnerabilities"),
    "broken_auth": (BrokenAuthScanner, "Broken Authentication"),
    "nosql_injection": (NoSQLInjectionScanner, "NoSQL Injection"),
    "file_upload": (FileUploadScanner, "File Upload"),
    "host_header": (HostHeaderScanner, "Host Header Attacks"),
    "info_disclosure": (InfoDisclosureScanner, "Information Disclosure"),
    "prototype_pollution": (PrototypePollutionScanner, "Prototype Pollution"),
    "insecure_deserialization": (
        InsecureDeserializationScanner,
        "Insecure Deserialization",
    ),
}
