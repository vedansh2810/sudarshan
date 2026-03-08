import re
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher
from app.scanner.vulnerabilities.base import BaseScanner

class IDORScanner(BaseScanner):
    """Insecure Direct Object Reference detection"""
    
    # Common error page / not-found indicators
    ERROR_INDICATORS = [
        'not found', '404', 'error', 'does not exist', 'no record',
        'access denied', 'forbidden', 'unauthorized', 'invalid',
        'no results', 'not available'
    ]
    
    def _find_id_params(self, url):
        """Find parameters that look like object IDs"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        id_params = []
        
        id_keywords = ['id', 'user_id', 'userid', 'account', 'uid', 'profile',
                       'record', 'doc', 'document', 'file', 'order', 'invoice',
                       'num', 'number', 'pid', 'ref']
        
        for param, values in params.items():
            for keyword in id_keywords:
                if keyword in param.lower():
                    try:
                        current_id = int(values[0])
                        id_params.append({
                            'param': param,
                            'value': current_id,
                            'url': url
                        })
                    except ValueError:
                        pass
        return id_params

    def _is_error_page(self, text):
        """Check if response looks like an error/not-found page."""
        if not text:
            return True
        text_lower = text.lower()
        error_count = sum(1 for ind in self.ERROR_INDICATORS if ind in text_lower)
        return error_count >= 2  # Multiple error indicators

    def scan(self, target_url, injectable_points):
        self.findings = []
        seen = set()

        all_urls = [p.get('url', target_url) for p in injectable_points if isinstance(p, dict)]
        all_urls.append(target_url)

        for url in set(all_urls):
            id_params = self._find_id_params(url)
            
            for id_info in id_params:
                param = id_info['param']
                current_id = id_info['value']
                
                # Test accessing adjacent IDs
                test_ids = [current_id - 1, current_id + 1, 1, 2, 999]
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                
                original_response = self._request('GET', url)
                if not original_response:
                    continue
                
                # Get a second baseline to measure page dynamism
                baseline2 = self._request('GET', url)
                if baseline2:
                    baseline_ratio = SequenceMatcher(
                        None, original_response.text, baseline2.text
                    ).ratio()
                else:
                    baseline_ratio = 1.0
                
                for test_id in test_ids:
                    if test_id == current_id or test_id <= 0:
                        continue
                    
                    test_params = dict(params)
                    test_params[param] = [str(test_id)]
                    query = '&'.join(f"{k}={v[0]}" for k, v in test_params.items())
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                    
                    response = self._request('GET', test_url)
                    
                    if not response or response.status_code != 200:
                        continue
                    if len(response.text) <= 100:
                        continue
                    
                    # Skip if response looks like an error page
                    if self._is_error_page(response.text):
                        continue
                    
                    # Use similarity ratio instead of exact text comparison
                    similarity = SequenceMatcher(
                        None, original_response.text, response.text
                    ).ratio()
                    
                    # Only report if significantly different from original
                    # AND the difference isn't just page dynamism
                    if similarity < 0.85 and similarity < baseline_ratio - 0.05:
                        key = f"{url}:{param}"
                        if key not in seen:
                            seen.add(key)
                            self.findings.append({
                                'vuln_type': 'idor',
                                'name': 'Insecure Direct Object Reference (IDOR)',
                                'description': f'Parameter "{param}" may allow access to resources belonging to other users by simply changing the ID value.',
                                'impact': 'Unauthorized access to other users\' data, privacy violations, data leakage.',
                                'severity': 'high',
                                'cvss_score': 8.1,
                                'owasp_category': 'A01',
                                'affected_url': test_url,
                                'parameter': param,
                                'payload': f'{param}={test_id} (changed from {current_id})',
                                'request_data': f'GET {test_url}',
                                'response_data': f'Different resource returned for ID {test_id} (similarity: {similarity:.2f}, status: {response.status_code})',
                                'remediation': 'Implement proper authorization checks. Use indirect references (GUIDs). Verify user owns the resource before returning data.'
                            })
                        break

        return self.findings


class DirectoryListingScanner(BaseScanner):
    """Directory listing vulnerability detection"""
    
    COMMON_DIRS = [
        '/backup/', '/admin/', '/config/', '/files/', '/uploads/',
        '/data/', '/logs/', '/tmp/', '/test/', '/dev/', '/api/',
        '/private/', '/secret/', '/docs/', '/old/', '/archive/'
    ]

    LISTING_INDICATORS = [
        r'index of /',
        r'directory listing',
        r'<title>index of',
        r'parent directory',
        r'\[to parent directory\]',
        r'directory: /',
    ]

    def _is_directory_listing(self, response_text):
        if not response_text:
            return False
        text_lower = response_text.lower()
        for pattern in self.LISTING_INDICATORS:
            if re.search(pattern, text_lower):
                return True
        return False

    def scan(self, target_url, injectable_points):
        self.findings = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for directory in self.COMMON_DIRS:
            test_url = base + directory
            response = self._request('GET', test_url)
            
            if response and response.status_code == 200:
                if self._is_directory_listing(response.text):
                    self.findings.append({
                        'vuln_type': 'directory_listing',
                        'name': 'Directory Listing Enabled',
                        'description': f'Directory listing is enabled at {directory}. Files and directories are exposed to unauthenticated users.',
                        'impact': 'Source code exposure, configuration file leakage, intellectual property theft, reconnaissance aid.',
                        'severity': 'medium',
                        'cvss_score': 5.3,
                        'owasp_category': 'A05',
                        'affected_url': test_url,
                        'parameter': 'N/A',
                        'payload': f'GET {directory}',
                        'request_data': f'GET {test_url}\nHTTP/1.1',
                        'response_data': 'Directory index page returned',
                        'remediation': 'Disable directory listing in web server config (Apache: Options -Indexes, Nginx: autoindex off). Add index.html to directories.'
                    })

        return self.findings
