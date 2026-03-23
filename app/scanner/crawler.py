import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import re
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.models.database import db, CrawledUrlModel

logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, target_url, max_depth=3, max_urls=150, timeout=8,
                 delay=0.5, respect_robots=True, auth_config=None,
                 threads=5, session=None):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.delay = delay
        self.respect_robots = respect_robots
        self.auth_config = auth_config
        self.threads = max(1, threads)

        # Thread-safe shared state
        self._lock = threading.Lock()
        self.visited_urls = set()
        self.discovered_urls = []
        self.forms = []
        self.injectable_points = []
        self.stopped = False  # Stop-signal support

        # Session management — reuse an authenticated session if provided
        self.session = session or requests.Session()
        if not session:
            self.session.headers.update({
                'User-Agent': 'Sudarshan-Scanner/1.0 (Security Research)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            })
            self.session.verify = False

        self.disallowed_paths = []
        # Skip robots.txt when an authenticated session is provided
        # (we have explicit permission to scan)
        if respect_robots and not session:
            self._parse_robots()
        if auth_config and not session:
            self._authenticate()

    # ── URL Normalization ────────────────────────────────────────────

    @staticmethod
    def _normalize_url(url):
        """Normalize a URL for consistent deduplication.
        Strips fragments, trailing slashes on paths, empty query strings,
        and sorts query parameters."""
        parsed = urlparse(url)
        # Remove fragment
        path = parsed.path.rstrip('/') or '/'
        # Sort query parameters for consistent comparison
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_query = urlencode(
                {k: v[0] for k, v in sorted(params.items())},
                doseq=False
            )
        else:
            sorted_query = ''
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            path,
            '',  # params
            sorted_query,
            ''  # fragment
        ))

    # ── Robots.txt ───────────────────────────────────────────────────

    def _parse_robots(self):
        """Parse robots.txt for Disallow/Allow paths and Sitemap references."""
        self._robots_discovered_paths = []  # paths from Allow + Disallow for discovery
        self._sitemap_urls = []  # Sitemap URLs from robots.txt
        try:
            robots_url = f"{self.target_url}/robots.txt"
            r = self.session.get(robots_url, timeout=self.timeout)
            if r.status_code == 200:
                for line in r.text.split('\n'):
                    stripped = line.strip()
                    if stripped.lower().startswith('disallow:'):
                        path = stripped.split(':', 1)[1].strip()
                        if path:
                            self.disallowed_paths.append(path)
                            # Also record for discovery (hidden paths)
                            if path != '/' and not path.endswith('*'):
                                self._robots_discovered_paths.append(path)
                    elif stripped.lower().startswith('allow:'):
                        path = stripped.split(':', 1)[1].strip()
                        if path and path != '/' and not path.endswith('*'):
                            self._robots_discovered_paths.append(path)
                    elif stripped.lower().startswith('sitemap:'):
                        sitemap_url = stripped.split(':', 1)[1].strip()
                        # Handle "Sitemap: https://..." (the split removes the https:)
                        if not sitemap_url.startswith('http'):
                            sitemap_url = stripped.split(' ', 1)[1].strip() if ' ' in stripped else ''
                        if sitemap_url:
                            self._sitemap_urls.append(sitemap_url)
                logger.info(
                    f"Parsed robots.txt: {len(self.disallowed_paths)} disallowed, "
                    f"{len(self._robots_discovered_paths)} discovery paths, "
                    f"{len(self._sitemap_urls)} sitemap(s)"
                )
        except requests.exceptions.RequestException as e:
            logger.debug(f"Could not fetch robots.txt: {e}")
        except Exception as e:
            logger.warning(f"Error parsing robots.txt: {e}")

    # ── Sitemap.xml ──────────────────────────────────────────────────

    def _parse_sitemap(self):
        """Fetch and parse sitemap.xml for additional URLs.

        Checks /sitemap.xml by default plus any Sitemap URLs found
        in robots.txt.  Returns a list of discovered same-domain URLs.
        """
        urls = set()
        sitemap_locs = list(getattr(self, '_sitemap_urls', []))
        sitemap_locs.append(f"{self.target_url}/sitemap.xml")

        for sitemap_url in sitemap_locs:
            try:
                resp = self.session.get(sitemap_url, timeout=self.timeout, verify=False)
                if resp.status_code != 200:
                    continue
                # Extract <loc> tags (works for both sitemap index and url entries)
                for match in re.findall(r'<loc>\s*([^<]+?)\s*</loc>', resp.text, re.I):
                    normalized = self._normalize_url(match.strip())
                    if self._is_same_domain(normalized):
                        urls.add(normalized)
            except Exception as e:
                logger.debug(f"Could not parse sitemap {sitemap_url}: {e}")

        logger.info(f"Sitemap discovery: {len(urls)} URLs found")
        return list(urls)[:200]  # Cap to avoid huge sitemaps

    def _is_allowed(self, url):
        parsed = urlparse(url)
        for path in self.disallowed_paths:
            # Skip overly-broad rules like '/' that would block everything
            if path == '/':
                continue
            if parsed.path.startswith(path):
                return False
        return True

    # ── Authentication ───────────────────────────────────────────────

    def _authenticate(self):
        if not self.auth_config:
            return
        try:
            login_url = self.auth_config.get('login_url', '')
            username = self.auth_config.get('username', '')
            password = self.auth_config.get('password', '')
            username_field = self.auth_config.get('username_field', 'username')
            password_field = self.auth_config.get('password_field', 'password')
            if login_url:
                resp = self.session.post(login_url, data={
                    username_field: username,
                    password_field: password
                }, timeout=self.timeout)
                if resp.status_code == 200:
                    logger.info(f"Authenticated to {login_url}")
                else:
                    logger.warning(f"Authentication may have failed: status {resp.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {e}")

    # ── Domain / Content Checks ──────────────────────────────────────

    def _is_same_domain(self, url):
        return urlparse(url).netloc == self.base_domain

    def _is_html_content(self, url):
        """Send a HEAD request to check if URL serves HTML content.
        Returns True if HTML, False if binary/non-HTML, None if HEAD fails."""
        # Skip for common non-HTML extensions
        skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.zip', '.tar', '.gz', '.mp3', '.mp4', '.avi',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
        }
        parsed_path = urlparse(url).path.lower()
        for ext in skip_extensions:
            if parsed_path.endswith(ext):
                return False

        try:
            resp = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            content_type = resp.headers.get('content-type', '')
            # If no content-type or it's HTML, allow through
            if not content_type:
                return None  # Can't determine, will try GET
            return 'text/html' in content_type or 'application/xhtml' in content_type
        except Exception:
            return None  # Can't determine, will try GET

    # ── Link & Form Extraction ───────────────────────────────────────

    def _extract_links(self, html, base_url):
        links = set()
        try:
            try:
                soup = BeautifulSoup(html, 'lxml')
            except Exception:
                soup = BeautifulSoup(html, 'html.parser')

            # Standard href-bearing tags
            for tag in soup.find_all(['a', 'link'], href=True):
                href = tag['href']
                full_url = urljoin(base_url, href)
                # Skip logout/session-destroying URLs to preserve auth
                path_lower = urlparse(full_url).path.lower()
                if any(skip in path_lower for skip in ['logout', 'signout', 'sign_out', 'log_out']):
                    continue
                if self._is_same_domain(full_url):
                    links.add(self._normalize_url(full_url))

            # Resource tags
            for tag in soup.find_all(['script', 'img', 'iframe'], src=True):
                src = tag['src']
                full_url = urljoin(base_url, src)
                if self._is_same_domain(full_url):
                    links.add(self._normalize_url(full_url))

            # Extract URLs from inline JavaScript (window.location, href=, etc.)
            js_url_patterns = [
                r'(?:href|src|url|location)\s*[=:]\s*["\']([^"\']+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
                r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
                r'\.open\s*\(\s*["\']([^"\']+)["\']',
                r'["\'](/(?:api|auth|admin|user|account)[^"\' ]*)["\']',
            ]
            for script in soup.find_all('script'):
                js_text = script.string or ''
                # Also handle external JS files
                if not js_text and script.get('src'):
                    js_src = urljoin(base_url, script['src'])
                    if self._is_same_domain(js_src):
                        try:
                            js_resp = self.session.get(
                                js_src, timeout=self.timeout, verify=False
                            )
                            if js_resp.status_code == 200:
                                js_text = js_resp.text or ''
                        except Exception:
                            pass
                if js_text:
                    for pattern in js_url_patterns:
                        for js_url in re.findall(pattern, js_text, re.IGNORECASE):
                            # Skip data URIs, fragments, and template literals
                            if js_url.startswith(('data:', 'javascript:', '#', '${')):
                                continue
                            full_url = urljoin(base_url, js_url)
                            if self._is_same_domain(full_url):
                                links.add(self._normalize_url(full_url))

            # Extract URLs from HTML comments
            for comment in soup.find_all(string=lambda t: t and hasattr(t, 'extract') and str(type(t).__name__) == 'Comment'):
                comment_urls = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', str(comment))
                for curl in comment_urls:
                    full_url = urljoin(base_url, curl)
                    if self._is_same_domain(full_url):
                        links.add(self._normalize_url(full_url))

        except Exception as e:
            logger.debug(f"Error extracting links from {base_url}: {e}")
        return links

    def _extract_forms(self, html, base_url):
        forms = []
        try:
            try:
                soup = BeautifulSoup(html, 'lxml')
            except Exception:
                soup = BeautifulSoup(html, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                # Strip fragment from action (e.g., action="#" -> current page)
                if action == '#' or action == '':
                    form_url = base_url.split('#')[0].split('?')[0]
                else:
                    form_url = urljoin(base_url, action).split('#')[0]
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    inp_name = inp.get('name', '')
                    inp_type = inp.get('type', 'text')
                    inp_value = inp.get('value', '')
                    if inp_name:
                        inputs.append({
                            'name': inp_name,
                            'type': inp_type,
                            'value': inp_value
                        })
                if inputs:
                    forms.append({
                        'action': form_url,
                        'method': method,
                        'inputs': inputs
                    })
        except Exception as e:
            logger.debug(f"Error extracting forms from {base_url}: {e}")
        return forms

    def _extract_params(self, url):
        params = []
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    name, value = param.split('=', 1)
                    params.append({'name': name, 'value': value, 'url': url})
        return params

    # ── Retry Logic ──────────────────────────────────────────────────

    def _fetch_with_retry(self, url, max_retries=2):
        """Fetch a URL with exponential backoff retry for transient errors."""
        for attempt in range(max_retries + 1):
            try:
                time.sleep(self.delay)
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if response.status_code >= 500 and attempt < max_retries:
                    wait = (2 ** attempt) * 0.5
                    logger.debug(f"Server error {response.status_code} for {url}, retrying in {wait}s")
                    time.sleep(wait)
                    continue
                return response
            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    wait = (2 ** attempt) * 0.5
                    logger.debug(f"Timeout for {url}, retrying in {wait}s")
                    time.sleep(wait)
                else:
                    logger.warning(f"Timeout for {url} after {max_retries + 1} attempts")
                    return None
            except requests.exceptions.ConnectionError as e:
                if attempt < max_retries:
                    wait = (2 ** attempt) * 0.5
                    time.sleep(wait)
                else:
                    logger.warning(f"Connection error for {url}: {e}")
                    return None
            except Exception as e:
                logger.error(f"Unexpected error fetching {url}: {e}")
                return None
        return None

    # ── Single URL Processing ────────────────────────────────────────

    def _process_url(self, url, depth):
        """Process a single URL. Returns (new_links, url_info) or None."""
        if self.stopped:
            return None

        normalized = self._normalize_url(url)
        with self._lock:
            if normalized in self.visited_urls or len(self.discovered_urls) >= self.max_urls:
                return None
            self.visited_urls.add(normalized)

        if depth > self.max_depth:
            return None
        if not self._is_allowed(url):
            return None

        # Content-type pre-check for non-root URLs
        if depth > 0:
            is_html = self._is_html_content(url)
            if is_html is False:
                return None

        response = self._fetch_with_retry(url)
        if response is None:
            return None

        url_info = {
            'url': url,
            'status_code': response.status_code,
            'depth': depth
        }

        new_links = []

        if response.status_code == 200:
            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type:
                links = self._extract_links(response.text, url)
                forms = self._extract_forms(response.text, url)
                params = self._extract_params(url)

                url_info['forms'] = len(forms)
                url_info['params'] = len(params)

                with self._lock:
                    self.forms.extend(forms)
                    self.injectable_points.extend(params)
                    for form in forms:
                        self.injectable_points.append({
                            'type': 'form',
                            'action': form['action'],
                            'method': form['method'],
                            'inputs': form['inputs']
                        })

                for link in links:
                    with self._lock:
                        if link not in self.visited_urls:
                            new_links.append((link, depth + 1))

        with self._lock:
            self.discovered_urls.append(url_info)

        return new_links, url_info, response.status_code

    # ── Main Crawl Loop ──────────────────────────────────────────────

    def crawl(self, scan_id=None, callback=None):
        """Crawl the target URL using concurrent threads.
        
        Args:
            scan_id: Optional scan ID for persisting results to DB.
            callback: Optional function(url, count) called for each discovered URL.
        
        Returns:
            Tuple of (discovered_urls, injectable_points).
        """
        queue = [(self.target_url, 0)]

        # Seed queue with sitemap.xml URLs
        try:
            sitemap_urls = self._parse_sitemap()
            for surl in sitemap_urls:
                normalized = self._normalize_url(surl)
                if normalized not in self.visited_urls:
                    queue.append((surl, 1))
        except Exception as e:
            logger.debug(f"Sitemap seeding failed: {e}")

        # Seed queue with robots.txt discovered paths
        for rpath in getattr(self, '_robots_discovered_paths', []):
            try:
                rurl = self.target_url.rstrip('/') + rpath
                normalized = self._normalize_url(rurl)
                if normalized not in self.visited_urls:
                    queue.append((rurl, 1))
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while queue and not self.stopped:
                # Check URL limit
                with self._lock:
                    if len(self.discovered_urls) >= self.max_urls:
                        break

                # Submit a batch of URLs from the queue
                batch_size = min(len(queue), self.threads)
                batch = [queue.pop(0) for _ in range(batch_size)]

                futures = {}
                for url, depth in batch:
                    future = executor.submit(self._process_url, url, depth)
                    futures[future] = (url, depth)

                for future in as_completed(futures):
                    if self.stopped:
                        break

                    url, depth = futures[future]
                    try:
                        result = future.result()
                        if result is None:
                            continue

                        new_links, url_info, status_code = result

                        # Persist to DB
                        if scan_id:
                            try:
                                crawled = CrawledUrlModel(
                                    scan_id=scan_id,
                                    url=url,
                                    status_code=status_code,
                                    forms_found=url_info.get('forms', 0),
                                    params_found=url_info.get('params', 0)
                                )
                                db.session.add(crawled)
                                db.session.commit()
                            except Exception as e:
                                db.session.rollback()
                                logger.debug(f"DB insert error for crawled URL: {e}")

                        # Callback
                        if callback:
                            with self._lock:
                                count = len(self.discovered_urls)
                            callback(url, count)

                        # Add new links to queue
                        if new_links:
                            with self._lock:
                                remaining = self.max_urls - len(self.discovered_urls)
                            for link in new_links[:remaining]:
                                queue.append(link)

                    except Exception as e:
                        logger.error(f"Error processing future for {url}: {e}")

        # Deduplicate injectable points
        seen_points = set()
        unique_points = []
        for point in self.injectable_points:
            if point.get('type') == 'form':
                key = f"form:{point.get('url')}:{point.get('method')}:{','.join(i['name'] for i in point.get('inputs', []))}"
            else:
                key = f"param:{point.get('url')}:{point.get('name')}"
            if key not in seen_points:
                seen_points.add(key)
                unique_points.append(point)
        self.injectable_points = unique_points

        return self.discovered_urls, self.injectable_points
