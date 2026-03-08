import requests
import time
import urllib3

# Suppress InsecureRequestWarning for self-signed cert scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
            return None, time.time() - start if 'start' in dir() else self.timeout
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
