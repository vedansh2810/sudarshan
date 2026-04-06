"""Scan Manager — dual-mode: Celery (if Redis available) or in-process threading.

Responsibilities:
- start/pause/resume/stop scans
- SSE event streaming (Redis pub/sub or in-memory fallback)
- Scan status queries
"""
import threading
import queue
import time
import json
import logging
import requests as requests_lib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from flask import current_app

from app.config import Config
from app.scanner.crawler import Crawler
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
from app.scanner.dvwa_auth import DVWAAuth
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

from app.monitoring.metrics import track_scan_started, track_scan_completed, track_vulnerability
from app.ai.analyzer import analyze_vulnerability as ai_analyze

logger = logging.getLogger(__name__)


class ScanManager:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.active_scans = {}  # scan_id -> scan context (threading-only fallback when NO Redis)
        self.sse_queues = {}    # scan_id -> list of queues (threading-only fallback when NO Redis)
        self.event_history = defaultdict(list)  # in-memory fallback only when Redis unavailable
        self._redis = None
        self._redis_checked = False
        self._use_celery = False

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = ScanManager()
        return cls._instance

    def _get_redis(self):
        """Lazy-init Redis connection. Returns None if unavailable."""
        if self._redis_checked:
            return self._redis
        self._redis_checked = True
        try:
            # Use Flask app config if available, otherwise fall back to Config
            try:
                redis_url = current_app.config.get('REDIS_URL', '')
            except RuntimeError:
                redis_url = Config.REDIS_URL
            if not redis_url:
                logger.info("REDIS_URL not configured — using threading mode")
                self._redis = None
                self._use_celery = False
                return self._redis
            import redis as redis_lib
            r = redis_lib.from_url(redis_url, socket_connect_timeout=2)
            r.ping()
            self._redis = r
            self._use_celery = True
            logger.info("Redis connected — using Celery for scans")
        except Exception as e:
            logger.info(f"Redis unavailable ({e}) — falling back to threading mode")
            self._redis = None
            self._use_celery = False
        return self._redis

    def _get_speed_config(self, speed):
        return Config.SCAN_SPEEDS.get(speed, Config.SCAN_SPEEDS['balanced'])

    # ─── Start / Pause / Resume / Stop ──────────────────────────────────

    def start_scan(self, scan_id, target_url, scan_mode, scan_speed,
                   crawl_depth, selected_checks=None, dvwa_security='low'):
        if scan_id in self.active_scans:
            return False

        redis = self._get_redis()

        if self._use_celery and redis:
            # ── Celery mode: dispatch to worker ──
            from app.tasks import run_scan_task
            run_scan_task.delay(
                scan_id=scan_id,
                target_url=target_url,
                scan_mode=scan_mode,
                scan_speed=scan_speed,
                crawl_depth=crawl_depth,
                selected_checks=selected_checks or Config.VULNERABILITY_CHECKS,
                dvwa_security=dvwa_security
            )
            # Track state in Redis hash — no in-memory dict needed for Celery scans
            try:
                redis.hset(f'scan:{scan_id}:state', mapping={
                    'status': 'running',
                    'mode': 'celery',
                    'start_time': str(time.time()),
                    'tested_urls': '0',
                    'total_urls': '0',
                    'findings': '0',
                })
                redis.expire(f'scan:{scan_id}:state', 86400)  # 24h TTL
            except Exception as e:
                logger.warning(f"Failed to store scan state in Redis: {e}")
            return True
        else:
            # ── Threading fallback ──
            ctx = {
                'scan_id': scan_id,
                'target_url': target_url,
                'scan_mode': scan_mode,
                'scan_speed': scan_speed,
                'crawl_depth': crawl_depth,
                'selected_checks': selected_checks or Config.VULNERABILITY_CHECKS,
                'status': 'running',
                'paused': False,
                'stopped': False,
                'pause_event': threading.Event(),
                'start_time': time.time(),
                'findings': [],
                'tested_urls': 0,
                'total_urls': 0,
                'dvwa_security': dvwa_security,
                'mode': 'threading',
            }
            ctx['pause_event'].set()
            self.active_scans[scan_id] = ctx
            self.sse_queues[scan_id] = []

            # Capture the Flask app for use in the background thread
            app = current_app._get_current_object()
            ctx['_app'] = app

            thread = threading.Thread(
                target=self._run_scan,
                args=(ctx,),
                daemon=True
            )
            thread.start()
            return True

    def pause_scan(self, scan_id):
        redis = self._get_redis()
        if redis:
            # Redis-backed control for both Celery and threading modes
            redis.set(f'scan:{scan_id}:control', 'paused')
            Scan.update_status(scan_id, 'paused')
            # Also update in-memory ctx if threading mode with Redis
            ctx = self.active_scans.get(scan_id)
            if ctx and ctx.get('mode') == 'threading':
                ctx['paused'] = True
                ctx['pause_event'].clear()
                ctx['status'] = 'paused'
                self._emit(scan_id, 'log', '[~] Scan paused by user', 'warning')
            return True
        # Pure in-memory fallback (no Redis at all)
        ctx = self.active_scans.get(scan_id)
        if ctx and ctx['status'] == 'running':
            ctx['paused'] = True
            ctx['pause_event'].clear()
            ctx['status'] = 'paused'
            Scan.update_status(scan_id, 'paused')
            self._emit(scan_id, 'log', '[~] Scan paused by user', 'warning')
            return True
        return False

    def resume_scan(self, scan_id):
        redis = self._get_redis()
        if redis:
            redis.delete(f'scan:{scan_id}:control')
            Scan.update_status(scan_id, 'running')
            ctx = self.active_scans.get(scan_id)
            if ctx and ctx.get('mode') == 'threading':
                ctx['paused'] = False
                ctx['pause_event'].set()
                ctx['status'] = 'running'
                self._emit(scan_id, 'log', '[+] Scan resumed', 'info')
            return True
        ctx = self.active_scans.get(scan_id)
        if ctx and ctx['status'] == 'paused':
            ctx['paused'] = False
            ctx['pause_event'].set()
            ctx['status'] = 'running'
            Scan.update_status(scan_id, 'running')
            self._emit(scan_id, 'log', '[+] Scan resumed', 'info')
            return True
        return False

    def stop_scan(self, scan_id):
        redis = self._get_redis()
        if redis:
            redis.set(f'scan:{scan_id}:control', 'stopped')
            Scan.update_status(scan_id, 'stopped')
            # Revoke Celery task if applicable
            task_id = redis.get(f'scan:{scan_id}:task_id')
            if task_id:
                try:
                    from app.celery_app import celery
                    celery.control.revoke(task_id.decode(), terminate=True)
                except Exception as e:
                    logger.warning(f"Failed to revoke task: {e}")
            # Also stop in-memory threading context if present
            ctx = self.active_scans.get(scan_id)
            if ctx and ctx.get('mode') == 'threading':
                ctx['stopped'] = True
                ctx['status'] = 'stopped'
                ctx['pause_event'].set()
                crawler = ctx.get('_crawler')
                if crawler:
                    crawler.stopped = True
                self._emit(scan_id, 'log', '[X] Scan stopped by user', 'error')
            # Clean up Redis state
            try:
                redis.delete(f'scan:{scan_id}:state')
            except Exception:
                pass
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            return True
        # Pure in-memory fallback
        ctx = self.active_scans.get(scan_id)
        if ctx:
            ctx['stopped'] = True
            ctx['status'] = 'stopped'
            ctx['pause_event'].set()
            crawler = ctx.get('_crawler')
            if crawler:
                crawler.stopped = True
            Scan.update_status(scan_id, 'stopped')
            self._emit(scan_id, 'log', '[X] Scan stopped by user', 'error')
            return True
        return False

    # ─── Status ──────────────────────────────────────────────────────────

    def get_status(self, scan_id):
        """Get scan status. Priority: Redis hash > in-memory ctx > DB."""
        redis = self._get_redis()
        if redis:
            try:
                state = redis.hgetall(f'scan:{scan_id}:state')
                if state:
                    return {
                        'status': state.get(b'status', b'unknown').decode(),
                        'tested_urls': int(state.get(b'tested_urls', b'0')),
                        'total_urls': int(state.get(b'total_urls', b'0')),
                        'findings': int(state.get(b'findings', b'0')),
                        'elapsed': int(time.time() - float(state.get(b'start_time', b'0')))
                    }
            except Exception as e:
                logger.debug(f"Redis get_status failed: {e}")

        # In-memory fallback for threading mode (when no Redis)
        ctx = self.active_scans.get(scan_id)
        if ctx and ctx.get('mode') == 'threading':
            return {
                'status': ctx['status'],
                'tested_urls': ctx['tested_urls'],
                'total_urls': ctx['total_urls'],
                'findings': len(ctx['findings']),
                'elapsed': int(time.time() - ctx['start_time'])
            }
        # DB fallback (always works)
        scan = Scan.get_by_id(scan_id)
        if scan:
            return {
                'status': scan['status'],
                'tested_urls': scan['tested_urls'],
                'total_urls': scan['total_urls'],
                'findings': scan['vuln_count'],
                'elapsed': scan['duration']
            }
        return None

    # ─── SSE Streaming ──────────────────────────────────────────────────

    def register_sse_client(self, scan_id):
        """Register an SSE client. Returns queue (threading) or None (Redis)."""
        redis = self._get_redis()
        if redis:
            return None  # Redis mode uses pub/sub in stream route
        q = queue.Queue()
        if scan_id not in self.sse_queues:
            self.sse_queues[scan_id] = []
        self.sse_queues[scan_id].append(q)
        return q

    def unregister_sse_client(self, scan_id, q):
        if q is None:
            return  # Redis mode
        if scan_id in self.sse_queues:
            try:
                self.sse_queues[scan_id].remove(q)
            except ValueError:
                pass

    def is_redis_mode(self):
        """Check if we're using Redis for SSE."""
        return self._use_celery and self._get_redis() is not None

    def get_event_history(self, scan_id):
        """Get all previously emitted events for a scan.
        Uses Redis when available, falls back to in-memory."""
        redis = self._get_redis()
        if redis:
            try:
                events = redis.lrange(f'scan:{scan_id}:event_history', 0, -1)
                if events:
                    return [e.decode() for e in events]
            except Exception as e:
                logger.debug(f"Redis event history read failed: {e}")
        return list(self.event_history.get(scan_id, []))

    def get_redis_client(self):
        """Get the Redis client for pub/sub subscriptions."""
        return self._get_redis()

    # ─── Internal: event emission ────────────────────────────────────────

    def _emit(self, scan_id, event_type, data, log_level='info'):
        """Emit event — always stores in Redis when available, plus in-memory fallback."""
        msg = {
            'type': event_type,
            'data': data,
            'level': log_level,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        serialized = f"data: {json.dumps(msg)}\n\n"

        redis = self._get_redis()
        if redis:
            try:
                # Publish to live subscribers
                redis.publish(f'scan:{scan_id}:events', json.dumps(msg))
                # Store in Redis list for event replay (1h TTL)
                redis.rpush(f'scan:{scan_id}:event_history', serialized)
                redis.expire(f'scan:{scan_id}:event_history', 3600)
            except Exception as e:
                logger.warning(f"Redis event emit failed: {e}")
        else:
            # Pure in-memory queue fallback (no Redis at all)
            self.event_history[scan_id].append(serialized)
            if scan_id in self.sse_queues:
                dead_queues = []
                for q in self.sse_queues[scan_id]:
                    try:
                        q.put_nowait(serialized)
                    except queue.Full:
                        dead_queues.append(q)
                for q in dead_queues:
                    try:
                        self.sse_queues[scan_id].remove(q)
                    except:
                        pass

        # Also push to in-memory queues even in Redis mode (for threading+Redis hybrid)
        if redis and scan_id in self.sse_queues:
            for q in self.sse_queues.get(scan_id, []):
                try:
                    q.put_nowait(serialized)
                except queue.Full:
                    pass

        # Persist log events to DB
        if event_type == 'log':
            Scan.add_log(scan_id, data, log_level)

    def _calculate_score(self, findings):
        if not findings:
            return 'A'
        critical = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        medium = sum(1 for f in findings if f.get('severity') == 'medium')

        score_num = 100
        score_num -= critical * 20
        score_num -= high * 10
        score_num -= medium * 5
        score_num = max(0, score_num)

        if score_num >= 90: return 'A'
        elif score_num >= 80: return 'B'
        elif score_num >= 70: return 'C'
        elif score_num >= 60: return 'D'
        else: return 'F'

    # ─── Threading fallback: _run_scan (unchanged from original) ─────────

    def _run_scan(self, ctx):
        app = ctx.get('_app')
        if app:
            with app.app_context():
                self._run_scan_inner(ctx)
        else:
            self._run_scan_inner(ctx)

    def _run_scan_inner(self, ctx):
        scan_id = ctx['scan_id']
        seen_vulns = set()  # (vuln_type, affected_url, parameter) dedup
        target_url = ctx['target_url']
        speed_config = self._get_speed_config(ctx['scan_speed'])

        try:
            Scan.update_status(scan_id, 'running')
            track_scan_started()
            self._emit(scan_id, 'log', f'[+] Starting scan: {target_url}', 'info')
            self._emit(scan_id, 'log', f'[+] Mode: {ctx["scan_mode"]} | Speed: {ctx["scan_speed"]}', 'info')

            # Phase 0: Connectivity pre-check
            self._emit(scan_id, 'log', '[+] Checking target connectivity...', 'info')
            target_reachable = False
            try:
                precheck_resp = requests_lib.get(
                    target_url, timeout=speed_config['timeout'],
                    verify=False, allow_redirects=True,
                    headers={'User-Agent': 'Sudarshan-Scanner/1.0 (Security Research)'}
                )
                target_reachable = True
                self._emit(scan_id, 'log',
                    f'[+] Target reachable: HTTP {precheck_resp.status_code} ({len(precheck_resp.text)} bytes)',
                    'success')
            except requests_lib.exceptions.Timeout:
                self._emit(scan_id, 'log',
                    f'[!] Target unreachable: Connection timed out after {speed_config["timeout"]}s',
                    'error')
            except requests_lib.exceptions.ConnectionError as ce:
                self._emit(scan_id, 'log',
                    f'[!] Target unreachable: Connection failed — {str(ce)[:120]}',
                    'error')
            except Exception as pe:
                self._emit(scan_id, 'log',
                    f'[!] Target unreachable: {str(pe)[:120]}',
                    'error')

            if not target_reachable:
                self._emit(scan_id, 'log',
                    '[!] Cannot reach target. Scan will continue with limited checks.',
                    'warning')

            # Phase 1: Crawling
            self._emit(scan_id, 'log', '[+] Phase 1: Crawling target...', 'info')

            _crawl_counter = [0]  # mutable counter for closure

            def crawl_callback(url, count):
                if ctx['stopped']:
                    return
                ctx['pause_event'].wait()
                ctx['total_urls'] = count
                _crawl_counter[0] += 1
                # Throttle DB writes: update every 5th URL instead of every URL
                if _crawl_counter[0] % 5 == 0 or count <= 5:
                    Scan.update_progress(scan_id, ctx['tested_urls'], len(ctx['findings']))
                    Scan.update_total_urls(scan_id, count)
                self._emit(scan_id, 'log', f'[+] Crawling: {url[:70]}', 'info')
                self._emit(scan_id, 'progress', {
                    'phase': 'crawling',
                    'total': count,
                    'tested': ctx['tested_urls'],
                    'findings': len(ctx['findings'])
                }, 'info')

            # Auto-detect DVWA
            authenticated_session = None
            if DVWAAuth.is_dvwa_target(target_url):
                self._emit(scan_id, 'log', '[+] DVWA detected — authenticating...', 'info')
                authenticated_session = DVWAAuth.login(target_url.rstrip('/'))
                if authenticated_session:
                    dvwa_level = ctx.get('dvwa_security', 'low')
                    DVWAAuth.set_security_level(authenticated_session, target_url.rstrip('/'), dvwa_level)
                    self._emit(scan_id, 'log', f'[+] DVWA authenticated (security: {dvwa_level.upper()})', 'success')
                else:
                    self._emit(scan_id, 'log', '[-] DVWA authentication failed — scanning without auth', 'warning')

            if target_reachable:
                crawler = Crawler(
                    target_url=target_url,
                    max_depth=ctx['crawl_depth'],
                    max_urls=speed_config['max_urls'],
                    timeout=speed_config['timeout'],
                    delay=speed_config['delay'],
                    threads=speed_config.get('threads', 5),
                    session=authenticated_session
                )
                ctx['_crawler'] = crawler

                discovered_urls, injectable_points = crawler.crawl(scan_id=scan_id, callback=crawl_callback)
            else:
                # Target unreachable — skip crawling to avoid wasting time on timeouts
                discovered_urls = []
                injectable_points = []

            ctx['total_urls'] = len(discovered_urls)

            if ctx['stopped']:
                self._finalize(ctx, discovered_urls)
                return

            self._emit(scan_id, 'log',
                f'[+] Crawl complete: {len(discovered_urls)} URLs, {len(injectable_points)} injectable points',
                'success')

            # When crawler finds 0 URLs, create a fallback injectable point
            # from the target URL so scanners still have something to test
            if len(injectable_points) == 0 and target_reachable:
                self._emit(scan_id, 'log',
                    '[*] Creating fallback test points from target URL...',
                    'info')
                # Add the target URL itself as an injectable point
                parsed = urlparse(target_url)
                # Add any query parameters from the target URL
                if parsed.query:
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    for param_name, param_values in params.items():
                        injectable_points.append({
                            'name': param_name,
                            'value': param_values[0] if param_values else '',
                            'url': target_url
                        })
                # Always add the target URL as a base injectable point
                injectable_points.append({
                    'type': 'url',
                    'url': target_url,
                    'name': '',
                    'value': ''
                })
                # Add common injectable endpoints
                common_paths = [
                    '/search?q=test', '/login', '/?id=1', '/?page=1',
                    '/index.php?id=1', '/product?id=1'
                ]
                base = target_url.rstrip('/')
                for path in common_paths:
                    full_url = base + path
                    p = urlparse(full_url)
                    if p.query:
                        qp = parse_qs(p.query, keep_blank_values=True)
                        for pn, pv in qp.items():
                            injectable_points.append({
                                'name': pn,
                                'value': pv[0] if pv else '',
                                'url': full_url
                            })
                discovered_urls.append({'url': target_url, 'status_code': 200, 'depth': 0})
                ctx['total_urls'] = len(discovered_urls)
                self._emit(scan_id, 'log',
                    f'[+] Created {len(injectable_points)} fallback test points',
                    'info')
            elif len(discovered_urls) == 0 and not target_reachable:
                self._emit(scan_id, 'log',
                    '[!] Warning: Target is unreachable. No URLs to scan.',
                    'warning')

            # Phase 1.5: AI Reconnaissance (non-blocking)
            target_context = {}
            try:
                from app.ai.smart_engine import get_smart_engine
                smart_engine = get_smart_engine()
                self._emit(scan_id, 'log', '[*] AI Reconnaissance: Analyzing target technology stack...', 'info')
                import requests as _req
                recon_resp = _req.get(target_url, timeout=10, verify=False)
                recon_result = smart_engine.reconnaissance(target_url, recon_resp)
                if recon_result:
                    target_context = recon_result
                    ctx['target_context'] = recon_result
                    tech_info = []
                    if recon_result.get('language'):
                        tech_info.append(f"Language: {recon_result['language']}")
                    if recon_result.get('framework'):
                        tech_info.append(f"Framework: {recon_result['framework']}")
                    if recon_result.get('server'):
                        tech_info.append(f"Server: {recon_result['server']}")
                    if recon_result.get('waf_detected'):
                        waf_name = recon_result.get('waf_name', 'Unknown')
                        tech_info.append(f"WAF: {waf_name}")
                    if tech_info:
                        self._emit(scan_id, 'log', f'[+] AI Recon: {" | ".join(tech_info)}', 'success')
                    if recon_result.get('scan_recommendations'):
                        for rec in recon_result['scan_recommendations'][:3]:
                            self._emit(scan_id, 'log', f'[*] AI Recommendation: {rec[:100]}', 'info')
                else:
                    self._emit(scan_id, 'log', '[*] AI Recon: Could not determine technology stack', 'info')
            except Exception as recon_err:
                logger.debug(f'AI reconnaissance skipped: {recon_err}')
                self._emit(scan_id, 'log', '[*] AI Recon: Skipped (LLM unavailable)', 'info')

            # Phase 2: Vulnerability Scanning
            if ctx['scan_mode'] == 'active':
                self._emit(scan_id, 'log', '[+] Phase 2: Active vulnerability scanning...', 'info')

                scanner_map = {
                    'sql_injection': (SQLInjectionScanner, 'SQL Injection'),
                    'xss': (XSSScanner, 'Cross-Site Scripting'),
                    'csrf': (CSRFScanner, 'CSRF'),
                    'security_headers': (SecurityHeadersScanner, 'Security Headers'),
                    'directory_traversal': (DirectoryTraversalScanner, 'Directory Traversal'),
                    'command_injection': (CommandInjectionScanner, 'Command Injection'),
                    'idor': (IDORScanner, 'IDOR'),
                    'directory_listing': (DirectoryListingScanner, 'Directory Listing'),
                    'xxe': (XXEScanner, 'XXE Injection'),
                    'ssrf': (SSRFScanner, 'SSRF'),
                    'open_redirect': (OpenRedirectScanner, 'Open Redirect'),
                    'cors': (CORSScanner, 'CORS Misconfiguration'),
                    'clickjacking': (ClickjackingScanner, 'Clickjacking'),
                    'ssti': (SSTIScanner, 'Server-Side Template Injection'),
                    'jwt_attacks': (JWTAttackScanner, 'JWT Vulnerabilities'),
                    'broken_auth': (BrokenAuthScanner, 'Broken Authentication'),
                }

                selected = ctx['selected_checks']
                parallel_scanners = [
                    (name, cls, display)
                    for name, (cls, display) in scanner_map.items()
                    if name in selected
                ]

                def run_scanner(check_name, ScannerClass, display_name):
                    if ctx['stopped']:
                        return display_name, [], None
                    try:
                        # Create a fresh session and copy cookies/headers
                        # instead of deepcopy which breaks transport adapters
                        if crawler.session:
                            scanner_session = requests_lib.Session()
                            scanner_session.cookies.update(crawler.session.cookies)
                            scanner_session.headers.update(crawler.session.headers)
                        else:
                            scanner_session = None
                        scanner = ScannerClass(
                            session=scanner_session,
                            timeout=speed_config['timeout'],
                            delay=speed_config['delay']
                        )
                        # Enable ML data collection
                        scanner.collect_ml_data = True
                        scanner.current_scan_id = scan_id
                        if check_name in ('security_headers', 'cors', 'clickjacking'):
                            findings = scanner.scan(target_url, [])
                        else:
                            findings = scanner.scan(target_url, injectable_points)
                        return display_name, findings, None
                    except Exception as e:
                        return display_name, [], str(e)

                max_workers = min(len(parallel_scanners), speed_config.get('threads', 5))

                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures_map = {}
                    for check_name, ScannerClass, display_name in parallel_scanners:
                        self._emit(scan_id, 'log', f'[!] Testing {display_name}...', 'warning')
                        future = executor.submit(run_scanner, check_name, ScannerClass, display_name)
                        futures_map[future] = display_name

                    for future in as_completed(futures_map):
                        if ctx['stopped']:
                            break
                        display_name, findings, error = future.result()

                        if error:
                            self._emit(scan_id, 'log', f'[-] Error in {display_name}: {error[:80]}', 'warning')
                            continue

                        # Collect deduplicated findings for batch insert
                        batch_findings = []
                        for finding in findings:
                            dedup_key = (finding['vuln_type'], finding['affected_url'], finding['parameter'])
                            if dedup_key in seen_vulns:
                                continue
                            seen_vulns.add(dedup_key)
                            ctx['findings'].append(finding)
                            batch_findings.append(finding)

                            track_vulnerability(finding['severity'], finding.get('vuln_type', 'unknown'))
                            sev = finding['severity'].upper()
                            self._emit(scan_id, 'log',
                                f'[X] FOUND: {finding["name"]} ({sev}) at {finding["affected_url"][:50]}',
                                'error')
                            self._emit(scan_id, 'finding', {
                                'name': finding['name'],
                                'severity': finding['severity'],
                                'url': finding['affected_url']
                            }, 'error')

                        # Batch-insert all findings from this scanner (1 commit instead of N)
                        if batch_findings:
                            Vulnerability.create_batch(scan_id, batch_findings)

                        if not findings:
                            self._emit(scan_id, 'log', f'[+] {display_name}: No issues found', 'success')

                        ctx['tested_urls'] = min(
                            ctx['tested_urls'] + max(1, len(discovered_urls) // max(1, len(scanner_map))),
                            ctx['total_urls']
                        )
                        Scan.update_progress(scan_id, ctx['tested_urls'], len(ctx['findings']))
                        self._emit(scan_id, 'progress', {
                            'phase': 'scanning',
                            'total': ctx['total_urls'],
                            'tested': ctx['tested_urls'],
                            'findings': len(ctx['findings'])
                        }, 'info')

            else:
                self._emit(scan_id, 'log', '[+] Passive mode: Checking security headers...', 'info')
                scanner = SecurityHeadersScanner(timeout=speed_config['timeout'])
                findings = scanner.scan(target_url, [])
                for finding in findings:
                    ctx['findings'].append(finding)
                # Batch-insert all passive findings in one commit
                if findings:
                    Vulnerability.create_batch(scan_id, findings)

            # Phase 3: Post-scan AI Analysis (batched — decoupled from scan loop)
            if ctx['findings'] and not ctx.get('stopped'):
                try:
                    from app.ai.smart_engine import get_smart_engine
                    _engine = get_smart_engine()
                    self._emit(scan_id, 'log', '[*] Phase 3: AI analysis of findings...', 'info')

                    import json as _json
                    from app.models.database import db as _db, VulnerabilityModel

                    ai_updates = 0
                    for finding in ctx['findings']:
                        if ctx.get('stopped'):
                            break
                        try:
                            vuln_info = {
                                'vuln_type': finding['vuln_type'],
                                'severity': finding['severity'],
                                'url': finding['affected_url'],
                                'parameter': finding['parameter'],
                                'payload': finding['payload'],
                                'evidence': finding.get('description', ''),
                            }

                            latest = VulnerabilityModel.query.filter_by(
                                scan_id=scan_id,
                                vuln_type=finding['vuln_type'],
                                affected_url=finding['affected_url']
                            ).order_by(VulnerabilityModel.id.desc()).first()

                            if not latest:
                                continue

                            # Step 1: LLM analysis + remediation enrichment
                            try:
                                ai_result = ai_analyze(vuln_info)
                                if ai_result:
                                    latest.ai_analysis = _json.dumps(ai_result)
                            except Exception:
                                pass

                            try:
                                if finding.get('remediation'):
                                    enriched = _engine.enrich_remediation(
                                        finding['vuln_type'], finding['remediation']
                                    )
                                    if enriched:
                                        latest.remediation = enriched
                            except Exception:
                                pass

                            # Step 2: ML false-positive verification
                            try:
                                fp_features = {
                                    'payload_length': len(finding.get('payload', '') or ''),
                                    'payload_special_chars': sum(1 for c in (finding.get('payload', '') or '') if c in "'\"<>;&|`$(){}[]\\"),
                                    'payload_has_script_tag': 1 if '<script' in (finding.get('payload', '') or '').lower() else 0,
                                    'payload_has_sql_keyword': 1 if any(kw in (finding.get('payload', '') or '').upper() for kw in ('SELECT', 'UNION', 'DROP', 'SLEEP')) else 0,
                                    'payload_has_encoding': 1 if '%' in (finding.get('payload', '') or '') else 0,
                                    'baseline_status': 200, 'baseline_length': 0,
                                    'test_status': 200, 'test_length': 0,
                                    'response_time': 0, 'status_changed': 0,
                                    'length_diff': 0, 'length_ratio': 0,
                                    'error_count': 0, 'has_db_error': 0,
                                    'payload_reflected': 0,
                                }
                                verdict, confidence, reasoning = _engine.verify_finding(
                                    vuln_info, fp_features
                                )
                                if verdict == 'false_positive':
                                    latest.likely_false_positive = True
                                    latest.fp_confidence = confidence
                                    self._emit(scan_id, 'log',
                                        f'[*] AI: {finding["name"]} marked as likely false positive ({confidence:.0%})',
                                        'info')
                                elif verdict == 'needs_manual_review':
                                    latest.fp_confidence = confidence
                            except Exception:
                                pass

                            # Step 3: Attack narrative (critical/high only)
                            if finding.get('severity') in ('critical', 'high'):
                                try:
                                    narrative = _engine.generate_attack_narrative(vuln_info)
                                    if narrative:
                                        latest.ai_narrative = _json.dumps(narrative)
                                except Exception:
                                    pass

                            ai_updates += 1
                        except Exception:
                            pass

                    # Single batch commit for all AI updates
                    if ai_updates:
                        _db.session.commit()
                        self._emit(scan_id, 'log',
                            f'[+] AI analysis complete: {ai_updates} findings enriched',
                            'success')
                except Exception as deep_err:
                    logger.debug(f'Post-scan AI analysis skipped: {deep_err}')

            self._finalize(ctx, discovered_urls)

        except Exception as e:
            self._emit(scan_id, 'log', f'[-] Fatal error: {str(e)}', 'error')
            Scan.update_status(scan_id, 'error')
            ctx['status'] = 'error'
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]

    def _finalize(self, ctx, discovered_urls):
        scan_id = ctx['scan_id']
        findings = ctx['findings']

        score = self._calculate_score(findings)
        duration = int(time.time() - ctx['start_time'])

        critical = sum(1 for f in findings if f.get('severity') == 'critical')
        high = sum(1 for f in findings if f.get('severity') == 'high')
        medium = sum(1 for f in findings if f.get('severity') == 'medium')
        low = sum(1 for f in findings if f.get('severity') in ('low', 'info'))

        Scan.complete(
            scan_id=scan_id,
            score=score,
            duration=duration,
            total_urls=len(discovered_urls),
            critical=critical,
            high=high,
            medium=medium,
            low=low
        )

        status = 'completed' if not ctx.get('stopped') else 'stopped'
        ctx['status'] = status
        track_scan_completed(duration, status)

        self._emit(scan_id, 'log', f'[+] Scan complete! Score: {score} | Vulnerabilities: {len(findings)}', 'success')
        self._emit(scan_id, 'complete', {
            'score': score,
            'duration': duration,
            'total_vulns': len(findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'scan_id': scan_id
        }, 'success')

        # Trigger webhooks (best-effort)
        try:
            from app.models.webhook import Webhook
            Webhook.trigger(ctx.get('user_id'), 'scan_complete', {
                'scan_id': scan_id,
                'score': score,
                'duration': duration,
                'total_vulns': len(findings),
                'critical': critical,
                'high': high,
            })
        except Exception:
            pass  # Webhooks are non-critical

        # Clean up Redis state (keep event_history for 1h for late-joining clients)
        redis = self._get_redis()
        if redis:
            try:
                redis.delete(f'scan:{scan_id}:state')
                redis.delete(f'scan:{scan_id}:control')
            except Exception:
                pass

        if scan_id in self.active_scans:
            del self.active_scans[scan_id]

