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
import copy
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from app.config import Config
from app.scanner.crawler import Crawler
from app.scanner.vulnerabilities.sql_injection import SQLInjectionScanner
from app.scanner.vulnerabilities.xss import XSSScanner
from app.scanner.vulnerabilities.csrf import CSRFScanner
from app.scanner.vulnerabilities.security_headers import SecurityHeadersScanner
from app.scanner.vulnerabilities.directory_traversal import DirectoryTraversalScanner
from app.scanner.vulnerabilities.command_injection import CommandInjectionScanner
from app.scanner.vulnerabilities.idor import IDORScanner, DirectoryListingScanner
from app.scanner.dvwa_auth import DVWAAuth
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.database import execute_db

logger = logging.getLogger(__name__)


class ScanManager:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.active_scans = {}  # scan_id -> scan context (threading mode only)
        self.sse_queues = {}    # scan_id -> list of queues (threading mode only)
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
            import redis as redis_lib
            r = redis_lib.from_url(Config.REDIS_URL, socket_connect_timeout=2)
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
            # Track as "active" locally for get_status fallback
            self.active_scans[scan_id] = {
                'scan_id': scan_id,
                'status': 'running',
                'mode': 'celery',
                'start_time': time.time(),
            }
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
            # Celery mode: set Redis control key
            redis.set(f'scan:{scan_id}:control', 'paused')
            Scan.update_status(scan_id, 'paused')
            return True
        # Threading mode
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
            # Also try to revoke the Celery task
            task_id = redis.get(f'scan:{scan_id}:task_id')
            if task_id:
                try:
                    from app.celery_app import celery
                    celery.control.revoke(task_id.decode(), terminate=True)
                except Exception as e:
                    logger.warning(f"Failed to revoke task: {e}")
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            return True
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
        # Threading mode: in-memory context
        ctx = self.active_scans.get(scan_id)
        if ctx and ctx.get('mode') == 'threading':
            return {
                'status': ctx['status'],
                'tested_urls': ctx['tested_urls'],
                'total_urls': ctx['total_urls'],
                'findings': len(ctx['findings']),
                'elapsed': int(time.time() - ctx['start_time'])
            }
        # DB fallback (works for both Celery and threading)
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

    def get_redis_client(self):
        """Get the Redis client for pub/sub subscriptions."""
        return self._get_redis()

    # ─── Internal: event emission ────────────────────────────────────────

    def _emit(self, scan_id, event_type, data, log_level='info'):
        """Emit event — Redis pub/sub in Celery mode, in-memory queues otherwise."""
        msg = {
            'type': event_type,
            'data': data,
            'level': log_level,
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }

        redis = self._get_redis()
        if redis:
            try:
                redis.publish(f'scan:{scan_id}:events', json.dumps(msg))
            except Exception as e:
                logger.warning(f"Redis publish failed: {e}")
        else:
            # In-memory queue fallback
            serialized = f"data: {json.dumps(msg)}\n\n"
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
        scan_id = ctx['scan_id']
        target_url = ctx['target_url']
        speed_config = self._get_speed_config(ctx['scan_speed'])

        try:
            Scan.update_status(scan_id, 'running')
            self._emit(scan_id, 'log', f'[+] Starting scan: {target_url}', 'info')
            self._emit(scan_id, 'log', f'[+] Mode: {ctx["scan_mode"]} | Speed: {ctx["scan_speed"]}', 'info')

            # Phase 1: Crawling
            self._emit(scan_id, 'log', '[+] Phase 1: Crawling target...', 'info')

            def crawl_callback(url, count):
                if ctx['stopped']:
                    return
                ctx['pause_event'].wait()
                ctx['total_urls'] = count
                Scan.update_progress(scan_id, ctx['tested_urls'], len(ctx['findings']))
                execute_db('UPDATE scans SET total_urls = ? WHERE id = ?', (count, scan_id))
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
            ctx['total_urls'] = len(discovered_urls)

            if ctx['stopped']:
                self._finalize(ctx, discovered_urls)
                return

            self._emit(scan_id, 'log',
                f'[+] Crawl complete: {len(discovered_urls)} URLs, {len(injectable_points)} injectable points',
                'success')

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
                        scanner_session = copy.deepcopy(crawler.session) if crawler.session else None
                        scanner = ScannerClass(
                            session=scanner_session,
                            timeout=speed_config['timeout'],
                            delay=speed_config['delay']
                        )
                        if check_name == 'security_headers':
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

                        for finding in findings:
                            ctx['findings'].append(finding)
                            Vulnerability.create(
                                scan_id=scan_id,
                                vuln_type=finding['vuln_type'],
                                name=finding['name'],
                                description=finding['description'],
                                impact=finding['impact'],
                                severity=finding['severity'],
                                cvss_score=finding['cvss_score'],
                                owasp_category=finding['owasp_category'],
                                affected_url=finding['affected_url'],
                                parameter=finding['parameter'],
                                payload=finding['payload'],
                                request_data=finding['request_data'],
                                response_data=finding['response_data'],
                                remediation=finding['remediation']
                            )
                            sev = finding['severity'].upper()
                            self._emit(scan_id, 'log',
                                f'[X] FOUND: {finding["name"]} ({sev}) at {finding["affected_url"][:50]}',
                                'error')
                            self._emit(scan_id, 'finding', {
                                'name': finding['name'],
                                'severity': finding['severity'],
                                'url': finding['affected_url']
                            }, 'error')

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
                    Vulnerability.create(
                        scan_id=scan_id,
                        vuln_type=finding['vuln_type'],
                        name=finding['name'],
                        description=finding['description'],
                        impact=finding['impact'],
                        severity=finding['severity'],
                        cvss_score=finding['cvss_score'],
                        owasp_category=finding['owasp_category'],
                        affected_url=finding['affected_url'],
                        parameter=finding['parameter'],
                        payload=finding['payload'],
                        request_data=finding['request_data'],
                        response_data=finding['response_data'],
                        remediation=finding['remediation']
                    )

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

        ctx['status'] = 'completed' if not ctx.get('stopped') else 'stopped'

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

        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
