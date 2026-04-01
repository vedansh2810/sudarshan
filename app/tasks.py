"""Celery tasks for background scan execution."""
import time
import json
import logging
import requests as requests_lib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from app.celery_app import celery
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

logger = logging.getLogger(__name__)


def _get_redis():
    """Get Redis client, returns None if unavailable."""
    try:
        import redis as redis_lib
        r = redis_lib.from_url(Config.REDIS_URL)
        r.ping()
        return r
    except Exception:
        return None


def _emit_redis(redis_client, scan_id, event_type, data, log_level='info'):
    """Publish scan event to Redis pub/sub channel."""
    msg = {
        'type': event_type,
        'data': data,
        'level': log_level,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }
    serialized = json.dumps(msg)
    channel = f'scan:{scan_id}:events'
    try:
        redis_client.publish(channel, serialized)
    except Exception as e:
        logger.warning(f"Redis publish failed: {e}")

    # Persist logs to DB
    if event_type == 'log':
        try:
            Scan.add_log(scan_id, data, log_level)
        except Exception as e:
            logger.warning(f"Failed to persist log: {e}")


def _check_control(redis_client, scan_id):
    """Check Redis for pause/stop control signals."""
    if not redis_client:
        return None
    try:
        val = redis_client.get(f'scan:{scan_id}:control')
        return val.decode('utf-8') if val else None
    except Exception:
        return None


def _get_speed_config(speed):
    return Config.SCAN_SPEEDS.get(speed, Config.SCAN_SPEEDS['balanced'])


def _calculate_score(findings):
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


@celery.task(bind=True, name='app.tasks.run_scan_task')
def run_scan_task(self, scan_id, target_url, scan_mode, scan_speed,
                  crawl_depth, selected_checks=None, dvwa_security='low'):
    """Execute a vulnerability scan as a Celery background task."""
    redis_client = _get_redis()
    speed_config = _get_speed_config(scan_speed)
    findings = []
    seen_vulns = set()  # (vuln_type, affected_url, parameter) dedup
    start_time = time.time()

    def emit(event_type, data, log_level='info'):
        _emit_redis(redis_client, scan_id, event_type, data, log_level)

    def is_stopped():
        ctrl = _check_control(redis_client, scan_id)
        return ctrl == 'stopped'

    def wait_if_paused():
        """Block while paused, return True if stopped during pause."""
        while True:
            ctrl = _check_control(redis_client, scan_id)
            if ctrl == 'stopped':
                return True
            if ctrl != 'paused':
                return False
            time.sleep(0.5)

    try:
        Scan.update_status(scan_id, 'running')
        # Store Celery task ID in Redis for revocation
        if redis_client:
            redis_client.set(f'scan:{scan_id}:task_id', self.request.id, ex=86400)

        emit('log', f'[+] Starting scan: {target_url}', 'info')
        track_scan_started()
        emit('log', f'[+] Mode: {scan_mode} | Speed: {scan_speed}', 'info')

        # Phase 1: Crawling
        emit('log', '[+] Phase 1: Crawling target...', 'info')

        tested_urls = 0
        total_urls = 0

        def crawl_callback(url, count):
            nonlocal total_urls
            if is_stopped():
                return
            wait_if_paused()
            total_urls = count
            Scan.update_progress(scan_id, tested_urls, len(findings))
            Scan.update_total_urls(scan_id, count)
            emit('log', f'[+] Crawling: {url[:70]}', 'info')
            emit('progress', {
                'phase': 'crawling',
                'total': count,
                'tested': tested_urls,
                'findings': len(findings)
            }, 'info')

        # DVWA auto-detection
        authenticated_session = None
        if DVWAAuth.is_dvwa_target(target_url):
            emit('log', '[+] DVWA detected - authenticating...', 'info')
            authenticated_session = DVWAAuth.login(target_url.rstrip('/'))
            if authenticated_session:
                DVWAAuth.set_security_level(authenticated_session, target_url.rstrip('/'), dvwa_security)
                emit('log', f'[+] DVWA authenticated (security: {dvwa_security.upper()})', 'success')
            else:
                emit('log', '[-] DVWA authentication failed - scanning without auth', 'warning')

        crawler = Crawler(
            target_url=target_url,
            max_depth=crawl_depth,
            max_urls=speed_config['max_urls'],
            timeout=speed_config['timeout'],
            delay=speed_config['delay'],
            threads=speed_config.get('threads', 5),
            session=authenticated_session
        )

        discovered_urls, injectable_points = crawler.crawl(scan_id=scan_id, callback=crawl_callback)
        total_urls = len(discovered_urls)

        if is_stopped():
            _finalize(scan_id, findings, discovered_urls, start_time, stopped=True, redis_client=redis_client)
            return

        emit('log',
             f'[+] Crawl complete: {len(discovered_urls)} URLs, {len(injectable_points)} injectable points',
             'success')

        # Phase 2: Vulnerability Scanning
        if scan_mode == 'active':
            emit('log', '[+] Phase 2: Active vulnerability scanning...', 'info')

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

            checks = selected_checks or Config.VULNERABILITY_CHECKS
            parallel_scanners = [
                (name, cls, display)
                for name, (cls, display) in scanner_map.items()
                if name in checks
            ]

            def run_scanner(check_name, ScannerClass, display_name):
                if is_stopped():
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
                    # Header-only scanners don't need injectable points
                    if check_name in ('security_headers', 'cors', 'clickjacking'):
                        results = scanner.scan(target_url, [])
                    else:
                        results = scanner.scan(target_url, injectable_points)
                    return display_name, results, None
                except Exception as e:
                    return display_name, [], str(e)

            max_workers = min(len(parallel_scanners), speed_config.get('threads', 5))

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures_map = {}
                for check_name, ScannerClass, display_name in parallel_scanners:
                    emit('log', f'[!] Testing {display_name}...', 'warning')
                    future = executor.submit(run_scanner, check_name, ScannerClass, display_name)
                    futures_map[future] = display_name

                for future in as_completed(futures_map):
                    if is_stopped():
                        break
                    wait_if_paused()

                    display_name, scan_findings, error = future.result()

                    if error:
                        emit('log', f'[-] Error in {display_name}: {error[:80]}', 'warning')
                        continue

                    # Collect deduplicated findings for batch insert
                    batch_findings = []
                    for finding in scan_findings:
                        dedup_key = (finding['vuln_type'], finding['affected_url'], finding['parameter'])
                        if dedup_key in seen_vulns:
                            continue
                        seen_vulns.add(dedup_key)
                        findings.append(finding)
                        batch_findings.append(finding)
                        track_vulnerability(finding['severity'], finding.get('vuln_type', 'unknown'))

                        sev = finding['severity'].upper()
                        emit('log',
                             f'[X] FOUND: {finding["name"]} ({sev}) at {finding["affected_url"][:50]}',
                             'error')
                        emit('finding', {
                            'name': finding['name'],
                            'severity': finding['severity'],
                            'url': finding['affected_url']
                        }, 'error')

                    # Batch-insert all findings from this scanner (1 commit instead of N)
                    if batch_findings:
                        Vulnerability.create_batch(scan_id, batch_findings)

                    if not scan_findings:
                        emit('log', f'[+] {display_name}: No issues found', 'success')

                    tested_urls = min(
                        tested_urls + max(1, len(discovered_urls) // max(1, len(scanner_map))),
                        total_urls
                    )
                    Scan.update_progress(scan_id, tested_urls, len(findings))
                    emit('progress', {
                        'phase': 'scanning',
                        'total': total_urls,
                        'tested': tested_urls,
                        'findings': len(findings)
                    }, 'info')

        else:
            # Passive mode
            emit('log', '[+] Passive mode: Checking security headers...', 'info')
            scanner = SecurityHeadersScanner(timeout=speed_config['timeout'])
            passive_findings = scanner.scan(target_url, [])
            for finding in passive_findings:
                findings.append(finding)
            # Batch-insert all passive findings
            if passive_findings:
                Vulnerability.create_batch(scan_id, passive_findings)

        # Post-scan AI Analysis (batched — decoupled from scan loop)
        if findings and not is_stopped():
            try:
                from app.ai.smart_engine import get_smart_engine
                from app.ai.analyzer import analyze_vulnerability as ai_analyze
                _engine = get_smart_engine()
                emit('log', '[*] AI analysis of findings...', 'info')

                from app.models.database import db as _db, VulnerabilityModel
                ai_updates = 0
                for finding in findings:
                    if is_stopped():
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

                        try:
                            ai_result = ai_analyze(vuln_info)
                            if ai_result:
                                latest.ai_analysis = json.dumps(ai_result)
                        except Exception:
                            pass
                        try:
                            if finding.get('remediation'):
                                enriched = _engine.enrich_remediation(
                                    finding['vuln_type'], finding['remediation'])
                                if enriched:
                                    latest.remediation = enriched
                        except Exception:
                            pass
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
                                vuln_info, fp_features)
                            if verdict == 'false_positive':
                                latest.likely_false_positive = True
                                latest.fp_confidence = confidence
                                emit('log', f'[*] AI: {finding["name"]} likely FP ({confidence:.0%})', 'info')
                            elif verdict == 'needs_manual_review':
                                latest.fp_confidence = confidence
                        except Exception:
                            pass
                        if finding.get('severity') in ('critical', 'high'):
                            try:
                                narrative = _engine.generate_attack_narrative(vuln_info)
                                if narrative:
                                    latest.ai_narrative = json.dumps(narrative)
                            except Exception:
                                pass
                        ai_updates += 1
                    except Exception:
                        pass
                if ai_updates:
                    _db.session.commit()
                    emit('log', f'[+] AI analysis complete: {ai_updates} findings enriched', 'success')
            except Exception as ai_err:
                logger.debug(f'Post-scan AI analysis skipped: {ai_err}')

        _finalize(scan_id, findings, discovered_urls, start_time,
                  stopped=is_stopped(), redis_client=redis_client)

    except Exception as e:
        logger.error(f"Scan {scan_id} fatal error: {e}", exc_info=True)
        emit('log', f'[-] Fatal error: {str(e)}', 'error')
        Scan.update_status(scan_id, 'error')
        _cleanup_redis(redis_client, scan_id)


def _finalize(scan_id, findings, discovered_urls, start_time, stopped=False, redis_client=None):
    """Complete the scan and emit final events."""
    score = _calculate_score(findings)
    duration = int(time.time() - start_time)

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

    if stopped:
        Scan.update_status(scan_id, 'stopped')

    status = 'stopped' if stopped else 'completed'
    track_scan_completed(duration, status)
    _emit_redis(redis_client, scan_id, 'log',
                f'[+] Scan {status}! Score: {score} | Vulnerabilities: {len(findings)}', 'success')
    _emit_redis(redis_client, scan_id, 'complete', {
        'score': score,
        'duration': duration,
        'total_vulns': len(findings),
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'scan_id': scan_id
    }, 'success')

    _cleanup_redis(redis_client, scan_id)


def _cleanup_redis(redis_client, scan_id):
    """Remove Redis control keys after scan completion."""
    if redis_client:
        try:
            redis_client.delete(f'scan:{scan_id}:control')
            redis_client.delete(f'scan:{scan_id}:task_id')
        except Exception:
            pass
