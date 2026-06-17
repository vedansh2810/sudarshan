"""Celery tasks for background scan execution."""

import time
import json
import logging
import httpx
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

from app.celery_app import celery
from app.config import Config
from app.scanner.crawler import Crawler
from app.scanner.registry import SCANNER_MAP
from app.scanner.vulnerabilities.security_headers import SecurityHeadersScanner
from app.scanner.dvwa_auth import DVWAAuth
from app.ai.smart_engine import get_smart_engine
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.monitoring.metrics import (
    track_scan_started,
    track_scan_completed,
    track_vulnerability,
)

logger = logging.getLogger(__name__)

# Pre-compiled prompt injection patterns for _sanitize_for_llm()
import re
_INJECTION_PATTERNS = [re.compile(pat) for pat in [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)",
    r"(?i)you\s+are\s+now\s+a",
    r"(?i)new\s+instructions?:",
    r"(?i)system\s*:\s*",
    r"(?i)forget\s+(everything|all)",
    r"(?i)do\s+not\s+report\s+(this|any)",
    r"(?i)mark\s+(this\s+)?(as\s+)?safe",
    r"(?i)this\s+is\s+not\s+a\s+vulnerability",
]]


def _sanitize_for_llm(text):
    """Strip potential prompt injection patterns from target response content.

    Removes common prompt injection phrases to prevent scan targets
    from manipulating AI verification results.
    """
    if not text:
        return ""
    for pat in _INJECTION_PATTERNS:
        text = pat.sub("[PROMPT_INJECTION_FILTERED]", text)
    return text


def _get_redis():
    """Get Redis client, returns None if unavailable."""
    try:
        import redis as redis_lib

        r = redis_lib.from_url(Config.REDIS_URL)
        r.ping()
        return r
    except Exception:
        return None


def _emit_redis(redis_client, scan_id, event_type, data, log_level="info"):
    """Publish scan event to Redis pub/sub channel."""
    msg = {
        "type": event_type,
        "data": data,
        "level": log_level,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    serialized = json.dumps(msg)
    channel = f"scan:{scan_id}:events"
    try:
        redis_client.publish(channel, serialized)
    except Exception as e:
        logger.warning(f"Redis publish failed: {e}")

    # Persist logs to DB
    if event_type == "log":
        try:
            Scan.add_log(scan_id, data, log_level)
        except Exception as e:
            logger.warning(f"Failed to persist log: {e}")


def _check_control(redis_client, scan_id):
    """Check Redis for pause/stop control signals."""
    if not redis_client:
        return None
    try:
        val = redis_client.get(f"scan:{scan_id}:control")
        return val.decode("utf-8") if val else None
    except Exception:
        return None


def _get_speed_config(speed):
    return Config.SCAN_SPEEDS.get(speed, Config.SCAN_SPEEDS["balanced"])


def _calculate_score(findings):
    if not findings:
        return "A"
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")

    score_num = 100
    score_num -= critical * 20
    score_num -= high * 10
    score_num -= medium * 5
    score_num = max(0, score_num)

    if score_num >= 90:
        return "A"
    elif score_num >= 80:
        return "B"
    elif score_num >= 70:
        return "C"
    elif score_num >= 60:
        return "D"
    else:
        return "F"


@celery.task(bind=True, name="app.tasks.run_scan_task")
def run_scan_task(
    self,
    scan_id,
    target_url,
    scan_mode,
    scan_speed,
    crawl_depth,
    selected_checks=None,
    dvwa_security="low",
):
    """Execute a vulnerability scan as a Celery background task."""
    redis_client = _get_redis()
    speed_config = _get_speed_config(scan_speed)
    findings = []
    seen_vulns = set()  # (vuln_type, affected_url, parameter) dedup
    start_time = time.time()

    def emit(event_type, data, log_level="info"):
        _emit_redis(redis_client, scan_id, event_type, data, log_level)

    def is_stopped():
        ctrl = _check_control(redis_client, scan_id)
        return ctrl == "stopped"

    def wait_if_paused():
        """Block while paused, return True if stopped during pause."""
        MAX_PAUSE_SECONDS = 1800  # 30 minutes
        pause_start = time.time()
        while True:
            ctrl = _check_control(redis_client, scan_id)
            if ctrl == "stopped":
                return True
            if ctrl != "paused":
                return False
            if time.time() - pause_start > MAX_PAUSE_SECONDS:
                emit("log", "[-] Auto-resuming after 30min pause timeout", "warning")
                return False
            time.sleep(2)

    try:
        Scan.update_status(scan_id, "running")
        # Store Celery task ID in Redis for revocation
        if redis_client:
            redis_client.set(f"scan:{scan_id}:task_id", self.request.id, ex=86400)

        emit("log", f"[+] Starting scan: {target_url}", "info")
        track_scan_started()
        emit("log", f"[+] Mode: {scan_mode} | Speed: {scan_speed}", "info")

        # Phase 1: Crawling
        emit("log", "[+] Phase 1: Crawling target...", "info")

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
            emit("log", f"[+] Crawling: {url[:70]}", "info")
            emit(
                "progress",
                {
                    "phase": "crawling",
                    "total": count,
                    "tested": tested_urls,
                    "findings": len(findings),
                },
                "info",
            )

        # DVWA auto-detection
        authenticated_session = None
        if DVWAAuth.is_dvwa_target(target_url):
            emit("log", "[+] DVWA detected - authenticating...", "info")
            authenticated_session = DVWAAuth.login(target_url.rstrip("/"))
            if authenticated_session:
                DVWAAuth.set_security_level(
                    authenticated_session, target_url.rstrip("/"), dvwa_security
                )
                emit(
                    "log",
                    f"[+] DVWA authenticated (security: {dvwa_security.upper()})",
                    "success",
                )
            else:
                emit(
                    "log",
                    "[-] DVWA authentication failed - scanning without auth",
                    "warning",
                )

        crawler = Crawler(
            target_url=target_url,
            max_depth=crawl_depth,
            max_urls=speed_config["max_urls"],
            timeout=speed_config["timeout"],
            delay=speed_config["delay"],
            threads=speed_config.get("threads", 5),
            session=authenticated_session,
        )

        discovered_urls, injectable_points = crawler.crawl(
            scan_id=scan_id, callback=crawl_callback
        )
        total_urls = len(discovered_urls)

        if is_stopped():
            _finalize(
                scan_id,
                findings,
                discovered_urls,
                start_time,
                stopped=True,
                redis_client=redis_client,
            )
            return

        emit(
            "log",
            f"[+] Crawl complete: {len(discovered_urls)} URLs, {len(injectable_points)} injectable points",
            "success",
        )

        # Phase 1.5: AI Reconnaissance (non-blocking)
        target_context = {}
        try:
            smart_engine = get_smart_engine()
            emit("log", "[*] AI Reconnaissance: Analyzing target...", "info")
            recon_resp = httpx.get(
                target_url, timeout=speed_config["timeout"],
                verify=not Config.ALLOW_INSECURE_TARGETS, follow_redirects=True
            )
            recon_result = smart_engine.reconnaissance(target_url, recon_resp)
            if recon_result:
                target_context = recon_result
                tech_parts = []
                if recon_result.get("language"):
                    tech_parts.append(f"Language: {recon_result['language']}")
                if recon_result.get("framework"):
                    tech_parts.append(f"Framework: {recon_result['framework']}")
                if recon_result.get("waf_detected"):
                    tech_parts.append(f"WAF: {recon_result.get('waf_name', 'Unknown')}")
                if tech_parts:
                    emit("log", f'[+] AI Recon: {" | ".join(tech_parts)}', "success")
        except Exception as e:
            logger.debug(f"AI reconnaissance skipped: {e}")

        # Phase 2: Vulnerability Scanning
        if scan_mode == "active":
            emit("log", "[+] Phase 2: Active vulnerability scanning...", "info")

            scanner_map = SCANNER_MAP

            checks = selected_checks or Config.VULNERABILITY_CHECKS
            parallel_scanners = [
                (name, cls, display)
                for name, (cls, display) in scanner_map.items()
                if name in checks
            ]

            def run_scanner(check_name, ScannerClass, display_name):
                if is_stopped():
                    return display_name, [], None
                scanner_session = None
                try:
                    # Create a fresh session and copy cookies/headers
                    # instead of deepcopy which breaks transport adapters
                    if crawler.session:
                        timeout_val = speed_config["timeout"]
                        crawler_cookies = crawler.session.cookies
                        crawler_headers = crawler.session.headers
                        scanner_session = httpx.Client(
                            verify=not Config.ALLOW_INSECURE_TARGETS,
                            timeout=httpx.Timeout(timeout_val, connect=5.0),
                            follow_redirects=True,
                            cookies=dict(crawler_cookies),
                            headers=dict(crawler_headers),
                            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                        )
                    scanner = ScannerClass(
                        session=scanner_session,
                        timeout=speed_config["timeout"],
                        delay=speed_config["delay"],
                    )
                    # Header-only scanners don't need injectable points
                    if check_name in ("security_headers", "cors", "clickjacking"):
                        results = scanner.scan(target_url, [])
                    else:
                        results = scanner.scan(target_url, injectable_points)
                    return display_name, results, None
                except Exception as e:
                    return display_name, [], str(e)
                finally:
                    if scanner_session:
                        scanner_session.close()

            max_workers = min(len(parallel_scanners), speed_config.get("threads", 5))

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures_map = {}
                for check_name, ScannerClass, display_name in parallel_scanners:
                    emit("log", f"[!] Testing {display_name}...", "warning")
                    future = executor.submit(
                        run_scanner, check_name, ScannerClass, display_name
                    )
                    futures_map[future] = display_name

                for future in as_completed(futures_map):
                    if is_stopped():
                        break
                    wait_if_paused()

                    scanner_name = futures_map[future]
                    try:
                        display_name, scan_findings, error = future.result(timeout=120)
                    except TimeoutError:
                        emit(
                            "log",
                            f"[-] {scanner_name}: Timed out after 120s — skipping",
                            "warning",
                        )
                        continue
                    except Exception as exc:
                        emit(
                            "log",
                            f"[-] {scanner_name}: Unexpected error: {str(exc)[:80]}",
                            "warning",
                        )
                        continue

                    if error:
                        emit(
                            "log",
                            f"[-] Error in {display_name}: {error[:80]}",
                            "warning",
                        )
                        continue

                    # Collect deduplicated findings for batch insert
                    batch_findings = []
                    for finding in scan_findings:
                        dedup_key = (
                            finding["vuln_type"],
                            finding["affected_url"],
                            finding["parameter"],
                        )
                        if dedup_key in seen_vulns:
                            continue
                        seen_vulns.add(dedup_key)
                        findings.append(finding)
                        batch_findings.append(finding)
                        track_vulnerability(
                            finding["severity"], finding.get("vuln_type", "unknown")
                        )

                        sev = finding["severity"].upper()
                        emit(
                            "log",
                            f'[X] FOUND: {finding["name"]} ({sev}) at {finding["affected_url"][:50]}',
                            "error",
                        )
                        emit(
                            "finding",
                            {
                                "name": finding["name"],
                                "severity": finding["severity"],
                                "url": finding["affected_url"],
                            },
                            "error",
                        )

                    # Batch-insert all findings from this scanner (1 commit instead of N)
                    if batch_findings:
                        Vulnerability.create_batch(scan_id, batch_findings)

                    if not scan_findings:
                        emit("log", f"[+] {display_name}: No issues found", "success")

                    tested_urls = min(
                        tested_urls
                        + max(1, len(discovered_urls) // max(1, len(scanner_map))),
                        total_urls,
                    )
                    Scan.update_progress(scan_id, tested_urls, len(findings))
                    emit(
                        "progress",
                        {
                            "phase": "scanning",
                            "total": total_urls,
                            "tested": tested_urls,
                            "findings": len(findings),
                        },
                        "info",
                    )

        else:
            # Passive mode
            emit("log", "[+] Passive mode: Checking security headers...", "info")
            scanner = SecurityHeadersScanner(timeout=speed_config["timeout"])
            passive_findings = scanner.scan(target_url, [])
            for finding in passive_findings:
                findings.append(finding)
            # Batch-insert all passive findings
            if passive_findings:
                Vulnerability.create_batch(scan_id, passive_findings)

        # Phase 3: AI-Powered Finding Verification
        if findings:
            try:
                smart_engine = get_smart_engine()
                emit("log", f"[*] Phase 3: AI verification of {len(findings)} findings...", "info")
                verified_findings = []
                for i, finding in enumerate(findings):
                    if is_stopped():
                        break
                    try:
                        # Build verification data
                        vuln_data = {
                            "vuln_type": finding.get("vuln_type", ""),
                            "url": finding.get("affected_url", ""),
                            "parameter": finding.get("parameter", ""),
                            "payload": finding.get("payload", ""),
                            "evidence": finding.get("response_data", finding.get("description", "")),
                        }
                        # Use ML features from the finding if available
                        features = finding.get("ml_features", {})
                        response_data = {
                            "status_code": finding.get("status_code", "N/A"),
                            "content_length": finding.get("content_length", "N/A"),
                            "response_time": finding.get("response_time", "N/A"),
                            "reflection_detected": finding.get("payload_reflected", "N/A"),
                            "body_preview": _sanitize_for_llm(finding.get("response_data", "")[:500]),
                        }

                        verdict, confidence, reasoning = smart_engine.verify_finding(
                            vuln_data, features, response_data
                        )

                        finding["ai_verified"] = True
                        finding["ai_verdict"] = verdict
                        finding["ai_confidence"] = round(confidence, 2)
                        finding["ai_reasoning"] = reasoning

                        if verdict == "false_positive":
                            emit("log", f"[~] AI filtered: {finding['name']} (FP, {confidence:.0%})", "info")
                        else:
                            verified_findings.append(finding)

                    except Exception as e:
                        logger.debug(f"AI verification failed for finding: {e}")
                        verified_findings.append(finding)  # Keep finding if verification fails

                filtered_count = len(findings) - len(verified_findings)
                if filtered_count > 0:
                    emit("log", f"[+] AI filtered {filtered_count} false positives", "success")
                    # Update findings list (but keep all in DB for transparency)
                    # The verdict is stored on each finding for the UI to use

            except Exception as e:
                logger.debug(f"AI verification phase skipped: {e}")

        _finalize(
            scan_id,
            findings,
            discovered_urls,
            start_time,
            stopped=is_stopped(),
            redis_client=redis_client,
        )

    except Exception as e:
        logger.error(f"Scan {scan_id} fatal error: {e}", exc_info=True)
        emit("log", f"[-] Fatal error: {str(e)}", "error")
        Scan.update_status(scan_id, "error")
        _cleanup_redis(redis_client, scan_id)


def _finalize(
    scan_id, findings, discovered_urls, start_time, stopped=False, redis_client=None
):
    """Complete the scan and emit final events."""
    score = _calculate_score(findings)
    duration = int(time.time() - start_time)

    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") in ("low", "info"))

    # Pass status atomically to avoid race condition between two commits
    final_status = "stopped" if stopped else "completed"
    Scan.complete(
        scan_id=scan_id,
        score=score,
        duration=duration,
        total_urls=len(discovered_urls),
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        status=final_status,
    )

    status = "stopped" if stopped else "completed"
    track_scan_completed(duration, status)
    _emit_redis(
        redis_client,
        scan_id,
        "log",
        f"[+] Scan {status}! Score: {score} | Vulnerabilities: {len(findings)}",
        "success",
    )
    _emit_redis(
        redis_client,
        scan_id,
        "complete",
        {
            "score": score,
            "duration": duration,
            "total_vulns": len(findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "scan_id": scan_id,
        },
        "success",
    )

    _cleanup_redis(redis_client, scan_id)


def _cleanup_redis(redis_client, scan_id):
    """Remove Redis control keys after scan completion."""
    if redis_client:
        try:
            redis_client.delete(f"scan:{scan_id}:control")
            redis_client.delete(f"scan:{scan_id}:task_id")
        except Exception:
            pass
