from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, Response
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.scanner.scan_manager import ScanManager
from app.config import Config
from app.utils.auth_utils import login_required
from app.utils.auth_helpers import user_can_access_scan
from app import limiter, csrf
import json
import time
import queue
import logging

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan', __name__)


@scan_bp.route('/scan/new', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
@login_required
def new_scan():
    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        scan_mode = request.form.get('scan_mode', 'active')
        scan_speed = request.form.get('scan_speed', 'balanced')
        try:
            crawl_depth = max(1, min(10, int(request.form.get('crawl_depth', 3))))
        except (ValueError, TypeError):
            crawl_depth = 3
        dvwa_security = request.form.get('dvwa_security', 'low')
        authorized = request.form.get('authorized')
        selected_checks = request.form.getlist('checks')

        if not authorized:
            return render_template('scan/new.html',
                error='You must confirm legal authorization before scanning.',
                checks=Config.VULNERABILITY_CHECKS)

        if not target_url:
            return render_template('scan/new.html',
                error='Please enter a target URL.',
                checks=Config.VULNERABILITY_CHECKS)

        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        # SSRF protection: block scans targeting internal/private IPs
        from app.utils.url_safety import is_safe_url
        is_safe, reason = is_safe_url(target_url)
        if not is_safe:
            return render_template('scan/new.html',
                error=f'Target URL blocked for security: {reason}',
                checks=Config.VULNERABILITY_CHECKS)

        if not selected_checks:
            selected_checks = Config.VULNERABILITY_CHECKS

        scan_id = Scan.create(
            user_id=session['user_id'],
            target_url=target_url,
            scan_mode=scan_mode,
            scan_speed=scan_speed,
            crawl_depth=crawl_depth
        )

        manager = ScanManager.get_instance()
        manager.start_scan(
            scan_id=scan_id,
            target_url=target_url,
            scan_mode=scan_mode,
            scan_speed=scan_speed,
            crawl_depth=crawl_depth,
            selected_checks=selected_checks,
            dvwa_security=dvwa_security
        )

        return redirect(url_for('scan.progress', scan_id=scan_id))

    return render_template('scan/new.html', checks=Config.VULNERABILITY_CHECKS)

@scan_bp.route('/scan/<int:scan_id>/progress')
@login_required
def progress(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return redirect(url_for('dashboard.index'))
    return render_template('scan/progress.html', scan=scan)

@scan_bp.route('/scan/<int:scan_id>/status')
@limiter.exempt
@login_required
def status(scan_id):
    """Lightweight JSON endpoint for polling scan stats."""
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return jsonify({'error': 'Forbidden'}), 403
    manager = ScanManager.get_instance()
    st = manager.get_status(scan_id)
    if st:
        return jsonify(st)
    return jsonify({
        'status': scan['status'],
        'total_urls': scan['total_urls'] or 0,
        'tested_urls': scan['tested_urls'] or 0,
        'findings': scan['vuln_count'] or 0,
        'elapsed': scan['duration'] or 0
    })

@scan_bp.route('/scan/<int:scan_id>/stream')
@limiter.exempt
@login_required
def stream(scan_id):
    # Ownership check: prevent users from subscribing to other users' scans
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return jsonify({'error': 'Forbidden'}), 403

    manager = ScanManager.get_instance()

    if manager.is_redis_mode():
        return _stream_redis(scan_id, manager)
    else:
        return _stream_threading(scan_id, manager)


def _stream_redis(scan_id, manager):
    """SSE streaming via Redis pub/sub (Celery mode)."""
    redis_client = manager.get_redis_client()

    # ── Pre-fetch all replay data in the request context ──────────────────
    replay_messages = []
    initial_complete = False
    complete_msg = None
    initial_progress = None

    try:
        logs = Scan.get_logs(scan_id)
        for log in logs:
            msg = {
                'type': 'log',
                'data': log['message'],
                'level': log['log_type'],
                'timestamp': str(log['logged_at'])
            }
            replay_messages.append(f"data: {json.dumps(msg)}\n\n")
    except Exception as e:
        logger.warning(f"Failed to replay logs for scan {scan_id}: {e}")

    try:
        existing_vulns = Vulnerability.get_by_scan(scan_id)
        for vuln in existing_vulns:
            finding_msg = {
                'type': 'finding',
                'data': {
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'url': vuln['affected_url']
                },
                'level': 'error',
                'timestamp': str(vuln['found_at'])
            }
            replay_messages.append(f"data: {json.dumps(finding_msg)}\n\n")
    except Exception as e:
        logger.warning(f"Failed to replay findings for scan {scan_id}: {e}")

    try:
        status = manager.get_status(scan_id)
        if status:
            if status['status'] in ('completed', 'stopped', 'error'):
                scan = Scan.get_by_id(scan_id)
                complete_msg = f"data: {json.dumps({'type': 'complete', 'data': {'score': scan['score'] if scan else 'N/A', 'scan_id': scan_id}, 'level': 'success'})}\n\n"
                initial_complete = True
            else:
                initial_progress = f"data: {json.dumps({'type': 'progress', 'data': {'phase': 'scanning', 'total': status['total_urls'], 'tested': status['tested_urls'], 'findings': status['findings']}, 'level': 'info'})}\n\n"
    except Exception as e:
        logger.warning(f"Failed to get status for scan {scan_id}: {e}")

    def generate():
        pubsub = None
        try:
            # Yield pre-fetched replay data
            for msg in replay_messages:
                yield msg

            # Yield completion or progress if applicable
            if initial_complete and complete_msg:
                yield complete_msg
                return

            if initial_progress:
                yield initial_progress

            # Subscribe to Redis channel for live events
            pubsub = redis_client.pubsub()
            pubsub.subscribe(f'scan:{scan_id}:events')

            while True:
                message = pubsub.get_message(ignore_subscribe_messages=True, timeout=30)
                if message and message['type'] == 'message':
                    data = message['data']
                    if isinstance(data, bytes):
                        data = data.decode('utf-8')
                    yield f"data: {data}\n\n"
                    try:
                        parsed = json.loads(data)
                        if parsed.get('type') == 'complete':
                            break
                    except json.JSONDecodeError:
                        pass
                else:
                    yield ': heartbeat\n\n'
        except GeneratorExit:
            pass
        except Exception as e:
            logger.error(f"SSE Redis generator error for scan {scan_id}: {e}")
        finally:
            if pubsub:
                try:
                    pubsub.unsubscribe()
                    pubsub.close()
                except Exception:
                    pass

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


def _stream_threading(scan_id, manager):
    """SSE streaming via in-memory queues (threading fallback mode)."""
    q = manager.register_sse_client(scan_id)

    # ── Pre-fetch all replay data in the request context ──────────────────
    replay_messages = []
    initial_complete = False
    complete_msg = None
    initial_progress = None

    # First try to replay from in-memory event history (captures ALL event types)
    event_history = manager.get_event_history(scan_id)
    if event_history:
        replay_messages = list(event_history)
    else:
        # Fallback to DB logs (only captures 'log' events)
        try:
            logs = Scan.get_logs(scan_id)
            for log in logs:
                msg = {
                    'type': 'log',
                    'data': log['message'],
                    'level': log['log_type'],
                    'timestamp': str(log['logged_at'])
                }
                replay_messages.append(f"data: {json.dumps(msg)}\n\n")
        except Exception as e:
            logger.warning(f"Failed to replay logs for scan {scan_id}: {e}")

    try:
        existing_vulns = Vulnerability.get_by_scan(scan_id)
        for vuln in existing_vulns:
            finding_msg = {
                'type': 'finding',
                'data': {
                    'name': vuln['name'],
                    'severity': vuln['severity'],
                    'url': vuln['affected_url']
                },
                'level': 'error',
                'timestamp': str(vuln['found_at'])
            }
            replay_messages.append(f"data: {json.dumps(finding_msg)}\n\n")
    except Exception as e:
        logger.warning(f"Failed to replay findings for scan {scan_id}: {e}")

    try:
        status = manager.get_status(scan_id)
        if status:
            if status['status'] in ('completed', 'stopped', 'error'):
                scan = Scan.get_by_id(scan_id)
                complete_msg = f"data: {json.dumps({'type': 'complete', 'data': {'score': scan['score'] if scan else 'N/A', 'scan_id': scan_id}, 'level': 'success'})}\n\n"
                initial_complete = True
            else:
                initial_progress = f"data: {json.dumps({'type': 'progress', 'data': {'phase': 'scanning', 'total': status['total_urls'], 'tested': status['tested_urls'], 'findings': status['findings']}, 'level': 'info'})}\n\n"
    except Exception as e:
        logger.warning(f"Failed to get status for scan {scan_id}: {e}")

    def generate():
        try:
            # Yield pre-fetched replay data
            for msg in replay_messages:
                yield msg

            # Yield completion or progress if applicable
            if initial_complete and complete_msg:
                yield complete_msg
                return

            if initial_progress:
                yield initial_progress

            # Stream live events from queue
            while True:
                try:
                    data = q.get(timeout=30)
                    yield data
                    parsed = json.loads(data.replace('data: ', '').strip())
                    if parsed.get('type') == 'complete':
                        break
                except queue.Empty:
                    yield ': heartbeat\n\n'
                except Exception as e:
                    logger.debug(f"SSE stream error: {e}")
                    yield ': heartbeat\n\n'
        except GeneratorExit:
            pass
        except Exception as e:
            logger.error(f"SSE threading generator error for scan {scan_id}: {e}")
        finally:
            manager.unregister_sse_client(scan_id, q)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@scan_bp.route('/scan/<int:scan_id>/pause', methods=['POST'])
@csrf.exempt
@login_required
def pause(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return jsonify({'success': False})
    manager = ScanManager.get_instance()
    success = manager.pause_scan(scan_id)
    return jsonify({'success': success})

@scan_bp.route('/scan/<int:scan_id>/resume', methods=['POST'])
@csrf.exempt
@login_required
def resume(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return jsonify({'success': False})
    manager = ScanManager.get_instance()
    success = manager.resume_scan(scan_id)
    return jsonify({'success': success})

@scan_bp.route('/scan/<int:scan_id>/stop', methods=['POST'])
@csrf.exempt
@login_required
def stop(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not user_can_access_scan(scan, session.get('user_id')):
        return jsonify({'success': False})
    manager = ScanManager.get_instance()
    success = manager.stop_scan(scan_id)
    return jsonify({'success': success})
