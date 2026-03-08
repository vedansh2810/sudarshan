from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, Response
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.scanner.scan_manager import ScanManager
from app.config import Config
from app.utils.auth_utils import login_required
from app import limiter, csrf
import json
import time

scan_bp = Blueprint('scan', __name__)


@scan_bp.route('/scan/new', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
@login_required
def new_scan():
    if request.method == 'POST':
        target_url = request.form.get('target_url', '').strip()
        scan_mode = request.form.get('scan_mode', 'active')
        scan_speed = request.form.get('scan_speed', 'balanced')
        crawl_depth = int(request.form.get('crawl_depth', 3))
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
    if not scan or scan['user_id'] != session['user_id']:
        return redirect(url_for('dashboard.index'))
    return render_template('scan/progress.html', scan=scan)

@scan_bp.route('/scan/<int:scan_id>/stream')
@login_required
def stream(scan_id):
    manager = ScanManager.get_instance()

    if manager.is_redis_mode():
        return _stream_redis(scan_id, manager)
    else:
        return _stream_threading(scan_id, manager)


def _stream_redis(scan_id, manager):
    """SSE streaming via Redis pub/sub (Celery mode)."""
    redis_client = manager.get_redis_client()

    def generate():
        pubsub = None
        try:
            # Replay existing logs from DB
            logs = Scan.get_logs(scan_id)
            for log in logs:
                msg = {
                    'type': 'log',
                    'data': log['message'],
                    'level': log['log_type'],
                    'timestamp': str(log['logged_at'])
                }
                yield f"data: {json.dumps(msg)}\n\n"

            # Replay existing findings from DB
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
                yield f"data: {json.dumps(finding_msg)}\n\n"

            # Check if scan is already done
            status = manager.get_status(scan_id)
            if status:
                if status['status'] in ('completed', 'stopped', 'error'):
                    scan = Scan.get_by_id(scan_id)
                    yield f"data: {json.dumps({'type': 'complete', 'data': {'score': scan['score'] if scan else 'N/A', 'scan_id': scan_id}, 'level': 'success'})}\n\n"
                    return
                else:
                    progress_msg = {
                        'type': 'progress',
                        'data': {
                            'phase': 'scanning',
                            'total': status['total_urls'],
                            'tested': status['tested_urls'],
                            'findings': status['findings']
                        },
                        'level': 'info'
                    }
                    yield f"data: {json.dumps(progress_msg)}\n\n"

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

    def generate():
        try:
            # Replay existing logs
            logs = Scan.get_logs(scan_id)
            for log in logs:
                msg = {
                    'type': 'log',
                    'data': log['message'],
                    'level': log['log_type'],
                    'timestamp': str(log['logged_at'])
                }
                yield f"data: {json.dumps(msg)}\n\n"

            # Replay existing findings
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
                yield f"data: {json.dumps(finding_msg)}\n\n"

            # Check if already complete
            status = manager.get_status(scan_id)
            if status:
                if status['status'] in ('completed', 'stopped', 'error'):
                    scan = Scan.get_by_id(scan_id)
                    yield f"data: {json.dumps({'type': 'complete', 'data': {'score': scan['score'] if scan else 'N/A', 'scan_id': scan_id}, 'level': 'success'})}\n\n"
                    return
                else:
                    progress_msg = {
                        'type': 'progress',
                        'data': {
                            'phase': 'scanning',
                            'total': status['total_urls'],
                            'tested': status['tested_urls'],
                            'findings': status['findings']
                        },
                        'level': 'info'
                    }
                    yield f"data: {json.dumps(progress_msg)}\n\n"

            # Stream live events from queue
            while True:
                try:
                    data = q.get(timeout=30)
                    yield data
                    parsed = json.loads(data.replace('data: ', '').strip())
                    if parsed.get('type') == 'complete':
                        break
                except:
                    yield ': heartbeat\n\n'
        finally:
            manager.unregister_sse_client(scan_id, q)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@scan_bp.route('/scan/<int:scan_id>/pause', methods=['POST'])
@csrf.exempt
@login_required
def pause(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan or scan['user_id'] != session['user_id']:
        return jsonify({'success': False})
    manager = ScanManager.get_instance()
    success = manager.pause_scan(scan_id)
    return jsonify({'success': success})

@scan_bp.route('/scan/<int:scan_id>/resume', methods=['POST'])
@csrf.exempt
@login_required
def resume(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan or scan['user_id'] != session['user_id']:
        return jsonify({'success': False})
    manager = ScanManager.get_instance()
    success = manager.resume_scan(scan_id)
    return jsonify({'success': success})

@scan_bp.route('/scan/<int:scan_id>/stop', methods=['POST'])
@csrf.exempt
@login_required
def stop(scan_id):
    scan = Scan.get_by_id(scan_id)
    if not scan or scan['user_id'] != session['user_id']:
        return jsonify({'success': False})
    manager = ScanManager.get_instance()
    success = manager.stop_scan(scan_id)
    return jsonify({'success': success})
