"""
ML Admin Routes — labeling interface, stats, data export, vulnerability labeling, retraining.

All routes require login.
"""
from flask import Blueprint, render_template, request, jsonify, session
from app.utils.auth_utils import login_required
from app.models.ml_training import ScanAttempt
import logging

logger = logging.getLogger(__name__)

ml_admin_bp = Blueprint('ml_admin', __name__)


@ml_admin_bp.route('/ml/labeling')
@login_required
def labeling():
    """Show unlabeled scan attempts for manual verification."""
    vuln_type = request.args.get('type')
    attempts = ScanAttempt.get_unlabeled(limit=50, vulnerability_type=vuln_type)
    stats = ScanAttempt.get_statistics()
    return render_template(
        'ml_admin/labeling.html',
        attempts=attempts,
        stats=stats,
        selected_type=vuln_type,
    )


@ml_admin_bp.route('/ml/label/<int:attempt_id>', methods=['POST'])
@login_required
def label_attempt(attempt_id):
    """Label a scan attempt as true/false positive."""
    data = request.get_json()
    if not data or 'is_true_positive' not in data:
        return jsonify({'error': 'Missing is_true_positive field'}), 400

    is_tp = bool(data['is_true_positive'])
    notes = data.get('notes', '')
    verified_by = session.get('username', 'unknown')

    attempt = ScanAttempt.label(attempt_id, is_tp, verified_by, notes)
    if attempt:
        return jsonify({
            'success': True,
            'attempt_id': attempt.id,
            'label': 'true_positive' if is_tp else 'false_positive',
        })
    return jsonify({'error': 'Attempt not found'}), 404


@ml_admin_bp.route('/ml/stats')
@login_required
def stats():
    """Show ML training statistics."""
    statistics = ScanAttempt.get_statistics()
    return render_template('ml_admin/stats.html', stats=statistics)


@ml_admin_bp.route('/ml/export')
@login_required
def export_data():
    """Export labeled data as JSON."""
    vuln_type = request.args.get('type')
    labeled = ScanAttempt.get_labeled(vulnerability_type=vuln_type)
    return jsonify({
        'count': len(labeled),
        'data': [a.to_dict() for a in labeled],
    })


# ── Vulnerability Finding Labeling ───────────────────────────────────

@ml_admin_bp.route('/ml/findings')
@login_required
def findings_for_labeling():
    """List vulnerability findings for TP/FP labeling."""
    from app.models.database import VulnerabilityModel
    page = request.args.get('page', 1, type=int)
    per_page = 20
    vuln_type = request.args.get('type')

    query = VulnerabilityModel.query
    if vuln_type:
        query = query.filter_by(vuln_type=vuln_type)

    vulns = query.order_by(VulnerabilityModel.id.desc()) \
                 .limit(per_page).offset((page - 1) * per_page).all()

    results = []
    for v in vulns:
        results.append({
            'id': v.id,
            'scan_id': v.scan_id,
            'vuln_type': v.vuln_type,
            'name': v.name,
            'severity': v.severity,
            'affected_url': v.affected_url,
            'parameter': v.parameter,
            'payload': (v.payload or '')[:200],
            'likely_false_positive': v.likely_false_positive or False,
            'fp_confidence': v.fp_confidence,
        })

    return jsonify({
        'page': page,
        'per_page': per_page,
        'count': len(results),
        'findings': results,
    })


@ml_admin_bp.route('/ml/label-vuln/<int:vuln_id>', methods=['POST'])
@login_required
def label_vulnerability(vuln_id):
    """Label a vulnerability finding as true/false positive.

    Sets likely_false_positive on the vulnerability and optionally
    creates a ScanAttempt record for ML retraining.
    """
    from app.models.database import db, VulnerabilityModel
    data = request.get_json()
    if not data or 'is_true_positive' not in data:
        return jsonify({'error': 'Missing is_true_positive field'}), 400

    vuln = db.session.get(VulnerabilityModel, vuln_id)
    if not vuln:
        return jsonify({'error': 'Vulnerability not found'}), 404

    is_tp = bool(data['is_true_positive'])
    vuln.likely_false_positive = not is_tp
    vuln.fp_confidence = 1.0 if data.get('confident', True) else 0.8
    db.session.commit()

    # Also create a ScanAttempt record for ML training
    try:
        ScanAttempt.create(
            scan_id=vuln.scan_id,
            url=vuln.affected_url or '',
            parameter=vuln.parameter or '',
            payload=(vuln.payload or '')[:500],
            vulnerability_type=vuln.vuln_type,
            scanner_module='manual_label',
            is_true_positive=is_tp,
            verified_by=session.get('username', 'admin'),
            notes=data.get('notes', f'Manually labeled via ML admin'),
        )
    except Exception as e:
        logger.debug(f'ScanAttempt creation skipped: {e}')

    return jsonify({
        'success': True,
        'vuln_id': vuln_id,
        'label': 'true_positive' if is_tp else 'false_positive',
    })


@ml_admin_bp.route('/ml/retrain', methods=['POST'])
@login_required
def retrain_model():
    """Trigger ML classifier retraining from labeled data."""
    try:
        from app.ml.false_positive_classifier import FalsePositiveClassifier
        classifier = FalsePositiveClassifier()

        # Prepare data from labeled ScanAttempts
        data = classifier.prepare_training_data()
        if not data or len(data.get('X', [])) < 10:
            return jsonify({
                'error': 'Not enough labeled data for training (need at least 10 samples)',
                'current_samples': len(data.get('X', [])) if data else 0,
            }), 400

        # Train
        metrics = classifier.train(data['X'], data['y'])

        # Save model
        import pathlib
        from datetime import datetime
        model_dir = pathlib.Path('data/ml_models')
        model_dir.mkdir(parents=True, exist_ok=True)
        version = datetime.now().strftime('%Y%m%d_%H%M%S')
        model_path = model_dir / f'fp_classifier_v{version}.joblib'
        classifier.save(str(model_path))

        # Reload in SmartEngine
        try:
            from app.ai.smart_engine import get_smart_engine
            engine = get_smart_engine()
            engine._ml_loaded = False  # Force reload
            engine._ml_classifier = None
        except Exception:
            pass

        return jsonify({
            'success': True,
            'model_path': str(model_path),
            'metrics': metrics,
        })
    except Exception as e:
        logger.error(f'ML retraining failed: {e}')
        return jsonify({'error': str(e)}), 500
