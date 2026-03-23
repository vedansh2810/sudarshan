"""
ML Training Data Models
Stores scan attempts and features for machine learning.
"""
from app.models.database import db
from datetime import datetime, timezone
import json


class ScanAttempt(db.Model):
    """Records every scan attempt for ML training."""
    __tablename__ = 'scan_attempts'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Request information
    url = db.Column(db.String(2048), nullable=False)
    parameter = db.Column(db.String(255))
    original_value = db.Column(db.Text)
    payload = db.Column(db.Text, nullable=False)
    method = db.Column(db.String(10), default='GET')
    context = db.Column(db.String(50))  # 'query_parameter', 'form_field', 'header', etc.

    # Response information
    status_code = db.Column(db.Integer)
    content_length = db.Column(db.Integer)
    response_time = db.Column(db.Float)  # in seconds
    error_patterns = db.Column(db.Text)  # JSON array
    reflection_detected = db.Column(db.Boolean, default=False)

    # Detection results
    vulnerability_found = db.Column(db.Boolean, default=False, index=True)
    vulnerability_type = db.Column(db.String(50), index=True)
    confidence = db.Column(db.Float)
    technique = db.Column(db.String(100))
    severity = db.Column(db.String(20))

    # Ground truth (manual verification)
    is_true_positive = db.Column(db.Boolean, index=True)  # NULL = unlabeled
    verified_by = db.Column(db.String(100))
    verification_date = db.Column(db.DateTime)
    verification_notes = db.Column(db.Text)

    # ML features (JSON object)
    features = db.Column(db.Text, nullable=False)  # JSON-encoded feature dict

    # Metadata
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationship
    scan = db.relationship('ScanModel', backref=db.backref('attempts', lazy='dynamic'))

    def __repr__(self):
        return f'<ScanAttempt {self.id} - {self.vulnerability_type}>'

    def to_dict(self):
        """Convert to dictionary for ML training."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'url': self.url,
            'parameter': self.parameter,
            'payload': self.payload,
            'method': self.method,
            'context': self.context,
            'status_code': self.status_code,
            'content_length': self.content_length,
            'response_time': self.response_time,
            'error_patterns': json.loads(self.error_patterns) if self.error_patterns else [],
            'reflection_detected': self.reflection_detected,
            'vulnerability_found': self.vulnerability_found,
            'vulnerability_type': self.vulnerability_type,
            'confidence': self.confidence,
            'technique': self.technique,
            'severity': self.severity,
            'is_true_positive': self.is_true_positive,
            'verified_by': self.verified_by,
            'verification_date': self.verification_date.isoformat() if self.verification_date else None,
            'verification_notes': self.verification_notes,
            'features': json.loads(self.features) if self.features else {},
        }

    @classmethod
    def create(cls, scan_id, request_data, response_data, detection_result, features):
        """Create new scan attempt record.

        Args:
            scan_id: Integer ID of the scan.
            request_data: Dict with url, parameter, original_value, payload, method, context.
            response_data: Dict with status_code, content_length, response_time, error_patterns, reflection_detected.
            detection_result: Dict with vulnerability_found, vulnerability_type, confidence, technique, severity.
            features: Dict with extracted ML features.

        Returns:
            ScanAttempt instance.
        """
        attempt = cls(
            scan_id=scan_id,
            # Request
            url=request_data.get('url', ''),
            parameter=request_data.get('parameter'),
            original_value=request_data.get('original_value'),
            payload=request_data.get('payload', ''),
            method=request_data.get('method', 'GET'),
            context=request_data.get('context'),
            # Response
            status_code=response_data.get('status_code'),
            content_length=response_data.get('content_length'),
            response_time=response_data.get('response_time'),
            error_patterns=json.dumps(response_data.get('error_patterns', [])),
            reflection_detected=response_data.get('reflection_detected', False),
            # Detection
            vulnerability_found=detection_result.get('vulnerability_found', False),
            vulnerability_type=detection_result.get('vulnerability_type'),
            confidence=detection_result.get('confidence'),
            technique=detection_result.get('technique'),
            severity=detection_result.get('severity'),
            # Features
            features=json.dumps(features),
        )
        db.session.add(attempt)
        db.session.commit()
        return attempt

    @classmethod
    def label(cls, attempt_id, is_true_positive, verified_by, notes=''):
        """Add ground truth label to attempt."""
        attempt = db.session.get(cls, attempt_id)
        if attempt:
            attempt.is_true_positive = is_true_positive
            attempt.verified_by = verified_by
            attempt.verification_date = datetime.now(timezone.utc)
            attempt.verification_notes = notes
            db.session.commit()
            return attempt
        return None

    @classmethod
    def get_unlabeled(cls, limit=100, vulnerability_type=None):
        """Get unlabeled attempts (detected as vulnerabilities) for manual verification."""
        query = cls.query.filter(
            cls.is_true_positive.is_(None),
            cls.vulnerability_found == True,  # noqa: E712
        )
        if vulnerability_type:
            query = query.filter(cls.vulnerability_type == vulnerability_type)
        return query.order_by(cls.timestamp.desc()).limit(limit).all()

    @classmethod
    def get_labeled(cls, vulnerability_type=None):
        """Get all labeled attempts for training."""
        query = cls.query.filter(cls.is_true_positive.isnot(None))
        if vulnerability_type:
            query = query.filter(cls.vulnerability_type == vulnerability_type)
        return query.all()

    @classmethod
    def get_statistics(cls):
        """Get training data statistics."""
        total = cls.query.count()
        labeled = cls.query.filter(cls.is_true_positive.isnot(None)).count()
        true_positives = cls.query.filter(cls.is_true_positive == True).count()  # noqa: E712
        false_positives = cls.query.filter(cls.is_true_positive == False).count()  # noqa: E712

        # By vulnerability type
        by_type = db.session.query(
            cls.vulnerability_type,
            db.func.count(cls.id).label('total'),
            db.func.sum(db.case((cls.is_true_positive == True, 1), else_=0)).label('tp_count'),  # noqa: E712
        ).filter(
            cls.vulnerability_type.isnot(None),
        ).group_by(cls.vulnerability_type).all()

        return {
            'total_attempts': total,
            'labeled_attempts': labeled,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'unlabeled': total - labeled,
            'by_type': [
                {'type': vtype, 'total': cnt, 'true_positives': tp_count or 0}
                for vtype, cnt, tp_count in by_type
            ],
        }


class MLModel(db.Model):
    """Tracks ML model versions and metadata."""
    __tablename__ = 'ml_models'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, index=True)
    version = db.Column(db.String(50), nullable=False)
    model_type = db.Column(db.String(50))  # 'false_positive_classifier', etc.

    # Training metadata
    training_samples = db.Column(db.Integer)
    training_accuracy = db.Column(db.Float)
    test_accuracy = db.Column(db.Float)
    f1_score = db.Column(db.Float)
    roc_auc = db.Column(db.Float)

    # Model info
    feature_count = db.Column(db.Integer)
    feature_names = db.Column(db.Text)  # JSON array
    hyperparameters = db.Column(db.Text)  # JSON object

    # Status
    is_active = db.Column(db.Boolean, default=False, index=True)
    is_production = db.Column(db.Boolean, default=False)

    # File paths
    model_path = db.Column(db.String(500))

    # Timestamps
    trained_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    deployed_at = db.Column(db.DateTime)

    # Metadata
    notes = db.Column(db.Text)
    trained_by = db.Column(db.String(100))

    def __repr__(self):
        return f'<MLModel {self.name} v{self.version}>'

    @classmethod
    def create(cls, name, version, model_type, metrics, features, hyperparams, model_path, trained_by='system'):
        """Create new model record."""
        model = cls(
            name=name,
            version=version,
            model_type=model_type,
            training_samples=metrics.get('training_samples'),
            training_accuracy=metrics.get('training_accuracy'),
            test_accuracy=metrics.get('test_accuracy'),
            f1_score=metrics.get('f1_score'),
            roc_auc=metrics.get('roc_auc'),
            feature_count=len(features),
            feature_names=json.dumps(features),
            hyperparameters=json.dumps(hyperparams),
            model_path=model_path,
            trained_by=trained_by,
        )
        db.session.add(model)
        db.session.commit()
        return model

    @classmethod
    def set_active(cls, model_id):
        """Set a model as active (deactivate others of same type)."""
        model = db.session.get(cls, model_id)
        if model:
            cls.query.filter(
                cls.model_type == model.model_type,
                cls.id != model_id,
            ).update({'is_active': False})
            model.is_active = True
            model.deployed_at = datetime.now(timezone.utc)
            db.session.commit()
            return model
        return None

    @classmethod
    def get_active(cls, model_type):
        """Get currently active model of given type."""
        return cls.query.filter(
            cls.model_type == model_type,
            cls.is_active == True,  # noqa: E712
        ).first()
