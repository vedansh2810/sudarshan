"""
False Positive Classifier
Ensemble ML model for reducing false positives in vulnerability scan results.
"""
import os
import json
import logging
import numpy as np
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class FalsePositiveClassifier:
    """ML classifier to predict whether a vulnerability finding is a true positive.

    Uses an ensemble of RandomForestClassifier and GradientBoostingClassifier
    (from scikit-learn). Falls back gracefully if dependencies are missing.
    """

    FEATURE_NAMES = [
        'payload_length',
        'payload_special_chars',
        'payload_has_script_tag',
        'payload_has_sql_keyword',
        'payload_has_encoding',
        'baseline_status',
        'baseline_length',
        'test_status',
        'test_length',
        'response_time',
        'status_changed',
        'length_diff',
        'length_ratio',
        'error_count',
        'has_db_error',
        'payload_reflected',
    ]

    def __init__(self):
        self.rf_model = None
        self.gb_model = None
        self.is_trained = False
        self.model_name = None
        self.model_version = None

    def prepare_data_from_db(self, vulnerability_type=None):
        """Load labeled scan attempts from DB and prepare for training.

        Returns:
            Tuple of (X, y) suitable for scikit-learn, or (None, None) if not enough data.
        """
        try:
            import pandas as pd
            from app.models.ml_training import ScanAttempt
        except ImportError as e:
            logger.error(f'ML dependencies missing: {e}')
            return None, None

        labeled = ScanAttempt.get_labeled(vulnerability_type=vulnerability_type)

        if len(labeled) < 20:
            logger.warning(f'Not enough labeled data ({len(labeled)}). Need at least 20.')
            return None, None

        rows = []
        labels = []
        for attempt in labeled:
            feature_dict = json.loads(attempt.features) if isinstance(attempt.features, str) else attempt.features
            row = [feature_dict.get(f, 0) for f in self.FEATURE_NAMES]
            rows.append(row)
            labels.append(1 if attempt.is_true_positive else 0)

        X = np.array(rows, dtype=float)
        y = np.array(labels, dtype=int)

        # Replace NaN/Inf
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

        return X, y

    def train(self, vulnerability_type=None, test_size=0.2):
        """Train the ensemble classifier.

        Returns:
            Dict of training metrics, or None on failure.
        """
        try:
            from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
            from sklearn.model_selection import train_test_split, cross_val_score
            from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
        except ImportError:
            logger.error('scikit-learn not installed. Run: pip install scikit-learn')
            return None

        X, y = self.prepare_data_from_db(vulnerability_type)
        if X is None:
            return None

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y if len(np.unique(y)) > 1 else None,
        )

        # Train Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced',
        )
        self.rf_model.fit(X_train, y_train)

        # Train Gradient Boosting
        self.gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
        )
        self.gb_model.fit(X_train, y_train)

        # Evaluate
        rf_pred = self.rf_model.predict(X_test)
        gb_pred = self.gb_model.predict(X_test)

        # Ensemble: majority vote
        ensemble_pred = np.round((rf_pred + gb_pred) / 2).astype(int)

        metrics = {
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'training_accuracy': float(accuracy_score(y_train, self.rf_model.predict(X_train))),
            'test_accuracy': float(accuracy_score(y_test, ensemble_pred)),
            'f1_score': float(f1_score(y_test, ensemble_pred, zero_division=0)),
        }

        # ROC AUC (only if both classes present)
        if len(np.unique(y_test)) > 1:
            rf_proba = self.rf_model.predict_proba(X_test)[:, 1]
            gb_proba = self.gb_model.predict_proba(X_test)[:, 1]
            ensemble_proba = (rf_proba + gb_proba) / 2
            metrics['roc_auc'] = float(roc_auc_score(y_test, ensemble_proba))
        else:
            metrics['roc_auc'] = 0.0

        # Cross-validation
        cv_scores = cross_val_score(self.rf_model, X, y, cv=min(5, len(y)), scoring='f1')
        metrics['cv_f1_mean'] = float(np.mean(cv_scores))
        metrics['cv_f1_std'] = float(np.std(cv_scores))

        # Feature importances
        metrics['feature_importances'] = dict(
            zip(self.FEATURE_NAMES, self.rf_model.feature_importances_.tolist())
        )

        self.is_trained = True
        return metrics

    def save(self, model_dir, version=None):
        """Save trained models to disk and record in DB.

        Args:
            model_dir: Directory to save model files.
            version: Optional version string.

        Returns:
            Model path string.
        """
        try:
            import joblib
        except ImportError:
            logger.error('joblib not installed.')
            return None

        if not self.is_trained:
            logger.error('No trained model to save.')
            return None

        os.makedirs(model_dir, exist_ok=True)
        version = version or datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        model_path = os.path.join(model_dir, f'fp_classifier_v{version}.joblib')

        joblib.dump({
            'rf_model': self.rf_model,
            'gb_model': self.gb_model,
            'feature_names': self.FEATURE_NAMES,
            'version': version,
            'saved_at': datetime.now(timezone.utc).isoformat(),
        }, model_path)

        self.model_name = 'false_positive_classifier'
        self.model_version = version
        logger.info(f'Model saved to {model_path}')
        return model_path

    def load(self, model_path):
        """Load a previously saved model.

        Args:
            model_path: Path to the saved .joblib file.

        Returns:
            True if loaded successfully, False otherwise.
        """
        try:
            import joblib
        except ImportError:
            logger.error('joblib not installed.')
            return False

        if not os.path.exists(model_path):
            logger.error(f'Model file not found: {model_path}')
            return False

        try:
            data = joblib.load(model_path)
            self.rf_model = data['rf_model']
            self.gb_model = data['gb_model']
            self.is_trained = True
            self.model_version = data.get('version', 'unknown')
            logger.info(f'Model loaded from {model_path} (v{self.model_version})')
            return True
        except Exception as e:
            logger.error(f'Failed to load model: {e}')
            return False

    def predict(self, features_dict):
        """Predict if a finding is a true positive.

        Args:
            features_dict: Dict with feature values matching FEATURE_NAMES.

        Returns:
            Tuple (is_true_positive: bool, confidence: float 0-100).
            Returns (True, 50.0) if model is not trained (pass-through).
        """
        if not self.is_trained:
            return True, 50.0  # Default: assume true positive

        try:
            feature_values = [features_dict.get(f, 0) for f in self.FEATURE_NAMES]
            X = np.array([feature_values], dtype=float)
            X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

            rf_proba = self.rf_model.predict_proba(X)[0, 1]
            gb_proba = self.gb_model.predict_proba(X)[0, 1]

            # Ensemble average
            avg_proba = (rf_proba + gb_proba) / 2
            is_tp = avg_proba >= 0.5
            confidence = abs(avg_proba - 0.5) * 200  # Scale 0-100

            return bool(is_tp), float(min(confidence, 100.0))
        except Exception as e:
            logger.debug(f'ML prediction failed (non-fatal): {e}')
            return True, 50.0
