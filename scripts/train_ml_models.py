#!/usr/bin/env python3
"""
ML Model Training Pipeline for Sudarshan
Trains the false positive classifier from labeled scan data.

Usage:
    python scripts/train_ml_models.py
"""
import os
import sys

# Ensure project root is on path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from app import create_app
from app.ml.false_positive_classifier import FalsePositiveClassifier
from app.models.ml_training import ScanAttempt, MLModel


def main():
    print('=' * 60)
    print('  Sudarshan — ML Model Training Pipeline')
    print('=' * 60)

    app = create_app()
    with app.app_context():
        # Check data availability
        stats = ScanAttempt.get_statistics()
        print(f'\nTraining Data Summary:')
        print(f'   Total attempts:  {stats["total_attempts"]}')
        print(f'   Labeled:         {stats["labeled_attempts"]}')
        print(f'   True positives:  {stats["true_positives"]}')
        print(f'   False positives: {stats["false_positives"]}')

        if stats['labeled_attempts'] < 20:
            print(f'\n[X] Not enough labeled data ({stats["labeled_attempts"]}/20 minimum).')
            print('   Label more samples at /ml/labeling')
            sys.exit(1)

        if stats['true_positives'] == 0 or stats['false_positives'] == 0:
            print('\n[X] Need both true positives and false positives for training.')
            print('   Currently: TP={}, FP={}'.format(stats['true_positives'], stats['false_positives']))
            sys.exit(1)

        # Train the classifier
        print('\n[*] Training false positive classifier...')
        classifier = FalsePositiveClassifier()
        metrics = classifier.train()

        if not metrics:
            print('\n[X] Training failed. Check logs for details.')
            sys.exit(1)

        print(f'\n[OK] Training Complete:')
        print(f'   Training samples:  {metrics["training_samples"]}')
        print(f'   Test samples:      {metrics["test_samples"]}')
        print(f'   Training accuracy: {metrics["training_accuracy"]:.3f}')
        print(f'   Test accuracy:     {metrics["test_accuracy"]:.3f}')
        print(f'   F1 Score:          {metrics["f1_score"]:.3f}')
        print(f'   ROC AUC:           {metrics["roc_auc"]:.3f}')
        print(f'   CV F1 (mean+/-std): {metrics["cv_f1_mean"]:.3f} +/- {metrics["cv_f1_std"]:.3f}')

        # Top features
        importances = metrics.get('feature_importances', {})
        if importances:
            sorted_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)
            print(f'\nTop 5 Features:')
            for feat, imp in sorted_features[:5]:
                print(f'   {feat:30s} {imp:.4f}')

        # Save model
        model_dir = os.path.join(project_root, 'data', 'ml_models')
        model_path = classifier.save(model_dir)

        if model_path:
            print(f'\n[SAVED] Model saved to: {model_path}')

            # Record in DB
            db_model = MLModel.create(
                name='false_positive_classifier',
                version=classifier.model_version,
                model_type='false_positive_classifier',
                metrics=metrics,
                features=FalsePositiveClassifier.FEATURE_NAMES,
                hyperparams={
                    'rf_n_estimators': 100,
                    'rf_max_depth': 10,
                    'gb_n_estimators': 100,
                    'gb_max_depth': 5,
                    'gb_learning_rate': 0.1,
                },
                model_path=model_path,
            )

            # Activate
            MLModel.set_active(db_model.id)
            print(f'   Model ID: {db_model.id} (ACTIVE)')
        else:
            print('\n[X] Failed to save model.')
            sys.exit(1)

    print(f'\n{"=" * 60}')
    print('  Training pipeline complete!')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
