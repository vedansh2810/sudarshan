#!/usr/bin/env python3
"""
PortSwigger Lab Auto-Trainer
Automatically generate labeled ML training data from lab solutions.

Produces 10,000+ pre-labeled samples by:
  1. Loading working payloads from PortSwigger lab solutions (TRUE POSITIVES)
  2. Generating mutated payloads that won't work (FALSE POSITIVES)
  3. Extracting ML features matching FalsePositiveClassifier.FEATURE_NAMES
  4. Storing everything in the database with ground truth labels

Usage:
    python scripts/portswigger_auto_trainer.py
"""
import os
import sys
import json
import random
import hashlib
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is on path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from app import create_app
from app.ml.false_positive_classifier import FalsePositiveClassifier


# ── Category → vulnerability type mapping ───────────────────────────────
CATEGORY_MAPPING = {
    'sql-injection': 'sql_injection',
    'cross-site-scripting': 'xss',
    'os-command-injection': 'command_injection',
    'directory-traversal': 'directory_traversal',
    'file-path-traversal': 'directory_traversal',
    'xxe': 'xxe',
    'xml-external-entity-xxe-injection': 'xxe',
    'ssrf': 'ssrf',
    'server-side-request-forgery-ssrf': 'ssrf',
    'cross-site-request-forgery-csrf': 'csrf',
    'access-control-vulnerabilities': 'access_control',
    'access-control': 'access_control',
    'authentication': 'authentication',
    'authentication-vulnerabilities': 'authentication',
    'business-logic-vulnerabilities': 'business_logic',
    'information-disclosure': 'information_disclosure',
    'dom-based-vulnerabilities': 'xss',
    'insecure-deserialization': 'deserialization',
    'race-conditions': 'race_condition',
    'server-side-template-injection': 'ssti',
    'web-cache-poisoning': 'cache_poisoning',
    'http-request-smuggling': 'request_smuggling',
    'oauth-authentication': 'oauth',
    'jwt': 'jwt',
    'jwt-attacks': 'jwt',
    'prototype-pollution': 'prototype_pollution',
    'clickjacking': 'clickjacking',
    'cors': 'cors',
    'websockets': 'websockets',
    'graphql-api-vulnerabilities': 'graphql',
    'api-testing': 'api_testing',
    'file-upload-vulnerabilities': 'file_upload',
    'nosql-injection': 'nosql_injection',
    'web-llm-attacks': 'llm_attacks',
}


class PortSwiggerLabTrainer:
    """
    Generate ML training data from PortSwigger lab solutions.

    Creates true positives (working payloads) and false positives
    (mutated payloads) with features matching FalsePositiveClassifier.FEATURE_NAMES.
    """

    # Features must match FalsePositiveClassifier.FEATURE_NAMES exactly
    FEATURE_NAMES = FalsePositiveClassifier.FEATURE_NAMES

    def __init__(self, knowledge_base_path=None):
        """Load the PortSwigger knowledge base."""
        if knowledge_base_path is None:
            knowledge_base_path = os.path.join(
                project_root, 'data', 'portswigger_knowledge', 'portswigger_knowledge.json'
            )
        self.knowledge_base_path = Path(knowledge_base_path)

        if not self.knowledge_base_path.exists():
            raise FileNotFoundError(
                f"Knowledge base not found: {self.knowledge_base_path}\n"
                "Run Task 1 first: python scripts/portswigger_scraper.py"
            )

        with open(self.knowledge_base_path, 'r', encoding='utf-8') as f:
            self.knowledge_base = json.load(f)

        self.labs = self.knowledge_base.get('labs', [])
        print(f"[+] Loaded {len(self.labs)} labs from knowledge base")

        # Track created payloads to avoid duplicates
        self._seen_hashes = set()
        self._stats = {
            'true_positives': 0,
            'false_positives': 0,
            'skipped_short': 0,
            'skipped_duplicate': 0,
            'errors': 0,
        }

    # ── Feature Extraction ──────────────────────────────────────────────

    def _extract_features(self, payload, lab, is_true_positive):
        """
        Extract 16 ML features matching FalsePositiveClassifier.FEATURE_NAMES.

        Features:
          payload_length, payload_special_chars, payload_has_script_tag,
          payload_has_sql_keyword, payload_has_encoding,
          baseline_status, baseline_length,
          test_status, test_length, response_time,
          status_changed, length_diff, length_ratio,
          error_count, has_db_error, payload_reflected
        """
        category = lab.get('category', '')
        difficulty = lab.get('difficulty', 'apprentice')

        # ── Payload-derived features ──
        payload_length = len(payload)
        payload_special_chars = sum(1 for c in payload if not c.isalnum() and c != ' ')
        payload_has_script_tag = int('<script' in payload.lower() or 'javascript:' in payload.lower())
        payload_has_sql_keyword = int(any(
            kw in payload.upper()
            for kw in ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
                       'OR 1=1', "OR '1'='1", 'SLEEP', 'WAITFOR', 'BENCHMARK']
        ))
        payload_has_encoding = int('%' in payload or '\\u' in payload or '&#' in payload)

        # ── Simulated response features (based on ground truth) ──
        baseline_status = 200
        baseline_length = random.randint(5000, 15000)

        if is_true_positive:
            # Successful exploit — response differs from baseline
            if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                test_status = 200
                test_length = baseline_length + random.randint(-50, 50)
                response_time = random.uniform(3.0, 6.0)
            elif payload_has_sql_keyword:
                test_status = random.choice([200, 200, 200, 500])
                length_delta = random.randint(100, 2000)
                test_length = baseline_length + length_delta
                response_time = random.uniform(0.1, 0.5)
            elif payload_has_script_tag:
                test_status = 200
                test_length = baseline_length + len(payload)
                response_time = random.uniform(0.05, 0.3)
            else:
                test_status = random.choice([200, 302])
                test_length = baseline_length + random.randint(50, 500)
                response_time = random.uniform(0.1, 0.5)

            # Error patterns — more for easier labs
            if difficulty == 'apprentice':
                error_count = random.randint(1, 4)
            elif difficulty == 'practitioner':
                error_count = random.randint(0, 2)
            else:
                error_count = random.randint(0, 1)

            has_db_error = int(payload_has_sql_keyword and difficulty != 'expert')
            payload_reflected = int(
                category in ('cross-site-scripting', 'dom-based-vulnerabilities')
                or (payload_has_sql_keyword and random.random() > 0.3)
            )
        else:
            # Mutated/broken payload — response similar to baseline
            test_status = random.choice([200, 200, 200, 400, 403])
            test_length = baseline_length + random.randint(-30, 30)
            response_time = random.uniform(0.05, 0.3)
            error_count = random.randint(0, 1)
            has_db_error = 0
            payload_reflected = int(random.random() > 0.85)

        status_changed = int(test_status != baseline_status)
        length_diff = abs(test_length - baseline_length)
        length_ratio = test_length / baseline_length if baseline_length > 0 else 1.0

        return {
            'payload_length': payload_length,
            'payload_special_chars': payload_special_chars,
            'payload_has_script_tag': payload_has_script_tag,
            'payload_has_sql_keyword': payload_has_sql_keyword,
            'payload_has_encoding': payload_has_encoding,
            'baseline_status': baseline_status,
            'baseline_length': baseline_length,
            'test_status': test_status,
            'test_length': test_length,
            'response_time': response_time,
            'status_changed': status_changed,
            'length_diff': length_diff,
            'length_ratio': length_ratio,
            'error_count': error_count,
            'has_db_error': has_db_error,
            'payload_reflected': payload_reflected,
        }

    # ── Negative Payload Generation ─────────────────────────────────────

    def _generate_negative_payloads(self, positive_payload, lab_title=''):
        """
        Generate mutated payloads that won't work (false positives).

        Returns 10+ diverse mutations; callers take 8.
        """
        negatives = []
        salt = lab_title[:10]  # Lab-specific salt for uniqueness

        # 1. Remove critical quotes/chars
        if "'" in positive_payload:
            negatives.append(positive_payload.replace("'", ""))
        elif '"' in positive_payload:
            negatives.append(positive_payload.replace('"', ''))
        else:
            negatives.append(positive_payload + '_noquote')

        # 2. Flip logical operators
        if ' OR ' in positive_payload.upper():
            negatives.append(positive_payload.replace(' OR ', ' AND NOT ', 1)
                             .replace(' or ', ' and not ', 1))
        if ' AND ' in positive_payload.upper():
            negatives.append(positive_payload.replace(' AND ', ' XNOR ', 1)
                             .replace(' and ', ' xnor ', 1))

        # 3. URL-encode everything (breaks most exploits)
        negatives.append(urllib.parse.quote(positive_payload, safe=''))

        # 4. Truncate to half (incomplete payload)
        if len(positive_payload) > 6:
            negatives.append(positive_payload[:len(positive_payload) // 2])

        # 5. Add garbage suffix that breaks syntax
        negatives.append(positive_payload + 'XXXINVALID###')

        # 6. Swap case (breaks case-sensitive exploits)
        swapped = positive_payload.swapcase()
        if swapped != positive_payload:
            negatives.append(swapped)

        # 7. Comment out the exploit
        negatives.append('/* ' + positive_payload + ' */')

        # 8. Double-encode
        negatives.append(urllib.parse.quote(
            urllib.parse.quote(positive_payload, safe=''), safe=''))

        # 9. Prefix with benign text (breaks injection context)
        negatives.append('safe_input_' + salt + '_' + positive_payload)

        # 10. Truncate to first third
        if len(positive_payload) > 9:
            negatives.append(positive_payload[:len(positive_payload) // 3])

        # 11. Reverse the payload
        negatives.append(positive_payload[::-1])

        # 12. Replace special chars with underscores
        sanitized = ''.join(c if c.isalnum() else '_' for c in positive_payload)
        negatives.append(sanitized)

        # 13. Wrap in HTML-encoded container
        negatives.append('&lt;' + positive_payload + '&gt;')

        # 14. Add random noise in the middle
        mid = len(positive_payload) // 2
        negatives.append(positive_payload[:mid] + '_BROKEN_' + salt + positive_payload[mid:])

        return negatives

    # ── Technique Extraction ────────────────────────────────────────────

    def _extract_technique(self, payload, category):
        """Determine the attack technique from payload content."""
        p_upper = payload.upper()

        if category == 'sql-injection':
            if 'UNION' in p_upper:
                return 'union-based'
            if 'SLEEP' in p_upper or 'WAITFOR' in p_upper or 'BENCHMARK' in p_upper:
                return 'time-based-blind'
            if '1=1' in payload or "'1'='1'" in payload:
                return 'boolean-blind'
            return 'error-based'
        elif category in ('cross-site-scripting', 'dom-based-vulnerabilities'):
            if '<script' in payload.lower():
                return 'script-tag'
            if 'onerror' in payload.lower() or 'onload' in payload.lower():
                return 'event-handler'
            if 'javascript:' in payload.lower():
                return 'protocol-handler'
            return 'reflected-xss'
        elif category == 'os-command-injection':
            if '|' in payload:
                return 'pipe-injection'
            if '&&' in payload:
                return 'command-chaining'
            if ';' in payload:
                return 'semicolon-injection'
            return 'direct-injection'
        elif category in ('directory-traversal', 'file-path-traversal'):
            if 'php://' in payload.lower():
                return 'php-wrapper'
            if '%' in payload:
                return 'encoded-traversal'
            return 'basic-traversal'
        elif category in ('xxe', 'xml-external-entity-xxe-injection'):
            if 'SYSTEM' in payload:
                return 'external-entity'
            return 'parameter-entity'
        elif category in ('ssrf', 'server-side-request-forgery-ssrf'):
            if '169.254' in payload:
                return 'cloud-metadata'
            if '127.0.0.1' in payload or 'localhost' in payload:
                return 'localhost-access'
            return 'internal-network'
        return 'standard'

    # ── Hash for deduplication ──────────────────────────────────────────

    def _payload_hash(self, payload, is_tp):
        """Generate unique hash for a (payload, label) pair."""
        key = f"{payload}::{is_tp}"
        return hashlib.md5(key.encode('utf-8', errors='replace')).hexdigest()

    # ── Sample Creation ─────────────────────────────────────────────────

    def _create_sample(self, db, ScanAttempt, scan_id, lab, payload,
                       features, is_true_positive, notes=''):
        """Insert a training sample into the database."""
        # Dedup check
        h = self._payload_hash(payload, is_true_positive)
        if h in self._seen_hashes:
            self._stats['skipped_duplicate'] += 1
            return False
        self._seen_hashes.add(h)

        category = lab.get('category', '')
        vuln_type = CATEGORY_MAPPING.get(category, category.replace('-', '_'))
        technique = self._extract_technique(payload, category)

        try:
            attempt = ScanAttempt(
                scan_id=scan_id,
                url=lab.get('url', 'https://portswigger.net/web-security/lab'),
                parameter='test_param',
                original_value='1',
                payload=payload[:2048],  # truncate very long payloads
                method='GET',
                context='portswigger_lab',
                status_code=features.get('test_status', 200),
                content_length=features.get('test_length', 1000),
                response_time=features.get('response_time', 0.5),
                error_patterns=json.dumps([]),
                reflection_detected=bool(features.get('payload_reflected', False)),
                vulnerability_found=is_true_positive,
                vulnerability_type=vuln_type,
                confidence=0.9 if is_true_positive else 0.2,
                technique=technique,
                severity='high' if is_true_positive else 'info',
                is_true_positive=is_true_positive,
                verified_by='portswigger_academy',
                verification_date=datetime.now(timezone.utc),
                verification_notes=notes,
                features=json.dumps(features),
            )
            db.session.add(attempt)
            return True
        except Exception as e:
            self._stats['errors'] += 1
            print(f"    [!] Error: {e}")
            return False

    # ── Main Generation Loop ────────────────────────────────────────────

    def generate_training_data(self, db, ScanAttempt, scan_id,
                               categories=None, max_labs_per_category=None):
        """
        Generate training data from all labs.

        Args:
            db: SQLAlchemy db instance
            ScanAttempt: ScanAttempt model class
            scan_id: ID of the placeholder scan record
            categories: List of categories to process (None = all)
            max_labs_per_category: Max labs per category (None = all)

        Returns:
            Total samples created
        """
        # Group labs by category
        by_category = {}
        for lab in self.labs:
            cat = lab.get('category', 'unknown')
            by_category.setdefault(cat, []).append(lab)

        if categories:
            by_category = {k: v for k, v in by_category.items() if k in categories}

        total_created = 0

        for cat_idx, (category, labs) in enumerate(sorted(by_category.items()), 1):
            if max_labs_per_category:
                labs = labs[:max_labs_per_category]

            print(f"\n{'='*60}")
            print(f"[{cat_idx}/{len(by_category)}] Category: {category} ({len(labs)} labs)")
            print(f"{'='*60}")

            cat_created = 0

            for i, lab in enumerate(labs, 1):
                payloads = lab.get('payloads', [])
                if not payloads:
                    continue

                title = lab.get('title', 'Unknown')[:55]
                difficulty = lab.get('difficulty', 'unknown')
                print(f"  [{i}/{len(labs)}] {title} ({difficulty}) - {len(payloads)} payloads")

                for payload_obj in payloads:
                    code = payload_obj.get('code', '') if isinstance(payload_obj, dict) else str(payload_obj)

                    # Skip very short or empty payloads
                    if len(code.strip()) < 3:
                        self._stats['skipped_short'] += 1
                        continue

                    # ── TRUE POSITIVE ──
                    tp_features = self._extract_features(code, lab, is_true_positive=True)
                    if self._create_sample(
                        db, ScanAttempt, scan_id, lab, code,
                        tp_features, is_true_positive=True,
                        notes=f"PortSwigger: {lab.get('title', '')} ({difficulty})"
                    ):
                        self._stats['true_positives'] += 1
                        cat_created += 1

                    # ── FALSE POSITIVES (8 per TP) ──
                    negatives = self._generate_negative_payloads(
                        code, lab_title=lab.get('title', ''))
                    for neg in negatives[:8]:
                        fp_features = self._extract_features(neg, lab, is_true_positive=False)
                        if self._create_sample(
                            db, ScanAttempt, scan_id, lab, neg,
                            fp_features, is_true_positive=False,
                            notes=f"Mutated from: {code[:50]}..."
                        ):
                            self._stats['false_positives'] += 1
                            cat_created += 1

                # Commit every 10 labs
                if i % 10 == 0:
                    db.session.commit()
                    print(f"    [checkpoint] {cat_created} samples in this category")

            # Commit remaining
            db.session.commit()
            total_created += cat_created
            print(f"  => {cat_created} samples created for {category}")

        return total_created

    def print_stats(self):
        """Print generation statistics."""
        total = self._stats['true_positives'] + self._stats['false_positives']
        tp = self._stats['true_positives']
        fp = self._stats['false_positives']
        ratio = fp / tp if tp > 0 else 0

        print(f"\n{'='*60}")
        print(f"  Training Data Generation Complete")
        print(f"{'='*60}")
        print(f"  Total samples created:  {total}")
        print(f"  True positives:         {tp}")
        print(f"  False positives:        {fp}")
        print(f"  FP:TP ratio:            {ratio:.1f}:1")
        print(f"  Skipped (short):        {self._stats['skipped_short']}")
        print(f"  Skipped (duplicate):    {self._stats['skipped_duplicate']}")
        print(f"  Errors:                 {self._stats['errors']}")


def _ensure_placeholder_scan(db, ScanModel, UserModel):
    """
    Create a placeholder scan record so the FK constraint on scan_attempts.scan_id
    is satisfied. Returns the scan_id.
    """
    # Check if placeholder already exists
    existing = ScanModel.query.filter_by(
        target_url='https://portswigger.net/web-security'
    ).first()
    if existing:
        print(f"[+] Using existing placeholder scan (id={existing.id})")
        return existing.id

    # Need a user — find or create a system user
    user = UserModel.query.first()
    if not user:
        user = UserModel(
            supabase_uid='system-portswigger-trainer',
            username='system',
            email='system@sudarshan.local',
            is_admin=True,
        )
        db.session.add(user)
        db.session.commit()
        print(f"[+] Created system user (id={user.id})")

    scan = ScanModel(
        user_id=user.id,
        target_url='https://portswigger.net/web-security',
        scan_mode='training',
        scan_speed='fast',
        crawl_depth=0,
        status='completed',
        score='A',
        total_urls=0,
        tested_urls=0,
        vuln_count=0,
    )
    db.session.add(scan)
    db.session.commit()
    print(f"[+] Created placeholder scan (id={scan.id})")
    return scan.id


def main():
    """Main entry point — run the auto-trainer."""
    print('=' * 60)
    print('  PortSwigger Lab Auto-Trainer')
    print('  Generating ML training data from lab solutions')
    print('=' * 60)

    app = create_app()
    with app.app_context():
        from app.models.database import db, ScanModel, UserModel
        from app.models.ml_training import ScanAttempt

        # Ensure placeholder scan exists
        scan_id = _ensure_placeholder_scan(db, ScanModel, UserModel)

        # Check if data already exists
        existing = ScanAttempt.query.filter_by(
            verified_by='portswigger_academy'
        ).count()
        if existing > 0:
            print(f"\n[!] Found {existing} existing PortSwigger samples")
            resp = input("    Delete and regenerate? (y/N): ").strip().lower()
            if resp == 'y':
                ScanAttempt.query.filter_by(
                    verified_by='portswigger_academy'
                ).delete()
                db.session.commit()
                print(f"    Deleted {existing} samples")
            else:
                print("    Keeping existing data. Exiting.")
                return

        # Initialize trainer
        trainer = PortSwiggerLabTrainer()

        # Generate training data for all categories
        total = trainer.generate_training_data(
            db=db,
            ScanAttempt=ScanAttempt,
            scan_id=scan_id,
        )

        trainer.print_stats()

        # Show DB statistics
        stats = ScanAttempt.get_statistics()
        print(f"\n  Database Statistics:")
        print(f"    Total attempts:   {stats['total_attempts']}")
        print(f"    True positives:   {stats['true_positives']}")
        print(f"    False positives:  {stats['false_positives']}")
        print(f"    Unlabeled:        {stats['unlabeled']}")

        if stats['by_type']:
            print(f"\n  By Vulnerability Type:")
            for entry in stats['by_type']:
                print(f"    {entry['type']:25s} {entry['total']:5d} samples ({entry['true_positives']} TP)")

        print(f"\n  Next steps:")
        print(f"    1. Train models: python scripts/train_ml_models.py")
        print(f"    2. Check stats:  http://localhost:5000/ml/stats")


if __name__ == '__main__':
    main()
