from app.models.database import db, ScanModel, ScanLogModel
from datetime import datetime, timezone
from sqlalchemy import func, or_


class Scan:
    """Scan operations backed by SQLAlchemy ORM.
    Keeps the same static method API used by routes and scan_manager."""

    @staticmethod
    def _row_to_dict(scan):
        """Convert a ScanModel to dict matching old sqlite3.Row interface."""
        if scan is None:
            return None
        return {c.name: getattr(scan, c.name) for c in ScanModel.__table__.columns}

    @staticmethod
    def create(user_id, target_url, scan_mode='active', scan_speed='balanced',
               crawl_depth=3, org_id=None):
        scan = ScanModel(
            user_id=user_id,
            org_id=org_id,
            target_url=target_url,
            scan_mode=scan_mode,
            scan_speed=scan_speed,
            crawl_depth=crawl_depth,
            status='pending'
        )
        db.session.add(scan)
        db.session.commit()
        return scan.id

    @staticmethod
    def get_by_id(scan_id):
        return Scan._row_to_dict(db.session.get(ScanModel, scan_id))

    @staticmethod
    def get_by_id_for_user(scan_id, user_id):
        """Get scan by ID with ownership/org-membership check.
        Returns scan dict if user has access, else None."""
        scan = db.session.get(ScanModel, scan_id)
        if not scan:
            return None
        if scan.user_id == user_id:
            return Scan._row_to_dict(scan)
        # Check org membership
        if scan.org_id:
            from app.models.organization import Organization
            if Organization.user_has_access(scan.org_id, user_id):
                return Scan._row_to_dict(scan)
        return None

    @staticmethod
    def for_user_query(user_id):
        """Base query returning scans the user can access (own + org shared)."""
        from app.models.organization import Organization
        org_ids = Organization.get_user_org_ids(user_id)
        if org_ids:
            return ScanModel.query.filter(
                or_(
                    ScanModel.user_id == user_id,
                    ScanModel.org_id.in_(org_ids)
                )
            )
        return ScanModel.query.filter_by(user_id=user_id)

    @staticmethod
    def get_recent(user_id, limit=10):
        scans = Scan.for_user_query(user_id) \
            .order_by(ScanModel.started_at.desc()).limit(limit).all()
        return [Scan._row_to_dict(s) for s in scans]

    @staticmethod
    def get_stats(user_id):
        """Get scan stats for user (includes org-shared scans)."""
        base_query = Scan.for_user_query(user_id)
        total = base_query.count()

        # Build a subquery of accessible scan IDs for aggregation
        accessible_ids = base_query.with_entities(ScanModel.id).subquery()
        vulns = db.session.query(
            func.sum(ScanModel.critical_count),
            func.sum(ScanModel.high_count),
            func.sum(ScanModel.medium_count),
            func.sum(ScanModel.low_count)
        ).filter(ScanModel.id.in_(db.session.query(accessible_ids.c.id))).first()

        total_dict = {'cnt': total or 0}
        vulns_dict = {
            'crit': (vulns[0] or 0) if vulns else 0,
            'high': (vulns[1] or 0) if vulns else 0,
            'med': (vulns[2] or 0) if vulns else 0,
            'low': (vulns[3] or 0) if vulns else 0,
        }
        return total_dict, vulns_dict

    @staticmethod
    def update_status(scan_id, status):
        """Update scan status using direct UPDATE (no ORM load overhead)."""
        db.session.query(ScanModel).filter_by(id=scan_id).update(
            {'status': status}
        )
        db.session.commit()

    @staticmethod
    def update_progress(scan_id, tested_urls, vuln_count):
        """Update progress counters using direct UPDATE (no ORM load overhead)."""
        db.session.query(ScanModel).filter_by(id=scan_id).update(
            {'tested_urls': tested_urls, 'vuln_count': vuln_count}
        )
        db.session.commit()

    @staticmethod
    def complete(scan_id, score, duration, total_urls, critical, high, medium, low):
        scan = db.session.get(ScanModel, scan_id)
        if scan:
            scan.status = 'completed'
            scan.score = score
            scan.duration = duration
            scan.total_urls = total_urls
            scan.vuln_count = critical + high + medium + low
            scan.critical_count = critical
            scan.high_count = high
            scan.medium_count = medium
            scan.low_count = low
            scan.completed_at = datetime.now(timezone.utc)
            db.session.commit()

    @staticmethod
    def get_logs(scan_id):
        logs = ScanLogModel.query.filter_by(scan_id=scan_id) \
            .order_by(ScanLogModel.logged_at.asc()).all()
        return [{c.name: getattr(l, c.name) for c in ScanLogModel.__table__.columns} for l in logs]

    @staticmethod
    def add_log(scan_id, message, log_type='info'):
        log = ScanLogModel(scan_id=scan_id, log_type=log_type, message=message)
        db.session.add(log)
        db.session.commit()

    @staticmethod
    def add_logs_batch(scan_id, messages):
        """Batch-insert multiple log entries with a single commit.
        
        Args:
            scan_id: The scan ID.
            messages: List of (message, log_type) tuples or plain strings.
        """
        if not messages:
            return
        logs = []
        for msg in messages:
            if isinstance(msg, tuple):
                logs.append(ScanLogModel(scan_id=scan_id, message=msg[0], log_type=msg[1]))
            else:
                logs.append(ScanLogModel(scan_id=scan_id, message=str(msg), log_type='info'))
        db.session.add_all(logs)
        db.session.commit()

    @staticmethod
    def update_total_urls(scan_id, total_urls):
        """Update only the total_urls count using direct UPDATE."""
        db.session.query(ScanModel).filter_by(id=scan_id).update(
            {'total_urls': total_urls}
        )
        db.session.commit()

    @staticmethod
    def recover_orphaned(max_age_minutes=10):
        """Reset scans stuck in 'running'/'pending' after a server restart.

        Any scan older than max_age_minutes that is still 'running' or
        'pending' is assumed to have been orphaned by a crash.
        """
        import logging
        logger = logging.getLogger(__name__)
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
        orphaned = ScanModel.query.filter(
            ScanModel.status.in_(['running', 'pending']),
            ScanModel.started_at < cutoff
        ).all()
        for scan in orphaned:
            scan.status = 'error'
            log = ScanLogModel(
                scan_id=scan.id,
                log_type='error',
                message='[!] Scan terminated: server restarted while scan was in progress'
            )
            db.session.add(log)
            logger.warning(f"Recovered orphaned scan {scan.id} (was '{scan.status}')")
        if orphaned:
            db.session.commit()
            logger.info(f"Recovered {len(orphaned)} orphaned scan(s)")
        return len(orphaned)

    @staticmethod
    def delete(scan_id):
        scan = db.session.get(ScanModel, scan_id)
        if scan:
            # Cascade deletes vulnerabilities, crawled_urls, scan_logs
            db.session.delete(scan)
            db.session.commit()

    @staticmethod
    def delete_by_org(org_id):
        """Delete all scans belonging to an organization (GDPR tenant purge).
        Cascading relationships handle vulnerabilities, logs, crawled_urls."""
        scans = ScanModel.query.filter_by(org_id=org_id).all()
        count = len(scans)
        for scan in scans:
            db.session.delete(scan)
        if count:
            db.session.commit()
        return count
