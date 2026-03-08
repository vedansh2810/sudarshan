from app.models.database import db, ScanModel, ScanLogModel
from datetime import datetime, timezone
from sqlalchemy import func


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
    def create(user_id, target_url, scan_mode='active', scan_speed='balanced', crawl_depth=3):
        scan = ScanModel(
            user_id=user_id,
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
    def get_recent(user_id, limit=10):
        scans = ScanModel.query.filter_by(user_id=user_id) \
            .order_by(ScanModel.started_at.desc()).limit(limit).all()
        return [Scan._row_to_dict(s) for s in scans]

    @staticmethod
    def get_stats(user_id):
        total = db.session.query(func.count(ScanModel.id)) \
            .filter(ScanModel.user_id == user_id).scalar()
        vulns = db.session.query(
            func.sum(ScanModel.critical_count),
            func.sum(ScanModel.high_count),
            func.sum(ScanModel.medium_count),
            func.sum(ScanModel.low_count)
        ).filter(ScanModel.user_id == user_id).first()

        total_dict = {'cnt': total or 0}
        vulns_dict = {
            'crit': vulns[0] or 0 if vulns else 0,
            'high': vulns[1] or 0 if vulns else 0,
            'med': vulns[2] or 0 if vulns else 0,
            'low': vulns[3] or 0 if vulns else 0,
        }
        return total_dict, vulns_dict

    @staticmethod
    def update_status(scan_id, status):
        scan = db.session.get(ScanModel, scan_id)
        if scan:
            scan.status = status
            db.session.commit()

    @staticmethod
    def update_progress(scan_id, tested_urls, vuln_count):
        scan = db.session.get(ScanModel, scan_id)
        if scan:
            scan.tested_urls = tested_urls
            scan.vuln_count = vuln_count
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
    def delete(scan_id):
        scan = db.session.get(ScanModel, scan_id)
        if scan:
            # Cascade deletes vulnerabilities, crawled_urls, scan_logs
            db.session.delete(scan)
            db.session.commit()
