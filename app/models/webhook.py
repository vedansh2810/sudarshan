"""
Webhook model for event-driven notifications.
Sends HTTP POST to registered URLs when scan events occur.
"""
import json
import logging
import threading
import requests
from datetime import datetime, timezone
from flask import current_app
from app.models.database import db

logger = logging.getLogger(__name__)


class Webhook(db.Model):
    """Webhook endpoint for receiving scan notifications."""
    __tablename__ = 'webhooks'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(2048), nullable=False)

    # Event subscriptions
    on_scan_complete = db.Column(db.Boolean, default=True)
    on_vulnerability_found = db.Column(db.Boolean, default=False)
    on_scan_error = db.Column(db.Boolean, default=True)

    is_active = db.Column(db.Boolean, default=True, index=True)
    last_triggered = db.Column(db.DateTime)
    failure_count = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    user = db.relationship('UserModel', backref=db.backref('webhooks', lazy='dynamic'))

    def __repr__(self):
        return f'<Webhook {self.name} -> {self.url[:50]}>'

    @classmethod
    def create(cls, user_id, name, url, on_scan_complete=True, on_vulnerability_found=False, on_scan_error=True):
        """Register a new webhook."""
        webhook = cls(
            user_id=user_id,
            name=name,
            url=url,
            on_scan_complete=on_scan_complete,
            on_vulnerability_found=on_vulnerability_found,
            on_scan_error=on_scan_error,
        )
        db.session.add(webhook)
        db.session.commit()
        return webhook

    @classmethod
    def trigger(cls, user_id, event_type, data):
        """Trigger all matching webhooks for a user.

        Args:
            user_id: Owner of the webhooks.
            event_type: One of 'scan_complete', 'vulnerability_found', 'scan_error'.
            data: Payload dict to send.

        Webhooks are fired in background threads so they don't block scanning.
        """
        event_field_map = {
            'scan_complete': 'on_scan_complete',
            'vulnerability_found': 'on_vulnerability_found',
            'scan_error': 'on_scan_error',
        }
        field = event_field_map.get(event_type)
        if not field:
            return

        try:
            webhooks = cls.query.filter_by(user_id=user_id, is_active=True).all()
            matching = [w for w in webhooks if getattr(w, field, False)]
        except Exception as e:
            logger.debug(f'Webhook query failed (non-fatal): {e}')
            return

        # Capture the current Flask app so background threads can reuse it
        # instead of creating a new app on every callback
        try:
            app = current_app._get_current_object()
        except RuntimeError:
            app = None

        for webhook in matching:
            thread = threading.Thread(
                target=cls._send_webhook,
                args=(app, webhook.id, webhook.url, event_type, data),
                daemon=True,
            )
            thread.start()

    @classmethod
    def _send_webhook(cls, app, webhook_id, url, event_type, data):
        """Send webhook payload (runs in background thread)."""
        # SSRF protection: block requests to private/internal IPs
        from app.utils.url_safety import is_safe_url
        is_safe, reason = is_safe_url(url)
        if not is_safe:
            logger.warning(
                f'Webhook {webhook_id} blocked — SSRF protection: {reason}'
            )
            cls._increment_failure(app, webhook_id)
            return

        payload = {
            'event': event_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': data,
        }
        try:
            resp = requests.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json', 'User-Agent': 'Sudarshan-Webhook/1.0'},
                timeout=10,
            )
            if resp.status_code >= 400:
                logger.warning(f'Webhook {webhook_id} returned {resp.status_code}')
                cls._increment_failure(app, webhook_id)
            else:
                logger.info(f'Webhook {webhook_id} triggered successfully')
                cls._update_last_triggered(app, webhook_id)
        except Exception as e:
            logger.warning(f'Webhook {webhook_id} failed: {e}')
            cls._increment_failure(app, webhook_id)

    @classmethod
    def _update_last_triggered(cls, app, webhook_id):
        """Update last triggered time (best-effort)."""
        if not app:
            return
        try:
            with app.app_context():
                webhook = db.session.get(cls, webhook_id)
                if webhook:
                    webhook.last_triggered = datetime.now(timezone.utc)
                    webhook.failure_count = 0
                    db.session.commit()
        except Exception:
            pass

    @classmethod
    def _increment_failure(cls, app, webhook_id):
        """Increment failure count; deactivate after 10 failures."""
        if not app:
            return
        try:
            with app.app_context():
                webhook = db.session.get(cls, webhook_id)
                if webhook:
                    webhook.failure_count = (webhook.failure_count or 0) + 1
                    if webhook.failure_count >= 10:
                        webhook.is_active = False
                        logger.warning(f'Webhook {webhook_id} deactivated after 10 failures')
                    db.session.commit()
        except Exception:
            pass
