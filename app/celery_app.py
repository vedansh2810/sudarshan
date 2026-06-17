"""Celery application factory with Flask context integration."""

from celery import Celery

# Module-level Celery instance — will be configured by init_celery()
celery = Celery("sudarshan")


def init_celery(app):
    """Configure the module-level Celery instance with Flask app config."""
    celery.conf.update(
        broker_url=app.config.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
        result_backend=app.config.get(
            "CELERY_RESULT_BACKEND", "redis://localhost:6379/0"
        ),
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
    )

    # Guard against re-binding on repeated init_celery() calls (e.g. testing)
    if not getattr(celery, '_flask_app_bound', False):
        class ContextTask(celery.Task):
            """Ensure every task runs inside the Flask app context."""

            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return super().__call__(*args, **kwargs)

        celery.Task = ContextTask
        celery._flask_app_bound = True
    return celery
