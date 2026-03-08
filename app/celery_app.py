"""Celery application factory with Flask context integration."""
from celery import Celery

# Module-level Celery instance — will be configured by init_celery()
celery = Celery('sudarshan')


def init_celery(app):
    """Configure the module-level Celery instance with Flask app config."""
    celery.conf.update(
        broker_url=app.config.get('broker_url', 'redis://localhost:6379/0'),
        result_backend=app.config.get('result_backend', 'redis://localhost:6379/0'),
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
    )

    class ContextTask(celery.Task):
        """Ensure every task runs inside the Flask app context."""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
