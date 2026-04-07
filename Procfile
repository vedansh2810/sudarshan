web: gunicorn -k gevent --worker-connections 50 -w 2 -b 0.0.0.0:$PORT --timeout 300 --keep-alive 5 --access-logfile - --error-logfile - run:app
worker: celery -A app.celery_app:celery worker --loglevel=info --concurrency=2
