#!/bin/bash
# start.sh — Starts both Gunicorn (web) and Celery (worker) in one container
# Required because Render's free tier doesn't support separate worker services

set -e

echo "🛡 Sudarshan — Starting services..."

# Start Celery worker in the background
echo "→ Starting Celery worker..."
celery -A app.celery_app:celery worker --loglevel=info --concurrency=2 &
CELERY_PID=$!

# Give Celery a moment to connect to Redis
sleep 2

# Start Gunicorn (foreground — Render monitors this process)
echo "→ Starting Gunicorn web server on port ${PORT:-5000}..."
exec gunicorn -k gevent --worker-connections 50 -w 2 -b 0.0.0.0:${PORT:-5000} --timeout 300 --keep-alive 5 --access-logfile - --error-logfile - run:app
