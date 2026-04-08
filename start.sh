#!/bin/bash
# start.sh — Starts both Gunicorn (web) and Celery (worker) in one container
# Required because Render's free tier doesn't support separate worker services
#
# Architecture:
#   - Celery worker runs in background (1 process, 1 concurrent task)
#   - Gunicorn runs in foreground with gevent async workers
#   - Both share the same Redis instance for task queue + pub/sub

echo "🛡 Sudarshan — Starting services..."
echo "→ Memory limit: ${MEMORY_LIMIT:-512MB (Render Free)}"

# ── Wait for Redis to be ready (Render Redis may cold-start) ────────────
echo "→ Waiting for Redis..."
MAX_RETRIES=15
RETRY=0
while [ $RETRY -lt $MAX_RETRIES ]; do
    if python -c "
import os, sys
try:
    import redis
    r = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'), socket_connect_timeout=3)
    r.ping()
    print('Redis connected!')
    sys.exit(0)
except Exception as e:
    print(f'Redis not ready: {e}')
    sys.exit(1)
" 2>/dev/null; then
        break
    fi
    RETRY=$((RETRY + 1))
    echo "  Retry $RETRY/$MAX_RETRIES..."
    sleep 2
done

if [ $RETRY -eq $MAX_RETRIES ]; then
    echo "⚠ Redis not available — scans will use threading fallback mode"
else
    # ── Start Celery worker in the background ────────────────────────────
    # --concurrency=1: Only 1 scan at a time (saves memory on 512MB free tier)
    # --max-tasks-per-child=3: Restart worker process after 3 tasks (prevents memory leaks)
    echo "→ Starting Celery worker (concurrency=1, memory-optimized)..."
    celery -A app.celery_app:celery worker \
        --loglevel=info \
        --concurrency=1 \
        --max-tasks-per-child=3 \
        --without-heartbeat \
        --without-mingle \
        --without-gossip \
        -Q celery &
    CELERY_PID=$!
    echo "  Celery worker started (PID: $CELERY_PID)"

    # Give Celery a moment to initialize
    sleep 3
fi

# ── Start Gunicorn (foreground — Render monitors this process) ──────────
# -k gevent: async workers for SSE streaming (each SSE = lightweight greenlet)
# -w 1: single worker process to save memory (gevent handles concurrency)
# --worker-connections 50: max concurrent greenlets per worker
echo "→ Starting Gunicorn web server on port ${PORT:-5000}..."
exec gunicorn \
    -k gevent \
    --worker-connections 50 \
    -w 1 \
    -b 0.0.0.0:${PORT:-5000} \
    --timeout 300 \
    --keep-alive 5 \
    --access-logfile - \
    --error-logfile - \
    run:app
