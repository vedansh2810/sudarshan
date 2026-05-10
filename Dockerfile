# ============================================================================
# Sudarshan Web Vulnerability Scanner — Dockerfile
# ============================================================================
# Multi-stage build for minimal image size.
#
# Build:   docker build -t sudarshan .
# Run:     docker run -p 5000:5000 --env-file .env sudarshan
# Compose: docker compose up --build
# ============================================================================

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build-time system dependencies for C extensions (psycopg, lxml)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        libxml2-dev \
        libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="Vedansh Gupta"
LABEL description="Sudarshan Web Vulnerability Scanner"

# Runtime system dependencies (shared libs for psycopg and lxml)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 \
        libxml2 \
        libxslt1.1 \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built Python packages from builder stage
COPY --from=builder /install /usr/local

# Create non-root user for security
RUN groupadd -r sudarshan && useradd -r -g sudarshan -m sudarshan

WORKDIR /app

# Copy application source code
COPY app/ ./app/
COPY run.py .
COPY requirements.txt .

# Create writable data directories (for SQLite fallback, reports, logs, ML models)
# Data assets (PortSwigger KB, ML models) are bind-mounted from the host via
# docker-compose, NOT baked into the image — they are .gitignored and may not
# exist in the build context on a fresh clone.
RUN mkdir -p data/reports data/ml_models data/report_diagrams data/portswigger_knowledge logs \
    && chown -R sudarshan:sudarshan /app

USER sudarshan

# Flask / Gunicorn configuration
ENV FLASK_ENV=production \
    FLASK_DEBUG=0 \
    PORT=5000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Default command: gunicorn for production (4 workers, 120s timeout for long scans)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--threads", "2", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "run:app"]
