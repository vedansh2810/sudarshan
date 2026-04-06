FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p data/reports data/ml_models logs

# Production environment
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0
ENV PORT=8000

EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT}/api/health || exit 1

# Run with gunicorn — single-service mode (threading fallback for scans)
# 2 workers + 4 threads each = handles concurrent requests while scanning
CMD gunicorn -w 2 --threads 4 -b 0.0.0.0:${PORT} --timeout 300 --keep-alive 5 run:app
