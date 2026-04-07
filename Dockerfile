FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories with proper permissions
RUN mkdir -p data/reports data/ml_models logs && \
    chmod -R 777 data logs

# Production environment — HF Spaces requires port 7860
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0
ENV PORT=7860

EXPOSE 7860

# Run with gunicorn — single-service mode (threading fallback for scans)
# 2 workers + 4 threads each = handles concurrent requests while scanning
CMD gunicorn -w 2 --threads 4 -b 0.0.0.0:7860 --timeout 300 --keep-alive 5 run:app
