FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (curl for healthcheck, bash for start.sh)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories & make start script executable
RUN mkdir -p data/reports data/ml_models logs && chmod +x start.sh

# Production defaults (Render injects PORT automatically)
ENV PORT=5000
ENV FLASK_ENV=production
EXPOSE ${PORT}

# Run both Gunicorn + Celery via start.sh
CMD ["./start.sh"]
