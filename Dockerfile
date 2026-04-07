FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (curl needed for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directories
RUN mkdir -p data/reports data/ml_models logs

# Production defaults (Render injects PORT automatically)
ENV PORT=5000
ENV FLASK_ENV=production
EXPOSE ${PORT}

# Run with gunicorn — uses $PORT so Render can override it
CMD gunicorn -w 2 -b 0.0.0.0:${PORT} --timeout 300 --keep-alive 5 --access-logfile - --error-logfile - run:app
