# Running Sudarshan

This document explains how to run the project locally and common troubleshooting steps.

Prerequisites
- Python 3.12+
- (Optional) PostgreSQL or Supabase — the app falls back to SQLite when PostgreSQL is not available
- (Optional) Redis for Celery

Quick start
1. Create and activate a virtual environment:

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
```

2. Install dependencies (use the pinned set to reduce compatibility warnings):

```bash
pip install -r requirements.txt
```

3. Copy the example env and edit values as needed:

```bash
cp .env.example .env
# edit .env and set DATABASE_URL and optional keys
```

4. Run the dev server:

```bash
python run.py
```

Notes and troubleshooting
- Missing env vars:
  - In development the app will warn about missing env vars (for example `SUPABASE_URL`) and continue using the debug fallback for authentication.
  - In production the app will raise an error if critical vars like `SECRET_KEY` or `SQLALCHEMY_DATABASE_URI` are missing.

- TLS verification when scanning targets:
  - For local testing of intentionally broken TLS targets, set `ALLOW_INSECURE_TARGETS=1` in your `.env`. This will make the scanner skip TLS verification. Do NOT enable this in production.

- Dependency warnings (Requests/urllib3):
  - If you see a `RequestsDependencyWarning` about `urllib3` or `charset_normalizer`, install the pinned versions from `requirements.txt`.

- Running tests:

```bash
pytest -q
```

- Running Celery worker (optional):

```bash
celery -A app.celery_app:celery worker --loglevel=info
```

If something still fails, check `logs/` for application logs and open an issue with the failing traceback and the contents of your `.env` (omit secrets).