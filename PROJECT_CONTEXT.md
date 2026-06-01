# Sudarshan - Web Vulnerability Scanner

**Project Type:** Full-stack web application
**Backend:** Python 3.12+ / Flask 3.0
**Database:** PostgreSQL (Supabase) with SQLite fallback
**Auth:** Supabase Auth (GoTrue) - client-side SDK + server-side token verification
**AI/LLM:** Groq API (Llama 3.3 70B Versatile)
**ML:** scikit-learn (Random Forest + Gradient Boosting ensemble)
**Task Queue:** Celery + Redis (optional - falls back to in-process threading)
**Frontend:** Jinja2 templates + Tailwind CSS (pre-built) + vanilla JS
**Deployment:** Gunicorn (Unix) or `python run.py` (Windows/dev)

---

## Quick Start

```bash
python start.py       # Auto-setup + run (first time: installs deps, creates .env, builds CSS)
python start.py --check   # Show setup status
python start.py --setup   # Force re-run setup
```

---

## Project Structure

```
sudarshan/
|-- start.py                    # One-click setup & run script
|-- run.py                      # Flask entry point (used by start.py)
|-- requirements.txt            # Python dependencies
|-- package.json                # Node.js dependencies (Tailwind CSS build)
|-- tailwind.config.js          # Tailwind CSS configuration
|-- .env.example                # Environment template with setup instructions
|-- .gitignore
|-- PROJECT_CONTEXT.md          # This file
|-- README.md                   # User-facing documentation
|
|-- app/
|   |-- __init__.py             # Flask factory: create_app(), extensions, middleware
|   |-- config.py               # Configuration (env vars, security headers, DB URI)
|   |-- celery_app.py           # Celery worker configuration
|   |-- tasks.py                # Celery task definitions (async scan execution)
|   |
|   |-- routes/
|   |   |-- main.py             # Landing page, static pages
|   |   |-- auth.py             # Login/register/logout/callback (Supabase Auth)
|   |   |-- dashboard.py        # User dashboard (scan history, stats)
|   |   |-- scan.py             # Scan CRUD, SSE streaming, progress page
|   |   |-- results.py          # Scan results, PDF reports, AI analysis
|   |   |-- history.py          # Scan history with filtering
|   |   |-- api.py              # API v1 (health, metrics, legacy status)
|   |   |-- api_v2.py           # API v2 (full REST API with API key auth)
|   |   |-- ml_admin.py         # ML model admin (labeling, stats, retraining)
|   |
|   |-- models/
|   |   |-- database.py         # SQLAlchemy models (ScanModel, VulnerabilityModel, UserModel)
|   |   |-- user.py             # User upsert logic (Supabase UID mapping)
|   |   |-- scan.py             # Scan CRUD helpers (dict-based interface)
|   |   |-- vulnerability.py    # Vulnerability CRUD helpers
|   |   |-- api_key.py          # API key model (hashed, scoped, org-aware)
|   |   |-- webhook.py          # Webhook model (event-driven notifications)
|   |   |-- organization.py     # Multi-tenant org model (roles, memberships)
|   |   |-- ml_training.py      # ML training data models (labels, scan attempts)
|   |
|   |-- scanner/
|   |   |-- scan_manager.py     # Orchestrator: threading, SSE, Redis pub/sub
|   |   |-- crawler.py          # Web crawler (BFS, robots.txt, form discovery)
|   |   |-- dvwa_auth.py        # DVWA auto-login for testing
|   |   |-- payload_manager.py  # Centralized payload system (PortSwigger + custom)
|   |   |-- vulnerabilities/
|   |       |-- base.py         # Base scanner class (shared logic, AI enrichment)
|   |       |-- sql_injection.py
|   |       |-- xss.py
|   |       |-- command_injection.py
|   |       |-- directory_traversal.py
|   |       |-- xxe.py
|   |       |-- ssrf.py
|   |       |-- csrf.py
|   |       |-- cors.py
|   |       |-- clickjacking.py
|   |       |-- security_headers.py
|   |       |-- open_redirect.py
|   |       |-- ssti.py
|   |       |-- idor.py
|   |       |-- broken_auth.py
|   |       |-- jwt_attacks.py
|   |
|   |-- ai/
|   |   |-- smart_engine.py     # AI orchestrator (PortSwigger context, ML integration)
|   |   |-- llm_client.py       # Groq API wrapper (retry, JSON parsing)
|   |   |-- analyzer.py         # LLM vulnerability analysis prompts
|   |   |-- report_writer.py    # LLM report generation (exec summary, remediation)
|   |
|   |-- ml/
|   |   |-- false_positive_classifier.py  # ML false-positive classifier (ensemble)
|   |
|   |-- monitoring/
|   |   |-- metrics.py          # Prometheus metrics endpoint
|   |   |-- security_logger.py  # Structured security event logger (auth, API, SIEM)
|   |
|   |-- utils/
|   |   |-- auth_utils.py       # @login_required decorator, session management
|   |   |-- auth_helpers.py     # Scan access control (owner + org member checks)
|   |   |-- url_safety.py       # SSRF protection (private IP blocking)
|   |
|   |-- static/
|   |   |-- css/
|   |   |   |-- sudarshan.css       # Custom design system (glass, neon, nav effects)
|   |   |   |-- tailwind-built.css  # Pre-built Tailwind CSS (30KB minified)
|   |   |   |-- tailwind-input.css  # Tailwind build input (@tailwind directives)
|   |   |-- js/
|   |       |-- utils.js            # Shared JS (sanitizer, password toggle)
|   |
|   |-- templates/
|       |-- base.html               # Root template (meta, fonts, CSS, CSRF)
|       |-- layout.html             # Authenticated layout (nav, sidebar, flash)
|       |-- auth/
|       |   |-- login.html          # Supabase Auth login (email + Google OAuth)
|       |   |-- register.html       # Registration page
|       |   |-- callback_handler.html  # OAuth callback token handler
|       |-- dashboard/
|       |   |-- index.html          # Dashboard with charts and stats
|       |-- scan/
|       |   |-- new.html            # New scan form (URL, depth, modules)
|       |   |-- progress.html       # Live scan progress (SSE + polling fallback)
|       |-- results/
|       |   |-- detail.html         # Scan results with vulnerability cards
|       |   |-- report.html         # Printable/PDF report view
|       |-- history/
|       |   |-- index.html          # Scan history with filters
|       |-- main/
|       |   |-- index.html          # Landing page
|       |-- ml_admin/
|           |-- labeling.html       # ML training data labeling interface
|           |-- stats.html          # ML model performance stats
|
|-- data/
|   |-- portswigger_knowledge/      # PortSwigger Academy data (committed)
|   |   |-- portswigger_knowledge.json  # 2MB vulnerability knowledge base
|   |   |-- payloads_by_category.json   # 765KB attack payloads
|   |   |-- lab_index.json              # 77KB lab reference index
|   |-- ml_models/                  # Trained ML models (committed)
|   |   |-- fp_classifier_*.joblib  # False-positive classifier model
|   |-- database.db                 # SQLite database (gitignored, auto-created)
|   |-- reports/                    # Generated PDF reports (gitignored)
|   |-- report_diagrams/            # Generated diagrams (gitignored)
|
|-- scripts/                        # Standalone dev/build scripts
|   |-- portswigger_scraper.py      # Scrape PortSwigger Academy labs
|   |-- portswigger_auto_trainer.py # Auto-train ML on PortSwigger data
|   |-- portswigger_complete_integration.py  # Integration orchestrator
|   |-- train_ml_models.py          # Train false-positive classifier
|   |-- generate_diagrams.py        # Generate architecture diagrams
|   |-- generate_report_p1/p2/p3.py # Generate project documentation
|
|-- tests/                          # Test suite
|   |-- test_crawler_scanner.py     # Crawler and scanner integration tests
|   |-- test_new_scanners.py        # Vulnerability scanner unit tests
|   |-- test_multi_tenancy.py       # Organization/multi-tenant tests
|   |-- test_smart_engine_integration.py  # AI engine integration tests
|   |-- test_stateless_scan_manager.py    # Scan manager state tests
|
|-- docs/
    |-- RUNNING.md                  # Deployment/running instructions
```

---

## Architecture

### Authentication Flow

1. User clicks Login/Register -> Supabase JS SDK (client-side)
2. Supabase handles email/password or Google OAuth
3. On success, Supabase redirects to `/auth/callback-handler`
4. `callback_handler.html` extracts the access token from URL hash
5. Token is POSTed to `POST /auth/callback` (Flask backend)
6. Flask verifies the token via Supabase GoTrue, upserts user in local DB
7. Flask sets server-side session (`session["user_id"]`, `session["username"]`)
8. All subsequent requests use Flask session (8-hour expiry, permanent)

### Scan Execution Flow

1. User submits scan form -> `POST /scan/new`
2. `ScanManager.start_scan()` creates a thread (or Celery task if Redis available)
3. **Phase 1 - Crawling:** BFS crawler discovers URLs, forms, parameters
4. **Phase 2 - Scanning:** Each vulnerability scanner tests discovered endpoints
5. **Phase 3 - AI Analysis:** SmartEngine enriches findings with PortSwigger context
6. **Phase 4 - ML Classification:** False-positive classifier filters noise
7. **Phase 5 - Scoring:** Security score calculated, results saved to DB
8. Real-time updates via SSE (Server-Sent Events) with Redis pub/sub fallback to polling

### Database Strategy

- **Primary:** PostgreSQL via Supabase (`DATABASE_URL` in `.env`)
- **Fallback:** SQLite at `data/database.db` (auto-detected on startup)
- The app probes PostgreSQL connectivity BEFORE initializing SQLAlchemy
- If PostgreSQL is unreachable, engine pool options are cleared and SQLite is used
- All models use SQLAlchemy ORM (no raw SQL)

### AI / LLM Integration

- **Provider:** Groq API (fast inference on Llama 3.3 70B)
- **SmartEngine** (`app/ai/smart_engine.py`) orchestrates:
  - PortSwigger knowledge base lookups
  - AI-powered vulnerability analysis
  - Smart payload selection
  - Executive summary generation
- **Graceful degradation:** All AI features are optional; app works without `GROQ_API_KEY`

### Multi-Tenancy

- Organizations with roles: `owner`, `admin`, `member`, `viewer`
- Scans are scoped to user or organization
- API keys can be org-scoped
- Webhooks fire on scan events (complete, error, vulnerability found)

---

## Key Configuration (`.env`)

| Variable | Required | Description |
|----------|:--------:|-------------|
| `SECRET_KEY` | Yes | Flask session secret (auto-generated by `start.py`) |
| `SUPABASE_URL` | Yes* | Supabase project URL |
| `SUPABASE_ANON_KEY` | Yes* | Supabase public anon key |
| `SUPABASE_SERVICE_KEY` | Yes* | Supabase service role key |
| `DATABASE_URL` | No | PostgreSQL URI (falls back to SQLite) |
| `REDIS_URL` | No | Redis URI (falls back to threading) |
| `GROQ_API_KEY` | No | Groq API key for AI features |
| `PORT` | No | Server port (default: 5000) |

*Required for login/register to work. Without these, auth pages will render but Supabase JS SDK will fail silently.

---

## API Endpoints

### Web Routes (Server-Rendered)
- `GET /` - Landing page
- `GET /login`, `GET /register` - Auth pages
- `POST /auth/callback` - Token verification
- `GET /dashboard` - User dashboard
- `GET /scan/new`, `POST /scan/new` - New scan
- `GET /scan/<id>/progress` - Live progress (SSE)
- `GET /scan/<id>/results` - Results page
- `GET /scan/<id>/report` - PDF report
- `GET /history` - Scan history

### API v2 (JSON, session auth via @login_required)
- `GET /api/v2/auth/session` - Current session info
- `GET /api/v2/dashboard` - Dashboard stats
- `GET /api/v2/scans` - List scans (paginated, filterable)
- `POST /api/v2/scans` - Start scan (CSRF-exempt, rate limited 10/hr)
- `GET /api/v2/scans/<id>` - Scan details
- `DELETE /api/v2/scans/<id>` - Delete scan (CSRF-exempt, rate limited 20/hr)
- `GET /api/v2/scans/<id>/status` - Live scan status
- `GET /api/v2/scans/<id>/results` - Vulnerabilities (severity/type filters)
- `POST /api/v2/scans/<id>/pause` - Pause scan
- `POST /api/v2/scans/<id>/resume` - Resume scan
- `POST /api/v2/scans/<id>/stop` - Stop scan
- `GET /api/v2/scans/<id>/stream` - SSE event stream
- `GET /api/v2/scans/<id>/report/<fmt>` - Download PDF/HTML report
- `GET /api/v2/checks` - List available vulnerability checks

### Infrastructure
- `GET /api/health` - Health check
- `GET /api/metrics` - Prometheus metrics

---

## Vulnerability Scanners (15 modules)

| Scanner | File | Techniques |
|---------|------|------------|
| SQL Injection | `sql_injection.py` | Error-based, union, time-based, boolean, stacked |
| XSS | `xss.py` | Reflected, stored, DOM, event handlers, polyglots |
| Command Injection | `command_injection.py` | Linux/Windows, blind, IFS bypass |
| Directory Traversal | `directory_traversal.py` | Path traversal, null byte, encoding |
| XXE | `xxe.py` | File retrieval, SSRF via XXE, OOB, parameter entity |
| SSRF | `ssrf.py` | Localhost, cloud metadata, protocol smuggling |
| CSRF | `csrf.py` | Token validation, SameSite, origin checks |
| CORS | `cors.py` | Origin reflection, null origin, wildcard |
| Clickjacking | `clickjacking.py` | X-Frame-Options, CSP frame-ancestors |
| Security Headers | `security_headers.py` | HSTS, CSP, X-Content-Type, Referrer-Policy |
| Open Redirect | `open_redirect.py` | Parameter-based, path-based, encoding bypass |
| SSTI | `ssti.py` | Jinja2, Twig, Freemarker, Velocity detection |
| IDOR | `idor.py` | Sequential ID, UUID, parameter manipulation |
| Broken Auth | `broken_auth.py` | Default creds, session fixation, enum |
| JWT Attacks | `jwt_attacks.py` | Algorithm confusion, none alg, key confusion |

---

## Development

### Rebuild Tailwind CSS (after template changes)
```bash
npm run build:css       # One-time build
npm run watch:css       # Watch mode (auto-rebuild on save)
```

### Run Tests
```bash
.venv/Scripts/python -m pytest tests/ -v
```

### Celery Worker (optional, for async scans)
```bash
celery -A app.celery_app.celery worker --loglevel=info
```
