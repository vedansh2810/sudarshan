# Sudarshan — Web Vulnerability Scanner

**Full-stack Python/Flask web application** that crawls websites, tests for 16 vulnerability types, and generates detailed security reports enhanced by AI (Groq/Llama 3.3 70B).

---

## Table of Contents
1. [Tech Stack](#tech-stack)
2. [Project Structure](#project-structure)
3. [Configuration](#configuration)
4. [Database Schema](#database-schema)
5. [Authentication](#authentication)
6. [Routes & API](#routes--api)
7. [Scanner Engine](#scanner-engine)
8. [AI / LLM Integration](#ai--llm-integration)
9. [ML Pipeline](#ml-pipeline)
10. [Frontend](#frontend)
11. [Deployment](#deployment)
12. [Scripts & Training](#scripts--training)
13. [Tests](#tests)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12, Flask 3.0, Gunicorn |
| **Database** | PostgreSQL (Supabase) / SQLite fallback, SQLAlchemy ORM, Flask-Migrate |
| **Auth** | Supabase Auth (GoTrue JWT), Flask session |
| **Task Queue** | Celery + Redis (optional; falls back to threading) |
| **AI/LLM** | Groq API → Llama 3.3 70B (`groq` SDK) |
| **ML** | scikit-learn (RF + GB ensemble), pandas, joblib |
| **Frontend** | Jinja2 templates (primary), React SPA via Vite (secondary `/frontend`) |
| **Reports** | fpdf2 (PDF), inline HTML |
| **Monitoring** | Prometheus (prometheus-client) |
| **HTTP** | requests, beautifulsoup4, lxml |
| **Security** | Flask-WTF CSRF, Flask-Limiter, HMAC-SHA256 API keys, SSRF protection |

---

## Project Structure

```
sudarshan/
├── run.py                          # Entry point — auto-activates venv, creates Flask app
├── requirements.txt                # Python dependencies
├── .env                            # Environment variables (secrets, DB, LLM keys)
├── Dockerfile                      # Python 3.12-slim, gunicorn entrypoint
├── docker-compose.yml              # web + worker + redis services
│
├── app/
│   ├── __init__.py                 # create_app() factory — registers extensions & blueprints
│   ├── config.py                   # Config / DevelopmentConfig / ProductionConfig classes
│   ├── celery_app.py               # Celery factory with Flask app context
│   ├── tasks.py                    # Celery task: run_scan_task()
│   │
│   ├── models/                     # SQLAlchemy ORM models
│   │   ├── database.py             # db instance, all model classes, init_db(), migrations
│   │   ├── user.py                 # User CRUD (maps Supabase UID → local int ID)
│   │   ├── scan.py                 # Scan CRUD + status/progress/scoring/orphan recovery
│   │   ├── vulnerability.py        # Vulnerability CRUD (auto-returns all columns via _row_to_dict)
│   │   ├── organization.py         # Multi-tenant orgs + memberships (owner/admin/member/viewer)
│   │   ├── api_key.py              # HMAC-SHA256 API key auth (with legacy SHA-256 migration)
│   │   ├── webhook.py              # Event-driven webhook delivery (scan_complete, vuln_found)
│   │   └── ml_training.py          # ScanAttempt (ML training data), MLModel (model metadata)
│   │
│   ├── routes/                     # Flask blueprints
│   │   ├── main.py                 # / — Landing page with platform stats
│   │   ├── auth.py                 # /login, /register, /auth/callback, /logout (Supabase JWT)
│   │   ├── dashboard.py            # /dashboard — stats, recent scans, trend charts
│   │   ├── scan.py                 # /scan/new, progress, status, SSE stream, pause/resume/stop
│   │   ├── results.py              # /scan/<id>/results, HTML/PDF report generation
│   │   ├── history.py              # /history — paginated scan history with search/filters
│   │   ├── api.py                  # /api/ — legacy JSON endpoints (stats, health, metrics)
│   │   ├── api_v2.py               # /api/v2/ — full REST API for React SPA frontend
│   │   └── ml_admin.py             # /ml/ — labeling, stats, export, vuln labeling, retraining
│   │
│   ├── scanner/                    # Core scanning engine
│   │   ├── crawler.py              # Web crawler — BFS, form extraction, URL discovery
│   │   ├── scan_manager.py         # ScanManager singleton — orchestrates full scan pipeline
│   │   ├── payload_manager.py      # Payload loading + encoding (URL, HTML, Base64, double)
│   │   ├── dvwa_auth.py            # DVWA auto-authentication handler
│   │   └── vulnerabilities/        # 16 scanner modules (see Scanner Engine section)
│   │       ├── base.py             # BaseScanner ABC + _get_smart_payloads() for AI payloads
│   │       ├── sql_injection.py    # Error-based, blind boolean, blind time-based, UNION
│   │       ├── xss.py              # Reflected, stored, DOM-based
│   │       ├── csrf.py             # Token/header/SameSite analysis
│   │       ├── command_injection.py# OS command injection (Linux + Windows payloads)
│   │       ├── directory_traversal.py # Path traversal with encoding bypass
│   │       ├── xxe.py              # XML External Entity injection
│   │       ├── ssrf.py             # Server-Side Request Forgery
│   │       ├── ssti.py             # Server-Side Template Injection
│   │       ├── open_redirect.py    # Open Redirect detection
│   │       ├── cors.py             # CORS misconfiguration
│   │       ├── clickjacking.py     # X-Frame-Options / CSP frame-ancestors
│   │       ├── security_headers.py # HTTP security headers audit
│   │       ├── idor.py             # Insecure Direct Object Reference + directory listing
│   │       ├── jwt_attacks.py      # JWT algorithm confusion, weak secrets, none attacks
│   │       └── broken_auth.py      # Broken authentication checks
│   │
│   ├── ai/                         # AI / LLM layer
│   │   ├── llm_client.py           # Groq API client (rate limiter, cache, singleton)
│   │   ├── analyzer.py             # LLM-powered vuln analysis + FP classification
│   │   ├── smart_engine.py         # Unified AI engine (LLM + PortSwigger + ML)
│   │   └── report_writer.py        # AI report generation (exec summary, remediation, narrative)
│   │
│   ├── ml/                         # Machine Learning
│   │   └── false_positive_classifier.py  # RF + GB ensemble FP classifier
│   │
│   ├── monitoring/
│   │   └── metrics.py              # Prometheus counters/histograms/gauges
│   │
│   ├── utils/
│   │   ├── auth_utils.py           # @login_required decorator
│   │   ├── auth_helpers.py         # Multi-tenant access control (user_can_access_scan)
│   │   └── url_safety.py           # SSRF protection — blocks private/cloud IPs
│   │
│   ├── templates/                  # Jinja2 HTML templates
│   │   ├── base.html               # Base layout
│   │   ├── layout.html             # Authenticated layout with sidebar
│   │   ├── auth/                   # login.html, register.html, callback_handler.html
│   │   ├── main/                   # index.html (landing page)
│   │   ├── dashboard/              # index.html (dashboard)
│   │   ├── scan/                   # new.html, progress.html
│   │   ├── results/                # view.html (scan results with AI badges)
│   │   ├── history/                # index.html
│   │   └── ml_admin/               # labeling.html, stats.html
│   │
│   └── static/                     # CSS, JS, images
│
├── frontend/                       # React SPA (Vite)
│   ├── package.json                # Vite + React dependencies
│   ├── vite.config.js              # Proxy to Flask backend
│   └── src/                        # React components
│
├── scripts/                        # Training & data scripts
│   ├── portswigger_scraper.py      # Scrapes PortSwigger labs + payloads
│   ├── portswigger_auto_trainer.py # Auto-trains on PortSwigger data
│   ├── portswigger_complete_integration.py  # Full integration script
│   └── train_ml_models.py          # ML model training script
│
├── data/
│   ├── database.db                 # SQLite database (dev fallback)
│   ├── ml_models/                  # Trained ML model files (.joblib)
│   ├── portswigger_knowledge/      # Scraped PortSwigger labs/payloads JSON
│   └── reports/                    # Generated scan reports
│
├── tests/
│   ├── test_crawler_scanner.py     # Crawler + scanner integration tests
│   ├── test_new_scanners.py        # New scanner module tests
│   └── test_smart_engine_integration.py  # AI/ML integration tests
│
└── logs/                           # Application logs
```

---

## Configuration

### Environment Variables (`.env`)

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask secret key (REQUIRED in production) |
| `FLASK_ENV` | `development` or `production` |
| `DATABASE_URL` | PostgreSQL connection string (Supabase) |
| `REDIS_URL` | Redis URL for Celery + rate limiting |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_ANON_KEY` | Supabase anonymous key (public) |
| `SUPABASE_SERVICE_KEY` | Supabase service role key (server-side) |
| `GROQ_API_KEY` | Groq API key for Llama 3.3 70B |
| `GROQ_MODEL` | Model name (default: `llama-3.3-70b-versatile`) |
| `ALLOW_LOCAL_TARGETS` | Allow scanning localhost/private IPs (default: false) |

### Config Classes (`app/config.py`)

- **`Config`** — Base config with all defaults, scan speeds, OWASP categories, vulnerability checks list
- **`DevelopmentConfig`** — DEBUG=True, in-memory rate limiter
- **`ProductionConfig`** — Secure cookies, Redis rate limiter, required SECRET_KEY

### Scan Speed Profiles

| Speed | Delay | Threads | Timeout | Max URLs |
|-------|-------|---------|---------|----------|
| Safe | 1.0s | 3 | 10s | 75 |
| Balanced | 0.15s | 6 | 8s | 200 |
| Aggressive | 0.05s | 10 | 5s | 500 |

---

## Database Schema

### Core Tables

**`users`** — Local user records (mapped from Supabase Auth)
| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | Auto-increment |
| supabase_uid | String(36) | Unique, indexed |
| username | String(80) | Unique |
| email | String(120) | Unique |
| is_admin | Boolean | Default false |
| created_at | DateTime | UTC |

**`scans`** — Scan sessions
| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| user_id | FK → users.id | |
| org_id | FK → organizations.id | Nullable (multi-tenant) |
| target_url | Text | |
| scan_mode | String(20) | active/passive |
| scan_speed | String(20) | safe/balanced/aggressive |
| crawl_depth | Integer | 1–10 |
| status | String(20) | pending/running/paused/completed/stopped/error |
| score | String(2) | A/B/C/D/F |
| total_urls, tested_urls, vuln_count | Integer | Progress counters |
| critical_count, high_count, medium_count, low_count | Integer | Severity counts |
| duration | Integer | Seconds |
| started_at, completed_at | DateTime | |

**`vulnerabilities`** — Discovered vulnerabilities
| Column | Type | Notes |
|--------|------|-------|
| id | Integer PK | |
| scan_id | FK → scans.id | Cascading delete |
| vuln_type | String(50) | e.g., `sql_injection`, `xss` |
| name | String(200) | Human-readable name |
| description, impact, remediation | Text | |
| severity | String(20) | critical/high/medium/low/info |
| cvss_score | Float | 0.0–10.0 |
| owasp_category | String(50) | A01–A10 |
| affected_url | Text | |
| parameter | String(200) | |
| payload | Text | Proof of concept |
| request_data, response_data | Text | |
| ai_analysis | Text | JSON — LLM analysis result |
| ai_narrative | Text | JSON — AI attack narrative |
| likely_false_positive | Boolean | FP detection flag |
| fp_confidence | Float | 0.0–1.0 |
| found_at | DateTime | |

### Supporting Tables

| Table | Purpose |
|-------|---------|
| `crawled_urls` | URLs discovered during crawl (url, status_code, forms/params found) |
| `scan_logs` | Timestamped log entries per scan |
| `organizations` | Teams with name, slug, plan (free/pro/enterprise) |
| `org_memberships` | User↔Org with role (owner/admin/member/viewer) |
| `api_keys` | HMAC-SHA256 hashed API keys with usage tracking |
| `webhooks` | Event-driven HTTP POST endpoints (scan_complete, vuln_found, scan_error) |
| `scan_attempts` | ML training data — every scan attempt with features + ground truth labels |
| `ml_models` | ML model versioning, metrics, deployment status |

---

## Authentication

**Flow:** Supabase Auth (client-side) → Flask session (server-side)

1. Client loads `/login` page with Supabase JS SDK
2. User authenticates via Supabase (email/password or OAuth)
3. Supabase returns access_token to client
4. Client POSTs token to `/auth/callback`
5. Server verifies token with `GET {SUPABASE_URL}/auth/v1/user` using service key
6. Server creates/updates local `UserModel` and sets Flask session
7. All subsequent requests use Flask session (`session['user_id']`)

### Authorization

- **`@login_required`** — Decorator in `auth_utils.py`; redirects browser / returns 401 JSON
- **Scan access** — `user_can_access_scan()` checks direct ownership OR org membership
- **Multi-tenant** — Scans can belong to organizations; org members with any role get access
- **API Keys** — `APIKey.verify()` for programmatic access (HMAC-SHA256, with legacy SHA-256 fallback)

---

## Routes & API

### Server-Rendered Routes (Jinja2)

| Route | Method | Blueprint | Description |
|-------|--------|-----------|-------------|
| `/` | GET | main | Landing page with platform stats |
| `/login` | GET | auth | Login page (Supabase JS) |
| `/register` | GET | auth | Registration page |
| `/auth/callback` | POST | auth | Receives Supabase JWT, creates session |
| `/auth/callback-handler` | GET | auth | OAuth redirect handler |
| `/logout` | GET | auth | Clear session |
| `/dashboard` | GET | dashboard | User dashboard with stats + charts |
| `/scan/new` | GET/POST | scan | New scan form + initiation |
| `/scan/<id>/progress` | GET | scan | Real-time scan progress page |
| `/scan/<id>/status` | GET | scan | JSON status (polling) |
| `/scan/<id>/stream` | GET | scan | SSE event stream |
| `/scan/<id>/pause` | POST | scan | Pause scan |
| `/scan/<id>/resume` | POST | scan | Resume scan |
| `/scan/<id>/stop` | POST | scan | Stop scan |
| `/scan/<id>/results` | GET | results | Results page (filters, AI badges) |
| `/scan/<id>/report/html` | GET | results | Download HTML report |
| `/scan/<id>/report/pdf` | GET | results | Download PDF report |
| `/history` | GET | history | Paginated scan history |
| `/history/<id>/delete` | POST | history | Delete scan |
| `/ml/labeling` | GET | ml_admin | ML labeling interface |
| `/ml/label/<id>` | POST | ml_admin | Label ScanAttempt |
| `/ml/stats` | GET | ml_admin | ML training statistics |
| `/ml/export` | GET | ml_admin | Export labeled data as JSON |
| `/ml/findings` | GET | ml_admin | List vuln findings for labeling |
| `/ml/label-vuln/<id>` | POST | ml_admin | Label vulnerability as TP/FP |
| `/ml/retrain` | POST | ml_admin | Trigger ML retraining |

### REST API v2 (React SPA)

Prefix: `/api/v2`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/session` | GET | Current session info |
| `/dashboard` | GET | Full dashboard data |
| `/scans` | GET | Paginated scan list |
| `/scans` | POST | Start new scan |
| `/scans/<id>` | GET | Scan details |
| `/scans/<id>` | DELETE | Delete scan |
| `/scans/<id>/results` | GET | Vulnerabilities + counts |
| `/scans/<id>/status` | GET | Live scan status |
| `/scans/<id>/pause` | POST | Pause |
| `/scans/<id>/resume` | POST | Resume |
| `/scans/<id>/stop` | POST | Stop |
| `/scans/<id>/stream` | GET | SSE stream |
| `/scans/<id>/report/<fmt>` | GET | PDF/HTML report |
| `/checks` | GET | Available vuln checks |
| `/api/health` | GET | Health check |
| `/api/metrics` | GET | Prometheus metrics |

---

## Scanner Engine

### Architecture

```
ScanManager (singleton)
├── Phase 0: Connectivity pre-check
├── Phase 1: Crawling (BFS, form extraction, URL discovery)
│   └── Crawler → injectable_points [{url, params, forms}]
├── Phase 2: Vulnerability scanning (concurrent ThreadPoolExecutor)
│   ├── Per URL: instantiate selected scanners
│   ├── Each scanner.scan(url, params, session) → findings[]
│   └── Per finding: dedup → DB → AI pipeline
├── AI Pipeline (per finding, best-effort):
│   ├── Step 1: LLM Analysis (analyze_vulnerability)
│   ├── Step 2: FP Detection (verify_finding → likely_false_positive)
│   └── Step 3: Attack Narrative (generate_attack_narrative)
├── Phase 3: Scoring (A–F based on critical/high/medium counts)
└── Completion: update DB, trigger webhooks, emit SSE
```

### Dual-Mode Execution

| Mode | When | SSE Transport | Scan Execution |
|------|------|---------------|----------------|
| **Celery** | Redis available | Redis pub/sub | Celery worker task |
| **Threading** | Redis unavailable | In-memory queues | Background thread |

### 16 Vulnerability Scanners

| Scanner | Class | Module | AI Payloads |
|---------|-------|--------|-------------|
| SQL Injection | `SQLInjectionScanner` | `sql_injection.py` | ✅ Merged into ERROR_PAYLOADS |
| XSS | `XSSScanner` | `xss.py` | ✅ Merged into BASIC_PAYLOADS |
| CSRF | `CSRFScanner` | `csrf.py` | ❌ |
| Security Headers | `SecurityHeadersScanner` | `security_headers.py` | ❌ |
| Directory Traversal | `DirectoryTraversalScanner` | `directory_traversal.py` | ❌ |
| Command Injection | `CommandInjectionScanner` | `command_injection.py` | ✅ Merged into LINUX_OUTPUT_PAYLOADS |
| IDOR | `IDORScanner` | `idor.py` | ❌ |
| Directory Listing | `DirectoryListingScanner` | `idor.py` | ❌ |
| XXE | `XXEScanner` | `xxe.py` | ✅ Stored in _smart_xxe_payloads |
| SSRF | `SSRFScanner` | `ssrf.py` | ❌ |
| Open Redirect | `OpenRedirectScanner` | `open_redirect.py` | ❌ |
| CORS | `CORSScanner` | `cors.py` | ❌ |
| Clickjacking | `ClickjackingScanner` | `clickjacking.py` | ❌ |
| SSTI | `SSTIScanner` | `ssti.py` | ✅ Merged into EXPRESSION_PROBES |
| JWT Attacks | `JWTAttackScanner` | `jwt_attacks.py` | ❌ |
| Broken Auth | `BrokenAuthScanner` | `broken_auth.py` | ❌ |

### BaseScanner (`base.py`)

Abstract base class with:
- `scan(url, params, session)` — abstract method
- `_get_smart_payloads(vuln_type, target_context)` — calls SmartEngine for AI-generated payloads
- `_make_request()` — HTTP request helper with retries and error handling

### Crawler (`crawler.py`)

- BFS crawl with configurable depth, max URLs, and speed
- Extracts: links, forms, URL parameters, input fields
- Respects `robots.txt` (configurable)
- Returns `injectable_points` list for scanners

### PayloadManager (`payload_manager.py`)

- 30,676 bytes of categorized payloads
- Encoding: URL, HTML entity, Base64, double encoding
- Per-vulnerability-type payload sets

---

## AI / LLM Integration

### LLM Client (`llm_client.py`)

| Feature | Implementation |
|---------|---------------|
| **Provider** | Groq (Llama 3.3 70B Versatile) |
| **Rate Limiting** | Token-bucket (28 RPM, under 30 RPM free tier) |
| **Caching** | TTL-based (1 hour), MD5 keyed, max 500 entries |
| **Thread Safety** | Locks on rate limiter + cache |
| **API** | `generate(prompt, context)` → text, `generate_json(prompt)` → dict |

### Smart Engine (`smart_engine.py`)

Unified intelligence layer integrating 3 systems:
1. **LLM** (Groq) — reasoning, payload generation, analysis
2. **PortSwigger KB** — 269 labs, 2197 payloads, 31 categories
3. **ML Classifier** — RF + GB ensemble for false-positive prediction

Key methods:
- `generate_smart_payloads(vuln_type, context)` — AI-generated payloads
- `verify_finding(vuln_data, features)` — ML + LLM false-positive detection
- `generate_attack_narrative(vuln_data)` — professional exploitation narrative
- `get_portswigger_context(vuln_type)` — PortSwigger lab/payload context
- `ai_recon(target_url)` — tech stack + WAF detection
- `ml_predict(features)` — ML classifier prediction

### Analyzer (`analyzer.py`)

LLM-powered analysis with 3 prompt templates:
- `analyze_vulnerability()` — severity, impact, remediation, OWASP, CWE
- `classify_false_positive()` — TP/FP classification with ML enrichment
- `analyze_with_portswigger()` — deep analysis with PortSwigger lab references

### Report Writer (`report_writer.py`)

AI-generated report components:
- `generate_executive_summary(scan_data)` — C-suite summary
- `generate_remediation_plan(findings)` — prioritized remediation roadmap
- `generate_attack_narrative(vuln_data)` — detailed exploitation story
- `generate_risk_score_explanation(score_data)` — risk score context

### AI Pipeline (per finding in scan_manager)

```
Finding detected →
  1. ai_analyze(vuln_data) → store ai_analysis JSON
  2. engine.verify_finding() → set likely_false_positive + fp_confidence
  3. engine.generate_attack_narrative() → store ai_narrative JSON
```

### Report Integration

- **HTML/PDF reports**: AI executive summary, per-finding attack narratives, FP warning badges
- **Results page**: AI Analysis panel, AI Attack Narrative section, Likely FP badge

---

## ML Pipeline

### False Positive Classifier (`false_positive_classifier.py`)

- **Architecture**: Random Forest + Gradient Boosting ensemble
- **Features**: payload length, special chars, script tags, SQL keywords, encoding, status codes, response times, length diffs, error patterns, reflection detection
- **Training data**: `ScanAttempt` records with `is_true_positive` labels
- **Admin interface**: `/ml/findings`, `/ml/label-vuln/<id>`, `/ml/retrain`

### Training Workflow

1. Scanner runs → creates `ScanAttempt` records with features
2. Admin labels findings via `/ml/label-vuln/<id>` (TP or FP)
3. Admin triggers retraining via `POST /ml/retrain`
4. New model saved to `data/ml_models/fp_classifier_v{timestamp}.joblib`
5. SmartEngine reloads new model

---

## Frontend

### Jinja2 Templates (Primary)

- **Base layout**: `layout.html` with sidebar navigation
- **Styling**: Custom CSS with dark mode, glassmorphism, gradient accents
- **Icons**: Material Symbols
- **Interactive**: Vanilla JS (toggles, SSE streaming, chart rendering)

### React SPA (Secondary — `/frontend`)

- **Build tool**: Vite
- **API proxy**: `/api/v2` endpoints
- **Status**: Scaffolded, uses same auth flow

---

## Deployment

### Local Development

```bash
python run.py  # Auto-activates venv, starts Flask dev server on port 5000
```

### Docker Compose

3 services:
- **web**: Flask + Gunicorn (2 workers)
- **worker**: Celery worker (2 concurrency)
- **redis**: Redis 7 Alpine (password protected)

```bash
docker-compose up --build
```

### Production Checklist

1. Set `SECRET_KEY` (generate with `python -c "import secrets; print(secrets.token_hex(32))"`)
2. Set `FLASK_ENV=production`
3. Configure PostgreSQL `DATABASE_URL`
4. Set Redis password
5. Set Supabase keys
6. Set `GROQ_API_KEY`

---

## Scripts & Training

| Script | Purpose |
|--------|---------|
| `scripts/portswigger_scraper.py` | Scrapes PortSwigger Web Security Academy labs + payloads |
| `scripts/portswigger_auto_trainer.py` | Auto-trains ML models on PortSwigger data |
| `scripts/portswigger_complete_integration.py` | Full PortSwigger data integration |
| `scripts/train_ml_models.py` | Standalone ML model training |

---

## Tests

| Test File | Coverage |
|-----------|----------|
| `tests/test_crawler_scanner.py` | Crawler + scanner integration tests |
| `tests/test_new_scanners.py` | New scanner module tests |
| `tests/test_smart_engine_integration.py` | AI/ML integration tests |

Run tests:
```bash
pytest tests/ -v
```

---

## Key Design Decisions

1. **Dual-mode execution** — Celery when Redis is available, in-process threading otherwise. Same code path, different transport.
2. **Graceful AI degradation** — All AI features are best-effort. Scanning never stops if LLM/ML is unavailable.
3. **Multi-tenant isolation** — Organization memberships with role-based access. Scans can be org-scoped.
4. **SSRF protection** — All user-supplied URLs validated against blocked IP ranges (private, loopback, cloud metadata).
5. **API key security** — HMAC-SHA256 with app SECRET_KEY, transparent migration from legacy SHA-256.
6. **SSE for real-time updates** — Server-Sent Events with Redis pub/sub or in-memory queue fallback.
7. **PortSwigger knowledge base** — 269 labs and 2197 payloads enriching AI analysis and payload generation.
8. **Smart payloads** — AI-generated payloads merged into 5 injection-type scanners at init time.
9. **False positive filtering** — ML + LLM verification marks findings (not drops), preserving all data.
10. **Report generation** — AI executive summary + per-finding attack narratives + FP badges in HTML/PDF.
