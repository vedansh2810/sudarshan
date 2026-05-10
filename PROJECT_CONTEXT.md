# Sudarshan — Web Vulnerability Scanner

**Project Type:** Full-stack web application  
**Backend:** Python 3.12 / Flask 3.0  
**Database:** PostgreSQL (Supabase) with SQLite fallback  
**Auth:** Supabase Auth (GoTrue)  
**AI/LLM:** Groq API (Llama 3.3 70B Versatile)  
**ML:** scikit-learn (Random Forest + Gradient Boosting ensemble)  
**Task Queue:** Celery + Redis (optional — falls back to in-process threading)  
**Deployment:** Docker Compose (Gunicorn + Redis + Celery) or local dev (venv + `run.py`)  

---

## Architecture Overview

```
sudarshan/
├── run.py                          # Entry point (Flask dev server, port 5000)
├── requirements.txt                # Python dependencies (45 lines)
├── Dockerfile                      # Multi-stage Docker build (Python 3.12 slim)
├── docker-compose.yml              # Dev/Prod: web + worker + redis
├── .dockerignore                   # Build context exclusions
├── .env                            # Environment variables (Supabase, Groq, Redis)
├── .env.example                    # Safe env template (no secrets)
├── .gitignore                      # Git exclusions
├── PROJECT_CONTEXT.md              # This file
├── README.md                       # Project documentation
├── app/
│   ├── __init__.py                 # Flask app factory (create_app) — 5.2KB
│   ├── config.py                   # Config classes (Dev/Prod) — 5.0KB
│   ├── celery_app.py               # Celery factory with Flask context — 1.1KB
│   ├── tasks.py                    # Celery task definitions (run_scan_task) — 15.8KB
│   ├── ai/                         # AI/LLM intelligence layer
│   │   ├── __init__.py
│   │   ├── smart_engine.py         # Unified AI engine (LLM + PortSwigger + ML) — 27.6KB
│   │   ├── llm_client.py           # Groq LLM client (rate-limited, cached) — 7.8KB
│   │   ├── analyzer.py             # Vulnerability analysis & FP classification — 10.2KB
│   │   └── report_writer.py        # AI-generated report sections — 11.8KB
│   ├── ml/                         # Machine Learning
│   │   ├── __init__.py
│   │   └── false_positive_classifier.py  # RF+GB ensemble FP classifier — 8.9KB
│   ├── models/                     # SQLAlchemy ORM models
│   │   ├── __init__.py
│   │   ├── database.py             # Core models + db init + migrations — 7.7KB
│   │   ├── scan.py                 # Scan CRUD operations — 8.2KB
│   │   ├── user.py                 # User CRUD (Supabase ↔ local mapping) — 3.5KB
│   │   ├── vulnerability.py        # Vulnerability CRUD — 4.3KB
│   │   ├── organization.py         # Multi-tenant org/team model — 11.8KB
│   │   ├── webhook.py              # Webhook event notifications — 6.1KB
│   │   ├── api_key.py              # HMAC-SHA256 API key auth — 4.8KB
│   │   └── ml_training.py          # ML training data (ScanAttempt, MLModel) — 11.3KB
│   ├── scanner/                    # Core scanning engine
│   │   ├── __init__.py
│   │   ├── scan_manager.py         # Scan orchestration (Celery or threading) — 37.0KB
│   │   ├── crawler.py              # Multi-threaded web crawler — 23.7KB
│   │   ├── dvwa_auth.py            # DVWA auto-authentication — 6.2KB
│   │   ├── payload_manager.py      # Static payload database — 30.7KB
│   │   └── vulnerabilities/        # 15 vulnerability scanner modules (16 checks)
│   │       ├── __init__.py
│   │       ├── base.py             # Base scanner class — 17.2KB
│   │       ├── sql_injection.py    # SQL Injection — 26.2KB
│   │       ├── xss.py              # Cross-Site Scripting — 24.6KB
│   │       ├── csrf.py             # CSRF — 10.3KB
│   │       ├── command_injection.py # OS Command Injection — 15.0KB
│   │       ├── directory_traversal.py # Path Traversal — 11.3KB
│   │       ├── xxe.py              # XML External Entity — 14.8KB
│   │       ├── ssrf.py             # Server-Side Request Forgery — 16.3KB
│   │       ├── ssti.py             # Server-Side Template Injection — 9.8KB
│   │       ├── jwt_attacks.py      # JWT Vulnerabilities — 19.7KB
│   │       ├── broken_auth.py      # Broken Authentication — 19.6KB
│   │       ├── idor.py             # IDOR + Directory Listing (2 scanners) — 8.2KB
│   │       ├── open_redirect.py    # Open Redirect — 11.3KB
│   │       ├── cors.py             # CORS Misconfiguration — 6.9KB
│   │       ├── clickjacking.py     # Clickjacking — 4.5KB
│   │       └── security_headers.py # Security Headers — 15.5KB
│   ├── routes/                     # Flask blueprints
│   │   ├── __init__.py
│   │   ├── main.py                 # Landing page — 1.0KB
│   │   ├── auth.py                 # Login/Register (Supabase Auth) — 4.4KB
│   │   ├── dashboard.py            # User dashboard — 3.6KB
│   │   ├── scan.py                 # Start/manage scans — 13.7KB
│   │   ├── results.py              # View results + HTML/PDF reports — 27.2KB
│   │   ├── history.py              # Scan history — 3.4KB
│   │   ├── api.py                  # Legacy API v1 — 2.0KB
│   │   ├── api_v2.py               # RESTful API v2 (API key auth) — 15.1KB
│   │   └── ml_admin.py             # ML training data admin panel — 7.7KB
│   ├── utils/                      # Utility modules
│   │   ├── __init__.py
│   │   ├── auth_helpers.py         # @login_required decorator — 641B
│   │   ├── auth_utils.py           # Session helpers — 666B
│   │   └── url_safety.py           # SSRF protection (IP validation) — 3.5KB
│   ├── monitoring/
│   │   ├── __init__.py
│   │   └── metrics.py              # Prometheus metrics — 2.6KB
│   ├── static/                     # Local static assets
│   │   ├── css/
│   │   │   └── sudarshan.css       # Shared stylesheet — 10.3KB
│   │   └── js/
│   │       └── utils.js            # Shared JS utilities — 1.0KB
│   └── templates/                  # Jinja2 HTML templates
│       ├── base.html               # Base template (CDN links, nav) — 3.8KB
│       ├── layout.html             # Layout template (sidebar) — 4.8KB
│       ├── auth/
│       │   ├── login.html          # Login page — 9.7KB
│       │   ├── register.html       # Registration page — 10.9KB
│       │   └── callback_handler.html # OAuth callback handler — 2.9KB
│       ├── dashboard/
│       │   └── index.html          # Dashboard page — 11.5KB
│       ├── scan/
│       │   ├── new.html            # Scan configuration page — 7.1KB
│       │   └── progress.html       # Real-time scan progress (SSE) — 12.8KB
│       ├── results/
│       │   └── view.html           # Scan results & report view — 9.8KB
│       ├── history/
│       │   └── index.html          # Scan history page — 9.4KB
│       ├── main/
│       │   └── index.html          # Landing page — 13.0KB
│       └── ml_admin/
│           ├── labeling.html       # ML training data labeling — 9.2KB
│           └── stats.html          # ML model stats & management — 6.5KB
├── data/
│   ├── database.db                 # SQLite database (dev) — 11.4MB
│   ├── ml_models/
│   │   └── fp_classifier_v20260311_113925.joblib  # Trained ML model — 484KB
│   ├── portswigger_knowledge/      # PortSwigger KB (JSON)
│   │   ├── portswigger_knowledge.json  # Full KB — 2.0MB
│   │   ├── lab_index.json              # 269 labs index — 77KB
│   │   └── payloads_by_category.json   # 2197 payloads — 765KB
│   ├── report_diagrams/            # Generated report diagram assets (empty)
│   └── reports/                    # Generated HTML/PDF reports (empty)
├── scripts/                        # Utility scripts
│   ├── portswigger_scraper.py      # Scrape PortSwigger labs — 32.5KB
│   ├── portswigger_auto_trainer.py # Auto-train from scraped data — 24.5KB
│   ├── portswigger_complete_integration.py — 3.3KB
│   ├── train_ml_models.py          # Train ML false-positive classifier — 4.1KB
│   ├── generate_diagrams.py        # Generate report diagram assets — 14.3KB
│   ├── generate_report_p1.py       # Report generation (part 1) — 19.2KB
│   ├── generate_report_p2.py       # Report generation (part 2) — 28.7KB
│   └── generate_report_p3.py       # Report generation (part 3) — 30.3KB
├── tests/                          # pytest test suite
│   ├── __init__.py
│   ├── test_crawler_scanner.py     # Crawler & scanner integration tests — 20.2KB
│   ├── test_new_scanners.py        # Vulnerability scanner tests — 15.6KB
│   ├── test_smart_engine_integration.py  # AI/SmartEngine tests — 9.8KB
│   ├── test_multi_tenancy.py       # Organization & multi-tenant tests — 4.0KB
│   └── test_stateless_scan_manager.py    # Scan manager state tests — 9.1KB
└── logs/                           # Application log files
```

---

## Database Schema (SQLAlchemy ORM)

### Core Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `users` | Local user records (mapped from Supabase Auth) | `id`, `supabase_uid`, `username`, `email`, `is_admin` |
| `scans` | Scan jobs | `id`, `user_id`, `org_id`, `target_url`, `scan_mode`, `scan_speed`, `crawl_depth`, `status`, `score`, `total_urls`, `tested_urls`, `vuln_count`, `critical_count`, `high_count`, `medium_count`, `low_count`, `duration`, `started_at`, `completed_at` |
| `vulnerabilities` | Found vulnerabilities | `id`, `scan_id`, `vuln_type`, `name`, `description`, `impact`, `severity`, `cvss_score`, `owasp_category`, `affected_url`, `parameter`, `payload`, `request_data`, `response_data`, `remediation`, `ai_analysis`, `ai_narrative`, `likely_false_positive`, `fp_confidence` |
| `crawled_urls` | URLs discovered during crawling | `id`, `scan_id`, `url`, `status_code`, `forms_found`, `params_found` |
| `scan_logs` | Real-time scan log messages | `id`, `scan_id`, `log_type`, `message` |
| `organizations` | Multi-tenant teams | `id`, `name`, `slug`, `plan` (free/pro/enterprise) |
| `org_memberships` | User ↔ Org mapping | `user_id`, `org_id`, `role` (owner/admin/member/viewer) |
| `webhooks` | Event-driven HTTP notifications | `id`, `user_id`, `url`, `on_scan_complete`, `on_vulnerability_found`, `on_scan_error`, `is_active`, `failure_count` |
| `api_keys` | Programmatic access tokens | `id`, `user_id`, `key_hash` (HMAC-SHA256), `key_prefix`, `is_active`, `expires_at`, `usage_count` |
| `scan_attempts` | ML training data (every scan attempt) | `id`, `scan_id`, `url`, `parameter`, `payload`, `status_code`, `response_time`, `vulnerability_found`, `is_true_positive`, `features` (JSON) |
| `ml_models` | ML model version tracking | `id`, `name`, `version`, `model_type`, `training_accuracy`, `f1_score`, `is_active`, `model_path` |

### Relationships
- `User` → has many `Scans`, `Webhooks`, `APIKeys`, `OrgMemberships`
- `Scan` → has many `Vulnerabilities`, `CrawledUrls`, `ScanLogs`, `ScanAttempts`
- `Organization` → has many `OrgMemberships`, `Scans` (via `org_id`)

### Auto-Migrations (in `init_db()`)
- Adds `org_id` column to `scans` table if missing
- Adds AI columns (`ai_analysis`, `ai_narrative`, `likely_false_positive`, `fp_confidence`) to `vulnerabilities` if missing
- Adds `org_id` column to `api_keys` table if missing

---

## Scan Pipeline

```
Phase 0:   Connectivity Check  →  HTTP GET target, verify reachability
Phase 1:   Crawling            →  Multi-threaded crawler discovers URLs & injectable points
                                  Fallback test points created if crawler finds 0 URLs
Phase 1.5: AI Recon            →  LLM analyzes HTTP response to detect tech stack, WAF, framework
Phase 2:   Vulnerability Scan  →  16 scanners run in parallel via ThreadPoolExecutor
           ├─ For each finding:
           │   ├─ Deduplicated by (vuln_type, affected_url, parameter)
           │   ├─ Batch-saved to DB (Vulnerability.create_batch)
           │   └─ Prometheus metrics tracked
           └─ Progress streaming via SSE (Redis pub/sub or in-memory queues)
Finalize:  Score calculation (A–F letter grade), duration, severity counts → DB
           Webhook triggers (best-effort)
           Redis state cleanup
```

> **Note:** Phase 3 (Post-Scan AI Deep Analysis) was removed to eliminate database session
> poisoning issues and reduce false-positive noise. AI analysis now runs inline during Phase 2.

### Dual Execution Modes
The scan pipeline runs in two modes, automatically selected at startup:
1. **Celery mode** — When Redis is available: dispatches to Celery worker, state tracked in Redis hashes, SSE via Redis pub/sub
2. **Threading mode** — When Redis is unavailable: runs scan in daemon thread, state tracked in-memory dicts, SSE via in-memory queues

### Score Calculation
| Score | Condition |
|-------|-----------|
| A | score_num ≥ 90 |
| B | score_num ≥ 80 |
| C | score_num ≥ 70 |
| D | score_num ≥ 60 |
| F | score_num < 60 |

Formula: `100 - (critical × 20) - (high × 10) - (medium × 5)`, clamped to ≥ 0.

### Supported Vulnerability Checks (16)
`sql_injection`, `xss`, `csrf`, `security_headers`, `directory_traversal`, `command_injection`, `idor`, `directory_listing`, `xxe`, `ssrf`, `open_redirect`, `cors`, `clickjacking`, `ssti`, `jwt_attacks`, `broken_auth`

### Scan Modes & Speeds
- **Modes:** `active` (full scanning) | `passive` (headers only)
- **Speeds:** `safe` (1.0s delay, 3 threads, 75 URLs) | `balanced` (0.15s, 6 threads, 200 URLs) | `aggressive` (0.05s, 10 threads, 500 URLs)

### Scan Controls
- **Start / Pause / Resume / Stop** — via Redis control keys (`scan:{id}:control`) or in-memory threading flags
- **Orphan Recovery** — on app startup, scans stuck in `running` for >10 min are recovered to `error`

---

## AI/LLM System

### SmartEngine (`app/ai/smart_engine.py`) — Unified Intelligence Layer
Thread-safe singleton integrating 3 systems:

1. **LLM (Groq / Llama 3.3 70B)** — All reasoning, analysis, payload generation
   - Rate-limited (28 RPM, Groq free tier)
   - Response caching (1-hour TTL, MD5-keyed)
   - Graceful fallback — scanning never stops if LLM is unavailable

2. **PortSwigger Knowledge Base** — 269 labs, 2197 payloads, 31 categories
   - Lazy-loaded from `data/portswigger_knowledge/portswigger_knowledge.json`
   - Maps scanner vuln_types to PortSwigger category slugs
   - Enriches LLM prompts with real lab solutions and payloads

3. **ML False-Positive Classifier** — Random Forest + Gradient Boosting ensemble
   - 16 features (payload analysis, response comparison, error patterns)
   - Trained from labeled `scan_attempts` data
   - Combined verdict: ML (40%) + LLM (60%)
   - Current model: `fp_classifier_v20260311_113925.joblib` (484KB)

### Key AI Functions
| Function | Purpose |
|----------|---------|
| `reconnaissance()` | Detect target tech stack, WAF, framework from HTTP response |
| `generate_smart_payloads()` | Context-aware payload generation using LLM + PortSwigger |
| `generate_waf_bypass()` | WAF bypass variants using LLM + PortSwigger bypass techniques |
| `verify_finding()` | 3-layer FP verification: ML → LLM → combined (40/60 weight) |
| `generate_attack_narrative()` | Professional exploitation writeup with PortSwigger lab refs |
| `enrich_remediation()` | Add PortSwigger Academy learning links to remediation text |

### LLM Prompt Templates (in `smart_engine.py`)
- `PAYLOAD_GENERATION_PROMPT` — Context-aware payload generation
- `WAF_BYPASS_PROMPT` — WAF evasion payload variants
- `RECON_PROMPT` — Technology stack fingerprinting
- `ATTACK_NARRATIVE_PROMPT` — Professional finding writeups
- `FINDING_VERIFICATION_PROMPT` — ML+LLM combined FP verification

### Report Generation (AI-powered, `app/ai/report_writer.py`)
- Executive summary (3-5 paragraphs, professional consultant tone)
- Prioritized remediation plan with code examples
- Attack narratives per finding
- Risk score explanations (business-friendly)
- All with fallbacks if LLM is unavailable

---

## Authentication & Authorization

- **Supabase Auth** handles registration, login, JWT tokens
- **Local user mapping:** `supabase_uid` → local `users.id` via `User.get_or_create_from_supabase()`
- **Session-based auth** with `@login_required` decorator
- **OAuth callback:** `auth/callback_handler.html` handles Supabase OAuth redirects
- **API key auth** for v2 API (HMAC-SHA256 hashing with transparent legacy migration)
- **Multi-tenant access:** Users see own scans + organization-shared scans
- **CSRF protection** via Flask-WTF (1-hour token validity)
- **Rate limiting** via Flask-Limiter (200/day, 50/hour default)

---

## API Endpoints

### Web Routes (Server-rendered Jinja2)
| Blueprint | Prefix | Purpose |
|-----------|--------|---------|
| `main_bp` | `/` | Landing page |
| `auth_bp` | `/auth` | Login, register, logout, OAuth callback |
| `dashboard_bp` | `/dashboard` | User dashboard with stats |
| `scan_bp` | `/scan` | Start new scan, configure checks, real-time progress |
| `results_bp` | `/results` | View results, download HTML/PDF reports |
| `history_bp` | `/history` | Scan history with filtering |
| `ml_admin_bp` | `/ml-admin` | ML training data labeling & model stats |

### REST API v2 (`/api/v2/`)
API key authenticated (`X-API-Key` header), CSRF-exempt. Includes:
- Scan management (create, status, list, delete)
- Vulnerability retrieval
- Organization management
- Webhook CRUD

### Legacy API v1 (`/api/`)
Basic scan endpoints (maintained for backward compatibility).

---

## Infrastructure

### Application Factory (`app/__init__.py`)
1. Loads `.env` via `python-dotenv`
2. Fixes `postgres://` → `postgresql+psycopg://` URI format
3. Initializes extensions (SQLAlchemy, Flask-Migrate, CSRF, Flask-Limiter)
4. Initializes Celery with Flask context
5. **Probes database connectivity** — if PostgreSQL is unreachable, falls back to SQLite
6. Creates tables + runs column migrations
7. Recovers orphaned scans from previous crashes
8. Registers all 9 blueprints

### Database Connectivity
- **Primary:** PostgreSQL via Supabase (connection pooler, port 5432)
- **Fallback:** SQLite at `data/database.db` — activated automatically if PostgreSQL probe fails
- Connection pool: 10 connections, 20 overflow, 30s timeout, 30min recycle, pre-ping enabled

### SSE Event Streaming
- **Redis mode:** pub/sub on `scan:{id}:events` channel + `scan:{id}:event_history` list (1h TTL)
- **Threading mode:** in-memory queues with event history for late-joining clients
- Events: `log`, `progress`, `finding`, `complete`

### Plan-Based Resource Limits
| Plan | Scans/Month | Concurrent | Team Members | URLs/Scan | AI Analysis |
|------|-------------|-----------|--------------|-----------|-------------|
| Free | 5 | 1 | 3 | 100 | No |
| Pro | 50 | 3 | 15 | 500 | Yes |
| Enterprise | Unlimited | 10 | Unlimited | Unlimited | Yes |

### Monitoring
- Prometheus metrics via `prometheus-client`
- Tracks: scans started/completed, vulnerabilities by severity/type

---

## Key Dependencies

| Category | Package | Version |
|----------|---------|---------|
| Framework | Flask | 3.0.0 |
| ORM | Flask-SQLAlchemy | 3.1.1 |
| Migrations | Flask-Migrate | 4.0.7 |
| DB Driver | psycopg (3.x) | ≥3.1.0 |
| Auth | gotrue + PyJWT | ≥2.0.0 / ≥2.8.0 |
| Task Queue | celery[redis] | 5.4.0 |
| AI/LLM | groq | ≥0.12.0 |
| ML | scikit-learn + pandas + joblib | ≥1.3.2 / ≥2.1.4 / ≥1.3.2 |
| Scraping | requests + beautifulsoup4 + lxml | 2.31.0 / 4.12.2 / latest |
| Reports | fpdf2 | 2.7.6 |
| CSRF | Flask-WTF | 1.2.1 |
| Rate Limiting | Flask-Limiter | 3.8.0 |
| HTTP | Werkzeug + urllib3 | 3.0.1 / 2.0.7 |
| Server | gunicorn | 22.0.0 |
| Monitoring | prometheus-client | ≥0.19.0 |
| Env | python-dotenv | 1.0.0 |
| Testing | pytest + pytest-cov | 7.4.3 / 4.1.0 |

---

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `SECRET_KEY` | Flask session encryption | Production |
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection (Celery, rate-limiting, SSE) | Optional |
| `REDIS_PASSWORD` | Redis authentication password | Optional |
| `SUPABASE_URL` | Supabase project URL | Yes |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | Yes |
| `SUPABASE_SERVICE_KEY` | Supabase service role key | Yes |
| `GROQ_API_KEY` | Groq LLM API key | Optional (AI features) |
| `GROQ_MODEL` | LLM model name | Optional (default: llama-3.3-70b-versatile) |
| `FLASK_ENV` | development / production | Optional |
| `FLASK_DEBUG` | Enable debug mode (1/0) | Optional (default: 1) |
| `PORT` | Server port | Optional (default: 5000) |
| `ALLOW_LOCAL_TARGETS` | Allow scanning localhost/private IPs | Optional |

---

## How to Run

### Docker (recommended)

```bash
# Start all services (web + worker + redis)
docker compose up --build

# Or web only (no Celery — falls back to threading mode)
docker compose up --build web

# Stop and remove volumes
docker compose down -v
```

### Local Development

```bash
# Development (venv must be activated)
python run.py

# Celery worker (separate terminal, requires Redis)
celery -A app.celery_app:celery worker --loglevel=info

# Tests
pytest tests/ -v
```

The app runs at `http://localhost:5000` by default.

---

## Codebase Statistics

| Metric | Value |
|--------|-------|
| Total source files (excl. venv, pycache, git) | ~73 files |
| Backend Python code | ~400KB across 35 .py files |
| Frontend templates | ~116KB across 12 .html files |
| Vulnerability scanners | 15 modules (16 checks) |
| Test files | 5 test modules (~59KB) |
| PortSwigger KB | ~2.8MB (3 JSON files) |
| ML model | 1 trained model (~484KB) |
| Static assets | CSS (10.3KB) + JS (1.0KB) |

*Last updated: 2026-05-10*
