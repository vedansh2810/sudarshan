# Sudarshan — Web Vulnerability Scanner

**Project Type:** Full-stack web application  
**Backend:** Python 3.12 / Flask 3.0  
**Database:** PostgreSQL (Supabase) with SQLite fallback  
**Auth:** Supabase Auth (GoTrue)  
**AI/LLM:** Groq API (Llama 3.3 70B Versatile)  
**ML:** scikit-learn (Random Forest + Gradient Boosting ensemble)  
**Task Queue:** Celery + Redis (optional — falls back to in-process threading)  
**Deployment:** Docker + docker-compose (gunicorn)  

---

## Architecture Overview

```
sudarshan/
├── run.py                          # Entry point (auto-activates venv)
├── app/
│   ├── __init__.py                 # Flask app factory (create_app)
│   ├── config.py                   # Config classes (Dev/Prod)
│   ├── celery_app.py               # Celery factory with Flask context
│   ├── tasks.py                    # Celery task definitions (run_scan_task)
│   ├── ai/                         # AI/LLM intelligence layer
│   │   ├── smart_engine.py         # Unified AI engine (LLM + PortSwigger + ML)
│   │   ├── llm_client.py           # Groq LLM client (rate-limited, cached)
│   │   ├── analyzer.py             # Vulnerability analysis & FP classification
│   │   └── report_writer.py        # AI-generated report sections
│   ├── ml/                         # Machine Learning
│   │   └── false_positive_classifier.py  # RF+GB ensemble FP classifier
│   ├── models/                     # SQLAlchemy ORM models
│   │   ├── database.py             # Core models + db init + migrations
│   │   ├── scan.py                 # Scan CRUD operations
│   │   ├── user.py                 # User CRUD (Supabase ↔ local mapping)
│   │   ├── vulnerability.py        # Vulnerability CRUD
│   │   ├── organization.py         # Multi-tenant org/team model
│   │   ├── webhook.py              # Webhook event notifications
│   │   ├── api_key.py              # HMAC-SHA256 API key auth
│   │   └── ml_training.py          # ML training data (ScanAttempt, MLModel)
│   ├── scanner/                    # Core scanning engine
│   │   ├── scan_manager.py         # Scan orchestration (Celery or threading)
│   │   ├── crawler.py              # Multi-threaded web crawler
│   │   ├── dvwa_auth.py            # DVWA auto-authentication
│   │   ├── payload_manager.py      # Static payload database
│   │   └── vulnerabilities/        # 16 vulnerability scanner modules
│   │       ├── base.py             # Base scanner class
│   │       ├── sql_injection.py    # SQL Injection (26KB)
│   │       ├── xss.py              # Cross-Site Scripting (24KB)
│   │       ├── csrf.py             # CSRF
│   │       ├── command_injection.py # OS Command Injection
│   │       ├── directory_traversal.py # Path Traversal
│   │       ├── xxe.py              # XML External Entity
│   │       ├── ssrf.py             # Server-Side Request Forgery
│   │       ├── ssti.py             # Server-Side Template Injection
│   │       ├── jwt_attacks.py      # JWT Vulnerabilities
│   │       ├── broken_auth.py      # Broken Authentication
│   │       ├── idor.py             # IDOR + Directory Listing
│   │       ├── open_redirect.py    # Open Redirect
│   │       ├── cors.py             # CORS Misconfiguration
│   │       ├── clickjacking.py     # Clickjacking
│   │       └── security_headers.py # Security Headers
│   ├── routes/                     # Flask blueprints
│   │   ├── main.py                 # Landing page
│   │   ├── auth.py                 # Login/Register (Supabase Auth)
│   │   ├── dashboard.py            # User dashboard
│   │   ├── scan.py                 # Start/manage scans
│   │   ├── results.py              # View results + HTML/PDF reports (27KB)
│   │   ├── history.py              # Scan history
│   │   ├── api.py                  # Legacy API v1
│   │   ├── api_v2.py               # RESTful API v2 (API key auth)
│   │   └── ml_admin.py             # ML training data admin panel
│   ├── utils/                      # Utility modules
│   │   ├── auth_helpers.py         # @login_required decorator
│   │   ├── auth_utils.py           # Session helpers
│   │   └── url_safety.py           # SSRF protection (IP validation)
│   ├── monitoring/
│   │   └── metrics.py              # Prometheus metrics
│   └── templates/                  # Jinja2 HTML templates
│       ├── base.html / layout.html # Base templates
│       ├── auth/                   # Login/Register pages
│       ├── dashboard/              # Dashboard page
│       ├── scan/                   # Scan configuration page
│       ├── results/                # Scan results + reports
│       ├── history/                # Scan history page
│       ├── main/                   # Landing page
│       └── ml_admin/               # ML admin panel
├── frontend/                       # Vite-based frontend (unused/WIP)
├── data/
│   ├── database.db                 # SQLite database (dev)
│   ├── ml_models/                  # Trained ML model files (.joblib)
│   ├── portswigger_knowledge/      # PortSwigger KB (JSON)
│   └── reports/                    # Generated HTML/PDF reports
├── scripts/                        # Utility scripts
│   ├── portswigger_scraper.py      # Scrape PortSwigger labs
│   ├── portswigger_auto_trainer.py # Auto-train from scraped data
│   ├── portswigger_complete_integration.py
│   └── train_ml_models.py          # Train ML false-positive classifier
├── tests/                          # pytest test suite
│   ├── test_crawler_scanner.py
│   ├── test_new_scanners.py
│   └── test_smart_engine_integration.py
├── Dockerfile                      # Python 3.12-slim + gunicorn
├── docker-compose.yml              # web + worker + redis (3 services)
├── requirements.txt                # 46 Python dependencies
└── .env                            # Environment variables
```

---

## Database Schema (SQLAlchemy ORM)

### Core Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `users` | Local user records (mapped from Supabase Auth) | `id`, `supabase_uid`, `username`, `email`, `is_admin` |
| `scans` | Scan jobs | `id`, `user_id`, `org_id`, `target_url`, `scan_mode`, `scan_speed`, `crawl_depth`, `status`, `score`, `total_urls`, `tested_urls`, `vuln_count`, `critical_count`, `high_count`, `medium_count`, `low_count`, `duration` |
| `vulnerabilities` | Found vulnerabilities | `id`, `scan_id`, `vuln_type`, `name`, `description`, `severity`, `cvss_score`, `owasp_category`, `affected_url`, `parameter`, `payload`, `request_data`, `response_data`, `remediation`, `ai_analysis`, `ai_narrative`, `likely_false_positive`, `fp_confidence` |
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

---

## Scan Pipeline (3 Phases)

```
Phase 0: Connectivity Check  →  HTTP GET target, verify reachability
Phase 1: Crawling           →  Multi-threaded crawler discovers URLs & injectable points
Phase 1.5: AI Recon         →  LLM analyzes HTTP response to detect tech stack, WAF, framework
Phase 2: Vulnerability Scan →  16 scanners run in parallel via ThreadPoolExecutor
         ├─ For each finding:
         │   ├─ Save to DB (Vulnerability.create)
         │   ├─ AI Analysis (LLM explains finding, OWASP mapping, CWE)
         │   ├─ FP Verification (ML classifier + LLM combined, 40%/60% weight)
         │   └─ Attack Narrative (LLM generates detailed exploitation writeup)
         └─ Progress streaming via SSE (Redis pub/sub or in-memory queues)
Phase 3: Post-Scan AI       →  Deep analysis of critical/high findings, attack narratives
```

### Supported Vulnerability Checks (16)
`sql_injection`, `xss`, `csrf`, `security_headers`, `directory_traversal`, `command_injection`, `idor`, `directory_listing`, `xxe`, `ssrf`, `open_redirect`, `cors`, `clickjacking`, `ssti`, `jwt_attacks`, `broken_auth`

### Scan Modes & Speeds
- **Modes:** `active` (full scanning) | `passive` (headers only)
- **Speeds:** `safe` (1.0s delay, 3 threads, 75 URLs) | `balanced` (0.15s, 6 threads, 200 URLs) | `aggressive` (0.05s, 10 threads, 500 URLs)

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

### Key AI Functions
| Function | Purpose |
|----------|---------|
| `reconnaissance()` | Detect target tech stack, WAF, framework from HTTP response |
| `generate_smart_payloads()` | Context-aware payload generation using LLM + PortSwigger |
| `generate_waf_bypass()` | WAF bypass variants using LLM + PortSwigger bypass techniques |
| `verify_finding()` | 3-layer FP verification: ML → LLM → combined (40/60 weight) |
| `generate_attack_narrative()` | Professional exploitation writeup with PortSwigger lab refs |
| `enrich_remediation()` | Add PortSwigger Academy learning links to remediation text |

### Report Generation (AI-powered)
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
| `auth_bp` | `/auth` | Login, register, logout |
| `dashboard_bp` | `/dashboard` | User dashboard with stats |
| `scan_bp` | `/scan` | Start new scan, configure checks |
| `results_bp` | `/results` | View results, download HTML/PDF reports |
| `history_bp` | `/history` | Scan history with filtering |
| `ml_admin_bp` | `/ml-admin` | ML training data labeling & model management |

### REST API v2 (`/api/v2/`)
API key authenticated (`X-API-Key` header), CSRF-exempt. Includes:
- Scan management (create, status, list, delete)
- Vulnerability retrieval
- Organization management
- Webhook CRUD

---

## Infrastructure

### Docker Stack (3 services)
1. **web** — Flask + gunicorn (2 workers, port 5000)
2. **worker** — Celery worker (concurrency 2)
3. **redis** — Redis 7 Alpine (password-protected)

### SSE Event Streaming
- **Redis mode:** pub/sub on `scan:{id}:events` channel
- **Threading mode:** in-memory queues with event history for late-joining clients
- Events: `log`, `progress`, `finding`, `complete`

### Monitoring
- Prometheus metrics via `prometheus-client`
- Tracks: scans started/completed, vulnerabilities by severity/type

---

## Key Dependencies

| Category | Package | Version |
|----------|---------|---------|
| Framework | Flask | 3.0.0 |
| ORM | Flask-SQLAlchemy | 3.1.1 |
| DB Driver | psycopg (3.x) | ≥3.1.0 |
| Auth | gotrue + PyJWT | ≥2.0.0 / ≥2.8.0 |
| Task Queue | celery[redis] | 5.4.0 |
| AI/LLM | groq | ≥0.12.0 |
| ML | scikit-learn + pandas | ≥1.3.2 / ≥2.1.4 |
| Scraping | requests + beautifulsoup4 | 2.31.0 / 4.12.2 |
| Reports | fpdf2 | 2.7.6 |
| Rate Limiting | Flask-Limiter | 3.8.0 |
| Monitoring | prometheus-client | ≥0.19.0 |

---

## Environment Variables

| Variable | Purpose | Required |
|----------|---------|----------|
| `SECRET_KEY` | Flask session encryption | Production |
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection (Celery, rate-limiting, SSE) | Optional |
| `SUPABASE_URL` | Supabase project URL | Yes |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | Yes |
| `SUPABASE_SERVICE_KEY` | Supabase service role key | Yes |
| `GROQ_API_KEY` | Groq LLM API key | Optional (AI features) |
| `GROQ_MODEL` | LLM model name | Optional (default: llama-3.3-70b-versatile) |
| `FLASK_ENV` | development / production | Optional |
| `ALLOW_LOCAL_TARGETS` | Allow scanning localhost/private IPs | Optional |

---

## How to Run

```bash
# Development (auto-activates venv)
python run.py

# Docker
docker-compose up --build

# Celery worker (separate terminal)
celery -A app.celery_app:celery worker --loglevel=info

# Tests
pytest tests/ -v
```

The app runs at `http://localhost:5000` by default.
